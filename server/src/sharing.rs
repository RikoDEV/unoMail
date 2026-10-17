//! Folder sharing: access rights on mailboxes owned by another account (RFC 4314 rights).
//!
//! A mailbox always belongs to one account, which holds every right on it. Other accounts get
//! access through entries in `mailbox_acl`; the identifier `anyone` (grantee 0) stands for
//! every account of the owner's domain, which is how global folders are made.

use sqlx::SqlitePool;

use crate::{auth::Account, store::Mailbox};

/// lookup, read, seen, write flags, insert, post, create child, delete mailbox, delete
/// messages, expunge, administer.
pub const ALL_RIGHTS: &str = "lrswipkxtea";
pub const ANYONE: &str = "anyone";

/// Keeps only valid right letters, in canonical order and without duplicates.
pub fn normalize_rights(rights: &str) -> Option<String> {
    if rights.chars().any(|c| !ALL_RIGHTS.contains(c)) {
        return None;
    }
    Some(ALL_RIGHTS.chars().filter(|c| rights.contains(*c)).collect())
}

/// Applies an IMAP SETACL modification (`+rights`, `-rights` or a replacement) to `current`.
pub fn modify_rights(current: &str, change: &str) -> Option<String> {
    match change.split_at_checked(1) {
        Some(("+", add)) => normalize_rights(&format!("{current}{}", normalize_rights(add)?)),
        Some(("-", remove)) => {
            let remove = normalize_rights(remove)?;
            Some(current.chars().filter(|c| !remove.contains(*c)).collect())
        }
        _ => normalize_rights(change),
    }
}

/// The rights `account` holds on `mailbox`: everything for the owner, otherwise the union of
/// the entries naming the account and, within the owner's domain, `anyone`.
pub async fn rights(db: &SqlitePool, account: &Account, mailbox: &Mailbox) -> sqlx::Result<String> {
    if mailbox.account_id == account.id {
        return Ok(ALL_RIGHTS.to_owned());
    }
    let granted: Vec<String> = sqlx::query_scalar(
        "SELECT rights FROM mailbox_acl WHERE mailbox_id = ?1
           AND (grantee_id = ?2 OR (grantee_id = 0 AND (SELECT domain_id FROM accounts WHERE id = ?3) = ?4))",
    )
    .bind(mailbox.id)
    .bind(account.id)
    .bind(mailbox.account_id)
    .bind(account.domain_id)
    .fetch_all(db)
    .await?;
    Ok(normalize_rights(&granted.concat()).unwrap_or_default())
}

/// A mailbox the account can at least see, with the rights it holds on it.
pub async fn mailbox(db: &SqlitePool, account: &Account, mailbox_id: i64) -> sqlx::Result<Option<(Mailbox, String)>> {
    let Some(mailbox): Option<Mailbox> = sqlx::query_as("SELECT * FROM mailboxes WHERE id = ?").bind(mailbox_id).fetch_optional(db).await? else {
        return Ok(None);
    };
    let rights = rights(db, account, &mailbox).await?;
    // Without the lookup right the mailbox does not exist as far as this account is concerned.
    Ok(rights.contains('l').then_some((mailbox, rights)))
}

/// A mailbox shared with an account, together with its owner's address.
#[derive(Debug, Clone)]
pub struct Shared {
    pub mailbox: Mailbox,
    pub owner: String,
    pub rights: String,
}

impl Shared {
    /// The name under which the mailbox appears to the account it is shared with.
    pub fn display_name(&self) -> String {
        format!("{SHARED_PREFIX}{}/{}", self.owner, self.mailbox.name)
    }
}

/// IMAP namespace of other users' mailboxes.
pub const SHARED_PREFIX: &str = "Shared/";

/// Every mailbox of other accounts that `account` may look up.
pub async fn shared_with(db: &SqlitePool, account: &Account) -> sqlx::Result<Vec<Shared>> {
    let ids: Vec<(i64, String)> = sqlx::query_as(
        "SELECT DISTINCT m.id, o.email FROM mailbox_acl a
           JOIN mailboxes m ON m.id = a.mailbox_id JOIN accounts o ON o.id = m.account_id
         WHERE m.account_id != ?1 AND o.enabled = 1 AND (a.grantee_id = ?1 OR (a.grantee_id = 0 AND o.domain_id = ?2))
         ORDER BY o.email, m.name",
    )
    .bind(account.id)
    .bind(account.domain_id)
    .fetch_all(db)
    .await?;
    let mut out = Vec::new();
    for (id, owner) in ids {
        if let Some((mailbox, rights)) = mailbox(db, account, id).await? {
            out.push(Shared { mailbox, owner, rights });
        }
    }
    Ok(out)
}

/// Resolves a name in the shared namespace (`Shared/<owner>/<mailbox>`).
pub async fn shared_by_name(db: &SqlitePool, account: &Account, name: &str) -> sqlx::Result<Option<Shared>> {
    let Some((owner, mailbox_name)) = name.strip_prefix(SHARED_PREFIX).and_then(|rest| rest.split_once('/')) else { return Ok(None) };
    let id: Option<i64> = sqlx::query_scalar("SELECT m.id FROM mailboxes m JOIN accounts o ON o.id = m.account_id WHERE o.email = ? AND o.enabled = 1 AND m.name = ? AND m.account_id != ?")
        .bind(owner.to_ascii_lowercase())
        .bind(if mailbox_name.eq_ignore_ascii_case("INBOX") { "INBOX" } else { mailbox_name })
        .bind(account.id)
        .fetch_optional(db)
        .await?;
    let Some(id) = id else { return Ok(None) };
    Ok(mailbox(db, account, id).await?.map(|(mailbox, rights)| Shared { mailbox, owner: owner.to_ascii_lowercase(), rights }))
}

/// The access list of a mailbox as (identifier, rights) pairs; the owner comes first.
pub async fn list(db: &SqlitePool, mailbox: &Mailbox) -> sqlx::Result<Vec<(String, String)>> {
    let owner: String = sqlx::query_scalar("SELECT email FROM accounts WHERE id = ?").bind(mailbox.account_id).fetch_one(db).await?;
    let mut out = vec![(owner, ALL_RIGHTS.to_owned())];
    let rows: Vec<(i64, Option<String>, String)> = sqlx::query_as(
        "SELECT a.grantee_id, g.email, a.rights FROM mailbox_acl a LEFT JOIN accounts g ON g.id = a.grantee_id WHERE a.mailbox_id = ? ORDER BY a.grantee_id",
    )
    .bind(mailbox.id)
    .fetch_all(db)
    .await?;
    for (grantee, email, rights) in rows {
        match (grantee, email) {
            (0, _) => out.push((ANYONE.to_owned(), rights)),
            (_, Some(email)) => out.push((email, rights)),
            _ => {}
        }
    }
    Ok(out)
}

#[derive(Debug, thiserror::Error)]
pub enum AclError {
    #[error("unknown user")]
    UnknownUser,
    #[error("the owner always has every right")]
    Owner,
    #[error("invalid rights")]
    InvalidRights,
    #[error(transparent)]
    Db(#[from] sqlx::Error),
}

/// Resolves an ACL identifier to a grantee id. Only accounts of the owner's domain can be
/// named, so the existence of accounts elsewhere on the server is not revealed.
async fn grantee(db: &SqlitePool, mailbox: &Mailbox, identifier: &str) -> Result<i64, AclError> {
    if identifier.eq_ignore_ascii_case(ANYONE) {
        return Ok(0);
    }
    let id: Option<i64> = sqlx::query_scalar(
        "SELECT g.id FROM accounts g WHERE g.email = ? AND g.domain_id = (SELECT domain_id FROM accounts WHERE id = ?)",
    )
    .bind(identifier.trim().to_ascii_lowercase())
    .bind(mailbox.account_id)
    .fetch_optional(db)
    .await?;
    match id {
        Some(id) if id == mailbox.account_id => Err(AclError::Owner),
        Some(id) => Ok(id),
        None => Err(AclError::UnknownUser),
    }
}

/// Sets (or, with empty rights, removes) the rights of `identifier` on a mailbox.
pub async fn set(db: &SqlitePool, mailbox: &Mailbox, identifier: &str, change: &str) -> Result<(), AclError> {
    let grantee = grantee(db, mailbox, identifier).await?;
    let current: Option<String> = sqlx::query_scalar("SELECT rights FROM mailbox_acl WHERE mailbox_id = ? AND grantee_id = ?").bind(mailbox.id).bind(grantee).fetch_optional(db).await?;
    let rights = modify_rights(current.as_deref().unwrap_or(""), change).ok_or(AclError::InvalidRights)?;
    if rights.is_empty() {
        sqlx::query("DELETE FROM mailbox_acl WHERE mailbox_id = ? AND grantee_id = ?").bind(mailbox.id).bind(grantee).execute(db).await?;
    } else {
        sqlx::query("INSERT INTO mailbox_acl (mailbox_id, grantee_id, rights) VALUES (?, ?, ?) ON CONFLICT(mailbox_id, grantee_id) DO UPDATE SET rights = excluded.rights")
            .bind(mailbox.id)
            .bind(grantee)
            .bind(rights)
            .execute(db)
            .await?;
    }
    Ok(())
}

pub async fn remove(db: &SqlitePool, mailbox: &Mailbox, identifier: &str) -> Result<(), AclError> {
    let grantee = grantee(db, mailbox, identifier).await?;
    sqlx::query("DELETE FROM mailbox_acl WHERE mailbox_id = ? AND grantee_id = ?").bind(mailbox.id).bind(grantee).execute(db).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rights_are_normalized_and_modified() {
        assert_eq!(normalize_rights("srl").as_deref(), Some("lrs"));
        assert_eq!(normalize_rights("lrr").as_deref(), Some("lr"));
        assert_eq!(normalize_rights("lrz"), None);
        assert_eq!(modify_rights("lr", "+swi").as_deref(), Some("lrswi"));
        assert_eq!(modify_rights("lrswi", "-wi").as_deref(), Some("lrs"));
        assert_eq!(modify_rights("lrswi", "lr").as_deref(), Some("lr"));
        assert_eq!(modify_rights("lr", "-lr").as_deref(), Some(""));
        assert_eq!(modify_rights("lr", "+q"), None);
        assert_eq!(modify_rights("lr", "").as_deref(), Some(""));
    }
}

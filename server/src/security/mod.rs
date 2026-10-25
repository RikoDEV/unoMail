//! Sender authentication, signing and reputation checks.

pub mod access;
pub mod attachments;
pub mod authn;
pub mod bimi;
pub mod clamav;
pub mod summary;
pub mod dkim;
pub mod feedback;
pub mod filter;
pub mod outbound;
pub mod reputation;
pub mod rspamd;

/// Prepares a message that a user stores directly (IMAP APPEND, JMAP, mailbox import) rather
/// than one that arrived by SMTP, which is checked on the way in.
///
/// Verdicts that only this server may state are removed, so an uploaded message cannot show
/// as "Sender verified". When the folder belongs to someone else (a shared mailbox), the
/// executable-attachment policy applies as it would to mail sent to them; the refused file's
/// name is the error.
pub fn admit_stored(app: &crate::app::App, raw: &[u8], foreign: bool) -> Result<Vec<u8>, String> {
    let stripped = authn::strip_forged_results(raw, &app.cfg.hostname);
    if foreign
        && app.rt().block_executable_attachments
        && let Some(name) = attachments::blocked_attachment(&stripped)
    {
        return Err(name);
    }
    Ok(stripped)
}

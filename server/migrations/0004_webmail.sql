-- Web mail features: sender identities, address book, response templates, preferences,
-- folder sharing, PGP key storage and webhooks.

-- Additional sender identities. An identity without its own SMTP server must be an address the
-- account owns (its own or an alias delivering to it); one with an SMTP server sends through
-- that server and may use any address the remote server accepts.
CREATE TABLE identities (
    id             INTEGER PRIMARY KEY,
    account_id     INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name           TEXT NOT NULL DEFAULT '',
    email          TEXT NOT NULL,
    reply_to       TEXT NOT NULL DEFAULT '',
    signature_html TEXT NOT NULL DEFAULT '',
    is_default     INTEGER NOT NULL DEFAULT 0,
    smtp_host      TEXT,
    smtp_port      INTEGER,
    smtp_security  TEXT CHECK (smtp_security IN ('tls', 'starttls', 'none')),
    smtp_username  TEXT NOT NULL DEFAULT '',
    smtp_password  TEXT NOT NULL DEFAULT '',                   -- sealed with the server key
    created_at     INTEGER NOT NULL,
    UNIQUE (account_id, email)
) STRICT;

-- Outbound mail of an identity with its own SMTP server is relayed through that server.
ALTER TABLE queue ADD COLUMN relay_identity_id INTEGER;

CREATE TABLE contacts (
    id           INTEGER PRIMARY KEY,
    account_id   INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name         TEXT NOT NULL DEFAULT '',
    email        TEXT NOT NULL,
    phone        TEXT NOT NULL DEFAULT '',
    organization TEXT NOT NULL DEFAULT '',
    notes        TEXT NOT NULL DEFAULT '',
    pgp_key      TEXT NOT NULL DEFAULT '',                     -- armored public key
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    UNIQUE (account_id, email)
) STRICT;

CREATE TABLE contact_groups (
    id         INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    UNIQUE (account_id, name)
) STRICT;

CREATE TABLE contact_group_members (
    group_id   INTEGER NOT NULL REFERENCES contact_groups(id) ON DELETE CASCADE,
    contact_id INTEGER NOT NULL REFERENCES contacts(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, contact_id)
) STRICT;

-- Canned responses.
CREATE TABLE templates (
    id         INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    subject    TEXT NOT NULL DEFAULT '',
    html       TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL,
    UNIQUE (account_id, name)
) STRICT;

-- Per-user web client preferences (skin, spell-check language, trusted image senders, ...).
CREATE TABLE preferences (
    account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    data       TEXT NOT NULL DEFAULT '{}'
) STRICT;

-- Folder sharing (IMAP ACL, RFC 4314). grantee_id 0 stands for "anyone": every account of
-- the owner's domain.
CREATE TABLE mailbox_acl (
    mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    grantee_id INTEGER NOT NULL,
    rights     TEXT NOT NULL,
    PRIMARY KEY (mailbox_id, grantee_id)
) STRICT;
CREATE INDEX mailbox_acl_grantee ON mailbox_acl(grantee_id);
CREATE TRIGGER mailbox_acl_account_deleted AFTER DELETE ON accounts
BEGIN
    DELETE FROM mailbox_acl WHERE grantee_id = OLD.id;
END;

-- OpenPGP keys of an account. The private key is stored only in its passphrase-protected,
-- armored form; the server never sees the passphrase.
CREATE TABLE pgp_keys (
    account_id  INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    public_key  TEXT NOT NULL,
    private_key TEXT NOT NULL DEFAULT '',
    updated_at  INTEGER NOT NULL
) STRICT;

-- Outgoing webhooks: the server-side half of the plug-in API.
CREATE TABLE webhooks (
    id          INTEGER PRIMARY KEY,
    url         TEXT NOT NULL,
    secret      TEXT NOT NULL,                                 -- sealed with the server key
    events      TEXT NOT NULL DEFAULT '[]',                    -- JSON array of event names
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL,
    last_status TEXT NOT NULL DEFAULT '',
    last_at     INTEGER
) STRICT;

-- Accounts that signed in through the external identity provider at least once.
CREATE TABLE oauth_links (
    account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    subject    TEXT NOT NULL,
    linked_at  INTEGER NOT NULL
) STRICT;

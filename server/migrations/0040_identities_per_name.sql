-- Sender identities: several may share an address (one per name, reply-to or signature), and
-- every account has one primary identity, its own address, which cannot be removed.

CREATE TABLE identities_new (
    id             INTEGER PRIMARY KEY,
    account_id     INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name           TEXT NOT NULL DEFAULT '',
    email          TEXT NOT NULL,
    reply_to       TEXT NOT NULL DEFAULT '',
    is_default     INTEGER NOT NULL DEFAULT 0,
    -- The account's own address; its address follows the account's.
    is_primary     INTEGER NOT NULL DEFAULT 0,
    smtp_host      TEXT,
    smtp_port      INTEGER,
    smtp_security  TEXT CHECK (smtp_security IN ('tls', 'starttls', 'none')),
    smtp_username  TEXT NOT NULL DEFAULT '',
    smtp_password  TEXT NOT NULL DEFAULT '',                   -- sealed with the server key
    created_at     INTEGER NOT NULL
) STRICT;

-- Ids are kept: queued messages name the identity whose SMTP server sends them.
INSERT INTO identities_new (id, account_id, name, email, reply_to, is_default, is_primary, smtp_host, smtp_port, smtp_security, smtp_username, smtp_password, created_at)
SELECT i.id, i.account_id, i.name, i.email, i.reply_to, i.is_default, i.email = a.email AND i.smtp_host IS NULL,
       i.smtp_host, i.smtp_port, i.smtp_security, i.smtp_username, i.smtp_password, i.created_at
FROM identities i JOIN accounts a ON a.id = i.account_id;

DROP TABLE identities;
ALTER TABLE identities_new RENAME TO identities;

CREATE INDEX identities_account ON identities(account_id, email);
CREATE UNIQUE INDEX identities_primary ON identities(account_id) WHERE is_primary = 1;

-- Accounts that never saved their own address get it as their primary identity now.
INSERT INTO identities (account_id, name, email, is_default, is_primary, created_at)
SELECT a.id, a.display_name, a.email, NOT EXISTS (SELECT 1 FROM identities d WHERE d.account_id = a.id AND d.is_default = 1), 1, unixepoch()
FROM accounts a
WHERE NOT EXISTS (SELECT 1 FROM identities p WHERE p.account_id = a.id AND p.is_primary = 1);

-- The built-in entry used to be the default when nothing was chosen; the primary identity is now.
UPDATE identities SET is_default = 1
WHERE is_primary = 1 AND NOT EXISTS (SELECT 1 FROM identities d WHERE d.account_id = identities.account_id AND d.is_default = 1);

-- Signatures are chosen per identity rather than per address. Masked addresses, which are
-- not stored identities, are named by the negated id of the mask.
CREATE TABLE signature_defaults_new (
    account_id         INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    identity_id        INTEGER NOT NULL,
    new_signature_id   INTEGER REFERENCES signatures(id) ON DELETE SET NULL,
    reply_signature_id INTEGER REFERENCES signatures(id) ON DELETE SET NULL,
    PRIMARY KEY (account_id, identity_id)
) STRICT, WITHOUT ROWID;

INSERT INTO signature_defaults_new (account_id, identity_id, new_signature_id, reply_signature_id)
SELECT d.account_id, i.id, d.new_signature_id, d.reply_signature_id
FROM signature_defaults d JOIN identities i ON i.account_id = d.account_id AND i.email = d.email;

INSERT OR IGNORE INTO signature_defaults_new (account_id, identity_id, new_signature_id, reply_signature_id)
SELECT d.account_id, -m.id, d.new_signature_id, d.reply_signature_id
FROM signature_defaults d JOIN masked_addresses m ON m.account_id = d.account_id AND m.email = d.email;

DROP TABLE signature_defaults;
ALTER TABLE signature_defaults_new RENAME TO signature_defaults;

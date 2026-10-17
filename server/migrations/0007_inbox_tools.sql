-- Per-user tools for keeping the inbox tidy.

-- Senders a user does not want to hear from. An entry is an address or, written "@domain", a
-- whole domain. Their mail is still accepted (the sender learns nothing) but goes to Junk.
CREATE TABLE blocked_senders (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    sender     TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (account_id, sender)
) STRICT;

-- Labels a user defined, with their colour. A label is an IMAP/JMAP keyword on messages; this
-- table lets a label exist before it is first used and remembers how it is displayed.
CREATE TABLE labels (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    color      TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (account_id, name)
) STRICT;

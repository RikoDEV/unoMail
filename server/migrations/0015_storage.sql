-- Blobs already copied to a backup target (named by its description), so that each backup
-- only copies what is new.
CREATE TABLE backup_blobs (
    target TEXT NOT NULL,
    hash   TEXT NOT NULL,
    PRIMARY KEY (target, hash)
) STRICT;

-- Backup runs, for the admin panel.
CREATE TABLE backup_runs (
    id           INTEGER PRIMARY KEY,
    snapshot     TEXT NOT NULL,
    target       TEXT NOT NULL,
    started_at   INTEGER NOT NULL,
    finished_at  INTEGER,
    status       TEXT NOT NULL CHECK (status IN ('running', 'ok', 'failed')),
    detail       TEXT NOT NULL DEFAULT '',
    blobs_copied INTEGER NOT NULL DEFAULT 0,
    bytes_copied INTEGER NOT NULL DEFAULT 0
) STRICT;

-- Incoming mail is stored encrypted to the account's OpenPGP public key.
ALTER TABLE pgp_keys ADD COLUMN encrypt_incoming INTEGER NOT NULL DEFAULT 0;

-- When a message arrived in its current mailbox, for emptying Trash and Junk after a while.
ALTER TABLE messages ADD COLUMN mailbox_since INTEGER NOT NULL DEFAULT 0;

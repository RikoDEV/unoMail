-- Blobs uploaded by a user (attachments of messages being composed). An upload may only be
-- referenced by the account that created it.
CREATE TABLE uploads (
    account_id   INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    hash         TEXT NOT NULL REFERENCES blobs(hash),
    content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
    size         INTEGER NOT NULL,
    created_at   INTEGER NOT NULL,
    PRIMARY KEY (account_id, hash)
) STRICT;

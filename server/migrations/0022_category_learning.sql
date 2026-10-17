-- Inbox categories learned from the user: every message they moved to another category, and
-- per-category token counts for a classifier trained on those corrections. Tokens are 64-bit
-- hashes, as for the personal spam filter.
CREATE TABLE category_learned (
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    category    TEXT NOT NULL,
    sender      TEXT NOT NULL,
    learned_at  INTEGER NOT NULL, -- milliseconds, increasing per account
    PRIMARY KEY (account_id, fingerprint)
) STRICT, WITHOUT ROWID;

-- "Where did the user last put mail from this sender?"
CREATE INDEX category_learned_sender ON category_learned (account_id, sender, learned_at);

CREATE TABLE category_tokens (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    token      INTEGER NOT NULL,
    category   TEXT NOT NULL,
    count      INTEGER NOT NULL,
    PRIMARY KEY (account_id, token, category)
) STRICT, WITHOUT ROWID;

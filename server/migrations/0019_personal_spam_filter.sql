-- Personal spam filter: per-account Bayes token statistics, learned from the user's own
-- "spam" and "not spam" decisions. Tokens are stored as 64-bit hashes, not as text.
CREATE TABLE bayes_tokens (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    token      INTEGER NOT NULL,
    spam       INTEGER NOT NULL DEFAULT 0,
    ham        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (account_id, token)
) STRICT, WITHOUT ROWID;

-- Every message learned, by a fingerprint of its content, so a message is counted once and a
-- changed mind (spam, then not spam) moves its tokens instead of counting them twice.
CREATE TABLE bayes_learned (
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    spam        INTEGER NOT NULL,
    learned_at  INTEGER NOT NULL,
    PRIMARY KEY (account_id, fingerprint)
) STRICT, WITHOUT ROWID;

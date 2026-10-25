-- Messages a Sieve script has seen, for the duplicate test (RFC 7352): a hash of the
-- script's handle and the message's id, kept until it expires.
CREATE TABLE sieve_duplicates (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    key        TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (account_id, key)
) STRICT;

CREATE INDEX sieve_duplicates_expiry ON sieve_duplicates (expires_at);

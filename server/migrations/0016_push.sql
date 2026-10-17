-- JMAP push subscriptions (RFC 8620 section 7.2), delivered as Web Push.
CREATE TABLE push_subscriptions (
    id                INTEGER PRIMARY KEY,
    account_id        INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    device_client_id  TEXT NOT NULL,
    url               TEXT NOT NULL,
    p256dh            TEXT NOT NULL DEFAULT '',
    auth              TEXT NOT NULL DEFAULT '',
    verification_code TEXT NOT NULL,
    verified          INTEGER NOT NULL DEFAULT 0,
    expires           INTEGER NOT NULL,
    types             TEXT NOT NULL DEFAULT 'null',
    created_at        INTEGER NOT NULL
) STRICT;
CREATE INDEX push_subscriptions_account ON push_subscriptions(account_id);

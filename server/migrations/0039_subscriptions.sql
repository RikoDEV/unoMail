-- Subscription management: which stored contents offer a way to unsubscribe (List-Unsubscribe),
-- keyed by content like the search index, and the senders the user has unsubscribed from.
CREATE TABLE message_unsubscribe (
    hash    TEXT PRIMARY KEY,
    offered INTEGER NOT NULL
) STRICT;

CREATE TABLE unsubscribed_senders (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    sender     TEXT NOT NULL,
    at         INTEGER NOT NULL,
    PRIMARY KEY (account_id, sender)
) STRICT;

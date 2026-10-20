-- Purchase facts belong to the receiving account, even when the same blob is delivered twice.
CREATE TABLE purchase_cards (
    id INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    entity_key TEXT NOT NULL,
    dismissed INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    UNIQUE(account_id, entity_key)
);
CREATE TABLE purchase_card_sources (
    card_id INTEGER NOT NULL REFERENCES purchase_cards(id) ON DELETE CASCADE,
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    details TEXT NOT NULL,
    method TEXT NOT NULL,
    evidence TEXT NOT NULL,
    PRIMARY KEY(card_id, message_id)
);
CREATE INDEX purchase_card_sources_message ON purchase_card_sources(message_id);
CREATE TABLE summary_card_jobs (
    message_id INTEGER PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    state TEXT NOT NULL DEFAULT 'pending',
    use_ai INTEGER NOT NULL DEFAULT 0,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    version INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX summary_card_jobs_pending ON summary_card_jobs(state, next_attempt);

-- MT-PRIORITY (RFC 6710): higher priorities leave the queue first.
ALTER TABLE queue ADD COLUMN priority INTEGER NOT NULL DEFAULT 0;

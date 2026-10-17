-- Send-only mailboxes (e.g. noreply@): they send, and incoming mail for them is discarded.
ALTER TABLE accounts ADD COLUMN send_only INTEGER NOT NULL DEFAULT 0;

-- Per-mailbox overrides of the server's sending limits; NULL uses the server setting.
-- The hourly limits replace the server's; message size and recipients can only tighten it.
ALTER TABLE accounts ADD COLUMN max_messages_per_hour INTEGER;
ALTER TABLE accounts ADD COLUMN max_recipients_per_hour INTEGER;
ALTER TABLE accounts ADD COLUMN max_message_size INTEGER;
ALTER TABLE accounts ADD COLUMN max_recipients INTEGER;

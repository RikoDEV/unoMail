-- Full-text search over messages, and the attachment list of each message content for the
-- list view. Both are kept per blob: copies of a message in several mailboxes share them.
CREATE TABLE message_extras (
    id          INTEGER PRIMARY KEY,                           -- also the row id in message_text
    hash        TEXT NOT NULL UNIQUE,
    attachments TEXT NOT NULL DEFAULT '[]'                     -- JSON, as the JMAP property
) STRICT;

CREATE VIRTUAL TABLE message_text USING fts5(
    subject, sender, recipients_to, recipients_cc, recipients_bcc, body, attachments,
    tokenize = 'unicode61 remove_diacritics 2'
);

-- When the content itself goes, so does what was indexed from it.
CREATE TRIGGER blobs_search_cleanup AFTER DELETE ON blobs BEGIN
    DELETE FROM message_text WHERE rowid IN (SELECT id FROM message_extras WHERE hash = OLD.hash);
    DELETE FROM message_extras WHERE hash = OLD.hash;
END;

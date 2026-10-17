-- Indexes and side tables found necessary by profiling a 20,000-message mailbox.

-- Counting threads and unread mail per mailbox (Mailbox/get, unread counts, the thread total
-- of a folder listing) without reading the wide message rows.
CREATE INDEX messages_mailbox_thread ON messages(mailbox_id, thread_id, seen);

-- What changed in a mailbox since a mod-sequence (IMAP synchronisation).
CREATE INDEX messages_mailbox_modseq ON messages(mailbox_id, modseq);

-- The newest message of each thread (thread-collapsed listings, filtered ones included).
CREATE INDEX messages_thread_newest ON messages(account_id, thread_id, internal_date DESC, id DESC, mailbox_id);

-- Every keyword (label, category, $junk, ...) of every message, kept in step with the JSON
-- column by triggers, so that labels and categories are found through an index instead of
-- parsing the keywords of every message.
CREATE TABLE message_keywords (
    message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
    account_id INTEGER NOT NULL,
    keyword    TEXT NOT NULL,
    PRIMARY KEY (message_id, keyword)
) STRICT, WITHOUT ROWID;
CREATE INDEX message_keywords_account ON message_keywords(account_id, keyword);

INSERT OR IGNORE INTO message_keywords (message_id, account_id, keyword)
    SELECT m.id, m.account_id, k.value
      FROM messages m, json_each(CASE WHEN json_valid(m.keywords) THEN m.keywords ELSE '[]' END) k
     WHERE k.type = 'text';

CREATE TRIGGER messages_keywords_insert AFTER INSERT ON messages BEGIN
    INSERT OR IGNORE INTO message_keywords (message_id, account_id, keyword)
        SELECT NEW.id, NEW.account_id, value FROM json_each(CASE WHEN json_valid(NEW.keywords) THEN NEW.keywords ELSE '[]' END) WHERE type = 'text';
END;

-- Only when the keywords really change: flag updates write the same list again.
CREATE TRIGGER messages_keywords_update AFTER UPDATE OF keywords, account_id ON messages
WHEN OLD.keywords IS NOT NEW.keywords OR OLD.account_id IS NOT NEW.account_id BEGIN
    DELETE FROM message_keywords WHERE message_id = NEW.id;
    INSERT OR IGNORE INTO message_keywords (message_id, account_id, keyword)
        SELECT NEW.id, NEW.account_id, value FROM json_each(CASE WHEN json_valid(NEW.keywords) THEN NEW.keywords ELSE '[]' END) WHERE type = 'text';
END;

-- Addresses each account has written to, for the personal spam filter's "correspondent"
-- check (filled on sending; seeded from what the Sent folders hold).
CREATE TABLE correspondents (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    address    TEXT NOT NULL,
    last_at    INTEGER NOT NULL,
    PRIMARY KEY (account_id, address)
) STRICT, WITHOUT ROWID;

INSERT OR IGNORE INTO correspondents (account_id, address, last_at)
    SELECT m.account_id, lower(trim(k.value)), MAX(m.internal_date)
      FROM messages m JOIN mailboxes b ON b.id = m.mailbox_id,
           json_each(CASE WHEN json_valid('["' || replace(m.to_addrs, ', ', '","') || '"]') THEN '["' || replace(m.to_addrs, ', ', '","') || '"]' ELSE '[]' END) k
     WHERE b.role = 'sent' AND m.to_addrs <> '' AND instr(k.value, '@') > 0
     GROUP BY m.account_id, lower(trim(k.value));

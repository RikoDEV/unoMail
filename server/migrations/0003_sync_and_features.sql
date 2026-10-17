-- Change log backing JMAP /changes and /queryChanges. The JMAP state of an account is the
-- highest change id recorded for it.
CREATE TABLE changes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('email', 'mailbox')),
    object_id  INTEGER NOT NULL,
    thread_id  INTEGER,
    change     TEXT NOT NULL CHECK (change IN ('created', 'updated', 'destroyed'))
) STRICT;
CREATE INDEX changes_account ON changes(account_id, id);

-- UIDs removed from a mailbox, for IMAP QRESYNC (VANISHED responses).
CREATE TABLE expunged (
    mailbox_id INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    uid        INTEGER NOT NULL,
    modseq     INTEGER NOT NULL,
    PRIMARY KEY (mailbox_id, uid)
) STRICT;

-- Mailbox import jobs (IMAP sync, Maildir ingestion).
CREATE TABLE import_jobs (
    id          INTEGER PRIMARY KEY,
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('imap', 'maildir')),
    source      TEXT NOT NULL,
    status      TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'completed', 'failed')),
    imported    INTEGER NOT NULL DEFAULT 0,
    skipped     INTEGER NOT NULL DEFAULT 0,
    error       TEXT,
    started_at  INTEGER NOT NULL,
    finished_at INTEGER
) STRICT;

-- Which side of the report a DMARC aggregate report describes is implied by its domain being
-- hosted here; reports are deduplicated by (org_name, report_id) in dmarc_reports.
CREATE INDEX dmarc_reports_domain ON dmarc_reports(domain, date_end DESC);
CREATE INDEX dmarc_records_report ON dmarc_records(report_id);

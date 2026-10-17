-- Submissions held back until a time (scheduled send, undo send): RFC 8621 section 7 with
-- FUTURERELEASE (RFC 4865).
CREATE TABLE email_submissions (
    id          INTEGER PRIMARY KEY,
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    message_id  INTEGER NOT NULL,
    send_at     INTEGER NOT NULL,
    undo_status TEXT NOT NULL DEFAULT 'pending' CHECK (undo_status IN ('pending', 'final', 'canceled')),
    error       TEXT NOT NULL DEFAULT '',
    on_success  TEXT NOT NULL DEFAULT 'null',
    created_at  INTEGER NOT NULL
) STRICT;
CREATE INDEX email_submissions_due ON email_submissions(undo_status, send_at);

-- Snoozed messages: out of the way until a time, then back where they were.
CREATE TABLE snoozes (
    message_id        INTEGER PRIMARY KEY,
    account_id        INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    until             INTEGER NOT NULL,
    return_mailbox_id INTEGER NOT NULL,
    created_at        INTEGER NOT NULL
) STRICT;
CREATE INDEX snoozes_due ON snoozes(until);

-- S/MIME: the user's certificate and private key (sealed with the server key), and the
-- certificates of correspondents who sent signed mail.
CREATE TABLE smime_identities (
    account_id  INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    certificate TEXT NOT NULL,
    chain       TEXT NOT NULL DEFAULT '[]',
    key_sealed  TEXT NOT NULL,
    created_at  INTEGER NOT NULL
) STRICT;

CREATE TABLE smime_certificates (
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    certificate TEXT NOT NULL,
    not_after   INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    PRIMARY KEY (account_id, email)
) STRICT;

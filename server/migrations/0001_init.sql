-- unoMail initial schema. All timestamps are unix seconds (UTC).

CREATE TABLE settings (
    key   TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
) STRICT;

CREATE TABLE domains (
    id                  INTEGER PRIMARY KEY,
    name                TEXT NOT NULL UNIQUE,
    enabled             INTEGER NOT NULL DEFAULT 1,
    max_mailboxes       INTEGER NOT NULL DEFAULT 0,            -- 0 = unlimited
    default_quota_bytes INTEGER NOT NULL DEFAULT 1073741824,
    catch_all           TEXT,
    created_at          INTEGER NOT NULL
) STRICT;

CREATE TABLE accounts (
    id               INTEGER PRIMARY KEY,
    domain_id        INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    local_part       TEXT NOT NULL,
    email            TEXT NOT NULL UNIQUE,
    display_name     TEXT NOT NULL DEFAULT '',
    password_hash    TEXT NOT NULL,
    role             TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'domain_admin', 'super_admin')),
    quota_bytes      INTEGER NOT NULL DEFAULT 1073741824,      -- 0 = unlimited
    used_bytes       INTEGER NOT NULL DEFAULT 0,
    enabled          INTEGER NOT NULL DEFAULT 1,
    imap_enabled     INTEGER NOT NULL DEFAULT 1,
    pop3_enabled     INTEGER NOT NULL DEFAULT 1,
    smtp_enabled     INTEGER NOT NULL DEFAULT 1,
    outbound_blocked INTEGER NOT NULL DEFAULT 0,
    outbound_blocked_reason TEXT,
    created_at       INTEGER NOT NULL,
    UNIQUE (domain_id, local_part)
) STRICT;

-- Domains a domain_admin account is allowed to manage.
CREATE TABLE domain_admins (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    domain_id  INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    PRIMARY KEY (account_id, domain_id)
) STRICT;

CREATE TABLE aliases (
    id           INTEGER PRIMARY KEY,
    domain_id    INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    source       TEXT NOT NULL UNIQUE,
    destinations TEXT NOT NULL,                                -- JSON array of addresses
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   INTEGER NOT NULL
) STRICT;

CREATE TABLE sessions (
    token_hash TEXT PRIMARY KEY NOT NULL,                      -- sha256 of the bearer token
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    ip         TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX sessions_account ON sessions(account_id);

CREATE TABLE mailboxes (
    id             INTEGER PRIMARY KEY,
    account_id     INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name           TEXT NOT NULL,                              -- hierarchy separator is '/'
    role           TEXT,                                       -- inbox|sent|drafts|trash|junk|archive
    uid_validity   INTEGER NOT NULL,
    uid_next       INTEGER NOT NULL DEFAULT 1,
    highest_modseq INTEGER NOT NULL DEFAULT 1,
    subscribed     INTEGER NOT NULL DEFAULT 1,
    UNIQUE (account_id, name)
) STRICT;

CREATE TABLE blobs (
    hash     TEXT PRIMARY KEY NOT NULL,                        -- sha256 hex of raw content
    size     INTEGER NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE messages (
    id              INTEGER PRIMARY KEY,
    account_id      INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    mailbox_id      INTEGER NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    uid             INTEGER NOT NULL,
    blob_hash       TEXT NOT NULL REFERENCES blobs(hash),
    size            INTEGER NOT NULL,
    internal_date   INTEGER NOT NULL,
    modseq          INTEGER NOT NULL DEFAULT 1,
    seen            INTEGER NOT NULL DEFAULT 0,
    answered        INTEGER NOT NULL DEFAULT 0,
    flagged         INTEGER NOT NULL DEFAULT 0,
    deleted         INTEGER NOT NULL DEFAULT 0,
    draft           INTEGER NOT NULL DEFAULT 0,
    keywords        TEXT NOT NULL DEFAULT '[]',                -- JSON array of custom keywords
    thread_id       INTEGER NOT NULL,
    message_id      TEXT NOT NULL DEFAULT '',
    in_reply_to     TEXT NOT NULL DEFAULT '',
    subject         TEXT NOT NULL DEFAULT '',
    from_addr       TEXT NOT NULL DEFAULT '',
    from_name       TEXT NOT NULL DEFAULT '',
    to_addrs        TEXT NOT NULL DEFAULT '',
    snippet         TEXT NOT NULL DEFAULT '',
    has_attachments INTEGER NOT NULL DEFAULT 0,
    sent_date       INTEGER NOT NULL DEFAULT 0,
    UNIQUE (mailbox_id, uid)
) STRICT;
CREATE INDEX messages_account_thread ON messages(account_id, thread_id);
CREATE INDEX messages_account_msgid ON messages(account_id, message_id);
CREATE INDEX messages_mailbox_date ON messages(mailbox_id, internal_date DESC);

CREATE TABLE threads (
    id         INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE
) STRICT;

-- Outbound delivery queue: one row per (message, recipient).
CREATE TABLE queue (
    id              INTEGER PRIMARY KEY,
    sender          TEXT NOT NULL,                             -- envelope MAIL FROM ('' for bounces)
    recipient       TEXT NOT NULL,
    recipient_domain TEXT NOT NULL,
    blob_hash       TEXT NOT NULL REFERENCES blobs(hash),
    size            INTEGER NOT NULL,
    account_id      INTEGER,                                   -- originating local account, if any
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    expires_at      INTEGER NOT NULL,
    last_error      TEXT,
    status          TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'sending', 'held'))
) STRICT;
CREATE INDEX queue_due ON queue(status, next_attempt_at);

CREATE TABLE delivery_log (
    id         INTEGER PRIMARY KEY,
    ts         INTEGER NOT NULL,
    direction  TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound', 'local')),
    sender     TEXT NOT NULL,
    recipient  TEXT NOT NULL,
    status     TEXT NOT NULL,                                  -- delivered|deferred|bounced|rejected|junk|queued
    detail     TEXT NOT NULL DEFAULT '',
    remote     TEXT NOT NULL DEFAULT '',
    message_id TEXT NOT NULL DEFAULT '',
    size       INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE INDEX delivery_log_ts ON delivery_log(ts DESC);

CREATE TABLE audit_log (
    id     INTEGER PRIMARY KEY,
    ts     INTEGER NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    ip     TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX audit_log_ts ON audit_log(ts DESC);

CREATE TABLE dkim_keys (
    id          INTEGER PRIMARY KEY,
    domain_id   INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    selector    TEXT NOT NULL,
    algorithm   TEXT NOT NULL CHECK (algorithm IN ('rsa-sha256', 'ed25519-sha256')),
    private_key TEXT NOT NULL,                                 -- PKCS#8 PEM (rsa) / base64 seed (ed25519)
    public_key  TEXT NOT NULL,                                 -- base64, as published in the p= tag
    active      INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL,
    UNIQUE (domain_id, selector)
) STRICT;

CREATE TABLE certificates (
    id         INTEGER PRIMARY KEY,
    kind       TEXT NOT NULL CHECK (kind IN ('acme', 'custom', 'self_signed')),
    domains    TEXT NOT NULL,                                  -- JSON array of SANs
    cert_pem   TEXT NOT NULL,
    key_pem    TEXT NOT NULL,
    not_before INTEGER NOT NULL,
    not_after  INTEGER NOT NULL,
    issuer     TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE greylist (
    key        TEXT PRIMARY KEY NOT NULL,                      -- sha256(ip-net | sender | recipient)
    first_seen INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    passed     INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE sieve_scripts (
    id         INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    script     TEXT NOT NULL,
    active     INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL,
    UNIQUE (account_id, name)
) STRICT;

CREATE TABLE vacation (
    account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    enabled    INTEGER NOT NULL DEFAULT 0,
    subject    TEXT NOT NULL DEFAULT '',
    body       TEXT NOT NULL DEFAULT '',
    starts_at  INTEGER,
    ends_at    INTEGER,
    interval_days INTEGER NOT NULL DEFAULT 7
) STRICT;

-- Deduplication of autoreplies: at most one reply per sender per interval.
CREATE TABLE vacation_sent (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    sender     TEXT NOT NULL,
    sent_at    INTEGER NOT NULL,
    PRIMARY KEY (account_id, sender)
) STRICT;

CREATE TABLE dmarc_reports (
    id          INTEGER PRIMARY KEY,
    org_name    TEXT NOT NULL,
    report_id   TEXT NOT NULL,
    domain      TEXT NOT NULL,
    date_begin  INTEGER NOT NULL,
    date_end    INTEGER NOT NULL,
    policy      TEXT NOT NULL DEFAULT '',
    received_at INTEGER NOT NULL,
    UNIQUE (org_name, report_id)
) STRICT;

CREATE TABLE dmarc_records (
    id          INTEGER PRIMARY KEY,
    report_id   INTEGER NOT NULL REFERENCES dmarc_reports(id) ON DELETE CASCADE,
    source_ip   TEXT NOT NULL,
    count       INTEGER NOT NULL,
    disposition TEXT NOT NULL,
    dkim        TEXT NOT NULL,
    spf         TEXT NOT NULL,
    header_from TEXT NOT NULL
) STRICT;

-- Sliding-window counters used for outbound abuse detection.
CREATE TABLE outbound_stats (
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    bucket      INTEGER NOT NULL,                              -- unix hour
    messages    INTEGER NOT NULL DEFAULT 0,
    recipients  INTEGER NOT NULL DEFAULT 0,
    spam_hits   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (account_id, bucket)
) STRICT;

CREATE TABLE ip_reputation (
    ip         TEXT PRIMARY KEY NOT NULL,
    score      INTEGER NOT NULL,                               -- AbuseIPDB confidence 0-100
    checked_at INTEGER NOT NULL
) STRICT;

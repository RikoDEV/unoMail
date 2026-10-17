-- MTA-STS (published for hosted domains, honoured for others), DANE and SMTP TLS reporting.

-- The policy published at mta-sts.<domain>: none (not published), testing or enforce.
ALTER TABLE domains ADD COLUMN mta_sts_mode TEXT NOT NULL DEFAULT 'none';

-- Policies of receiving domains, as fetched.
CREATE TABLE mta_sts_cache (
    domain     TEXT PRIMARY KEY,
    policy_id  TEXT NOT NULL,
    mode       TEXT NOT NULL,
    mx         TEXT NOT NULL,                                  -- JSON array of patterns
    max_age    INTEGER NOT NULL,
    fetched_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
) STRICT;

-- Outcomes of outgoing sessions, per day, for the reports receiving domains ask for.
CREATE TABLE tls_rpt_results (
    day           INTEGER NOT NULL,
    domain        TEXT NOT NULL,
    policy_type   TEXT NOT NULL,                               -- tlsa, sts, no-policy-found
    policy_string TEXT NOT NULL DEFAULT '',
    mx_host       TEXT NOT NULL,
    result_type   TEXT NOT NULL,                               -- success, or a TLS-RPT failure type
    receiving_ip  TEXT NOT NULL DEFAULT '',
    count         INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, domain, policy_type, mx_host, result_type, receiving_ip)
) STRICT;

-- Reports other servers sent about hosted domains.
CREATE TABLE tls_reports (
    id          INTEGER PRIMARY KEY,
    reporter    TEXT NOT NULL,
    report_id   TEXT NOT NULL,
    domain      TEXT NOT NULL,
    policy_type TEXT NOT NULL,
    date_begin  INTEGER NOT NULL,
    date_end    INTEGER NOT NULL,
    successes   INTEGER NOT NULL,
    failures    INTEGER NOT NULL,
    details     TEXT NOT NULL DEFAULT '[]',
    received_at INTEGER NOT NULL,
    UNIQUE (reporter, report_id, domain, policy_type)
) STRICT;
CREATE INDEX tls_reports_domain ON tls_reports(domain, date_begin);

-- Which daily reports (TLS, DMARC) were sent already.
CREATE TABLE report_runs (
    kind TEXT NOT NULL,
    day  INTEGER NOT NULL,
    PRIMARY KEY (kind, day)
) STRICT;

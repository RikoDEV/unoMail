-- Abuse and authentication-failure reports (ARF, RFC 5965 / RFC 6591) other services sent
-- to hosted domains: complaints from feedback loops, and DMARC/DKIM/SPF failure reports.
CREATE TABLE feedback_reports (
    id               INTEGER PRIMARY KEY,
    received_at      INTEGER NOT NULL,
    reporter         TEXT NOT NULL,                 -- domain of the report's verified author
    feedback_type    TEXT NOT NULL,                 -- abuse, auth-failure, fraud, not-spam, virus, other
    auth_failure     TEXT NOT NULL DEFAULT '',      -- dmarc, dkim, spf, …
    source_ip        TEXT NOT NULL DEFAULT '',
    reported_domain  TEXT NOT NULL DEFAULT '',
    original_from    TEXT NOT NULL DEFAULT '',
    original_rcpt    TEXT NOT NULL DEFAULT '',
    subject          TEXT NOT NULL DEFAULT '',
    incidents        INTEGER NOT NULL DEFAULT 1,
    user_agent       TEXT NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX feedback_reports_received ON feedback_reports (received_at);

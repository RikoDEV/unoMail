-- Counters of the metrics endpoint and dashboard, kept across restarts.
CREATE TABLE metric_counters (
    name   TEXT PRIMARY KEY,
    value  INTEGER NOT NULL
) STRICT;

-- The login limiter's failures and lockouts, kept across restarts.
CREATE TABLE login_limiter (
    key           TEXT PRIMARY KEY,                            -- ip:<net>, pair:<email>|<net> or acct:<email>
    failures      INTEGER NOT NULL,
    window_start  INTEGER NOT NULL,
    strikes       INTEGER NOT NULL,
    locked_until  INTEGER NOT NULL
) STRICT;

-- Other in-memory state kept across restarts (recent activity, log buffers, report
-- bookkeeping), one JSON document per name.
CREATE TABLE state_snapshots (
    name   TEXT PRIMARY KEY,
    value  TEXT NOT NULL
) STRICT;

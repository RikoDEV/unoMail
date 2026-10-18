-- Hourly counters of copies an alias or mailing list sent on to other servers: mail that
-- arrives from outside and leaves again is not covered by any account's sending limit.
CREATE TABLE forward_stats (
    source  TEXT NOT NULL,                                     -- the alias or list address
    bucket  INTEGER NOT NULL,                                  -- unix hour
    copies  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (source, bucket)
) STRICT;

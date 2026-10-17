-- SMTP access control: blacklist and whitelist rules, and per-address reputation ("karma").

-- A rule covers one address or a network (CIDR). When several rules match a connecting
-- address, the one with the highest priority wins; among equals the most specific network,
-- then the whitelist.
CREATE TABLE ip_rules (
    id          INTEGER PRIMARY KEY,
    list        TEXT NOT NULL CHECK (list IN ('blacklist', 'whitelist')),
    source      TEXT NOT NULL DEFAULT 'user' CHECK (source IN ('user', 'auto')),
    network     TEXT NOT NULL,                                 -- canonical CIDR, e.g. 203.0.113.0/24
    priority    INTEGER NOT NULL DEFAULT 0,
    hits        INTEGER NOT NULL DEFAULT 0,
    last_seen   INTEGER,
    description TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER,                                       -- automatic rules lapse on their own
    UNIQUE (list, network)
) STRICT;

-- Behaviour score of remote addresses. Good mail raises it, rejected mail, failed logins and
-- protocol abuse lower it; a low enough score produces an automatic blacklist rule.
CREATE TABLE ip_karma (
    ip         TEXT PRIMARY KEY NOT NULL,
    score      INTEGER NOT NULL DEFAULT 0,
    good       INTEGER NOT NULL DEFAULT 0,
    bad        INTEGER NOT NULL DEFAULT 0,
    hits       INTEGER NOT NULL DEFAULT 0,
    last_seen  INTEGER NOT NULL,
    last_event TEXT NOT NULL DEFAULT ''
) STRICT;

-- What the server learned about where mail comes from: a sending network (`ip:…/24`), an
-- autonomous system (`asn:…`) or a verified sender domain (`domain:…`), with how many of its
-- messages were judged good and how many spam.
CREATE TABLE sender_reputation (
    key        TEXT PRIMARY KEY,
    ham        INTEGER NOT NULL DEFAULT 0,
    spam       INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL
) STRICT;
CREATE INDEX sender_reputation_updated ON sender_reputation(updated_at);

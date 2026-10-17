-- Brand logos (BIMI) and Gravatars fetched for senders, and the knowledge that a sender has
-- none, so that neither is asked for again with every message opened.
CREATE TABLE sender_avatars (
    key          TEXT PRIMARY KEY,                             -- "bimi:<domain>" or "gravatar:<address>"
    source       TEXT NOT NULL,                                -- bimi-verified, bimi, gravatar, none
    content_type TEXT NOT NULL DEFAULT '',
    data         BLOB NOT NULL,
    detail       TEXT NOT NULL DEFAULT '',                     -- who a verified mark belongs to
    fetched_at   INTEGER NOT NULL
) STRICT;

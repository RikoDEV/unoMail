-- Mailing lists: an address whose posts go to every member.
CREATE TABLE mailing_lists (
    id             INTEGER PRIMARY KEY,
    domain_id      INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    address        TEXT NOT NULL UNIQUE,
    name           TEXT NOT NULL,
    description    TEXT NOT NULL DEFAULT '',
    -- Who may post: anyone, members, moderated (moderators only, others held), announce.
    posting        TEXT NOT NULL DEFAULT 'members' CHECK (posting IN ('anyone', 'members', 'moderated', 'announce')),
    -- open: anyone may subscribe by mail (confirmed); closed: only administrators add members.
    subscription   TEXT NOT NULL DEFAULT 'closed' CHECK (subscription IN ('open', 'closed')),
    reply_to_list  INTEGER NOT NULL DEFAULT 0,
    subject_prefix TEXT NOT NULL DEFAULT '',
    enabled        INTEGER NOT NULL DEFAULT 1,
    created_at     INTEGER NOT NULL
) STRICT;

CREATE TABLE list_members (
    id         INTEGER PRIMARY KEY,
    list_id    INTEGER NOT NULL REFERENCES mailing_lists(id) ON DELETE CASCADE,
    email      TEXT NOT NULL,
    name       TEXT NOT NULL DEFAULT '',
    role       TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('member', 'moderator', 'owner')),
    bounces    INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    UNIQUE (list_id, email)
) STRICT;

-- Things waiting for someone: posts held for moderation, subscriptions and unsubscriptions
-- to be confirmed.
CREATE TABLE list_pending (
    id         INTEGER PRIMARY KEY,
    list_id    INTEGER NOT NULL REFERENCES mailing_lists(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('post', 'subscribe', 'unsubscribe')),
    token      TEXT NOT NULL UNIQUE,
    email      TEXT NOT NULL,
    subject    TEXT NOT NULL DEFAULT '',
    reason     TEXT NOT NULL DEFAULT '',
    blob_hash  TEXT,
    created_at INTEGER NOT NULL
) STRICT;
CREATE INDEX list_pending_list ON list_pending(list_id, kind);

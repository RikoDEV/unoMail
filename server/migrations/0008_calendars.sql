-- Calendars (CalDAV). An object is one event or to-do, stored exactly as the client sent it.
CREATE TABLE calendars (
    id          INTEGER PRIMARY KEY,
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    slug        TEXT NOT NULL,                                 -- last path segment of the collection
    name        TEXT NOT NULL,
    color       TEXT NOT NULL DEFAULT '',
    description TEXT NOT NULL DEFAULT '',
    -- Incremented on every change inside the calendar; doubles as CTag and sync token.
    sync_token  INTEGER NOT NULL DEFAULT 1,
    created_at  INTEGER NOT NULL,
    UNIQUE (account_id, slug)
) STRICT;

CREATE TABLE calendar_objects (
    id          INTEGER PRIMARY KEY,
    calendar_id INTEGER NOT NULL REFERENCES calendars(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,                                 -- resource name, e.g. "<uid>.ics"
    uid         TEXT NOT NULL,
    etag        TEXT NOT NULL,
    data        TEXT NOT NULL,
    component   TEXT NOT NULL,                                 -- VEVENT or VTODO
    summary     TEXT NOT NULL DEFAULT '',
    first_start INTEGER,                                       -- start of the first occurrence
    last_end    INTEGER,                                       -- NULL: recurs without an end
    modified    INTEGER NOT NULL,                              -- the calendar's sync token at the last change
    UNIQUE (calendar_id, name),
    UNIQUE (calendar_id, uid)
) STRICT;
CREATE INDEX calendar_objects_range ON calendar_objects(calendar_id, first_start);

-- Deleted objects, so that clients synchronising incrementally learn about removals.
CREATE TABLE calendar_tombstones (
    calendar_id INTEGER NOT NULL REFERENCES calendars(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    modified    INTEGER NOT NULL,
    PRIMARY KEY (calendar_id, name)
) STRICT;

-- Change log for the JMAP objects that are not mail: calendars and their events, the address
-- book and its cards, and Sieve scripts. Triggers keep it, so every writer (the web client,
-- CalDAV, CardDAV, ManageSieve, JMAP) is seen by `/changes`. Rows of a deleted account are
-- removed with it; the log is pruned like `changes`.
CREATE TABLE jmap_changes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    account_id INTEGER NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('Calendar', 'CalendarEvent', 'ContactCard', 'SieveScript')),
    item_id    INTEGER NOT NULL,
    change     TEXT NOT NULL CHECK (change IN ('created', 'updated', 'destroyed'))
) STRICT;
CREATE INDEX jmap_changes_account ON jmap_changes(account_id, kind, id);

CREATE TRIGGER jmap_accounts_delete AFTER DELETE ON accounts BEGIN
    DELETE FROM jmap_changes WHERE account_id = OLD.id;
END;

CREATE TRIGGER jmap_calendars_insert AFTER INSERT ON calendars BEGIN
    INSERT INTO jmap_changes (account_id, kind, item_id, change) VALUES (NEW.account_id, 'Calendar', NEW.id, 'created');
END;
CREATE TRIGGER jmap_calendars_update AFTER UPDATE OF name, color, description ON calendars BEGIN
    INSERT INTO jmap_changes (account_id, kind, item_id, change) VALUES (NEW.account_id, 'Calendar', NEW.id, 'updated');
END;
-- Before the delete: its events go with it, and afterwards nothing names the account.
CREATE TRIGGER jmap_calendars_delete BEFORE DELETE ON calendars WHEN EXISTS (SELECT 1 FROM accounts WHERE id = OLD.account_id) BEGIN
    INSERT INTO jmap_changes (account_id, kind, item_id, change) SELECT OLD.account_id, 'CalendarEvent', id, 'destroyed' FROM calendar_objects WHERE calendar_id = OLD.id;
    INSERT INTO jmap_changes (account_id, kind, item_id, change) VALUES (OLD.account_id, 'Calendar', OLD.id, 'destroyed');
END;

CREATE TRIGGER jmap_events_insert AFTER INSERT ON calendar_objects BEGIN
    INSERT INTO jmap_changes (account_id, kind, item_id, change) SELECT account_id, 'CalendarEvent', NEW.id, 'created' FROM calendars WHERE id = NEW.calendar_id;
END;
CREATE TRIGGER jmap_events_update AFTER UPDATE OF data, calendar_id ON calendar_objects BEGIN
    INSERT INTO jmap_changes (account_id, kind, item_id, change) SELECT account_id, 'CalendarEvent', NEW.id, 'updated' FROM calendars WHERE id = NEW.calendar_id;
END;
-- Within a calendar's deletion the calendar row is gone: that trigger has logged these.
CREATE TRIGGER jmap_events_delete AFTER DELETE ON calendar_objects BEGIN
    INSERT INTO jmap_changes (account_id, kind, item_id, change) SELECT account_id, 'CalendarEvent', OLD.id, 'destroyed' FROM calendars WHERE id = OLD.calendar_id;
END;

CREATE TRIGGER jmap_contacts_insert AFTER INSERT ON contacts BEGIN
    INSERT INTO jmap_changes (account_id, kind, item_id, change) VALUES (NEW.account_id, 'ContactCard', NEW.id, 'created');
END;
CREATE TRIGGER jmap_contacts_update AFTER UPDATE OF name, email, phone, organization, notes, vcard ON contacts BEGIN
    INSERT INTO jmap_changes (account_id, kind, item_id, change) VALUES (NEW.account_id, 'ContactCard', NEW.id, 'updated');
END;
CREATE TRIGGER jmap_contacts_delete AFTER DELETE ON contacts WHEN EXISTS (SELECT 1 FROM accounts WHERE id = OLD.account_id) BEGIN
    INSERT INTO jmap_changes (account_id, kind, item_id, change) VALUES (OLD.account_id, 'ContactCard', OLD.id, 'destroyed');
END;

CREATE TRIGGER jmap_sieve_insert AFTER INSERT ON sieve_scripts BEGIN
    INSERT INTO jmap_changes (account_id, kind, item_id, change) VALUES (NEW.account_id, 'SieveScript', NEW.id, 'created');
END;
CREATE TRIGGER jmap_sieve_update AFTER UPDATE OF name, script, active ON sieve_scripts BEGIN
    INSERT INTO jmap_changes (account_id, kind, item_id, change) VALUES (NEW.account_id, 'SieveScript', NEW.id, 'updated');
END;
CREATE TRIGGER jmap_sieve_delete AFTER DELETE ON sieve_scripts WHEN EXISTS (SELECT 1 FROM accounts WHERE id = OLD.account_id) BEGIN
    INSERT INTO jmap_changes (account_id, kind, item_id, change) VALUES (OLD.account_id, 'SieveScript', OLD.id, 'destroyed');
END;

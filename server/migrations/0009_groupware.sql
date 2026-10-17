-- Calendar sharing, and what CardDAV needs to synchronise the address book.

-- A calendar shared with a colleague, for reading or for reading and writing.
CREATE TABLE calendar_shares (
    calendar_id INTEGER NOT NULL REFERENCES calendars(id) ON DELETE CASCADE,
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    writable    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (calendar_id, account_id)
) STRICT;
CREATE INDEX calendar_shares_account ON calendar_shares(account_id);

-- Contacts are rebuilt: a card stored by a phone need not have an e-mail address, and two
-- cards may share one, so the uniqueness of (account, address) moves from the schema into the
-- web client's API. Group memberships are set aside, because dropping the table cascades.
CREATE TABLE contact_members_moving AS SELECT group_id, contact_id FROM contact_group_members;

CREATE TABLE contacts_new (
    id           INTEGER PRIMARY KEY,
    account_id   INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name         TEXT NOT NULL DEFAULT '',
    email        TEXT NOT NULL DEFAULT '',
    phone        TEXT NOT NULL DEFAULT '',
    organization TEXT NOT NULL DEFAULT '',
    notes        TEXT NOT NULL DEFAULT '',
    pgp_key      TEXT NOT NULL DEFAULT '',                     -- armored public key
    created_at   INTEGER NOT NULL,
    updated_at   INTEGER NOT NULL,
    uid          TEXT NOT NULL DEFAULT '',                     -- vCard UID
    dav_name     TEXT NOT NULL DEFAULT '',                     -- resource name, e.g. "<uid>.vcf"
    -- The card as a CardDAV client stored it; the columns above win over what it says.
    vcard        TEXT,
    modified     INTEGER NOT NULL DEFAULT 0                    -- the address book's sync token at the last change
) STRICT;
INSERT INTO contacts_new (id, account_id, name, email, phone, organization, notes, pgp_key, created_at, updated_at, uid)
    SELECT id, account_id, name, email, phone, organization, notes, pgp_key, created_at, updated_at, lower(hex(randomblob(16))) FROM contacts;
UPDATE contacts_new SET dav_name = uid || '.vcf', modified = 1;
DROP TABLE contacts;
ALTER TABLE contacts_new RENAME TO contacts;
CREATE INDEX contacts_account_email ON contacts(account_id, email);
CREATE UNIQUE INDEX contacts_dav_name ON contacts(account_id, dav_name);
INSERT OR IGNORE INTO contact_group_members (group_id, contact_id) SELECT group_id, contact_id FROM contact_members_moving;
DROP TABLE contact_members_moving;

-- One address book per account; the token counts its changes (CTag and sync token).
CREATE TABLE addressbooks (
    account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    sync_token INTEGER NOT NULL DEFAULT 1
) STRICT;
INSERT INTO addressbooks (account_id) SELECT DISTINCT account_id FROM contacts;

CREATE TABLE contact_tombstones (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    modified   INTEGER NOT NULL,
    PRIMARY KEY (account_id, name)
) STRICT;

-- Whoever changes a contact (the web client, an import, a CardDAV client), synchronising
-- clients learn about it: the bookkeeping lives here rather than in every writer.
CREATE TRIGGER contacts_sync_insert AFTER INSERT ON contacts BEGIN
    INSERT OR IGNORE INTO addressbooks (account_id) VALUES (NEW.account_id);
    UPDATE addressbooks SET sync_token = sync_token + 1 WHERE account_id = NEW.account_id;
    UPDATE contacts SET uid = CASE WHEN uid = '' THEN lower(hex(randomblob(16))) ELSE uid END,
                        modified = (SELECT sync_token FROM addressbooks WHERE account_id = NEW.account_id)
     WHERE id = NEW.id;
    UPDATE contacts SET dav_name = uid || '.vcf' WHERE id = NEW.id AND dav_name = '';
    DELETE FROM contact_tombstones WHERE account_id = NEW.account_id AND name = (SELECT dav_name FROM contacts WHERE id = NEW.id);
END;

CREATE TRIGGER contacts_sync_update AFTER UPDATE OF name, email, phone, organization, notes, pgp_key, vcard ON contacts BEGIN
    UPDATE addressbooks SET sync_token = sync_token + 1 WHERE account_id = NEW.account_id;
    UPDATE contacts SET modified = (SELECT sync_token FROM addressbooks WHERE account_id = NEW.account_id) WHERE id = NEW.id;
END;

CREATE TRIGGER contacts_sync_delete AFTER DELETE ON contacts BEGIN
    UPDATE addressbooks SET sync_token = sync_token + 1 WHERE account_id = OLD.account_id;
    -- Not while the account itself is being deleted: there is nobody left to tell.
    INSERT OR REPLACE INTO contact_tombstones (account_id, name, modified)
        SELECT OLD.account_id, OLD.dav_name, sync_token FROM addressbooks
         WHERE account_id = OLD.account_id AND EXISTS (SELECT 1 FROM accounts WHERE id = OLD.account_id);
END;

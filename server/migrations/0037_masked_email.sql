-- An address has one routing owner across all address types. Mask reservations survive
-- deletion, including account/domain deletion, so catch-all cannot resurrect an old mask.
CREATE TABLE address_reservations (email TEXT PRIMARY KEY, kind TEXT NOT NULL, resource_id INTEGER);
INSERT OR IGNORE INTO address_reservations SELECT email, 'account', id FROM accounts;
INSERT OR IGNORE INTO address_reservations SELECT source, 'alias', id FROM aliases;
INSERT OR IGNORE INTO address_reservations SELECT address, 'list', id FROM mailing_lists;
INSERT OR IGNORE INTO address_reservations SELECT substr(address,1,instr(address,'@')-1)||'-request'||substr(address,instr(address,'@')), 'list', id FROM mailing_lists;
INSERT OR IGNORE INTO address_reservations SELECT substr(address,1,instr(address,'@')-1)||'-owner'||substr(address,instr(address,'@')), 'list', id FROM mailing_lists;
INSERT OR IGNORE INTO address_reservations SELECT substr(address,1,instr(address,'@')-1)||'-bounces'||substr(address,instr(address,'@')), 'list', id FROM mailing_lists;
CREATE TRIGGER reserve_account AFTER INSERT ON accounts BEGIN
 INSERT INTO address_reservations VALUES (NEW.email,'account',NEW.id);
END;
CREATE TRIGGER release_account AFTER DELETE ON accounts BEGIN
 DELETE FROM address_reservations WHERE kind='account' AND resource_id=OLD.id;
END;
CREATE TRIGGER rename_account AFTER UPDATE OF email ON accounts WHEN OLD.email<>NEW.email BEGIN
 DELETE FROM address_reservations WHERE kind='account' AND resource_id=OLD.id;
 INSERT INTO address_reservations VALUES (NEW.email,'account',NEW.id);
END;
CREATE TRIGGER reserve_alias AFTER INSERT ON aliases BEGIN
 INSERT INTO address_reservations VALUES (NEW.source,'alias',NEW.id);
END;
CREATE TRIGGER release_alias AFTER DELETE ON aliases BEGIN
 DELETE FROM address_reservations WHERE kind='alias' AND resource_id=OLD.id;
END;
CREATE TRIGGER rename_alias AFTER UPDATE OF source ON aliases WHEN OLD.source<>NEW.source BEGIN
 DELETE FROM address_reservations WHERE kind='alias' AND resource_id=OLD.id;
 INSERT INTO address_reservations VALUES (NEW.source,'alias',NEW.id);
END;
CREATE TRIGGER reserve_list AFTER INSERT ON mailing_lists BEGIN
 INSERT INTO address_reservations VALUES (NEW.address,'list',NEW.id);
 INSERT INTO address_reservations VALUES (substr(NEW.address,1,instr(NEW.address,'@')-1)||'-request'||substr(NEW.address,instr(NEW.address,'@')),'list',NEW.id);
 INSERT INTO address_reservations VALUES (substr(NEW.address,1,instr(NEW.address,'@')-1)||'-owner'||substr(NEW.address,instr(NEW.address,'@')),'list',NEW.id);
 INSERT INTO address_reservations VALUES (substr(NEW.address,1,instr(NEW.address,'@')-1)||'-bounces'||substr(NEW.address,instr(NEW.address,'@')),'list',NEW.id);
END;
CREATE TRIGGER release_list AFTER DELETE ON mailing_lists BEGIN
 DELETE FROM address_reservations WHERE kind='list' AND resource_id=OLD.id;
END;
CREATE TRIGGER immutable_list_address BEFORE UPDATE OF address ON mailing_lists WHEN OLD.address<>NEW.address BEGIN
 SELECT RAISE(ABORT,'list address is immutable');
END;
CREATE TABLE masked_addresses (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 domain_id INTEGER NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
 email TEXT NOT NULL UNIQUE,
 description TEXT NOT NULL DEFAULT '',
 for_domain TEXT NOT NULL DEFAULT '',
 integration_url TEXT NOT NULL DEFAULT '',
 enabled INTEGER NOT NULL DEFAULT 1,
 created_at INTEGER NOT NULL,
 expires_at INTEGER,
 created_by TEXT NOT NULL,
 updated_at INTEGER NOT NULL
);
CREATE INDEX masked_addresses_owner ON masked_addresses(account_id, id);
CREATE TABLE masked_changes (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 kind TEXT NOT NULL DEFAULT 'masked',
 item_id INTEGER NOT NULL,
 change TEXT NOT NULL CHECK(change IN ('created','updated','destroyed'))
);
CREATE INDEX masked_changes_owner ON masked_changes(account_id,id);
CREATE TRIGGER reserve_mask AFTER INSERT ON masked_addresses BEGIN
 INSERT INTO address_reservations VALUES (NEW.email,'masked',NEW.id);
END;
CREATE TRIGGER retire_mask AFTER DELETE ON masked_addresses BEGIN
 UPDATE address_reservations SET resource_id=NULL WHERE email=OLD.email AND kind='masked';
END;
CREATE TRIGGER immutable_mask BEFORE UPDATE OF email,account_id,domain_id,expires_at ON masked_addresses
 WHEN OLD.email<>NEW.email OR OLD.account_id<>NEW.account_id OR OLD.domain_id<>NEW.domain_id OR OLD.expires_at IS NOT NEW.expires_at BEGIN
 SELECT RAISE(ABORT,'mask identity and expiry are immutable');
END;
CREATE TABLE masked_account_policy (
 account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
 max_masks INTEGER,
 extra_domains TEXT NOT NULL DEFAULT '[]'
);
-- Trusted SMTP envelope provenance is separate from untrusted MIME headers and survives
-- removal of a mask. Kept as an address so a disabled/deleted mask never falls back to primary.
CREATE TABLE message_mask_delivery (
 message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
 email TEXT NOT NULL,
 PRIMARY KEY(message_id,email)
);
CREATE TABLE masked_integration_tokens (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
 token_hash TEXT NOT NULL UNIQUE,
 name TEXT NOT NULL,
 created_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL
);

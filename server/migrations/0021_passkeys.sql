-- Passkeys as a sign-in method of their own (no password), and what the authenticator said
-- about each one when it was made.
ALTER TABLE passkeys ADD COLUMN backup_eligible INTEGER NOT NULL DEFAULT 0;  -- may be synced between devices
ALTER TABLE passkeys ADD COLUMN backed_up INTEGER NOT NULL DEFAULT 0;        -- is synced (as of its last use)
ALTER TABLE passkeys ADD COLUMN discoverable INTEGER;                        -- signs in without an address; NULL: unknown
ALTER TABLE passkeys ADD COLUMN transports TEXT NOT NULL DEFAULT '[]';       -- JSON: usb, nfc, ble, internal, hybrid
ALTER TABLE passkeys ADD COLUMN aaguid TEXT NOT NULL DEFAULT '';             -- authenticator model, hex

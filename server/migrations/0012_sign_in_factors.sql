-- Two-step sign-in (an authenticator app, passkeys, recovery codes) and app passwords.

-- The secret of an authenticator app (TOTP, RFC 6238), sealed with the server's secret key.
CREATE TABLE totp_secrets (
    account_id INTEGER PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    secret     TEXT NOT NULL,
    -- Off until the user proved the app works by entering a code.
    enabled    INTEGER NOT NULL DEFAULT 0,
    -- The time step of the last accepted code: a code is good once.
    last_step  INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
) STRICT;

-- One-time codes for when the phone is lost.
CREATE TABLE recovery_codes (
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL,
    used_at    INTEGER,
    PRIMARY KEY (account_id, code_hash)
) STRICT;

-- Passkeys and security keys (WebAuthn).
CREATE TABLE passkeys (
    id            INTEGER PRIMARY KEY,
    account_id    INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,                        -- base64url
    public_key    BLOB NOT NULL,                               -- COSE key
    sign_count    INTEGER NOT NULL DEFAULT 0,
    name          TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER
) STRICT;
CREATE INDEX passkeys_account ON passkeys(account_id);

-- Passwords for one program each (a phone's mail app, a calendar program). They work for the
-- protocols in `scopes` only, never for the web sign-in, and can be revoked one by one.
CREATE TABLE app_passwords (
    id           INTEGER PRIMARY KEY,
    account_id   INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    hash         TEXT NOT NULL UNIQUE,                         -- sha256 of the normalized password
    scopes       TEXT NOT NULL DEFAULT 'mail,dav,jmap',
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    last_ip      TEXT NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX app_passwords_account ON app_passwords(account_id);

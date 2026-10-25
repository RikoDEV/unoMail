-- Plug-in and theme packages installed from git: where each came from, the exact commit that
-- is installed and its validated manifest. Users opt in to plug-ins one by one.
CREATE TABLE packages (
    id           TEXT PRIMARY KEY,
    kind         TEXT NOT NULL CHECK (kind IN ('plugin', 'theme')),
    source_url   TEXT NOT NULL,
    git_ref      TEXT NOT NULL,
    git_commit   TEXT NOT NULL,
    manifest     TEXT NOT NULL,
    enabled      INTEGER NOT NULL DEFAULT 0,
    installed_at INTEGER NOT NULL,
    installed_by TEXT NOT NULL
) STRICT;

CREATE TABLE package_users (
    package_id TEXT NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    enabled    INTEGER NOT NULL DEFAULT 0,
    settings   TEXT NOT NULL DEFAULT '{}',
    storage    TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (package_id, account_id)
) STRICT;

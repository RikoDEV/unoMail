-- Settings administrators give a package, whether its mail hooks fail closed, and the
-- package-wide store its server module keeps.
ALTER TABLE packages ADD COLUMN admin_settings TEXT NOT NULL DEFAULT '{}';
ALTER TABLE packages ADD COLUMN fail_closed INTEGER NOT NULL DEFAULT 0;

CREATE TABLE package_kv (
    package_id TEXT NOT NULL REFERENCES packages(id) ON DELETE CASCADE,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    PRIMARY KEY (package_id, key)
) STRICT;

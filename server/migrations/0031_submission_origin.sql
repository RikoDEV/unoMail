-- The credential a scheduled submission was made with ("session:<token hash>", "app:<id>",
-- "password", "oauth"), so revoking that credential also calls off what it scheduled.
ALTER TABLE email_submissions ADD COLUMN origin TEXT NOT NULL DEFAULT '';

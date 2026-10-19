-- Memory of each bundled service (unomail, rspamd, clamav, redis, other) as a JSON object of
-- bytes; NULL for samples taken before it was recorded.
ALTER TABLE system_samples ADD COLUMN services TEXT;

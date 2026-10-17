-- Mailboxes the server keeps for every domain (postmaster@, RFC 5321 4.5.1): they cannot be
-- deleted, and receive the DMARC and TLS reports the suggested DNS records ask for.
ALTER TABLE accounts ADD COLUMN system INTEGER NOT NULL DEFAULT 0;

-- REQUIRETLS (RFC 8689): the sender demanded verified encryption on every hop.
ALTER TABLE queue ADD COLUMN require_tls INTEGER NOT NULL DEFAULT 0;

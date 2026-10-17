-- DMARC evaluations of incoming mail, counted per day, for the aggregate reports this server
-- sends to the domains that ask for them (RFC 7489 section 7.2).
CREATE TABLE dmarc_observations (
    day             INTEGER NOT NULL,
    domain          TEXT NOT NULL,                 -- the visible sender's domain (header From)
    source_ip       TEXT NOT NULL,
    envelope_from   TEXT NOT NULL,
    disposition     TEXT NOT NULL,                 -- none, quarantine, reject
    dkim            TEXT NOT NULL,                 -- aligned DKIM: pass / fail
    spf             TEXT NOT NULL,                 -- aligned SPF: pass / fail
    dkim_domain     TEXT NOT NULL,
    dkim_result     TEXT NOT NULL,
    spf_domain      TEXT NOT NULL,
    spf_result      TEXT NOT NULL,
    override_reason TEXT NOT NULL DEFAULT '',
    count           INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (day, domain, source_ip, envelope_from, disposition, dkim, spf, dkim_domain, dkim_result, spf_domain, spf_result, override_reason)
) STRICT;

-- The policy each reported domain published that day, and where it wants reports.
CREATE TABLE dmarc_policies (
    day    INTEGER NOT NULL,
    domain TEXT NOT NULL,
    policy TEXT NOT NULL,                          -- PolicyPublished as JSON
    rua    TEXT NOT NULL,                          -- JSON array of mailto: addresses
    PRIMARY KEY (day, domain)
) STRICT;

-- Delivery status notifications (RFC 3461) asked for by the sender of a queued message.
ALTER TABLE queue ADD COLUMN dsn_notify TEXT;         -- NULL: default (failures); else e.g. 'SUCCESS,FAILURE', 'NEVER'
ALTER TABLE queue ADD COLUMN dsn_ret TEXT;            -- FULL or HDRS
ALTER TABLE queue ADD COLUMN dsn_envid TEXT;
ALTER TABLE queue ADD COLUMN dsn_orcpt TEXT;
ALTER TABLE queue ADD COLUMN delay_notified INTEGER NOT NULL DEFAULT 0;

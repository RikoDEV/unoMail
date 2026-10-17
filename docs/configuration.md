# Configuration

Everything is configured through environment variables; the full list with defaults is in
[`server/src/config.rs`](../server/src/config.rs). The most relevant ones:

| Variable | Default | Purpose |
| --- | --- | --- |
| `UNOMAIL_HOSTNAME` | `localhost` | Public hostname (banner, HELO, certificate) |
| `UNOMAIL_ADMIN_EMAIL`, `UNOMAIL_ADMIN_PASSWORD` | – | First super administrator |
| `UNOMAIL_DATA_DIR` | `./data` | Database, message store, keys |
| `UNOMAIL_OUTBOUND_RELAY` | – | `host:port` smarthost for hosts with port 25 blocked; switches on *Server settings → Default SMTP route* with this server, where sign-in can be added |
| `UNOMAIL_OUTBOUND_REQUIRE_TLS` | `false` | Refuse to deliver over unverified or plaintext links |
| `UNOMAIL_GREYLIST` | `true` | Greylisting of unknown senders |
| `UNOMAIL_DNSBL_ZONES` | `zen.spamhaus.org` | DNS blocklists checked on connect; set it empty to check none. Spamhaus refuses queries through public resolvers (8.8.8.8, 1.1.1.1, most cloud providers'), so the container needs a resolver of its own; refusals are ignored and logged once |
| `UNOMAIL_ABUSEIPDB_KEY`, `UNOMAIL_ABUSEIPDB_THRESHOLD` | –, `90` | AbuseIPDB reputation check |
| `UNOMAIL_ABUSEIPDB_REPORT` | `false` | Also report abusive addresses to AbuseIPDB: password guessing (5 failed sign-ins on any protocol, category 18 Brute-Force) and SMTP abuse: mail to a spam trap, mail the content filter refuses as spam or that carries a virus, 5 unknown recipients in one connection (directory harvesting) — all category 11 Email Spam — and 3 refused relay attempts in one connection (category 15 Hacking). One report per address per 15 minutes, listing all its reasons. Reports name the protocol or behaviour, never the accounts or recipients; private and trusted addresses are never reported |
| `UNOMAIL_RSPAMD_URL` | – (image: local Rspamd) | Rspamd scanner endpoint |
| `UNOMAIL_RSPAMD_FAIL_OPEN` | `false` | Accept mail unscanned when the filter is down (default: defer with 451) |
| `UNOMAIL_CLAMAV_ADDR` | – (image: local clamd) | `host:port` of clamd for scanning complete messages |
| `UNOMAIL_VIRUS_ACTION` | `reject` | What happens to incoming mail in which the scanner finds malware: `reject` refuses it, `quarantine` delivers it to Junk with a warning (also *Server settings → Antivirus*) |
| `UNOMAIL_GRAVATAR` | `on` | Sender pictures from Gravatar, fetched by the server; `off` disables them, a URL names a compatible service |
| `UNOMAIL_RSPAMD_CONTROLLER_URL` | – (image: local Rspamd) | Trains Bayes and fuzzy storage when users move mail into or out of Junk |
| `UNOMAIL_SMTP_REQUIRE_TLS` | `false` | Refuse inbound mail on port 25 without STARTTLS |
| `UNOMAIL_ACME_CA_FILE` | – | Extra root certificate for a private or test ACME directory |
| `UNOMAIL_OUTBOUND_MAX_MESSAGES_PER_HOUR` | `300` | Per-account limit (mail sent on by Sieve `redirect` counts too); exceeding it blocks the account |
| `UNOMAIL_TRUSTED_PROXIES` | – | Networks whose `X-Forwarded-For` is trusted |
| `UNOMAIL_TRUSTED_NETWORKS` | – | Mail relays trusted like the server itself on port 25 (no SPF/DKIM/DMARC checks or greylisting) and allowed to read `/metrics` without the token. Only loopback is trusted otherwise; private addresses are **not**, because NAT in front of the server (e.g. Docker's userland proxy, used for IPv6 clients) makes every client look private. The server logs a warning when port 25 sees an untrusted private address |
| `UNOMAIL_HTTP_REDIRECT`, `UNOMAIL_COOKIE_SECURE` | `true` | Disable only behind a TLS-terminating proxy / for local development |
| `UNOMAIL_METRICS_TOKEN` | – | Bearer token for `/metrics` (otherwise loopback and `UNOMAIL_TRUSTED_NETWORKS` only). Besides counters and gauges, it serves latency histograms of HTTP requests and outbound deliveries |
| `UNOMAIL_OTLP_ENDPOINT` | – | OpenTelemetry collector (OTLP/HTTP), e.g. `http://otel-collector:4318`: spans of HTTP requests, JMAP methods, IMAP commands, received and delivered mail go to `<endpoint>/v1/traces` as JSON |
| `UNOMAIL_OTLP_HEADERS` | – | Extra headers for the collector, `key=value,key2=value2` (for an API key) |
| `UNOMAIL_OTLP_SERVICE_NAME` | `unomail` | `service.name` of the exported spans |
| `UNOMAIL_PUBLIC_URL` | `https://<hostname>` | Address users reach the web interface at (used for the single sign-on redirect) |
| `UNOMAIL_ALLOW_PRIVATE_DESTINATIONS` | `false` | Lets identity SMTP servers, the image proxy and the identity provider be on private addresses or plain HTTP. For tests and closed networks only |
| `UNOMAIL_SIEVE_PORT` | `4190` | ManageSieve (STARTTLS); `0` turns it off |
| `UNOMAIL_LMTP_PORT` | `0` (off) | LMTP for a mail server in front of this one; only clients on private networks or the SMTP allow list may connect |
| `UNOMAIL_MILTERS`, `UNOMAIL_MILTER_FAIL_OPEN` | –, `false` | Content filters speaking the milter protocol (`host:port,...`), run on incoming mail in order; unreachable ones defer mail unless fail-open |
| `UNOMAIL_ARC_TRUSTED_SEALERS` | Google, Microsoft, Yahoo, Apple, Fastmail, Zoho, Proton | Domains whose ARC seal may override a failed DMARC check (mailing lists, forwarders) |
| `UNOMAIL_S3_BUCKET`, `UNOMAIL_S3_ENDPOINT`, `UNOMAIL_S3_REGION`, `UNOMAIL_S3_ACCESS_KEY`, `UNOMAIL_S3_SECRET_KEY`, `UNOMAIL_S3_PREFIX`, `UNOMAIL_S3_PATH_STYLE` | – | Keep message contents in an S3-compatible bucket instead of `<data>/blobs` |
| `UNOMAIL_ENCRYPT_MAIL` | `false` | Encrypt stored message contents with the key in `<data>/blob.key` |
| `UNOMAIL_BACKUP_DIR` or `UNOMAIL_BACKUP_S3_*` | – | Where daily backups go: a directory, or a bucket (same variables as above with `BACKUP_S3_`) |
| `UNOMAIL_BACKUP_HOUR`, `UNOMAIL_BACKUP_KEEP` | `3`, `7` | Hour (UTC) of the daily backup, and how many snapshots to keep |

The settings for greylisting, size and recipient limits, blocklists, TLS requirements, sending
limits, MTA-STS and DANE checks, TLS and DMARC reports, and how long Trash and Junk keep mail
(30 days by default; 0 keeps it) can also be changed at runtime under **Administration →
Server settings**; those changes are stored in the database and override the environment.
The same page has settings with no environment variable:

- *Spam and reputation:* spam checks for incoming and outgoing mail (each can be switched
  off), a subject mark such as `[SPAM]` from a chosen content-filter score, and quarantine
  (delivery to Junk) of mail from connections that made three or more protocol errors or come
  from an address with a bad karma record.
- *Antivirus:* virus scanning of incoming and outgoing mail, quarantine instead of refusal,
  and refusal of executable attachments.
- *Default SMTP route:* a switch to hand all outgoing mail to another server (`host:port`),
  and a second switch to sign in to it with a user name and password (stored encrypted, never
  shown again; port 465 uses TLS, other ports STARTTLS).
- *Sending mail:* the strict check that the `From` header of submitted mail is one of the
  sender's addresses (on by default).
- *Privacy* of submitted mail: removal of `X-*` headers and of `User-Agent`, and whether the
  last `Received:` header names the client (off) or `localhost` (on, the default).
- *Storage:* how long the delivery and audit logs (90 days) and the daily statistics (400 days)
  are kept.

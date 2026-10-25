# Configuration

The server is configured with environment variables. Defaults are in
[`server/src/config.rs`](../server/src/config.rs), and
[`docker-compose.yml`](../docker-compose.yml) lists the common ones. Some settings can also
be changed at runtime, see [Runtime settings](#runtime-settings).

## Basics

| Variable | Default | Description |
| --- | --- | --- |
| `UNOMAIL_HOSTNAME` | `localhost` | Public hostname (banner, HELO, certificate) |
| `UNOMAIL_ADMIN_EMAIL` | – | First super administrator |
| `UNOMAIL_ADMIN_PASSWORD` | random, logged once | Password for that administrator |
| `UNOMAIL_DATA_DIR` | `./data` | Database, messages, keys |
| `UNOMAIL_PUBLIC_URL` | `https://<hostname>` | Web address, used for SSO redirects |
| `UNOMAIL_SESSION_TTL` | `43200` | Web session lifetime (seconds) |
| `UNOMAIL_GRAVATAR` | `on` | `on`, `off`, or URL of a compatible service |

## Network

| Variable | Default | Description |
| --- | --- | --- |
| `UNOMAIL_BIND` | `0.0.0.0` | Listen address |
| `UNOMAIL_SMTP_PORT` | `25` | Inbound SMTP |
| `UNOMAIL_SUBMISSION_PORT` | `587` | Submission (STARTTLS) |
| `UNOMAIL_SMTPS_PORT` | `465` | Submission (TLS) |
| `UNOMAIL_IMAPS_PORT` | `993` | IMAP (TLS) |
| `UNOMAIL_IMAP_PORT` | `143` | IMAP (STARTTLS) |
| `UNOMAIL_POP3S_PORT` | `995` | POP3 (TLS) |
| `UNOMAIL_SIEVE_PORT` | `4190` | ManageSieve; `0` disables |
| `UNOMAIL_LMTP_PORT` | `0` | LMTP; trusted networks only |
| `UNOMAIL_HTTP_PORT` | `80` | HTTP and ACME |
| `UNOMAIL_HTTPS_PORT` | `443` | HTTPS |
| `UNOMAIL_PUBLIC_HTTPS_PORT` | HTTPS port | External HTTPS port, if remapped |
| `UNOMAIL_HTTP_REDIRECT` | `true` | Redirect HTTP to HTTPS |
| `UNOMAIL_COOKIE_SECURE` | `true` | `false` only for local development |
| `UNOMAIL_TRUSTED_PROXIES` | – | CIDRs whose `X-Forwarded-For` is trusted |
| `UNOMAIL_TRUSTED_NETWORKS` | – | CIDRs of relays that skip sender checks and may read `/metrics` |
| `UNOMAIL_ALLOW_PRIVATE_DESTINATIONS` | `false` | Allow private addresses for outbound HTTP and SMTP (testing only) |
| `UNOMAIL_PACKAGES_ALLOW_LOCAL` | `false` | Allow installing packages from local `file://` repositories (testing only) |

> [!WARNING]
> Don't add Docker or NAT networks to `UNOMAIL_TRUSTED_NETWORKS`: every client would appear
> to come from them.

## Certificates

| Variable | Default | Description |
| --- | --- | --- |
| `UNOMAIL_ACME_DIRECTORY` | Let's Encrypt | ACME directory URL |
| `UNOMAIL_ACME_CA_FILE` | – | Extra root CA for a private ACME server |
| `UNOMAIL_ACME_DNS_WAIT` | `20` | Seconds to wait for DNS-01 propagation |

## Inbound mail

| Variable | Default | Description |
| --- | --- | --- |
| `UNOMAIL_MAX_MESSAGE_SIZE` | `52428800` | Bytes |
| `UNOMAIL_MAX_RECIPIENTS` | `100` | Per message |
| `UNOMAIL_SMTP_REQUIRE_TLS` | `false` | Require STARTTLS on port 25 |
| `UNOMAIL_GREYLIST` | `true` | Greylist unknown senders |
| `UNOMAIL_GREYLIST_DELAY` | `60` | Seconds |
| `UNOMAIL_DNSBL_ZONES` | `zen.spamhaus.org` | Comma-separated; empty disables |
| `UNOMAIL_ARC_TRUSTED_SEALERS` | major providers | Domains whose ARC seal can override DMARC |
| `UNOMAIL_ABUSEIPDB_KEY` | – | Enables AbuseIPDB lookups |
| `UNOMAIL_ABUSEIPDB_THRESHOLD` | `90` | Score at which connections are refused |
| `UNOMAIL_ABUSEIPDB_REPORT` | `false` | Report brute force and spam sources |

> [!NOTE]
> Spamhaus refuses queries through public resolvers. Give the container its own resolver.

## Filtering

| Variable | Default | Description |
| --- | --- | --- |
| `UNOMAIL_RSPAMD_URL` | image: local | Rspamd worker |
| `UNOMAIL_RSPAMD_CONTROLLER_URL` | image: local | Rspamd controller (training) |
| `UNOMAIL_RSPAMD_SOCKET` | image: set | Unix socket for the worker |
| `UNOMAIL_RSPAMD_CONTROLLER_SOCKET` | image: set | Unix socket for the controller |
| `UNOMAIL_RSPAMD_PASSWORD` | – | Controller password |
| `UNOMAIL_RSPAMD_FAIL_OPEN` | `false` | Accept unscanned mail when Rspamd is down |
| `UNOMAIL_MILTERS` | – | `host:port,...`, run in order |
| `UNOMAIL_MILTER_FAIL_OPEN` | `false` | Accept mail when a milter is down |
| `UNOMAIL_CLAMAV_ADDR` | image: local | clamd `host:port` |
| `UNOMAIL_VIRUS_ACTION` | `reject` | `reject` or `quarantine` |
| `CLAMAV_ENABLED` | `true` | Image only. Needs more than 1 GB RAM. |

## Outbound mail

| Variable | Default | Description |
| --- | --- | --- |
| `UNOMAIL_OUTBOUND_RELAY` | – | Smarthost `host:port` |
| `UNOMAIL_OUTBOUND_REQUIRE_TLS` | `false` | Never send without verified TLS |
| `UNOMAIL_OUTBOUND_MAX_MESSAGES_PER_HOUR` | `300` | Per account; exceeding blocks the account |
| `UNOMAIL_OUTBOUND_MAX_RECIPIENTS_PER_HOUR` | `1000` | Per account |
| `UNOMAIL_QUEUE_MAX_AGE` | `432000` | Seconds before undeliverable mail bounces |

## Storage and backups

| Variable | Default | Description |
| --- | --- | --- |
| `UNOMAIL_S3_BUCKET` | – | Store messages in S3 instead of `<data>/blobs` |
| `UNOMAIL_S3_ENDPOINT`, `_REGION`, `_ACCESS_KEY`, `_SECRET_KEY`, `_PREFIX`, `_PATH_STYLE` | – | S3 connection |
| `UNOMAIL_ENCRYPT_MAIL` | `false` | Encrypt message contents with `<data>/blob.key` |
| `UNOMAIL_BACKUP_DIR` | – | Backup directory |
| `UNOMAIL_BACKUP_S3_*` | – | Backup bucket (same keys as `UNOMAIL_S3_*`) |
| `UNOMAIL_BACKUP_HOUR` | `3` | UTC hour |
| `UNOMAIL_BACKUP_KEEP` | `7` | Snapshots kept |

## Monitoring

| Variable | Default | Description |
| --- | --- | --- |
| `UNOMAIL_METRICS_TOKEN` | – | Bearer token for `/metrics` |
| `UNOMAIL_OTLP_ENDPOINT` | – | OTLP/HTTP collector, e.g. `http://otel-collector:4318` |
| `UNOMAIL_OTLP_HEADERS` | – | `key=value,...` |
| `UNOMAIL_OTLP_SERVICE_NAME` | `unomail` | Span `service.name` |
| `UNOMAIL_LOG` | `info` | Log filter, e.g. `info,unomail=debug` |
| `UNOMAIL_LOG_FORMAT` | text | `json` for structured logs |

## Internal

Set by the image or used in tests.

| Variable | Description |
| --- | --- |
| `UNOMAIL_WEB_DIR` | Built web client; without it only the API is served |
| `UNOMAIL_ABUSEIPDB_URL`, `UNOMAIL_CLOUDFLARE_API_URL` | API base URLs, overridden in tests |
| `UNOMAIL_SMIME_OUT` | Output directory for the S/MIME interoperability test |

## Runtime settings

**Administration → Server settings** overrides the environment for greylisting, limits,
blocklists, TLS policy, MTA-STS, DANE, reports and Trash/Junk retention (default 30 days).
It also has settings with no variable:

| Section | Settings |
| --- | --- |
| Spam and reputation | Inbound/outbound checks, `[SPAM]` subject tag, quarantine of bad-karma senders |
| Antivirus | Inbound/outbound scanning, quarantine, executable attachment refusal |
| Default SMTP route | Relay host and credentials |
| Sending | Require `From` to match the sender (on) |
| Privacy | Strip `X-*` and `User-Agent`; hide the client in `Received:` (on) |
| Storage | Log retention (90 days), statistics retention (400 days) |

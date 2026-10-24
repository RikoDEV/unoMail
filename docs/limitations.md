# Known limitations

## Architecture

- Single node on SQLite. Clustering and PostgreSQL are not supported.
- OpenTelemetry exports traces only. Metrics are on `/metrics`, logs on stdout.

## Protocols

| Area | Limitation |
| --- | --- |
| POP3 | No single sign-on tokens |
| ManageSieve, LMTP | SASL `PLAIN` only |
| Milters | Inbound only; no `ADDRCPT`/`DELRCPT` |
| ARC | Only trusted sealers can override DMARC |
| REQUIRETLS | Not available from the web client; bounces are sent without it |
| SMTPUTF8 | Bounces when the receiving server lacks it |
| IMAP search | Body index covers the first 200,000 characters |
| IMAP import | Source must use TLS or STARTTLS |

## Calendars and contacts

- CalDAV and CardDAV use Basic auth; SSO tokens are not accepted.
- No server-side scheduling (RFC 6638) and no reminder e-mails.
- Sharing and free/busy are limited to the same domain.
- CardDAV has no contact groups.
- JMAP calendars cover a subset of JSCalendar and only your own calendars. To-dos are CalDAV only.
- JMAP push announces mail changes only.

## Encryption

| Feature | Limitation |
| --- | --- |
| OpenPGP | Subject and addresses aren't encrypted. Clear-signed mail isn't verified. Can't queue offline. |
| OpenPGP at rest | Applies to mail received after enabling it |
| S/MIME | RSA keys only. No CRL/OCSP checks. The server holds the private key. |
| BIMI | No revocation or Certificate Transparency checks |
| DNS-01 | Cloudflare only |

## Spam filtering

- The built-in filter has no public suffix list.
- The personal filter starts after 10 spam and 10 wanted messages.
- Fuzzy training applies after about 15 seconds.

## Web client

- Offline mode: folder list, first page of each folder, last 30 conversations.
- Shared folders: JMAP `/changes` covers your own folders only.
- Server messages (errors, bounces, `Re:`/`Fwd:`) are English only.
- Reminders and notifications need the browser. Web Push goes through the browser vendor.
- Gravatar receives a hash of the sender's address. Set `UNOMAIL_GRAVATAR=off` to disable it.
- Mailing lists have no archive or digests.
- Snooze and scheduled send are checked every 30 and 2 seconds.

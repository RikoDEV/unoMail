<div align="center">

# unoMail

**A complete, self-hosted mail server in a single container.**

SMTP, IMAP, POP3, JMAP, CalDAV and CardDAV, a modern web client, an admin panel,
and built-in spam and virus filtering. Written in Rust and React.

[![CI](https://github.com/RikoDEV/unoMail/actions/workflows/ci.yml/badge.svg)](https://github.com/RikoDEV/unoMail/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/RikoDEV/unoMail?include_prereleases&sort=semver)](https://github.com/RikoDEV/unoMail/releases)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue.svg)](LICENSE)

[Quick start](#quick-start) · [Features](#features) · [Documentation](#documentation) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

| <img width="2560" height="1308" alt="chrome_8qYBMqJqk8" src="https://github.com/user-attachments/assets/c94b102f-faa5-4527-8fe9-5d6b117597aa" /> | <img width="2560" height="1308" alt="chrome_uCfniMMI6q" src="https://github.com/user-attachments/assets/016033c0-91f9-4a8b-b54c-3c2a50deafe4" />  | <img width="2559" height="1304" alt="chrome_sbYsQllvUS" src="https://github.com/user-attachments/assets/490a9373-63c5-423a-8e89-c5c266680307" /> | <img width="2560" height="1308" alt="chrome_MJLOfmXXLU" src="https://github.com/user-attachments/assets/5b47c808-c302-426f-a475-e90a45403226" /> |
|---|---|---|---|
| <img width="2560" height="1308" alt="chrome_8RIEgoK5CD" src="https://github.com/user-attachments/assets/f27b2618-6dd5-442b-9bd3-35dbca8b9464" /> | <img width="2560" height="1308" alt="chrome_4rjY4rFzDj" src="https://github.com/user-attachments/assets/fec91be4-155b-4c2c-8662-181a071c0103" /> | <img width="2560" height="1308" alt="chrome_1pSjcGWGT0" src="https://github.com/user-attachments/assets/fc55d2ea-40d0-4501-8d96-33315c7b5f2e" /> | <img width="2560" height="1308" alt="chrome_MiLhp4DKPi" src="https://github.com/user-attachments/assets/ae88d6c9-4803-4d6e-8fdc-59cdbb2b398b" /> |

</div>

---

## Features

**Mail server**
- SMTP with DKIM signing, SPF/DKIM/DMARC/ARC verification, SRS, DSN, MTA-STS and DANE
- IMAP4rev1 and IMAP4rev2 (IDLE, CONDSTORE/QRESYNC, ACL, QUOTA, SORT/THREAD, BINARY, COMPRESS…), POP3, ManageSieve, LMTP
- JMAP (RFC 8620/8621) including WebSocket push, delayed send and undo, plus JMAP for
  quotas, Sieve scripts, contacts and calendars
- REQUIRETLS (RFC 8689) for mail that must never travel unencrypted
- Internationalized addresses (SMTPUTF8) for mailboxes, aliases and recipients
- CalDAV and CardDAV for Thunderbird, Apple Calendar/Contacts, DAVx⁵ and others
- Automatic Let's Encrypt certificates (HTTP-01 and Cloudflare DNS-01)

**Web client**
- Conversations, inbox categories, labels, snooze, scheduled send and undo send
- Condensed or expanded message list with quick actions, drag and drop and bulk selection
- Gmail-style search operators, filters (Sieve), templates, signatures and identities
- Out-of-office replies, read receipts and one-click unsubscribe
- On-demand AI summaries and translations with administrator-configured models
- Calendar with invitations, sharing, reminders and tasks; address book with groups and vCard import/export
- Shared and global folders with per-right access control
- Sender details and BIMI logos, warnings for deceptive links, blocked remote images,
  and previews for images, text and PDF attachments
- OpenPGP and S/MIME, offline mode, Web Push notifications, several accounts at once
- Passkeys, TOTP two-step sign-in, app passwords and OpenID Connect single sign-on
- English and Polish interface, skins and a plug-in API; usable on small screens

**Administration**
- Domains with DNS record checks and DKIM key management, mailboxes, aliases and
  `postmaster@` mailboxes; domain administrators confined to their own domains
- Mailbox import over IMAP or from a Maildir
- Dashboard with daily and live traffic charts, queue, delivery, system and audit logs
- TLS (RFC 8460) and DMARC aggregate reports, received and sent
- Mailing lists with moderation, webhooks, LDAP lookups, milters, skins and plug-ins
- AI model management for OpenAI-compatible providers, Anthropic, Gemini and local Ollama

**Protection and operations**
- Rspamd, ClamAV, greylisting, DNS blocklists, karma-based auto-blocking, and a personal Bayes filter for each user
- A built-in filter for deceptive links, sender reputation (network, provider, domain),
  penalised countries and networks, and spam traps
- SMTP blacklist with user-defined, automatic and karma rules
- Automatic clean-up of Trash and Junk after a configurable number of days
- Prometheus metrics and OpenTelemetry traces
- Incremental daily backups to a directory or S3, optional encryption of stored mail, message contents in S3

## Quick start

1. Set `UNOMAIL_HOSTNAME` (the server's public name, your MX target) and `UNOMAIL_ADMIN_EMAIL`
   in [`docker-compose.yml`](docker-compose.yml), then start it:

   ```sh
   docker compose up -d --build
   docker compose logs unomail | grep -A3 "initial administrator"
   ```

   Without `UNOMAIL_ADMIN_PASSWORD`, a random administrator password is printed once on first start.

2. Open `https://<hostname>/`, sign in, and go to **Administration**:
   1. **Domains**: add your domain and publish the DNS records shown (MX, SPF, DKIM, DMARC, PTR).
   2. **Certificates**: request a Let's Encrypt certificate or upload your own
      (a self-signed one is used until then).
   3. **Mailboxes**: create accounts. **Mailboxes → Import** can copy existing mail over IMAP
      or from a Maildir in `/data/unomail/import/<name>`.

| Port | Service |
| --- | --- |
| 25 | SMTP |
| 465, 587 | Submission (TLS, STARTTLS) |
| 993, 143 | IMAP (TLS, mandatory STARTTLS) |
| 995 | POP3 over TLS |
| 4190 | ManageSieve |
| 80, 443 | Web, ACME |

All state lives in the `/data` volume. ClamAV needs more than 1 GB of RAM; set
`CLAMAV_ENABLED=false` on small hosts. LMTP is off unless `UNOMAIL_LMTP_PORT` is set.

Prebuilt binaries (Linux x86_64 and ARM64) are attached to each [GitHub release](https://github.com/RikoDEV/unoMail/releases).

## Documentation

| Guide | Contents |
| --- | --- |
| [Configuration](docs/configuration.md) | Environment variables and runtime server settings |
| [Web client](docs/web-client.md) | Everything the webmail, calendar and address book can do |
| [Administration](docs/administration.md) | Integrations, mailing lists, dashboard, blacklist, backups and restore |
| [Mail programs](docs/mail-programs.md) | Passkeys and app passwords, IMAP/SMTP/JMAP details, CalDAV and CardDAV setup |
| [Security model](docs/security-model.md) | How authentication, sessions, storage and transport are protected |
| [Known limitations](docs/limitations.md) | What is not supported (yet) |
| [Development](docs/development.md) | Running tests and the hot-reload dev setup |

## Architecture

| Part | Technology | Location |
| --- | --- | --- |
| Mail server and API | Rust (Tokio, Axum, rustls, SQLite) | [`server/`](server) |
| Web client and admin panel | React, Vite, MUI | [`web/`](web) |
| Spam and virus filtering | Rspamd, ClamAV, Redis (inside the container) | [`docker/`](docker) |
| End-to-end tests | Playwright | [`e2e/`](e2e) |

unoMail runs as a single node on SQLite; message contents can live in S3.

## Contributing

Bug reports and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
Please report security issues privately as described in [SECURITY.md](SECURITY.md).

## License

unoMail is licensed under the [GNU Affero General Public License v3.0](LICENSE).

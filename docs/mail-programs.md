# Mail programs, calendars and contacts

## Connection settings

| Service | Host | Port | Security |
| --- | --- | --- | --- |
| IMAP | `<hostname>` | 993 / 143 | TLS / STARTTLS |
| POP3 | `<hostname>` | 995 | TLS |
| SMTP submission | `<hostname>` | 465 / 587 | TLS / STARTTLS |
| ManageSieve | `<hostname>` | 4190 | STARTTLS |
| CalDAV, CardDAV | `https://<hostname>/dav/` | 443 | TLS |
| JMAP | `https://<hostname>/.well-known/jmap` | 443 | TLS |

User name: the full e-mail address. Password: the account password, or an
[app password](#two-step-sign-in) when two-step sign-in is on.

### Thunderbird for Android by QR code

**Settings → Security → Thunderbird on your phone** shows a QR code in Thunderbird's
[export format](https://github.com/thunderbird/thunderbird-android/blob/main/feature/migration/qrcode/qr-code-format.md).
In Thunderbird for Android choose **Import settings → Scan QR code**: the account is added with
IMAP (993, TLS) and SMTP (465, TLS). The code carries the account password, after it is
confirmed, or, with two-step sign-in on, a new app password with mail access (from the dialog
that shows it). The code is drawn in the browser and never stored; anyone who sees it can sign in.

## Signing in

### Passkeys

Settings → Security → Add a passkey. A passkey replaces both the password and the second
step. The web client must be opened by host name, not IP address.

### Two-step sign-in

Settings → Security. Supports TOTP, passkeys and recovery codes. With it on, mail programs
need an **app password**, scoped to mail, calendars and contacts, or JMAP. Single sign-on
replaces only the password; the second step is still required.

## Protocols

### IMAP

IMAP4rev1 and IMAP4rev2. Extensions: `IDLE`, `MOVE`, `UIDPLUS`, `CONDSTORE`, `QRESYNC`,
`ACL`, `SPECIAL-USE`, `QUOTA`, `SORT`, `THREAD=ORDEREDSUBJECT`, `THREAD=REFERENCES`,
`ESEARCH`, `LIST-EXTENDED`, `LIST-STATUS`, `STATUS=SIZE`, `BINARY`, `COMPRESS=DEFLATE`.

### SMTP

Extensions: `DSN`, `CHUNKING`, `SIZE`, `8BITMIME`, `SMTPUTF8`, `PIPELINING`, `REQUIRETLS`.

- Outbound STARTTLS is opportunistic unless DANE, MTA-STS or the *Require verified TLS for outgoing mail* server setting requires it.
- `REQUIRETLS` messages bounce if no verified TLS path exists.
- `TLS-Required: No` delivers even when the receiver's TLS policy fails.
- Mail forwarded through an alias is ARC-sealed.

### JMAP

RFC 8620/8621, WebSocket (RFC 8887), Web Push, `EmailSubmission` with delayed send, `MDN/send`,
`Quota`, `SieveScript`, `AddressBook`/`ContactCard` and `Calendar`/`CalendarEvent`.

### ManageSieve

RFC 5804. Edits the same scripts as Settings → Filters.

## Calendars and contacts

Works with Thunderbird, Apple Calendar and Contacts, DAVx⁵ and other CalDAV/CardDAV clients.
Use the server URL above; discovery via `/.well-known/caldav` and `/.well-known/carddav`.

| Resource | URL |
| --- | --- |
| Calendar | `/dav/calendars/<address>/<calendar>/` (shown under Calendar → Sync with other apps) |
| Address book | `/dav/addressbooks/<address>/contacts/` |
| Shared calendar | `shared-<id>` in the calendar home |

- `GET` on a calendar URL returns the whole calendar as iCalendar.
- Events and cards are stored as sent. Edits from the web client change only the edited fields.
- Supported reports: `calendar-query`, `calendar-multiget`, `free-busy-query`,
  `addressbook-query`, `addressbook-multiget`, `sync-collection`.
- Floating times use the time zone of the browser that last used the web client.

### Invitations

Server-side scheduling (RFC 6638) isn't offered, so calendar programs send invitations by mail
themselves. Incoming replies, updates and cancellations are applied automatically when the
sender is verified (a local user, or DMARC passed). New invitations are never added
automatically.

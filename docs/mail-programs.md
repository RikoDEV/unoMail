# Mail programs, calendars and contacts

## Signing in

- **Passkeys** (Settings → Security → Add a passkey) sign in without an address or password:
  the browser offers them in the address field's autofill, or behind *Sign in with a
  passkey*. They are made discoverable and unlocked by the device's PIN or biometrics, so a
  passkey counts as both factors; after a password it also serves as the second step. The
  list shows whether each one is synced across devices; passkeys can be renamed, and removing
  one tells the browser to stop offering it (where the browser supports the Signal API).
  Passkeys need the web client to be reached by a host name (not an IP address).
- **Two-step sign-in** (Settings → Security): an authenticator app (TOTP), passkeys
  (WebAuthn) and one-time recovery codes. With it on, mail programs sign in with **app
  passwords** (each limited to mail, calendars and contacts, or JMAP) instead of the account
  password. Sign-in through the identity provider (single sign-on) replaces the password only:
  a second step set up here is still asked for. Adding a passkey or an app password, and
  turning a factor off, asks for the password.

## Protocols

- **IMAP** extensions besides the basics: `IDLE`, `MOVE`, `UIDPLUS`, `CONDSTORE`, `QRESYNC`,
  `ACL`, `SPECIAL-USE`, `QUOTA`, `SORT`, `THREAD=ORDEREDSUBJECT`, `THREAD=REFERENCES`,
  `ESEARCH`, `LIST-STATUS` and `COMPRESS=DEFLATE`.
- **ManageSieve** (RFC 5804, port 4190) manages the filter scripts of the web client's Filters
  page from Thunderbird, Roundcube, K-9 and others.
- **JMAP** (RFC 8620/8621) at `/.well-known/jmap`, including JMAP over WebSocket (RFC 8887,
  with push), push subscriptions (Web Push with VAPID), `EmailSubmission` with delayed release
  and undo, and `MDN/send`.
- **SMTP** offers `DSN` (RFC 3461: `NOTIFY`, `RET`, `ENVID`, `ORCPT`; delay, relay and
  delivery notices, passed on to receivers that support them), `CHUNKING` (`BDAT`), `SIZE`,
  `8BITMIME`, `SMTPUTF8` and `PIPELINING`. Mail forwarded through an alias is sealed with ARC.
  Outgoing mail follows RFC 5321 towards other servers: MX hosts of equal preference are
  tried in random order, a server without EHLO is greeted with HELO, 8-bit mail is announced
  with `BODY=8BITMIME` (or converted to quoted-printable for a server without it, which
  breaks a DKIM signature over the body, as with other converting servers), and a domain that
  does not exist bounces at once instead of after the retry period. STARTTLS is
  opportunistic (RFC 7435): when a server's encryption cannot be set up, the mail goes
  without it, unless DANE, an enforced MTA-STS policy or `UNOMAIL_OUTBOUND_REQUIRE_TLS`
  demands encryption. The submission ports accept the `AUTH=` parameter of `MAIL FROM`.

## Calendars and contacts (CalDAV, CardDAV)

Thunderbird, Apple Calendar and Contacts, DAVx⁵ on Android and other CalDAV/CardDAV clients
synchronise with the calendars and the address book of the web client. Add an account with:

| | |
|---|---|
| Server | `https://<hostname>/dav/` (also found through `/.well-known/caldav` and `/.well-known/carddav`) |
| User name | the full e-mail address |
| Password | the account's password, or an app password with two-step sign-in |

Programs that want the address of one calendar find it in the web client under
**Calendar → Sync with other apps**: `https://<hostname>/dav/calendars/<address>/<calendar>/`.
A plain `GET` on that address returns the whole calendar as one iCalendar file.

Supported: discovery (`current-user-principal`, `calendar-home-set`), `PROPFIND`, `MKCALENDAR`,
`PROPPATCH` (name, colour, description), `GET`/`PUT`/`DELETE` with entity tags
(`If-Match`, `If-None-Match`), the reports `calendar-query` (with time ranges),
`calendar-multiget`, `free-busy-query` and `sync-collection` (RFC 6578), and CTags. Events
and to-dos are stored exactly as the program sent them; when an event is edited in the web
client only the edited properties change, so alarms, attendees and vendor extensions survive.

Calendars shared by colleagues appear in the calendar home as `shared-<id>`; those shared
for reading only say so in their privileges and refuse changes.

Times that name no time zone ("floating" times) are wall-clock times: they are read in the
zone of the browser the account last used the web client with (UTC until then).

### Invitations

The server does not announce scheduling of its own (RFC 6638) to calendar
programs, so they send their invitations by mail themselves, as they do with any plain CalDAV
server. Whatever arrives by mail is processed on delivery for every account: an answer
updates the guest's status on the organizer's event (only the sender's own answer counts),
a cancellation from the organizer removes the event, an update replaces it. This happens only
when the sender is known to be genuine (a user of this server, or a domain whose DMARC check
passed); anything else waits in the inbox for the user to act on. A new invitation is never
added by itself. Invitations written in a colleague's shared calendar carry a `Sender:` field
naming who wrote them, and count against that person's sending limits.

### Contacts

The address book is at `/dav/addressbooks/<address>/contacts/` with
`addressbook-query`, `addressbook-multiget` and `sync-collection`. A card stored by a program
is kept byte for byte, photo and postal addresses included. When the web client later changes
a field it knows (name, e-mail, phone, organization, notes), only that property is rewritten.
Cards need no e-mail address, and several may share one.

Sign-in goes through the same check as every other protocol, including the limits on failed
attempts. Each user reaches their own calendars only.

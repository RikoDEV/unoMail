# Known limitations

- **BIMI:** mark certificates are checked for purpose, domain, validity period and a chain
  to a trusted root; revocation and Certificate Transparency are not. The DigiCert Verified
  Mark root ships with the server; further roots (Entrust and others) go into
  `<data>/bimi-roots/` as PEM files. The organizational domain is found by walking up the
  labels, not from the public suffix list. Logos without a certificate are shown too, without
  the check mark. Verification against a live domain's certificate has not been exercised
  in the automated tests (they use generated certificates).
- **Sender warnings** rest on what the server recorded when a message arrived. Mail that was
  imported, or delivered from a private address (which is not checked), says "not checked".
- **Gravatar** receives a hash of the sender's address from the server; set
  `UNOMAIL_GRAVATAR=off` to avoid that.
- **DNS-01 certificates** use the Cloudflare API only. The flow is verified end to end against
  Pebble with real DNS validation, with a local stand-in for the Cloudflare API
  (`server/tests/acme_live.rs`); a run against a real Cloudflare zone needs an API token.
- **Fuzzy training** takes effect after the storage sync interval (15 seconds in the image).
- **Offline mode** keeps the folder list, the first page of each folder and the last 30 opened
  conversations readable, and queues stars, labels, moves, deletions and new messages
  (with attachments up to 25 MB each, kept in IndexedDB) until the connection returns. The
  queue lives in the browser's storage; signing out clears it after a confirmation.
- **Mailbox import over IMAP** needs TLS on the source server, either implicit (port 993) or
  STARTTLS (port 143). Unencrypted sources are refused on purpose.
- **Calendars and contacts:** CalDAV and CardDAV use HTTP Basic over TLS with the account
  password or an app password (required once two-step sign-in is on); single sign-on tokens
  are not accepted there.
  Invitations are mailed for changes made in the web client; calendar programs mail their
  own (see [Mail programs](mail-programs.md#invitations)). Reminders appear only while the web client is open in a browser; the
  server sends no reminder mail. Free/busy times and sharing are limited to mailboxes of the
  same domain. With "may edit", a colleague changes events in your name: guests get mail
  from you. An invitation is answered from its message; a recurring task shows as one task.
  Contact groups are not offered over CardDAV, and its searches match text anywhere in a card.
  Sharing, free/busy over CalDAV and CardDAV were tested with scripted clients, not yet with
  every calendar program.
- **Spell checking** relies on the dictionaries of the user's browser; the server ships none.
- **Translations** cover the web client and the administration pages. Messages produced by
  the server (API errors, SMTP replies, automatic replies, notices it mails) stay in English,
  and so do the `Re:`/`Fwd:` subject prefixes, which mail programs rely on.
- **Personal spam filter:** with few messages learned its decisions are rough, so it waits
  for ten of each kind; until then only Rspamd and blocked senders file mail away. Its
  statistics grow with every message learned and are not pruned.
- **OpenPGP:** the subject and the addresses are not encrypted (mail transport needs them).
  Messages are signed only together with encryption, and only while the key is unlocked;
  clear-signed mail from others is displayed without verifying its signature. Encrypted
  messages cannot be queued offline.
- **Shared folders:** the web client refreshes a shared folder on the owner's changes while
  it is open, but JMAP `/changes` for third-party clients covers the user's own folders only.
  Colleagues can be named from the same domain only.
- **Single sign-on tokens** are accepted on IMAP and SMTP submission, not on POP3.
- **LDAP** is used for recipient suggestions only (read-only); contacts are not synchronised.
- **Internationalized addresses** can only be delivered to servers that support SMTPUTF8;
  otherwise the message bounces with an explanation.
- **Dependency audit:** `./audit.sh` (also a weekly CI job). Some advisories are ignored, each with a
  written justification in `server/.cargo/audit.toml`: the `rsa` crate's timing side channel,
  which needs a decryption oracle that the S/MIME code does not offer (only the key's owner
  causes, and sees, a decryption), and three `zip` 8 extraction flaws in a copy pulled in by
  `mail-auth`, which reads report archives in memory and never extracts to disk.
- **One server, one database.** unoMail runs as a single node on SQLite. Message contents can
  live in S3 and backups go off-site, but several servers sharing one mail store (and a
  PostgreSQL database) are not supported: that would need a different data layer.
- **S/MIME:** RSA certificates only (ECDSA signatures from others are verified, but cannot be
  imported for your own use). Revocation (CRL/OCSP) is not checked. Trusted issuers are the
  web PKI roots plus `<data>/smime-roots/`; certificates from other authorities show as
  "unverified". The server holds the private key, so S/MIME protects mail in transit and
  against other servers, not against this server's operator.
- **OpenPGP encryption at rest** covers mail delivered after it is switched on, not messages
  you save or send yourself; the web client can read it only once the private key is unlocked.
- **Web Push** goes through the browser maker's push service (Google, Mozilla, Apple); only
  an encrypted "something changed" notice is sent, never content. Browsers allow it on HTTPS
  (and `localhost`) only.
- **Mailing lists** have no archive and no digests; subscribing by mail needs the list to be
  open, and moderation happens in the admin panel or from the emailed link.
- **IMAP:** `THREAD=REFERENCES` groups by the server's conversations (which follow
  `References`/`In-Reply-To`), as one chain per conversation. IMAP4rev2 is not offered.
  `SEARCH` answers `TEXT`, `BODY`, `SUBJECT`, `FROM`, `TO`, `CC` and `BCC` from the search
  index, which holds the decoded text (so base64 or quoted-printable bodies match) of the
  first 200,000 characters of the body; other `HEADER` criteria read the message itself.
- **ManageSieve and LMTP** accept SASL `PLAIN` only; LMTP is meant for a front server on the
  local network.
- **Milters** run on incoming mail only, and are not offered the `SMFIF_ADDRCPT`/`DELRCPT`
  actions.
- **ARC:** a failed DMARC check is overridden only for sealers on the trusted list; other
  seals are recorded in `Authentication-Results` but change nothing.
- **Snooze and scheduled send** are checked every 30 and 2 seconds; mail returns or leaves
  that much later at most.

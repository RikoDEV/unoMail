# Security model

The threat model and review record are in [SECURITY.md](../SECURITY.md).

- **Authentication.** Argon2id password hashes. One credential check shared by web, SMTP,
  IMAP and POP3, with uniform responses for unknown accounts and an audit log entry for
  every failure. Guessing is limited three ways per 15 minutes: 10 failures from one address
  (IPv6: one /64) whatever accounts they target, 5 for one account from one address, and 20
  for one account from anywhere. Attempts are counted before the password is checked, failed
  ones are answered with a growing delay, and repeated lockouts last four times longer each
  time, up to a day. A stranger's guesses do not lock the owner out from their own address.
- **Sessions.** Random 256-bit tokens stored only as SHA-256 hashes; `__Host-` cookie with
  `HttpOnly`, `Secure`, `SameSite=Strict`; a per-session CSRF token on every state-changing
  request; sessions are revoked on password change, reset and deactivation.
- **Authorization.** Three roles. Domain administrators are confined to their delegated
  domains and cannot see or modify administrator accounts. Every mail object lookup is scoped
  to the authenticated account, or to a folder explicitly shared with it, with each right
  (read, mark as read, flag, insert, delete, expunge, administer) checked separately. A folder
  that is not shared with an account does not exist as far as that account can tell.
- **Single sign-on.** Authorization code flow with PKCE and a state value bound to the
  browser, so a response cannot be replayed or planted. Tokens are verified with the
  provider's userinfo endpoint over TLS; a token for one user never opens another mailbox,
  and a token issued to another application never opens any; lockout and per-protocol
  switches apply as for passwords. The outcome of a failed or unfinished sign-in reaches the
  sign-in page through the server, never through the address.
- **Two-step sign-in and app passwords.** TOTP (RFC 6238), passkeys (WebAuthn, ES256/EdDSA/RS256)
  and recovery codes (stored hashed). Signing in with a passkey alone requires user
  verification and a user handle matching the credential; the challenge is single-use and
  bound to the requesting address; registration needs user verification and a discoverable
  credential; backup eligibility may not change after registration, and signature counters
  that go backwards are refused. The password alone is a first step only; with two-step
  sign-in on, mail programs need an app password, scoped to what it is for. Administrators can
  reset a mailbox's second factors.
- **Stored credentials.** Passwords the server must be able to use again (identity SMTP
  servers, the LDAP bind, the identity provider's client secret, webhook secrets), S/MIME,
  DKIM and TLS private keys, stored OpenPGP private keys and the SRS and mailing-list HMAC
  secrets are encrypted with a key kept in its own file (`secret.key`, mode 0600, repaired at
  startup if looser) next to the database, so a database copy or backup alone does not reveal
  them. Values stored in plain text by older versions are sealed at the next start.
- **Stored mail.** Message contents optionally sealed at rest (`UNOMAIL_ENCRYPT_MAIL`, key in
  `blob.key`; the database with its search index is not), and per user encrypted to their
  OpenPGP key on arrival. The server and its operator can read everything else; only OpenPGP
  mail encrypted to keys the server never holds is out of their reach. See
  [SECURITY.md](../SECURITY.md).
- **End-to-end encryption.** Encrypted mail is encrypted and decrypted in the browser; the
  server holds ciphertext and never the passphrase. Drafts of a message marked for encryption
  are not saved to the server.
- **SMTP.** No open relay; `VRFY`/`EXPN` disabled; strict CRLF handling that rejects SMTP
  smuggling; STARTTLS command-injection protection; credentials only over TLS; authenticated
  users may only send as their own address or aliases (envelope and `From` header); per-account
  sending limits with automatic blocking; DKIM signing; SPF, DKIM and DMARC verification with
  forged `Authentication-Results` headers stripped; SRS for forwards; outbound delivery refuses
  private address ranges.
- **Web.** Strict Content-Security-Policy, HSTS, no caching of API responses. HTML mail is
  sanitized with DOMPurify, stripped of remote content, and rendered in a sandboxed frame
  without script permission. Attachments are only ever served as downloads. Messages carrying
  programs (`.exe`, `.js`, `.scr`, ..., also inside ZIP archives and attached messages) are
  refused in both directions (*Server settings → Refuse executable attachments*); the
  dashboard warns when no virus scanner is configured. Remote images are
  loaded only on request and only through a server-side proxy that refuses private addresses,
  follows redirects only after re-checking them, and passes on nothing but real images.
- **TLS.** TLS 1.2 and 1.3 with AEAD suites (rustls). Certificates are validated before
  installation (key match, validity, chain order) and swapped without restarting listeners.
  Private keys (TLS, DKIM) are write-only through the API.
- **Container.** The server runs as an unprivileged user with only `CAP_NET_BIND_SERVICE`;
  Rspamd, Redis and ClamAV run under their own users and listen on loopback only.

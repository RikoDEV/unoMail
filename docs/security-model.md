# Security model

Threat model and review record: [SECURITY.md](../SECURITY.md).

## Authentication

- Argon2id password hashes. Web, SMTP, IMAP and POP3 share one credential check.
- Unknown accounts get the same response as wrong passwords. Every failure is audited.
- Second factors: TOTP, passkeys (WebAuthn) and recovery codes. App passwords are scoped.
- Single sign-on uses OpenID Connect with PKCE. Tokens must be issued to unoMail.

| Lockout (per 15 minutes) | Failures |
| --- | --- |
| One address (IPv6: /64) | 10 |
| One account from one address | 5 |
| One account from anywhere | 20 |

Repeated lockouts last four times longer each time, up to a day. Another user's failed
guesses never lock you out from your own address.

## Sessions

- 256-bit random tokens, stored as SHA-256 hashes.
- `__Host-` cookie: `HttpOnly`, `Secure`, `SameSite=Strict`.
- CSRF token on every state-changing request.
- Revoked on password change, reset or deactivation.

## Authorization

| Role | Scope |
| --- | --- |
| Super administrator | Everything |
| Domain administrator | Assigned domains; no access to administrator accounts |
| User | Own mailbox, plus folders shared with them, checked per right |

Folders that aren't shared with an account are invisible to it.

## Data at rest

| Data | Protection |
| --- | --- |
| Stored credentials, DKIM/TLS/S/MIME keys, SRS secrets | Encrypted with `secret.key` (mode 0600) |
| Message contents | Optional, `UNOMAIL_ENCRYPT_MAIL` |
| Mail for users with OpenPGP at rest | Encrypted to the user's key on arrival |
| Database and search index | Not encrypted; use disk encryption |

The operator can read all mail except OpenPGP-encrypted mail.

## Transport

- TLS 1.2 and 1.3 with AEAD ciphers only (rustls).
- Certificates are validated before installation and swapped without a restart.
- SMTP:
  - No open relay. `VRFY` and `EXPN` are disabled.
  - Strict CRLF handling, which blocks SMTP smuggling.
  - Authentication only over TLS. Senders are limited to their own addresses.
  - SPF, DKIM and DMARC are verified, and forged `Authentication-Results` headers are removed.
  - Outbound delivery to private addresses is refused.

## Web

- Strict CSP, HSTS, and no caching of API responses.
- HTML mail is sanitized with DOMPurify and shown in a sandboxed frame without scripts.
- Remote images go through a proxy that refuses private addresses.
- Attachments are served as downloads only. Executables can be refused at the server.
- OpenPGP runs in the browser; the server never sees the passphrase.

## Container

The server runs unprivileged with only `CAP_NET_BIND_SERVICE`. Rspamd, Redis and ClamAV run as
separate users and listen on loopback only.

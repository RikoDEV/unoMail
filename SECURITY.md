# unoMail security

This document is the threat model and the record of security reviews. The controls themselves
are summarised in [docs/security-model.md](docs/security-model.md); configuration is in `server/src/config.rs`.
Report vulnerabilities privately, not in a public issue: use GitHub's
[private vulnerability reporting](https://github.com/RikoDEV/unoMail/security/advisories/new)
or e-mail kontakt@riko.dev.

## 1. Assets

| Asset | Where it lives |
| --- | --- |
| Message contents and attachments | blob store (`<data>/blobs` or S3), optionally sealed (`blob.key`) |
| Message metadata, search index, contacts, calendars | SQLite database `<data>/unomail.db` (plaintext) |
| Account credentials | Argon2id hashes, app-password hashes, TOTP secrets (sealed), passkey public keys |
| Browser sessions | random tokens; only SHA-256 hashes stored; `HttpOnly` `SameSite=Strict` cookies |
| Server secrets | `secret.key` (seals third-party credentials, TOTP and S/MIME keys), `blob.key`, `vapid.key`, DKIM and TLS private keys (database) |
| Outbound reputation | DKIM keys, the server's IP addresses, the delivery queue |
| Backups | directory or bucket set by `UNOMAIL_BACKUP_*` |

## 2. Entry points and trust boundaries

| Entry point | Who reaches it | Boundary enforced by |
| --- | --- | --- |
| SMTP port 25 (MX) | anyone | no authentication offered; recipients must be local (`Relay access denied` otherwise); SPF/DKIM/DMARC/ARC verdicts added by us (skipped only for loopback and `UNOMAIL_TRUSTED_NETWORKS`), forged `Authentication-Results` removed; DNSBL, reputation, greylisting, size and recipient limits; strict CRLF (no SMTP smuggling) |
| SMTP 587/465 (submission) | users | TLS before AUTH; envelope sender and `From` must be the user's own address, alias or identity; per-account hourly limits with automatic blocking; outbound spam/virus scan |
| LMTP (off by default) | front mail server | only private networks or the allow list; relaying refused |
| IMAP 993/143, POP3 995 | users | TLS before credentials (`LOGINDISABLED` in plaintext); per-mailbox rights (ACL); literal size limits before reading |
| ManageSieve 4190 | users | STARTTLS before `AUTHENTICATE`; 1 KiB literals before sign-in, 64 KiB after |
| HTTPS web API and JMAP | users, admins | session cookie + per-session CSRF token on every state change; JMAP objects scoped to the account or shared folders; role checks (super admin, domain admin confined to delegated domains) |
| JMAP WebSocket | users | same authentication; cross-origin upgrades refused (Origin check) |
| Public pages `/lists/...`, `/.well-known/mta-sts.txt` | anyone | unguessable tokens (256-bit random, or 128-bit HMAC for unsubscribe); GET never changes anything |
| Outbound connections (SMTP delivery, image proxy, push services, MTA-STS, BIMI, report POSTs, identity provider) | the server | destinations resolved and refused when private/loopback/link-local (IPv4 and IPv6), connection pinned to the checked address, redirects re-checked, size and time limits |
| Milters, rspamd, clamd | trusted local services | configured by the operator only |
| CLI (`backup`, `restore`, `migrate-blobs`) | operator with shell access | filesystem permissions |

Attacker classes considered: unauthenticated internet clients (SMTP, HTTP, IMAP), malicious
remote mail servers and DNS zones, senders of hostile messages (HTML, MIME, attachments,
S/MIME/OpenPGP structures), authenticated malicious users, compromised accounts, and other tabs
or sites in the user's browser. A compromised server process or operator is **out of scope**:
it can read everything except OpenPGP mail encrypted to keys the server never holds.

## 3. Review of 2026-10-15

Scope: the code added since the previous review (two-step sign-in, MTA-STS/DANE/TLS-RPT, ARC,
DMARC reports, DSN, BDAT, backups, S3, encryption at rest, ManageSieve, IMAP extensions,
LMTP, milter, JMAP WebSocket and push, mailing lists, snooze, scheduled send, read receipts,
S/MIME, account switcher), plus a re-check of the mandatory controls (relay, authentication,
CSRF, rendering of hostile HTML).

### Findings (all fixed)

| # | Severity | Component | Vulnerability | Attack scenario | Fix | Verification |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | High | SMTP `BDAT` (`smtp/server.rs`) | Unchecked `received + size` with a client-chosen `size`; wraps in release builds | Unauthenticated client on port 25 announces `BDAT 18446744073709551610` after a valid RCPT; the size check passes and the server buffers without bound (memory exhaustion); debug builds panic | `chunk_fits` with `checked_add` | unit test `chunk_sizes_cannot_overflow` |
| 2 | High | DSN (`smtp/submit.rs`, `smtp/server.rs`) | Delivery notices and `RET=FULL` honoured for unauthenticated senders | Spammer sends to any local user with `MAIL FROM:<victim> RET=FULL NOTIFY=SUCCESS`: the server mails the victim a DKIM-signed notice containing the spam (backscatter/relay of content) | success notices for inbound mail only when SPF passed for the envelope sender; notices to unauthenticated senders never carry the message (headers only) | `unauthenticated_senders_cannot_turn_notices_into_backscatter` (fails without the fix) |
| 3 | Medium | rustls 0.23.45 | RUSTSEC-2026-0346 to 0349 (TLS secrets in `Debug`, ECH, Brotli allocation, key-exchange downgrade) | per advisories | upgraded to 0.23.46 | `cargo audit`: no vulnerabilities |
| 4 | Medium | S/MIME certificate collection (`smime.rs`) | Self-signed certificates kept for any `From` address | Attacker forges a signed message "from" a correspondent with their own certificate; the victim's later S/MIME-encrypted mail to that correspondent is encrypted to the attacker's key | unverified certificates are kept only when DMARC passed or a local user sent the message | `certificates_from_unauthenticated_senders_are_not_collected` |
| 5 | Medium | Read receipts (`jmap/mdn.rs`, web Reader) | Automatic receipts to an address other than the return path | A message with `Disposition-Notification-To: victim` makes users with "always send" mail third parties a DKIM-signed message carrying an attacker-chosen subject | RFC 8098 2.1: automatic receipts only when the receipt address is the return path; the server refuses other automatic requests; the web client asks instead | `read_receipts_go_out_once_when_asked_for`, unit test `automatic_receipts_only_to_the_return_path` |
| 6 | Medium | Backups (`backup.rs`) | Database snapshot stored unencrypted even with encryption at rest on | Leaked backup exposes subjects, addresses and the search index (which holds message text) | snapshot sealed with `blob.key` when encryption is on; restore requires the key | `backups_of_an_encrypted_store_are_encrypted` |
| 7 | Low | S/MIME import (`api/smime.rs`) | PKCS #12 key-derivation iterations come from the uploaded file and ran on an async worker | An authenticated user uploads a file with an enormous iteration count, tying up the runtime | runs on a blocking thread, one import at a time, 20 s limit | code review |
| 8 | Low | Push (`jmap/push.rs`) | `vapid.key` written with default permissions | Local users could read the key and impersonate the server to push services | `0600` on Unix like the other keys | code review |
| 9 | Low | Mailing lists (`lists.rs`) | Author address written into `X-Original-From`/`Reply-To` without sanitising | Header injection if the parser ever returned a line break | sanitised and stripped of angle brackets | robustness test |
| 10 | Low | Documentation | Encryption at rest described as protecting a stolen disk and backups | Operators over-trust the feature | README, module docs and this file state what is and is not covered | — |

### Checked and found sound

- No `unsafe` code in the server; no CORS layer (same-origin only); parameterised SQL throughout.
- Relay: port 25 and LMTP refuse non-local recipients before `DATA`/`BDAT`; submission requires
  TLS and authentication; sender identity enforced for envelope and `From`
  (`tests/smtp.rs`, `tests/lmtp.rs`). SRS addresses are verified before routing bounces.
- STARTTLS: pipelined commands after `STARTTLS` are refused (SMTP, IMAP, ManageSieve).
- Hostile HTML is sanitised with DOMPurify and shown in an iframe without `allow-scripts`, with
  its own CSP (`default-src 'none'`, images only from `data:`/the image proxy). The iframe keeps
  `allow-same-origin` so the page can measure its height; without script permission nothing in
  it can run. Remote content is blocked until the user asks, and then fetched by the server.
- Unsafe content (added after the review, same day): links whose text names another site,
  that hide their target behind `user@host`, point at a numeric address or use an IDN
  (`xn--`) domain are marked and ask before opening; every link shows its real target on
  hover. Attachments that run code (including `invoice.pdf.exe` and names with
  right-to-left override characters) are flagged and need a confirmation to download;
  macro documents, HTML/SVG, disk images and archives get a caution. A display name that shows
  another address or domain than the sender's is called out. The server refuses executable
  attachments (also attached messages and ZIP members) on inbound mail and on submission with
  `552 5.7.0`, switchable in *Server settings* (`block_executable_attachments`, default on).
  The dashboard and diagnostics warn when no virus scanner is configured
  (`src/security/attachments.rs`, `web/src/mail/risk.ts`, `e2e/tests/17-unsafe-content.spec.ts`).
- Personal spam filter (added after the review): statistics are per account, token hashes
  only (64-bit SHA-256 prefixes), deleted with the account. Training runs in the background
  in `BEGIN IMMEDIATE` transactions, one at a time. Mail from a correspondent is exempt and
  trains "wanted" only when DMARC passed, it was sent from this server, or this server ran no
  checks (trusted relay): a forged contact address does not get past the filter or poison it
  (`server/src/bayes.rs`, `server/tests/spam_filter.rs`).
- Passkey sign-in without a password (added after the review): options name no credentials
  (no account enumeration); the answer must carry the user verified flag and the user handle
  the credential was registered for; challenges are single-use, expire after five minutes and
  are bound to the address that asked; unknown credentials are reported as such only so the
  browser can drop them, and every failure is audited and slowed down like a wrong password
  (`server/src/api/signin.rs`, `server/tests/signin.rs`, `e2e/tests/19-passkeys.spec.ts`).
  WebAuthn is verified in-house on `ring` (no maintained Rust WebAuthn library builds without
  OpenSSL here); attestation is not checked (`none`), so the authenticator model is not proven.
- Interface translations are static files; values are interpolated without HTML escaping
  because React escapes on render, and the one place that builds HTML (the reply attribution)
  escapes the finished text.
- New public pages (`/lists/confirm|moderate|unsubscribe`) act only on POST with an unguessable
  token, escape all output, and are covered by the site CSP.
- WebSocket upgrades check `Origin`; the account switcher keeps other sessions in an `HttpOnly`,
  `SameSite=Strict` cookie, and every session keeps its own CSRF token, so a tab showing a
  stale account cannot change anything in the current one.
- Push subscription delivery, MTA-STS fetching and report POSTs use the same private-address
  checks as the image proxy, pinned to the resolved address.
- Backup and restore only read and write paths built from validated snapshot ids and hashes.
- Robustness: parsers of attacker-controlled data (ManageSieve, DSN parameters, list headers
  and commands, milter MIME split, S/MIME CMS and MIME, IMAP tokenizer, SMTP paths, header
  stripping, OpenPGP split) take ~30,000 generated hostile inputs per test run without
  panicking (`src/fuzzing.rs`; debug builds also trap integer overflow).

### Follow-up review of 2026-10-16

Scope: authentication paths end to end (password, second factors, app passwords, single
sign-on in the browser and for mail programs), trust decisions based on the client address,
HTML that reaches the application page outside the reader frame, and the HTTP response
headers.

| # | Severity | Component | Vulnerability | Attack scenario | Fix | Verification |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | High (shared identity provider) | SSO tokens (`oauth.rs`) | Mail-program tokens were only checked with the userinfo endpoint, not for the client they were issued to | Any other application the user signed into at the same provider holds an access token with the `email` scope; presented with `XOAUTH2`, it opened the mailbox | token introspection (RFC 7662) or the JWT's `aud`/`azp`/`client_id`/`cid`/`appid` must name our client id; opaque tokens that cannot be checked are refused | `mail_clients_sign_in_with_access_tokens` (`token-other-app`) |
| 2 | High (NAT deployments) | Inbound SMTP, `/metrics` (`smtp/submit.rs`, `smtp/server.rs`, `api/system.rs`) | Every private source address was trusted: no SPF/DKIM/DMARC checks, no greylisting, metrics without a token | Behind Docker's userland proxy (IPv6 clients of an IPv4 container, Docker Desktop, rootless) or a TCP load balancer, every sender appears as the bridge gateway: forged mail from any domain, including our own, arrived without a DMARC verdict and passed the personal filter as from a trusted relay | only loopback and `UNOMAIL_TRUSTED_NETWORKS` are trusted; a warning is logged when port 25 sees an untrusted private address | unit test `trusted_sources`, `health_is_public_and_metrics_are_protected` |
| 3 | Medium | TOTP setup (`api/signin.rs`) | Starting a new setup replaced the active secret with an inactive one, without the password | A stolen session switched the second factor off with one request (turning it off properly needs the password), after which IMAP accepted the bare password again | setup refuses (409) while an authenticator is active | `an_authenticator_app_guards_the_sign_in` |
| 4 | Medium | Passkey registration (`api/signin.rs`) | No password asked for | A stolen session added a passkey, which signs in on its own and survives a password change | `POST /api/me/passkeys/register/options` checks the password before handing out the challenge | `a_passkey_is_a_second_factor`, e2e `19-passkeys` |
| 5 | Medium | App passwords (`api/accounts.rs`, `api/signin.rs`, `api/auth.rs`) | Never revoked by a password reset or a reset of the second factors (contrary to section 5) | An intruder's app password kept IMAP/SMTP access after the administrator cleaned the account up | revoked by an administrator's password reset and second-factor reset (which also ends sessions); optional on the owner's own password change; administrators can no longer set their own password without the current one | `resets_revoke_app_passwords` |
| 6 | Medium | Composer (`web/src/mail/sanitize.ts`, `Composer.tsx`) | Replies and forwards put the quoted message into the application page with its `<style>` elements and positioning | A hostile message restyled the whole application or laid a full-window phishing link over it as soon as the user pressed Reply (no script: DOMPurify and CSP) | HTML for the page drops style sheets and `position`/`inset`/`top`/`left`/`z-index`/`transform`; the editor has `contain: paint` | `sanitize.test.ts` |
| 7 | Low | SSO (`api/oauth.rs`) | Sign-in through the provider skipped a second factor set up here | Whoever controls the identity at the provider skipped TOTP/passkeys | the second step is asked for after the provider's sign-in | `browser_sign_in_through_the_identity_provider` |
| 8 | Low | SSO (`oauth.rs`) | Token sign-in ignored a switched-off domain | Mailboxes of a disabled domain stayed reachable with tokens | domain must be enabled | `mail_clients_sign_in_with_access_tokens` |
| 9 | Low | Login page | The SSO error text came from the address (`?sso_error=`) | A link put arbitrary text ("call support at ...") on the sign-in page | the outcome is kept on the server and fetched once with a `SameSite=Strict` cookie | `browser_sign_in_through_the_identity_provider` |
| 10 | Low | Address checks (`security/reputation.rs`) | Non-public ranges missing: `0.0.0.0/8`, `192.0.0.0/24`, `198.18.0.0/15`, `240.0.0.0/4`, multicast, site-local, NAT64/6to4/IPv4-compatible forms of private addresses, Teredo | Outbound request checks could be steered to internal addresses through such forms where the network routes them | added; embedded IPv4 addresses are judged by themselves | unit test `private_ranges` |
| 11 | Low | HTTP headers (`api/mod.rs`) | `no-store` only on `/api` and `/jmap`; unused `frame-src blob:`; short `Permissions-Policy` | Calendars, contacts, list tokens and setup files could be kept by caches | `no-store` also on DAV, list pages and setup files; `frame-src 'self'`, `worker-src 'self'`; more features denied; `X-Permitted-Cross-Domain-Policies: none` | `responses_carry_security_headers` |

Kept as is: `style-src 'unsafe-inline'` (required by the UI toolkit's runtime styles).

### Second follow-up review of 2026-10-16

Scope: what one authenticated user can make the server do to other users or to itself:
sender identities, mail filters, calendar scheduling, delayed sending, long-lived protocol
connections, and the unauthenticated sign-in state kept in memory.

| # | Severity | Component | Vulnerability | Attack scenario | Fix | Verification |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | High | Sender identities (`api/personal.rs`, `smtp/submit.rs`) | An identity with its own SMTP server could name any address, including one hosted here, and only the first `From` address decided whether a message was relayed | Bob added `ceo@example.org` with this server's port 25 as "his provider" (no user name: no AUTH): the message reached our MX from our own address, passed SPF/DMARC and landed in colleagues' inboxes as from the CEO. Or `From: bob@example.org, ceo@example.org`: each address passed the check, the message was signed and delivered by us | identities for addresses in hosted domains must be owned, whatever server they name (stored ones are ignored); mail we sign may name only owned authors; a relay identity must be the only author | `relay_identities_cannot_claim_addresses_hosted_here` |
| 2 | High | Submission and inbound SMTP (`smtp/submit.rs`) | Several `From` (or `Sender`) fields were accepted; checks and DKIM read the last one, mail clients may show the first | `From: ceo@example.org` followed by `From: bob@example.org` passed the sender check and was signed for the domain; inbound, DMARC aligned with the attacker's `From` while the reader saw the bank's | messages with more than one `From` or `Sender` field are refused (RFC 5322 allows one) | `messages_with_two_authors_are_refused` |
| 3 | High | Sieve redirects (`smtp/delivery.rs`) | Redirects to the mailbox's own `+tag` addresses were not seen as loops, and redirected copies carried no trace of the mailbox | `redirect :copy` to `me+1@` ... `me+5@`: every copy came back, ran the script again and produced five more, stopped only by the 50-hop limit (5^50 messages) | redirects resolving to the same mailbox are skipped; copies carry `Delivered-To`, and a message that was here before is kept, not sent on | `sieve_redirects_do_not_loop_and_count_as_sending` |
| 4 | Medium | Calendar scheduling (`calendar/scheduling.rs`, `smtp/delivery.rs`) | Incoming CANCEL, REQUEST and REPLY changed calendars on the strength of an unauthenticated `From` | A co-invitee posing as the organizer deleted the meeting or changed its time and link; forged answers changed guests' status | applied automatically only when DMARC passed, a user of this server sent it, or a trusted source handed it over; otherwise left to the user | `calendar_messages_change_nothing_unless_their_author_is_verified` |
| 5 | Medium | Shared calendars (`api/calendar.rs`) | A colleague with write access sent invitations as the owner, to anyone, counted against the owner's limits | Mail in the owner's name with the colleague's title and link; enough of it blocked the owner's sending | invitations carry `Sender:` naming the writer and count against the writer's limits | `invitations_from_a_shared_calendar_name_who_wrote_them` |
| 6 | Medium | Delayed sending (`jmap/submission.rs`) | Scheduled messages went out for disabled mailboxes and survived password and second-factor resets | An intruder scheduled phishing from the victim's address up to 30 days ahead; the clean-up did not stop it | disabled mailboxes (or domains) send nothing; an administrator's password or second-factor reset cancels everything pending | `scheduled_mail_of_a_locked_or_reset_account_is_not_sent` |
| 7 | Medium | IMAP, POP3, ManageSieve, SMTP sessions | A connection, once signed in, was never checked again | After the mailbox was disabled, its password reset or the app password revoked, an intruder's IMAP IDLE connection kept reading mail | every minute (and during IDLE) the sign-in is checked again: account and domain enabled, protocol allowed, password unchanged, app password not revoked | `protocol_sign_ins_end_with_the_credential_they_used` |
| 8 | Low | Sign-in state in memory (`api/signin.rs`, `oauth.rs`, `api/oauth.rs`) | Passkey sign-ins were limited per exact address; SSO starts and outcomes not per address at all | From an IPv6 /64 (or a few thousand requests), the shared tables filled and nobody could start a passkey or SSO sign-in | limited per network (an address, or an IPv6 /64) | `passkey_sign_ins_are_limited_per_network`, `one_network_cannot_crowd_out_everybody_elses_sign_ins` |
| 9 | Low | Sieve redirects | Mail sent on by a filter did not count against the hourly sending limits | Combined with 3, unbounded; alone, a way around the limits | counted (and refused while the account is blocked) | `sieve_redirects_do_not_loop_and_count_as_sending` |

Behaviour changes: invitations, answers and cancellations from outside apply by themselves only
when the sender's domain passes DMARC; a user who forwards a lot of mail with a Sieve
`redirect` can reach the hourly sending limit.

### Resource and robustness review of 2026-10-16

| # | Severity | Component | Problem | Fix | Verification |
| --- | --- | --- | --- | --- | --- |
| 1 | Medium | Delivery queue (`smtp/queue.rs`) | Deliveries ran in batches of 20, each batch waiting for its slowest member: one slow or tarpitting server held up all outgoing mail for up to half an hour per try | each delivery starts as soon as a slot is free (20 in all, 4 per receiving domain) | `a_slow_server_does_not_hold_up_other_mail`, `each_domain_gets_only_its_share_of_the_delivery_slots` |
| 2 | Medium | JMAP upload (`jmap/mod.rs`) | Bodies up to 1 GB were read into memory before the size check, any number at once; uploads waited a day outside any quota | the size is checked before and while reading; 4 uploads at once per account; waiting uploads count against the mailbox's free space (at most 1 GB) | `uploads_are_limited_in_size_and_in_what_may_wait` |
| 3 | Low | Webhooks (`webhooks.rs`) | A task and a database query per event without bound; failed notifications were lost | one worker with a backlog of 1,000 events, 8 notifications at once, two retries of the identical notification | `webhook_notifications_are_tried_again_when_the_receiver_fails` |
| 4 | Low | Client address (`api/mod.rs`) | Unreadable `X-Forwarded-For` entries (such as `IP:port`) were skipped, so an address the client wrote itself could be taken for the client's | `IP:port` and bracketed forms are read; any other unreadable entry ends the walk at the last proxy | unit test `the_client_is_the_first_untrusted_hop_from_the_right` |
| 5 | Low | ManageSieve | `MAXREDIRECTS 0` was announced although filters may redirect five times | the real limit is announced | `scripts_are_managed_over_managesieve` |

### Residual risks and limits (not fixed)

- **Database in plaintext.** Encryption at rest covers message blobs and backups, not the live
  database (subjects, addresses, previews, search index). Use disk encryption for that.
- **Plaintext seen by the server.** Before storage the server (and rspamd, clamd, milters) reads
  every message, including those then encrypted to a user's OpenPGP key. S/MIME private keys
  are held by the server (sealed with `secret.key`).
- **Backscatter by design.** Mailbox-full bounces go to the claimed sender (headers only now).
  TLS-RPT reports go to whatever `rua` the receiving domain publishes, without external
  verification (RFC 8460 defines none); mailing-list confirmation mails go to the address in
  `From`. Volumes are small (one per request or per domain and day).
- **List amplification.** A list open to posts from anyone (`posting = anyone`) with many remote
  members multiplies one message; posts from non-members are held by default.
- **Spoofed list posts.** "Members only" trusts `From`/envelope; forged member addresses pass
  unless DMARC of the member's domain rejects them.
- **TLS-RPT/DMARC report and push verification** requests go to addresses chosen by remote
  domains or users (public addresses only, bounded in number).
- **No coverage-guided fuzzing** yet (cargo-fuzz needs a nightly toolchain); the robustness tests
  are random, not coverage-driven. `cargo deny` is not installed here; licences and duplicate
  crates were not checked.
- **Administrators** can reset a user's password and second factors (audited) and thereby
  reach their mail; there is no separation from the operator.
- **Multi-node** deployments are not supported; one compromised host holds everything.
- **Unsafe content is recognised by rules, not by a scanner.** Link, sender-name and attachment
  warnings in the web client and the server's refusal of executable attachments work on names
  and addresses. Archives other than ZIP (7z, RAR, ...), password-protected or nested archives,
  and documents carrying exploits or macros are only caught by a virus scanner: keep ClamAV
  (or Rspamd's antivirus module) enabled. The warnings appear in this web client only; IMAP
  and POP3 clients get the messages as they are. A look-alike domain written in plain ASCII
  (`paypa1.com`) is not detected unless the link text names a different domain.

## 4. Production checklist

- Set `UNOMAIL_HOSTNAME`, a real certificate (ACME or uploaded) and keep `UNOMAIL_COOKIE_SECURE`
  and `UNOMAIL_HTTP_REDIRECT` at their defaults (true).
- Never set `UNOMAIL_ALLOW_PRIVATE_DESTINATIONS` outside tests.
- Make sure port 25 sees the real client addresses (no NAT or userland proxy in front, or a
  warning appears in the log); list real relays only in `UNOMAIL_TRUSTED_NETWORKS`.
- Keep *Refuse executable attachments* on, and the bundled rspamd and clamd (or milters) running; `UNOMAIL_RSPAMD_FAIL_OPEN` and
  `UNOMAIL_MILTER_FAIL_OPEN` stay false.
- Expose only the mail and web ports; LMTP stays off unless a front server needs it, and then
  only on a private network.
- Back up `secret.key`, `blob.key` and `vapid.key` separately from the data backups.
- Run `./audit.sh` before releases (and weekly in CI), and `cargo test`, `pnpm test` and the
  Playwright suite.
- Encrypt the disk holding `/data`.

## 5. Incident response

- **Compromised account:** disable it or reset its password (signs out every session, ends
  open IMAP/POP3/SMTP connections within a minute, revokes its app passwords and cancels
  scheduled messages), reset its second factors (also revokes app passwords, ends sessions and
  cancels scheduled messages), review the audit log, the passkeys, sender identities, Sieve
  redirects and sent mail.
- **Spam outbreak:** the account is blocked automatically on exceeding its hourly limit; check
  the queue page, hold or delete queued messages, review the outbound log.
- **Exposed secret:** rotate DKIM keys (new selector), replace the TLS certificate, and for
  `secret.key` re-enter the third-party credentials it sealed (identity SMTP passwords, LDAP,
  OIDC secret, webhook secrets) and ask users to set up TOTP and S/MIME again.
- **Data breach:** sessions can be revoked globally by deleting rows of the `sessions` table;
  notify affected users as the law requires.

## 6. Verification for this review

Commands run on 2026-10-15, results as observed:

- `cargo audit`: 4 rustls advisories before, none after the upgrade (RUSTSEC-2023-0071 for
  `rsa` is ignored with the justification in `server/.cargo/audit.toml`).
- `pnpm audit --prod` (web): no known vulnerabilities.
- `cargo test`: all suites pass, including the new regression and robustness tests.
- `cargo clippy --all-targets`: no warnings.
- `pnpm exec tsc --noEmit`, `pnpm exec vitest run`, `pnpm build`: pass.
- Playwright end-to-end suite: 70 of 70 tests pass (73 of 73 after the unsafe-content work, 76 of 76 after the personal spam filter and translations, 81 of 81 after both follow-up reviews of 2026-10-16).
- `cargo fmt --check` was not applied: the codebase does not follow rustfmt's default width,
  and reformatting it would bury the security changes.

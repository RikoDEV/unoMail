# Administration

## Dashboard

- Daily mail and connection stats for 7, 30 or 90 days (kept 400 days).
- Disk and memory use for the last day or week.
- Recent remote connections and SMTP replies (in memory, cleared on restart).

Country flags come from Team Cymru's IP-to-ASN DNS service. They show where the network is
registered, not necessarily where the host is.

## Postmaster

Every domain gets a `postmaster@<domain>` system mailbox. DMARC and TLS reports are delivered
there and parsed into the report pages. Set a password to read it, or forward it with Sieve.
An existing `postmaster@` alias takes its place.

## SMTP blacklist

| Tab | Contents |
| --- | --- |
| User defined | Block or allow addresses and CIDRs. Highest priority wins, then the most specific network. |
| Automatic | Day-long blocks created by the server. Editing one makes it permanent. |
| Karma | Score per remote address. Blocked at −20. Private addresses are never blocked. |

Allowed addresses skip DNS blocklists, reputation checks and greylisting.

| Event | Karma |
| --- | --- |
| Accepted mail | +1 |
| Unknown recipient | −1 |
| DNS blocklist hit | −2 |
| Failed login | −3 |
| Rejected mail, too many errors, spam trap | −5 |

## Spam filtering

- **Spam filter** sets Rspamd's action thresholds and rule scores. Changes apply immediately.
- **Built-in filter** (Server settings) runs after Rspamd and records its results in
  `X-Unomail-Filter`. It checks deceptive links, sender network and domain reputation,
  countries or networks you penalise, and traces of forged messages: a spam verdict written
  before any server scanned the message, a mail program name that does not fit the message,
  and Google's notification redirect in mail not from Google. `X-Spam-*` headers arriving
  from outside (other than through a trusted relay) are removed. Footer links that lead
  nowhere around a single real destination also count.
- **AI phishing check** (Server settings, off by default) asks one of your AI models whether
  mail the built-in filter already finds doubtful (from *Ask from score*) is phishing. The
  model gets a digest the server makes (sender, subject, text, and the hosts links
  really lead to), fenced with a random marker and labelled as untrusted data. Only the exact
  answer `PHISHING` adds points (`AI_PHISHING`); any other answer, an error, a busy model or a
  20-second timeout changes nothing, so a message that tries to talk the model round can at
  most go unflagged, never get cleared. Calls are capped at 30 a minute. Turning it on sends
  that digest to the model's provider: prefer a self-hosted model for private mail. Its
  verdicts never teach sender reputation.
- **Spam traps** are unused addresses. Mail to them is dropped and its source is penalised.

## Reports

- **DMARC**: incoming aggregate reports are parsed; outgoing ones are sent daily to domains that ask (`rua`).
- **Feedback reports** (ARF, RFC 5965): complaints and failure reports sent to a hosted domain are listed
  under Insights → DMARC. **Send failure reports** (Server settings, off by default) sends
  per-message reports for DMARC (`ruf`), DKIM (RFC 6651) and SPF (RFC 6652) failures, with recipient
  addresses redacted and at most one an hour per domain.
- **TLS** (RFC 8460): received reports and the server's own outbound sessions.
- **MTA-STS and DANE** are enforced on outbound mail. Hosted domains can publish an MTA-STS policy.

## Backups and restore

Set `UNOMAIL_BACKUP_DIR` or `UNOMAIL_BACKUP_S3_*`. The server then takes a daily snapshot of
the database and all messages at `UNOMAIL_BACKUP_HOUR`. Runs are incremental, and
`UNOMAIL_BACKUP_KEEP` snapshots are kept.

> [!IMPORTANT]
> `secret.key`, `blob.key` and `vapid.key` are **not** backed up. Store them separately.
> Without `secret.key`, a restore loses DKIM keys, the TLS key and stored credentials.

```sh
unomail backup                        # take one now
unomail backups                       # list snapshots
unomail restore [snapshot] [--force]  # server must be stopped
unomail migrate-blobs [--from DIR]    # move to S3, or encrypt existing mail
```

`UNOMAIL_ENCRYPT_MAIL` encrypts message contents only. The database (subjects, addresses,
search index) stays readable, so use disk encryption too.

If `secret.key` leaks: rotate the DKIM selector, reissue the TLS certificate, delete the
`srs.secret` and `lists.secret` settings, and re-enter stored credentials.

## Integrations

### Single sign-on

OpenID Connect with PKCE. The provider's verified e-mail address selects an existing mailbox;
no mailboxes are created. The first sign-in links the mailbox to the provider's identity
(its `sub`); a different identity with the same address is refused from then on. If a user's
provider account is replaced, reset the mailbox's 2-step verification in its dialog: that also
removes the link. IMAP and SMTP accept provider tokens (`XOAUTH2`, `OAUTHBEARER`) if
they were issued to unoMail's client ID. Providers with opaque tokens and no introspection
(e.g. Google) work for web sign-in only.

### LDAP

Recipient suggestions only. `ldaps://`, or `ldap://` with StartTLS.

### Webhooks

Events: `message.received`, `message.sent`, `message.bounced`, `account.created`. The payload
holds addresses and sizes, never content.

- Signature: `X-Unomail-Signature: sha256=<HMAC-SHA256 of the body>`.
- Retries after 5 and 30 seconds on no answer, 408, 429 or 5xx.
- The queue holds 1,000 events; more are dropped with a warning.

### Skins

Skins pasted here are JSON design tokens only, so a skin can't carry CSS or code. The tokens
are the same as a theme package's; see [Writing themes](theme-development.md).

### Plug-ins and themes

Install packages from a git repository at a tag, branch or commit. A plug-in's web part
runs in sandboxed frames and its server part (WebAssembly) in a sandbox inside the server,
both with only the permissions you approved. Plug-ins can declare settings for you (the gear
button) and for each user. See [Plug-ins and themes](plugins.md).

## Mailing lists

For a list `team@example.org`:

| Address | Purpose |
| --- | --- |
| `team@` | Posts, delivered to all members |
| `team-request@` | `subscribe`, `unsubscribe`, `help` by mail |
| `team-owner@` | Reaches the owners |
| `team-bounces@` | Return path; members are removed after 5 bounces |

Posting policy: anyone, members, moderators, or owners only. Held posts are approved in the
admin panel or from the moderator's e-mail. Mail from strict-DMARC domains is sent "via" the list.

## AI models

Administration → Models (super administrators). Supported providers: OpenAI, Anthropic,
Gemini, OpenRouter, Groq, DeepSeek, Ollama, and any OpenAI-compatible API.

- **Base URL**: include the version for OpenAI-compatible APIs (`https://api.openai.com/v1`);
  use the server root for Ollama (`http://ollama:11434`). `localhost` means the container.
- **API keys** are encrypted and never shown again. Leave blank to keep the current one.
- **Test connection** sends a prompt without mail content.

| Limit | Value |
| --- | --- |
| Body sent | 60,000 characters |
| Timeout | 90 seconds |
| Per account | 10 requests per minute |
| Server-wide | 8 concurrent requests |

Only the subject and text body are sent. Results are not stored.

### Summary cards

Schema.org JSON-LD in the mail is read locally, without AI. For other mail, choose a model
under **Models → Summary card extraction**. Automatic extraction runs only when both the
administrator and the user turn it on (both off by default). AI-extracted fields are kept
only if they appear verbatim in the message.

## Masked addresses

Administration → Masked addresses manages a mailbox's masks, quota and allowed domains.

| Setting | Default |
| --- | --- |
| Masks per account | 100 (blank inherits, 0 blocks) |
| Creation rate | 30 per account per hour |
| Allowed domains | The account's primary domain; others need a grant |

Deleted masks keep their address reserved so it is never reused. Domain administrators manage
only their own domains. API: [API and command line](api.md#masked-addresses).

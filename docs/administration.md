# Administration

## AI models (Administration → Models)

Super administrators can add, edit, disable, test and delete models at `/admin/models`.
Choose OpenAI, Anthropic, Google Gemini, OpenRouter, Groq, DeepSeek, Ollama or an
OpenAI-compatible provider. Enter a display name, the provider's exact model ID, its API
base URL and API key. Several models from the same provider can be configured.

The provider presets fill in the base URL. OpenAI-compatible URLs include the API version
(for example, `https://api.openai.com/v1`); Ollama uses its server root
(for example, `http://ollama:11434`). Local addresses must be reachable from the mail
server container, where `localhost` refers to the container itself. Ollama and custom
OpenAI-compatible servers may be used without an API key.

API keys are encrypted with the server's existing credential key and never returned to
the browser. Leave the key blank when editing to preserve it. Changing the provider or
base URL requires entering the key again. **Test connection** sends a small test prompt
without email content. **Available in webmail** controls whether users can select a model.

Enabled models are available to every signed-in user for their own messages. Each
summary or translation is requested explicitly and sends only the subject and text body
to the selected provider. Encrypted messages and shared messages owned by another account
are excluded. Requests allow up to 60,000 body characters, take at most 90 seconds and
are limited to ten per minute per account, with eight simultaneous provider requests
server-wide. Results are displayed in the reader without being stored in the mailbox.

## Integrations (Administration → Integrations)

- **Single sign-on** through an OpenID Connect provider (authorization code flow with PKCE).
  The provider's verified e-mail address selects an existing mailbox; mailboxes are never
  created automatically. Mail programs can sign in with the provider's access tokens using
  SASL `XOAUTH2` or `OAUTHBEARER` on IMAP and SMTP submission; such a token must have been
  issued to unoMail's client id, which is checked with the provider's token introspection
  endpoint or, without one, the claims of a JWT access token. Providers that issue opaque
  tokens and offer no introspection (Google) work for the web sign-in only.
- **LDAP directory** for recipient suggestions (`ldaps://`, or `ldap://` with StartTLS).
- **Webhooks**: signed JSON notifications for `message.received`, `message.sent`,
  `message.bounced` and `account.created`. The body is signed with HMAC-SHA256
  (`X-Unomail-Signature: sha256=<hex>`); notifications carry addresses and sizes, never content.
  A notification the receiver does not take (no answer, 408, 429 or 5xx) is sent again after
  5 and 30 seconds, byte for byte the same, so repeats can be recognised. Up to 1,000 events
  wait for delivery; beyond that new ones are dropped with a warning in the log.
- **Skins** are JSON design tokens: `id`, `name`, `mode` (`light`/`dark`/`auto`), `primary`,
  `secondary`, `background`, `paper`, `text` (`#rrggbb`), `radius` (0–32), `density`
  (`comfortable`/`compact`) and `font` (`roboto`/`system`/`serif`/`mono`). Anything else is
  refused, so a skin cannot carry CSS or code.
- **Plug-ins** extend the web client. A plug-in is a directory `plugins/<id>/` in the data
  volume with a `plugin.json` (`name`, `version`, `description`) and a `plugin.js` module:

  ```js
  export default function (api) {
    api.addMessageAction({ id: 'translate', label: 'Translate', onClick: (message) => { /* message.subject, .from, .html … */ } });
    api.addComposerAction({ id: 'greeting', label: 'Greeting', onClick: (composer) => composer.insertHtml('<p>Hello,</p>') });
    api.addSidebarLink({ id: 'wiki', label: 'Wiki', href: 'https://wiki.example.org/' });
    api.on('message:open', (message) => api.log(message.subject));
    api.on('message:sent', ({ subject, recipients }) => api.notify(`Sent: ${subject}`));
  }
  ```

  Plug-ins run in every user's browser with the page's privileges. They can therefore only be
  installed by someone with access to the server's disk, and are switched on and off in the
  admin panel. The API is defined in [`web/src/plugins.ts`](../web/src/plugins.ts).

## Mailing lists (Administration → Mailing lists)

A list `team@example.org` delivers each post to all members, with RFC 2369 list headers and a
one-click unsubscribe link (RFC 8058) per member, signed for the list's domain. Who may post:
anyone, members (others are held), moderators (others are held) or owners only
(announcements). Held posts are approved or discarded in the admin panel or from the link in
the notice moderators receive. `team-request@` handles `subscribe`, `unsubscribe` and `help`
by mail (confirmed by a link; subscribing only when the list is open), `team-owner@` reaches
the owners, and `team-bounces@` is the return path: members whose copies keep bouncing are
removed after five failures. When the sender's domain publishes a strict DMARC policy, copies
are sent "via" the list address, as changing them would break the sender's signature.

## Operations (Administration)

- **Postmaster mailboxes:** every hosted domain has a `postmaster@<domain>` mailbox, created
  with the domain (and at startup for older domains). Mail domains must accept postmaster
  (RFC 5321), and the DMARC and TLS-RPT records on the DNS page send reports there: they are
  read into the DMARC and TLS report pages and also kept in the mailbox. It is marked
  *system* in Mailboxes and cannot be deleted; set a password to read it, or forward it with
  a Sieve filter. An existing alias named postmaster@ is used instead, and the mailbox does not
  count against a domain's mailbox limit.

- **Dashboard** opens with *Daily stats*, a full-width line chart of the last 7, 30 or 90
  days: valid and invalid SMTP connections (blocked by the blacklist, a DNS blocklist or
  reputation; limited by the per-address connection limit), delivered mail (local and remote),
  bounced, quarantined and discarded mail. Counts are per UTC day and kept for 400 days; the
  mail figures start from the delivery log already on the server. It also charts free space
  on the data volume and memory use over the last day or week (sampled every minute, kept for
  a week). Below the mail flow it shows the remote addresses that connected most recently
  (with country flag and reverse DNS name) and the last SMTP replies the server gave, with
  their status codes. Both are kept in memory and start empty after a restart.
- **SMTP blacklist** has three tabs. *User defined*: addresses or networks (CIDR) you block or
  allow, with a priority, hit counter, last-seen time and description. A blacklisted address
  is refused at connect on every SMTP port; a whitelisted one skips DNS blocklists, the
  reputation check and greylisting. When several rules match, the highest priority wins, then
  the most specific network, then the whitelist. *Automatically generated*: day-long blocks
  the server creates itself; editing one makes it permanent. *Karma records*: a score per
  remote address (accepted mail +1; unknown recipient −1; DNS blocklist hit −2; failed login
  −3; rejected mail or too many errors −5). At −20 an address is blocked automatically;
  private addresses are scored but never blocked.
- **Spam filter** configures the built-in Rspamd: the scores at which mail is marked as spam
  or rejected, the score of every rule, and the latest verdicts. Changes are stored by Rspamd
  and apply immediately.
- **Built-in spam filter** (Server settings) adds the server's own tests after Rspamd, recorded
  in an `X-Unomail-Filter` header: links written as IP numbers, look-alike (mixed-script)
  domains, user names in front of a host, link shorteners, links whose text names another
  domain, and floods of domains; the reputation of the sending network (/24 or /48), its
  autonomous system and its verified domain; and countries or autonomous systems you
  penalise (looked up in Team Cymru's DNS service, `origin.asn.cymru.com`). Mail at the junk
  score goes to Junk. Reputation is learned from clear verdicts (Rspamd's junk action, the
  filter's own tests, spam traps), from DMARC-verified mail that was accepted, and from users
  moving mail into or out of Junk. **Spam traps** are addresses of your domains that nobody
  uses (publish them where only harvesters look): mail to them is accepted, never delivered,
  teaches the reputation that its source sends spam, and lowers the sender's karma by 5.
- **TLS reports** (RFC 8460) received about your domains, and how this server's own outgoing
  sessions fared; domains that ask get the latter as a daily report. Outgoing mail honours
  receivers' **MTA-STS** policies (RFC 8461) and **DANE** TLSA records (RFC 7672, checked with
  DNSSEC); hosted domains can publish an MTA-STS policy (served at
  `https://mta-sts.<domain>/.well-known/mta-sts.txt`), and the DNS page lists the records.
- **DMARC aggregate reports** are also sent, once a day, to the domains whose policy asks for
  them (`rua`), after checking that an address outside the domain agreed to receive them.
- **Backups** shows the backup target, the snapshots kept there and recent runs, and starts
  one on request (see [Backups and restore](#backups-and-restore)).

## Backups and restore

With `UNOMAIL_BACKUP_DIR` (ideally another disk) or a bucket (`UNOMAIL_BACKUP_S3_*`) set, the
server backs itself up daily at `UNOMAIL_BACKUP_HOUR`: a consistent snapshot of the database and
every message. Messages are content-addressed, so each run copies only new ones; snapshots
beyond `UNOMAIL_BACKUP_KEEP` are removed together with the messages no remaining snapshot
needs. The keys in the data directory (`secret.key`, `blob.key`, `vapid.key`) are deliberately
not in the backup: keep a copy of them somewhere safe.

Signing keys and secrets in the database (DKIM and TLS private keys, the SRS and list secrets)
are sealed with `secret.key`, so a backup restored without that file cannot sign mail: DKIM
keys must be generated again and a self-signed certificate replaces the TLS one. If a backup or
database copy made by a version before this sealing leaked, treat those keys as exposed: add a
new DKIM selector and retire the old one, reissue the TLS certificate, and delete the
`srs.secret` and `lists.secret` settings so new ones are generated (outstanding SRS bounces and
unsubscribe links stop working). If `secret.key` itself leaked, all of the above applies too:
stop the server, move `secret.key` aside and re-enter the credentials it protected.

```sh
unomail backup                     # take one now
unomail backups                    # list the snapshots
unomail restore [snapshot] [--force]   # with the server stopped; default: the latest
unomail migrate-blobs [--from DIR] # move messages into S3, or seal older ones after enabling UNOMAIL_ENCRYPT_MAIL
```

Encrypting stored mail (`UNOMAIL_ENCRYPT_MAIL`) seals each message with ChaCha20-Poly1305,
bound to its address; mail stored before stays readable, and `migrate-blobs` seals it too.
Backups taken with it on also seal their copy of the database. The live database itself is
**not** encrypted: subjects, addresses, message previews and the full-text search index are
readable to anyone with the data directory, so encryption at rest protects a leaked message
store or bucket, not a stolen server. Disk encryption covers the rest.

Country flags come from Team Cymru's IP-to-ASN service over DNS (no account or database
needed); they show where the network is registered, which is not always where the host is.

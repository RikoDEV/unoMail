# Web client

## Mail

| Feature | Notes |
| --- | --- |
| Message list | Condensed or expanded (Settings → General). Hover a row for archive, delete and read/unread. `x` selects. |
| Bulk actions | Select some, all, or the whole folder; archive, delete, report, mark, move or label. |
| Inbox categories | General, Offers, Communities, Notifications, Forums. Learns from your moves. Stored as `$cat_*` keywords. |
| Labels and folders | Drag a conversation onto a folder to move it, onto a label to apply it. |
| All mail | Every message outside Trash and Junk. |
| Shared folders | Share with colleagues or the whole domain: read, read and file, or read/file/delete. Visible over IMAP under `Shared/<owner>/`. |
| Import and export | mbox or `.eml` per folder; single messages as `.eml`. |
| Snooze | Returns unread to its folder. Moving it out of *Snoozed* cancels it. |
| Unsubscribe | One-click (RFC 8058) where supported, otherwise by mail or the sender's page. |
| Attachment previews | Images, text and PDF (pdf.js, no scripts). |
| Block sender | Their mail goes to Junk. Whole domains in Settings. |

### Search

Searches subject, addresses, body and attachment names. Trash and Junk are excluded unless you
use `in:`. Supports Gmail operators:

```text
from: to: cc: bcc: subject: filename: label: category: in:<folder> in:anywhere
has:attachment is:unread is:starred before: after: older_than: newer_than:
larger: smaller: -word OR
```

### Spam

- **Report spam** / **Not spam** train your personal filter and the server's Rspamd.
- The personal filter acts after 10 spam and 10 wanted messages, and only on scores ≥ 0.9.
- Senders that pass verification are never filed away by it.
- Review or reset it in Settings → Inbox.

### Filters

Settings → Filters edits server-side Sieve scripts as rules or raw Sieve. Rules match headers,
text or size, and move, copy, label, mark, forward or delete.

## Writing

| Feature | Notes |
| --- | --- |
| Identities | Name and reply-to per address. An identity can send through its own SMTP server. |
| [Masked addresses](#masked-addresses) | A random address per website. |
| Signatures | Several per account; separate defaults for new mail and replies. |
| Templates | Inserted from the composer toolbar. |
| Undo send | 5 seconds by default, up to 30. |
| Scheduled send | Up to 30 days ahead. Listed under *Scheduled*. |
| Read receipts | Request or send (RFC 8098). |
| Spell check | Browser dictionaries. |

### Masked addresses

Settings → Masked addresses creates a random address delivered to your mailbox.

- Set a description, website, prefix, domain and expiry. The address and expiry can't change.
- Disabled, expired or deleted masks reject mail, even on catch-all domains.
- Replies are sent from the mask the message arrived at.
- **Mask integrations** issues 90-day tokens for password managers. See the [API](api.md#masked-addresses).

## AI

Needs a model configured under Administration → Models. Content goes to the provider only
when you request an action. Encrypted messages are never sent.

| Feature | Notes |
| --- | --- |
| Summarize | Key points and requested actions. |
| Translate | Offered when the message's language differs from yours. Chrome and Edge can translate on-device without a model. |
| Smart replies | Up to three editable drafts. Toggle in Settings → Inbox. |
| Summary cards | Orders, bookings and bills, merged across related messages. Structured data is read without AI. |

## Security

- **Sender checks.** Hover the sender to see SPF, DKIM, DMARC and TLS results. Failures show a warning.
- **Sender pictures.** BIMI logos for DMARC-enforcing domains (check mark with a VMC), otherwise Gravatar.
- **Links and attachments.** Deceptive links and executable attachments ask before opening.
- **Remote images.** Blocked until allowed, then loaded through the server's proxy.
- **OpenPGP.** Keys live in the browser. Optionally encrypt all incoming mail to your key.
- **S/MIME.** Import a `.p12` in Settings → Security; the server signs, encrypts and decrypts.

## Calendar and contacts

- **Contacts** (`/contacts`): groups, vCard import/export, recipient suggestions (including LDAP).
- **Calendar** (`/calendar`): multiple calendars, tasks, recurring events, iCalendar import/export.
- **Invitations** are mailed to guests; replies update the event.
- **Sharing**: read or edit, within the domain.
- **Reminders** appear only while the web client is open.

For programs, see [CalDAV and CardDAV](mail-programs.md#calendars-and-contacts).

## Account

- **Multiple accounts**: up to five per browser, switched from the account menu.
- **Notifications**: Web Push, also with no tab open.
- **Usage**: quota and hourly sending limit in Settings → General.
- **Languages**: English and Polish. Strings are in `web/src/locales/<code>.json`.
- **Skins**: six built in, more from the [administrator](administration.md#integrations), including theme packages.
- **Add-ons**: plug-ins the administrator made available, turned on per user in Settings → General. They can add buttons, views and pages, or hide some built-in features. See [Plug-ins and themes](plugins.md).

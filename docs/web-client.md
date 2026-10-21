# Web client

Besides reading and writing mail, the web client offers:

- **Masked addresses** (Settings → Masked addresses): create a separate, randomly generated
  address for each website. Incoming mail uses the existing mailbox and its normal spam and
  Sieve processing. Give the address a description, website label, optional prefix, domain
  and expiration. The website label is informational, not a sender restriction. Addresses
  and expiry dates are immutable; descriptions and website metadata can be edited.
  Disable/re-enable an address or delete it permanently; existing messages remain available.
  Disabled, expired and deleted masks reject incoming mail even on catch-all domains.
  The reader shows **Received via …**, including for Bcc mail, using trusted SMTP envelope
  metadata. Reply, Reply all and Smart Reply choose that mask as the sender. It is also
  available in the composer's From selector. An unavailable mask remains selected with an
  error rather than falling back to the primary address. Sending and scheduled release
  recheck ownership and expiry. Mask identities start with a blank display name and no
  primary-address signature; an explicit identity/signature can be configured separately.
  **Mask integrations** creates revocable, mask-only JMAP tokens shown once and expiring
  after 90 days. See [administration](administration.md#masked-addresses) for API details.
- **Smart replies.** With an AI model configured, **Suggest replies** below a received
  message generates up to three response options. It uses the model selected in the
  message's AI tools and the email's language by default; **Reply language** selects another.
  Earlier messages from the same account and conversation provide bounded context, with
  encrypted messages excluded. Select a suggestion to open an editable reply draft, or
  check **Reply all** first to include the other recipients. Normal Reply-To addressing,
  threading, quoted text, signatures and draft autosave are preserved. The ordinary Send
  button sends the reply after review. Opening an email makes no suggestion request.
  Settings → Inbox → **Offer AI reply suggestions** controls the feature.
- **Purchase cards.** Order and shipping emails can show a compact card above the message:
  merchant, order number, items, total, delivery estimates and tracking links when known.
  Cards consolidate updates from related messages, including ones in separate conversations.
  **Related messages** opens their source emails. **Dismiss** hides an order's card across
  its related messages; **Show purchase card** restores it. Open cards refresh periodically
  to pick up new delivery updates. Links open the original merchant or carrier page.
  Settings → Inbox controls card visibility and optional automatic AI extraction.
  Structured email data is processed locally without AI. Ordinary purchase emails can be
  processed with the administrator's configured model, either on explicit request or when
  both the administrator and user enable automatic extraction. **Process recent mail**
  queues up to 200 messages using those settings. Encrypted messages are excluded.
- **AI summaries and translations.** When an administrator enables a model in
  Administration → Models, open a message and choose a model and target language above
  its body. Translation is suggested only when the message's detected language differs
  from the interface language; detection runs locally and uncertain results show no
  suggestion. The target defaults to the interface language. **Summarize** shows key points
  and requested actions; **Translate to …** shows a translation of the subject and body.
  Results appear alongside the original message and can be hidden separately. Content is
  sent to the selected provider only when an action is requested. Encrypted messages and
  other accounts' shared messages cannot be processed.
- **A one-line-per-conversation list** with checkboxes: select some or all conversations (or
  everything in the folder) and archive, delete, report, mark read/unread, move or label them
  in one go. `x` selects the highlighted conversation.
- **Inbox categories**: General, Offers, Communities, Notifications and Forums, as tabs with
  unread counts. Mail is sorted on arrival from its headers (a social network's domain,
  mailing-list headers, bulk-mail markers, automatic senders); a conversation can be moved to
  another category from its menu or by dropping it on a tab. Each account learns from those
  moves: later mail from the same sender goes where the user put it, and once a few messages
  have been moved into two or more categories, a per-user Bayes classifier sorts mail from new
  senders by its content, overruling the header rules when confident. What it learned can be
  reviewed and reset in Settings → Inbox. The category is a keyword on the
  message (`$cat_offers`, ...), so it is visible over IMAP and JMAP too. Can be switched off
  in Settings.
- **Personal spam filter.** Besides the server-wide Rspamd filter, every user has a Bayes
  filter of their own that learns from what they do: *Report spam* (or moving mail into Junk,
  or the `$Junk` keyword that Thunderbird and Apple Mail set) teaches it spam; *Not spam* (in
  Junk), `$NotJunk`, replying to a message and mail from people in the address book or
  written to teach it what is wanted. Once it has seen ten of each, new mail it is sure about
  (score ≥ 0.9) goes to Junk. Mail from correspondents whose address passed verification is
  never filed away by it. Settings → Inbox shows what it has learned and can reset it; the
  administrator can switch the feature off (*Server settings → Personal spam filters*).
  Reports also train Rspamd's shared Bayes and fuzzy storage where Rspamd runs.
- **Languages.** The interface is available in English and Polish. It follows the browser's
  language until one is chosen in Settings → General (stored with the account, so it
  follows you to other devices) or on the sign-in page. Dates and numbers use the chosen
  language. Translations live in `web/src/locales/<code>.json`, keyed by the English text;
  a unit test fails when a text has no translation.
- **Labels** with colours, created in the sidebar and applied from the reader, the selection
  toolbar or by drag and drop.
- **Per-message menu**: *Show original* (the message as it arrived, with the sender-check
  results), *Block sender* (their later mail goes to Junk without them noticing; whole
  domains can be blocked in Settings) and *Move to category*.
- **Unsubscribe** button on mailing-list mail (`List-Unsubscribe`, RFC 2369/8058): a one-click
  request made by the server where the sender supports it, otherwise an unsubscribe e-mail
  sent on your behalf, otherwise the sender's page.
- **Folders and labels** with drag and drop: drop a conversation on a folder to move it, on a
  label to apply it. Folders can be exported as mbox files and `.eml`/mbox files imported
  (folder menu), and single messages downloaded as `.eml`.
- **Shared and global folders.** A folder's owner shares it from the folder menu with
  colleagues of the same domain, or with `anyone` (everybody in the domain), at three levels:
  read, read and file, read/file/delete. Shared folders appear under "Shared with me" and, for
  mail programs, in the IMAP namespace `Shared/<owner>/<folder>` with the ACL extension
  (RFC 4314: `SETACL`, `GETACL`, `DELETEACL`, `MYRIGHTS`, `LISTRIGHTS`).
- **Sender identities** (Settings): name and reply-to address per address. An
  identity is either an address you own (your own or an alias) or it brings its own SMTP
  server, through which all its mail is sent; that server's password is stored encrypted.
- **Signatures** (Settings → Signatures): any number of named signatures with bold, italic,
  underline, links and small images (sent as inline parts). Each address chooses one for new
  messages and one for replies and forwards; the composer puts it in by itself and its
  *Signature* menu switches to another or none. Optional `-- ` separator line, and placement
  above or below the quoted message in replies. JMAP clients see the new-message signature
  as the identity's `htmlSignature`.
- **Mail filters** (Settings → Filters): Sieve scripts run on the server for every incoming
  message, edited either as a list of rules or as Sieve. A rule matches all, any or every
  message on From, To, Cc, Subject, List-Id, any header, the text or the size (contains, is,
  wildcards, regular expressions, exists, larger/smaller) and moves, copies, labels, marks as
  read, stars, forwards, keeps or deletes; rules can be switched off, reordered and stop the
  ones after them. The rules are saved as an ordinary Sieve script, each described by a
  `# rule:` comment above its code; a script changed by hand opens in the Sieve editor instead.
- **Address book** (`/contacts`) with groups and vCard import/export. The composer suggests
  recipients from your contacts and groups, the accounts of your domain and, if configured,
  an LDAP directory.
- **Calendar** (`/calendar`): any number of calendars per account, each with its own colour,
  in month, week, day and agenda views, plus a list of **tasks**. Events can repeat (daily,
  on weekdays, weekly, monthly, yearly, optionally until a date); one occurrence can be
  changed or deleted on its own. Calendars are imported and exported as iCalendar files.
  - **Guests:** people invited to an event get an invitation by e-mail, and are told when
    the event changes or is cancelled. Their answers arrive by mail and are noted on the
    event without your doing. An invitation you receive shows *Accept / Maybe / Decline*
    in the message; the event goes into your calendar and the organizer is told. While you
    pick a time, colleagues of your domain who are busy then are pointed out.
  - **Sharing:** a calendar can be shared with colleagues of the same domain, for reading
    or for editing. It appears next to their own calendars, here and in their programs.
  - **Reminders** are shown while the web client is open, on the page and, if you allow it,
    as desktop notifications.
  The same calendars are served to calendar programs over **CalDAV**, the address book over
  **CardDAV**, see [Mail programs](mail-programs.md#calendars-and-contacts-caldav-carddav).
- **Search** covers subject, sender, recipients, the whole body text and attachment names
  (accents ignored, words match by their beginning). The search box understands Gmail's
  operators: `from:` `to:` `cc:` `bcc:` `subject:` `filename:` `has:attachment` `is:unread`
  `is:starred` `label:` `category:` `in:<folder>` / `in:anywhere` `before:` `after:`
  `older_than:` `newer_than:` `larger:` `smaller:`, `-word` to exclude and `OR`. The
  options button in the search box opens Gmail's advanced-search form, which writes such a
  query. Without `in:`, Trash and Junk are left out.
- **Message list:** *condensed* (one line per conversation) or *expanded* (sender picture,
  subject and text on separate lines, the attached files as chips that open a preview).
  The choice (Settings, General) applies with or without a conversation open.
- **Quick actions** in the message list: with the pointer on a conversation, archive, delete
  and read/unread buttons appear at the right edge of its row.
- **Response templates**, inserted from the composer's toolbar. The composer can be switched
  to full screen.
- **Sender details and warnings.** Hovering (or focusing) the sender of a message shows from,
  to, date and subject, the domain it was mailed by and signed by, and whether the connection
  to this server was encrypted. A message whose sender failed SPF, DKIM or DMARC, or could
  not be checked at all, carries a warning naming what failed; so does a message in which
  the virus scanner found something (see `UNOMAIL_VIRUS_ACTION`).
- **Sender pictures.** For mail that passed DMARC from a domain with an enforced DMARC
  policy, the domain's **BIMI** logo is shown. With a valid **Verified Mark Certificate** it
  gets a check mark and the certified organization's name. Other senders get their
  **Gravatar**, unless the message failed verification. The server fetches and caches both.
- **Several accounts at once.** *Add another account* in the account menu signs in to a
  further mailbox without signing out (up to five per browser); the menu then lists them
  with their unread counts and switches with one click. Other open tabs follow the switch.
  *Sign out* leaves only the current account (the next one takes over), *Sign out of all
  accounts* ends every session. Each account's sessions stay separate on the server; the
  browser keeps the others in an `HttpOnly`, `SameSite=Strict` cookie.
- **Navigation.** The name in the header leads back to the inbox from every page. The
  sidebar switch reduces the sidebar to a strip of icons instead of hiding it. On phones the
  side menu (mail, calendar, settings, administration) opens with a swipe from the left edge
  and closes with a swipe back.
- **Attachment previews** for images, text files and PDFs, next to the download link. Text
  (HTML included) is shown as plain text, PDFs are drawn by pdf.js without running anything
  inside them.
- **Unsafe content warnings.** A link whose text names a different site than it leads to, or
  that hides its target, points at a bare IP address or uses a look-alike international
  domain, asks before it opens; every link shows its real destination on hover. Attachments
  that run code (`.exe`, `.js`, `.scr`, `invoice.pdf.exe`, ...) are marked red and need a
  confirmation to download; macro documents, HTML files and archives are marked as a caution.
  A sender whose display name shows another address or domain gets a warning.
- **Remote images** are blocked until you click "Show images" (or trust the sender). They are
  then fetched by the server, so the sender sees neither your address nor a cookie.
- **End-to-end encryption (OpenPGP).** Keys are created in Settings and used in the browser
  only; the server stores the public key and, optionally, the passphrase-protected private
  key. Messages are sent as PGP/MIME, so other OpenPGP mail programs can read them. With
  *Store incoming mail encrypted to this key*, every new message is encrypted to your public
  key on arrival, before it is stored: only you can read it (here after unlocking the key, or
  in any OpenPGP mail program), and search sees its subject and senders only.
- **S/MIME.** Import your certificate (a `.p12`/`.pfx` file) in Settings → Security; the
  server then signs what you send, encrypts it to recipients whose certificates it knows
  (collected from their signed mail; your own copy is encrypted to you too), and decrypts S/MIME
  mail to you when you read it. Signatures on incoming mail are checked (signature, validity,
  sender, issuing authority) and shown next to the message. Checked against OpenSSL in both
  directions.
- **Undo send.** A sent message waits a few seconds (5 by default, up to 30, or off in
  Settings) and can be called back with *Undo*; it then reopens in the composer.
- **Scheduled send** from the arrow next to *Send*: tomorrow morning or afternoon, Monday
  morning, or any time within 30 days. Waiting messages are listed under *Scheduled* and can
  be cancelled from there. This is JMAP `EmailSubmission` with `FUTURERELEASE` (`HOLDFOR`,
  `HOLDUNTIL`) and `undoStatus`, so JMAP clients can use it too.
- **Snooze** a conversation until later today, tomorrow, the weekend, next week or a chosen
  time. It waits in the *Snoozed* folder (visible over IMAP too) and comes back unread, on
  top of the folder it came from. Moving it out of *Snoozed* by hand cancels the snooze.
- **Read receipts** (RFC 8098): the composer can ask for one; when a message asks you, the
  reader offers to send it (or always/never, as set in Settings). Sent with JMAP `MDN/send`.
- **New-mail notifications** in the browser, also with no tab open (Web Push with VAPID; the
  server pushes JMAP state changes, encrypted for the browser, through its push service).
- **Spell checking** uses the browser's checker; the composer lets you switch it off and pick
  the language.
- **Skins**: six built in, more can be installed by the administrator (see [Administration](administration.md#integrations-administration--integrations)). Nine
  accent colours; on dark themes the accent is used in a lighter tone so it stays readable.
- **Internationalized addresses** (SMTPUTF8, RFC 6531) for mailboxes, aliases and recipients.

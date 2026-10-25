# Plug-ins and themes

unoMail is extended with **packages**: git repositories with a `unomail.json` manifest at
their root.

- **Plug-ins** extend the web client and the mail server:
  - add buttons, views and pages to the layout
  - hide or replace some built-in features
  - with a WebAssembly module, check and change mail as it arrives or leaves, answer their
    own API routes and run scheduled jobs
  - declare settings for users and for administrators
- **Themes** are colours, background images and styles for named parts of the interface.
  They contain no code.

| Guide | For |
| --- | --- |
| This page | Administrators: installing, configuring and trusting packages |
| [Writing plug-ins](plugin-development.md) | Developers: manifest, permissions, settings, the complete SDK, the server ABI, limits, testing and publishing |
| [Writing themes](theme-development.md) | Designers: tokens, images, parts |
| [API](api.md#plug-ins-and-themes) | The HTTP routes behind all of this |

## Examples

[`examples/`](examples) holds working packages; each folder can be pushed as a repository
and installed.

| Example | Shows |
| --- | --- |
| [`plugins/hello-world`](examples/plugins/hello-world) | A reader action and a notice |
| [`plugins/word-count`](examples/plugins/word-count) | Composer actions and a user setting |
| [`plugins/notes-panel`](examples/plugins/notes-panel) | A page of its own, a reader view, an item, per-user storage |
| [`plugins/no-calendar`](examples/plugins/no-calendar) | Hiding a built-in feature and adding a page in its place |
| [`plugins/subject-tagger`](examples/plugins/subject-tagger) | A server module in WebAssembly text: a mail hook, a route, an admin setting and an admin page |
| [`plugins/cloud-files`](examples/plugins/cloud-files) | A WebDAV cloud integration: an admin-chosen server, user credentials, saving attachments, attaching cloud files from a panel |
| [`themes/solarized`](examples/themes/solarized) | Colours, a background image, translucent parts, a gradient |

## Installing

Under **Admin → Integrations → Plug-ins and themes**:

1. Enter the repository's https address and a tag, branch or commit. A tag is recommended.
2. **Fetch.** The server fetches that one commit and validates everything in it, including
   the server module and theme images. It then shows the package, the exact commit and
   every permission in plain words, with the sensitive ones marked.
3. **Install.** The commit is recorded, and the package changes only when you update it.

**After installing**
- A theme is offered to every user in Settings → General at once.
- A plug-in stays off until you switch on **Available**. After that:
  - its web part runs for users who turn it on under Settings → General → Add-ons
  - its server part and administration pages work straight away
- The **gear button** opens the package's administrator settings. For plug-ins with mail
  hooks, it also holds **Hold mail when the plug-in fails**. Off (the default), failing
  plug-ins are skipped. On, mail is deferred and retried.

**Updating:** **Check for updates** looks up the newest commit of the same ref. The preview
lists the permissions the new version adds; nothing changes until you confirm.

**Uninstalling** deletes the package's files, its stored data, and every user's settings
and data for it.

**What the server accepts**
- https only, with no credentials in the address.
- Hosts with public addresses only.
- No redirects, submodules, hooks or symbolic links.
- At most 10 MB and 2,000 files.
- The server needs `git`, which the Docker image includes.

## Security model

| Layer | What it does |
| --- | --- |
| Web frames | Plug-in code runs in `<iframe sandbox="allow-scripts">` without `allow-same-origin`. Its origin is opaque, so it can't read the page, cookies or storage, or call the API. Its CSP allows only the inlined SDK and plug-in script (by hash), and network access only to declared hosts. Only unoMail may embed it. |
| Channel | Frames talk to the client over a private `MessageChannel`. Every call is checked against the manifest's permissions, rate limited and size limited. Views can't change the interface, and inserted HTML is sanitized. |
| Layout | Plug-ins add to fixed slots and hide only listed features. The client draws the chrome around their views, so a plug-in can't pass its content off as part of unoMail or remove a security warning. |
| Server modules | Interpreted WebAssembly with fuel, memory and time limits. Its one way out, `unomail.call`, answers only what the permissions allow. Web requests are https only, to declared hosts with public addresses. Header changes are validated, and identity headers are protected. Repeated failures suspend the module. |
| Themes | Bounded design tokens and images from the package only, with no CSS. Text that would become hard to read falls back to readable colours. |
| Pinning | Files are served from `/plugin-frame/<id>/<commit>` and `/package-asset/<id>/<commit>/…`. Code changes only when you approve an update. |
| Secrets | Secret settings are encrypted at rest. Admin secrets reach only the server module. |

A sandbox limits what a plug-in can reach, not what it does with what it's given. For
example:
- A plug-in with `message:read` (or `server:mail-body`) and a `network:` host can send the
  mail it reads to that host.
- One with `server:mail-incoming` decides what happens to every incoming message.

Review the code of the commit you install, and grant such combinations only to code you
trust.

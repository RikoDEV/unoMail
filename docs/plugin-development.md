# Writing plug-ins

This is the developer reference for unoMail plug-ins:
- the package layout
- the manifest
- every SDK call of the web part
- the server ABI and every host request
- the limits, and how to test and publish

Installing and administering packages is in [Plug-ins and themes](plugins.md). Themes are in
[Writing themes](theme-development.md). Working examples are in [`examples/`](examples).

## Contents

1. [Getting started](#getting-started)
2. [The manifest](#the-manifest)
3. [Permissions](#permissions)
4. [Settings](#settings)
5. [The web part](#the-web-part)
6. [SDK reference](#sdk-reference)
7. [Server modules](#server-modules)
8. [Host requests](#host-requests)
9. [Limits](#limits)
10. [Testing and debugging](#testing-and-debugging)
11. [Publishing and updating](#publishing-and-updating)
12. [Security checklist](#security-checklist)
13. [Guide: cloud storage integrations](#guide-cloud-storage-integrations)

## Getting started

A plug-in is a git repository with `unomail.json` at its root:

```text
my-plugin/
├── unomail.json      the manifest
├── index.js          the web part (optional): one bundled script
└── server.wasm       the server part (optional): a WebAssembly module, or server.wat
```

The smallest plug-in adds a button under every message:

```json
{
  "schema": 2,
  "id": "hello-world",
  "type": "plugin",
  "name": "Hello world",
  "version": "1.0.0",
  "api": "^2",
  "entry": "index.js",
  "permissions": ["message:read", "notify"]
}
```

```js
await unomail.ready;
unomail.ui.addMessageAction({
  id: 'hello',
  label: 'Say hello',
  onClick: (message) => unomail.notify(`You are reading "${message.subject}".`),
});
```

Push it, tag it (`git tag v1.0.0 && git push --tags`) and install it from
**Admin → Integrations → Plug-ins and themes** with the repository's https address and
`v1.0.0`.

**Rules for the files**
- There's no build step on the server. The repository must contain the final files.
- The web part must be one self-contained script: `import` isn't available, so use a bundler
  such as esbuild, Rollup or Vite in library mode, and commit the output.
- A repository may hold at most 2,000 files and 10 MB.
- The entry script may be at most 2 MB, and the server module at most 8 MB.
- Symbolic links and submodules are refused.

## The manifest

| Key | Type | Required | Notes |
| --- | --- | --- | --- |
| `schema` | number | yes | `2` |
| `id` | string | yes | `a-z`, `0-9`, `-`; at most 40 characters; can't start with `-`. Must stay the same across versions |
| `type` | string | yes | `"plugin"` |
| `name` | string | yes | At most 60 characters |
| `version` | string | yes | Letters, digits, `.`, `-`, `+`; at most 30 characters. Semantic versioning is recommended |
| `description` | string | | At most 300 characters |
| `author` | string | | At most 100 characters |
| `license` | string | | At most 40 characters, e.g. an SPDX id |
| `homepage` | string | | An `https://` address |
| `api` | string | yes | `"^2"`, the plug-in API this document describes |
| `entry` | string | | The web part: a relative path ending in `.js` |
| `server` | object | | The server part; see [Server modules](#server-modules) |
| `permissions` | string[] | | See [Permissions](#permissions) |
| `settings` | object[] | | See [Settings](#settings) |

- A plug-in needs `entry`, `server`, or both.
- Unknown keys, permissions, hooks or setting properties make the manifest invalid. The
  administrator sees the reason when fetching the package.

## Permissions

Ask only for what you use. The administrator sees each permission in plain words before
installing, and again for every permission an update adds.

| Permission | Grants | Used by |
| --- | --- | --- |
| `message:read` | The opened message's content (sender, recipients, subject, sanitized HTML, the list of attachments) | `message.getCurrent()`, message-action payloads, the `message:open` and `message:sent` events |
| `attachments:read` | The opened message's attachments, as files | `message.getAttachments()`, `message.getAttachment()`, the attachment list in message-action payloads |
| `composer:read` | The subject and recipients of the message being written | `composer.getSubject()`, `composer.getRecipients()` |
| `composer:write` | Changing the message being written: subject, text, links, attachments | `composer.setSubject()`, `composer.insertHtml()`, `composer.insertLink()`, `composer.addAttachment()` |
| `auth` | Asking the user to sign in at another service (OAuth) in a window | `auth.start()` |
| `sidebar` | Links that leave unoMail | `ui.addSidebarLink()`, `ui.addItem({ kind: 'link' })` |
| `panel` | A side panel showing the main frame | `ui.openPanel()`, `ui.closePanel()` |
| `storage` | Per-user data (64 KB per user) | `storage.get()`, `storage.set()` |
| `notify` | Short notices | `notify()` |
| `ui:widget` | Views in the mail, reader and composer slots | `ui.mount()` |
| `ui:page` | Pages in the navigation and sections in Settings | `ui.mount()` in `app.navigation` or `settings.section` |
| `ui:admin` | Pages in the administration | `ui.mount()` in `admin.section` |
| `ui:replace` | Hiding or replacing built-in features | `features.*` |
| `network:<host>` | https connections to one host, such as `network:api.example.com`. At most 10 per plug-in; no wildcards, ports or IP addresses. Servers the administrator enters in `host` settings are added to these | `fetch()` in the web part, `http.fetch` on the server, `auth.start()` |
| `server:mail-incoming` | The `mail:incoming` hook | `server.hooks` |
| `server:mail-outgoing` | The `mail:outgoing` hook | `server.hooks` |
| `server:mail-body` | The message body in mail hooks (otherwise headers only) | `server.hooks` |
| `server:routes` | Own HTTP routes at `/api/x/<id>/…` | `server.routes`, `server.call()` |
| `server:storage` | A store on the server: 1 MB for the package, plus 256 KB per user in routes | the `kv.*` requests |

## Settings

```json
"settings": [
  { "key": "apiKey",   "type": "string",  "label": "API key", "secret": true, "scope": "admin" },
  { "key": "language", "type": "select",  "label": "Language", "options": ["en", "de"], "default": "en" },
  { "key": "compact",  "type": "boolean", "label": "Compact view", "default": false }
]
```

| Property | Notes |
| --- | --- |
| `key` | Letters, digits, `_`; unique; at most 40 characters |
| `type` | `string`, `boolean`, `select` (with `options`) or `host` |
| `label` | Shown in the form; at most 80 characters |
| `scope` | `user` (default): each user, in Settings → General → Add-ons. `admin`: the administrator, with the gear button on the package's row |
| `options` | For `select`: 1 to 20 strings of at most 80 characters |
| `default` | Used until a value is saved. Must match the type, and for `select` be one of the options |
| `secret` | `string` only. Encrypted at rest and never shown again in the form; an empty field keeps the stored value |

**`host` settings** are for servers each installation names itself: a self-hosted cloud,
an on-premises API. They're `admin` scope only, and hold a host name such as
`cloud.example.org`. Once the administrator enters one, the plug-in may connect to that host
over https, as if it had declared `network:<host>`, in the browser and on the server. The
administrator sees "Send data to the server you enter as …" among the permissions.

- There are at most 20 settings.
- Users get a form generated from the manifest, and the plug-in can't draw its own settings
  form there. For anything richer, mount a view in `settings.section`.

**What receives the values:** every declared key is present in what a reader receives,
holding its saved value, its `default`, or `null`.

| Reader | User settings | Admin settings |
| --- | --- | --- |
| Web part: `settings.get()` | The signed-in user's, secrets included | |
| Web part: `settings.getAdmin()` | | All except secrets |
| Server module, mail hooks and schedules | | All, secrets included |
| Server module, routes | The calling user's, secrets included | All, secrets included |

## The web part

### How it runs

The entry script runs in `<iframe sandbox="allow-scripts">`, served from
`/plugin-frame/<id>/<commit>`.
- The frame has an **opaque origin**: no cookies, no `localStorage`/`sessionStorage`/
  IndexedDB, no access to the page around it, and no requests to unoMail's API.
- Its Content-Security-Policy allows only the SDK and the entry script, which are inlined.
  `eval` and `new Function` aren't available, and neither are other scripts, remote images,
  styles or fonts.
- `fetch` and `WebSocket` work only to hosts declared with `network:<host>`. Those requests
  carry `Origin: null`, so the service must allow that with CORS.
- Images can use `data:` and `blob:` addresses. Inline styles and `<style>` elements work.
- The script runs as a module, so top-level `await` works.

### Frames and views

Every plug-in has a hidden **main frame**, the one that starts when the user signs in.
- It registers the plug-in's actions, items, views and features.
- It receives clicks and events.
- While a panel is open, it's shown as that panel.

A **view** is another frame of the same document, placed in a slot. It runs the same entry
script; `context.view` tells it which view to draw. Views can use the SDK, except for calls
that change the interface (`ui.add*`, `ui.mount`, `ui.removeItem`, `ui.unmount`,
`features.*`).

```js
const context = await unomail.ready;
if (context.view === 'stats') {
  drawStats();                       // the view's frame draws it
} else if (context.view === null) {
  await unomail.ui.mount({ slot: 'reader.footer', id: 'stats', title: 'Stats', height: 80 });
}
```

### Slots

| Slot | Where | Items | Views need |
| --- | --- | --- | --- |
| `mail.toolbar` | Next to the search box | yes | `ui:widget` |
| `mail.sidebar` | Under the folders | yes | `ui:widget` |
| `reader.header` | Above the message body | yes | `ui:widget` |
| `reader.footer` | Under the message body, above the reply buttons | yes | `ui:widget` |
| `composer.toolbar` | The composer's toolbar | yes | `ui:widget` |
| `app.navigation` | A page at `/x/<id>/<view>`, linked in the sidebar | | `ui:page` |
| `settings.section` | A section in Settings | | `ui:page` |
| `admin.section` | A page in the administration, for super administrators | | `ui:admin` |

For administrators, plug-ins with `ui:admin` start even if they haven't turned them on
themselves. Started that way, a plug-in may only mount `admin.section` views.

### Built-in features

Plug-ins with `ui:replace` can hide these, or put a view in their place:

| Feature | What disappears |
| --- | --- |
| `calendar` | The calendar link, the menu entry and the page (its address leads to the mail) |
| `contacts` | The contacts link and the page |
| `smart-reply` | Suggested replies and their button in the reader |
| `summary-cards` | Summary cards in the reader |
| `masked-email` | The masked addresses section in Settings |
| `templates` | The templates button in the composer and the section in Settings |
| `composer.emoji` | The emoji button in the composer |
| `composer.schedule` | Scheduled sending in the send menu |

Anything else can't be removed, including:
- sign-in and two-step verification
- the warnings about unsafe content, phishing and senders
- Settings → Add-ons and Admin → Integrations
- the chrome around plug-in views and panels

A feature stays hidden while any plug-in hides it.

## SDK reference

Everything is on the global `unomail`, which is frozen. Calls return promises. A refused or
failed call rejects with an `Error` whose `message` says why: a missing permission, a limit,
or a value that isn't accepted.

### Types

```ts
interface Context {
  id: string;            // the plug-in's id
  account: string;       // the signed-in user's address
  view: string | null;   // null in the main frame, the view's id in a view
  redirectUri: string;   // the address to give OAuth providers; see auth.start()
  locale: string;        // interface language, e.g. "de"
  dir: 'ltr' | 'rtl';    // text direction; set document.dir to it
  dark: boolean;         // whether the interface is dark
}

interface Message {
  id: string;
  subject: string;
  from: { name: string | null; email: string }[];
  to: { name: string | null; email: string }[];
  receivedAt: string;    // ISO 8601
  html: string;          // sanitized HTML of the body
  attachments: Attachment[];
}

interface Attachment {
  id: string;            // pass to message.getAttachment()
  name: string;
  type: string;          // media type
  size: number;          // bytes
}

type Slot = 'mail.toolbar' | 'mail.sidebar' | 'reader.header' | 'reader.footer' | 'composer.toolbar'
          | 'app.navigation' | 'settings.section' | 'admin.section';
```

### `unomail.ready: Promise<Context>`

Resolves once the client has connected to the frame. Await it before anything else; calls
made earlier wait for it.

### `unomail.version: number`

`2`.

### `unomail.ui`

#### `addItem(options): Promise<void>`

Places a button, link or badge in a slot.

| Option | Type | Notes |
| --- | --- | --- |
| `slot` | Slot | `mail.toolbar`, `mail.sidebar`, `reader.header`, `reader.footer` or `composer.toolbar` |
| `id` | string | `a-z`, `0-9`, `-`; at most 40 characters; unique within the plug-in. Re-adding an id replaces the item |
| `kind` | `'button'` \| `'link'` \| `'badge'` | Default `'button'` |
| `label` | string | At most 40 characters |
| `icon` | string | One of `extension`, `star`, `bolt`, `translate`, `note`, `link`, `label`, `info`, `chart`, `calendar`, `task`, `cloud` |
| `href` | string | For `link`: an `http(s)` address, opened in a new tab. Needs `sidebar` |
| `onClick` | `() => void` | For `button`: required; runs in the main frame |

At most 20 items per plug-in.

#### `removeItem(id: string): Promise<void>`

Removes one of the plug-in's items.

#### `mount(options): Promise<void>`

Shows a view of the plug-in in a slot.

| Option | Type | Notes |
| --- | --- | --- |
| `slot` | Slot | Needs `ui:widget`, `ui:page` or `ui:admin`, as listed under [Slots](#slots) |
| `id` | string | The view's id, passed to its frame as `context.view` |
| `title` | string | Shown by the client: as the page title, in the navigation, and as the frame's accessible name. At most 60 characters |
| `height` | number | For widgets: 32 to 1200 pixels (default 120). Pages and sections fill the space they're given |

At most 10 views per plug-in. Re-mounting an id replaces the view.

#### `unmount(id: string): Promise<void>`

Removes a view.

#### `navigate(view: string): Promise<void>`

Opens one of the plug-in's own pages (a view mounted in `app.navigation`).

#### `addMessageAction({ id, label, onClick }): Promise<void>`

Adds a button to the reader's actions. `onClick(message)` runs in the main frame. It
receives:
- the `Message`, with `message:read`
- `{ id, attachments }`, with only `attachments:read`
- otherwise only `{ id }`

#### `addComposerAction({ id, label, onClick }): Promise<void>`

Adds a button to the composer. `onClick()` runs in the main frame. (Items in the
`composer.toolbar` slot work the same way.)

#### `addSidebarLink({ id, label, href }): Promise<void>`

An external link under the folders. Needs `sidebar`; `href` must be `http(s)`.

#### `openPanel({ title }): Promise<void>` / `closePanel(): Promise<void>`

Shows the main frame as a side panel, with a title bar and close button drawn by the client.
Draw the panel's content in the main frame's document. Needs `panel`. When the user closes
the panel, the main frame receives `panel:close`.

### `unomail.features` (needs `ui:replace`)

| Call | Effect |
| --- | --- |
| `hide(feature)` | Hides a [built-in feature](#built-in-features) |
| `show(feature)` | Undoes this plug-in's `hide` |
| `replace(feature, { id, title, height })` | Hides the feature and shows the plug-in's view `id` where it was |

### `unomail.message`

| Call | Returns | Needs |
| --- | --- | --- |
| `getCurrent()` | `Promise<Message \| null>`: the message the user opened last | `message:read` |
| `getAttachments()` | `Promise<Attachment[]>`: the attachments of the message opened last (inline images excluded) | `attachments:read` |
| `getAttachment(id)` | `Promise<File>`: one attachment's content, at most 100 MB | `attachments:read` |

`getAttachment` accepts the id of any attachment the plug-in was shown in this session: in
the open message, in a message-action payload, or in an event. The client downloads the
file with the user's session and hands over the `File`. The plug-in never learns the
download address, and can't read other messages.

### `unomail.composer`

These act on the **composer opened or focused last**: from a composer button, from a panel,
or from a view. Without an open composer they reject with "no message is being written".

| Call | Returns | Needs |
| --- | --- | --- |
| `getSubject()` | `Promise<string>` | `composer:read` |
| `getRecipients()` | `Promise<string>`: To and Cc, comma-separated | `composer:read` |
| `setSubject(text)` | `Promise<void>`; at most 500 characters | `composer:write` |
| `insertHtml(html)` | `Promise<void>`. Inserts at the cursor, sanitized like pasted content (no scripts, forms or remote content) | `composer:write` |
| `insertLink({ href, text })` | `Promise<void>`. Inserts a link at the cursor; `href` must be `http(s)`, and `text` is shown as plain text | `composer:write` |
| `addAttachment(file, { name, type })` | `Promise<void>`. Attaches a `File` or `Blob` (at most 100 MB). It's uploaded like a file the user picked, so the server's message size limit applies. `name` and `type` default to the file's own | `composer:write` |

### `unomail.auth` (needs `auth`)

#### `start({ url }): Promise<Record<string, string>>`

Signs the user in at another service with OAuth 2.0 (or anything that redirects back with
query parameters).

1. The plug-in builds the provider's authorization address. It sends `context.redirectUri`
   as the redirect address, and a fresh `state` of at least 16 random characters. Use PKCE
   too.
2. The client asks the user ("Sign in to accounts.example.com?"). If they continue, the
   address opens in a new window, from their click, so popup blockers don't interfere.
3. The provider sends the window back to `redirectUri`. That page hands the query
   parameters to the client and closes.
4. `start` resolves with those parameters (`{ code, state, … }`), matched to the request by
   `state`.

It rejects if the user cancels, after 10 minutes, or while another sign-in is waiting. The
provider's host must be declared (`network:<host>`) or entered in a `host` setting.

Register `redirectUri` with the provider. It's `https://<your server>/plugin-auth/callback`,
the same for every plug-in on that server.

**Handling the result**
- Check that `state` matches the one you sent.
- Exchange the code for tokens where the client secret is:
  - with a public client (PKCE, no secret), in the web part with `fetch`
  - with a confidential client, on the server: `server.call('auth/exchange', { code })`, and
    the module calls `http.fetch` with the secret from its admin settings
- Keep tokens in `storage` (web part) or in the user's `kv` scope (server).

### `unomail.storage` (needs `storage`)

Per-user data, kept on the server with the user's account: JSON values under string keys.

| Call | Notes |
| --- | --- |
| `get(key)` | `Promise<any>`: the value, or `null` |
| `set(key, value)` | `Promise<void>`. `value` is any JSON value; `null` deletes the key |

- Keys are 1 to 100 characters, and all of a user's data for the plug-in is at most 64 KB.
- The data is deleted when the plug-in is uninstalled.

### `unomail.settings`

| Call | Returns |
| --- | --- |
| `get()` | `Promise<Record<string, any>>`: the user's settings, secrets included |
| `getAdmin()` | `Promise<Record<string, any>>`: the administrator's settings, without secrets |

### `unomail.server` (needs `server:routes`)

#### `call(path: string, body?: any): Promise<any>`

Sends `body` as JSON to the plug-in's own server routes (`POST /api/x/<id>/<path>`) as the
signed-in user, and resolves with the module's `json`.
- `path` may use `A-Z a-z 0-9 . _ ~ - /`, but not `..` or a query.
- Status codes of 400 and above reject.

### `unomail.notify(text: string): Promise<void>`

Shows a short notice, prefixed with the plug-in's name (at most 300 characters). Needs
`notify`.

### `unomail.on(event, handler): void`

Delivered to every frame of the plug-in.

| Event | Payload | Notes |
| --- | --- | --- |
| `message:open` | `Message` | The user opened a message. Needs `message:read` |
| `message:sent` | `{ subject, recipients }` | The user sent a message. Needs `message:read` |
| `settings:change` | `null` | The user saved the plug-in's settings |
| `panel:close` | `null` | The user closed the plug-in's panel |

## Server modules

```json
"server": {
  "module": "server.wasm",
  "hooks": ["mail:incoming", "mail:outgoing"],
  "routes": true,
  "schedule": [{ "id": "cleanup", "everyMinutes": 60 }]
}
```

| Key | Notes |
| --- | --- |
| `module` | A relative path to a `.wasm` binary or `.wat` text module |
| `hooks` | `mail:incoming` (needs `server:mail-incoming`) and/or `mail:outgoing` (needs `server:mail-outgoing`) |
| `routes` | `true` to answer `/api/x/<id>/…` (needs `server:routes`) |
| `schedule` | Up to 5 jobs. `id` uses `a-z 0-9 -`; `everyMinutes` is 5 to 10080 |

Before installing, the server compiles the module and checks its imports and exports.

### The ABI

A module may be written in any language that compiles to WebAssembly without WASI, such as
Rust (`wasm32-unknown-unknown`), Zig, C, AssemblyScript or TinyGo (`-target wasm`). Each
call gets a **fresh instance**; keep anything that must last in `kv`.

**Exports (all required)**

| Export | Signature | Purpose |
| --- | --- | --- |
| `memory` | memory | The module's linear memory |
| `alloc` | `(len: i32) -> i32` | Returns the address of `len` writable bytes. The host calls it for the event; the module calls it for replies |
| `handle` | `(ptr: i32, len: i32) -> i64` | Receives the event (UTF-8 JSON at `ptr`, `len` bytes). Returns the answer's address and length as `(ptr << 32) \| len`. Length 0 means `null` |

**Imports (all optional; nothing else may be imported)**

| Import | Signature | Purpose |
| --- | --- | --- |
| `unomail.call` | `(ptr: i32, len: i32) -> i32` | Sends a request (JSON) and returns the length of the reply |
| `unomail.reply` | `(ptr: i32)` | Copies the reply to the last `call` to `ptr`. Allocate that many bytes first |

A minimal module in Rust (`cargo build --release --target wasm32-unknown-unknown`, with
`crate-type = ["cdylib"]` and `serde_json`):

```rust
use serde_json::{json, Value};

#[no_mangle]
pub extern "C" fn alloc(len: i32) -> i32 {
    let mut buffer = Vec::<u8>::with_capacity(len as usize);
    let ptr = buffer.as_mut_ptr();
    std::mem::forget(buffer);
    ptr as i32
}

#[link(wasm_import_module = "unomail")]
extern "C" {
    fn call(ptr: i32, len: i32) -> i32;
    fn reply(ptr: i32);
}

/// Sends one request to the host and returns its reply.
fn host(request: Value) -> Value {
    let bytes = request.to_string().into_bytes();
    unsafe {
        let len = call(bytes.as_ptr() as i32, bytes.len() as i32);
        let ptr = alloc(len);
        reply(ptr);
        let answer = std::slice::from_raw_parts(ptr as *const u8, len as usize);
        serde_json::from_slice(answer).unwrap_or(Value::Null)
    }
}

#[no_mangle]
pub extern "C" fn handle(ptr: i32, len: i32) -> i64 {
    let event: Value = unsafe { serde_json::from_slice(std::slice::from_raw_parts(ptr as *const u8, len as usize)) }.unwrap_or_default();
    let answer = match event["event"].as_str() {
        Some("mail:incoming") => {
            let prefix = host(json!({ "op": "settings.admin" }))["result"]["prefix"].as_str().unwrap_or("[EXT]").to_owned();
            let subject = event["headers"].as_array().into_iter().flatten()
                .find(|h| h[0].as_str().is_some_and(|n| n.eq_ignore_ascii_case("subject")))
                .and_then(|h| h[1].as_str()).unwrap_or("");
            json!({ "action": "accept", "setHeaders": [["Subject", format!("{prefix} {subject}")]] })
        }
        Some("http:request") => json!({ "status": 200, "json": { "hello": event["user"]["email"] } }),
        _ => Value::Null,
    };
    let bytes = answer.to_string().into_bytes();
    let (out, out_len) = (bytes.as_ptr() as i64, bytes.len() as i64);
    std::mem::forget(bytes);
    (out << 32) | out_len
}
```

A module written directly in WebAssembly text, with no build step, is in
[`examples/plugins/subject-tagger/server.wat`](examples/plugins/subject-tagger/server.wat).

### Events

Every event is an object with `event` naming it.

#### `mail:incoming`

Mail arriving from other servers. It runs after the spam, virus, authentication and milter
checks, and before delivery to the mailboxes.

```json
{
  "event": "mail:incoming",
  "envelope": { "sender": "ann@remote.example", "recipients": ["bob@example.org"], "ip": "203.0.113.5" },
  "headers": [["From", "Ann <ann@remote.example>"], ["Subject", "Hello"]],
  "body": "…"
}
```

- `headers` are in message order, unfolded, with names as written.
- `body` is present only with `server:mail-body`: the raw body after the headers, as text,
  at most 1 MB.

#### `mail:outgoing`

Mail a signed-in user sends, after the sender address has been checked and before it's
signed, queued or delivered. The payload has the same shape.

#### The answer to a mail hook

```json
{
  "action": "accept",
  "addHeaders": [["X-Category", "external"]],
  "setHeaders": [["Subject", "[EXT] Hello"]],
  "reply": "550 5.7.1 Not accepted here",
  "reason": "looks like spam"
}
```

| Field | Notes |
| --- | --- |
| `action` | `accept` (default), `reject`, `tempfail`, `quarantine` (incoming only: delivered to Junk), `discard` (incoming only: dropped silently) |
| `addHeaders` | `[name, value]` pairs added at the top; at most 20 |
| `setHeaders` | `[name, value]` pairs replacing every header of that name, or adding it; at most 20 |
| `reply` | For `reject`, an SMTP reply starting with `5`; for `tempfail`, one starting with `4`. Otherwise a standard reply is used |
| `reason` | For `quarantine`, written to the server log |

**Header rules**
- Names use letters, digits and `-`, at most 76 characters.
- Values are at most 998 characters, with no line breaks.
- These headers can't be added or set: `From`, `Sender`, `Reply-To`, `To`, `Cc`, `Bcc`,
  `Date`, `Message-ID`, `Return-Path`, `Received`, `DKIM-Signature`,
  `Authentication-Results`, `ARC-*`, `Content-Type`, `Content-Transfer-Encoding`,
  `MIME-Version`.
- An invalid answer counts as a failure of the plug-in.

With several plug-ins hooked in, they run in the order of their ids. Each sees the message
as the previous one left it. The first `reject`, `tempfail` or `discard` ends the chain.

#### `http:request`

A request to `/api/x/<id>/<path>`, with any method, from a signed-in user. Requests are
CSRF-protected, as the rest of the API is.

```json
{
  "event": "http:request",
  "method": "POST",
  "path": "/stats",
  "query": "period=week",
  "body": { "any": "json" },
  "user": { "email": "bob@example.org", "role": "user" }
}
```

- `body` is `null` when empty; otherwise it must be JSON of at most 256 KB.
- `role` is `user`, `domain_admin` or `super_admin`.

Answer `{ "status": 200, "json": … }`. `status` is 200 to 599 (default 200); `json`
defaults to `null`.

#### `schedule`

```json
{ "event": "schedule", "id": "cleanup" }
```

Runs about every `everyMinutes`. The first run comes one interval after the server starts.
The answer is ignored.

## Host requests

Send a request with `unomail.call`. Every reply is either
`{ "ok": true, "result": … }` or `{ "ok": false, "error": "…" }`.

| Request | Result | Needs |
| --- | --- | --- |
| `{ "op": "log", "message": "…" }` | `null`. Written to the server log with the plug-in's id | |
| `{ "op": "settings.admin" }` | The admin settings, secrets included | |
| `{ "op": "settings.user" }` | In routes, the calling user's settings; elsewhere `{}` | |
| `{ "op": "kv.get", "key": "k", "scope": "package" }` | The stored JSON value, or `null` | `server:storage` |
| `{ "op": "kv.set", "key": "k", "value": …, "scope": "package" }` | `null` | `server:storage` |
| `{ "op": "kv.delete", "key": "k", "scope": "package" }` | `null` | `server:storage` |
| `{ "op": "kv.list", "scope": "package" }` | Up to 1,000 keys of that scope, sorted | `server:storage` |
| `{ "op": "http.fetch", "url": "https://…", "method": "GET", "headers": { … }, "body": "…" }` | `{ "status", "contentType", "body" }`, or `bodyBase64` with `"binary": true` | `network:<host>` |

**`kv`**
- `scope` is `package` (the default) or `user`.
- `package` is shared by the whole package, at most 1 MB.
- `user` is the calling user's own part, at most 256 KB per user: their tokens and
  preferences. It's only available in routes; elsewhere it's refused.
- Keys are 1 to 200 characters. Everything is deleted on uninstall.

**`http.fetch`**
- `method` is one of:
  - `GET` (default), `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`
  - WebDAV's `PROPFIND`, `MKCOL`, `MOVE`, `COPY`
- The request body is `body` (text) or `bodyBase64` (binary).
- With `"binary": true`, the response comes back as `bodyBase64` instead of text.
- The address must be `https`, to a declared host, without credentials, and resolve to a
  public address; the connection goes to the address that was checked.
- Redirects aren't followed.
- The headers `Host`, `Cookie`, `Connection`, `Content-Length` and `Transfer-Encoding` are
  ignored.
- Timeouts and sizes depend on where the request is made:

  | Made from | Timeout | Request and response |
  | --- | --- | --- |
  | Mail hooks | 3 s | 1 MB |
  | Routes | 15 s | 16 MB |
  | Schedules | 55 s | 16 MB |

## Limits

| | Web part | Mail hooks | Routes | Schedules |
| --- | --- | --- | --- | --- |
| Calls | 50 per second | | | |
| Size | 256 KB per call; files up to 100 MB | 1 MB event/answer | 256 KB request, 1 MB answer; 16 MB per web request | 16 MB per web request |
| Fuel (instructions) | | 50 million | 200 million | 200 million |
| Time | 15 s without a heartbeat answer stops the plug-in | 5 s | 20 s | 60 s |
| Memory | The browser's | 64 MB | 64 MB | 64 MB |
| At once | | 4 calls per package | 4 | 4 |

- **When a mail hook fails** (it traps, runs out of fuel or time, or gives an invalid
  answer), the mail is passed on as if the plug-in weren't installed. If the administrator
  switches on **Hold mail when the plug-in fails**, the mail is deferred with `451` instead,
  and the sending server retries.
- **Suspension:** after 20 failures in 5 minutes, all server calls of the package stop for
  15 minutes, and the audit log records `package.suspended`.

## Testing and debugging

- **Web part:** open the browser's developer tools. Plug-in frames show up as
  `/plugin-frame/<id>/<commit>`; pick one in the console's context selector to inspect it.
  `console.log` works there.
- **Server part:** `{ "op": "log" }` and failures appear in the server log (`UNOMAIL_LOG=info`)
  as `plug-in log` and `plug-in call failed`.
- **Local repositories:** a test server started with `UNOMAIL_PACKAGES_ALLOW_LOCAL=true` also
  installs from `file://` addresses, so you can try a commit without pushing it. Never set
  this on a server people use.
- **Validation:** fetching a package (Admin → Integrations → Fetch) runs every check without
  installing anything. The error says what to fix.
- **Run the module yourself** in any WebAssembly runtime (wasmtime, Node's `WebAssembly`):
  call `alloc`, write an event, call `handle`, and provide `unomail.call`/`unomail.reply`
  stubs.

## Publishing and updating

1. Commit the final files, with the bundled entry script and the compiled module, and tag
   the commit (`v1.2.0`).
2. Tell administrators the repository address and the tag. Installing pins the exact commit.
3. For an update, push a new tag, or move the tag the administrator installed (`stable`, for
   example). **Check for updates** then offers the new commit and lists the permissions it
   adds.
4. Keep `id` the same: a repository whose id changed is refused as an update.
5. Keep settings keys stable. Values of removed keys are dropped; new keys start with their
   `default`.

## Security checklist

- Ask only for the permissions you use. Combinations such as `message:read` with a
  `network:` host, or a mail hook with `server:mail-body`, let a plug-in pass mail to a third
  party, and administrators are told so.
- Store tokens and keys as `secret` settings, never in the repository.
- Escape anything you put into `insertHtml` or your own document. The composer sanitizes,
  but your frame's own DOM doesn't.
- Make mail hooks fast and total: answer `accept` when unsure. A crashing hook is skipped,
  but it counts towards suspension.
- Treat `http:request` bodies as untrusted, and check `user.role` before doing anything
  administrative.
- In OAuth flows, use a fresh random `state` and PKCE for every sign-in, check `state` on
  return, and keep client secrets on the server.

## Guide: cloud storage integrations

The pieces a cloud storage plug-in usually needs, and where they come from:

| Need | API |
| --- | --- |
| Which cloud server (self-hosted) | An admin `host` setting, e.g. `{ "key": "server", "type": "host", "scope": "admin" }` |
| Signing the user in | `auth.start()` (OAuth), or user settings with a `secret` app password |
| Save an attachment to the cloud | `message.getAttachments()` + `message.getAttachment(id)` → `fetch(PUT)` to the cloud |
| Attach a cloud file | A panel or view with a file picker → `fetch(GET)` → `composer.addAttachment(blob, { name })` |
| Share a large file as a link | The cloud's share API → `composer.insertLink({ href, text })` |
| Remember tokens and folders | `storage` (web part) or `kv` with `"scope": "user"` (server) |
| Do it on the server instead (no CORS, secrets stay there) | `server.call()` → a route → `http.fetch` with `bodyBase64`, up to 16 MB |
| Act on every incoming message (e.g. archive attachments) | A `mail:incoming` hook with `server:mail-body`. Keep it under 3 s; queue bigger work in `kv` for a `schedule` job |

Moving files in the browser is the fastest way, but the cloud must accept cross-origin
requests from `Origin: null`. When it doesn't, do the transfer on the server.

[`examples/plugins/cloud-files`](examples/plugins/cloud-files) is a complete WebDAV
integration (Nextcloud, ownCloud and others). It saves a message's attachments to a folder
and attaches files from a panel in the composer.

An OAuth sign-in in the web part (a public client with PKCE):

```js
const context = await unomail.ready;
const random = (bytes) => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(bytes)))).replace(/[+/=]/g, '');
const verifier = random(48);
const challenge = btoa(String.fromCharCode(...new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier)))))
  .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const state = random(24);

const url = new URL('https://login.cloud.example/oauth/authorize');
url.search = new URLSearchParams({
  client_id: 'unomail-plugin', response_type: 'code', redirect_uri: context.redirectUri,
  scope: 'files', state, code_challenge: challenge, code_challenge_method: 'S256',
}).toString();

const answer = await unomail.auth.start({ url: url.toString() });
if (answer.state !== state || !answer.code) throw new Error('The sign-in failed.');
const tokens = await (await fetch('https://login.cloud.example/oauth/token', {
  method: 'POST',
  body: new URLSearchParams({ grant_type: 'authorization_code', code: answer.code, redirect_uri: context.redirectUri, client_id: 'unomail-plugin', code_verifier: verifier }),
})).json();
await unomail.storage.set('tokens', tokens);
```

With `"permissions": ["auth", "storage", "network:login.cloud.example", …]`.

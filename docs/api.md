# API and command line

## Masked addresses

### REST

Session-authenticated, CSRF-protected.

```text
GET/POST      /api/me/masked-addresses
PATCH/DELETE  /api/me/masked-addresses/{id}
GET           /api/me/masked-addresses/domains
GET/POST      /api/me/masked-addresses/tokens
DELETE        /api/me/masked-addresses/tokens/{id}
```

| Field | Create | Update |
| --- | --- | --- |
| `description`, `for_domain`, `enabled` | ✓ | ✓ |
| `integration_url` (HTTPS) | ✓ | ✓ |
| `prefix`, `domain` | ✓ | |
| `expires_at` (Unix seconds or `null`) | ✓ | |

### JMAP

Capability `urn:unomail:params:jmap:masked-email` with `MaskedEmail/get`, `/query`, `/set`
and `/changes`. Regular clients use `/jmap/api`. Integrations use a mask-only token:

```text
GET   /api/masked-email/session
POST  /api/masked-email/jmap
Authorization: Bearer um_mask_...
```

```json
{
  "using": ["urn:ietf:params:jmap:core", "urn:unomail:params:jmap:masked-email"],
  "methodCalls": [["MaskedEmail/set", {
    "accountId": "a1",
    "create": {"new": {"description": "Shopping", "forDomain": "https://shop.example"}}
  }, "create"]]
}
```

**Tokens** can't read mail, send, or reach other accounts. Each account can hold up to 10.
They last 90 days from the UI and up to a year from the API, and only their hash is stored.

## Plug-ins and themes

Session-authenticated, CSRF-protected. Writing a package is in
[Writing plug-ins](plugin-development.md); every route is also in `/api/openapi.json`.

### Administration (super administrators)

```text
POST    /api/packages/preview          {url, ref}           fetch and validate, nothing installed
POST    /api/packages                  {token}              install or update from a preview
PUT     /api/packages/{id}             {enabled}            make available to users, or withdraw
DELETE  /api/packages/{id}                                  uninstall: files, settings and data
POST    /api/packages/{id}/update                           newest commit of the ref, as a preview
GET/PUT /api/packages/{id}/settings    {settings, failClosed}
```

- A preview returns `{ token, url, ref, commit, manifest, update, newPermissions }`.
- A token is used once and expires after 15 minutes.
- An update to a package already up to date returns `{ upToDate: true, commit }`.
- Secret settings come back as `{ "set": true }`. A secret sent empty keeps the stored value.

### Users

```text
GET     /api/packages                                       available packages, with the user's choices
PUT     /api/me/packages/{id}          {enabled, settings}  turn a plug-in on or off, user settings
GET     /api/me/packages/{id}/settings                      user settings as the plug-in receives them
GET     /api/me/packages/{id}/admin-settings                admin settings without secrets
GET/PUT /api/me/packages/{id}/storage  {key, value}         per-user plug-in data (64 KB; null deletes)
ANY     /api/x/{id}/{path}                                  the plug-in's own routes (its server module)
GET     /api/me/startup                                     includes `themes` and `packages` to start
```

### Without a session

The sandboxed plug-in frames and theme images are fetched without cookies:

```text
GET  /plugin-frame/{id}/{commit}[?view=…]        frame document with the SDK and the entry inlined
GET  /package-asset/{id}/{commit}/{path}         an image the theme declared
GET  /plugin-auth/callback                       where OAuth providers return plug-ins' sign-in windows
```

Both serve only enabled packages at their installed commit.

## Server commands

The binary runs the server when started without a command.

| Command | Description |
| --- | --- |
| `backup` | Take a backup now |
| `backups` | List snapshots |
| `restore [SNAPSHOT] [--force]` | Restore a snapshot (default: latest). Stop the server first. |
| `migrate-blobs [--from DIR]` | Move message contents to the configured store; encrypt them if `UNOMAIL_ENCRYPT_MAIL` is on |
| `masked-email list\|create\|update\|delete ACCOUNT [ID] [JSON]` | Manage masks |

```sh
docker compose exec -u unomail unomail unomail backup
unomail masked-email create alice@example.com '{"description":"Shopping","prefix":"shop"}'
```

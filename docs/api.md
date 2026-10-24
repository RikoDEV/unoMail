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

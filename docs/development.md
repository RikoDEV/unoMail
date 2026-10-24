# Development

Requirements: Rust (stable), Node 24 with pnpm, Docker.

## Tests

```sh
cd server && cargo test && cargo clippy --all-targets -- -D warnings
cd web && pnpm install && pnpm run typecheck && pnpm test && pnpm run build
cd e2e && pnpm install && pnpm exec playwright install chromium && pnpm test
./audit.sh
```

Live tests (need Docker; see each file's header):

```sh
cd server && cargo test --test acme_live -- --ignored
cd server && cargo test --test ldap_live -- --ignored
```

## Local server with hot reload

Start the server on unprivileged ports, then run Vite, which proxies API calls to it.

```sh
cd server && UNOMAIL_HTTP_PORT=8080 UNOMAIL_HTTPS_PORT=8443 UNOMAIL_SMTP_PORT=2525 \
  UNOMAIL_SUBMISSION_PORT=2587 UNOMAIL_SMTPS_PORT=2465 UNOMAIL_IMAPS_PORT=2993 \
  UNOMAIL_IMAP_PORT=2143 UNOMAIL_POP3S_PORT=2995 \
  UNOMAIL_HTTP_REDIRECT=false UNOMAIL_COOKIE_SECURE=false \
  UNOMAIL_ADMIN_EMAIL=admin@example.test UNOMAIL_ADMIN_PASSWORD=dev-password-123 cargo run
cd web && pnpm dev
python dev/seed.py   # optional sample data
```

PowerShell:

```powershell
$env:UNOMAIL_HTTP_PORT=8080; $env:UNOMAIL_HTTPS_PORT=8443; $env:UNOMAIL_SMTP_PORT=2525
$env:UNOMAIL_SUBMISSION_PORT=2587; $env:UNOMAIL_SMTPS_PORT=2465; $env:UNOMAIL_IMAPS_PORT=2993
$env:UNOMAIL_IMAP_PORT=2143; $env:UNOMAIL_POP3S_PORT=2995
$env:UNOMAIL_HTTP_REDIRECT='false'; $env:UNOMAIL_COOKIE_SECURE='false'
$env:UNOMAIL_ADMIN_EMAIL='admin@example.test'; $env:UNOMAIL_ADMIN_PASSWORD='dev-password-123'
cd server; cargo run
```

## CI

[`ci.yml`](../.github/workflows/ci.yml) runs on pull requests and on pushes to `main`. Only
the jobs for the changed parts run.

| Job | Runs |
| --- | --- |
| `server` | Tests, Clippy, live ACME and LDAP tests |
| `web` | Type check, unit tests, build |
| `e2e` | Playwright against the real server |
| `audit` | `./audit.sh`, also weekly |
| `published-image` | Weekly Trivy scan of the latest image |

[`release.yml`](../.github/workflows/release.yml) builds binaries and images for `v*` tags.

## Dependencies

[Renovate](https://docs.renovatebot.com/) opens update PRs on Mondays
([config](../.github/renovate.json)). Minor and patch updates are grouped per project.
RustCrypto crates are held back on purpose; the config explains why.

Advisories ignored by `./audit.sh` are justified in `server/.cargo/audit.toml`.

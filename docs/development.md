# Development

Requirements: Rust (stable), Node 24+ with pnpm, Docker for the image.

```sh
# Backend: unit and integration tests (real sockets, TLS, a fake remote mail server)
cd server && cargo test && cargo clippy --all-targets

# Front end: type check, unit tests, production build
cd web && pnpm install && pnpm run typecheck && pnpm test && pnpm run build

# End to end: starts the real server with the built UI and drives it in Chromium
cd e2e && pnpm install && pnpm exec playwright install chromium && pnpm test

# Certificate issuance against a real ACME server (needs Docker; see the file header)
cd server && cargo test --test acme_live -- --ignored

# Address book lookups against a real LDAP server (needs Docker; see the file header)
cd server && cargo test --test ldap_live -- --ignored

# Dependency vulnerability audit
./audit.sh
```

To work on the UI with hot reload, start the server on plain HTTP and run Vite, which proxies
API calls to it:

```sh
cd server && UNOMAIL_HTTP_PORT=8080 UNOMAIL_HTTPS_PORT=8443 UNOMAIL_SMTP_PORT=2525 \
  UNOMAIL_SUBMISSION_PORT=2587 UNOMAIL_SMTPS_PORT=2465 UNOMAIL_IMAPS_PORT=2993 UNOMAIL_IMAP_PORT=2143 UNOMAIL_POP3S_PORT=2995 \
  UNOMAIL_HTTP_REDIRECT=false UNOMAIL_COOKIE_SECURE=false \
  UNOMAIL_ADMIN_EMAIL=admin@example.test UNOMAIL_ADMIN_PASSWORD=dev-password-123 cargo run
cd web && pnpm dev

# Optional: sample mailboxes (alice, bob), an alias and a varied inbox
python dev/seed.py
```

# Contributing to unoMail

Thanks for your interest! Bug reports, fixes and improvements are welcome.

## Reporting issues

- **Security vulnerabilities:** do not open a public issue; follow [SECURITY.md](SECURITY.md).
- **Bugs:** open an issue with the unoMail version, how you run it (Docker or binary), steps to
  reproduce, and relevant log output (with addresses and secrets removed).

## Development setup

- **Server** (`server/`): Rust stable. `cargo test` runs the test suite;
  `cargo clippy --all-targets -- -D warnings` must pass.
- **Web client** (`web/`): Node 24 and pnpm. `pnpm install`, then `pnpm run typecheck`,
  `pnpm test` and `pnpm run build`.
- **End-to-end tests** (`e2e/`): Playwright, run with `pnpm test` after building the web client.
- **Dependency audit:** `./audit.sh`. See [Development](docs/development.md) for CI and dependency updates.

## Pull requests

- Keep changes focused; one topic per pull request.
- Add or update tests for behaviour changes.
- Match the style of the surrounding code.
- CI must be green before a pull request is merged.

By contributing, you agree that your contributions are licensed under the
[GNU Affero General Public License v3.0](LICENSE).

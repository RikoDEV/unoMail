#!/bin/sh
# Dependency vulnerability audit for every part of the project.
# Requires cargo-audit (cargo install cargo-audit --locked) and pnpm.
set -eu
cd "$(dirname "$0")"
echo "== Rust (server) =="; (cd server && cargo audit)
echo "== Web client ==";   (cd web && pnpm audit --prod)
echo "== E2E tooling ==";  (cd e2e && pnpm audit)

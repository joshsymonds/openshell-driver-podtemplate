#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
# SPDX-License-Identifier: Apache-2.0
#
# The fast gate. Runs formatting, clippy with warnings denied, every test except
# the kind-backed e2e tests, rustdoc with warnings denied, cargo-deny, the SPDX
# gate and markdownlint. Exits non-zero at the first step that fails.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
root=$(cd -- "$script_dir/.." && pwd -P)
cd -- "$root"

cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Kind-backed tests live in integration-test binaries named e2e*. nextest
# rejects a binary() filter that matches no test binary, so the exclusion
# applies only once an e2e binary exists.
e2e_binaries=$(cargo nextest list --workspace --list-type binaries-only --message-format json |
  jq -r '."rust-binaries"[]."binary-name" | select(startswith("e2e"))')
if [ -n "$e2e_binaries" ]; then
  cargo nextest run --workspace -E 'not binary(/^e2e/)'
else
  cargo nextest run --workspace
fi

RUSTDOCFLAGS='-D warnings' cargo doc --workspace --no-deps
cargo deny check -D warnings
"$script_dir/odp-spdx.sh"
markdownlint-cli2

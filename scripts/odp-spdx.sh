#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
# SPDX-License-Identifier: Apache-2.0
#
# Lists every repository file whose first five lines lack an SPDX header.
# Exits 1 when any file is listed, 0 otherwise. Paths are repository-relative.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
root=$(cd -- "$script_dir/.." && pwd -P)
cd -- "$root"

has_header() {
  local first
  first=$(head -n 5 -- "$1" | tr -d '\0')
  grep -q -F 'SPDX-FileCopyrightText:' <<<"$first" &&
    grep -q -F 'SPDX-License-Identifier: Apache-2.0' <<<"$first"
}

files=$(
  find . \
    \( -name .git -prune \) -o \
    \( -type d \( -name target -o -name .devenv -o -name .direnv \) -prune \) \
    -o \( -type f ! -name .devenv.flake.nix -print \) |
    LC_ALL=C sort
)

status=0
while IFS= read -r rel; do
  [ -n "$rel" ] || continue
  rel=${rel#./}
  case $rel in
    LICENSE | NOTICE | Cargo.lock | devenv.lock) continue ;;
  esac
  if ! has_header "$rel"; then
    printf '%s\n' "$rel"
    status=1
  fi
done <<<"$files"

exit "$status"

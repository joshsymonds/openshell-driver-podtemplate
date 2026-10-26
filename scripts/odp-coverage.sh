#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

# Runs every workspace test except the e2e_gateway binary, kind-backed ones
# included, under coverage with a 90% line floor. The kind cluster exists only for
# the duration of this run.
cd "$(dirname "${BASH_SOURCE[0]}")/.."

kubeconfig_dir=$(mktemp -d)

cleanup() {
  local status=$?
  if ! kind delete cluster --name odp-coverage; then
    echo "odp-coverage: failed to delete kind cluster odp-coverage" >&2
    status=1
  fi
  rm -rf "$kubeconfig_dir"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

kind create cluster --name odp-coverage --image docker.io/kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f --kubeconfig "$kubeconfig_dir/kubeconfig"
export KUBECONFIG="$kubeconfig_dir/kubeconfig"

# The e2e_gateway binary needs the gateway that odp-e2e installs, so it is left out.
cargo llvm-cov nextest --workspace -E 'not binary(e2e_gateway)' --fail-under-lines 90

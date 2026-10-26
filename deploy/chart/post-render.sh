#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
# SPDX-License-Identifier: Apache-2.0
#
# Helm post-renderer for the stock OpenShell chart. Reads the rendered manifests
# on stdin, applies deploy/chart/kustomization.yaml to them with kubectl
# kustomize, and writes the result to stdout. The chart has no hook for extra
# containers, so the driver sidecar and its RBAC come in through this step. The
# work directory is removed on exit.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)

workdir=$(mktemp -d)
trap 'rm -rf -- "$workdir"' EXIT

cat >"$workdir/rendered.yaml"
cp -- "$script_dir/kustomization.yaml" "$script_dir/driver-sidecar.yaml" \
  "$script_dir/rbac.yaml" "$workdir/"
kubectl kustomize "$workdir"

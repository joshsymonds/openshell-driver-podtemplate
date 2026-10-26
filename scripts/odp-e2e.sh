#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
# SPDX-License-Identifier: Apache-2.0
#
# Creates the kind cluster odp-e2e, runs the e2e_gateway binary against it and
# deletes the cluster again. The binary runs against the stock OpenShell v0.1.5
# gateway with the driver sidecar: the script loads the driver images, installs
# the chart, applies the fixture and forwards the gateway port to the host. Its
# tests run in parallel, except the ones .config/nextest.toml runs alone. The
# driver API tests are not run here; odp-coverage runs them once. The script ends
# by counting the images that carry the build label openshell-driver-podtemplate.build,
# tagged or dangling, and fails unless the count is 0. The cluster, the port-forward
# and the temporary kubeconfig directory are removed on success, failure and
# interruption. The script exits with the suite's status, or 1 when the count is not 0.
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
root=$(cd -- "$script_dir/.." && pwd -P)
cd -- "$root"

cluster=odp-e2e
gateway_port=18443
workdir=$(mktemp -d)
port_forward_pid=

cleanup() {
  local status=$?
  if [ -n "$port_forward_pid" ] && kill "$port_forward_pid" 2>/dev/null; then
    wait "$port_forward_pid" 2>/dev/null || true
  fi
  kind delete cluster --name "$cluster" || status=$?
  rm -rf -- "$workdir"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# wait_for_port <port> waits until the forwarded gateway port accepts a connection.
wait_for_port() {
  local attempt
  for attempt in $(seq 1 60); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "odp-e2e: nothing listens on 127.0.0.1:$1" >&2
  return 1
}

kubeconfig="$workdir/kubeconfig"
kind create cluster --name "$cluster" --image docker.io/kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f --kubeconfig "$kubeconfig"
export KUBECONFIG="$kubeconfig"

"$root/scripts/odp-images.sh" "$cluster"
helm upgrade --install openshell oci://ghcr.io/nvidia/openshell/helm-chart \
  --version 0.1.5 \
  --namespace openshell \
  --create-namespace \
  -f "$root/deploy/chart/values.yaml" \
  --post-renderer "$root/deploy/chart/post-render.sh" \
  --wait \
  --timeout 10m
kubectl apply \
  -f "$root/deploy/fixture/secret.yaml" \
  -f "$root/deploy/fixture/configmap.yaml" \
  -f "$root/deploy/fixture/podtemplate.yaml" \
  -f "$root/deploy/fixture/podtemplate-init-egress.yaml" \
  -f "$root/deploy/fixture/invalid-templates.yaml" \
  -f "$root/deploy/fixture/echo.yaml"
kubectl wait --namespace openshell --for=condition=Ready pod/odp-echo --timeout=5m

# forward_gateway keeps the gateway port forwarded to the host. The forward ends when the gateway
# pod is replaced, so the loop starts it again until cleanup signals the loop. The trap stops the
# kubectl that the loop waits for, so the forward ends with the loop.
forward_gateway() {
  local forward_pid=
  trap 'kill "$forward_pid" 2>/dev/null || true; exit 0' TERM
  while :; do
    kubectl port-forward --namespace openshell service/openshell "$gateway_port:8080" \
      >>"$workdir/port-forward.log" 2>&1 &
    forward_pid=$!
    wait "$forward_pid" || true
    sleep 1
  done
}

forward_gateway &
port_forward_pid=$!
wait_for_port "$gateway_port"

ODP_GATEWAY_ENDPOINT="https://127.0.0.1:$gateway_port" \
  cargo nextest run --workspace -E 'binary(e2e_gateway)'

# odp-images labels every build stage openshell-driver-podtemplate.build and removes the
# images it built, so an image that still carries the label is a leftover and fails the gate.
leftover=$(podman images --all --filter label=openshell-driver-podtemplate.build --quiet | wc -l)
if [ "$leftover" -ne 0 ]; then
  echo "odp-e2e: $leftover images still carry openshell-driver-podtemplate.build" >&2
  exit 1
fi

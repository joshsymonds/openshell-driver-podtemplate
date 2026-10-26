#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
# SPDX-License-Identifier: Apache-2.0
#
# Builds the driver and probe-helper images with rootless podman and loads both
# into the kind cluster named by the argument. Each build reads a temporary
# ignore file, so target/, .devenv/ and .direnv/ never enter the build context.
# Every stage of both images carries the build label. Once kind has loaded an
# image, its :e2e tag is removed. On success, failure and interruption, the
# image archives, the ignore file and every image carrying the label are
# removed. The script does not create or delete the cluster.
# usage: scripts/odp-images.sh <kind-cluster>
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
root=$(cd -- "$script_dir/.." && pwd -P)
cd -- "$root"

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
  echo "usage: scripts/odp-images.sh <kind-cluster>" >&2
  exit 2
fi
cluster=$1
workdir=$(mktemp -d)
label=openshell-driver-podtemplate.build=e2e

# remove_labelled removes every image carrying the build label, tagged or dangling.
remove_labelled() {
  podman images --all --filter "label=$label" --quiet | sort -u | xargs -r podman rmi --force --
}

cleanup() {
  local status=$?
  trap - EXIT
  rm -rf -- "$workdir"
  if ! remove_labelled; then
    echo "odp-images: could not remove the images labelled $label" >&2
    if [ "$status" -eq 0 ]; then status=1; fi
  fi
  exit "$status"
}
trap cleanup EXIT

ignorefile="$workdir/containerignore"
printf '%s\n' target .devenv .direnv >"$ignorefile"

# build_and_load <containerfile> <image> <archive-name>
build_and_load() {
  local containerfile=$1 image=$2 archive="$workdir/$3.tar"
  podman build --file "$containerfile" --ignorefile "$ignorefile" --tag "$image" .
  podman save --format docker-archive --output "$archive" "$image"
  kind load image-archive "$archive" --name "$cluster"
  rm -f -- "$archive"
  podman rmi -- "$image"
}

build_and_load deploy/images/driver.Containerfile localhost/openshell-driver-podtemplate:e2e driver
build_and_load deploy/images/probe-helper.Containerfile localhost/odp-probe-helper:e2e probe-helper

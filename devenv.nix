# SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
# SPDX-License-Identifier: Apache-2.0
{ pkgs, ... }:

{
  packages = [
    pkgs.kind
    pkgs.kubectl
    pkgs.kubernetes-helm
    pkgs.jq
    pkgs.cargo-nextest
    pkgs.cargo-llvm-cov
    pkgs.cargo-deny
    pkgs.markdownlint-cli2
  ];

  # Toolchain pinned by rust-toolchain.toml, resolved through the rust-overlay
  # input declared in devenv.yaml.
  languages.rust = {
    enable = true;
    toolchainFile = ./rust-toolchain.toml;
  };

  env = {
    # kind talks to the host's container runtime. A rootless-podman host runs
    # podman, not docker; this selects kind's podman provider.
    KIND_EXPERIMENTAL_PROVIDER = "podman";

    # openshell-core's build script honours PROTOC and otherwise runs a vendored
    # protoc that does not run on NixOS.
    PROTOC = "${pkgs.protobuf}/bin/protoc";
  };

  scripts = {
    odp-check.exec = ''"$DEVENV_ROOT/scripts/odp-check.sh" "$@"'';
    odp-coverage.exec = ''"$DEVENV_ROOT/scripts/odp-coverage.sh" "$@"'';
    odp-e2e.exec = ''"$DEVENV_ROOT/scripts/odp-e2e.sh" "$@"'';
    odp-spdx.exec = ''"$DEVENV_ROOT/scripts/odp-spdx.sh" "$@"'';
  };
}

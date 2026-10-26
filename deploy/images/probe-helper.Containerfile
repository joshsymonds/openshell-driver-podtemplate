# SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
# SPDX-License-Identifier: Apache-2.0
#
# The odp-probe helper on scratch. The driver's init container copies the
# binary into a shared volume, and it then runs inside arbitrary workload
# images, so it is linked statically against musl and carries no other files.

FROM docker.io/library/rust:1.95.0-trixie@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3 AS builder
LABEL openshell-driver-podtemplate.build=e2e

# musl-gcc provides the C compiler for aws-lc-sys on the musl target. cmake is
# needed by the aws-lc-sys build.
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake musl-tools \
 && rm -rf /var/lib/apt/lists/* \
 && rustup target add x86_64-unknown-linux-musl

ENV CC_x86_64_unknown_linux_musl=musl-gcc

WORKDIR /src
COPY . .
# The cargo registry and target/ are cache mounts, which are not part of the
# stage's layer. The binary is copied to /out in the same RUN so that the final
# stage can read it.
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=odp-cargo-registry \
    --mount=type=cache,target=/src/target,id=odp-probe-target \
    cargo build --release --locked \
      --target x86_64-unknown-linux-musl \
      --package odp-probe \
      --bin odp-probe \
 && mkdir -p /out \
 && cp target/x86_64-unknown-linux-musl/release/odp-probe /out/

FROM scratch
LABEL openshell-driver-podtemplate.build=e2e

COPY --from=builder /out/odp-probe /odp-probe

ENTRYPOINT ["/odp-probe"]

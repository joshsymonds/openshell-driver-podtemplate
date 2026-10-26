# SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
# SPDX-License-Identifier: Apache-2.0
#
# The release openshell-driver-podtemplate binary on distroless Debian 13. The
# binary is dynamically linked against glibc, which the cc base provides. The
# image runs as a numeric non-root user and its entrypoint is the driver.

FROM docker.io/library/rust:1.95.0-trixie@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3 AS builder
LABEL openshell-driver-podtemplate.build=e2e

# cmake is needed by the aws-lc-sys build. openshell-core builds its own protoc
# when PROTOC is unset.
RUN apt-get update \
 && apt-get install -y --no-install-recommends cmake \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
# The cargo registry and target/ are cache mounts, which are not part of the
# stage's layer. The binary is copied to /out in the same RUN so that the final
# stage can read it.
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=odp-cargo-registry \
    --mount=type=cache,target=/src/target,id=odp-driver-target \
    cargo build --release --locked \
      --package openshell-driver-podtemplate \
      --bin openshell-driver-podtemplate \
 && mkdir -p /out \
 && cp target/release/openshell-driver-podtemplate /out/

FROM gcr.io/distroless/cc-debian13:nonroot@sha256:3ee00291cf386ec52a552e6a858d555debd74776eb4bfa53fa3df2cd6677515e
LABEL openshell-driver-podtemplate.build=e2e

COPY --from=builder /out/openshell-driver-podtemplate /usr/local/bin/openshell-driver-podtemplate

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/openshell-driver-podtemplate"]

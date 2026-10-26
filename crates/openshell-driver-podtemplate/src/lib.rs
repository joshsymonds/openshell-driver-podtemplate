// SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
// SPDX-License-Identifier: Apache-2.0

//! Library for the `openshell-driver-podtemplate` compute driver.
//!
//! The driver implements `OpenShell`'s `ComputeDriver` gRPC service for sandboxes that run
//! from Kubernetes `PodTemplate`s. [`service`] answers the RPCs on a private Unix socket,
//! reading its settings from [`config`]. [`capabilities`] reports the driver's handshake,
//! [`auth`] authenticates a sandbox supervisor, [`create`] validates, provisions and starts
//! a sandbox, [`delete`] removes its record and stops its runtime, and [`registry`] reads
//! and watches the records. [`conditions`] maps a sandbox's pods to its conditions and
//! [`runtime_objects`] builds its per-sandbox objects. [`template`] turns a `PodTemplate`
//! into the workload pod and holds the `OpenShell` v0.1.5 workload-pod constants and pod
//! parts. [`error`] defines [`error::DriverError`], the one error type every driver
//! operation returns.

pub mod auth;
pub mod capabilities;
pub mod conditions;
pub mod config;
pub mod create;
pub mod delete;
pub mod error;
pub mod registry;
pub mod runtime_objects;
pub mod service;
pub mod template;

use openshell_core::proto::compute::v1::compute_driver_server::SERVICE_NAME;

/// Returns the driver identity line: the crate version and the `ComputeDriver` gRPC service name.
pub fn banner() -> String {
    format!(
        "openshell-driver-podtemplate {} ({SERVICE_NAME})",
        env!("CARGO_PKG_VERSION")
    )
}

#[cfg(test)]
mod tests {
    use super::banner;

    #[test]
    fn banner_names_crate_version_and_compute_driver_service() {
        assert_eq!(
            banner(),
            format!(
                "openshell-driver-podtemplate {} (openshell.compute.v1.ComputeDriver)",
                env!("CARGO_PKG_VERSION")
            )
        );
    }
}

// SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
// SPDX-License-Identifier: Apache-2.0

//! The capability handshake: what the driver reports to the gateway and the
//! gateway check the driver applies to the gateway's own metadata.

use openshell_core::extension_protocol::{
    ExtensionFamily, extension_metadata, validate_gateway_metadata,
};
use openshell_core::proto::compute::v1::{
    CpuResourceCapabilities, GetCapabilitiesResponse, GpuResourceCapabilities,
    MemoryResourceCapabilities, ResourceCapabilities,
};
use openshell_core::proto::extension::v1::PeerMetadata;
use openshell_core::resource_admission::DriverAdmissionConfig;

use crate::error::DriverError;

/// The driver name the gateway selects this driver by.
pub const DRIVER_NAME: &str = "podtemplate";

/// Returns the capabilities this driver reports to the gateway.
pub fn capabilities(admission: &DriverAdmissionConfig) -> GetCapabilitiesResponse {
    GetCapabilitiesResponse {
        resource_admission_policy: admission.acknowledgement(),
        driver_name: DRIVER_NAME.to_string(),
        driver_version: env!("CARGO_PKG_VERSION").to_string(),
        default_image: String::new(),
        gateway_manages_lifecycle: false,
        supports_sandbox_authentication: true,
        driver_reports_runtime_readiness: false,
        resource_capabilities: Some(ResourceCapabilities {
            cpu: Some(CpuResourceCapabilities {
                limit_supported: false,
            }),
            memory: Some(MemoryResourceCapabilities {
                limit_supported: false,
            }),
            gpu: Some(GpuResourceCapabilities {
                default_selection_supported: false,
                count_selection_supported: false,
            }),
        }),
        rootfs_tar_staging_dir: String::new(),
        rootfs_tar_max_bytes: 0,
        extension: Some(extension_metadata(
            ExtensionFamily::Compute,
            "openshell-driver-podtemplate",
            env!("CARGO_PKG_VERSION"),
            [],
        )),
    }
}

/// Checks the gateway's metadata against this driver's compute extension contract.
pub fn negotiate(
    capabilities: &GetCapabilitiesResponse,
    gateway: Option<PeerMetadata>,
) -> Result<(), DriverError> {
    validate_gateway_metadata(
        ExtensionFamily::Compute,
        DRIVER_NAME,
        capabilities.extension.as_ref(),
        gateway,
    )
    .map_err(|error| DriverError::Precondition(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use openshell_core::extension_protocol::{ExtensionFamily, gateway_metadata};
    use openshell_core::proto::extension::v1::ProtocolVersion;
    use openshell_core::resource_admission::{DriverAdmissionConfig, ResourceAdmissionConfig};

    use super::{DRIVER_NAME, capabilities, negotiate};
    use crate::error::DriverError;

    fn admission() -> DriverAdmissionConfig {
        DriverAdmissionConfig {
            allow_driver_config: true,
            resource_admission: ResourceAdmissionConfig {
                enabled: false,
                required_labels: BTreeMap::new(),
            },
        }
    }

    #[test]
    fn capabilities_driver_name_is_podtemplate() {
        assert_eq!(DRIVER_NAME, "podtemplate");
        assert_eq!(capabilities(&admission()).driver_name, "podtemplate");
    }

    #[test]
    fn capabilities_driver_version_is_crate_version() {
        assert_eq!(
            capabilities(&admission()).driver_version,
            env!("CARGO_PKG_VERSION")
        );
    }

    #[test]
    fn capabilities_default_image_is_empty_because_template_names_the_image() {
        assert_eq!(capabilities(&admission()).default_image, "");
    }

    #[test]
    fn capabilities_gateway_does_not_manage_lifecycle() {
        assert!(!capabilities(&admission()).gateway_manages_lifecycle);
    }

    #[test]
    fn capabilities_supports_sandbox_authentication() {
        assert!(capabilities(&admission()).supports_sandbox_authentication);
    }

    #[test]
    fn capabilities_driver_does_not_report_runtime_readiness() {
        assert!(!capabilities(&admission()).driver_reports_runtime_readiness);
    }

    #[test]
    fn capabilities_declares_no_cpu_memory_or_gpu_selection() {
        let resources = capabilities(&admission())
            .resource_capabilities
            .expect("resource capabilities are reported");
        assert!(!resources.cpu.expect("cpu is reported").limit_supported);
        assert!(
            !resources
                .memory
                .expect("memory is reported")
                .limit_supported
        );
        let gpu = resources.gpu.expect("gpu is reported");
        assert!(!gpu.default_selection_supported);
        assert!(!gpu.count_selection_supported);
    }

    #[test]
    fn capabilities_declares_no_rootfs_tar_staging() {
        let response = capabilities(&admission());
        assert_eq!(response.rootfs_tar_staging_dir, "");
        assert_eq!(response.rootfs_tar_max_bytes, 0);
    }

    #[test]
    fn capabilities_extension_declares_protocol_one_zero_and_compute_contract() {
        let extension = capabilities(&admission())
            .extension
            .expect("extension is reported");
        let version = extension
            .protocol_version
            .expect("protocol version is reported");
        assert_eq!((version.major, version.minor), (1, 0));
        assert_eq!(
            extension.implementation_name,
            "openshell-driver-podtemplate"
        );
        assert_eq!(extension.implementation_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(
            extension.supported_capabilities,
            vec!["openshell.compute.contract".to_string()]
        );
        assert_eq!(
            extension.required_capabilities,
            vec!["openshell.compute.contract".to_string()]
        );
    }

    #[test]
    fn capabilities_resource_admission_policy_is_the_acknowledgement() {
        let config = admission();
        let response = capabilities(&config);
        assert_eq!(response.resource_admission_policy, config.acknowledgement());
        assert!(
            config
                .verify_acknowledgement(&response.resource_admission_policy)
                .is_ok()
        );
    }

    #[test]
    fn capabilities_acknowledgement_fails_for_a_different_config() {
        let response = capabilities(&admission());
        let other = DriverAdmissionConfig {
            allow_driver_config: false,
            ..admission()
        };
        assert!(
            other
                .verify_acknowledgement(&response.resource_admission_policy)
                .is_err()
        );
    }

    #[test]
    fn negotiate_accepts_a_compatible_gateway() {
        let response = capabilities(&admission());
        assert!(negotiate(&response, Some(gateway_metadata(ExtensionFamily::Compute))).is_ok());
    }

    #[test]
    fn negotiate_rejects_a_missing_gateway_with_precondition() {
        let response = capabilities(&admission());
        let error = negotiate(&response, None).expect_err("missing gateway is rejected");
        assert!(matches!(error, DriverError::Precondition(_)));
    }

    #[test]
    fn negotiate_rejects_a_gateway_with_a_different_protocol_major_with_precondition() {
        let response = capabilities(&admission());
        let mut gateway = gateway_metadata(ExtensionFamily::Compute);
        gateway.protocol_version = Some(ProtocolVersion { major: 2, minor: 0 });
        let error = negotiate(&response, Some(gateway)).expect_err("protocol 2.0 is rejected");
        assert!(matches!(error, DriverError::Precondition(_)));
    }
}

// SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
// SPDX-License-Identifier: Apache-2.0

//! The driver's command line and the validated configuration every later module
//! reads its settings from.

use std::net::IpAddr;
use std::path::PathBuf;

use openshell_core::resource_admission::DriverAdmissionConfig;
use openshell_driver_kubernetes::config::is_dns_1123_label;
use openshell_driver_kubernetes::{
    DEFAULT_GATEWAY_ID, DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME, KubernetesImagePullPolicy,
};

use crate::error::DriverError;

/// The admission policy when `--admission-config-json` is not set: caller driver config
/// is allowed and resource admission is off.
const DEFAULT_ADMISSION_CONFIG_JSON: &str =
    r#"{"allow_driver_config":true,"resource_admission":{"enabled":false}}"#;

/// The shortest projected service account token lifetime kubelet enforces, in seconds.
const MIN_SA_TOKEN_TTL_SECS: i64 = 600;

/// The longest projected service account token lifetime the driver allows: 24 hours.
const MAX_SA_TOKEN_TTL_SECS: i64 = 86_400;

/// The token lifetime used when the requested value is zero or negative, in seconds.
const DEFAULT_SA_TOKEN_TTL_SECS: i64 = 3600;

/// The driver's command line. Each flag also reads an environment variable. Build a
/// [`Config`] from it with `TryFrom`, which rejects invalid settings.
#[derive(Debug, clap::Parser)]
#[command(name = "openshell-driver-podtemplate", version)]
pub struct Args {
    /// Unix socket the gateway connects to for the `ComputeDriver` gRPC service.
    #[arg(long, env = "OPENSHELL_COMPUTE_DRIVER_SOCKET")]
    bind_socket: PathBuf,

    /// Kubernetes namespace that sandbox pods are created in. Must be a DNS-1123 label.
    #[arg(long, env = "OPENSHELL_SANDBOX_NAMESPACE", default_value = "default")]
    sandbox_namespace: String,

    /// Identifier of the gateway this driver serves, stamped on driver-owned labels.
    #[arg(long, env = "OPENSHELL_GATEWAY_ID", default_value = DEFAULT_GATEWAY_ID)]
    gateway_id: String,

    /// Gateway gRPC endpoint that sandbox supervisors call back to. Must not be empty.
    #[arg(long, env = "OPENSHELL_GRPC_ENDPOINT")]
    grpc_endpoint: String,

    /// `ServiceAccount` name given to sandbox pods.
    #[arg(
        long,
        env = "OPENSHELL_K8S_SANDBOX_SERVICE_ACCOUNT",
        default_value = DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME
    )]
    sandbox_service_account: String,

    /// Image that carries the sandbox supervisor binary.
    #[arg(
        long,
        env = openshell_core::config::SUPERVISOR_IMAGE_ENV,
        default_value_t = openshell_core::config::default_supervisor_image()
    )]
    supervisor_image: String,

    /// Pull policy for the supervisor image. Omitted leaves the Kubernetes default.
    #[arg(long, env = "OPENSHELL_SUPERVISOR_IMAGE_PULL_POLICY")]
    supervisor_image_pull_policy: Option<KubernetesImagePullPolicy>,

    /// Image that runs the sandbox workload runtime.
    #[arg(
        long,
        env = openshell_core::config::SANDBOX_RUNTIME_IMAGE_ENV,
        default_value_t = openshell_core::config::default_sandbox_runtime_image()
    )]
    sandbox_runtime_image: String,

    /// Pull policy for the sandbox runtime image. Omitted leaves the Kubernetes default.
    #[arg(long, env = "OPENSHELL_SANDBOX_RUNTIME_IMAGE_PULL_POLICY")]
    sandbox_runtime_image_pull_policy: Option<KubernetesImagePullPolicy>,

    /// Image that carries the readiness probe helper binary. Must not be empty.
    #[arg(long, env = "ODP_PROBE_HELPER_IMAGE")]
    probe_helper_image: String,

    /// Pull policy for the probe helper image. Omitted leaves the Kubernetes default.
    #[arg(long, env = "ODP_PROBE_HELPER_IMAGE_PULL_POLICY")]
    probe_helper_image_pull_policy: Option<KubernetesImagePullPolicy>,

    /// Port of the sandbox runtime boundary. Must not be 0.
    #[arg(
        long,
        env = "OPENSHELL_K8S_SANDBOX_RUNTIME_BOUNDARY_PORT",
        default_value_t = 5500
    )]
    sandbox_runtime_boundary_port: u16,

    /// UID that sandbox containers run as. Must not be 0.
    #[arg(long, env = "OPENSHELL_K8S_SANDBOX_UID", default_value_t = 10001)]
    sandbox_uid: u32,

    /// GID that sandbox containers run as. Defaults to the UID. Must not be 0.
    #[arg(long, env = "OPENSHELL_K8S_SANDBOX_GID")]
    sandbox_gid: Option<u32>,

    /// Lifetime in seconds of the projected `ServiceAccount` token. Zero or less means
    /// 3600, and other values are clamped to 600 through 86400.
    #[arg(long, env = "OPENSHELL_K8S_SA_TOKEN_TTL_SECS", default_value_t = 3600)]
    sa_token_ttl_secs: i64,

    /// Kubernetes Secret holding the client TLS material. An empty name means none.
    #[arg(long, env = "OPENSHELL_CLIENT_TLS_SECRET_NAME")]
    client_tls_secret_name: Option<String>,

    /// IP address of the host gateway, when sandboxes reach the host directly.
    #[arg(long, env = "OPENSHELL_HOST_GATEWAY_IP")]
    host_gateway_ip: Option<IpAddr>,

    /// Operator-owned JSON admission policy. Must allow driver config and must not enable
    /// resource admission.
    #[arg(
        long,
        env = "OPENSHELL_DRIVER_ADMISSION_CONFIG_JSON",
        default_value = DEFAULT_ADMISSION_CONFIG_JSON
    )]
    admission_config_json: DriverAdmissionConfig,

    /// Log filter level for the driver process.
    #[arg(long, env = "OPENSHELL_LOG_LEVEL", default_value = "info")]
    log_level: String,
}

/// The validated driver configuration. Built once at startup from [`Args`].
#[derive(Debug, Clone)]
pub struct Config {
    /// Unix socket the gRPC service listens on.
    pub socket_path: PathBuf,
    /// Kubernetes namespace that sandbox pods are created in.
    pub namespace: String,
    /// Identifier of the gateway this driver serves.
    pub gateway_id: String,
    /// Gateway gRPC endpoint that sandbox supervisors call back to.
    pub grpc_endpoint: String,
    /// `ServiceAccount` name given to sandbox pods.
    pub service_account_name: String,
    /// Image that carries the sandbox supervisor binary.
    pub supervisor_image: String,
    /// Pull policy for the supervisor image. `None` leaves the Kubernetes default.
    pub supervisor_image_pull_policy: Option<KubernetesImagePullPolicy>,
    /// Image that runs the sandbox workload runtime.
    pub runtime_image: String,
    /// Pull policy for the runtime image. `None` leaves the Kubernetes default.
    pub runtime_image_pull_policy: Option<KubernetesImagePullPolicy>,
    /// Image that carries the readiness probe helper binary.
    pub probe_helper_image: String,
    /// Pull policy for the probe helper image. `None` leaves the Kubernetes default.
    pub probe_helper_image_pull_policy: Option<KubernetesImagePullPolicy>,
    /// Port of the sandbox runtime boundary. Never 0.
    pub boundary_port: u16,
    /// UID that sandbox containers run as. Never 0.
    pub sandbox_uid: u32,
    /// GID that sandbox containers run as. Never 0.
    pub sandbox_gid: u32,
    /// Lifetime in seconds of the projected service account token, within 600 through
    /// 86400.
    pub sa_token_ttl_secs: i64,
    /// Kubernetes Secret holding the client TLS material, when one is configured.
    pub client_tls_secret_name: Option<String>,
    /// IP address of the host gateway, when sandboxes reach the host directly.
    pub host_gateway_ip: Option<IpAddr>,
    /// Admission policy the driver acknowledges. Resource admission is always off.
    pub admission: DriverAdmissionConfig,
    /// Log filter level for the driver process.
    pub log_level: String,
}

impl TryFrom<Args> for Config {
    type Error = DriverError;

    fn try_from(args: Args) -> Result<Self, Self::Error> {
        if !is_dns_1123_label(&args.sandbox_namespace) {
            return Err(invalid("--sandbox-namespace must be a DNS-1123 label"));
        }
        if args.sandbox_uid == 0 {
            return Err(invalid("--sandbox-uid must not be 0"));
        }
        let sandbox_gid = args.sandbox_gid.unwrap_or(args.sandbox_uid);
        if sandbox_gid == 0 {
            return Err(invalid("--sandbox-gid must not be 0"));
        }
        if args.sandbox_runtime_boundary_port == 0 {
            return Err(invalid("--sandbox-runtime-boundary-port must not be 0"));
        }
        if args.grpc_endpoint.is_empty() {
            return Err(invalid("--grpc-endpoint must not be empty"));
        }
        if args.probe_helper_image.is_empty() {
            return Err(invalid("--probe-helper-image must not be empty"));
        }
        if args.admission_config_json.resource_admission.enabled {
            return Err(invalid(
                "--admission-config-json must not enable resource_admission; this driver implements none",
            ));
        }
        if !args.admission_config_json.allow_driver_config {
            return Err(invalid(
                "--admission-config-json must set allow_driver_config to true; the sandbox template is named in driver config",
            ));
        }
        Ok(Self {
            socket_path: args.bind_socket,
            namespace: args.sandbox_namespace,
            gateway_id: args.gateway_id,
            grpc_endpoint: args.grpc_endpoint,
            service_account_name: args.sandbox_service_account,
            supervisor_image: args.supervisor_image,
            supervisor_image_pull_policy: args.supervisor_image_pull_policy,
            runtime_image: args.sandbox_runtime_image,
            runtime_image_pull_policy: args.sandbox_runtime_image_pull_policy,
            probe_helper_image: args.probe_helper_image,
            probe_helper_image_pull_policy: args.probe_helper_image_pull_policy,
            boundary_port: args.sandbox_runtime_boundary_port,
            sandbox_uid: args.sandbox_uid,
            sandbox_gid,
            sa_token_ttl_secs: effective_sa_token_ttl_secs(args.sa_token_ttl_secs),
            client_tls_secret_name: args.client_tls_secret_name.filter(|name| !name.is_empty()),
            host_gateway_ip: args.host_gateway_ip,
            admission: args.admission_config_json,
            log_level: args.log_level,
        })
    }
}

fn invalid(message: &str) -> DriverError {
    DriverError::InvalidArgument(message.to_string())
}

/// Maps a requested token lifetime to the effective one: zero or less becomes the
/// default, and any other value is clamped to the 600 through 86400 second range.
fn effective_sa_token_ttl_secs(requested: i64) -> i64 {
    if requested <= 0 {
        DEFAULT_SA_TOKEN_TTL_SECS
    } else {
        requested.clamp(MIN_SA_TOKEN_TTL_SECS, MAX_SA_TOKEN_TTL_SECS)
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::path::PathBuf;
    use std::str::FromStr;

    use clap::Parser;
    use openshell_core::resource_admission::DriverAdmissionConfig;
    use openshell_driver_kubernetes::{
        DEFAULT_GATEWAY_ID, DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME, KubernetesImagePullPolicy,
    };

    use super::{Args, Config, DEFAULT_ADMISSION_CONFIG_JSON};
    use crate::error::DriverError;

    /// The flags clap requires. Tests that override one of them build argv themselves.
    const REQUIRED: [&str; 6] = [
        "--bind-socket",
        "/run/odp/driver.sock",
        "--grpc-endpoint",
        "https://gateway.example:8080",
        "--probe-helper-image",
        "registry.example/probe:1",
    ];

    fn parse_argv(flags: &[&str]) -> Args {
        Args::try_parse_from(
            std::iter::once("openshell-driver-podtemplate").chain(flags.iter().copied()),
        )
        .expect("flags parse")
    }

    fn build(extra: &[&str]) -> Result<Config, DriverError> {
        let flags: Vec<&str> = REQUIRED.iter().chain(extra).copied().collect();
        Config::try_from(parse_argv(&flags))
    }

    /// Returns the rejection message, failing the test when the result is not an
    /// `InvalidArgument` error.
    fn rejection(result: Result<Config, DriverError>) -> String {
        match result {
            Err(DriverError::InvalidArgument(message)) => message,
            Err(other) => panic!("expected InvalidArgument, got {other:?}"),
            Ok(config) => panic!("expected a rejection, got {config:?}"),
        }
    }

    #[test]
    fn config_defaults_match_the_v015_driver_surface() {
        let config = build(&[]).expect("defaults validate");
        assert_eq!(config.socket_path, PathBuf::from("/run/odp/driver.sock"));
        assert_eq!(config.namespace, "default");
        assert_eq!(config.gateway_id, DEFAULT_GATEWAY_ID);
        assert_eq!(config.grpc_endpoint, "https://gateway.example:8080");
        assert_eq!(
            config.service_account_name,
            DEFAULT_SANDBOX_SERVICE_ACCOUNT_NAME
        );
        assert_eq!(
            config.supervisor_image,
            openshell_core::config::default_supervisor_image()
        );
        assert_eq!(config.supervisor_image_pull_policy, None);
        assert_eq!(
            config.runtime_image,
            openshell_core::config::default_sandbox_runtime_image()
        );
        assert_eq!(config.runtime_image_pull_policy, None);
        assert_eq!(config.probe_helper_image, "registry.example/probe:1");
        assert_eq!(config.probe_helper_image_pull_policy, None);
        assert_eq!(config.boundary_port, 5500);
        assert_eq!(config.sandbox_uid, 10001);
        assert_eq!(config.sandbox_gid, 10001);
        assert_eq!(config.sa_token_ttl_secs, 3600);
        assert_eq!(config.client_tls_secret_name, None);
        assert_eq!(config.host_gateway_ip, None);
        assert_eq!(config.log_level, "info");
    }

    #[test]
    fn config_default_admission_acknowledgement_matches_the_json_default() {
        let config = build(&[]).expect("defaults validate");
        let expected = DriverAdmissionConfig::from_str(
            r#"{"allow_driver_config":true,"resource_admission":{"enabled":false}}"#,
        )
        .expect("default parses");
        assert_eq!(
            config.admission.acknowledgement(),
            expected.acknowledgement()
        );
    }

    #[test]
    fn config_parses_every_flag() {
        let config = Config::try_from(parse_argv(&[
            "--bind-socket",
            "/run/other/driver.sock",
            "--sandbox-namespace",
            "sandboxes",
            "--gateway-id",
            "gateway-east",
            "--grpc-endpoint",
            "https://gateway.example:9443",
            "--sandbox-service-account",
            "sandbox-runner",
            "--supervisor-image",
            "registry.example/supervisor:1.2.3",
            "--supervisor-image-pull-policy",
            "always",
            "--sandbox-runtime-image",
            "registry.example/runtime:1.2.3",
            "--sandbox-runtime-image-pull-policy",
            "if_not_present",
            "--probe-helper-image",
            "registry.example/probe:1.2.3",
            "--probe-helper-image-pull-policy",
            "never",
            "--sandbox-runtime-boundary-port",
            "6000",
            "--sandbox-uid",
            "2000",
            "--sandbox-gid",
            "3000",
            "--sa-token-ttl-secs",
            "7200",
            "--client-tls-secret-name",
            "gateway-client-tls",
            "--host-gateway-ip",
            "10.0.0.1",
            "--admission-config-json",
            DEFAULT_ADMISSION_CONFIG_JSON,
            "--log-level",
            "debug",
        ]))
        .expect("every flag validates");
        assert_eq!(config.socket_path, PathBuf::from("/run/other/driver.sock"));
        assert_eq!(config.namespace, "sandboxes");
        assert_eq!(config.gateway_id, "gateway-east");
        assert_eq!(config.grpc_endpoint, "https://gateway.example:9443");
        assert_eq!(config.service_account_name, "sandbox-runner");
        assert_eq!(config.supervisor_image, "registry.example/supervisor:1.2.3");
        assert_eq!(
            config.supervisor_image_pull_policy,
            Some(KubernetesImagePullPolicy::Always)
        );
        assert_eq!(config.runtime_image, "registry.example/runtime:1.2.3");
        assert_eq!(
            config.runtime_image_pull_policy,
            Some(KubernetesImagePullPolicy::IfNotPresent)
        );
        assert_eq!(config.probe_helper_image, "registry.example/probe:1.2.3");
        assert_eq!(
            config.probe_helper_image_pull_policy,
            Some(KubernetesImagePullPolicy::Never)
        );
        assert_eq!(config.boundary_port, 6000);
        assert_eq!(config.sandbox_uid, 2000);
        assert_eq!(config.sandbox_gid, 3000);
        assert_eq!(config.sa_token_ttl_secs, 7200);
        assert_eq!(
            config.client_tls_secret_name,
            Some("gateway-client-tls".to_string())
        );
        assert_eq!(
            config.host_gateway_ip,
            Some("10.0.0.1".parse::<IpAddr>().expect("literal IP"))
        );
        assert_eq!(config.log_level, "debug");
    }

    #[test]
    fn config_sandbox_gid_defaults_to_the_uid() {
        let config = build(&["--sandbox-uid", "4242"]).expect("valid");
        assert_eq!(config.sandbox_uid, 4242);
        assert_eq!(config.sandbox_gid, 4242);
    }

    #[test]
    fn config_rejects_sandbox_namespace_that_is_not_a_dns_1123_label() {
        for namespace in ["Bad_Name", "-leading", ""] {
            let flag = format!("--sandbox-namespace={namespace}");
            let message = rejection(build(&[flag.as_str()]));
            assert!(message.contains("--sandbox-namespace"), "{message}");
        }
    }

    #[test]
    fn config_rejects_zero_sandbox_uid() {
        let message = rejection(build(&["--sandbox-uid", "0"]));
        assert!(message.contains("--sandbox-uid"), "{message}");
    }

    #[test]
    fn config_rejects_zero_sandbox_gid() {
        let message = rejection(build(&["--sandbox-uid", "2000", "--sandbox-gid", "0"]));
        assert!(message.contains("--sandbox-gid"), "{message}");
    }

    #[test]
    fn config_rejects_zero_boundary_port() {
        let message = rejection(build(&["--sandbox-runtime-boundary-port", "0"]));
        assert!(
            message.contains("--sandbox-runtime-boundary-port"),
            "{message}"
        );
    }

    #[test]
    fn config_rejects_empty_grpc_endpoint() {
        let message = rejection(Config::try_from(parse_argv(&[
            "--bind-socket",
            "/run/odp/driver.sock",
            "--grpc-endpoint",
            "",
            "--probe-helper-image",
            "registry.example/probe:1",
        ])));
        assert!(message.contains("--grpc-endpoint"), "{message}");
    }

    #[test]
    fn config_rejects_empty_probe_helper_image() {
        let message = rejection(Config::try_from(parse_argv(&[
            "--bind-socket",
            "/run/odp/driver.sock",
            "--grpc-endpoint",
            "https://gateway.example:8080",
            "--probe-helper-image",
            "",
        ])));
        assert!(message.contains("--probe-helper-image"), "{message}");
    }

    #[test]
    fn config_rejects_resource_admission_enabled() {
        let json = r#"{"allow_driver_config":true,"resource_admission":{"enabled":true,"required_labels":{"openshell.ai/sandbox-attachable":"true"}}}"#;
        let message = rejection(build(&["--admission-config-json", json]));
        assert!(message.contains("--admission-config-json"), "{message}");
    }

    #[test]
    fn config_rejects_driver_config_disallowed() {
        let json = r#"{"allow_driver_config":false,"resource_admission":{"enabled":false}}"#;
        let message = rejection(build(&["--admission-config-json", json]));
        assert!(message.contains("--admission-config-json"), "{message}");
    }

    #[test]
    fn config_empty_client_tls_secret_name_becomes_none() {
        let config = build(&["--client-tls-secret-name", ""]).expect("valid");
        assert_eq!(config.client_tls_secret_name, None);
    }

    #[test]
    fn config_clamps_sa_token_ttl_to_the_kubelet_window() {
        let cases: [(i64, i64); 7] = [
            (0, 3600),
            (-5, 3600),
            (1, 600),
            (600, 600),
            (7200, 7200),
            (86_400, 86_400),
            (999_999, 86_400),
        ];
        for (requested, expected) in cases {
            let flag = format!("--sa-token-ttl-secs={requested}");
            let config = build(&[flag.as_str()]).expect("valid");
            assert_eq!(config.sa_token_ttl_secs, expected, "requested {requested}");
        }
    }
}

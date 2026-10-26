// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
// SPDX-License-Identifier: Apache-2.0

//! Per-sandbox Kubernetes objects other than the workload pod.
//!
//! The builders cover the namespace network fences, the boundary Service, the gated
//! supervisor pod, the two bootstrap Secrets, their names, and the proxy CA material.
//! Vendored from `OpenShell` v0.1.5 `crates/openshell-driver-kubernetes/src/`
//! (`sandbox_runtime.rs` and `driver.rs`), as listed in `NOTICE`. The proxy, SPIFFE,
//! tracing and image-pull paths are omitted: the driver has no setting for a proxy, SPIFFE,
//! OTLP tracing or image-pull Secret. The Service, Pod and Secret builders take the owner
//! reference they stamp.

use std::collections::BTreeMap;

use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::{
    Capabilities, Container, EmptyDirVolumeSource, EnvVar, KeyToPath, Pod, PodSchedulingGate,
    PodSecurityContext, PodSpec, Probe, ProjectedVolumeSource, SeccompProfile, Secret,
    SecretVolumeSource, SecurityContext, Service, ServiceAccountTokenProjection, ServicePort,
    ServiceSpec, TCPSocketAction, Volume, VolumeMount, VolumeProjection,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::core::ObjectMeta;
use openshell_core::driver_utils::{
    LABEL_GATEWAY_ID, LABEL_MANAGED_BY, LABEL_MANAGED_BY_VALUE, LABEL_SANDBOX_ID,
};
use openshell_core::{sandbox_env, telemetry};
use openshell_crypto::pki::{generate_keypair, self_signed};
use openshell_driver_kubernetes::KubernetesImagePullPolicy;
use openshell_driver_kubernetes::isolation::{
    BACKEND_NAME, KubernetesSandboxRuntimeNetworkFence, KubernetesSandboxRuntimeNetworkFenceSpec,
};
use rcgen::{CertificateParams, DnType, IsCa, KeyUsagePurpose};

use crate::error::DriverError;
use crate::template::upstream::{
    BOUNDARY_PAIR_LABEL, BOUNDARY_ROLE_LABEL, SANDBOX_BOOTSTRAP_SCHEDULING_GATE, WORKLOAD_ROLE,
    pair_label_value,
};

// Constants vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/sandbox_runtime.rs:27-63`.
const SANDBOX_SECRET_COMPONENT: &str = "sandbox-bootstrap";
const SUPERVISOR_SECRET_COMPONENT: &str = "supervisor-bootstrap";
const COMPONENT_LABEL: &str = "openshell.ai/component";
const SUPERVISOR_ROLE: &str = "supervisor";
const BOUNDARY_CONFIG_KEY: &str = "boundary.json";
const BOUNDARY_CERTIFICATE_KEY: &str = "tls.crt";
const BOUNDARY_PRIVATE_KEY: &str = "tls.key";
const BACKEND_DESCRIPTOR_KEY: &str = "runtime-descriptor.json";
const SUPERVISOR_AUTH_BUNDLE_KEY: &str = "auth.json";
const PROXY_CA_CERTIFICATE_KEY: &str = "proxy-ca.crt";
const PROXY_CA_PRIVATE_KEY: &str = "proxy-ca.key";
const BACKEND_DESCRIPTOR_PATH: &str = "/.openshell/supervisor/runtime-descriptor.json";
const SUPERVISOR_AUTH_BUNDLE_PATH: &str = "/.openshell/supervisor/auth.json";
const PROXY_CA_CERTIFICATE_PATH: &str = "/.openshell/supervisor/proxy-ca.crt";
const PROXY_CA_PRIVATE_KEY_PATH: &str = "/.openshell/supervisor/proxy-ca.key";
const CONTROL_HEALTH_SOCKET_PATH: &str = "/run/openshell/health.sock";
const CONTROL_HEALTH_PORT: u16 = 5501;
const NAMESPACE_WORKLOAD_POLICY_NAME: &str = "openshell-sandbox-workloads";
const NAMESPACE_SUPERVISOR_EGRESS_POLICY_NAME: &str = "openshell-sandbox-supervisors";
const SUPERVISOR_TERMINATION_GRACE_PERIOD_SECONDS: i64 = 30;

/// Where the supervisor reads the gateway CA.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/sandbox_runtime.rs:71-79`,
/// without the `Bootstrap` variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SupervisorClientTls<'a> {
    /// The supervisor reads no gateway CA.
    Disabled,
    /// A Secret in the sandbox namespace, mounted by name with its `ca.crt` key.
    Secret(&'a str),
}

/// The generated proxy CA: a self-signed CA certificate and its PKCS#8 private key, both PEM.
///
/// No `Debug` derive, so the private key cannot reach a log. Vendored from
/// `v0.1.5:crates/openshell-driver-kubernetes/src/sandbox_runtime.rs:81-84`.
pub struct ProxyCaMaterial {
    /// The CA certificate, PEM.
    pub certificate_pem: String,
    /// The CA private key, PKCS#8 PEM.
    pub private_key_pem: String,
}

/// Bytes staged into the supervisor bootstrap Secret.
///
/// No `Debug` derive, because the bytes carry credentials.
pub struct SupervisorSecretData {
    /// The serialized runtime descriptor the supervisor reads at start.
    pub backend_descriptor: Vec<u8>,
    /// The supervisor authentication bundle.
    pub auth_bundle: Vec<u8>,
    /// The generated proxy CA certificate, PEM.
    pub proxy_ca_certificate: Vec<u8>,
    /// The generated proxy CA private key, PEM.
    pub proxy_ca_private_key: Vec<u8>,
}

/// Inputs of the supervisor pod.
///
/// No `Debug` derive, because the pod inputs can carry credential material.
pub struct SupervisorPodParams<'a> {
    /// Namespace the pod is created in.
    pub namespace: &'a str,
    /// Per-sandbox object names.
    pub names: &'a SandboxRuntimeNames,
    /// Sandbox ID, which labels the pod and selects its boundary pair.
    pub sandbox_id: &'a str,
    /// Sandbox name, passed to the supervisor as `OPENSHELL_SANDBOX`.
    pub sandbox_name: &'a str,
    /// Gateway ID label value.
    pub gateway_id: &'a str,
    /// Supervisor image.
    pub image: &'a str,
    /// Image pull policy of the supervisor container, when set.
    pub image_pull_policy: Option<KubernetesImagePullPolicy>,
    /// Service account the pod runs as.
    pub service_account_name: &'a str,
    /// Numeric user the supervisor runs as.
    pub uid: u32,
    /// Numeric group the supervisor runs as; also the pod's `fsGroup`.
    pub gid: u32,
    /// Gateway gRPC endpoint the supervisor dials.
    pub grpc_endpoint: &'a str,
    /// Where the supervisor reads the gateway CA.
    pub client_tls: SupervisorClientTls<'a>,
    /// Serialized main-process specification.
    pub main_process_spec: &'a str,
    /// Supervisor log level.
    pub log_level: &'a str,
    /// Lifetime, in seconds, of the projected gateway service account token.
    pub sa_token_ttl_secs: i64,
    /// Owner reference the pod stamps.
    pub owner: OwnerReference,
}

/// Per-sandbox object names, derived from the sandbox ID.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/sandbox_runtime.rs:108-159`,
/// without the image-pull Secret names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxRuntimeNames {
    /// Name of the sandbox bootstrap Secret.
    pub sandbox_secret: String,
    /// Name of the supervisor bootstrap Secret.
    pub supervisor_secret: String,
    /// Name of the boundary Service.
    pub boundary_service: String,
    /// Name of the supervisor pod.
    pub supervisor_pod: String,
    /// Name of the namespace policy that fences the workload pod.
    pub workload_policy: String,
    /// Name of the namespace policy that governs the supervisor pod.
    pub supervisor_policy: String,
}

impl SandboxRuntimeNames {
    /// Returns the names for a sandbox ID.
    #[must_use]
    pub fn new(sandbox_id: &str) -> Self {
        let suffix = sandbox_id.to_ascii_lowercase();
        Self {
            sandbox_secret: format!("os-sandbox-{suffix}"),
            supervisor_secret: format!("os-supervisor-{suffix}"),
            boundary_service: format!("os-boundary-{suffix}"),
            supervisor_pod: format!("os-supervisor-{suffix}"),
            workload_policy: NAMESPACE_WORKLOAD_POLICY_NAME.to_string(),
            supervisor_policy: NAMESPACE_SUPERVISOR_EGRESS_POLICY_NAME.to_string(),
        }
    }

    /// Returns the names for a sandbox ID, with the two bootstrap Secret names carrying
    /// the runtime generation so each generation's Secrets are immutable and distinct.
    #[must_use]
    pub fn for_generation(sandbox_id: &str, generation: &str) -> Self {
        let mut names = Self::new(sandbox_id);
        let generation = generation
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .take(12)
            .collect::<String>()
            .to_ascii_lowercase();
        names.sandbox_secret = format!("{}-{generation}", names.sandbox_secret);
        names.supervisor_secret = format!("{}-{generation}", names.supervisor_secret);
        names
    }
}

/// Generates the sandbox proxy CA: a self-signed P-256 CA certificate and its PKCS#8 key.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/sandbox_runtime.rs:86-106`.
pub fn generate_proxy_ca_material() -> Result<ProxyCaMaterial, DriverError> {
    let key = generate_keypair()
        .map_err(|error| DriverError::Message(format!("generate proxy CA key: {error}")))?;
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, "OpenShell Sandbox CA");
    params
        .distinguished_name
        .push(DnType::OrganizationName, "OpenShell");
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let certificate = self_signed(params, &key)
        .map_err(|error| DriverError::Message(format!("generate proxy CA certificate: {error}")))?;
    Ok(ProxyCaMaterial {
        certificate_pem: certificate.pem(),
        private_key_pem: key
            .serialize_pem()
            .map_err(|error| DriverError::Message(format!("export proxy CA key: {error}")))?,
    })
}

/// Renders the workload pod's namespace fence: ingress from the supervisor on the boundary
/// port only, and an empty egress list.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/sandbox_runtime.rs:166-179`.
#[must_use]
pub fn workload_fence(
    namespace: &str,
    names: &SandboxRuntimeNames,
    boundary_port: u16,
) -> KubernetesSandboxRuntimeNetworkFence {
    KubernetesSandboxRuntimeNetworkFenceSpec {
        namespace: namespace.to_string(),
        policy_name: names.workload_policy.clone(),
        supervisor_policy_name: names.supervisor_policy.clone(),
        boundary_port,
    }
    .provision()
}

/// Returns the TLS authority of the boundary Service: `<service>.<namespace>.svc:<port>`.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:136-145`.
#[must_use]
pub fn boundary_service_authority(
    namespace: &str,
    names: &SandboxRuntimeNames,
    boundary_port: u16,
) -> String {
    format!(
        "{}.{}.svc:{boundary_port}",
        names.boundary_service, namespace
    )
}

/// Renders the boundary Service, which selects only the workload pod.
///
/// It publishes the workload pod's address before the pod is Ready: when the template sets a
/// readiness probe, the probe passes only once the main process serves, and the supervisor
/// starts that process through this Service.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/sandbox_runtime.rs:181-210`,
/// which leaves `publish_not_ready_addresses` unset, so its Service publishes only Ready
/// addresses.
#[must_use]
pub fn boundary_service(
    namespace: &str,
    names: &SandboxRuntimeNames,
    sandbox_id: &str,
    boundary_port: u16,
    owner: OwnerReference,
) -> Service {
    Service {
        metadata: ObjectMeta {
            name: Some(names.boundary_service.clone()),
            namespace: Some(namespace.to_string()),
            owner_references: Some(vec![owner]),
            labels: Some(common_labels(sandbox_id, "boundary-service")),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            selector: Some(pair_labels(sandbox_id, WORKLOAD_ROLE)),
            publish_not_ready_addresses: Some(true),
            ports: Some(vec![ServicePort {
                name: Some("boundary".to_string()),
                protocol: Some("TCP".to_string()),
                port: i32::from(boundary_port),
                target_port: Some(IntOrString::Int(i32::from(boundary_port))),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Renders the supervisor pod: scheduling-gated, never restarted, unprivileged, with a
/// read-only root filesystem, no service-account token automount, and no image-pull Secrets.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/sandbox_runtime.rs:212-494`,
/// without the upstream proxy, SPIFFE, tracing and image-pull paths, which the driver has no
/// setting for.
#[must_use]
pub fn supervisor_pod(params: &SupervisorPodParams<'_>) -> Pod {
    let names = params.names;
    let mut environment = vec![
        env_var("OPENSHELL_ADMITTED_ISOLATION_BACKEND", BACKEND_NAME),
        env_var("OPENSHELL_ENDPOINT", params.grpc_endpoint),
        env_var("OPENSHELL_SANDBOX_ID", params.sandbox_id),
        env_var("OPENSHELL_SANDBOX", params.sandbox_name),
        env_var("OPENSHELL_MAIN_PROCESS_SPEC", params.main_process_spec),
        env_var(
            "OPENSHELL_K8S_SA_TOKEN_FILE",
            "/var/run/secrets/openshell/token",
        ),
        env_var("OPENSHELL_SSH_SOCKET_PATH", "/run/openshell/ssh.sock"),
        env_var(sandbox_env::SSH_SOCKET_SHARED, "true"),
        env_var("OPENSHELL_PROXY_TLS_DIR", "/run/openshell/proxy-tls"),
        env_var(sandbox_env::PROXY_CA_CERT, PROXY_CA_CERTIFICATE_PATH),
        env_var(sandbox_env::PROXY_CA_KEY, PROXY_CA_PRIVATE_KEY_PATH),
        env_var("OPENSHELL_LOG_LEVEL", params.log_level),
        env_var(
            sandbox_env::TELEMETRY_ENABLED,
            telemetry::enabled_env_value(),
        ),
        env_var(sandbox_env::NETWORK_RUNTIME_CAPABILITIES, ""),
    ];
    if let Some(server_name) = gateway_tls_server_name(params.grpc_endpoint) {
        environment.push(env_var(sandbox_env::GATEWAY_TLS_SERVER_NAME, &server_name));
    }
    let mut volume_mounts = vec![
        volume_mount("bootstrap", "/.openshell/supervisor", true),
        volume_mount("sa-token", "/var/run/secrets/openshell", true),
        volume_mount("run", "/run/openshell", false),
        volume_mount("logs", "/var/log", false),
    ];
    let mut volumes = vec![
        secret_volume("bootstrap", &names.supervisor_secret, None),
        Volume {
            name: "sa-token".to_string(),
            projected: Some(ProjectedVolumeSource {
                default_mode: Some(0o440),
                sources: Some(vec![VolumeProjection {
                    service_account_token: Some(ServiceAccountTokenProjection {
                        audience: Some("openshell-gateway".to_string()),
                        expiration_seconds: Some(params.sa_token_ttl_secs),
                        path: "token".to_string(),
                    }),
                    ..Default::default()
                }]),
            }),
            ..Default::default()
        },
        empty_dir_volume("run"),
        empty_dir_volume("logs"),
    ];
    if let SupervisorClientTls::Secret(secret_name) = params.client_tls {
        environment.push(env_var(
            "OPENSHELL_TLS_CA",
            "/var/run/secrets/openshell-tls/ca.crt",
        ));
        volume_mounts.push(volume_mount(
            "client-tls",
            "/var/run/secrets/openshell-tls",
            true,
        ));
        volumes.push(secret_volume(
            "client-tls",
            secret_name,
            Some(KeyToPath {
                key: "ca.crt".to_string(),
                path: "ca.crt".to_string(),
                ..Default::default()
            }),
        ));
    }
    let command = vec![
        "/openshell-supervisor".to_string(),
        "--backend-descriptor-file".to_string(),
        BACKEND_DESCRIPTOR_PATH.to_string(),
        "--auth-bundle-file".to_string(),
        SUPERVISOR_AUTH_BUNDLE_PATH.to_string(),
        "--workdir".to_string(),
        "/sandbox".to_string(),
        "--health-socket-path".to_string(),
        CONTROL_HEALTH_SOCKET_PATH.to_string(),
        "--health-port".to_string(),
        CONTROL_HEALTH_PORT.to_string(),
    ];
    let container = Container {
        name: "supervisor".to_string(),
        image: Some(params.image.to_string()),
        command: Some(command),
        image_pull_policy: params
            .image_pull_policy
            .map(|policy| policy.as_kubernetes_str().to_string()),
        termination_message_policy: Some("FallbackToLogsOnError".to_string()),
        env: Some(environment),
        readiness_probe: Some(Probe {
            tcp_socket: Some(TCPSocketAction {
                port: IntOrString::Int(i32::from(CONTROL_HEALTH_PORT)),
                ..Default::default()
            }),
            period_seconds: Some(1),
            failure_threshold: Some(3),
            ..Default::default()
        }),
        security_context: Some(SecurityContext {
            run_as_user: Some(i64::from(params.uid)),
            run_as_group: Some(i64::from(params.gid)),
            run_as_non_root: Some(true),
            read_only_root_filesystem: Some(true),
            allow_privilege_escalation: Some(false),
            capabilities: Some(Capabilities {
                drop: Some(vec!["ALL".to_string()]),
                ..Default::default()
            }),
            ..Default::default()
        }),
        volume_mounts: Some(volume_mounts),
        ..Default::default()
    };
    Pod {
        metadata: ObjectMeta {
            name: Some(names.supervisor_pod.clone()),
            namespace: Some(params.namespace.to_string()),
            owner_references: Some(vec![params.owner.clone()]),
            labels: Some(control_labels(params.sandbox_id, params.gateway_id)),
            annotations: Some(BTreeMap::from([(
                "openshell.ai/sandbox-id".to_string(),
                params.sandbox_id.to_string(),
            )])),
            ..Default::default()
        },
        spec: Some(PodSpec {
            termination_grace_period_seconds: Some(SUPERVISOR_TERMINATION_GRACE_PERIOD_SECONDS),
            service_account_name: Some(params.service_account_name.to_string()),
            automount_service_account_token: Some(false),
            scheduling_gates: Some(vec![PodSchedulingGate {
                name: SANDBOX_BOOTSTRAP_SCHEDULING_GATE.to_string(),
            }]),
            security_context: Some(PodSecurityContext {
                fs_group: Some(i64::from(params.gid)),
                fs_group_change_policy: Some("OnRootMismatch".to_string()),
                seccomp_profile: Some(SeccompProfile {
                    type_: "RuntimeDefault".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            restart_policy: Some("Never".to_string()),
            containers: vec![container],
            volumes: Some(volumes),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Renders the sandbox bootstrap Secret: the boundary config and its TLS identity. Immutable.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/sandbox_runtime.rs:496-530`.
#[must_use]
pub fn sandbox_bootstrap_secret(
    namespace: &str,
    names: &SandboxRuntimeNames,
    sandbox_id: &str,
    boundary_config: Vec<u8>,
    boundary_certificate: Vec<u8>,
    boundary_private_key: Vec<u8>,
    owner: OwnerReference,
) -> Secret {
    bootstrap_secret(
        &names.sandbox_secret,
        namespace,
        sandbox_id,
        SANDBOX_SECRET_COMPONENT,
        owner,
        BTreeMap::from([
            (BOUNDARY_CONFIG_KEY.to_string(), ByteString(boundary_config)),
            (
                BOUNDARY_CERTIFICATE_KEY.to_string(),
                ByteString(boundary_certificate),
            ),
            (
                BOUNDARY_PRIVATE_KEY.to_string(),
                ByteString(boundary_private_key),
            ),
        ]),
    )
}

/// Renders the supervisor bootstrap Secret: the runtime descriptor, auth bundle and proxy CA.
/// Immutable.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/sandbox_runtime.rs:532-588`.
#[must_use]
pub fn supervisor_bootstrap_secret(
    namespace: &str,
    names: &SandboxRuntimeNames,
    sandbox_id: &str,
    data: SupervisorSecretData,
    owner: OwnerReference,
) -> Secret {
    bootstrap_secret(
        &names.supervisor_secret,
        namespace,
        sandbox_id,
        SUPERVISOR_SECRET_COMPONENT,
        owner,
        BTreeMap::from([
            (
                BACKEND_DESCRIPTOR_KEY.to_string(),
                ByteString(data.backend_descriptor),
            ),
            (
                SUPERVISOR_AUTH_BUNDLE_KEY.to_string(),
                ByteString(data.auth_bundle),
            ),
            (
                PROXY_CA_CERTIFICATE_KEY.to_string(),
                ByteString(data.proxy_ca_certificate),
            ),
            (
                PROXY_CA_PRIVATE_KEY.to_string(),
                ByteString(data.proxy_ca_private_key),
            ),
        ]),
    )
}

fn bootstrap_secret(
    name: &str,
    namespace: &str,
    sandbox_id: &str,
    component: &str,
    owner: OwnerReference,
    data: BTreeMap<String, ByteString>,
) -> Secret {
    Secret {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            owner_references: Some(vec![owner]),
            labels: Some(common_labels(sandbox_id, component)),
            ..Default::default()
        },
        data: Some(data),
        immutable: Some(true),
        type_: Some("Opaque".to_string()),
        ..Default::default()
    }
}

fn pair_labels(sandbox_id: &str, role: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            BOUNDARY_PAIR_LABEL.to_string(),
            pair_label_value(sandbox_id),
        ),
        (BOUNDARY_ROLE_LABEL.to_string(), role.to_string()),
    ])
}

fn common_labels(sandbox_id: &str, component: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            LABEL_MANAGED_BY.to_string(),
            LABEL_MANAGED_BY_VALUE.to_string(),
        ),
        (LABEL_SANDBOX_ID.to_string(), sandbox_id.to_string()),
        (COMPONENT_LABEL.to_string(), component.to_string()),
    ])
}

fn control_labels(sandbox_id: &str, gateway_id: &str) -> BTreeMap<String, String> {
    let mut labels = common_labels(sandbox_id, SUPERVISOR_ROLE);
    labels.extend(pair_labels(sandbox_id, SUPERVISOR_ROLE));
    labels.insert(LABEL_GATEWAY_ID.to_string(), gateway_id.to_string());
    labels
}

/// Returns the host the supervisor verifies a gateway dial against, for an `https` endpoint.
///
/// The gateway may redirect the supervisor to a replica by pod address, which the server
/// certificate does not name. Verifying against the configured host keeps those redirects valid.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/sandbox_runtime.rs:673-680`.
fn gateway_tls_server_name(grpc_endpoint: &str) -> Option<String> {
    let uri = grpc_endpoint.parse::<tonic::transport::Uri>().ok()?;
    if uri.scheme_str() != Some("https") {
        return None;
    }
    let host = uri.host()?.trim_start_matches('[').trim_end_matches(']');
    (!host.is_empty()).then(|| host.to_string())
}

fn env_var(name: &str, value: &str) -> EnvVar {
    EnvVar {
        name: name.to_string(),
        value: Some(value.to_string()),
        ..Default::default()
    }
}

fn volume_mount(name: &str, mount_path: &str, read_only: bool) -> VolumeMount {
    VolumeMount {
        name: name.to_string(),
        mount_path: mount_path.to_string(),
        read_only: read_only.then_some(true),
        ..Default::default()
    }
}

fn secret_volume(name: &str, secret_name: &str, item: Option<KeyToPath>) -> Volume {
    Volume {
        name: name.to_string(),
        secret: Some(SecretVolumeSource {
            secret_name: Some(secret_name.to_string()),
            default_mode: Some(0o440),
            items: item.map(|item| vec![item]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn empty_dir_volume(name: &str) -> Volume {
    Volume {
        name: name.to_string(),
        empty_dir: Some(EmptyDirVolumeSource::default()),
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(name: &str) -> OwnerReference {
        OwnerReference {
            api_version: "coordination.k8s.io/v1".to_string(),
            kind: "Lease".to_string(),
            name: name.to_string(),
            uid: format!("{name}-uid"),
            controller: Some(true),
            block_owner_deletion: Some(true),
        }
    }

    fn params<'a>(
        names: &'a SandboxRuntimeNames,
        client_tls: SupervisorClientTls<'a>,
        endpoint: &'a str,
    ) -> SupervisorPodParams<'a> {
        SupervisorPodParams {
            namespace: "sandbox",
            names,
            sandbox_id: "pair",
            sandbox_name: "demo",
            gateway_id: "gateway",
            image: "supervisor:latest",
            image_pull_policy: Some(KubernetesImagePullPolicy::IfNotPresent),
            service_account_name: "sandbox-sa",
            uid: 1000,
            gid: 1000,
            grpc_endpoint: endpoint,
            client_tls,
            main_process_spec: "{}",
            log_level: "info",
            sa_token_ttl_secs: 600,
            owner: owner("lease"),
        }
    }

    fn supervisor(client_tls: SupervisorClientTls<'_>, endpoint: &str) -> Pod {
        let names = SandboxRuntimeNames::new("pair");
        supervisor_pod(&params(&names, client_tls, endpoint))
    }

    fn pod_spec(pod: &Pod) -> &PodSpec {
        pod.spec.as_ref().expect("Pod spec")
    }

    fn supervisor_container(pod: &Pod) -> &Container {
        &pod_spec(pod).containers[0]
    }

    fn env_value<'a>(container: &'a Container, name: &str) -> Option<&'a str> {
        container
            .env
            .as_ref()?
            .iter()
            .find(|variable| variable.name == name)?
            .value
            .as_deref()
    }

    fn find_volume<'a>(spec: &'a PodSpec, name: &str) -> Option<&'a Volume> {
        spec.volumes
            .as_ref()?
            .iter()
            .find(|volume| volume.name == name)
    }

    fn find_mount<'a>(container: &'a Container, name: &str) -> Option<&'a VolumeMount> {
        container
            .volume_mounts
            .as_ref()?
            .iter()
            .find(|mount| mount.name == name)
    }

    fn secret_keys(secret: &Secret) -> Vec<&str> {
        secret
            .data
            .as_ref()
            .expect("Secret data")
            .keys()
            .map(String::as_str)
            .collect()
    }

    fn secret_value<'a>(secret: &'a Secret, key: &str) -> &'a [u8] {
        &secret.data.as_ref().expect("Secret data")[key].0
    }

    #[test]
    fn runtime_objects_service_selects_only_the_workload_boundary() {
        let names = SandboxRuntimeNames::new("4B67C0D0-1111");
        let service = boundary_service("sandbox", &names, "Pair", 5500, owner("lease"));
        let selector = service
            .spec
            .expect("Service spec")
            .selector
            .expect("Service selector");
        assert_eq!(
            selector,
            BTreeMap::from([
                (BOUNDARY_PAIR_LABEL.to_string(), "pair".to_string()),
                (BOUNDARY_ROLE_LABEL.to_string(), WORKLOAD_ROLE.to_string()),
            ])
        );
    }

    #[test]
    fn runtime_objects_boundary_service_publishes_the_not_ready_workload() {
        let names = SandboxRuntimeNames::new("pair");
        let service = boundary_service("sandbox", &names, "pair", 5500, owner("lease"));
        assert_eq!(
            service
                .spec
                .expect("Service spec")
                .publish_not_ready_addresses,
            Some(true)
        );
    }

    #[test]
    fn runtime_objects_boundary_service_stamps_owner_and_port() {
        let names = SandboxRuntimeNames::new("pair");
        let service = boundary_service("sandbox", &names, "pair", 5500, owner("lease"));
        assert_eq!(service.metadata.name.as_deref(), Some("os-boundary-pair"));
        assert_eq!(service.metadata.namespace.as_deref(), Some("sandbox"));
        assert_eq!(
            service.metadata.owner_references,
            Some(vec![owner("lease")])
        );
        let ports = service
            .spec
            .expect("Service spec")
            .ports
            .expect("Service ports");
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 5500);
        assert_eq!(ports[0].target_port, Some(IntOrString::Int(5500)));
        assert_eq!(ports[0].protocol.as_deref(), Some("TCP"));
    }

    #[test]
    fn runtime_objects_boundary_authority_names_service_namespace_and_port() {
        let names = SandboxRuntimeNames::new("pair");
        assert_eq!(
            boundary_service_authority("sandbox", &names, 5500),
            "os-boundary-pair.sandbox.svc:5500"
        );
    }

    #[test]
    fn runtime_objects_generation_names_are_per_generation_for_secrets_only() {
        let first = SandboxRuntimeNames::for_generation("pair", "ABCdef123456789");
        let second = SandboxRuntimeNames::for_generation("pair", "zyx987654321000");
        let stable = SandboxRuntimeNames::new("pair");
        assert_eq!(first.sandbox_secret, "os-sandbox-pair-abcdef123456");
        assert_eq!(first.supervisor_secret, "os-supervisor-pair-abcdef123456");
        assert_ne!(first.sandbox_secret, second.sandbox_secret);
        assert_ne!(first.supervisor_secret, second.supervisor_secret);
        assert_eq!(first.supervisor_pod, stable.supervisor_pod);
        assert_eq!(first.boundary_service, stable.boundary_service);
        assert_eq!(first.workload_policy, stable.workload_policy);
        assert_eq!(first.supervisor_policy, stable.supervisor_policy);
    }

    #[test]
    fn runtime_objects_fence_is_upstream_isolation_output() {
        let names = SandboxRuntimeNames::new("pair");
        let fence = workload_fence("sandbox", &names, 5500);
        let upstream = KubernetesSandboxRuntimeNetworkFenceSpec {
            namespace: "sandbox".to_string(),
            policy_name: names.workload_policy.clone(),
            supervisor_policy_name: names.supervisor_policy,
            boundary_port: 5500,
        }
        .provision();
        assert_eq!(fence.workload_labels, upstream.workload_labels);
        assert_eq!(fence.control_labels, upstream.control_labels);
        assert_eq!(fence.workload_policy, upstream.workload_policy);
        assert_eq!(fence.supervisor_policy, upstream.supervisor_policy);

        let workload = fence.workload_policy.spec.expect("workload policy spec");
        assert_eq!(
            fence.workload_policy.metadata.name.as_deref(),
            Some("openshell-sandbox-workloads")
        );
        assert_eq!(workload.egress, Some(Vec::new()));
        let ingress = workload.ingress.expect("workload ingress rules");
        let port = ingress[0].ports.as_ref().expect("ingress ports")[0]
            .port
            .clone();
        assert_eq!(port, Some(IntOrString::Int(5500)));
    }

    #[test]
    fn runtime_objects_supervisor_pod_is_gated_non_restarting_and_unprivileged() {
        let pod = supervisor(SupervisorClientTls::Disabled, "https://gateway:8080");
        let spec = pod_spec(&pod);
        assert_eq!(
            spec.scheduling_gates,
            Some(vec![PodSchedulingGate {
                name: SANDBOX_BOOTSTRAP_SCHEDULING_GATE.to_string(),
            }])
        );
        assert_eq!(spec.restart_policy.as_deref(), Some("Never"));
        assert_eq!(spec.automount_service_account_token, Some(false));
        assert_eq!(
            spec.termination_grace_period_seconds,
            Some(SUPERVISOR_TERMINATION_GRACE_PERIOD_SECONDS)
        );
        let pod_security = spec
            .security_context
            .as_ref()
            .expect("Pod security context");
        assert_eq!(pod_security.fs_group, Some(1000));
        assert_eq!(
            pod_security
                .seccomp_profile
                .as_ref()
                .map(|profile| profile.type_.as_str()),
            Some("RuntimeDefault")
        );

        let container = supervisor_container(&pod);
        assert_eq!(container.image_pull_policy.as_deref(), Some("IfNotPresent"));
        let security = container
            .security_context
            .as_ref()
            .expect("container security context");
        assert_eq!(security.run_as_user, Some(1000));
        assert_eq!(security.run_as_group, Some(1000));
        assert_eq!(security.run_as_non_root, Some(true));
        assert_eq!(security.read_only_root_filesystem, Some(true));
        assert_eq!(security.allow_privilege_escalation, Some(false));
        assert_eq!(
            security
                .capabilities
                .as_ref()
                .and_then(|capabilities| capabilities.drop.as_ref()),
            Some(&vec!["ALL".to_string()])
        );

        let probe = container.readiness_probe.as_ref().expect("readiness probe");
        assert!(
            probe.exec.is_none(),
            "exec probes spawn a process per period"
        );
        assert_eq!(
            probe.tcp_socket.as_ref().map(|tcp| &tcp.port),
            Some(&IntOrString::Int(i32::from(CONTROL_HEALTH_PORT)))
        );
        let command = container.command.as_ref().expect("supervisor command");
        assert!(
            command
                .windows(2)
                .any(|args| args == ["--health-socket-path", CONTROL_HEALTH_SOCKET_PATH])
        );
        let health_port = CONTROL_HEALTH_PORT.to_string();
        assert!(
            command
                .windows(2)
                .any(|args| args == ["--health-port", health_port.as_str()])
        );
    }

    #[test]
    fn runtime_objects_supervisor_pod_projects_gateway_token_for_the_given_lifetime() {
        let pod = supervisor(SupervisorClientTls::Disabled, "https://gateway:8080");
        let spec = pod_spec(&pod);
        let projection = find_volume(spec, "sa-token")
            .and_then(|volume| volume.projected.as_ref())
            .and_then(|projected| projected.sources.as_ref())
            .and_then(|sources| sources.first())
            .and_then(|source| source.service_account_token.as_ref())
            .expect("projected service account token");
        assert_eq!(projection.audience.as_deref(), Some("openshell-gateway"));
        assert_eq!(projection.expiration_seconds, Some(600));
        assert_eq!(projection.path, "token");
        let mount = find_mount(supervisor_container(&pod), "sa-token").expect("token mount");
        assert_eq!(mount.mount_path, "/var/run/secrets/openshell");
        assert_eq!(mount.read_only, Some(true));
    }

    #[test]
    fn runtime_objects_supervisor_pod_mounts_the_supervisor_bootstrap_secret() {
        let names = SandboxRuntimeNames::for_generation("pair", "gen7");
        let pod = supervisor_pod(&params(
            &names,
            SupervisorClientTls::Disabled,
            "https://gateway:8080",
        ));
        let secret = find_volume(pod_spec(&pod), "bootstrap")
            .and_then(|volume| volume.secret.as_ref())
            .expect("bootstrap secret volume");
        assert_eq!(
            secret.secret_name.as_deref(),
            Some("os-supervisor-pair-gen7")
        );
        let mount = find_mount(supervisor_container(&pod), "bootstrap").expect("bootstrap mount");
        assert_eq!(mount.mount_path, "/.openshell/supervisor");
        assert_eq!(mount.read_only, Some(true));
        let container = supervisor_container(&pod);
        assert_eq!(
            env_value(container, sandbox_env::PROXY_CA_CERT),
            Some("/.openshell/supervisor/proxy-ca.crt")
        );
        assert_eq!(
            env_value(container, sandbox_env::PROXY_CA_KEY),
            Some("/.openshell/supervisor/proxy-ca.key")
        );
    }

    #[test]
    fn runtime_objects_supervisor_pod_mounts_a_client_tls_secret_by_name() {
        let pod = supervisor(
            SupervisorClientTls::Secret("client-tls"),
            "https://gateway:8080",
        );
        let container = supervisor_container(&pod);
        assert_eq!(
            env_value(container, "OPENSHELL_TLS_CA"),
            Some("/var/run/secrets/openshell-tls/ca.crt")
        );
        assert!(env_value(container, "OPENSHELL_TLS_CERT").is_none());
        assert!(env_value(container, "OPENSHELL_TLS_KEY").is_none());
        let mount = find_mount(container, "client-tls").expect("client TLS mount");
        assert_eq!(mount.mount_path, "/var/run/secrets/openshell-tls");
        let items = find_volume(pod_spec(&pod), "client-tls")
            .and_then(|volume| volume.secret.as_ref())
            .and_then(|secret| secret.items.as_ref())
            .expect("client TLS secret items");
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].key, "ca.crt");
        assert_eq!(items[0].path, "ca.crt");
    }

    #[test]
    fn runtime_objects_supervisor_pod_omits_client_tls_when_disabled() {
        let pod = supervisor(SupervisorClientTls::Disabled, "https://gateway:8080");
        let container = supervisor_container(&pod);
        assert!(
            container
                .env
                .as_ref()
                .expect("supervisor environment")
                .iter()
                .all(|variable| !variable.name.starts_with("OPENSHELL_TLS_"))
        );
        assert!(find_mount(container, "client-tls").is_none());
        assert!(find_volume(pod_spec(&pod), "client-tls").is_none());
    }

    #[test]
    fn runtime_objects_supervisor_verifies_redirects_only_for_https_endpoints() {
        let https = supervisor(SupervisorClientTls::Disabled, "https://gateway:8080");
        assert_eq!(
            env_value(
                supervisor_container(&https),
                "OPENSHELL_GATEWAY_TLS_SERVER_NAME"
            ),
            Some("gateway")
        );
        let plain = supervisor(SupervisorClientTls::Disabled, "http://gateway:8080");
        assert!(
            env_value(
                supervisor_container(&plain),
                "OPENSHELL_GATEWAY_TLS_SERVER_NAME"
            )
            .is_none()
        );

        assert_eq!(
            gateway_tls_server_name("https://openshell.openshell.svc.cluster.local:8080")
                .as_deref(),
            Some("openshell.openshell.svc.cluster.local")
        );
        assert_eq!(
            gateway_tls_server_name("https://[fd00::1]:8080").as_deref(),
            Some("fd00::1")
        );
        assert_eq!(gateway_tls_server_name("http://gateway:8080"), None);
        assert_eq!(gateway_tls_server_name("not a uri"), None);
    }

    #[test]
    fn runtime_objects_supervisor_pod_stamps_owner_and_labels() {
        let pod = supervisor(SupervisorClientTls::Disabled, "https://gateway:8080");
        assert_eq!(pod.metadata.name.as_deref(), Some("os-supervisor-pair"));
        assert_eq!(pod.metadata.namespace.as_deref(), Some("sandbox"));
        assert_eq!(pod.metadata.owner_references, Some(vec![owner("lease")]));
        let labels = pod.metadata.labels.expect("supervisor labels");
        assert_eq!(labels[LABEL_MANAGED_BY], LABEL_MANAGED_BY_VALUE);
        assert_eq!(labels[LABEL_SANDBOX_ID], "pair");
        assert_eq!(labels[LABEL_GATEWAY_ID], "gateway");
        assert_eq!(labels[BOUNDARY_PAIR_LABEL], "pair");
        assert_eq!(labels[BOUNDARY_ROLE_LABEL], "supervisor");
    }

    #[test]
    fn runtime_objects_supervisor_pod_keeps_credentials_out_of_metadata_and_env_refs() {
        let pod = supervisor(SupervisorClientTls::Disabled, "https://gateway:8080");
        assert_eq!(
            pod.metadata.annotations,
            Some(BTreeMap::from([(
                "openshell.ai/sandbox-id".to_string(),
                "pair".to_string(),
            )]))
        );
        let spec = pod_spec(&pod);
        assert!(spec.image_pull_secrets.is_none());
        assert!(
            supervisor_container(&pod)
                .env
                .as_ref()
                .expect("supervisor environment")
                .iter()
                .all(|variable| variable.value_from.is_none())
        );
    }

    #[test]
    fn runtime_objects_bootstrap_secrets_are_immutable_with_upstream_keys() {
        let names = SandboxRuntimeNames::for_generation("pair", "gen7");
        let sandbox = sandbox_bootstrap_secret(
            "sandbox",
            &names,
            "pair",
            b"config".to_vec(),
            b"certificate".to_vec(),
            b"private".to_vec(),
            owner("lease"),
        );
        assert_eq!(
            sandbox.metadata.name.as_deref(),
            Some("os-sandbox-pair-gen7")
        );
        assert_eq!(sandbox.immutable, Some(true));
        assert_eq!(sandbox.type_.as_deref(), Some("Opaque"));
        assert_eq!(
            sandbox.metadata.labels.as_ref().expect("labels")["openshell.ai/component"],
            "sandbox-bootstrap"
        );
        assert_eq!(
            secret_keys(&sandbox),
            ["boundary.json", "tls.crt", "tls.key"]
        );
        assert_eq!(secret_value(&sandbox, "boundary.json"), b"config");
        assert_eq!(secret_value(&sandbox, "tls.crt"), b"certificate");
        assert_eq!(secret_value(&sandbox, "tls.key"), b"private");

        let supervisor = supervisor_bootstrap_secret(
            "sandbox",
            &names,
            "pair",
            SupervisorSecretData {
                backend_descriptor: b"descriptor".to_vec(),
                auth_bundle: b"auth".to_vec(),
                proxy_ca_certificate: b"ca-cert".to_vec(),
                proxy_ca_private_key: b"ca-key".to_vec(),
            },
            owner("lease"),
        );
        assert_eq!(
            supervisor.metadata.name.as_deref(),
            Some("os-supervisor-pair-gen7")
        );
        assert_eq!(supervisor.immutable, Some(true));
        assert_eq!(supervisor.type_.as_deref(), Some("Opaque"));
        assert_eq!(
            supervisor.metadata.labels.as_ref().expect("labels")["openshell.ai/component"],
            "supervisor-bootstrap"
        );
        assert_eq!(
            secret_keys(&supervisor),
            [
                "auth.json",
                "proxy-ca.crt",
                "proxy-ca.key",
                "runtime-descriptor.json",
            ]
        );
        assert_eq!(
            secret_value(&supervisor, "runtime-descriptor.json"),
            b"descriptor"
        );
        assert_eq!(secret_value(&supervisor, "auth.json"), b"auth");
        assert_eq!(secret_value(&supervisor, "proxy-ca.crt"), b"ca-cert");
        assert_eq!(secret_value(&supervisor, "proxy-ca.key"), b"ca-key");
    }

    #[test]
    fn runtime_objects_bootstrap_secrets_stamp_their_owner() {
        let names = SandboxRuntimeNames::new("pair");
        let sandbox = sandbox_bootstrap_secret(
            "sandbox",
            &names,
            "pair",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            owner("lease"),
        );
        assert_eq!(
            sandbox.metadata.owner_references,
            Some(vec![owner("lease")])
        );
        let supervisor = supervisor_bootstrap_secret(
            "sandbox",
            &names,
            "pair",
            SupervisorSecretData {
                backend_descriptor: Vec::new(),
                auth_bundle: Vec::new(),
                proxy_ca_certificate: Vec::new(),
                proxy_ca_private_key: Vec::new(),
            },
            owner("lease"),
        );
        assert_eq!(
            supervisor.metadata.owner_references,
            Some(vec![owner("lease")])
        );
    }

    #[test]
    fn runtime_objects_proxy_ca_material_is_pem() {
        let material = generate_proxy_ca_material().expect("proxy CA material");
        assert!(
            material
                .certificate_pem
                .starts_with("-----BEGIN CERTIFICATE-----")
        );
        assert!(
            material
                .certificate_pem
                .trim_end()
                .ends_with("-----END CERTIFICATE-----")
        );
        assert!(
            material
                .private_key_pem
                .starts_with("-----BEGIN PRIVATE KEY-----")
        );
        assert!(
            material
                .private_key_pem
                .trim_end()
                .ends_with("-----END PRIVATE KEY-----")
        );
    }
}

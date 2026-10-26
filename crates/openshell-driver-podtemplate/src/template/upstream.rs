// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell` v0.1.5 workload-pod constants and pod parts, as typed
//! `k8s-openapi` values.
//!
//! Upstream builds these parts as `serde_json::Value`. The values here carry the
//! same content, and each item cites the upstream lines it was vendored from.
//! The vendored files are listed in `NOTICE`.

use k8s_openapi::api::core::v1::{
    Capabilities, Container, ContainerPort, DownwardAPIVolumeFile, DownwardAPIVolumeSource,
    EmptyDirVolumeSource, EnvVar, ObjectFieldSelector, PodDNSConfig, PodDNSConfigOption,
    PodSecurityContext, SeccompProfile, SecretVolumeSource, SecurityContext, Sysctl, Volume,
    VolumeMount,
};
use openshell_core::{sandbox_env, telemetry};

/// Label that binds the workload and supervisor pods in one unique pair.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/isolation.rs:66`.
pub const BOUNDARY_PAIR_LABEL: &str = "openshell.ai/boundary-pair";

/// Label distinguishing the two pods in a sandbox generation.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/isolation.rs:69`.
pub const BOUNDARY_ROLE_LABEL: &str = "openshell.ai/boundary-role";

/// Boundary-role label value for the workload pod.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/isolation.rs:71`.
pub const WORKLOAD_ROLE: &str = "workload";

/// Path where the bootstrap Secret is mounted read-only in the bootstrap container.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/sandbox_runtime.rs:42`.
pub const SANDBOX_BOOTSTRAP_INPUT_PATH: &str = "/.openshell/bootstrap-input";

/// Path of the boundary config file inside the sandbox state volume.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/sandbox_runtime.rs:43`.
pub const BOUNDARY_CONFIG_PATH: &str = "/.openshell/state/bootstrap/boundary.json";

/// Returns the pair label value for a sandbox ID: its lowercase form.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/sandbox_runtime.rs:161-164`.
#[must_use]
pub fn pair_label_value(sandbox_id: &str) -> String {
    sandbox_id.to_ascii_lowercase()
}

/// Volume holding the sandbox runtime binary.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:5905`.
pub const SANDBOX_RUNTIME_VOLUME_NAME: &str = "openshell-runtime";

/// Volume holding the sandbox state directory.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:5906`.
pub const SANDBOX_STATE_VOLUME_NAME: &str = "openshell-runtime-state";

/// Volume holding the bootstrap Secret.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:5907`.
pub const SANDBOX_BOOTSTRAP_VOLUME_NAME: &str = "openshell-sandbox-bootstrap";

/// Name of the bootstrap init container.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:5908`.
pub const SANDBOX_BOOTSTRAP_CONTAINER_NAME: &str = "openshell-sandbox-bootstrap";

/// Volume exposing the pod UID through the downward API.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:5909`.
pub const SANDBOX_POD_IDENTITY_VOLUME_NAME: &str = "openshell-pod-identity";

/// Root of the reserved control tree, including future runtime and bootstrap paths.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:5911`.
pub const SANDBOX_CONTROL_ROOT: &str = "/.openshell";

/// Mount path of the sandbox runtime volume.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:5912`.
pub const SANDBOX_RUNTIME_MOUNT_PATH: &str = "/.openshell/runtime";

/// Mount path of the sandbox state volume.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:5913`.
pub const SANDBOX_STATE_MOUNT_PATH: &str = "/.openshell/state";

/// Mount path of the pod identity volume.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:5914`.
pub const SANDBOX_POD_IDENTITY_MOUNT_PATH: &str = "/.openshell/pod-identity";

/// Volume shared between the workload and the proxy CA material.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:5916`.
pub const SANDBOX_PROXY_CA_VOLUME_NAME: &str = "openshell-run";

/// Mount path of the proxy CA volume.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:5917`.
pub const SANDBOX_PROXY_CA_MOUNT_PATH: &str = "/run";

/// Scheduling gate that holds the workload pod until bootstrap completes.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:5918`.
pub const SANDBOX_BOOTSTRAP_SCHEDULING_GATE: &str = "openshell.ai/bootstrap";

/// Volume names the driver reserves in a workload pod.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:507-523`. The
/// values of the constants outside lines 5905-5918 are inlined here: `spiffe-workload-api`
/// (`:356`), the three names at `:507-509`, and `workspace` (`:716`).
pub const RESERVED_VOLUME_NAMES: &[&str] = &[
    "openshell-client-tls",
    "openshell-upstream-proxy-auth",
    "openshell-sa-token",
    "spiffe-workload-api",
    SANDBOX_RUNTIME_VOLUME_NAME,
    SANDBOX_STATE_VOLUME_NAME,
    SANDBOX_BOOTSTRAP_VOLUME_NAME,
    SANDBOX_POD_IDENTITY_VOLUME_NAME,
    SANDBOX_PROXY_CA_VOLUME_NAME,
    "workspace",
];

/// Renders the trusted init container that stages the sandbox runtime binary.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:5930-5958`.
/// `pull_policy` is the Kubernetes `imagePullPolicy` string, such as `Always`.
#[must_use]
pub fn sandbox_bootstrap_init_container(
    image: &str,
    pull_policy: Option<&str>,
    uid: u32,
    gid: u32,
) -> Container {
    Container {
        name: SANDBOX_BOOTSTRAP_CONTAINER_NAME.to_string(),
        image: Some(image.to_string()),
        image_pull_policy: pull_policy.map(str::to_string),
        command: Some(vec![
            "/openshell-sandbox".to_string(),
            "bootstrap".to_string(),
        ]),
        security_context: Some(SecurityContext {
            run_as_user: Some(i64::from(uid)),
            run_as_group: Some(i64::from(gid)),
            run_as_non_root: Some(true),
            read_only_root_filesystem: Some(true),
            allow_privilege_escalation: Some(false),
            capabilities: Some(Capabilities {
                drop: Some(vec!["ALL".to_string()]),
                add: None,
            }),
            ..SecurityContext::default()
        }),
        volume_mounts: Some(vec![
            VolumeMount {
                name: SANDBOX_BOOTSTRAP_VOLUME_NAME.to_string(),
                mount_path: SANDBOX_BOOTSTRAP_INPUT_PATH.to_string(),
                read_only: Some(true),
                ..VolumeMount::default()
            },
            VolumeMount {
                name: SANDBOX_RUNTIME_VOLUME_NAME.to_string(),
                mount_path: SANDBOX_RUNTIME_MOUNT_PATH.to_string(),
                ..VolumeMount::default()
            },
            VolumeMount {
                name: SANDBOX_STATE_VOLUME_NAME.to_string(),
                mount_path: SANDBOX_STATE_MOUNT_PATH.to_string(),
                ..VolumeMount::default()
            },
        ]),
        ..Container::default()
    }
}

/// DNS config for the workload pod, which is used with `dnsPolicy: None`: a fixed loopback
/// resolver and tuned options.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:6011-6019`.
#[must_use]
pub fn workload_dns_config() -> PodDNSConfig {
    PodDNSConfig {
        nameservers: Some(vec!["127.0.0.53".to_string()]),
        options: Some(vec![
            PodDNSConfigOption {
                name: Some("ndots".to_string()),
                value: Some("5".to_string()),
            },
            PodDNSConfigOption {
                name: Some("timeout".to_string()),
                value: Some("2".to_string()),
            },
            PodDNSConfigOption {
                name: Some("attempts".to_string()),
                value: Some("2".to_string()),
            },
        ]),
        searches: None,
    }
}

/// Pod-level security context for the workload pod.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:6022-6033`.
/// Upstream also sets `supplementalGroupsPolicy: Strict`, which the `v1_29` type of
/// `k8s-openapi` does not have, so this context omits it.
#[must_use]
pub fn workload_pod_security_context(uid: u32, gid: u32) -> PodSecurityContext {
    PodSecurityContext {
        run_as_user: Some(i64::from(uid)),
        run_as_group: Some(i64::from(gid)),
        run_as_non_root: Some(true),
        fs_group: Some(i64::from(gid)),
        fs_group_change_policy: Some("OnRootMismatch".to_string()),
        supplemental_groups: Some(Vec::new()),
        seccomp_profile: Some(SeccompProfile {
            type_: "RuntimeDefault".to_string(),
            localhost_profile: None,
        }),
        sysctls: Some(vec![Sysctl {
            name: "net.ipv4.ip_unprivileged_port_start".to_string(),
            value: "0".to_string(),
        }]),
        ..PodSecurityContext::default()
    }
}

/// Volumes the sandbox runtime adds to the workload pod.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:6055-6073`.
/// `bootstrap_secret_name` names the Secret mounted as the bootstrap volume.
#[must_use]
pub fn sandbox_runtime_volumes(bootstrap_secret_name: &str) -> Vec<Volume> {
    vec![
        Volume {
            name: SANDBOX_RUNTIME_VOLUME_NAME.to_string(),
            empty_dir: Some(EmptyDirVolumeSource {
                medium: Some("Memory".to_string()),
                size_limit: None,
            }),
            ..Volume::default()
        },
        Volume {
            name: SANDBOX_STATE_VOLUME_NAME.to_string(),
            empty_dir: Some(EmptyDirVolumeSource {
                medium: Some("Memory".to_string()),
                size_limit: None,
            }),
            ..Volume::default()
        },
        Volume {
            name: SANDBOX_BOOTSTRAP_VOLUME_NAME.to_string(),
            secret: Some(SecretVolumeSource {
                secret_name: Some(bootstrap_secret_name.to_string()),
                // Octal 0o440: owner and group read, no access for others.
                default_mode: Some(0o440),
                items: None,
                optional: None,
            }),
            ..Volume::default()
        },
        Volume {
            name: SANDBOX_POD_IDENTITY_VOLUME_NAME.to_string(),
            downward_api: Some(DownwardAPIVolumeSource {
                default_mode: None,
                items: Some(vec![DownwardAPIVolumeFile {
                    path: "uid".to_string(),
                    field_ref: Some(ObjectFieldSelector {
                        api_version: None,
                        field_path: "metadata.uid".to_string(),
                    }),
                    mode: None,
                    resource_field_ref: None,
                }]),
            }),
            ..Volume::default()
        },
        Volume {
            name: SANDBOX_PROXY_CA_VOLUME_NAME.to_string(),
            empty_dir: Some(EmptyDirVolumeSource {
                medium: Some("Memory".to_string()),
                size_limit: None,
            }),
            ..Volume::default()
        },
    ]
}

/// Command that starts the sandbox supervisor in bootstrap mode.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:6099-6106`.
#[must_use]
pub fn sandbox_runtime_command() -> Vec<String> {
    vec![
        format!("{SANDBOX_RUNTIME_MOUNT_PATH}/openshell-sandbox"),
        "--bootstrap".to_string(),
        BOUNDARY_CONFIG_PATH.to_string(),
    ]
}

/// Container security context for the workload container.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:6107-6116`.
#[must_use]
pub fn workload_container_security_context(uid: u32, gid: u32) -> SecurityContext {
    SecurityContext {
        run_as_user: Some(i64::from(uid)),
        run_as_group: Some(i64::from(gid)),
        run_as_non_root: Some(true),
        allow_privilege_escalation: Some(false),
        capabilities: Some(Capabilities {
            drop: Some(vec!["ALL".to_string()]),
            add: None,
        }),
        ..SecurityContext::default()
    }
}

/// Name of the container port that carries the sandbox control channel.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:6120`.
pub const SANDBOX_CONTROL_PORT_NAME: &str = "sandbox-control";

/// Container port for the sandbox control channel, on `boundary_port`.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:6117-6124`.
#[must_use]
pub fn sandbox_control_port(boundary_port: u16) -> ContainerPort {
    ContainerPort {
        name: Some(SANDBOX_CONTROL_PORT_NAME.to_string()),
        container_port: i32::from(boundary_port),
        protocol: Some("TCP".to_string()),
        ..ContainerPort::default()
    }
}

/// Volume mounts the sandbox runtime adds to the workload container.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:6141-6146`.
#[must_use]
pub fn sandbox_runtime_volume_mounts() -> Vec<VolumeMount> {
    vec![
        VolumeMount {
            name: SANDBOX_RUNTIME_VOLUME_NAME.to_string(),
            mount_path: SANDBOX_RUNTIME_MOUNT_PATH.to_string(),
            read_only: Some(true),
            ..VolumeMount::default()
        },
        VolumeMount {
            name: SANDBOX_STATE_VOLUME_NAME.to_string(),
            mount_path: SANDBOX_STATE_MOUNT_PATH.to_string(),
            ..VolumeMount::default()
        },
        VolumeMount {
            name: SANDBOX_POD_IDENTITY_VOLUME_NAME.to_string(),
            mount_path: SANDBOX_POD_IDENTITY_MOUNT_PATH.to_string(),
            read_only: Some(true),
            ..VolumeMount::default()
        },
        VolumeMount {
            name: SANDBOX_PROXY_CA_VOLUME_NAME.to_string(),
            mount_path: SANDBOX_PROXY_CA_MOUNT_PATH.to_string(),
            ..VolumeMount::default()
        },
    ]
}

/// Applies the `OpenShell` environment to the workload container.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:6858-6874`
/// and `:6876-6907`. Drops every `OPENSHELL_*` entry except `OPENSHELL_LOG_LEVEL`,
/// upserts `OPENSHELL_TELEMETRY_ENABLED`, then pins the resolved image user and
/// identity. Entries not named `OPENSHELL_*`, including `valueFrom` entries, keep
/// their position and content.
pub fn apply_workload_env(env: &mut Vec<EnvVar>, uid: u32, gid: u32) {
    env.retain(|var| !var.name.starts_with("OPENSHELL_") || var.name == sandbox_env::LOG_LEVEL);
    upsert_env(
        env,
        sandbox_env::TELEMETRY_ENABLED,
        telemetry::enabled_env_value(),
    );
    remove_env(env, sandbox_env::OCI_IMAGE_USER);
    remove_env(env, sandbox_env::SANDBOX_UID);
    remove_env(env, sandbox_env::SANDBOX_GID);
    upsert_env(env, sandbox_env::OCI_IMAGE_USER, "");
    upsert_env(env, sandbox_env::SANDBOX_UID, &uid.to_string());
    upsert_env(env, sandbox_env::SANDBOX_GID, &gid.to_string());
}

/// Sets the plain-valued env entry `name`, replacing an existing entry in place.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:6876-6886`.
/// Entries are matched by name only, so a `valueFrom` entry is never read.
pub fn upsert_env(env: &mut Vec<EnvVar>, name: &str, value: &str) {
    let entry = EnvVar {
        name: name.to_string(),
        value: Some(value.to_string()),
        value_from: None,
    };
    if let Some(existing) = env.iter_mut().find(|var| var.name == name) {
        *existing = entry;
        return;
    }
    env.push(entry);
}

/// Removes every env entry named `name`.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:6905-6907`.
pub fn remove_env(env: &mut Vec<EnvVar>, name: &str) {
    env.retain(|var| var.name != name);
}

#[cfg(test)]
mod tests {
    use k8s_openapi::api::core::v1::{EnvVar, EnvVarSource, SecretKeySelector};
    use openshell_core::{sandbox_env, telemetry};
    use serde_json::json;

    use super::{
        BOUNDARY_CONFIG_PATH, BOUNDARY_PAIR_LABEL, BOUNDARY_ROLE_LABEL, RESERVED_VOLUME_NAMES,
        SANDBOX_BOOTSTRAP_INPUT_PATH, SANDBOX_BOOTSTRAP_SCHEDULING_GATE, SANDBOX_CONTROL_PORT_NAME,
        SANDBOX_CONTROL_ROOT, WORKLOAD_ROLE, apply_workload_env, pair_label_value,
        sandbox_bootstrap_init_container, sandbox_control_port, sandbox_runtime_command,
        sandbox_runtime_volume_mounts, sandbox_runtime_volumes, upsert_env,
        workload_container_security_context, workload_dns_config, workload_pod_security_context,
    };

    macro_rules! render {
        ($value:expr) => {
            serde_json::to_value(&$value).expect("k8s-openapi types serialize")
        };
    }

    #[test]
    fn upstream_bootstrap_init_container_matches_upstream_json() {
        let container = sandbox_bootstrap_init_container(
            "ghcr.io/example/sandbox:1",
            Some("IfNotPresent"),
            1000,
            2000,
        );
        assert_eq!(
            render!(container),
            json!({
                "name": "openshell-sandbox-bootstrap",
                "image": "ghcr.io/example/sandbox:1",
                "command": ["/openshell-sandbox", "bootstrap"],
                "securityContext": {
                    "runAsUser": 1000,
                    "runAsGroup": 2000,
                    "runAsNonRoot": true,
                    "readOnlyRootFilesystem": true,
                    "allowPrivilegeEscalation": false,
                    "capabilities": {"drop": ["ALL"]}
                },
                "volumeMounts": [
                    {"name": "openshell-sandbox-bootstrap", "mountPath": "/.openshell/bootstrap-input", "readOnly": true},
                    {"name": "openshell-runtime", "mountPath": "/.openshell/runtime"},
                    {"name": "openshell-runtime-state", "mountPath": "/.openshell/state"}
                ],
                "imagePullPolicy": "IfNotPresent"
            })
        );
    }

    #[test]
    fn upstream_bootstrap_init_container_omits_unset_pull_policy() {
        let container =
            sandbox_bootstrap_init_container("ghcr.io/example/sandbox:1", None, 1000, 2000);
        assert!(render!(container).get("imagePullPolicy").is_none());
    }

    #[test]
    fn upstream_workload_dns_config_matches_upstream_json() {
        assert_eq!(
            render!(workload_dns_config()),
            json!({
                "nameservers": ["127.0.0.53"],
                "options": [
                    {"name": "ndots", "value": "5"},
                    {"name": "timeout", "value": "2"},
                    {"name": "attempts", "value": "2"}
                ]
            })
        );
    }

    #[test]
    fn upstream_workload_pod_security_context_matches_upstream_json() {
        assert_eq!(
            render!(workload_pod_security_context(1000, 2000)),
            json!({
                "runAsUser": 1000,
                "runAsGroup": 2000,
                "runAsNonRoot": true,
                "fsGroup": 2000,
                "fsGroupChangePolicy": "OnRootMismatch",
                "supplementalGroups": [],
                // Upstream also renders "supplementalGroupsPolicy": "Strict", which the
                // v1_29 k8s-openapi type cannot carry.
                "seccompProfile": {"type": "RuntimeDefault"},
                "sysctls": [{"name": "net.ipv4.ip_unprivileged_port_start", "value": "0"}]
            })
        );
    }

    #[test]
    fn upstream_sandbox_runtime_volumes_match_upstream_json() {
        assert_eq!(
            render!(sandbox_runtime_volumes("sandbox-bootstrap-secret")),
            json!([
                {"name": "openshell-runtime", "emptyDir": {"medium": "Memory"}},
                {"name": "openshell-runtime-state", "emptyDir": {"medium": "Memory"}},
                {
                    "name": "openshell-sandbox-bootstrap",
                    "secret": {
                        "secretName": "sandbox-bootstrap-secret",
                        // Upstream writes 0o440 here; JSON renders it in decimal.
                        "defaultMode": 288
                    }
                },
                {
                    "name": "openshell-pod-identity",
                    "downwardAPI": {
                        "items": [{"path": "uid", "fieldRef": {"fieldPath": "metadata.uid"}}]
                    }
                },
                {"name": "openshell-run", "emptyDir": {"medium": "Memory"}}
            ])
        );
    }

    #[test]
    fn upstream_sandbox_runtime_command_matches_upstream_json() {
        assert_eq!(
            render!(sandbox_runtime_command()),
            json!([
                "/.openshell/runtime/openshell-sandbox",
                "--bootstrap",
                "/.openshell/state/bootstrap/boundary.json"
            ])
        );
    }

    #[test]
    fn upstream_workload_container_security_context_matches_upstream_json() {
        assert_eq!(
            render!(workload_container_security_context(1000, 2000)),
            json!({
                "runAsUser": 1000,
                "runAsGroup": 2000,
                "runAsNonRoot": true,
                "allowPrivilegeEscalation": false,
                "capabilities": {"drop": ["ALL"]}
            })
        );
    }

    #[test]
    fn upstream_sandbox_control_port_matches_upstream_json() {
        assert_eq!(
            render!(sandbox_control_port(9443)),
            json!({"name": "sandbox-control", "containerPort": 9443, "protocol": "TCP"})
        );
    }

    #[test]
    fn upstream_sandbox_runtime_volume_mounts_match_upstream_json() {
        assert_eq!(
            render!(sandbox_runtime_volume_mounts()),
            json!([
                {"name": "openshell-runtime", "mountPath": "/.openshell/runtime", "readOnly": true},
                {"name": "openshell-runtime-state", "mountPath": "/.openshell/state"},
                {"name": "openshell-pod-identity", "mountPath": "/.openshell/pod-identity", "readOnly": true},
                {"name": "openshell-run", "mountPath": "/run"}
            ])
        );
    }

    #[test]
    fn upstream_apply_workload_env_keeps_value_from_entry_byte_identical() {
        let value_from = EnvVar {
            name: "API_TOKEN".to_string(),
            value: None,
            value_from: Some(EnvVarSource {
                secret_key_ref: Some(SecretKeySelector {
                    key: "token".to_string(),
                    ..SecretKeySelector::default()
                }),
                ..EnvVarSource::default()
            }),
        };
        let before = serde_json::to_string(&value_from).expect("EnvVar serializes");
        let mut env = vec![
            EnvVar {
                name: sandbox_env::ENDPOINT.to_string(),
                value: Some("https://gateway.invalid".to_string()),
                value_from: None,
            },
            value_from,
        ];

        apply_workload_env(&mut env, 1000, 2000);

        assert!(env.iter().all(|var| var.name != sandbox_env::ENDPOINT));
        assert_eq!(env[0].name, "API_TOKEN");
        assert_eq!(
            serde_json::to_string(&env[0]).expect("EnvVar serializes"),
            before
        );
    }

    #[test]
    fn upstream_apply_workload_env_filters_and_pins_identity() {
        let mut env = vec![
            EnvVar {
                name: sandbox_env::ENDPOINT.to_string(),
                value: Some("https://gateway.invalid".to_string()),
                value_from: None,
            },
            EnvVar {
                name: sandbox_env::LOG_LEVEL.to_string(),
                value: Some("debug".to_string()),
                value_from: None,
            },
            EnvVar {
                name: "FOO".to_string(),
                value: Some("bar".to_string()),
                value_from: None,
            },
            EnvVar {
                name: sandbox_env::SANDBOX_UID.to_string(),
                value: Some("9".to_string()),
                value_from: None,
            },
        ];

        apply_workload_env(&mut env, 1000, 2000);

        assert_eq!(
            render!(env),
            json!([
                {"name": "OPENSHELL_LOG_LEVEL", "value": "debug"},
                {"name": "FOO", "value": "bar"},
                {"name": "OPENSHELL_TELEMETRY_ENABLED", "value": telemetry::enabled_env_value()},
                {"name": "OPENSHELL_OCI_IMAGE_USER", "value": ""},
                {"name": "OPENSHELL_SANDBOX_UID", "value": "1000"},
                {"name": "OPENSHELL_SANDBOX_GID", "value": "2000"}
            ])
        );
    }

    #[test]
    fn upstream_upsert_env_replaces_existing_entry_in_place() {
        let mut env = vec![
            EnvVar {
                name: "A".to_string(),
                value: Some("old".to_string()),
                value_from: None,
            },
            EnvVar {
                name: "B".to_string(),
                value: Some("x".to_string()),
                value_from: None,
            },
        ];

        upsert_env(&mut env, "A", "new");
        upsert_env(&mut env, "C", "y");

        assert_eq!(
            render!(env),
            json!([
                {"name": "A", "value": "new"},
                {"name": "B", "value": "x"},
                {"name": "C", "value": "y"}
            ])
        );
    }

    #[test]
    fn upstream_fence_constants_match_upstream_values() {
        assert_eq!(BOUNDARY_PAIR_LABEL, "openshell.ai/boundary-pair");
        assert_eq!(BOUNDARY_ROLE_LABEL, "openshell.ai/boundary-role");
        assert_eq!(WORKLOAD_ROLE, "workload");
        assert_eq!(SANDBOX_BOOTSTRAP_SCHEDULING_GATE, "openshell.ai/bootstrap");
        assert_eq!(SANDBOX_CONTROL_ROOT, "/.openshell");
        assert_eq!(SANDBOX_BOOTSTRAP_INPUT_PATH, "/.openshell/bootstrap-input");
        assert_eq!(
            BOUNDARY_CONFIG_PATH,
            "/.openshell/state/bootstrap/boundary.json"
        );
        assert_eq!(SANDBOX_CONTROL_PORT_NAME, "sandbox-control");
    }

    #[test]
    fn upstream_pair_label_value_lowercases() {
        assert_eq!(pair_label_value("Sbx-ABC_123"), "sbx-abc_123");
    }

    #[test]
    fn upstream_reserved_volume_names_match_upstream_list() {
        assert_eq!(
            RESERVED_VOLUME_NAMES,
            &[
                "openshell-client-tls",
                "openshell-upstream-proxy-auth",
                "openshell-sa-token",
                "spiffe-workload-api",
                "openshell-runtime",
                "openshell-runtime-state",
                "openshell-sandbox-bootstrap",
                "openshell-pod-identity",
                "openshell-run",
                "workspace",
            ]
        );
    }
}

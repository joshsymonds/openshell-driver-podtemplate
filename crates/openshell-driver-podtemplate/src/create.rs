// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
// SPDX-License-Identifier: Apache-2.0

//! The create sequence of a sandbox.
//!
//! [`validate_sandbox_create`] rejects a request that cannot be provisioned before anything
//! exists. [`create_sandbox`] runs the dedicated-supervisor create against Kubernetes from the
//! named `PodTemplate`: fences, the Lease record, the boundary Service, the gated supervisor and
//! workload pods, the boundary provisioning, the bootstrap Secrets, the start-inputs Secret,
//! and the gate releases. [`start_sandbox`] recreates that runtime for a new generation from the
//! stored start-inputs Secret, without a record of its own. The pure steps the two are built from
//! (the template reference, launch authentication decoding, the child environment, the
//! main-process spec, the workload pod object, and the check of the admitted workload pod) are at
//! the top of the module.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use k8s_openapi::ByteString;
use k8s_openapi::api::coordination::v1::Lease;
use k8s_openapi::api::core::v1::{
    Container, Namespace, Pod, PodSpec, PodTemplate, Secret, Service,
};
use k8s_openapi::api::networking::v1::{NetworkPolicy, NetworkPolicySpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::{Api, ApiResource, Patch, PatchParams, PostParams};
use kube::core::{DynamicObject, ObjectMeta};
use openshell_core::driver_utils::{
    LABEL_MANAGED_BY, LABEL_MANAGED_BY_VALUE, LABEL_SANDBOX_ID, sandbox_log_level,
};
use openshell_core::jwt::{SandboxLaunchAuthentication, SessionVerificationKey};
use openshell_core::proto::compute::v1::{DriverSandbox, DriverSandboxSpec};
use openshell_core::sandbox_env::MainProcessConfig;
use openshell_driver_kubernetes::config::is_dns_1123_label;
use openshell_driver_kubernetes::isolation::{
    KubernetesSandboxRuntimeBoundaryProvisioning, KubernetesSandboxRuntimeBoundarySpec,
};
use openshell_isolation_interface::contract::ResolvedWorkloadIdentity;
use openshell_sandbox_backend::boundary_protocol::{
    GatewayVerificationKey, SandboxTlsClientConfig, SandboxTlsMaterial, SandboxTlsServerConfig,
    generate_sandbox_tls_material,
};
use prost::Message;
use prost_types::value::Kind;
use serde_json::{Value, json};
use tokio::sync::oneshot;
use tokio::time::timeout;

use crate::auth::runtime_identity;
use crate::config::Config;
use crate::delete::{controlled_by, delete_record, stop_runtime};
use crate::error::DriverError;
use crate::registry::{record_owner_reference, record_sandbox_id, sandbox_record};
use crate::runtime_objects::{
    SandboxRuntimeNames, SupervisorClientTls, SupervisorPodParams, SupervisorSecretData,
    boundary_service, boundary_service_authority, generate_proxy_ca_material,
    sandbox_bootstrap_secret, supervisor_bootstrap_secret, supervisor_pod, workload_fence,
};
use crate::template::upstream::{
    BOUNDARY_PAIR_LABEL, BOUNDARY_ROLE_LABEL, SANDBOX_BOOTSTRAP_CONTAINER_NAME,
    SANDBOX_BOOTSTRAP_SCHEDULING_GATE, SANDBOX_BOOTSTRAP_VOLUME_NAME, WORKLOAD_ROLE,
    pair_label_value,
};
use crate::template::{MutationParams, ValidatedTemplate, mutate, validate};

/// Driver-config field that names the pod template.
const TEMPLATE_NAME_FIELD: &str = "template";
/// Field that the template reference errors name.
const TEMPLATE_REF_FIELD: &str = "driver_config.podtemplate.template";
/// Message for a sandbox name that is not a DNS-1123 label, as upstream words it.
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:607-614`.
const SANDBOX_NAME_MESSAGE: &str = "sandbox name must be a DNS-1123 label: use lowercase alphanumeric characters or '-', start and end with an alphanumeric character, and use at most 63 characters";
/// Kind of the controller that owns the workload pod.
const LEASE_KIND: &str = "Lease";
/// Prefix of every rejection of an admitted workload pod, as upstream words it.
const ADMISSION_PREFIX: &str =
    "admitted workload Pod does not preserve capability-free isolation: ";
/// The only `supplementalGroupsPolicy` the workload pod may carry.
const STRICT_POLICY: &str = "Strict";
/// Sysctl the workload pod sets to allow unprivileged ports, and the value it must carry.
const UNPRIVILEGED_PORT_SYSCTL: &str = "net.ipv4.ip_unprivileged_port_start";
/// The one nameserver the workload pod resolves through.
const WORKLOAD_NAMESERVER: &str = "127.0.0.53";
/// Timeout of each fence read and write.
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:268`.
const KUBE_API_TIMEOUT: Duration = Duration::from_secs(30);
/// Label key that names the component a managed object belongs to.
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:2204-2224`.
const COMPONENT_LABEL: &str = "openshell.ai/component";
/// Component label of the workload fence.
const WORKLOAD_FENCE_COMPONENT: &str = "sandbox-workload-fence";
/// Component label of the supervisor egress fence.
const SUPERVISOR_FENCE_COMPONENT: &str = "sandbox-supervisor-egress";
/// Component label of the start-inputs Secret.
const START_INPUTS_COMPONENT: &str = "sandbox-start-inputs";
/// Data key of the start-inputs Secret, which holds the encoded `DriverSandbox`.
const START_INPUTS_KEY: &str = "driver-sandbox.pb";
/// Where the boundary certificate chain is staged in the workload pod.
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/sandbox_runtime.rs:44`.
const BOUNDARY_CERTIFICATE_PATH: &str = "/.openshell/state/bootstrap/tls.crt";
/// Where the boundary private key is staged in the workload pod.
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/sandbox_runtime.rs:45`.
const BOUNDARY_PRIVATE_KEY_PATH: &str = "/.openshell/state/bootstrap/tls.key";
/// Where the workload pod reads its own UID, which the boundary config binds.
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:5915`.
const SANDBOX_POD_UID_PATH: &str = "/.openshell/pod-identity/uid";
/// Source label of the workload identity, as the in-tree Kubernetes driver names it.
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:2686`.
const WORKLOAD_IDENTITY_SOURCE: &str = "kubernetes-config";

/// The template a create request names, read from the sandbox's driver config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateRef {
    /// Name of the template, a DNS-1123 subdomain.
    pub name: String,
    /// Image the sandbox container must name.
    pub image: String,
}

/// The per-sandbox values that an admitted workload pod is checked against.
#[derive(Debug)]
pub struct AdmissionExpectation<'a> {
    /// UID of the sandbox record, which the Lease that owns the workload pod carries.
    pub record_uid: &'a str,
    /// Sandbox ID that the pair label is derived from.
    pub sandbox_id: &'a str,
    /// User ID the sandbox runs as.
    pub uid: u32,
    /// Group ID the sandbox runs as.
    pub gid: u32,
    /// Name of the generation-specific bootstrap Secret.
    pub bootstrap_secret_name: &'a str,
}

/// Reads the template reference of `sandbox`.
///
/// The template name is the string field `template` of `spec.template.driver_config`, which
/// the gateway narrows to the `podtemplate` block. The image is `spec.template.image`.
///
/// # Errors
///
/// Returns `InvalidArgument` when `spec.template` is absent, or when the name is missing, not
/// a string, empty, or not a DNS-1123 subdomain.
pub fn template_ref(sandbox: &DriverSandbox) -> Result<TemplateRef, DriverError> {
    let template = sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .ok_or_else(|| template_ref_error("is required"))?;
    let name = template
        .driver_config
        .as_ref()
        .and_then(|config| config.fields.get(TEMPLATE_NAME_FIELD))
        .and_then(|value| match &value.kind {
            Some(Kind::StringValue(name)) => Some(name),
            _ => None,
        })
        .filter(|name| is_dns_subdomain(name))
        .ok_or_else(|| template_ref_error("must be a non-empty DNS-1123 subdomain"))?;
    Ok(TemplateRef {
        name: name.to_owned(),
        image: template.image.clone(),
    })
}

/// Builds the rejection for a template reference that is missing or invalid.
fn template_ref_error(reason: &str) -> DriverError {
    DriverError::InvalidArgument(format!("{TEMPLATE_REF_FIELD} {reason}"))
}

/// Reports whether `value` is a DNS-1123 subdomain: at most 253 characters, and every
/// dot-separated part a DNS-1123 label.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:603-605`.
fn is_dns_subdomain(value: &str) -> bool {
    value.len() <= 253 && value.split('.').all(is_dns_1123_label)
}

/// Checks that `name` is a DNS-1123 label, the form a sandbox name takes.
///
/// # Errors
///
/// Returns `InvalidArgument` naming the rule when `name` is not a DNS-1123 label.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:607-614`.
pub fn validate_sandbox_name(name: &str) -> Result<(), DriverError> {
    if is_dns_1123_label(name) {
        return Ok(());
    }
    Err(DriverError::InvalidArgument(
        SANDBOX_NAME_MESSAGE.to_owned(),
    ))
}

/// Decodes and validates the gateway's launch authentication.
///
/// A malformed document is named by its failure class and position only, never by its text,
/// because the text can quote token bytes.
///
/// # Errors
///
/// Returns `Precondition` when `encoded` is empty, malformed, or fails validation.
///
/// Adapted from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:300-316`; the decode error names only its class and position.
pub fn decode_launch_authentication(
    encoded: &[u8],
) -> Result<SandboxLaunchAuthentication, DriverError> {
    if encoded.is_empty() {
        return Err(DriverError::Precondition(
            "launch authentication is required".to_owned(),
        ));
    }
    let authentication: SandboxLaunchAuthentication =
        serde_json::from_slice(encoded).map_err(|error| decode_failure(&error))?;
    authentication.validate().map_err(|error| {
        DriverError::Precondition(format!("validate launch authentication: {error}"))
    })?;
    Ok(authentication)
}

/// Names the failure class and position of a launch-authentication document that does not
/// decode.
fn decode_failure(error: &serde_json::Error) -> DriverError {
    let category = error.classify();
    let (line, column) = (error.line(), error.column());
    DriverError::Precondition(format!(
        "decode launch authentication: {category:?} error at line {line} column {column}"
    ))
}

/// Converts the gateway's verification keys to the form the sandbox receives.
///
/// # Errors
///
/// Returns `Precondition` when a key's PEM is not UTF-8.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:318-335`.
pub fn gateway_verification_keys(
    keys: &[SessionVerificationKey],
) -> Result<Vec<GatewayVerificationKey>, DriverError> {
    keys.iter()
        .map(|key| {
            String::from_utf8(key.public_key_pem.clone())
                .map(|public_key_pem| GatewayVerificationKey {
                    key_id: key.key_id.clone(),
                    public_key_pem,
                })
                .map_err(|error| {
                    DriverError::Precondition(format!(
                        "sandbox verification key is not UTF-8 PEM: {error}"
                    ))
                })
        })
        .collect()
}

/// Builds the child environment: the template's environment with the spec's entries merged
/// over it, and every `OPENSHELL_` name removed.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:2664-2674`.
pub fn child_env(sandbox: &DriverSandbox) -> HashMap<String, String> {
    let mut child_env = sandbox
        .spec
        .as_ref()
        .and_then(|spec| spec.template.as_ref())
        .map_or_else(HashMap::new, |template| template.environment.clone());
    if let Some(spec) = sandbox.spec.as_ref() {
        child_env.extend(spec.environment.clone());
    }
    child_env.retain(|name, _| !name.starts_with("OPENSHELL_"));
    child_env
}

/// Serializes the main-process spec that the supervisor reads.
///
/// The command is the template's, never the request's. `tty` and `await_main_process_attachment`
/// come from `spec`, and are false when it is absent.
///
/// # Errors
///
/// Returns `InvalidArgument` when the spec cannot be serialized.
pub fn main_process_spec(
    template: &ValidatedTemplate,
    spec: Option<&DriverSandboxSpec>,
) -> Result<String, DriverError> {
    let config = MainProcessConfig {
        version: MainProcessConfig::VERSION,
        command: template.main_process_command().to_vec(),
        tty: spec.is_some_and(|spec| spec.tty),
        await_main_process_attachment: spec.is_some_and(|spec| spec.await_main_process_attachment),
    };
    serde_json::to_string(&config)
        .map_err(|error| DriverError::InvalidArgument(format!("encode main process spec: {error}")))
}

/// Serializes the workload pod with `owner` as its only owner reference and the
/// `supplementalGroupsPolicy` of `Strict`, a field the typed pod does not have.
///
/// # Errors
///
/// Returns `Message` when the pod or the owner reference cannot be serialized.
pub fn workload_pod_object(pod: &Pod, owner: OwnerReference) -> Result<Value, DriverError> {
    let owners = serde_json::to_value([owner]).map_err(serialization_error)?;
    let mut object = serde_json::to_value(pod).map_err(serialization_error)?;
    object["metadata"]["ownerReferences"] = owners;
    object["spec"]["securityContext"]["supplementalGroupsPolicy"] = json!(STRICT_POLICY);
    Ok(object)
}

/// Converts a serialization failure into the message the driver reports.
fn serialization_error(error: serde_json::Error) -> DriverError {
    DriverError::Message(error.to_string())
}

/// Checks an admitted workload pod as upstream checks it before any gate is released, and
/// returns it typed.
///
/// The pod's owner must be a controlling Lease carrying `expected.record_uid`. The pod's one
/// container is the sandbox container. `supplementalGroupsPolicy` is read from `admitted`: a
/// present value other than `Strict` is rejected, and an absent one is logged.
///
/// # Errors
///
/// Returns `Precondition`, with upstream's message prefix, when a check fails.
///
/// Adapted from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:2267-2472` (`validate_capability_free_workload_pod`).
pub fn verify_admitted_workload_pod(
    admitted: &Value,
    expected: &AdmissionExpectation<'_>,
) -> Result<Pod, DriverError> {
    let pod: Pod = serde_json::from_value(admitted.clone())
        .map_err(|_| rejected("Pod object is malformed"))?;
    if pod.metadata.uid.is_none() {
        return Err(rejected("missing Pod UID"));
    }
    check_owner(&pod, expected)?;
    check_labels(&pod, expected)?;
    let spec = pod
        .spec
        .as_ref()
        .ok_or_else(|| rejected("missing Pod spec"))?;
    check_pod_fence(spec)?;
    check_pod_identity(spec, expected)?;
    check_supplemental_groups_policy(admitted, &pod)?;
    check_containers(spec, expected)?;
    Ok(pod)
}

/// Builds the rejection for an admitted workload pod that fails a check.
fn rejected(reason: &str) -> DriverError {
    DriverError::Precondition(format!("{ADMISSION_PREFIX}{reason}"))
}

/// The pod must be controlled by the Lease that carries the sandbox record's UID.
fn check_owner(pod: &Pod, expected: &AdmissionExpectation<'_>) -> Result<(), DriverError> {
    let owned = pod
        .metadata
        .owner_references
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|owner| {
            owner.controller == Some(true)
                && owner.kind == LEASE_KIND
                && owner.uid == expected.record_uid
        });
    if !owned {
        return Err(rejected("Lease owner UID changed"));
    }
    Ok(())
}

/// The pod must keep the workload role and the pair label of its sandbox.
fn check_labels(pod: &Pod, expected: &AdmissionExpectation<'_>) -> Result<(), DriverError> {
    let labels = pod
        .metadata
        .labels
        .as_ref()
        .ok_or_else(|| rejected("missing labels"))?;
    let pair = pair_label_value(expected.sandbox_id);
    if labels.get(BOUNDARY_ROLE_LABEL).map(String::as_str) != Some(WORKLOAD_ROLE)
        || labels.get(BOUNDARY_PAIR_LABEL).map(String::as_str) != Some(pair.as_str())
    {
        return Err(rejected("pair labels changed"));
    }
    Ok(())
}

/// The pod must keep its fence: no host namespace, no `ServiceAccount` token, the workload DNS
/// posture, and the bootstrap scheduling gate.
fn check_pod_fence(spec: &PodSpec) -> Result<(), DriverError> {
    if spec.host_network == Some(true)
        || spec.host_pid == Some(true)
        || spec.host_ipc == Some(true)
        || spec.share_process_namespace == Some(true)
        || spec.automount_service_account_token != Some(false)
    {
        return Err(rejected("host namespaces or ServiceAccount token enabled"));
    }
    let projects_token = spec
        .volumes
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter_map(|volume| volume.projected.as_ref())
        .flat_map(|projected| projected.sources.as_deref().unwrap_or_default())
        .any(|source| source.service_account_token.is_some());
    if projects_token {
        return Err(rejected(
            "workload Pod must not receive a projected ServiceAccount token",
        ));
    }
    if spec.restart_policy.as_deref() != Some("Never")
        || spec.dns_policy.as_deref() != Some("None")
        || spec
            .dns_config
            .as_ref()
            .is_none_or(|dns| dns.nameservers.as_deref() != Some(&[WORKLOAD_NAMESERVER.to_owned()]))
    {
        return Err(rejected("restart or DNS posture changed"));
    }
    let gated = spec
        .scheduling_gates
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|gate| gate.name == SANDBOX_BOOTSTRAP_SCHEDULING_GATE);
    if !gated {
        return Err(rejected("bootstrap scheduling gate missing"));
    }
    Ok(())
}

/// The pod must run as the sandbox's numeric identity, with no supplemental groups, the
/// `RuntimeDefault` seccomp profile, and the unprivileged-port sysctl.
fn check_pod_identity(
    spec: &PodSpec,
    expected: &AdmissionExpectation<'_>,
) -> Result<(), DriverError> {
    let security = spec
        .security_context
        .as_ref()
        .ok_or_else(|| rejected("missing Pod security context"))?;
    let identity_held = security.run_as_user == Some(i64::from(expected.uid))
        && security.run_as_group == Some(i64::from(expected.gid))
        && security.run_as_non_root == Some(true)
        && security.fs_group == Some(i64::from(expected.gid))
        && security
            .supplemental_groups
            .as_deref()
            .is_none_or(<[i64]>::is_empty)
        && security
            .seccomp_profile
            .as_ref()
            .is_some_and(|profile| profile.type_ == "RuntimeDefault");
    if !identity_held {
        return Err(rejected(
            "numeric identity, groups, or seccomp profile changed",
        ));
    }
    let port_sysctl = security
        .sysctls
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|sysctl| sysctl.name == UNPRIVILEGED_PORT_SYSCTL && sysctl.value == "0");
    if !port_sysctl {
        return Err(rejected("safe unprivileged-port sysctl changed"));
    }
    Ok(())
}

/// `supplementalGroupsPolicy` is not a field of the typed pod, so it is read from the admitted
/// object. A present value other than `Strict` is rejected, and an absent one is logged.
fn check_supplemental_groups_policy(admitted: &Value, pod: &Pod) -> Result<(), DriverError> {
    let policy = admitted.pointer("/spec/securityContext/supplementalGroupsPolicy");
    if policy.is_some_and(|policy| policy != &json!(STRICT_POLICY)) {
        return Err(rejected("supplementalGroupsPolicy is not Strict"));
    }
    if policy.is_none() {
        tracing::warn!(
            pod = pod.metadata.name.as_deref().unwrap_or("<unknown>"),
            "Kubernetes omitted supplementalGroupsPolicy; exact runtime groups remain enforced by boundary confirmation"
        );
    }
    Ok(())
}

/// The pod's one container is the sandbox container, which must not mount the bootstrap Secret.
/// The trusted bootstrap init container must mount it.
fn check_containers(
    spec: &PodSpec,
    expected: &AdmissionExpectation<'_>,
) -> Result<(), DriverError> {
    let [sandbox] = spec.containers.as_slice() else {
        return Err(rejected(
            "the sandbox container must be the pod's only container",
        ));
    };
    check_container_security(sandbox, "sandbox container", expected)?;
    let bootstrap = spec
        .init_containers
        .as_deref()
        .unwrap_or_default()
        .iter()
        .find(|container| container.name == SANDBOX_BOOTSTRAP_CONTAINER_NAME)
        .ok_or_else(|| rejected("trusted bootstrap init container missing"))?;
    check_container_security(bootstrap, "bootstrap init container", expected)?;
    if mounts_volume(sandbox, SANDBOX_BOOTSTRAP_VOLUME_NAME)
        || !mounts_volume(bootstrap, SANDBOX_BOOTSTRAP_VOLUME_NAME)
    {
        return Err(rejected(
            "bootstrap Secret must be mounted only by the trusted init container",
        ));
    }
    let secret_matches = spec
        .volumes
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|volume| {
            volume.name == SANDBOX_BOOTSTRAP_VOLUME_NAME
                && volume
                    .secret
                    .as_ref()
                    .and_then(|secret| secret.secret_name.as_deref())
                    == Some(expected.bootstrap_secret_name)
        });
    if !secret_matches {
        return Err(rejected("generation-specific sandbox Secret changed"));
    }
    Ok(())
}

/// The container must run as the sandbox's numeric identity, forbid privilege escalation, and
/// drop every capability while adding none.
fn check_container_security(
    container: &Container,
    name: &str,
    expected: &AdmissionExpectation<'_>,
) -> Result<(), DriverError> {
    let context = container
        .security_context
        .as_ref()
        .ok_or_else(|| rejected(&format!("{name} has no security context")))?;
    let drops_all = context
        .capabilities
        .as_ref()
        .and_then(|capabilities| capabilities.drop.as_deref())
        .is_some_and(|drops| drops.iter().any(|capability| capability == "ALL"));
    let adds_none = context
        .capabilities
        .as_ref()
        .and_then(|capabilities| capabilities.add.as_deref())
        .is_none_or(<[String]>::is_empty);
    if context.run_as_user != Some(i64::from(expected.uid))
        || context.run_as_group != Some(i64::from(expected.gid))
        || context.run_as_non_root != Some(true)
        || context.allow_privilege_escalation != Some(false)
        || !drops_all
        || !adds_none
    {
        return Err(rejected(&format!("{name} security context changed")));
    }
    Ok(())
}

/// Reports whether `container` mounts the volume named `volume`.
fn mounts_volume(container: &Container, volume: &str) -> bool {
    container
        .volume_mounts
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|mount| mount.name == volume)
}

/// Checks a sandbox create request before anything is created, and returns the validated
/// `PodTemplate` that the request names.
///
/// The driver-config admission check runs first, then the sandbox name, then the template
/// reference. The `PodTemplate` is read from `config.namespace`.
///
/// # Errors
///
/// Returns `Precondition` when driver config is not allowed or the `PodTemplate` is absent,
/// `InvalidArgument` when the name, the template reference, or a `DESIGN.md` section 6 rule is
/// broken, or when the `PodTemplate` has no template. The API error is returned when the
/// template cannot be read.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:1705-1742`, with the
/// template lookup in place of upstream's workspace and GPU checks.
pub async fn validate_sandbox_create(
    client: &kube::Client,
    config: &Config,
    sandbox: &DriverSandbox,
) -> Result<ValidatedTemplate, DriverError> {
    openshell_core::resource_admission::check_sandbox_driver_config(
        config.admission.allow_driver_config,
        sandbox,
    )
    .map_err(|status| DriverError::Precondition(status.message().to_owned()))?;
    validate_sandbox_name(&sandbox.name)?;
    let reference = template_ref(sandbox)?;
    let templates: Api<PodTemplate> = Api::namespaced(client.clone(), &config.namespace);
    let template = templates
        .get_opt(&reference.name)
        .await
        .map_err(DriverError::from_kube)?
        .ok_or_else(|| {
            DriverError::Precondition(format!(
                "PodTemplate {} not found in namespace {}",
                reference.name, config.namespace
            ))
        })?;
    let spec = template.template.ok_or_else(|| {
        DriverError::InvalidArgument(format!("PodTemplate {} has no template", reference.name))
    })?;
    validate(&spec, &reference.image).map_err(DriverError::from)
}

/// Creates the sandbox named by `sandbox` from its `PodTemplate`, and returns its runtime
/// identity.
///
/// The sequence is upstream's dedicated-supervisor create. The record is a built-in
/// `coordination.k8s.io/v1` Lease (see the `registry` module), in place of upstream's agent-sandbox
/// `Sandbox` resource, so the driver needs no agent-sandbox CRD. The namespace fences exist before
/// the record. Every object after the record is owned by it, and a failure or a cancellation of
/// this future after the record deletes it. The workload and supervisor pods stay gated until both
/// bootstrap Secrets exist and the boundary is provisioned.
///
/// # Errors
///
/// Returns the first failure. When the record was created, a failed deletion of it is logged and
/// does not replace that failure.
///
/// Adapted from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:1955-2202` (the create
/// call) and `driver.rs:2475-2825` (the companions).
pub async fn create_sandbox(
    client: &kube::Client,
    config: &Config,
    sandbox: &DriverSandbox,
) -> Result<String, DriverError> {
    let template = validate_sandbox_create(client, config, sandbox).await?;
    let encoded = sandbox
        .spec
        .as_ref()
        .map_or(&[][..], |spec| spec.launch_authentication.as_slice());
    let authentication = decode_launch_authentication(encoded)?;
    let generation = authentication.supervisor.runtime_generation.to_string();
    let names = SandboxRuntimeNames::for_generation(&sandbox.id, &generation);
    let main_process = main_process_spec(&template, sandbox.spec.as_ref())?;
    create_sandbox_fences(client, &config.namespace, &names, config.boundary_port).await?;
    let record = create_record(client, config, sandbox).await?;
    let mut guard = RecordGuard::armed(client, &record);
    let run = RuntimeCreate {
        client,
        config,
        sandbox,
        template: &template,
        names: &names,
        main_process: &main_process,
        launch: Launch::Create,
    };
    let outcome = create_runtime(&run, &record, authentication).await;
    match outcome {
        Ok(identity) => {
            guard.disarm();
            Ok(identity)
        }
        Err(error) => {
            rollback_record(client, &record).await;
            guard.disarm();
            Err(error)
        }
    }
}

/// Recreates the runtime of the sandbox whose record is `record`, for the generation
/// `generation_id`, and returns the runtime identity of the new supervisor pod.
///
/// The stored start-inputs Secret supplies the request, and `launch_authentication` the fresh
/// credentials. Every check runs before anything changes: the record must not be deleting,
/// `expected_runtime_identity` must name this namespace and the record's UID, `generation_id` must
/// match the runtime generation of `launch_authentication`, and the sandbox's `PodTemplate` must
/// still validate. The runtime that remains is then stopped, which keeps the record and the
/// start-inputs Secret. The fences, boundary Service, pods and bootstrap Secrets are created as a
/// create creates them. A failure never deletes the record, since the record predates this call.
///
/// # Errors
///
/// Returns `Precondition` for a deleting record, a foreign identity, an invalid launch
/// authentication, a start-inputs Secret that the record does not control or that holds another
/// sandbox, or a `PodTemplate` that is gone, `InvalidArgument` when `generation_id` does not match
/// the launch authentication, `NotFound` when the start-inputs Secret is absent, and the first
/// failure of the runtime steps otherwise.
///
/// Adapted from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:3176-3330`, with the
/// record in place of the `Sandbox` resource.
pub async fn start_sandbox(
    client: &kube::Client,
    config: &Config,
    record: &Lease,
    generation_id: &str,
    launch_authentication: &[u8],
    expected_runtime_identity: &str,
) -> Result<String, DriverError> {
    if record.metadata.deletion_timestamp.is_some() {
        return Err(DriverError::Precondition(
            "sandbox is being deleted".to_owned(),
        ));
    }
    let record_uid = record
        .metadata
        .uid
        .as_deref()
        .ok_or_else(|| DriverError::Message("sandbox record has no UID".to_owned()))?;
    check_expected_identity(&config.namespace, record_uid, expected_runtime_identity)?;
    let authentication = decode_launch_authentication(launch_authentication)?;
    if authentication.supervisor.runtime_generation.as_str() != generation_id {
        return Err(DriverError::InvalidArgument(
            "generation_id does not match the launch authentication's runtime generation"
                .to_owned(),
        ));
    }
    let sandbox_id = record_sandbox_id(record)
        .ok_or_else(|| DriverError::Message("sandbox record has no sandbox ID".to_owned()))?;
    let sandbox = read_start_inputs(client, &config.namespace, record_uid, sandbox_id).await?;
    let template = validate_sandbox_create(client, config, &sandbox).await?;
    let names = SandboxRuntimeNames::for_generation(&sandbox.id, generation_id);
    let main_process = main_process_spec(&template, sandbox.spec.as_ref())?;
    stop_runtime(client, record).await?;
    create_sandbox_fences(client, &config.namespace, &names, config.boundary_port).await?;
    let run = RuntimeCreate {
        client,
        config,
        sandbox: &sandbox,
        template: &template,
        names: &names,
        main_process: &main_process,
        launch: Launch::Start,
    };
    create_runtime(&run, record, authentication).await
}

/// Checks that `expected` names the runtime of the record `record_uid` in `namespace`: the
/// identity of that record with a supervisor pod UID after it.
///
/// # Errors
///
/// Returns `Precondition` when `expected` names another namespace or record, or no pod.
fn check_expected_identity(
    namespace: &str,
    record_uid: &str,
    expected: &str,
) -> Result<(), DriverError> {
    // The identity with an empty pod UID is the prefix that every identity of this record shares.
    let prefix = runtime_identity(namespace, record_uid, "");
    if expected
        .strip_prefix(&prefix)
        .is_some_and(|pod| !pod.is_empty())
    {
        return Ok(());
    }
    Err(DriverError::Precondition(
        "expected runtime identity does not name this sandbox's runtime".to_owned(),
    ))
}

/// Deletes the record of a create whose future is dropped before it returns, such as a cancelled
/// gRPC call. The guard is armed as soon as `create_record` returns the record, and stays armed
/// until the create returns.
///
/// Dropping an armed guard spawns the rollback on the current Tokio runtime and does not wait for
/// it, so the drop never blocks the caller. Without a runtime the record cannot be deleted here,
/// and the failure is logged.
struct RecordGuard {
    client: kube::Client,
    record: Option<Lease>,
}

impl RecordGuard {
    fn armed(client: &kube::Client, record: &Lease) -> Self {
        Self {
            client: client.clone(),
            record: Some(record.clone()),
        }
    }

    /// Releases the record, because the create has returned and handled it.
    fn disarm(&mut self) {
        self.record = None;
    }
}

impl Drop for RecordGuard {
    fn drop(&mut self) {
        let Some(record) = self.record.take() else {
            return;
        };
        let client = self.client.clone();
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move { rollback_record(&client, &record).await });
            }
            Err(error) => {
                let name = record.metadata.name.as_deref().unwrap_or_default();
                tracing::warn!(record = name, error = %error, "no runtime to delete the record of a cancelled sandbox create");
            }
        }
    }
}

/// How a runtime is made. A create posts the start-inputs Secret that a later Start reads, and a
/// Start finds that Secret already stored.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Launch {
    Create,
    Start,
}

/// The values the steps after the record read, all fixed before the runtime is created.
struct RuntimeCreate<'a> {
    client: &'a kube::Client,
    config: &'a Config,
    sandbox: &'a DriverSandbox,
    template: &'a ValidatedTemplate,
    names: &'a SandboxRuntimeNames,
    main_process: &'a str,
    launch: Launch,
}

/// The Kubernetes identities of one sandbox runtime, observed once its objects exist.
struct ObservedRuntime {
    namespace_uid: String,
    service_ip: IpAddr,
    supervisor_uid: String,
    workload_uid: String,
    fence_uid: String,
    fence_version: String,
}

/// Creates the objects of a runtime under the record, and returns the runtime identity.
///
/// The order is the boundary Service, the supervisor pod, the workload pod (checked as admitted),
/// the workload fence's identity, the boundary provisioning, the bootstrap Secrets, the
/// start-inputs Secret (a create only), and then the gate releases: supervisor first, workload
/// second.
async fn create_runtime(
    run: &RuntimeCreate<'_>,
    record: &Lease,
    authentication: SandboxLaunchAuthentication,
) -> Result<String, DriverError> {
    let owner = record_owner_reference(record)?;
    let namespace = run.config.namespace.as_str();
    let auth_bundle = serde_json::to_vec(&authentication.supervisor)
        .map_err(|error| DriverError::Message(format!("encode supervisor auth bundle: {error}")))?;
    let namespace_uid = read_namespace_uid(run.client, namespace).await?;
    let service_ip = create_boundary_service(run, &owner).await?;
    let supervisor_uid = create_supervisor_pod(run, &owner).await?;
    let workload_uid = create_workload_pod(run, &owner).await?;
    let (fence_uid, fence_version) =
        read_workload_fence(run.client, namespace, &run.names.workload_policy).await?;
    let observed = ObservedRuntime {
        namespace_uid,
        service_ip,
        supervisor_uid,
        workload_uid,
        fence_uid,
        fence_version,
    };
    let tls = generate_sandbox_tls_material(authentication.supervisor.session_id)
        .map_err(|error| DriverError::Message(error.to_string()))?;
    let provisioned = provision_boundary(run, authentication, &observed, &owner.uid, &tls)?;
    let descriptor = provisioned
        .runtime_descriptor
        .backend_descriptor()
        .map_err(|error| DriverError::Message(error.to_string()))?;
    let boundary_config = provisioned
        .boundary_config
        .encode()
        .map_err(|error| DriverError::Message(error.to_string()))?;
    let proxy_ca = generate_proxy_ca_material()?;

    let sandbox_secret = sandbox_bootstrap_secret(
        namespace,
        run.names,
        &run.sandbox.id,
        boundary_config,
        tls.certificate_chain_pem.into_bytes(),
        tls.private_key_pem.into_bytes(),
        owner.clone(),
    );
    let supervisor_secret = supervisor_bootstrap_secret(
        namespace,
        run.names,
        &run.sandbox.id,
        SupervisorSecretData {
            backend_descriptor: descriptor.payload,
            auth_bundle,
            proxy_ca_certificate: proxy_ca.certificate_pem.into_bytes(),
            proxy_ca_private_key: proxy_ca.private_key_pem.into_bytes(),
        },
        owner.clone(),
    );
    let secrets: Api<Secret> = Api::namespaced(run.client.clone(), namespace);
    secrets
        .create(&PostParams::default(), &sandbox_secret)
        .await
        .map_err(DriverError::from_kube)?;
    secrets
        .create(&PostParams::default(), &supervisor_secret)
        .await
        .map_err(DriverError::from_kube)?;
    if run.launch == Launch::Create {
        let start_secret = start_inputs_secret(namespace, run.sandbox, owner.clone());
        secrets
            .create(&PostParams::default(), &start_secret)
            .await
            .map_err(DriverError::from_kube)?;
    }

    let pods: Api<Pod> = Api::namespaced(run.client.clone(), namespace);
    release_scheduling_gate(&pods, &run.names.supervisor_pod).await?;
    release_scheduling_gate(&pods, &run.sandbox.name).await?;
    Ok(runtime_identity(
        namespace,
        &owner.uid,
        &observed.supervisor_uid,
    ))
}

/// Returns the name of the start-inputs Secret of sandbox `sandbox_id`.
fn start_inputs_name(sandbox_id: &str) -> String {
    format!("os-start-{}", sandbox_id.to_ascii_lowercase())
}

/// Reads the start-inputs Secret of sandbox `sandbox_id` in `namespace`, and decodes the
/// `DriverSandbox` it holds. The Secret must be controlled by the record of UID `record_uid`, and
/// the `DriverSandbox` must name `sandbox_id`.
///
/// # Errors
///
/// Returns `NotFound` when the Secret is absent, `Precondition` when the record does not control
/// the Secret or the Secret holds another sandbox, and `Message` when it holds no request that
/// decodes.
async fn read_start_inputs(
    client: &kube::Client,
    namespace: &str,
    record_uid: &str,
    sandbox_id: &str,
) -> Result<DriverSandbox, DriverError> {
    let name = start_inputs_name(sandbox_id);
    let secret = Api::<Secret>::namespaced(client.clone(), namespace)
        .get(&name)
        .await
        .map_err(DriverError::from_kube)?;
    if !controlled_by(&secret.metadata, record_uid) {
        return Err(DriverError::Precondition(format!(
            "start-inputs Secret {name} is not controlled by the sandbox record"
        )));
    }
    let encoded = secret
        .data
        .and_then(|mut data| data.remove(START_INPUTS_KEY))
        .ok_or_else(|| {
            DriverError::Message(format!(
                "start-inputs Secret {name} has no {START_INPUTS_KEY} data"
            ))
        })?;
    let sandbox = DriverSandbox::decode(encoded.0.as_slice())
        .map_err(|error| DriverError::Message(format!("decode start inputs {name}: {error}")))?;
    if sandbox.id != sandbox_id {
        return Err(DriverError::Precondition(format!(
            "start-inputs Secret {name} holds sandbox {}, not {sandbox_id}",
            sandbox.id
        )));
    }
    Ok(sandbox)
}

/// Renders the start-inputs Secret: the create request's `DriverSandbox`, protobuf-encoded, with
/// its sandbox token, launch authentication and status cleared, for a later Start to recreate the
/// pods from. Immutable, `Opaque`, and controlled by the Lease.
fn start_inputs_secret(namespace: &str, sandbox: &DriverSandbox, owner: OwnerReference) -> Secret {
    let mut start = sandbox.clone();
    if let Some(spec) = start.spec.as_mut() {
        spec.sandbox_token.clear();
        spec.launch_authentication.clear();
    }
    start.status = None;
    Secret {
        metadata: ObjectMeta {
            name: Some(start_inputs_name(&sandbox.id)),
            namespace: Some(namespace.to_owned()),
            owner_references: Some(vec![owner]),
            labels: Some(BTreeMap::from([
                (
                    LABEL_MANAGED_BY.to_owned(),
                    LABEL_MANAGED_BY_VALUE.to_owned(),
                ),
                (LABEL_SANDBOX_ID.to_owned(), sandbox.id.clone()),
                (
                    COMPONENT_LABEL.to_owned(),
                    START_INPUTS_COMPONENT.to_owned(),
                ),
            ])),
            ..Default::default()
        },
        data: Some(BTreeMap::from([(
            START_INPUTS_KEY.to_owned(),
            ByteString(start.encode_to_vec()),
        )])),
        immutable: Some(true),
        type_: Some("Opaque".to_owned()),
        ..Default::default()
    }
}

/// Creates the two namespace fences, or validates the ones that exist.
async fn create_sandbox_fences(
    client: &kube::Client,
    namespace: &str,
    names: &SandboxRuntimeNames,
    boundary_port: u16,
) -> Result<(), DriverError> {
    let policies: Api<NetworkPolicy> = Api::namespaced(client.clone(), namespace);
    for policy in sandbox_fences(namespace, names, boundary_port) {
        create_or_validate_fence(&policies, &policy).await?;
    }
    Ok(())
}

/// Renders the two namespace fences of a sandbox runtime, labeled as the driver creates them.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:2204-2224`.
fn sandbox_fences(
    namespace: &str,
    names: &SandboxRuntimeNames,
    boundary_port: u16,
) -> [NetworkPolicy; 2] {
    let fence = workload_fence(namespace, names, boundary_port);
    [
        labeled_fence(fence.workload_policy, WORKLOAD_FENCE_COMPONENT),
        labeled_fence(fence.supervisor_policy, SUPERVISOR_FENCE_COMPONENT),
    ]
}

/// Adds the managed-by and component labels to a fence policy.
fn labeled_fence(mut policy: NetworkPolicy, component: &str) -> NetworkPolicy {
    let labels = policy.metadata.labels.get_or_insert_default();
    labels.insert(
        LABEL_MANAGED_BY.to_owned(),
        LABEL_MANAGED_BY_VALUE.to_owned(),
    );
    labels.insert(COMPONENT_LABEL.to_owned(), component.to_owned());
    policy
}

/// Creates `expected`, or validates the existing fence of that name against it.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:7068-7109`.
async fn create_or_validate_fence(
    policies: &Api<NetworkPolicy>,
    expected: &NetworkPolicy,
) -> Result<(), DriverError> {
    let name = expected.metadata.name.as_deref().unwrap_or_default();
    let existing = timeout(KUBE_API_TIMEOUT, policies.get_opt(name))
        .await
        .map_err(|_| {
            DriverError::Message("timed out reading sandbox-runtime workload fence".to_owned())
        })?
        .map_err(DriverError::from_kube)?;
    if let Some(existing) = existing {
        return validate_fence(&existing, expected);
    }
    match timeout(
        KUBE_API_TIMEOUT,
        policies.create(&PostParams::default(), expected),
    )
    .await
    {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(kube::Error::Api(response))) if response.code == 409 => {
            let existing = timeout(KUBE_API_TIMEOUT, policies.get(name))
                .await
                .map_err(|_| {
                    DriverError::Message(
                        "timed out validating existing sandbox-runtime workload fence".to_owned(),
                    )
                })?
                .map_err(DriverError::from_kube)?;
            validate_fence(&existing, expected)
        }
        Ok(Err(error)) => Err(DriverError::from_kube(error)),
        Err(_) => Err(DriverError::Message(
            "timed out creating sandbox-runtime workload fence".to_owned(),
        )),
    }
}

/// Accepts `existing` when it enforces what `expected` enforces.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:7111-7123`.
fn validate_fence(existing: &NetworkPolicy, expected: &NetworkPolicy) -> Result<(), DriverError> {
    if fence_matches(existing, expected) {
        return Ok(());
    }
    let name = expected.metadata.name.as_deref().unwrap_or_default();
    Err(DriverError::Precondition(format!(
        "sandbox-runtime workload fence {name} exists but does not match the intended enforcement"
    )))
}

/// Reports whether `existing` has the spec of `expected`, and carries its required labels and
/// annotations.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:7125-7160`.
fn fence_matches(existing: &NetworkPolicy, expected: &NetworkPolicy) -> bool {
    fn normalized_spec(mut spec: Option<NetworkPolicySpec>) -> Option<NetworkPolicySpec> {
        if let Some(spec) = spec.as_mut() {
            // The Kubernetes API server omits explicitly empty rule arrays when it
            // persists a NetworkPolicy. For a policy type named in `policyTypes`,
            // an omitted rule array and an empty rule array both deny all traffic.
            if spec.egress.as_ref().is_some_and(Vec::is_empty) {
                spec.egress = None;
            }
            if spec.ingress.as_ref().is_some_and(Vec::is_empty) {
                spec.ingress = None;
            }
        }
        spec
    }

    fn contains_required_metadata(
        actual: &Option<BTreeMap<String, String>>,
        required: &Option<BTreeMap<String, String>>,
    ) -> bool {
        required.as_ref().is_none_or(|required| {
            actual.as_ref().is_some_and(|actual| {
                required
                    .iter()
                    .all(|(key, value)| actual.get(key) == Some(value))
            })
        })
    }

    normalized_spec(existing.spec.clone()) == normalized_spec(expected.spec.clone())
        && contains_required_metadata(&existing.metadata.labels, &expected.metadata.labels)
        && contains_required_metadata(
            &existing.metadata.annotations,
            &expected.metadata.annotations,
        )
}

/// Creates the sandbox's Lease record, the owner of every per-sandbox object.
///
/// The POST runs on a task of its own, so dropping this future does not cancel it. The caller arms
/// its [`RecordGuard`] only after this returns, so a future dropped while the POST is in flight
/// leaves the admitted record to the task: the task deletes it, because nothing took it.
///
/// # Errors
///
/// Returns `AlreadyExists` when a record of the sandbox's name exists.
async fn create_record(
    client: &kube::Client,
    config: &Config,
    sandbox: &DriverSandbox,
) -> Result<Lease, DriverError> {
    let record = sandbox_record(&config.namespace, &config.gateway_id, sandbox);
    let (posted_sender, posted_receiver) = oneshot::channel();
    let (taken_sender, taken_receiver) = oneshot::channel();
    let task_client = client.clone();
    let namespace = config.namespace.clone();
    tokio::spawn(async move {
        let posted = Api::<Lease>::namespaced(task_client.clone(), &namespace)
            .create(&PostParams::default(), &record)
            .await
            .map_err(DriverError::from_kube);
        match posted {
            Ok(admitted) => {
                // The receiver is gone when the caller was dropped, and then `taken_sender` is
                // dropped too, so the task deletes the admitted record.
                let _ = posted_sender.send(Ok(admitted.clone()));
                if taken_receiver.await.is_err() {
                    rollback_record(&task_client, &admitted).await;
                }
            }
            Err(error) => {
                let _ = posted_sender.send(Err(error));
            }
        }
    });
    let admitted = posted_receiver.await.map_err(|_| {
        DriverError::Message("the sandbox record create ended without a result".to_owned())
    })??;
    if taken_sender.send(()).is_err() {
        rollback_record(client, &admitted).await;
        return Err(DriverError::Message(
            "the sandbox record create ended before the record was taken".to_owned(),
        ));
    }
    Ok(admitted)
}

/// Deletes the record of a failed create. A failed deletion is logged, and the create's own
/// error is what the caller returns.
async fn rollback_record(client: &kube::Client, record: &Lease) {
    if let Err(error) = delete_record(client, record).await {
        let name = record.metadata.name.as_deref().unwrap_or_default();
        tracing::warn!(record = name, error = %error, "failed to delete the record of a failed sandbox create");
    }
}

/// Reads the UID of the sandbox namespace.
async fn read_namespace_uid(client: &kube::Client, namespace: &str) -> Result<String, DriverError> {
    Api::<Namespace>::all(client.clone())
        .get(namespace)
        .await
        .map_err(DriverError::from_kube)?
        .metadata
        .uid
        .ok_or_else(|| DriverError::Message("sandbox namespace has no UID".to_owned()))
}

/// Creates the boundary Service, which selects the workload pod, and returns its `ClusterIP`.
async fn create_boundary_service(
    run: &RuntimeCreate<'_>,
    owner: &OwnerReference,
) -> Result<IpAddr, DriverError> {
    let namespace = run.config.namespace.as_str();
    let service = boundary_service(
        namespace,
        run.names,
        &run.sandbox.id,
        run.config.boundary_port,
        owner.clone(),
    );
    let services: Api<Service> = Api::namespaced(run.client.clone(), namespace);
    let created = services
        .create(&PostParams::default(), &service)
        .await
        .map_err(DriverError::from_kube)?;
    cluster_ip(&created)
}

/// Creates the gated supervisor pod, and returns its UID.
async fn create_supervisor_pod(
    run: &RuntimeCreate<'_>,
    owner: &OwnerReference,
) -> Result<String, DriverError> {
    let config = run.config;
    let log_level = sandbox_log_level(run.sandbox, "info");
    let client_tls = config
        .client_tls_secret_name
        .as_deref()
        .map_or(SupervisorClientTls::Disabled, SupervisorClientTls::Secret);
    let pod = supervisor_pod(&SupervisorPodParams {
        namespace: &config.namespace,
        names: run.names,
        sandbox_id: &run.sandbox.id,
        sandbox_name: &run.sandbox.name,
        gateway_id: &config.gateway_id,
        image: &config.supervisor_image,
        image_pull_policy: config.supervisor_image_pull_policy,
        service_account_name: &config.service_account_name,
        uid: config.sandbox_uid,
        gid: config.sandbox_gid,
        grpc_endpoint: &config.grpc_endpoint,
        client_tls,
        main_process_spec: run.main_process,
        log_level: &log_level,
        sa_token_ttl_secs: config.sa_token_ttl_secs,
        owner: owner.clone(),
    });
    let pods: Api<Pod> = Api::namespaced(run.client.clone(), &config.namespace);
    let created = pods
        .create(&PostParams::default(), &pod)
        .await
        .map_err(DriverError::from_kube)?;
    created
        .metadata
        .uid
        .ok_or_else(|| DriverError::Message("supervisor Pod has no UID".to_owned()))
}

/// Creates the gated workload pod from the template, checks the admitted object before any gate
/// is released, and returns the pod's UID.
///
/// The pod is created as a `DynamicObject` of the `Pod` resource, so that `supplementalGroupsPolicy`
/// survives the request and the reply.
async fn create_workload_pod(
    run: &RuntimeCreate<'_>,
    owner: &OwnerReference,
) -> Result<String, DriverError> {
    let config = run.config;
    let params = MutationParams {
        name: run.sandbox.name.clone(),
        namespace: config.namespace.clone(),
        pair_label: pair_label_value(&run.sandbox.id),
        bootstrap_secret_name: run.names.sandbox_secret.clone(),
        runtime_image: config.runtime_image.clone(),
        runtime_image_pull_policy: config
            .runtime_image_pull_policy
            .map(|policy| policy.as_kubernetes_str().to_owned()),
        probe_helper_image: config.probe_helper_image.clone(),
        probe_helper_image_pull_policy: config
            .probe_helper_image_pull_policy
            .map(|policy| policy.as_kubernetes_str().to_owned()),
        boundary_port: config.boundary_port,
        uid: config.sandbox_uid,
        gid: config.sandbox_gid,
    };
    let pod = mutate(run.template, &params);
    let object = workload_pod_object(&pod, owner.clone())?;
    let typed: DynamicObject = serde_json::from_value(object).map_err(serialization_error)?;
    let resource = ApiResource::erase::<Pod>(&());
    let pods: Api<DynamicObject> =
        Api::namespaced_with(run.client.clone(), &config.namespace, &resource);
    let created = pods
        .create(&PostParams::default(), &typed)
        .await
        .map_err(DriverError::from_kube)?;
    let admitted = serde_json::to_value(&created).map_err(serialization_error)?;
    let expectation = AdmissionExpectation {
        record_uid: &owner.uid,
        sandbox_id: &run.sandbox.id,
        uid: config.sandbox_uid,
        gid: config.sandbox_gid,
        bootstrap_secret_name: &run.names.sandbox_secret,
    };
    let admitted_pod = verify_admitted_workload_pod(&admitted, &expectation)?;
    admitted_pod
        .metadata
        .uid
        .ok_or_else(|| DriverError::Message("workload Pod has no UID".to_owned()))
}

/// Reads the UID and resourceVersion of the namespace workload fence.
async fn read_workload_fence(
    client: &kube::Client,
    namespace: &str,
    name: &str,
) -> Result<(String, String), DriverError> {
    let fence = Api::<NetworkPolicy>::namespaced(client.clone(), namespace)
        .get(name)
        .await
        .map_err(DriverError::from_kube)?;
    let uid = fence
        .metadata
        .uid
        .ok_or_else(|| DriverError::Message("workload NetworkPolicy has no UID".to_owned()))?;
    let version = fence.metadata.resource_version.ok_or_else(|| {
        DriverError::Message("workload NetworkPolicy has no resourceVersion".to_owned())
    })?;
    Ok((uid, version))
}

/// Provisions the boundary from the observed runtime and the generation's launch authentication.
///
/// The record UID is the sandbox resource UID that the workload identity binds.
///
/// Adapted from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:2686-2760`.
fn provision_boundary(
    run: &RuntimeCreate<'_>,
    authentication: SandboxLaunchAuthentication,
    observed: &ObservedRuntime,
    record_uid: &str,
    tls: &SandboxTlsMaterial,
) -> Result<KubernetesSandboxRuntimeBoundaryProvisioning, DriverError> {
    let config = run.config;
    let port = config.boundary_port;
    let workload_identity = ResolvedWorkloadIdentity::new(
        config.sandbox_uid,
        config.sandbox_gid,
        Vec::new(),
        WORKLOAD_IDENTITY_SOURCE.to_owned(),
        format!("sandbox:{record_uid}"),
    )
    .map_err(|error| DriverError::Message(error.to_string()))?;
    let verification_keys = gateway_verification_keys(&authentication.verification_keys)?;
    KubernetesSandboxRuntimeBoundarySpec {
        boundary_id: run.sandbox.id.clone(),
        generation: authentication.supervisor.runtime_generation.to_string(),
        session_id: authentication.supervisor.session_id,
        session_rotation: authentication.supervisor.session_rotation,
        auth_epoch: authentication.supervisor.auth_epoch,
        gateway_id: authentication.gateway_id,
        verification_keys,
        namespace_uid: observed.namespace_uid.clone(),
        sandbox_resource_uid: record_uid.to_owned(),
        workload_pod_uid: observed.workload_uid.clone(),
        workload_pod_uid_path: PathBuf::from(SANDBOX_POD_UID_PATH),
        supervisor_pod_uid: observed.supervisor_uid.clone(),
        egress_policy_uid: observed.fence_uid.clone(),
        egress_policy_resource_version: observed.fence_version.clone(),
        boundary_listener: boundary_listener(observed.service_ip, port),
        control_authority: boundary_service_authority(&config.namespace, run.names, port),
        control_address: SocketAddr::new(observed.service_ip, port),
        sandbox_tls: SandboxTlsServerConfig {
            certificate_chain_path: PathBuf::from(BOUNDARY_CERTIFICATE_PATH),
            private_key_path: PathBuf::from(BOUNDARY_PRIVATE_KEY_PATH),
        },
        supervisor_tls: SandboxTlsClientConfig {
            server_name: tls.server_name.clone(),
            trust_anchor_pem: tls.trust_anchor_pem.clone(),
        },
        host_gateway_ip: config.host_gateway_ip,
        workload_identity,
        child_env: child_env(run.sandbox),
    }
    .provision()
    .map_err(|error| DriverError::Message(error.to_string()))
}

/// Removes the bootstrap scheduling gate from a pod, which lets the scheduler place it.
async fn release_scheduling_gate(pods: &Api<Pod>, name: &str) -> Result<(), DriverError> {
    let release = json!({"spec": {"schedulingGates": []}});
    pods.patch(name, &PatchParams::default(), &Patch::Merge(&release))
        .await
        .map(|_| ())
        .map_err(DriverError::from_kube)
}

/// Returns the `ClusterIP` of a boundary Service, which the boundary connects to.
///
/// # Errors
///
/// Returns `Message` when the Service has no `ClusterIP` or the address does not parse.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:2527-2540`.
fn cluster_ip(service: &Service) -> Result<IpAddr, DriverError> {
    service
        .spec
        .as_ref()
        .and_then(|spec| spec.cluster_ip.as_deref())
        .filter(|ip| *ip != "None")
        .ok_or_else(|| DriverError::Message("boundary Service has no ClusterIP".to_owned()))?
        .parse::<IpAddr>()
        .map_err(|error| {
            DriverError::Message(format!("invalid boundary Service ClusterIP: {error}"))
        })
}

/// Returns the address the boundary listens on: the unspecified address of the Service's family.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:2706-2717`.
fn boundary_listener(service_ip: IpAddr, port: u16) -> SocketAddr {
    let unspecified = match service_ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    };
    SocketAddr::new(unspecified, port)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use clap::Parser;
    use k8s_openapi::api::core::v1::{PodTemplateSpec, ServiceSpec};
    use k8s_openapi::api::networking::v1::NetworkPolicyEgressRule;
    use openshell_core::proto::compute::v1::{DriverSandboxStatus, DriverSandboxTemplate};
    use openshell_sandbox_backend::boundary_protocol::BoundaryListener;
    use prost_types::Struct;
    use tokio::sync::{Notify, mpsc};

    use super::*;
    use crate::config::Args;

    const SANDBOX_ID: &str = "sandbox-1";
    const RECORD_UID: &str = "record-uid";
    const SECRET_NAME: &str = "sandbox-1-bootstrap";
    const SANDBOX_IMAGE: &str = "registry.example.com/agents/sandbox:1";
    const TEMPLATE_INVALID: &str =
        "driver_config.podtemplate.template must be a non-empty DNS-1123 subdomain";

    fn string_value(text: &str) -> prost_types::Value {
        prost_types::Value {
            kind: Some(Kind::StringValue(text.to_owned())),
        }
    }

    fn driver_config(fields: &[(&str, prost_types::Value)]) -> Struct {
        Struct {
            fields: fields
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect(),
        }
    }

    fn sandbox_named(name: &str) -> DriverSandbox {
        sandbox_with_template(Some(driver_config(&[(
            TEMPLATE_NAME_FIELD,
            string_value(name),
        )])))
    }

    fn sandbox_with_template(driver_config: Option<Struct>) -> DriverSandbox {
        DriverSandbox {
            spec: Some(DriverSandboxSpec {
                template: Some(DriverSandboxTemplate {
                    image: SANDBOX_IMAGE.to_owned(),
                    driver_config,
                    ..DriverSandboxTemplate::default()
                }),
                ..DriverSandboxSpec::default()
            }),
            ..DriverSandbox::default()
        }
    }

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    }

    fn precondition_message<T: std::fmt::Debug>(result: Result<T, DriverError>) -> String {
        match result {
            Err(DriverError::Precondition(message)) => message,
            other => panic!("expected a precondition failure, got {other:?}"),
        }
    }

    fn assert_invalid_argument<T: std::fmt::Debug>(result: Result<T, DriverError>, message: &str) {
        match result {
            Err(DriverError::InvalidArgument(actual)) => assert_eq!(actual, message),
            other => panic!("expected an InvalidArgument failure, got {other:?}"),
        }
    }

    #[test]
    fn create_template_ref_reads_name_and_image() {
        let sandbox = sandbox_named("agent.v1");
        assert_eq!(
            template_ref(&sandbox).expect("valid reference"),
            TemplateRef {
                name: "agent.v1".to_owned(),
                image: SANDBOX_IMAGE.to_owned(),
            }
        );
    }

    #[test]
    fn create_template_ref_rejects_missing_spec_template() {
        assert_invalid_argument(
            template_ref(&DriverSandbox::default()),
            "driver_config.podtemplate.template is required",
        );
        let sandbox = DriverSandbox {
            spec: Some(DriverSandboxSpec::default()),
            ..DriverSandbox::default()
        };
        assert_invalid_argument(
            template_ref(&sandbox),
            "driver_config.podtemplate.template is required",
        );
    }

    #[test]
    fn create_template_ref_rejects_missing_or_non_string_name() {
        let number = prost_types::Value {
            kind: Some(Kind::NumberValue(1.0)),
        };
        let configs = [
            None,
            Some(driver_config(&[])),
            Some(driver_config(&[(TEMPLATE_NAME_FIELD, number)])),
        ];
        for config in configs {
            assert_invalid_argument(
                template_ref(&sandbox_with_template(config)),
                TEMPLATE_INVALID,
            );
        }
    }

    #[test]
    fn create_template_ref_rejects_names_that_are_not_dns_subdomains() {
        let too_long = vec!["a".repeat(63); 4].join(".");
        let names = [
            "",
            "Upper",
            "a..b",
            "-leading",
            "trailing-.x",
            too_long.as_str(),
        ];
        for name in names {
            assert_invalid_argument(template_ref(&sandbox_named(name)), TEMPLATE_INVALID);
        }
    }

    #[test]
    fn create_validate_sandbox_name_accepts_dns_labels() {
        for name in ["my-sandbox", "a", "123abc"] {
            validate_sandbox_name(name).expect("valid DNS-1123 label");
        }
    }

    #[test]
    fn create_validate_sandbox_name_rejects_other_names() {
        let too_long = "a".repeat(64);
        let names = [
            "",
            "My_sandbox",
            "MySandbox",
            "dotted.name",
            "-lead",
            too_long.as_str(),
        ];
        for name in names {
            assert_invalid_argument(validate_sandbox_name(name), SANDBOX_NAME_MESSAGE);
        }
    }

    fn launch_document() -> Value {
        json!({
            "supervisor": {
                "session_id": "5f0c6c1e-3c4e-4a8e-9d6b-2f1a7b8c9d0e",
                "runtime_generation": "g0000000000000001",
                "session_rotation": 1,
                "auth_epoch": 1,
                "gateway_token": "gateway.token",
                "gateway_expires_at": 1_900_000_000,
                "sandbox_token": "sandbox.token",
                "sandbox_expires_at": 1_900_000_000
            },
            "gateway_id": "gateway-1",
            "verification_keys": [{ "key_id": "key-1", "public_key_pem": [80, 69, 77] }]
        })
    }

    #[test]
    fn create_decode_launch_authentication_accepts_valid_document() {
        let encoded = launch_document().to_string();
        let authentication =
            decode_launch_authentication(encoded.as_bytes()).expect("valid document");
        assert_eq!(authentication.gateway_id, "gateway-1");
        assert_eq!(authentication.verification_keys.len(), 1);
    }

    #[test]
    fn create_decode_launch_authentication_requires_input() {
        assert_eq!(
            precondition_message(decode_launch_authentication(b"")),
            "launch authentication is required"
        );
    }

    #[test]
    fn create_decode_launch_authentication_names_only_class_and_position() {
        let message = precondition_message(decode_launch_authentication(
            br#"{"supervisor" "SECRET-TOKEN"}"#,
        ));
        assert!(
            message.starts_with("decode launch authentication: Syntax error at line 1 column "),
            "{message}"
        );
        assert!(!message.contains("SECRET"), "{message}");
    }

    #[test]
    fn create_decode_launch_authentication_rejects_invalid_document() {
        let mut document = launch_document();
        document["verification_keys"] = json!([]);
        assert_eq!(
            precondition_message(decode_launch_authentication(
                document.to_string().as_bytes()
            )),
            "validate launch authentication: at least one verification key is required"
        );
    }

    #[test]
    fn create_gateway_verification_keys_maps_utf8_pem() {
        let keys = [SessionVerificationKey {
            key_id: "key-1".to_owned(),
            public_key_pem: b"PEM".to_vec(),
        }];
        assert_eq!(
            gateway_verification_keys(&keys).expect("UTF-8 PEM"),
            vec![GatewayVerificationKey {
                key_id: "key-1".to_owned(),
                public_key_pem: "PEM".to_owned(),
            }]
        );
    }

    #[test]
    fn create_gateway_verification_keys_rejects_non_utf8_pem() {
        let keys = [SessionVerificationKey {
            key_id: "key-1".to_owned(),
            public_key_pem: vec![0xff],
        }];
        assert!(
            precondition_message(gateway_verification_keys(&keys))
                .starts_with("sandbox verification key is not UTF-8 PEM: ")
        );
    }

    #[test]
    fn create_child_env_merges_spec_over_template_and_drops_openshell_names() {
        let sandbox = DriverSandbox {
            spec: Some(DriverSandboxSpec {
                environment: env(&[("B", "spec"), ("C", "spec"), ("OPENSHELL_Y", "2")]),
                template: Some(DriverSandboxTemplate {
                    environment: env(&[("A", "template"), ("B", "template"), ("OPENSHELL_X", "1")]),
                    ..DriverSandboxTemplate::default()
                }),
                ..DriverSandboxSpec::default()
            }),
            ..DriverSandbox::default()
        };
        assert_eq!(
            child_env(&sandbox),
            env(&[("A", "template"), ("B", "spec"), ("C", "spec")])
        );
    }

    #[test]
    fn create_child_env_is_empty_without_spec() {
        assert!(child_env(&DriverSandbox::default()).is_empty());
    }

    fn validated_template() -> ValidatedTemplate {
        let template: PodTemplateSpec = serde_json::from_value(json!({
            "spec": {
                "containers": [{
                    "name": "agent",
                    "image": SANDBOX_IMAGE,
                    "command": ["/usr/bin/agent", "--serve"],
                    "args": ["--port", "8080"]
                }]
            }
        }))
        .expect("template deserializes");
        validate(&template, SANDBOX_IMAGE).expect("template passes the rules")
    }

    const TEMPLATE_COMMAND: [&str; 4] = ["/usr/bin/agent", "--serve", "--port", "8080"];

    #[test]
    fn create_main_process_spec_carries_template_command_and_request_flags() {
        let spec = DriverSandboxSpec {
            tty: true,
            await_main_process_attachment: true,
            ..DriverSandboxSpec::default()
        };
        let encoded = main_process_spec(&validated_template(), Some(&spec)).expect("encodes");
        let config = MainProcessConfig::decode(&encoded).expect("supervisor decodes the spec");
        assert_eq!(
            config,
            MainProcessConfig {
                version: MainProcessConfig::VERSION,
                command: TEMPLATE_COMMAND
                    .iter()
                    .map(|part| (*part).to_owned())
                    .collect(),
                tty: true,
                await_main_process_attachment: true,
            }
        );
    }

    #[test]
    fn create_main_process_spec_ignores_request_command() {
        let spec = DriverSandboxSpec {
            command: vec!["/bin/evil".to_owned()],
            ..DriverSandboxSpec::default()
        };
        let encoded = main_process_spec(&validated_template(), Some(&spec)).expect("encodes");
        let config = MainProcessConfig::decode(&encoded).expect("decodes");
        assert_eq!(config.command, TEMPLATE_COMMAND);
    }

    #[test]
    fn create_main_process_spec_defaults_flags_without_spec() {
        let encoded = main_process_spec(&validated_template(), None).expect("encodes");
        let config = MainProcessConfig::decode(&encoded).expect("decodes");
        assert_eq!(config.command, TEMPLATE_COMMAND);
        assert!(!config.tty);
        assert!(!config.await_main_process_attachment);
    }

    /// The start-inputs Secret of `SANDBOX_ID` as a create writes it, holding the sandbox `holds`
    /// and carrying `owners` as its owner references.
    fn start_inputs_holding(holds: &str, owners: Option<Vec<OwnerReference>>) -> Secret {
        let mut request = start_inputs_request();
        request.id = holds.to_owned();
        let mut secret = start_inputs_secret("agents", &request, owner());
        secret.metadata.name = Some(start_inputs_name(SANDBOX_ID));
        secret.metadata.owner_references = owners;
        secret
    }

    /// A client that answers every request with `secret`.
    fn client_serving(secret: &Secret) -> kube::Client {
        let body = serde_json::to_value(secret).expect("Secret JSON");
        let api = tower::service_fn(move |_request: http::Request<kube::client::Body>| {
            let body = body.clone();
            async move { Ok::<_, kube::Error>(reply(200, &body)) }
        });
        kube::Client::new(api, "agents")
    }

    #[tokio::test]
    async fn read_start_inputs_rejects_a_secret_the_lease_does_not_control() {
        let client = client_serving(&start_inputs_holding(SANDBOX_ID, None));
        let error = read_start_inputs(&client, "agents", RECORD_UID, SANDBOX_ID)
            .await
            .expect_err("a Secret without the record as controller is rejected");
        assert!(matches!(error, DriverError::Precondition(_)));
    }

    #[tokio::test]
    async fn read_start_inputs_rejects_a_secret_another_lease_controls() {
        let other = OwnerReference {
            uid: "other-record-uid".to_owned(),
            ..owner()
        };
        let client = client_serving(&start_inputs_holding(SANDBOX_ID, Some(vec![other])));
        let error = read_start_inputs(&client, "agents", RECORD_UID, SANDBOX_ID)
            .await
            .expect_err("a Secret controlled by another Lease is rejected");
        assert!(matches!(error, DriverError::Precondition(_)));
    }

    #[tokio::test]
    async fn read_start_inputs_rejects_a_secret_holding_another_sandbox() {
        let client = client_serving(&start_inputs_holding("sandbox-2", Some(vec![owner()])));
        let error = read_start_inputs(&client, "agents", RECORD_UID, SANDBOX_ID)
            .await
            .expect_err("a Secret that holds another sandbox is rejected");
        assert!(matches!(error, DriverError::Precondition(_)));
    }

    fn owner() -> OwnerReference {
        OwnerReference {
            api_version: "coordination.k8s.io/v1".to_owned(),
            kind: "Lease".to_owned(),
            name: "sandbox-1-lease".to_owned(),
            uid: RECORD_UID.to_owned(),
            controller: Some(true),
            block_owner_deletion: Some(true),
        }
    }

    fn mutation_params() -> MutationParams {
        MutationParams {
            name: SANDBOX_ID.to_owned(),
            namespace: "agents".to_owned(),
            pair_label: pair_label_value(SANDBOX_ID),
            bootstrap_secret_name: SECRET_NAME.to_owned(),
            runtime_image: "registry.example.com/openshell/runtime:1".to_owned(),
            runtime_image_pull_policy: Some("Always".to_owned()),
            probe_helper_image: "registry.example.com/openshell/odp-probe:1".to_owned(),
            probe_helper_image_pull_policy: Some("IfNotPresent".to_owned()),
            boundary_port: 2222,
            uid: 1001,
            gid: 1002,
        }
    }

    fn mutated_pod() -> Pod {
        mutate(&validated_template(), &mutation_params())
    }

    #[test]
    fn create_workload_pod_object_sets_lease_owner_and_strict_policy() {
        let object = workload_pod_object(&mutated_pod(), owner()).expect("pod serializes");
        assert_eq!(
            object["metadata"]["ownerReferences"],
            json!([{
                "apiVersion": "coordination.k8s.io/v1",
                "kind": "Lease",
                "name": "sandbox-1-lease",
                "uid": RECORD_UID,
                "controller": true,
                "blockOwnerDeletion": true
            }])
        );
        assert_eq!(
            object["spec"]["securityContext"]["supplementalGroupsPolicy"],
            "Strict"
        );
        assert_eq!(
            object["metadata"]["labels"][BOUNDARY_ROLE_LABEL],
            WORKLOAD_ROLE
        );
    }

    #[test]
    fn create_workload_pod_object_is_typed_as_a_pod() {
        let object = workload_pod_object(&mutated_pod(), owner()).expect("pod serializes");
        assert_eq!(object["apiVersion"], "v1");
        assert_eq!(object["kind"], "Pod");
    }

    fn expectation() -> AdmissionExpectation<'static> {
        AdmissionExpectation {
            record_uid: RECORD_UID,
            sandbox_id: SANDBOX_ID,
            uid: 1001,
            gid: 1002,
            bootstrap_secret_name: SECRET_NAME,
        }
    }

    /// The admitted object: the workload pod as the create call serializes it, with the UID
    /// the API server assigns on admission.
    fn admitted() -> Value {
        let mut object = workload_pod_object(&mutated_pod(), owner()).expect("pod serializes");
        object["metadata"]["uid"] = json!("pod-uid");
        object
    }

    fn admission_reason(object: &Value) -> String {
        precondition_message(verify_admitted_workload_pod(object, &expectation()))
    }

    /// The rejection reason of the admitted object after the field at `path` becomes `value`.
    fn reason_with(path: &str, value: Value) -> String {
        let mut object = admitted();
        *object
            .pointer_mut(path)
            .expect("the admitted pod has the field") = value;
        admission_reason(&object)
    }

    fn rejection(reason: &str) -> String {
        format!("{ADMISSION_PREFIX}{reason}")
    }

    #[test]
    fn create_verify_admitted_accepts_mutated_pod() {
        let pod =
            verify_admitted_workload_pod(&admitted(), &expectation()).expect("admitted pod passes");
        let labels = pod.metadata.labels.expect("labels are kept");
        assert_eq!(
            labels.get(BOUNDARY_ROLE_LABEL).map(String::as_str),
            Some(WORKLOAD_ROLE)
        );
        assert_eq!(
            labels.get(BOUNDARY_PAIR_LABEL).map(String::as_str),
            Some(pair_label_value(SANDBOX_ID).as_str())
        );
        let spec = pod.spec.expect("spec is kept");
        let gates = spec.scheduling_gates.expect("gate is kept");
        assert_eq!(gates[0].name, SANDBOX_BOOTSTRAP_SCHEDULING_GATE);
        assert_eq!(spec.containers.len(), 1);
    }

    #[test]
    fn create_verify_admitted_accepts_pod_without_supplemental_groups_policy() {
        let mut object = admitted();
        object["spec"]["securityContext"]
            .as_object_mut()
            .expect("security context is an object")
            .remove("supplementalGroupsPolicy");
        verify_admitted_workload_pod(&object, &expectation())
            .expect("an absent policy is logged, not rejected");
    }

    #[test]
    fn create_verify_admitted_rejects_malformed_pod() {
        assert_eq!(
            reason_with("/spec/containers", json!("not a list")),
            rejection("Pod object is malformed")
        );
    }

    #[test]
    fn create_verify_admitted_rejects_missing_uid() {
        assert_eq!(
            reason_with("/metadata/uid", Value::Null),
            rejection("missing Pod UID")
        );
    }

    #[test]
    fn create_verify_admitted_rejects_owner_that_is_not_the_record_lease() {
        let changed = rejection("Lease owner UID changed");
        assert_eq!(
            reason_with("/metadata/ownerReferences/0/uid", json!("other-record")),
            changed
        );
        assert_eq!(
            reason_with("/metadata/ownerReferences/0/kind", json!("Sandbox")),
            changed
        );
        assert_eq!(
            reason_with("/metadata/ownerReferences/0/controller", json!(false)),
            changed
        );
    }

    #[test]
    fn create_verify_admitted_rejects_missing_labels() {
        assert_eq!(
            reason_with("/metadata/labels", Value::Null),
            rejection("missing labels")
        );
    }

    #[test]
    fn create_verify_admitted_rejects_changed_pair_labels() {
        let changed = rejection("pair labels changed");
        assert_eq!(
            reason_with(
                "/metadata/labels/openshell.ai~1boundary-role",
                json!("supervisor")
            ),
            changed
        );
        assert_eq!(
            reason_with(
                "/metadata/labels/openshell.ai~1boundary-pair",
                json!("other-sandbox")
            ),
            changed
        );
    }

    #[test]
    fn create_verify_admitted_rejects_missing_spec() {
        assert_eq!(
            reason_with("/spec", Value::Null),
            rejection("missing Pod spec")
        );
    }

    #[test]
    fn create_verify_admitted_rejects_host_namespace_or_service_account_token() {
        let changed = rejection("host namespaces or ServiceAccount token enabled");
        for path in [
            "/spec/hostNetwork",
            "/spec/hostPID",
            "/spec/hostIPC",
            "/spec/shareProcessNamespace",
        ] {
            assert_eq!(reason_with(path, json!(true)), changed, "{path}");
        }
        assert_eq!(
            reason_with("/spec/automountServiceAccountToken", json!(true)),
            changed
        );
    }

    #[test]
    fn create_verify_admitted_rejects_projected_service_account_token() {
        let mut object = admitted();
        object["spec"]["volumes"]
            .as_array_mut()
            .expect("volumes")
            .push(json!({
                "name": "token",
                "projected": { "sources": [{ "serviceAccountToken": { "path": "token" } }] }
            }));
        assert_eq!(
            admission_reason(&object),
            rejection("workload Pod must not receive a projected ServiceAccount token")
        );
    }

    #[test]
    fn create_verify_admitted_rejects_changed_restart_or_dns_posture() {
        let changed = rejection("restart or DNS posture changed");
        assert_eq!(reason_with("/spec/restartPolicy", json!("Always")), changed);
        assert_eq!(
            reason_with("/spec/dnsPolicy", json!("ClusterFirst")),
            changed
        );
        assert_eq!(
            reason_with("/spec/dnsConfig/nameservers/0", json!("10.0.0.10")),
            changed
        );
    }

    #[test]
    fn create_verify_admitted_rejects_missing_bootstrap_gate() {
        let missing = rejection("bootstrap scheduling gate missing");
        assert_eq!(reason_with("/spec/schedulingGates", Value::Null), missing);
        assert_eq!(
            reason_with("/spec/schedulingGates/0/name", json!("other-gate")),
            missing
        );
    }

    #[test]
    fn create_verify_admitted_rejects_changed_pod_identity() {
        let changed = rejection("numeric identity, groups, or seccomp profile changed");
        for path in [
            "/spec/securityContext/runAsUser",
            "/spec/securityContext/runAsGroup",
            "/spec/securityContext/fsGroup",
        ] {
            assert_eq!(reason_with(path, json!(0)), changed, "{path}");
        }
        assert_eq!(
            reason_with("/spec/securityContext/runAsNonRoot", json!(false)),
            changed
        );
        assert_eq!(
            reason_with("/spec/securityContext/supplementalGroups", json!([1])),
            changed
        );
        assert_eq!(
            reason_with(
                "/spec/securityContext/seccompProfile/type",
                json!("Unconfined")
            ),
            changed
        );
    }

    #[test]
    fn create_verify_admitted_rejects_changed_unprivileged_port_sysctl() {
        let changed = rejection("safe unprivileged-port sysctl changed");
        assert_eq!(
            reason_with("/spec/securityContext/sysctls/0/value", json!("1")),
            changed
        );
        assert_eq!(
            reason_with(
                "/spec/securityContext/sysctls/0/name",
                json!("net.core.somaxconn")
            ),
            changed
        );
    }

    #[test]
    fn create_verify_admitted_rejects_supplemental_groups_policy_that_is_not_strict() {
        assert_eq!(
            reason_with(
                "/spec/securityContext/supplementalGroupsPolicy",
                json!("Merge")
            ),
            rejection("supplementalGroupsPolicy is not Strict")
        );
    }

    #[test]
    fn create_verify_admitted_rejects_pod_with_second_container() {
        let mut object = admitted();
        object["spec"]["containers"]
            .as_array_mut()
            .expect("containers")
            .push(json!({ "name": "extra", "image": "registry.example.com/extra:1" }));
        assert_eq!(
            admission_reason(&object),
            rejection("the sandbox container must be the pod's only container")
        );
    }

    #[test]
    fn create_verify_admitted_rejects_changed_sandbox_container_security() {
        let changed = rejection("sandbox container security context changed");
        assert_eq!(
            reason_with("/spec/containers/0/securityContext/runAsUser", json!(0)),
            changed
        );
        assert_eq!(
            reason_with(
                "/spec/containers/0/securityContext/allowPrivilegeEscalation",
                json!(true)
            ),
            changed
        );
        assert_eq!(
            reason_with(
                "/spec/containers/0/securityContext/capabilities/drop",
                json!([])
            ),
            changed
        );
        let mut object = admitted();
        object["spec"]["containers"][0]["securityContext"]["capabilities"]["add"] =
            json!(["NET_ADMIN"]);
        assert_eq!(admission_reason(&object), changed);
        assert_eq!(
            reason_with("/spec/containers/0/securityContext", Value::Null),
            rejection("sandbox container has no security context")
        );
    }

    #[test]
    fn create_verify_admitted_rejects_changed_bootstrap_container() {
        assert_eq!(
            reason_with("/spec/initContainers/0/securityContext/runAsUser", json!(0)),
            rejection("bootstrap init container security context changed")
        );
        assert_eq!(
            reason_with("/spec/initContainers/0/name", json!("other")),
            rejection("trusted bootstrap init container missing")
        );
    }

    #[test]
    fn create_verify_admitted_rejects_bootstrap_secret_mount_outside_init_container() {
        let mounts_rejected =
            rejection("bootstrap Secret must be mounted only by the trusted init container");
        assert_eq!(
            reason_with("/spec/initContainers/0/volumeMounts", Value::Null),
            mounts_rejected
        );
        let mut object = admitted();
        object["spec"]["containers"][0]["volumeMounts"]
            .as_array_mut()
            .expect("sandbox mounts")
            .push(json!({ "name": SANDBOX_BOOTSTRAP_VOLUME_NAME, "mountPath": "/bootstrap" }));
        assert_eq!(admission_reason(&object), mounts_rejected);
    }

    #[test]
    fn create_verify_admitted_rejects_changed_bootstrap_secret() {
        let mut object = admitted();
        let index = object["spec"]["volumes"]
            .as_array()
            .expect("volumes")
            .iter()
            .position(|volume| volume["name"] == SANDBOX_BOOTSTRAP_VOLUME_NAME)
            .expect("bootstrap volume");
        let pointer = format!("/spec/volumes/{index}/secret/secretName");
        *object.pointer_mut(&pointer).expect("bootstrap secret name") = json!("other-secret");
        assert_eq!(
            admission_reason(&object),
            rejection("generation-specific sandbox Secret changed")
        );
    }

    /// A driver configuration that starts with the flags it requires.
    fn test_config() -> Config {
        let args = Args::try_parse_from([
            "openshell-driver-podtemplate",
            "--bind-socket",
            "/run/odp/driver.sock",
            "--grpc-endpoint",
            "https://gateway.example:8080",
            "--probe-helper-image",
            "registry.example/probe:1",
        ])
        .expect("flags parse");
        Config::try_from(args).expect("config builds")
    }

    /// A client for a server that is not listening, so a call the test does not expect fails.
    fn unreachable_client() -> kube::Client {
        let config = kube::Config::new("http://127.0.0.1:1".parse().expect("uri"));
        kube::Client::try_from(config).expect("client")
    }

    fn named_sandbox(name: &str, driver_config: Option<Struct>) -> DriverSandbox {
        DriverSandbox {
            name: name.to_owned(),
            ..sandbox_with_template(driver_config)
        }
    }

    /// A create request that carries the launch credentials and a status, as the gateway sends it.
    fn start_inputs_request() -> DriverSandbox {
        DriverSandbox {
            id: SANDBOX_ID.to_owned(),
            name: "sandbox-1-name".to_owned(),
            namespace: "agents".to_owned(),
            workspace: "team-a".to_owned(),
            spec: Some(DriverSandboxSpec {
                log_level: "debug".to_owned(),
                template: Some(DriverSandboxTemplate {
                    image: SANDBOX_IMAGE.to_owned(),
                    driver_config: Some(driver_config(&[(
                        TEMPLATE_NAME_FIELD,
                        string_value("agent-template"),
                    )])),
                    ..DriverSandboxTemplate::default()
                }),
                sandbox_token: "sandbox-token-value".to_owned(),
                command: vec!["/bin/agent".to_owned()],
                launch_authentication: b"launch-authentication-value".to_vec(),
                ..DriverSandboxSpec::default()
            }),
            status: Some(DriverSandboxStatus {
                name: "sandbox-1-name".to_owned(),
                deleting: true,
                ..DriverSandboxStatus::default()
            }),
        }
    }

    /// Decodes the sandbox that the start-inputs Secret carries.
    fn decode_start_inputs(secret: &Secret) -> DriverSandbox {
        let data = secret.data.as_ref().expect("the start inputs carry data");
        let bytes = data
            .get(START_INPUTS_KEY)
            .expect("the start inputs carry the sandbox under its key");
        DriverSandbox::decode(bytes.0.as_slice()).expect("the start inputs decode")
    }

    #[test]
    fn create_start_inputs_secret_clears_launch_credentials_and_status() {
        let request = start_inputs_request();
        let secret = start_inputs_secret("agents", &request, owner());
        let decoded = decode_start_inputs(&secret);

        let spec = decoded
            .spec
            .as_ref()
            .expect("the start inputs keep the spec");
        assert!(spec.sandbox_token.is_empty(), "sandbox_token is cleared");
        assert!(
            spec.launch_authentication.is_empty(),
            "launch_authentication is cleared"
        );
        assert!(decoded.status.is_none(), "status is cleared");

        let mut expected = request;
        expected.status = None;
        let expected_spec = expected.spec.as_mut().expect("the request has a spec");
        expected_spec.sandbox_token.clear();
        expected_spec.launch_authentication.clear();
        assert!(
            decoded == expected,
            "every other field of the request is stored unchanged"
        );
    }

    #[test]
    fn create_start_inputs_secret_is_immutable_opaque_and_lease_controlled() {
        let secret = start_inputs_secret("agents", &start_inputs_request(), owner());

        assert_eq!(secret.metadata.name.as_deref(), Some("os-start-sandbox-1"));
        assert_eq!(secret.metadata.namespace.as_deref(), Some("agents"));
        assert_eq!(secret.metadata.owner_references, Some(vec![owner()]));
        assert_eq!(secret.immutable, Some(true));
        assert_eq!(secret.type_.as_deref(), Some("Opaque"));
        assert_eq!(
            secret.data.as_ref().map(BTreeMap::len),
            Some(1),
            "the start inputs carry exactly one data key"
        );

        let labels = secret
            .metadata
            .labels
            .as_ref()
            .expect("the secret is labelled");
        assert_eq!(labels[LABEL_MANAGED_BY].as_str(), LABEL_MANAGED_BY_VALUE);
        assert_eq!(labels[LABEL_SANDBOX_ID].as_str(), SANDBOX_ID);
        assert_eq!(labels[COMPONENT_LABEL].as_str(), START_INPUTS_COMPONENT);
    }

    #[tokio::test]
    async fn create_validate_rejects_driver_config_when_disallowed_before_any_call() {
        let mut config = test_config();
        config.admission.allow_driver_config = false;
        let sandbox = named_sandbox(
            "agent",
            Some(driver_config(&[(
                TEMPLATE_NAME_FIELD,
                string_value("agent-template"),
            )])),
        );
        let result = validate_sandbox_create(&unreachable_client(), &config, &sandbox).await;
        assert_eq!(
            precondition_message(result),
            "caller driver config is disabled; a gateway administrator must enable allow_driver_config"
        );
    }

    #[tokio::test]
    async fn create_validate_rejects_invalid_name_before_any_call() {
        let sandbox = named_sandbox(
            "My_sandbox",
            Some(driver_config(&[(
                TEMPLATE_NAME_FIELD,
                string_value("agent-template"),
            )])),
        );
        assert_invalid_argument(
            validate_sandbox_create(&unreachable_client(), &test_config(), &sandbox).await,
            SANDBOX_NAME_MESSAGE,
        );
    }

    #[tokio::test]
    async fn create_validate_rejects_missing_template_reference_before_any_call() {
        let sandbox = named_sandbox("agent", None);
        assert_invalid_argument(
            validate_sandbox_create(&unreachable_client(), &test_config(), &sandbox).await,
            TEMPLATE_INVALID,
        );
    }

    fn component(policy: &NetworkPolicy) -> Option<&str> {
        policy
            .metadata
            .labels
            .as_ref()?
            .get(COMPONENT_LABEL)
            .map(String::as_str)
    }

    #[test]
    fn create_sandbox_fences_are_labeled_as_managed_components() {
        let names = SandboxRuntimeNames::new(SANDBOX_ID);
        let [workload, supervisor] = sandbox_fences("agents", &names, 2222);
        assert_eq!(component(&workload), Some("sandbox-workload-fence"));
        assert_eq!(component(&supervisor), Some("sandbox-supervisor-egress"));
        for policy in [&workload, &supervisor] {
            let managed_by = policy
                .metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get(LABEL_MANAGED_BY))
                .map(String::as_str);
            assert_eq!(managed_by, Some(LABEL_MANAGED_BY_VALUE));
        }
    }

    fn expected_workload_fence() -> NetworkPolicy {
        let [workload, _] = sandbox_fences("agents", &SandboxRuntimeNames::new(SANDBOX_ID), 2222);
        workload
    }

    #[test]
    fn create_fence_matches_when_the_server_omits_empty_egress() {
        let expected = expected_workload_fence();
        let mut existing = expected.clone();
        existing.spec.as_mut().expect("spec").egress = None;
        assert!(fence_matches(&existing, &expected));
    }

    #[test]
    fn create_fence_rejects_changed_enforcement() {
        let expected = expected_workload_fence();
        let mut existing = expected.clone();
        existing.spec.as_mut().expect("spec").egress =
            Some(vec![NetworkPolicyEgressRule::default()]);
        assert!(!fence_matches(&existing, &expected));
        assert_eq!(
            precondition_message(validate_fence(&existing, &expected)),
            "sandbox-runtime workload fence openshell-sandbox-workloads exists but does not match the intended enforcement"
        );
    }

    #[test]
    fn create_fence_match_requires_the_component_labels() {
        let expected = expected_workload_fence();
        let mut existing = expected.clone();
        existing.metadata.labels = None;
        assert!(!fence_matches(&existing, &expected));
    }

    fn service_with_cluster_ip(cluster_ip: Option<&str>) -> Service {
        Service {
            spec: Some(ServiceSpec {
                cluster_ip: cluster_ip.map(str::to_owned),
                ..ServiceSpec::default()
            }),
            ..Service::default()
        }
    }

    #[test]
    fn create_cluster_ip_reads_the_service_address() {
        let service = service_with_cluster_ip(Some("10.96.0.7"));
        assert_eq!(
            cluster_ip(&service).expect("address"),
            "10.96.0.7".parse::<IpAddr>().expect("ip")
        );
    }

    #[test]
    fn create_cluster_ip_rejects_services_without_an_address() {
        for address in [None, Some("None")] {
            assert!(matches!(
                cluster_ip(&service_with_cluster_ip(address)),
                Err(DriverError::Message(_))
            ));
        }
    }

    #[tokio::test]
    async fn create_boundary_provisioning_binds_the_observed_runtime() {
        let sandbox = DriverSandbox {
            id: SANDBOX_ID.to_owned(),
            name: "agent".to_owned(),
            spec: Some(DriverSandboxSpec {
                environment: env(&[("OPENSHELL_HIDDEN", "1"), ("B", "spec")]),
                template: Some(DriverSandboxTemplate {
                    environment: env(&[("A", "template")]),
                    ..DriverSandboxTemplate::default()
                }),
                ..DriverSandboxSpec::default()
            }),
            ..DriverSandbox::default()
        };
        let config = test_config();
        let client = unreachable_client();
        let template = validated_template();
        let names = SandboxRuntimeNames::new(SANDBOX_ID);
        let run = RuntimeCreate {
            client: &client,
            config: &config,
            sandbox: &sandbox,
            template: &template,
            names: &names,
            main_process: "{}",
            launch: Launch::Create,
        };
        let authentication = decode_launch_authentication(launch_document().to_string().as_bytes())
            .expect("valid document");
        let tls = generate_sandbox_tls_material(authentication.supervisor.session_id)
            .expect("boundary TLS material");
        let observed = ObservedRuntime {
            namespace_uid: "namespace-uid".to_owned(),
            service_ip: "10.96.0.7".parse().expect("ip"),
            supervisor_uid: "supervisor-uid".to_owned(),
            workload_uid: "workload-uid".to_owned(),
            fence_uid: "fence-uid".to_owned(),
            fence_version: "42".to_owned(),
        };

        let provisioned = provision_boundary(&run, authentication, &observed, RECORD_UID, &tls)
            .expect("boundary provisions");
        let boundary = provisioned.boundary_config;

        assert_eq!(boundary.boundary_id, SANDBOX_ID);
        assert_eq!(boundary.child_env, env(&[("A", "template"), ("B", "spec")]));
        assert_eq!(boundary.workload_identity.source, "kubernetes-config");
        assert_eq!(
            boundary.workload_identity.resource_digest,
            format!("sandbox:{RECORD_UID}")
        );
        assert_eq!(
            boundary
                .resource_claims
                .get("kubernetes.workload_pod_uid")
                .map(String::as_str),
            Some("workload-uid")
        );
        let BoundaryListener::TlsTcp { address, .. } = boundary.listener else {
            panic!("the Kubernetes boundary listens over TLS on TCP");
        };
        assert_eq!(
            address,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), config.boundary_port)
        );
    }

    #[test]
    fn create_boundary_listener_binds_the_service_family() {
        let v4 = boundary_listener("10.96.0.7".parse().expect("ip"), 2222);
        assert_eq!(v4, "0.0.0.0:2222".parse::<SocketAddr>().expect("addr"));
        let v6 = boundary_listener("fd00::7".parse().expect("ip"), 2222);
        assert_eq!(v6, "[::]:2222".parse::<SocketAddr>().expect("addr"));
    }

    /// Builds a JSON response with `status` and `body`.
    fn reply(status: u16, body: &Value) -> http::Response<kube::client::Body> {
        http::Response::builder()
            .status(status)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(kube::client::Body::from(
                serde_json::to_vec(body).expect("JSON body"),
            ))
            .expect("response")
    }

    /// The Kubernetes Status of a request the fake does not answer, or a missing object.
    fn not_found() -> Value {
        json!({
            "apiVersion": "v1",
            "kind": "Status",
            "status": "Failure",
            "reason": "NotFound",
            "code": 404
        })
    }

    /// Answers one API call of a create. The template, the fences and the record are accepted
    /// and echoed. The namespace read is held open and signals `held`. Each record delete is
    /// sent on `deletes` as its path and its delete options.
    async fn answer_create_call(
        request: http::Request<kube::client::Body>,
        namespace: String,
        held: Arc<Notify>,
        deletes: mpsc::UnboundedSender<(String, Value)>,
    ) -> Result<http::Response<kube::client::Body>, kube::Error> {
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let body = request.into_body().collect_bytes().await?;
        let lease_path = format!("/apis/coordination.k8s.io/v1/namespaces/{namespace}/leases");
        if method == http::Method::GET && path == format!("/api/v1/namespaces/{namespace}") {
            held.notify_one();
            return std::future::pending().await;
        }
        if method == http::Method::GET && path.contains("/podtemplates/") {
            let template = json!({
                "apiVersion": "v1",
                "kind": "PodTemplate",
                "metadata": {"name": "agent-template"},
                "template": {"spec": {"containers": [{
                    "name": "agent",
                    "image": SANDBOX_IMAGE,
                    "command": ["/usr/bin/agent", "--serve"],
                    "args": ["--port", "8080"]
                }]}}
            });
            return Ok(reply(200, &template));
        }
        if method == http::Method::GET && path.contains("/networkpolicies/") {
            return Ok(reply(404, &not_found()));
        }
        if method == http::Method::POST && path.ends_with("/networkpolicies") {
            let policy: Value = serde_json::from_slice(&body).expect("policy JSON");
            return Ok(reply(201, &policy));
        }
        if method == http::Method::POST && path == lease_path {
            let mut record: Value = serde_json::from_slice(&body).expect("record JSON");
            record["metadata"]["uid"] = json!(RECORD_UID);
            return Ok(reply(201, &record));
        }
        if method == http::Method::DELETE && path.starts_with(&format!("{lease_path}/")) {
            let options: Value = serde_json::from_slice(&body).expect("delete options JSON");
            let _ = deletes.send((path, options));
            let status = json!({
                "apiVersion": "v1",
                "kind": "Status",
                "status": "Success",
                "code": 200
            });
            return Ok(reply(200, &status));
        }
        Ok(reply(404, &not_found()))
    }

    #[tokio::test]
    async fn create_cancelled_after_the_record_deletes_the_record() {
        let config = test_config();
        let namespace = config.namespace.clone();
        let held = Arc::new(Notify::new());
        let (deletes_tx, mut deletes) = mpsc::unbounded_channel();
        let api = tower::service_fn({
            let held = Arc::clone(&held);
            let namespace = namespace.clone();
            move |request: http::Request<kube::client::Body>| {
                answer_create_call(
                    request,
                    namespace.clone(),
                    Arc::clone(&held),
                    deletes_tx.clone(),
                )
            }
        });
        let client = kube::Client::new(api, namespace.clone());
        let sandbox = DriverSandbox {
            id: SANDBOX_ID.to_owned(),
            name: "agent".to_owned(),
            spec: Some(DriverSandboxSpec {
                launch_authentication: launch_document().to_string().into_bytes(),
                template: Some(DriverSandboxTemplate {
                    image: SANDBOX_IMAGE.to_owned(),
                    driver_config: Some(driver_config(&[(
                        TEMPLATE_NAME_FIELD,
                        string_value("agent-template"),
                    )])),
                    ..DriverSandboxTemplate::default()
                }),
                ..DriverSandboxSpec::default()
            }),
            ..DriverSandbox::default()
        };

        let mut create = Box::pin(create_sandbox(&client, &config, &sandbox));
        tokio::select! {
            result = &mut create => {
                panic!("create returned before it was cancelled: {result:?}");
            }
            () = held.notified() => {}
        }
        drop(create);

        let (path, options) = timeout(Duration::from_secs(10), deletes.recv())
            .await
            .expect("the record delete arrives after the cancel")
            .expect("the delete channel stays open");
        assert_eq!(
            path,
            format!("/apis/coordination.k8s.io/v1/namespaces/{namespace}/leases/agent")
        );
        assert_eq!(options["propagationPolicy"], "Foreground");
        assert_eq!(options["preconditions"]["uid"], RECORD_UID);
    }
}

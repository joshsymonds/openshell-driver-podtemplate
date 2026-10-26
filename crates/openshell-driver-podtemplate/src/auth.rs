// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
// SPDX-License-Identifier: Apache-2.0

//! Checks behind `AuthenticateSandbox`, vendored from `OpenShell` v0.1.5.
//!
//! A `TokenReview` status becomes a pod-bound service-account identity. The
//! reviewed pod must be its sandbox's supervisor, and that pod must be controlled
//! by a Lease record whose UID and sandbox ID match. The runtime identity string
//! is the one `create` returns. Every function is pure except
//! `authenticate_sandbox`, which makes the `TokenReview` request and reads the pod
//! and Lease through the Kubernetes API.

use k8s_openapi::Resource;
use k8s_openapi::api::authentication::v1::{
    TokenReview, TokenReviewSpec, TokenReviewStatus, UserInfo,
};
use k8s_openapi::api::coordination::v1::Lease;
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference;
use kube::api::{Api, PostParams};
use openshell_core::driver_utils::LABEL_SANDBOX_ID;
use tracing::warn;

use crate::config::Config;
use crate::error::DriverError;
use crate::runtime_objects::SandboxRuntimeNames;
use crate::template::upstream::{BOUNDARY_PAIR_LABEL, BOUNDARY_ROLE_LABEL, pair_label_value};

/// The audience a sandbox credential must carry.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:351`.
pub const SANDBOX_TOKEN_AUDIENCE: &str = "openshell-gateway";

/// Extra key that binds a sandbox credential to a pod name.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:352`.
const POD_NAME_EXTRA: &str = "authentication.kubernetes.io/pod-name";

/// Extra key that binds a sandbox credential to a pod UID.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:353`.
const POD_UID_EXTRA: &str = "authentication.kubernetes.io/pod-uid";

/// Boundary-role label value for the supervisor pod.
///
/// The value is also set by `runtime_objects.rs`, where its constant is private.
const SUPERVISOR_ROLE: &str = "supervisor";

/// The pod-bound service-account identity that a `TokenReview` establishes.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:5191-5196`.
#[derive(Debug, PartialEq, Eq)]
pub struct TokenReviewIdentity {
    /// Namespace of the service account that presented the credential.
    pub namespace: String,
    /// Name of the pod the credential is bound to.
    pub pod_name: String,
    /// UID of the pod the credential is bound to.
    pub pod_uid: String,
}

/// Turns a `TokenReview` status into the pod-bound identity of a sandbox credential.
///
/// Returns `None` when the review did not authenticate the token.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:5198-5240`.
/// `tonic::Status` results become [`DriverError`] with the same codes.
pub fn token_review_identity(
    status: &TokenReviewStatus,
    expected_service_account: &str,
) -> Result<Option<TokenReviewIdentity>, DriverError> {
    if status.authenticated != Some(true) {
        return Ok(None);
    }
    if !status
        .audiences
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|audience| audience == SANDBOX_TOKEN_AUDIENCE)
    {
        return Err(DriverError::Unauthenticated(
            "sandbox credential audience not accepted".to_string(),
        ));
    }
    let user = status.user.as_ref().ok_or_else(|| {
        DriverError::PermissionDenied("TokenReview response missing user".to_string())
    })?;
    let rest = user
        .username
        .as_deref()
        .unwrap_or_default()
        .strip_prefix("system:serviceaccount:")
        .ok_or_else(|| {
            DriverError::PermissionDenied("credential is not a service account".to_string())
        })?;
    let (namespace, service_account) = rest
        .split_once(':')
        .filter(|(namespace, service_account)| !namespace.is_empty() && !service_account.is_empty())
        .ok_or_else(|| {
            DriverError::PermissionDenied("invalid service account identity".to_string())
        })?;
    if service_account != expected_service_account {
        return Err(DriverError::PermissionDenied(
            "credential is not from the configured sandbox service account".to_string(),
        ));
    }
    Ok(Some(TokenReviewIdentity {
        namespace: namespace.to_string(),
        pod_name: user_extra_one(user, POD_NAME_EXTRA)?,
        pod_uid: user_extra_one(user, POD_UID_EXTRA)?,
    }))
}

/// Returns the single non-empty value that a credential's extra key carries.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:5242-5256`.
fn user_extra_one(user: &UserInfo, key: &str) -> Result<String, DriverError> {
    let values = user
        .extra
        .as_ref()
        .and_then(|extra| extra.get(key))
        .ok_or_else(|| {
            DriverError::PermissionDenied("sandbox credential is not pod-bound".to_string())
        })?;
    match values.as_slice() {
        [value] if !value.is_empty() => Ok(value.clone()),
        _ => Err(DriverError::PermissionDenied(
            "sandbox credential has invalid pod binding".to_string(),
        )),
    }
}

/// Returns the sandbox ID that a pod's annotation binds it to.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:5258-5267`.
fn pod_sandbox_id(pod: &Pod) -> Result<String, DriverError> {
    pod.metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(LABEL_SANDBOX_ID))
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| {
            DriverError::PermissionDenied("pod is not bound to a sandbox identity".to_string())
        })
}

/// Rejects a pod whose UID is not the one the credential names.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:5269-5276`.
fn validate_pod_uid(pod: &Pod, expected_uid: &str) -> Result<(), DriverError> {
    if pod.metadata.uid.as_deref() == Some(expected_uid) {
        return Ok(());
    }
    Err(DriverError::PermissionDenied(
        "sandbox credential pod UID mismatch".to_string(),
    ))
}

/// Rejects a pod whose labels do not name it as the supervisor of this sandbox.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:5294-5319`.
fn validate_supervisor_labels(pod: &Pod, sandbox_id: &str) -> Result<(), DriverError> {
    let labels = pod.metadata.labels.as_ref().ok_or_else(|| {
        DriverError::PermissionDenied("control workload has no sandbox-runtime labels".to_string())
    })?;
    let expected_pair = pair_label_value(sandbox_id);
    let matches = labels
        .get(BOUNDARY_ROLE_LABEL)
        .is_some_and(|role| role == SUPERVISOR_ROLE)
        && labels
            .get(BOUNDARY_PAIR_LABEL)
            .is_some_and(|pair| pair == &expected_pair)
        && labels
            .get(LABEL_SANDBOX_ID)
            .is_some_and(|actual| actual == sandbox_id);
    if matches {
        return Ok(());
    }
    Err(DriverError::PermissionDenied(
        "control workload sandbox-runtime labels do not match the sandbox identity".to_string(),
    ))
}

/// Returns the one Lease owner of a pod, which must be its controller and carry a name and UID.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:5321-5353`, with the
/// owner kind and API version taken from `Lease` instead of agent-sandbox `Sandbox`. Upstream's
/// supervisor branch rejects a controller owner; this driver requires one.
fn lease_owner_reference(pod: &Pod) -> Result<&OwnerReference, DriverError> {
    let mut owners = pod
        .metadata
        .owner_references
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|owner| owner.kind == Lease::KIND && owner.api_version == Lease::API_VERSION);
    let owner = owners
        .next()
        .ok_or_else(|| DriverError::PermissionDenied("pod is not owned by a Lease".to_string()))?;
    if owners.next().is_some()
        || owner.controller != Some(true)
        || owner.name.is_empty()
        || owner.uid.is_empty()
    {
        return Err(DriverError::PermissionDenied(
            "pod has an invalid Lease owner".to_string(),
        ));
    }
    Ok(owner)
}

/// Verifies that a pod is the supervisor of the sandbox that its credential names, and returns
/// the sandbox ID and the Lease owner reference.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:1011-1032`, supervisor
/// branch only. Upstream's workload-pod branch is not vendored.
pub fn verify_supervisor_pod(
    pod: &Pod,
    identity: &TokenReviewIdentity,
) -> Result<(String, OwnerReference), DriverError> {
    validate_pod_uid(pod, &identity.pod_uid)?;
    let sandbox_id = pod_sandbox_id(pod)?;
    validate_supervisor_labels(pod, &sandbox_id)?;
    let names = SandboxRuntimeNames::new(&sandbox_id);
    if pod.metadata.name.as_deref() != Some(names.supervisor_pod.as_str()) {
        return Err(DriverError::PermissionDenied(
            "supervisor pod name does not match the sandbox runtime".to_string(),
        ));
    }
    let owner = lease_owner_reference(pod)?.clone();
    Ok((sandbox_id, owner))
}

/// Verifies that a Lease record is the one the pod's owner reference names, and that it carries
/// the same sandbox ID.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:5355-5373`
/// (`validate_sandbox_owner_identity`), with the record type changed from `Sandbox` to `Lease`.
pub fn verify_record(
    owner: &OwnerReference,
    sandbox_id: &str,
    record: &Lease,
) -> Result<(), DriverError> {
    let uid_matches = record.metadata.uid.as_deref() == Some(owner.uid.as_str());
    let sandbox_id_matches = record
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(LABEL_SANDBOX_ID))
        .is_some_and(|actual| actual == sandbox_id);
    if uid_matches && sandbox_id_matches {
        return Ok(());
    }
    Err(DriverError::PermissionDenied(
        "pod identity does not match its Lease owner".to_string(),
    ))
}

/// Returns the runtime identity string that `create` returns for a supervisor pod.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:5106-5108`.
pub fn runtime_identity(namespace: &str, record_uid: &str, supervisor_pod_uid: &str) -> String {
    format!("kubernetes://{namespace}/{record_uid}/{supervisor_pod_uid}")
}

/// Authenticates a supervisor's projected service-account token and returns the sandbox ID and
/// the runtime identity that `create` returns for that supervisor.
///
/// Vendored from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:940-1009`
/// (`authenticate_sandbox`), with the owner record changed from `Sandbox` to `Lease`. The operator
/// allowlist wait and the proxy-control check are not vendored, and the namespace check compares
/// against `Config::namespace`. The empty credential check is vendored from
/// `v0.1.5:crates/openshell-driver-kubernetes/src/grpc.rs:62-64`. The credential is sent only in
/// the `TokenReview` request and never appears in a log line or an error message.
///
/// The Lease UID is the owner reference's UID, which [`verify_record`] has just checked against the
/// stored Lease.
pub async fn authenticate_sandbox(
    client: &kube::Client,
    config: &Config,
    credential: &str,
) -> Result<(String, String), DriverError> {
    if credential.is_empty() {
        return Err(DriverError::InvalidArgument(
            "credential is required".to_string(),
        ));
    }
    let reviews: Api<TokenReview> = Api::all(client.clone());
    let review = TokenReview {
        spec: TokenReviewSpec {
            audiences: Some(vec![SANDBOX_TOKEN_AUDIENCE.to_string()]),
            token: Some(credential.to_string()),
        },
        ..Default::default()
    };
    let review = reviews
        .create(&PostParams::default(), &review)
        .await
        .map_err(|error| {
            warn!(%error, "Kubernetes TokenReview failed");
            DriverError::Message("Kubernetes TokenReview failed".to_string())
        })?;
    let status = review
        .status
        .ok_or_else(|| DriverError::Message("TokenReview response missing status".to_string()))?;
    let identity =
        token_review_identity(&status, &config.service_account_name)?.ok_or_else(|| {
            DriverError::Unauthenticated("sandbox credential was not accepted".to_string())
        })?;
    if identity.namespace != config.namespace {
        return Err(DriverError::PermissionDenied(
            "sandbox credential namespace is not accepted by the driver".to_string(),
        ));
    }

    let pods: Api<Pod> = Api::namespaced(client.clone(), &config.namespace);
    let pod = pods
        .get_opt(&identity.pod_name)
        .await
        .map_err(DriverError::from_kube)?
        .ok_or_else(|| {
            DriverError::PermissionDenied("authenticated sandbox pod not found".to_string())
        })?;
    let (sandbox_id, owner) = verify_supervisor_pod(&pod, &identity)?;

    let leases: Api<Lease> = Api::namespaced(client.clone(), &config.namespace);
    let lease = leases
        .get_opt(&owner.name)
        .await
        .map_err(DriverError::from_kube)?
        .ok_or_else(|| DriverError::PermissionDenied("sandbox owner not found".to_string()))?;
    verify_record(&owner, &sandbox_id, &lease)?;

    Ok((
        sandbox_id,
        runtime_identity(&config.namespace, &owner.uid, &identity.pod_uid),
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use clap::Parser;
    use k8s_openapi::Resource;
    use k8s_openapi::api::authentication::v1::{TokenReviewStatus, UserInfo};
    use k8s_openapi::api::coordination::v1::Lease;
    use k8s_openapi::api::core::v1::Pod;
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
    use openshell_core::driver_utils::LABEL_SANDBOX_ID;

    use super::*;
    use crate::config::Args;
    use crate::error::DriverError;
    use crate::runtime_objects::SandboxRuntimeNames;
    use crate::template::upstream::{BOUNDARY_PAIR_LABEL, BOUNDARY_ROLE_LABEL, pair_label_value};

    const SANDBOX_ID: &str = "sandbox-id-a";
    const POD_UID: &str = "pod-uid-a";
    const LEASE_NAME: &str = "lease-a";
    const LEASE_UID: &str = "lease-uid-a";

    fn authenticated_token_review(username: &str) -> TokenReviewStatus {
        TokenReviewStatus {
            authenticated: Some(true),
            audiences: Some(vec![SANDBOX_TOKEN_AUDIENCE.to_string()]),
            user: Some(UserInfo {
                username: Some(username.to_string()),
                extra: Some(BTreeMap::from([
                    (POD_NAME_EXTRA.to_string(), vec!["sandbox-pod".to_string()]),
                    (POD_UID_EXTRA.to_string(), vec![POD_UID.to_string()]),
                ])),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn assert_permission_denied<T: std::fmt::Debug>(result: Result<T, DriverError>, message: &str) {
        let error = result.expect_err("expected a rejection");
        assert!(
            matches!(&error, DriverError::PermissionDenied(actual) if actual == message),
            "{error:?}"
        );
    }

    fn lease_owner() -> OwnerReference {
        OwnerReference {
            api_version: Lease::API_VERSION.to_string(),
            kind: Lease::KIND.to_string(),
            name: LEASE_NAME.to_string(),
            uid: LEASE_UID.to_string(),
            controller: Some(true),
            block_owner_deletion: Some(true),
        }
    }

    fn lease_record(uid: &str, sandbox_id: &str) -> Lease {
        Lease {
            metadata: ObjectMeta {
                uid: Some(uid.to_string()),
                labels: Some(BTreeMap::from([(
                    LABEL_SANDBOX_ID.to_string(),
                    sandbox_id.to_string(),
                )])),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn supervisor_pod() -> Pod {
        Pod {
            metadata: ObjectMeta {
                name: Some(SandboxRuntimeNames::new(SANDBOX_ID).supervisor_pod),
                uid: Some(POD_UID.to_string()),
                annotations: Some(BTreeMap::from([(
                    LABEL_SANDBOX_ID.to_string(),
                    SANDBOX_ID.to_string(),
                )])),
                labels: Some(BTreeMap::from([
                    (LABEL_SANDBOX_ID.to_string(), SANDBOX_ID.to_string()),
                    (
                        BOUNDARY_PAIR_LABEL.to_string(),
                        pair_label_value(SANDBOX_ID),
                    ),
                    (BOUNDARY_ROLE_LABEL.to_string(), "supervisor".to_string()),
                ])),
                owner_references: Some(vec![lease_owner()]),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn identity() -> TokenReviewIdentity {
        TokenReviewIdentity {
            namespace: "workspaces".to_string(),
            pod_name: "sandbox-pod".to_string(),
            pod_uid: POD_UID.to_string(),
        }
    }

    #[test]
    fn auth_token_review_uses_configured_service_account_and_pod_binding() {
        let status = authenticated_token_review("system:serviceaccount:workspaces:sandbox-sa");
        let identity = token_review_identity(&status, "sandbox-sa")
            .unwrap()
            .expect("authenticated identity");
        assert_eq!(
            identity,
            TokenReviewIdentity {
                namespace: "workspaces".to_string(),
                pod_name: "sandbox-pod".to_string(),
                pod_uid: POD_UID.to_string(),
            }
        );
    }

    #[test]
    fn auth_token_review_rejects_a_different_service_account() {
        let status = authenticated_token_review("system:serviceaccount:workspaces:other");
        assert_permission_denied(
            token_review_identity(&status, "sandbox-sa"),
            "credential is not from the configured sandbox service account",
        );
    }

    #[test]
    fn auth_token_review_rejects_wrong_audience() {
        let mut status = authenticated_token_review("system:serviceaccount:workspaces:sandbox-sa");
        status.audiences = Some(vec!["kubernetes.default.svc".to_string()]);
        let error = token_review_identity(&status, "sandbox-sa").unwrap_err();
        assert!(
            matches!(&error, DriverError::Unauthenticated(actual) if actual == "sandbox credential audience not accepted"),
            "{error:?}"
        );
    }

    #[test]
    fn auth_token_review_rejects_missing_multi_valued_or_empty_pod_binding() {
        let mut missing = authenticated_token_review("system:serviceaccount:workspaces:sandbox-sa");
        missing.user.as_mut().unwrap().extra = None;
        assert_permission_denied(
            token_review_identity(&missing, "sandbox-sa"),
            "sandbox credential is not pod-bound",
        );

        let mut multi = authenticated_token_review("system:serviceaccount:workspaces:sandbox-sa");
        multi.user.as_mut().unwrap().extra.as_mut().unwrap().insert(
            POD_UID_EXTRA.to_string(),
            vec![POD_UID.to_string(), "pod-uid-b".to_string()],
        );
        assert_permission_denied(
            token_review_identity(&multi, "sandbox-sa"),
            "sandbox credential has invalid pod binding",
        );

        let mut empty = authenticated_token_review("system:serviceaccount:workspaces:sandbox-sa");
        empty
            .user
            .as_mut()
            .unwrap()
            .extra
            .as_mut()
            .unwrap()
            .insert(POD_UID_EXTRA.to_string(), vec![String::new()]);
        assert_permission_denied(
            token_review_identity(&empty, "sandbox-sa"),
            "sandbox credential has invalid pod binding",
        );
    }

    #[test]
    fn auth_token_review_returns_none_when_not_authenticated() {
        let status = TokenReviewStatus {
            authenticated: Some(false),
            error: Some("token rejected".to_string()),
            ..Default::default()
        };
        assert!(
            token_review_identity(&status, "sandbox-sa")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn auth_token_review_rejects_a_response_without_user() {
        let mut status = authenticated_token_review("system:serviceaccount:workspaces:sandbox-sa");
        status.user = None;
        assert_permission_denied(
            token_review_identity(&status, "sandbox-sa"),
            "TokenReview response missing user",
        );
    }

    #[test]
    fn auth_token_review_rejects_a_credential_that_is_not_a_service_account() {
        let status = authenticated_token_review("system:node:node-a");
        assert_permission_denied(
            token_review_identity(&status, "sandbox-sa"),
            "credential is not a service account",
        );
    }

    #[test]
    fn auth_token_review_rejects_an_empty_namespace_or_service_account() {
        for username in [
            "system:serviceaccount::sandbox-sa",
            "system:serviceaccount:workspaces:",
            "system:serviceaccount:workspaces",
        ] {
            let status = authenticated_token_review(username);
            assert_permission_denied(
                token_review_identity(&status, "sandbox-sa"),
                "invalid service account identity",
            );
        }
    }

    #[test]
    fn auth_supervisor_pod_returns_sandbox_id_and_lease_owner() {
        let (sandbox_id, owner) =
            verify_supervisor_pod(&supervisor_pod(), &identity()).expect("supervisor pod");
        assert_eq!(sandbox_id, SANDBOX_ID);
        assert_eq!(owner, lease_owner());
    }

    #[test]
    fn auth_supervisor_pod_rejects_uid_mismatch() {
        let mut review = identity();
        review.pod_uid = "other-pod-uid".to_string();
        assert_permission_denied(
            verify_supervisor_pod(&supervisor_pod(), &review),
            "sandbox credential pod UID mismatch",
        );
    }

    #[test]
    fn auth_supervisor_pod_rejects_missing_sandbox_id_annotation() {
        let mut pod = supervisor_pod();
        pod.metadata.annotations = None;
        assert_permission_denied(
            verify_supervisor_pod(&pod, &identity()),
            "pod is not bound to a sandbox identity",
        );
    }

    #[test]
    fn auth_supervisor_pod_rejects_empty_sandbox_id_annotation() {
        let mut pod = supervisor_pod();
        pod.metadata.annotations = Some(BTreeMap::from([(
            LABEL_SANDBOX_ID.to_string(),
            String::new(),
        )]));
        assert_permission_denied(
            verify_supervisor_pod(&pod, &identity()),
            "pod is not bound to a sandbox identity",
        );
    }

    #[test]
    fn auth_supervisor_pod_rejects_missing_labels() {
        let mut pod = supervisor_pod();
        pod.metadata.labels = None;
        assert_permission_denied(
            verify_supervisor_pod(&pod, &identity()),
            "control workload has no sandbox-runtime labels",
        );
    }

    #[test]
    fn auth_supervisor_pod_rejects_a_workload_role() {
        let mut pod = supervisor_pod();
        pod.metadata
            .labels
            .as_mut()
            .unwrap()
            .insert(BOUNDARY_ROLE_LABEL.to_string(), "workload".to_string());
        assert_permission_denied(
            verify_supervisor_pod(&pod, &identity()),
            "control workload sandbox-runtime labels do not match the sandbox identity",
        );
    }

    #[test]
    fn auth_supervisor_pod_rejects_a_mismatched_pair_label() {
        let mut pod = supervisor_pod();
        pod.metadata
            .labels
            .as_mut()
            .unwrap()
            .insert(BOUNDARY_PAIR_LABEL.to_string(), "sandbox-id-b".to_string());
        assert_permission_denied(
            verify_supervisor_pod(&pod, &identity()),
            "control workload sandbox-runtime labels do not match the sandbox identity",
        );
    }

    #[test]
    fn auth_supervisor_pod_rejects_a_mismatched_sandbox_id_label() {
        let mut pod = supervisor_pod();
        pod.metadata
            .labels
            .as_mut()
            .unwrap()
            .insert(LABEL_SANDBOX_ID.to_string(), "sandbox-id-b".to_string());
        assert_permission_denied(
            verify_supervisor_pod(&pod, &identity()),
            "control workload sandbox-runtime labels do not match the sandbox identity",
        );
    }

    #[test]
    fn auth_supervisor_pod_rejects_a_pod_name_outside_the_sandbox_runtime() {
        let mut pod = supervisor_pod();
        pod.metadata.name = Some("os-supervisor-other".to_string());
        assert_permission_denied(
            verify_supervisor_pod(&pod, &identity()),
            "supervisor pod name does not match the sandbox runtime",
        );
    }

    #[test]
    fn auth_supervisor_pod_rejects_a_pod_without_owners() {
        let mut pod = supervisor_pod();
        pod.metadata.owner_references = None;
        assert_permission_denied(
            verify_supervisor_pod(&pod, &identity()),
            "pod is not owned by a Lease",
        );
    }

    #[test]
    fn auth_supervisor_pod_rejects_a_non_lease_owner() {
        let mut sandbox_owner = lease_owner();
        sandbox_owner.kind = "Sandbox".to_string();
        sandbox_owner.api_version = "agents.x-k8s.io/v1alpha1".to_string();
        let mut pod = supervisor_pod();
        pod.metadata.owner_references = Some(vec![sandbox_owner]);
        assert_permission_denied(
            verify_supervisor_pod(&pod, &identity()),
            "pod is not owned by a Lease",
        );

        let mut other_version = lease_owner();
        other_version.api_version = "coordination.k8s.io/v1beta1".to_string();
        pod.metadata.owner_references = Some(vec![other_version]);
        assert_permission_denied(
            verify_supervisor_pod(&pod, &identity()),
            "pod is not owned by a Lease",
        );

        let mut other_kind = lease_owner();
        other_kind.kind = "Pod".to_string();
        pod.metadata.owner_references = Some(vec![other_kind]);
        assert_permission_denied(
            verify_supervisor_pod(&pod, &identity()),
            "pod is not owned by a Lease",
        );
    }

    #[test]
    fn auth_supervisor_pod_rejects_two_lease_owners() {
        let mut second = lease_owner();
        second.name = "lease-b".to_string();
        second.uid = "lease-uid-b".to_string();
        let mut pod = supervisor_pod();
        pod.metadata.owner_references = Some(vec![lease_owner(), second]);
        assert_permission_denied(
            verify_supervisor_pod(&pod, &identity()),
            "pod has an invalid Lease owner",
        );
    }

    #[test]
    fn auth_supervisor_pod_rejects_a_non_controller_lease_owner() {
        let mut owner = lease_owner();
        owner.controller = Some(false);
        let mut pod = supervisor_pod();
        pod.metadata.owner_references = Some(vec![owner]);
        assert_permission_denied(
            verify_supervisor_pod(&pod, &identity()),
            "pod has an invalid Lease owner",
        );
    }

    #[test]
    fn auth_supervisor_pod_rejects_a_lease_owner_without_name_or_uid() {
        let mut unnamed = lease_owner();
        unnamed.name = String::new();
        let mut pod = supervisor_pod();
        pod.metadata.owner_references = Some(vec![unnamed]);
        assert_permission_denied(
            verify_supervisor_pod(&pod, &identity()),
            "pod has an invalid Lease owner",
        );

        let mut unidentified = lease_owner();
        unidentified.uid = String::new();
        pod.metadata.owner_references = Some(vec![unidentified]);
        assert_permission_denied(
            verify_supervisor_pod(&pod, &identity()),
            "pod has an invalid Lease owner",
        );
    }

    #[test]
    fn auth_verify_record_accepts_matching_uid_and_sandbox_id() {
        verify_record(
            &lease_owner(),
            SANDBOX_ID,
            &lease_record(LEASE_UID, SANDBOX_ID),
        )
        .expect("matching record");
    }

    #[test]
    fn auth_verify_record_rejects_a_uid_mismatch() {
        assert_permission_denied(
            verify_record(
                &lease_owner(),
                SANDBOX_ID,
                &lease_record("other-lease-uid", SANDBOX_ID),
            ),
            "pod identity does not match its Lease owner",
        );
    }

    #[test]
    fn auth_verify_record_rejects_a_sandbox_id_mismatch() {
        assert_permission_denied(
            verify_record(
                &lease_owner(),
                SANDBOX_ID,
                &lease_record(LEASE_UID, "sandbox-id-b"),
            ),
            "pod identity does not match its Lease owner",
        );
    }

    #[test]
    fn auth_runtime_identity_joins_namespace_record_uid_and_pod_uid() {
        assert_eq!(
            runtime_identity("workspaces", LEASE_UID, POD_UID),
            "kubernetes://workspaces/lease-uid-a/pod-uid-a"
        );
    }

    fn sandbox_config() -> Config {
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
        Config::try_from(args).expect("defaults validate")
    }

    #[tokio::test]
    async fn auth_authenticate_rejects_an_empty_credential_before_any_api_call() {
        // Nothing listens on port 1, so any request through this client fails with a `Message`.
        let client = kube::Client::try_from(kube::Config::new(
            "http://127.0.0.1:1".parse().expect("loopback uri"),
        ))
        .expect("client");
        let error = authenticate_sandbox(&client, &sandbox_config(), "")
            .await
            .expect_err("empty credential is rejected");
        assert!(
            matches!(&error, DriverError::InvalidArgument(actual) if actual == "credential is required"),
            "{error:?}"
        );
    }
}

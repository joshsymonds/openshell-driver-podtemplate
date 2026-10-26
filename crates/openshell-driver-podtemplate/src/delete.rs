// SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
// SPDX-License-Identifier: Apache-2.0

//! Deletes a sandbox's registry record, and stops its runtime.
//!
//! The record owns every per-sandbox object, so a foreground delete of the record lets
//! Kubernetes garbage collection remove them. The record stays, reported as deleting,
//! until the objects it controls are gone.
//!
//! [`stop_runtime`] deletes the pods, boundary Service and bootstrap Secrets of a sandbox and
//! keeps its record, so a stopped sandbox has no runtime left to resume.

use std::fmt::Debug;
use std::time::Duration;

use k8s_openapi::Resource as _;
use k8s_openapi::api::coordination::v1::Lease;
use k8s_openapi::api::core::v1::{Pod, Secret, Service};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::serde::de::DeserializeOwned;
use kube::api::{DeleteParams, ListParams, Preconditions, PropagationPolicy};
use kube::core::NamespaceResourceScope;
use kube::{Api, Resource};
use openshell_core::driver_utils::LABEL_SANDBOX_ID;

use crate::error::DriverError;
use crate::registry::record_sandbox_id;
use crate::template::upstream::{BOUNDARY_PAIR_LABEL, pair_label_value};

/// Label key that names the component a managed object belongs to.
const COMPONENT_LABEL: &str = "openshell.ai/component";
/// Component label values of the two generation bootstrap Secrets, as `runtime_objects` sets them.
const BOOTSTRAP_SECRET_COMPONENTS: [&str; 2] = ["sandbox-bootstrap", "supervisor-bootstrap"];
/// The grace period Kubernetes gives a pod that names none.
const DEFAULT_TERMINATION_GRACE: Duration = Duration::from_secs(30);
/// One API timeout, the bound `create.rs` puts on its API calls. A pod's deletion may take it on
/// top of the pod's termination grace period.
const KUBE_API_TIMEOUT: Duration = Duration::from_secs(30);
/// How often a deleting pod is read again.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Returns the delete parameters for `record`: foreground propagation, guarded by the
/// record's UID so a replacement record with the same name is not deleted.
pub fn record_delete_params(record: &Lease) -> Result<DeleteParams, DriverError> {
    let Some(uid) = &record.metadata.uid else {
        return Err(DriverError::Message("sandbox record has no UID".to_owned()));
    };
    Ok(DeleteParams::foreground().preconditions(Preconditions {
        uid: Some(uid.clone()),
        resource_version: None,
    }))
}

/// Deletes `record` by name in its namespace.
///
/// Returns `true` when this call deleted it. Returns `false` without a call when the
/// record is already deleting, and when the API reports it not found or replaced (404 or
/// 409).
pub async fn delete_record(client: &kube::Client, record: &Lease) -> Result<bool, DriverError> {
    if record.metadata.deletion_timestamp.is_some() {
        return Ok(false);
    }
    let (Some(name), Some(namespace)) = (&record.metadata.name, &record.metadata.namespace) else {
        return Err(DriverError::Message(
            "sandbox record has no name or namespace".to_owned(),
        ));
    };
    let params = record_delete_params(record)?;
    let api = Api::<Lease>::namespaced(client.clone(), namespace);
    match api.delete(name, &params).await {
        Ok(_) => Ok(true),
        Err(error) if is_absent(&error) => Ok(false),
        Err(error) => Err(DriverError::from_kube(error)),
    }
}

/// Deletes the runtime of the sandbox whose record is `record`, and keeps the record.
///
/// The runtime is the workload and supervisor pods, the boundary Service and the generation
/// bootstrap Secrets. Each object is deleted only when `record` controls it. The start-inputs
/// Secret stays. The pods are deleted first, and the call returns once both are gone. Then the
/// Service and the Secrets are deleted. Stopping a sandbox that has no runtime changes nothing.
///
/// Adapted from `v0.1.5:crates/openshell-driver-kubernetes/src/driver.rs:3582-3665` (the
/// supervisor Pod deleted in the foreground with a UID precondition and polled until gone, and
/// the generation Secrets deleted by name with 404 ignored) and `driver.rs:7261-7290` (the wait
/// bound).
///
/// # Errors
///
/// Returns an error when the record lacks its namespace, UID or sandbox ID, the first API
/// failure, or a timeout when a pod is still present after its deletion timeout.
pub async fn stop_runtime(client: &kube::Client, record: &Lease) -> Result<(), DriverError> {
    let (Some(namespace), Some(record_uid)) = (&record.metadata.namespace, &record.metadata.uid)
    else {
        return Err(DriverError::Message(
            "sandbox record has no namespace or UID".to_owned(),
        ));
    };
    let Some(sandbox_id) = record_sandbox_id(record) else {
        return Err(DriverError::Message(
            "sandbox record has no sandbox ID".to_owned(),
        ));
    };

    let pods = Api::<Pod>::namespaced(client.clone(), namespace);
    let pod_selector = format!("{BOUNDARY_PAIR_LABEL}={}", pair_label_value(sandbox_id));
    let owned_pods = controlled(&pods, &pod_selector, record_uid).await?;
    delete_each(
        &pods,
        &targets(&owned_pods)?,
        &PropagationPolicy::Foreground,
    )
    .await?;
    wait_for_pods_gone(&pods, &owned_pods).await?;

    // Background propagation: a foreground Service waits for its EndpointSlices, so it would
    // still be listed when this call returns.
    let services = Api::<Service>::namespaced(client.clone(), namespace);
    let owned_services = controlled(
        &services,
        &format!("{LABEL_SANDBOX_ID}={sandbox_id}"),
        record_uid,
    )
    .await?;
    delete_each(
        &services,
        &targets(&owned_services)?,
        &PropagationPolicy::Background,
    )
    .await?;

    let secrets = Api::<Secret>::namespaced(client.clone(), namespace);
    let secret_selector = format!(
        "{LABEL_SANDBOX_ID}={sandbox_id},{COMPONENT_LABEL} in ({})",
        BOOTSTRAP_SECRET_COMPONENTS.join(",")
    );
    let owned_secrets = controlled(&secrets, &secret_selector, record_uid).await?;
    delete_each(
        &secrets,
        &targets(&owned_secrets)?,
        &PropagationPolicy::Background,
    )
    .await
}

/// Returns whether `error` is the API's answer that the object is not there, or was replaced
/// under the precondition (404 or 409).
fn is_absent(error: &kube::Error) -> bool {
    matches!(error, kube::Error::Api(response) if response.code == 404 || response.code == 409)
}

/// Returns whether `meta` names the record of UID `record_uid` as its controller.
pub(crate) fn controlled_by(meta: &ObjectMeta, record_uid: &str) -> bool {
    meta.owner_references.iter().flatten().any(|owner| {
        owner.kind == Lease::KIND && owner.uid == record_uid && owner.controller == Some(true)
    })
}

/// Returns the name and UID of `meta`, which an object read from the API always carries.
fn identity(meta: &ObjectMeta) -> Result<(&str, &str), DriverError> {
    match (&meta.name, &meta.uid) {
        (Some(name), Some(uid)) => Ok((name.as_str(), uid.as_str())),
        _ => Err(DriverError::Message("object has no name or UID".to_owned())),
    }
}

/// Returns the objects of `api` that match `selector` and that the record of UID `record_uid`
/// controls.
async fn controlled<K>(
    api: &Api<K>,
    selector: &str,
    record_uid: &str,
) -> Result<Vec<K>, DriverError>
where
    K: Resource<Scope = NamespaceResourceScope> + Clone + DeserializeOwned + Debug,
    K::DynamicType: Default,
{
    let listed = api
        .list(&ListParams::default().labels(selector))
        .await
        .map_err(DriverError::from_kube)?;
    Ok(listed
        .items
        .into_iter()
        .filter(|object| controlled_by(object.meta(), record_uid))
        .collect())
}

/// Returns the name and UID of each of `objects`.
fn targets<K: Resource>(objects: &[K]) -> Result<Vec<(String, String)>, DriverError> {
    objects
        .iter()
        .map(|object| identity(object.meta()).map(|(name, uid)| (name.to_owned(), uid.to_owned())))
        .collect()
}

/// Deletes each of `targets` with `propagation`, guarded by its UID. An object that is already
/// gone, or was replaced under that UID, is left alone.
async fn delete_each<K>(
    api: &Api<K>,
    targets: &[(String, String)],
    propagation: &PropagationPolicy,
) -> Result<(), DriverError>
where
    K: Resource<Scope = NamespaceResourceScope> + Clone + DeserializeOwned + Debug,
    K::DynamicType: Default,
{
    for (name, uid) in targets {
        let params = DeleteParams {
            propagation_policy: Some(propagation.clone()),
            preconditions: Some(Preconditions {
                uid: Some(uid.clone()),
                resource_version: None,
            }),
            ..DeleteParams::default()
        };
        match api.delete(name, &params).await {
            Ok(_) => {}
            Err(error) if is_absent(&error) => {}
            Err(error) => return Err(DriverError::from_kube(error)),
        }
    }
    Ok(())
}

/// Waits until each of `pods` is gone, which is when it is absent or replaced under its UID.
/// The wait ends with an error once the longest deletion timeout among `pods` has passed.
async fn wait_for_pods_gone(api: &Api<Pod>, pods: &[Pod]) -> Result<(), DriverError> {
    let timeout = pods
        .iter()
        .map(pod_deletion_timeout)
        .max()
        .unwrap_or_default();
    let deadline = tokio::time::Instant::now() + timeout;
    for pod in pods {
        let (name, uid) = identity(&pod.metadata)?;
        while still_present(api, name, uid).await? {
            if tokio::time::Instant::now() >= deadline {
                return Err(DriverError::Message(format!(
                    "timed out after {}s waiting for pod {name} deletion",
                    timeout.as_secs()
                )));
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }
    Ok(())
}

/// Returns whether the pod `name` of UID `uid` still exists.
async fn still_present(api: &Api<Pod>, name: &str, uid: &str) -> Result<bool, DriverError> {
    let current = api.get_opt(name).await.map_err(DriverError::from_kube)?;
    Ok(current.is_some_and(|pod| pod.metadata.uid.as_deref() == Some(uid)))
}

/// Returns how long `pod` may take to be deleted: its termination grace period plus one API
/// timeout.
fn pod_deletion_timeout(pod: &Pod) -> Duration {
    let grace = pod
        .spec
        .as_ref()
        .and_then(|spec| spec.termination_grace_period_seconds)
        .and_then(|seconds| u64::try_from(seconds).ok())
        .map_or(DEFAULT_TERMINATION_GRACE, Duration::from_secs);
    grace.saturating_add(KUBE_API_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use k8s_openapi::api::coordination::v1::Lease;
    use k8s_openapi::api::core::v1::{Pod, PodSpec};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference, Time};
    use k8s_openapi::chrono::DateTime;
    use kube::api::{Preconditions, PropagationPolicy};

    use super::{controlled_by, delete_record, pod_deletion_timeout, record_delete_params};
    use crate::error::DriverError;

    const RECORD_UID: &str = "record-uid";

    fn record() -> Lease {
        Lease {
            metadata: ObjectMeta {
                name: Some("agent-one".into()),
                namespace: Some("sandboxes".into()),
                uid: Some(RECORD_UID.into()),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn owner(kind: &str, uid: &str, controller: Option<bool>) -> OwnerReference {
        OwnerReference {
            api_version: "coordination.k8s.io/v1".into(),
            kind: kind.into(),
            name: "agent-one".into(),
            uid: uid.into(),
            controller,
            block_owner_deletion: None,
        }
    }

    fn owned_by(owners: Vec<OwnerReference>) -> ObjectMeta {
        ObjectMeta {
            owner_references: Some(owners),
            ..Default::default()
        }
    }

    #[test]
    fn controlled_by_requires_the_record_as_controller() {
        assert!(controlled_by(
            &owned_by(vec![owner("Lease", RECORD_UID, Some(true))]),
            RECORD_UID
        ));
        assert!(!controlled_by(
            &owned_by(vec![owner("Lease", RECORD_UID, Some(false))]),
            RECORD_UID
        ));
        assert!(!controlled_by(
            &owned_by(vec![owner("Lease", RECORD_UID, None)]),
            RECORD_UID
        ));
        assert!(!controlled_by(
            &owned_by(vec![owner("Lease", "other-record", Some(true))]),
            RECORD_UID
        ));
        assert!(!controlled_by(
            &owned_by(vec![owner("Pod", RECORD_UID, Some(true))]),
            RECORD_UID
        ));
        assert!(!controlled_by(&ObjectMeta::default(), RECORD_UID));
    }

    #[test]
    fn pod_deletion_timeout_adds_one_api_timeout_to_the_grace_period() {
        let pod = |grace: Option<i64>| Pod {
            spec: Some(PodSpec {
                termination_grace_period_seconds: grace,
                ..Default::default()
            }),
            ..Default::default()
        };

        assert_eq!(pod_deletion_timeout(&pod(Some(30))), Duration::from_mins(1));
        assert_eq!(
            pod_deletion_timeout(&pod(Some(120))),
            Duration::from_secs(150)
        );
        assert_eq!(pod_deletion_timeout(&pod(None)), Duration::from_mins(1));
    }

    #[test]
    fn delete_params_propagate_in_the_foreground() {
        let params = record_delete_params(&record()).expect("delete params");

        assert_eq!(
            params.propagation_policy,
            Some(PropagationPolicy::Foreground)
        );
    }

    #[test]
    fn delete_params_guard_the_record_by_its_uid() {
        let params = record_delete_params(&record()).expect("delete params");

        assert_eq!(
            params.preconditions,
            Some(Preconditions {
                uid: Some(RECORD_UID.into()),
                resource_version: None,
            })
        );
    }

    #[test]
    fn delete_params_require_a_record_uid() {
        let mut unuided = record();
        unuided.metadata.uid = None;

        assert!(matches!(
            record_delete_params(&unuided),
            Err(DriverError::Message(_))
        ));
    }

    #[tokio::test]
    async fn delete_already_deleting_record_returns_false_without_an_api_call() {
        let mut deleting = record();
        deleting.metadata.deletion_timestamp = Some(Time(
            DateTime::from_timestamp(1, 0).expect("valid timestamp"),
        ));
        // Nothing listens on port 1, so any request this call made would fail.
        let config = kube::Config::new("http://127.0.0.1:1".parse().expect("uri"));
        let client = kube::Client::try_from(config).expect("client");

        let deleted = delete_record(&client, &deleting)
            .await
            .expect("no API call");

        assert!(!deleted);
    }
}

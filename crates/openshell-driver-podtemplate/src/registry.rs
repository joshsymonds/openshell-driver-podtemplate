// SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
// SPDX-License-Identifier: Apache-2.0

//! The per-sandbox registry record: a `coordination.k8s.io/v1` Lease.
//!
//! The record carries a sandbox's identity, never its spec or any credential, and owns
//! the sandbox's per-sandbox objects. [`sandbox_from_record`] turns a record and its pods
//! into the `DriverSandbox` snapshot that Get, List and Watch report. [`Registry`] reads
//! those records and pods from the Kubernetes API, and [`WatchState`] turns watch events
//! into sandbox events.

use std::collections::{BTreeMap, BTreeSet};

use futures::StreamExt;
use futures::future::ready;
use futures::stream::{self, BoxStream, select};
use k8s_openapi::Resource;
use k8s_openapi::api::coordination::v1::Lease;
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
use kube::api::{Api, ListParams};
use kube::runtime::WatchStreamExt;
use kube::runtime::watcher::{self, Event};
use openshell_core::driver_utils::{
    LABEL_GATEWAY_ID, LABEL_MANAGED_BY, LABEL_MANAGED_BY_VALUE, LABEL_SANDBOX_ID,
    LABEL_SANDBOX_NAME, LABEL_SANDBOX_WORKSPACE,
};
use openshell_core::proto::compute::v1::{
    DriverSandbox, DriverSandboxStatus, WatchSandboxesDeletedEvent, WatchSandboxesEvent,
    WatchSandboxesSandboxEvent, watch_sandboxes_event,
};
use tracing::warn;

use crate::conditions::sandbox_conditions;
use crate::error::DriverError;
use crate::template::upstream::{
    BOUNDARY_PAIR_LABEL, BOUNDARY_ROLE_LABEL, WORKLOAD_ROLE, pair_label_value,
};

/// The longest value a Kubernetes label may carry.
const MAX_LABEL_VALUE_LEN: usize = 63;

/// Label key that names the component a managed object belongs to.
const LABEL_COMPONENT: &str = "openshell.ai/component";
/// Component label value that marks a sandbox record.
pub const RECORD_COMPONENT: &str = "sandbox-record";
/// Boundary-role label value for the supervisor pod.
const SUPERVISOR_ROLE: &str = "supervisor";

/// Returns the label selector that matches the sandbox records of one gateway.
pub fn record_selector(gateway_id: &str) -> String {
    format!(
        "{LABEL_MANAGED_BY}={LABEL_MANAGED_BY_VALUE},{LABEL_COMPONENT}={RECORD_COMPONENT},{LABEL_GATEWAY_ID}={gateway_id}"
    )
}

/// Builds the record for `sandbox`. The record carries identity only; nothing from
/// `sandbox.spec` is copied into it.
pub fn sandbox_record(namespace: &str, gateway_id: &str, sandbox: &DriverSandbox) -> Lease {
    Lease {
        metadata: ObjectMeta {
            name: Some(sandbox.name.clone()),
            namespace: Some(namespace.to_owned()),
            labels: Some(BTreeMap::from([
                (
                    LABEL_MANAGED_BY.to_owned(),
                    LABEL_MANAGED_BY_VALUE.to_owned(),
                ),
                (LABEL_COMPONENT.to_owned(), RECORD_COMPONENT.to_owned()),
                (LABEL_SANDBOX_ID.to_owned(), sandbox.id.clone()),
                (LABEL_GATEWAY_ID.to_owned(), gateway_id.to_owned()),
            ])),
            annotations: Some(BTreeMap::from([
                (LABEL_SANDBOX_NAME.to_owned(), sandbox.name.clone()),
                (
                    LABEL_SANDBOX_WORKSPACE.to_owned(),
                    sandbox.workspace.clone(),
                ),
            ])),
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Returns the owner reference that makes an object controlled by `record`.
pub fn record_owner_reference(record: &Lease) -> Result<OwnerReference, DriverError> {
    let (Some(name), Some(uid)) = (&record.metadata.name, &record.metadata.uid) else {
        return Err(DriverError::Message(
            "sandbox record has no name or UID".to_owned(),
        ));
    };
    Ok(OwnerReference {
        api_version: Lease::API_VERSION.to_owned(),
        kind: Lease::KIND.to_owned(),
        name: name.clone(),
        uid: uid.clone(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    })
}

/// Returns the sandbox ID the record carries.
pub fn record_sandbox_id(record: &Lease) -> Option<&str> {
    record
        .metadata
        .labels
        .as_ref()?
        .get(LABEL_SANDBOX_ID)
        .map(String::as_str)
}

/// Builds the `DriverSandbox` snapshot for `record` from the pods it controls.
///
/// Returns `None` when the record lacks its sandbox ID, its sandbox name or workspace
/// annotation, or its own name.
pub fn sandbox_from_record(record: &Lease, pods: &[Pod]) -> Option<DriverSandbox> {
    let id = record_sandbox_id(record)?;
    let annotations = record.metadata.annotations.as_ref()?;
    let name = annotations.get(LABEL_SANDBOX_NAME)?;
    let workspace = annotations.get(LABEL_SANDBOX_WORKSPACE)?;
    let record_name = record.metadata.name.as_ref()?;

    let owned = owned_pods(record, pods);
    let workload = owned
        .iter()
        .copied()
        .find(|pod| pod_role(pod) == Some(WORKLOAD_ROLE));
    let supervisor = owned
        .iter()
        .copied()
        .find(|pod| pod_role(pod) == Some(SUPERVISOR_ROLE));

    Some(DriverSandbox {
        id: id.to_owned(),
        name: name.clone(),
        namespace: record.metadata.namespace.clone().unwrap_or_default(),
        spec: None,
        status: Some(DriverSandboxStatus {
            name: record_name.clone(),
            instance_id: workload
                .and_then(|pod| pod.metadata.name.clone())
                .unwrap_or_default(),
            conditions: sandbox_conditions(workload, supervisor),
            deleting: record.metadata.deletion_timestamp.is_some(),
            ..Default::default()
        }),
        workspace: workspace.clone(),
    })
}

/// Returns the pods whose controlling owner reference is `record`.
fn owned_pods<'a>(record: &Lease, pods: &'a [Pod]) -> Vec<&'a Pod> {
    let Some(uid) = record.metadata.uid.as_deref() else {
        return Vec::new();
    };
    pods.iter()
        .filter(|pod| {
            pod.metadata.owner_references.iter().flatten().any(|owner| {
                owner.kind == Lease::KIND && owner.uid == uid && owner.controller == Some(true)
            })
        })
        .collect()
}

/// Returns the boundary role label of `pod`.
fn pod_role(pod: &Pod) -> Option<&str> {
    pod.metadata
        .labels
        .as_ref()?
        .get(BOUNDARY_ROLE_LABEL)
        .map(String::as_str)
}

/// Returns the UID of the record that controls `pod`.
fn controller_uid(pod: &Pod) -> Option<&str> {
    pod.metadata
        .owner_references
        .iter()
        .flatten()
        .find(|owner| owner.kind == Lease::KIND && owner.controller == Some(true))
        .map(|owner| owner.uid.as_str())
}

/// Returns whether `value` is a Kubernetes label value: at most 63 ASCII letters, digits,
/// `-`, `_` or `.`.
fn is_label_value(value: &str) -> bool {
    value.len() <= MAX_LABEL_VALUE_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// Returns the selector that matches the record of sandbox `sandbox_id` in one gateway, or
/// `None` when the ID is not a label value. A label value cannot carry `,` or `=`, so an ID
/// that did could widen the selector to other sandboxes' records.
fn lookup_selector(gateway_id: &str, sandbox_id: &str) -> Option<String> {
    is_label_value(sandbox_id).then(|| {
        format!(
            "{},{LABEL_SANDBOX_ID}={sandbox_id}",
            record_selector(gateway_id)
        )
    })
}

/// Reads and watches the sandbox records and pods of one gateway in one namespace.
///
/// The registry holds a client, a namespace and a gateway ID. Each call reads the API
/// server, so the registry keeps no snapshot of its own.
#[derive(Clone)]
pub struct Registry {
    client: kube::Client,
    namespace: String,
    gateway_id: String,
}

impl Registry {
    /// Returns a registry over the records and pods of gateway `gateway_id` in `namespace`.
    pub fn new(
        client: kube::Client,
        namespace: impl Into<String>,
        gateway_id: impl Into<String>,
    ) -> Self {
        Self {
            client,
            namespace: namespace.into(),
            gateway_id: gateway_id.into(),
        }
    }

    fn leases(&self) -> Api<Lease> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    fn pods(&self) -> Api<Pod> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    /// Returns the record of sandbox `sandbox_id`, or `None` when no record carries that ID.
    pub async fn find_record(&self, sandbox_id: &str) -> Result<Option<Lease>, DriverError> {
        let Some(selector) = lookup_selector(&self.gateway_id, sandbox_id) else {
            return Ok(None);
        };
        let records = self
            .leases()
            .list(&ListParams::default().labels(&selector))
            .await
            .map_err(DriverError::from_kube)?;
        Ok(records.items.into_iter().next())
    }

    /// Returns the snapshot of sandbox `sandbox_id`, built from its record and the pods the
    /// record controls, or `None` when no record carries that ID.
    pub async fn get_sandbox(
        &self,
        sandbox_id: &str,
    ) -> Result<Option<DriverSandbox>, DriverError> {
        let Some(record) = self.find_record(sandbox_id).await? else {
            return Ok(None);
        };
        let selector = format!("{BOUNDARY_PAIR_LABEL}={}", pair_label_value(sandbox_id));
        let pods = self
            .pods()
            .list(&ListParams::default().labels(&selector))
            .await
            .map_err(DriverError::from_kube)?;
        Ok(sandbox_from_record(&record, &pods.items))
    }

    /// Returns one snapshot per record that [`sandbox_from_record`] accepts, built from the
    /// role-labelled pods in the namespace.
    pub async fn list_sandboxes(&self) -> Result<Vec<DriverSandbox>, DriverError> {
        let records = self
            .leases()
            .list(&ListParams::default().labels(&record_selector(&self.gateway_id)))
            .await
            .map_err(DriverError::from_kube)?;
        let pods = self
            .pods()
            .list(&ListParams::default().labels(BOUNDARY_ROLE_LABEL))
            .await
            .map_err(DriverError::from_kube)?;
        Ok(records
            .items
            .iter()
            .filter_map(|record| sandbox_from_record(record, &pods.items))
            .collect())
    }

    /// Returns the sandbox events of this gateway, from the record and pod watches merged.
    ///
    /// Watcher errors are logged and the watch goes on. The stream ends only when the
    /// caller drops it.
    pub fn watch_sandboxes(&self) -> BoxStream<'static, Result<WatchSandboxesEvent, DriverError>> {
        let records = watcher::watcher(
            self.leases(),
            watcher::Config::default().labels(&record_selector(&self.gateway_id)),
        )
        .default_backoff()
        .filter_map(|result| ready(survive_watch_error("sandbox-record", result)))
        .map(|event| Watched::Record(Box::new(event)));
        let pods = watcher::watcher(
            self.pods(),
            watcher::Config::default().labels(BOUNDARY_ROLE_LABEL),
        )
        .default_backoff()
        .filter_map(|result| ready(survive_watch_error("sandbox-pod", result)))
        .map(|event| Watched::Pod(Box::new(event)));
        let mut state = WatchState::default();
        select(records, pods)
            .flat_map(move |watched| {
                let events = match watched {
                    Watched::Record(event) => state.record(*event),
                    Watched::Pod(event) => state.pod(*event),
                };
                stream::iter(events.into_iter().map(Ok))
            })
            .boxed()
    }
}

/// One watcher event, tagged with the watch that produced it. Both events are boxed so the
/// enum stays small.
enum Watched {
    Record(Box<Event<Lease>>),
    Pod(Box<Event<Pod>>),
}

/// Logs a watcher error and drops it, so the watch goes on. kube-runtime restarts the watch
/// after an error.
fn survive_watch_error<K>(
    name: &'static str,
    result: Result<Event<K>, watcher::Error>,
) -> Option<Event<K>> {
    match result {
        Ok(event) => Some(event),
        Err(error) => {
            warn!(watcher = name, error = %error, "Kubernetes watcher error; the watch continues");
            None
        }
    }
}

/// The records and pods a watch has seen so far, and the sandbox events they produce.
///
/// Each watcher event becomes the [`WatchSandboxesEvent`]s it produces:
/// - a record applied reports its sandbox's snapshot, when the record is accepted;
/// - a record deleted reports the deletion of its sandbox, and forgets the record;
/// - a record relist (`Init` to `InitDone`) forgets each known record it did not return,
///   and reports the deletion of each forgotten record's sandbox;
/// - a pod applied or deleted reports the snapshot of its controlling record, when that
///   record is known. A pod seen before its record is kept, so the record's snapshot
///   includes it once the record arrives;
/// - a pod relist (`Init` to `InitDone`) forgets each known pod it did not return, and
///   reports nothing.
#[derive(Debug, Default)]
pub struct WatchState {
    records: Vec<Lease>,
    pods: Vec<Pod>,
    /// The names of the records returned so far by the record relist in progress, if any.
    listed_records: Option<BTreeSet<Option<String>>>,
    /// The names of the pods returned so far by the pod relist in progress, if any.
    listed_pods: Option<BTreeSet<Option<String>>>,
}

impl WatchState {
    /// Applies a watcher event for a sandbox record.
    pub fn record(&mut self, event: Event<Lease>) -> Vec<WatchSandboxesEvent> {
        match event {
            Event::Apply(record) | Event::InitApply(record) => {
                if let Some(listed) = &mut self.listed_records {
                    listed.insert(record.metadata.name.clone());
                }
                let snapshot = sandbox_from_record(&record, &self.pods).map(sandbox_event);
                self.records
                    .retain(|known| known.metadata.name != record.metadata.name);
                self.records.push(record);
                snapshot.into_iter().collect()
            }
            Event::Delete(record) => {
                self.records
                    .retain(|known| known.metadata.name != record.metadata.name);
                record_sandbox_id(&record)
                    .map(deleted_event)
                    .into_iter()
                    .collect()
            }
            Event::Init => {
                self.listed_records = Some(BTreeSet::new());
                Vec::new()
            }
            Event::InitDone => {
                let Some(listed) = self.listed_records.take() else {
                    return Vec::new();
                };
                let (kept, gone): (Vec<Lease>, Vec<Lease>) = std::mem::take(&mut self.records)
                    .into_iter()
                    .partition(|record| listed.contains(&record.metadata.name));
                self.records = kept;
                gone.iter()
                    .filter_map(record_sandbox_id)
                    .map(deleted_event)
                    .collect()
            }
        }
    }

    /// Applies a watcher event for a sandbox pod.
    pub fn pod(&mut self, event: Event<Pod>) -> Vec<WatchSandboxesEvent> {
        match event {
            Event::Apply(pod) | Event::InitApply(pod) => {
                if let Some(listed) = &mut self.listed_pods {
                    listed.insert(pod.metadata.name.clone());
                }
                let owner = controller_uid(&pod).map(str::to_owned);
                self.pods
                    .retain(|known| known.metadata.name != pod.metadata.name);
                self.pods.push(pod);
                owner
                    .and_then(|uid| self.record_snapshot(&uid))
                    .into_iter()
                    .collect()
            }
            Event::Delete(pod) => {
                let owner = controller_uid(&pod).map(str::to_owned);
                self.pods
                    .retain(|known| known.metadata.name != pod.metadata.name);
                owner
                    .and_then(|uid| self.record_snapshot(&uid))
                    .into_iter()
                    .collect()
            }
            Event::Init => {
                self.listed_pods = Some(BTreeSet::new());
                Vec::new()
            }
            Event::InitDone => {
                if let Some(listed) = self.listed_pods.take() {
                    self.pods.retain(|pod| listed.contains(&pod.metadata.name));
                }
                Vec::new()
            }
        }
    }

    /// Returns the snapshot of the known record whose UID is `uid`, from the pods held now.
    fn record_snapshot(&self, uid: &str) -> Option<WatchSandboxesEvent> {
        let record = self
            .records
            .iter()
            .find(|record| record.metadata.uid.as_deref() == Some(uid))?;
        sandbox_from_record(record, &self.pods).map(sandbox_event)
    }
}

/// Wraps a snapshot in a sandbox event.
fn sandbox_event(sandbox: DriverSandbox) -> WatchSandboxesEvent {
    WatchSandboxesEvent {
        payload: Some(watch_sandboxes_event::Payload::Sandbox(
            WatchSandboxesSandboxEvent {
                sandbox: Some(sandbox),
            },
        )),
    }
}

/// Returns the event that reports sandbox `sandbox_id` deleted.
fn deleted_event(sandbox_id: &str) -> WatchSandboxesEvent {
    WatchSandboxesEvent {
        payload: Some(watch_sandboxes_event::Payload::Deleted(
            WatchSandboxesDeletedEvent {
                sandbox_id: sandbox_id.to_owned(),
            },
        )),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use k8s_openapi::Resource;
    use k8s_openapi::api::coordination::v1::Lease;
    use k8s_openapi::api::core::v1::{Pod, PodCondition, PodStatus};
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference, Time};
    use k8s_openapi::chrono::DateTime;
    use kube::runtime::watcher::Event;
    use openshell_core::driver_utils::{
        LABEL_GATEWAY_ID, LABEL_MANAGED_BY, LABEL_SANDBOX_ID, LABEL_SANDBOX_NAME,
        LABEL_SANDBOX_WORKSPACE,
    };
    use openshell_core::proto::compute::v1::{
        DriverCondition, DriverSandbox, DriverSandboxSpec, WatchSandboxesEvent,
        watch_sandboxes_event,
    };

    use super::{
        WatchState, lookup_selector, record_owner_reference, record_sandbox_id, record_selector,
        sandbox_from_record, sandbox_record,
    };
    use crate::conditions::{
        CONDITION_POD_READY, CONDITION_READY, REASON_POD_READY, REASON_SANDBOX_READY,
        sandbox_conditions,
    };
    use crate::error::DriverError;
    use crate::template::upstream::BOUNDARY_ROLE_LABEL;

    const NAMESPACE: &str = "sandboxes";
    const GATEWAY: &str = "gateway-a";
    const RECORD_UID: &str = "record-uid";
    const SECOND_RECORD_UID: &str = "second-record-uid";

    fn sandbox() -> DriverSandbox {
        DriverSandbox {
            id: "sbx-1".into(),
            name: "agent-one".into(),
            namespace: "unused-namespace".into(),
            spec: Some(DriverSandboxSpec {
                environment: [("API_KEY".to_owned(), "env-secret-value".to_owned())].into(),
                sandbox_token: "launch-token-bytes".into(),
                ..Default::default()
            }),
            status: None,
            workspace: "team-a".into(),
        }
    }

    /// The record for `sandbox()`, with the UID the API server would assign.
    fn record() -> Lease {
        let mut record = sandbox_record(NAMESPACE, GATEWAY, &sandbox());
        record.metadata.uid = Some(RECORD_UID.into());
        record
    }

    fn owner(kind: &str, uid: &str, controller: Option<bool>) -> OwnerReference {
        OwnerReference {
            api_version: Lease::API_VERSION.into(),
            kind: kind.into(),
            name: "agent-one".into(),
            uid: uid.into(),
            controller,
            block_owner_deletion: Some(true),
        }
    }

    /// A running pod with a `Ready` condition of `True`, carrying `role` and `owner`.
    fn pod(name: &str, role: &str, owner: OwnerReference) -> Pod {
        Pod {
            metadata: ObjectMeta {
                name: Some(name.into()),
                labels: Some(BTreeMap::from([(BOUNDARY_ROLE_LABEL.into(), role.into())])),
                owner_references: Some(vec![owner]),
                ..Default::default()
            },
            status: Some(PodStatus {
                phase: Some("Running".into()),
                conditions: Some(vec![PodCondition {
                    type_: "Ready".into(),
                    status: "True".into(),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// The pod `name` owned by the record as its controller.
    fn record_pod(name: &str, role: &str) -> Pod {
        pod(name, role, owner("Lease", RECORD_UID, Some(true)))
    }

    fn condition<'a>(conditions: &'a [DriverCondition], kind: &str) -> &'a DriverCondition {
        conditions
            .iter()
            .find(|condition| condition.r#type == kind)
            .expect("condition present")
    }

    /// The record for sandbox `sbx-2`, a second record in the same gateway.
    fn second_record() -> Lease {
        let mut record = sandbox_record(
            NAMESPACE,
            GATEWAY,
            &DriverSandbox {
                id: "sbx-2".into(),
                name: "agent-two".into(),
                namespace: "unused-namespace".into(),
                spec: None,
                status: None,
                workspace: "team-a".into(),
            },
        );
        record.metadata.uid = Some(SECOND_RECORD_UID.into());
        record
    }

    /// A workload or supervisor pod controlled by the second record.
    fn second_record_pod(name: &str, role: &str) -> Pod {
        pod(name, role, owner("Lease", SECOND_RECORD_UID, Some(true)))
    }

    /// The sandbox snapshot a watch call produced. Panics unless it produced exactly one
    /// event, and that event is not a deletion.
    fn watched_snapshot(events: Vec<WatchSandboxesEvent>) -> DriverSandbox {
        let [event] = <[WatchSandboxesEvent; 1]>::try_from(events).expect("one event");
        match event.payload {
            Some(watch_sandboxes_event::Payload::Sandbox(sandbox)) => {
                sandbox.sandbox.expect("snapshot carries a sandbox")
            }
            other => panic!("expected a sandbox snapshot, got {other:?}"),
        }
    }

    /// The sandbox IDs that a watch call deletes. Panics on any snapshot.
    fn deleted_ids(events: Vec<WatchSandboxesEvent>) -> Vec<String> {
        events
            .into_iter()
            .map(|event| match event.payload {
                Some(watch_sandboxes_event::Payload::Deleted(deleted)) => deleted.sandbox_id,
                other => panic!("expected a deletion, got {other:?}"),
            })
            .collect()
    }

    /// The sandbox ID of the one deletion a watch call produced. Panics otherwise.
    fn watched_deletion(events: Vec<WatchSandboxesEvent>) -> String {
        let [sandbox_id] = <[String; 1]>::try_from(deleted_ids(events)).expect("one deletion");
        sandbox_id
    }

    /// The workload instance ID of the snapshot a watch call produced.
    fn watched_instance(events: Vec<WatchSandboxesEvent>) -> String {
        watched_snapshot(events).status.expect("status").instance_id
    }

    #[test]
    fn registry_watch_record_apply_reports_sandbox_snapshot() {
        let mut state = WatchState::default();

        let snapshot = watched_snapshot(state.record(Event::Apply(record())));

        assert_eq!(snapshot.id, "sbx-1");
        assert_eq!(snapshot.workspace, "team-a");
        assert_eq!(snapshot.status.expect("status").instance_id, "");
    }

    #[test]
    fn registry_watch_record_init_apply_reports_sandbox_snapshot() {
        let mut state = WatchState::default();

        let snapshot = watched_snapshot(state.record(Event::InitApply(record())));

        assert_eq!(snapshot.id, "sbx-1");
    }

    #[test]
    fn registry_watch_init_markers_report_nothing() {
        let mut state = WatchState::default();

        assert!(state.record(Event::Init).is_empty());
        assert!(state.record(Event::InitDone).is_empty());
        assert!(state.pod(Event::Init).is_empty());
        assert!(state.pod(Event::InitDone).is_empty());
    }

    #[test]
    fn registry_watch_record_without_identity_reports_nothing() {
        let mut broken = record();
        broken.metadata.annotations = None;
        let mut state = WatchState::default();

        assert!(state.record(Event::Apply(broken)).is_empty());
    }

    #[test]
    fn registry_watch_record_delete_reports_deleted_sandbox() {
        let mut state = WatchState::default();

        assert_eq!(
            watched_deletion(state.record(Event::Delete(record()))),
            "sbx-1"
        );
    }

    #[test]
    fn registry_watch_record_delete_without_sandbox_id_reports_nothing() {
        let mut unlabelled = record();
        unlabelled.metadata.labels = None;
        let mut state = WatchState::default();

        assert!(state.record(Event::Delete(unlabelled)).is_empty());
    }

    #[test]
    fn registry_watch_record_delete_clears_record() {
        let mut state = WatchState::default();
        state.record(Event::Apply(record()));
        state.record(Event::Delete(record()));

        assert!(
            state
                .pod(Event::Apply(record_pod("sbx-1-workload", "workload")))
                .is_empty()
        );
    }

    #[test]
    fn registry_watch_pod_before_record_reports_nothing_then_record_carries_pod() {
        let mut state = WatchState::default();

        assert!(
            state
                .pod(Event::Apply(record_pod("sbx-1-workload", "workload")))
                .is_empty()
        );
        assert_eq!(
            watched_instance(state.record(Event::Apply(record()))),
            "sbx-1-workload"
        );
    }

    #[test]
    fn registry_watch_pod_apply_reports_snapshot_with_pod() {
        let mut state = WatchState::default();
        state.record(Event::Apply(record()));

        let snapshot =
            watched_snapshot(state.pod(Event::Apply(record_pod("sbx-1-workload", "workload"))));

        assert_eq!(
            snapshot.status.expect("status").instance_id,
            "sbx-1-workload"
        );
    }

    #[test]
    fn registry_watch_pod_reapply_replaces_the_pod() {
        let mut state = WatchState::default();
        state.record(Event::Apply(record()));
        state.pod(Event::Apply(record_pod("sbx-1-workload", "workload")));

        let snapshot =
            watched_snapshot(state.pod(Event::Apply(record_pod("sbx-1-workload", "supervisor"))));

        assert_eq!(snapshot.status.expect("status").instance_id, "");
    }

    #[test]
    fn registry_watch_record_reapply_replaces_the_record() {
        let mut state = WatchState::default();
        state.record(Event::Apply(record()));
        let mut deleting = record();
        deleting.metadata.deletion_timestamp = Some(Time(
            DateTime::from_timestamp(1, 0).expect("valid timestamp"),
        ));
        state.record(Event::Apply(deleting));

        let snapshot =
            watched_snapshot(state.pod(Event::Apply(record_pod("sbx-1-workload", "workload"))));

        assert!(snapshot.status.expect("status").deleting);
    }

    #[test]
    fn registry_watch_pod_delete_reports_snapshot_without_pod() {
        let mut state = WatchState::default();
        state.record(Event::Apply(record()));
        state.pod(Event::Apply(record_pod("sbx-1-workload", "workload")));

        let snapshot =
            watched_snapshot(state.pod(Event::Delete(record_pod("sbx-1-workload", "workload"))));

        assert_eq!(snapshot.status.expect("status").instance_id, "");
    }

    #[test]
    fn registry_watch_pod_of_another_record_reports_nothing() {
        let mut state = WatchState::default();
        state.record(Event::Apply(record()));
        let stranger = pod(
            "stranger",
            "workload",
            owner("Lease", "other-uid", Some(true)),
        );

        assert!(state.pod(Event::Apply(stranger.clone())).is_empty());
        assert!(state.pod(Event::Delete(stranger)).is_empty());
    }

    #[test]
    fn registry_watch_relist_reports_deleted_records_it_did_not_return() {
        let mut state = WatchState::default();
        state.record(Event::Apply(record()));
        state.record(Event::Apply(second_record()));

        assert!(state.record(Event::Init).is_empty());
        assert_eq!(
            watched_snapshot(state.record(Event::InitApply(record()))).id,
            "sbx-1"
        );
        assert_eq!(deleted_ids(state.record(Event::InitDone)), vec!["sbx-2"]);
        assert!(
            state
                .pod(Event::Apply(second_record_pod(
                    "sbx-2-workload",
                    "workload"
                )))
                .is_empty()
        );
    }

    #[test]
    fn registry_watch_relist_that_returns_every_record_reports_no_deletion() {
        let mut state = WatchState::default();
        state.record(Event::Apply(record()));
        state.record(Event::Apply(second_record()));

        state.record(Event::Init);
        state.record(Event::InitApply(record()));
        state.record(Event::InitApply(second_record()));

        assert!(state.record(Event::InitDone).is_empty());
        assert_eq!(
            watched_instance(state.pod(Event::Apply(second_record_pod(
                "sbx-2-workload",
                "workload"
            )))),
            "sbx-2-workload"
        );
    }

    #[test]
    fn registry_watch_pod_relist_forgets_pods_it_did_not_return() {
        let mut state = WatchState::default();
        state.record(Event::Apply(record()));
        state.pod(Event::Apply(record_pod("sbx-1-workload", "workload")));

        assert!(state.pod(Event::Init).is_empty());
        state.pod(Event::InitApply(record_pod(
            "sbx-1-supervisor",
            "supervisor",
        )));
        assert!(state.pod(Event::InitDone).is_empty());

        let snapshot =
            watched_snapshot(state.pod(Event::Apply(record_pod("sbx-1-supervisor", "supervisor"))));

        assert_eq!(snapshot.status.expect("status").instance_id, "");
    }

    #[test]
    fn registry_lookup_selector_admits_only_label_values() {
        assert_eq!(
            lookup_selector(GATEWAY, "sbx-1").as_deref(),
            Some(
                "openshell.ai/managed-by=openshell,openshell.ai/component=sandbox-record,openshell.ai/gateway-id=gateway-a,openshell.ai/sandbox-id=sbx-1"
            )
        );
        assert!(lookup_selector(GATEWAY, &"a".repeat(63)).is_some());
        assert_eq!(lookup_selector(GATEWAY, &"a".repeat(64)), None);
        assert_eq!(
            lookup_selector(GATEWAY, "sbx-1,openshell.ai/sandbox-id"),
            None
        );
        assert_eq!(lookup_selector(GATEWAY, "sbx=1"), None);
    }

    #[test]
    fn registry_record_carries_identity_labels_and_annotations() {
        let record = record();

        assert_eq!(record.metadata.name.as_deref(), Some("agent-one"));
        assert_eq!(record.metadata.namespace.as_deref(), Some(NAMESPACE));
        assert_eq!(
            record.metadata.labels,
            Some(BTreeMap::from([
                (LABEL_MANAGED_BY.to_owned(), "openshell".to_owned()),
                (
                    "openshell.ai/component".to_owned(),
                    "sandbox-record".to_owned(),
                ),
                (LABEL_SANDBOX_ID.to_owned(), "sbx-1".to_owned()),
                (LABEL_GATEWAY_ID.to_owned(), GATEWAY.to_owned()),
            ]))
        );
        assert_eq!(
            record.metadata.annotations,
            Some(BTreeMap::from([
                (LABEL_SANDBOX_NAME.to_owned(), "agent-one".to_owned()),
                (LABEL_SANDBOX_WORKSPACE.to_owned(), "team-a".to_owned()),
            ]))
        );
        assert!(record.spec.is_none());
    }

    #[test]
    fn registry_record_omits_spec_content() {
        let json = serde_json::to_string(&record()).expect("serialize record");

        assert!(!json.contains("env-secret-value"));
        assert!(!json.contains("API_KEY"));
        assert!(!json.contains("launch-token-bytes"));
    }

    #[test]
    fn registry_record_selector_names_managed_record_component_and_gateway() {
        assert_eq!(
            record_selector(GATEWAY),
            "openshell.ai/managed-by=openshell,openshell.ai/component=sandbox-record,openshell.ai/gateway-id=gateway-a"
        );
    }

    #[test]
    fn registry_owner_reference_points_at_the_record() {
        let reference = record_owner_reference(&record()).expect("owner reference");

        assert_eq!(
            reference,
            OwnerReference {
                api_version: "coordination.k8s.io/v1".into(),
                kind: "Lease".into(),
                name: "agent-one".into(),
                uid: RECORD_UID.into(),
                controller: Some(true),
                block_owner_deletion: Some(true),
            }
        );
    }

    #[test]
    fn registry_owner_reference_requires_record_name_and_uid() {
        let mut unnamed = record();
        unnamed.metadata.name = None;
        assert!(matches!(
            record_owner_reference(&unnamed),
            Err(DriverError::Message(_))
        ));

        let mut unuided = record();
        unuided.metadata.uid = None;
        assert!(matches!(
            record_owner_reference(&unuided),
            Err(DriverError::Message(_))
        ));
    }

    #[test]
    fn registry_record_sandbox_id_reads_the_id_label() {
        assert_eq!(record_sandbox_id(&record()), Some("sbx-1"));
        assert_eq!(record_sandbox_id(&Lease::default()), None);
    }

    #[test]
    fn registry_sandbox_from_record_without_pods_reports_no_instance() {
        let snapshot = sandbox_from_record(&record(), &[]).expect("sandbox");

        assert_eq!(snapshot.id, "sbx-1");
        assert_eq!(snapshot.name, "agent-one");
        assert_eq!(snapshot.namespace, NAMESPACE);
        assert_eq!(snapshot.workspace, "team-a");
        assert!(snapshot.spec.is_none());
        let status = snapshot.status.expect("status");
        assert_eq!(status.name, "agent-one");
        assert_eq!(status.instance_id, "");
        assert_eq!(status.conditions, sandbox_conditions(None, None));
        assert!(!status.deleting);
    }

    #[test]
    fn registry_sandbox_from_record_with_both_pods_reports_workload_and_conditions() {
        let workload = record_pod("sbx-1-workload", "workload");
        let supervisor = record_pod("sbx-1-supervisor", "supervisor");

        let snapshot = sandbox_from_record(&record(), &[supervisor.clone(), workload.clone()])
            .expect("sandbox");

        let status = snapshot.status.expect("status");
        assert_eq!(status.instance_id, "sbx-1-workload");
        assert_eq!(
            status.conditions,
            sandbox_conditions(Some(&workload), Some(&supervisor))
        );
        assert_eq!(
            condition(&status.conditions, CONDITION_READY).reason,
            REASON_SANDBOX_READY
        );
        assert_eq!(
            condition(&status.conditions, CONDITION_POD_READY).reason,
            REASON_POD_READY
        );
    }

    #[test]
    fn registry_sandbox_from_record_ignores_pods_not_controlled_by_the_record() {
        let pods = [
            pod(
                "other-uid",
                "workload",
                owner("Lease", "other-uid", Some(true)),
            ),
            pod("loose", "workload", owner("Lease", RECORD_UID, None)),
            pod(
                "loose-supervisor",
                "supervisor",
                owner("Lease", RECORD_UID, Some(false)),
            ),
            pod(
                "wrong-kind",
                "workload",
                owner("Pod", RECORD_UID, Some(true)),
            ),
        ];

        let status = sandbox_from_record(&record(), &pods)
            .expect("sandbox")
            .status
            .expect("status");

        assert_eq!(status.instance_id, "");
        assert_eq!(status.conditions, sandbox_conditions(None, None));
    }

    #[test]
    fn registry_sandbox_from_record_reports_a_deleting_record() {
        let mut deleting = record();
        deleting.metadata.deletion_timestamp = Some(Time(
            DateTime::from_timestamp(1, 0).expect("valid timestamp"),
        ));

        let status = sandbox_from_record(&deleting, &[])
            .expect("sandbox")
            .status
            .expect("status");

        assert!(status.deleting);
    }

    #[test]
    fn registry_sandbox_from_record_requires_each_identity_field() {
        let breaks: [fn(&mut Lease); 4] = [
            |record| {
                record
                    .metadata
                    .labels
                    .as_mut()
                    .expect("labels")
                    .remove(LABEL_SANDBOX_ID);
            },
            |record| {
                record
                    .metadata
                    .annotations
                    .as_mut()
                    .expect("annotations")
                    .remove(LABEL_SANDBOX_NAME);
            },
            |record| {
                record
                    .metadata
                    .annotations
                    .as_mut()
                    .expect("annotations")
                    .remove(LABEL_SANDBOX_WORKSPACE);
            },
            |record| record.metadata.name = None,
        ];

        for break_field in breaks {
            let mut broken = record();
            break_field(&mut broken);
            assert!(sandbox_from_record(&broken, &[]).is_none());
        }
    }
}

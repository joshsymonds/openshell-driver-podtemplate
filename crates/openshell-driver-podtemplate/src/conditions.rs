// SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
// SPDX-License-Identifier: Apache-2.0

//! Maps a sandbox's workload and supervisor pods to the driver's conditions.
//!
//! [`sandbox_conditions`] returns two conditions. [`CONDITION_READY`] tells the gateway
//! whether the sandbox is usable. While it is not, it reports a terminal reason only for a
//! pod that has reached a terminal phase without being deleted, and a gateway-transient
//! reason otherwise. A pod being deleted never reports its phase; the reason is
//! `DependenciesNotReady` unless the other pod is terminal. [`CONDITION_POD_READY`] carries
//! the workload pod's raw `Ready` condition, which the template's readiness probe drives.

use k8s_openapi::api::core::v1::{Pod, PodCondition};
use openshell_core::proto::compute::v1::DriverCondition;

/// Condition type for whether the sandbox is usable through the gateway.
pub const CONDITION_READY: &str = "Ready";
/// Condition type for the workload pod's raw readiness.
pub const CONDITION_POD_READY: &str = "PodReady";

/// The workload pod reached the `Failed` phase.
pub const REASON_POD_FAILED: &str = "PodFailed";
/// The workload pod reached the `Succeeded` phase.
pub const REASON_POD_SUCCEEDED: &str = "PodSucceeded";
/// The supervisor pod reached a terminal phase.
pub const REASON_SUPERVISOR_FAILED: &str = "SupervisorFailed";
/// A pod is missing, is being deleted, or the supervisor is not ready.
pub const REASON_DEPENDENCIES_NOT_READY: &str = "DependenciesNotReady";
/// The workload pod is pending: scheduling, init containers, image pull, or container creation.
pub const REASON_CONTAINER_STARTING: &str = "ContainerStarting";
/// The workload pod is running but its `Ready` condition is not true yet.
pub const REASON_HEALTH_CHECK_STARTING: &str = "HealthCheckStarting";
/// The sandbox is ready.
pub const REASON_SANDBOX_READY: &str = "SandboxReady";
/// The `PodReady` condition's reason when the workload pod is absent.
pub const REASON_POD_MISSING: &str = "PodMissing";
/// The `PodReady` condition's reason when the workload pod is ready and its `Ready` condition
/// gives no reason.
pub const REASON_POD_READY: &str = "PodReady";
/// The `PodReady` condition's reason when the workload pod is not ready and its `Ready` condition
/// gives no reason, or when it has no `Ready` condition.
pub const REASON_POD_NOT_READY: &str = "PodNotReady";

/// Returns the `Ready` and `PodReady` conditions for a sandbox.
///
/// `workload` and `supervisor` are the sandbox's pods, or `None` when a pod does not exist.
pub fn sandbox_conditions(
    workload: Option<&Pod>,
    supervisor: Option<&Pod>,
) -> Vec<DriverCondition> {
    vec![
        ready_condition(workload, supervisor),
        pod_ready_condition(workload),
    ]
}

fn ready_condition(workload: Option<&Pod>, supervisor: Option<&Pod>) -> DriverCondition {
    let live_workload = workload.filter(|pod| !is_deleting(pod));
    let live_supervisor = supervisor.filter(|pod| !is_deleting(pod));
    if phase(live_workload) == Some("Failed") {
        return not_ready(
            REASON_POD_FAILED,
            &terminal_message("Workload pod failed", workload),
        );
    }
    if phase(live_workload) == Some("Succeeded") {
        return not_ready(
            REASON_POD_SUCCEEDED,
            &terminal_message("Workload pod succeeded", workload),
        );
    }
    if matches!(phase(live_supervisor), Some("Failed" | "Succeeded")) {
        return not_ready(
            REASON_SUPERVISOR_FAILED,
            &terminal_message("Supervisor pod terminated", supervisor),
        );
    }
    let (Some(workload), Some(supervisor)) = (workload, supervisor) else {
        return not_ready(
            REASON_DEPENDENCIES_NOT_READY,
            "Workload or supervisor pod is missing",
        );
    };
    if is_deleting(workload) {
        return not_ready(
            REASON_DEPENDENCIES_NOT_READY,
            "Workload pod is being deleted",
        );
    }
    if is_deleting(supervisor) {
        return not_ready(
            REASON_DEPENDENCIES_NOT_READY,
            "Supervisor pod is being deleted",
        );
    }
    if matches!(phase(Some(workload)), None | Some("Pending")) {
        return not_ready(REASON_CONTAINER_STARTING, &starting_message(workload));
    }
    if !is_ready(workload) {
        return not_ready(
            REASON_HEALTH_CHECK_STARTING,
            "Workload pod is running but not ready",
        );
    }
    if !is_ready(supervisor) {
        return not_ready(REASON_DEPENDENCIES_NOT_READY, "Supervisor pod is not ready");
    }
    condition(
        CONDITION_READY,
        "True",
        REASON_SANDBOX_READY,
        "Sandbox is ready",
    )
}

fn pod_ready_condition(workload: Option<&Pod>) -> DriverCondition {
    let Some(pod) = workload else {
        return condition(
            CONDITION_POD_READY,
            "Unknown",
            REASON_POD_MISSING,
            "Workload pod is missing",
        );
    };
    let Some(ready) = ready_pod_condition(pod) else {
        return condition(CONDITION_POD_READY, "False", REASON_POD_NOT_READY, "");
    };
    let reason = match ready.reason.as_deref().filter(|reason| !reason.is_empty()) {
        Some(reason) => reason,
        None if ready.status == "True" => REASON_POD_READY,
        None => REASON_POD_NOT_READY,
    };
    DriverCondition {
        r#type: CONDITION_POD_READY.into(),
        status: ready.status.clone(),
        reason: reason.into(),
        message: ready.message.clone().unwrap_or_default(),
        transition_time: ready
            .last_transition_time
            .as_ref()
            .map(|time| prost_types::Timestamp {
                seconds: time.0.timestamp(),
                nanos: time.0.timestamp_subsec_nanos().cast_signed(),
            }),
    }
}

fn condition(kind: &str, status: &str, reason: &str, message: &str) -> DriverCondition {
    DriverCondition {
        r#type: kind.into(),
        status: status.into(),
        reason: reason.into(),
        message: message.into(),
        transition_time: None,
    }
}

fn not_ready(reason: &str, message: &str) -> DriverCondition {
    condition(CONDITION_READY, "False", reason, message)
}

fn phase(pod: Option<&Pod>) -> Option<&str> {
    pod?.status.as_ref()?.phase.as_deref()
}

fn is_deleting(pod: &Pod) -> bool {
    pod.metadata.deletion_timestamp.is_some()
}

fn ready_pod_condition(pod: &Pod) -> Option<&PodCondition> {
    pod.status
        .as_ref()?
        .conditions
        .as_ref()?
        .iter()
        .find(|candidate| candidate.type_ == "Ready")
}

fn is_ready(pod: &Pod) -> bool {
    ready_pod_condition(pod).is_some_and(|ready| ready.status == "True")
}

/// Names the pod in `summary` and appends its status `reason` and `message` when present.
fn terminal_message(summary: &str, pod: Option<&Pod>) -> String {
    let status = pod.and_then(|pod| pod.status.as_ref());
    let details: Vec<&str> = [
        status.and_then(|status| status.reason.as_deref()),
        status.and_then(|status| status.message.as_deref()),
    ]
    .into_iter()
    .flatten()
    .filter(|detail| !detail.is_empty())
    .collect();
    if details.is_empty() {
        summary.to_owned()
    } else {
        format!("{summary}: {}", details.join(": "))
    }
}

/// Names the first waiting container's reason, init containers first, when one exists.
fn starting_message(workload: &Pod) -> String {
    let reason = workload
        .status
        .iter()
        .flat_map(|status| {
            status
                .init_container_statuses
                .iter()
                .flatten()
                .chain(status.container_statuses.iter().flatten())
        })
        .find_map(|container| container.state.as_ref()?.waiting.as_ref())
        .and_then(|waiting| waiting.reason.as_deref())
        .filter(|reason| !reason.is_empty());
    reason.map_or_else(
        || "Waiting for containers to start".to_owned(),
        |reason| format!("Waiting for containers to start: {reason}"),
    )
}

#[cfg(test)]
mod tests {
    use k8s_openapi::api::core::v1::{
        ContainerState, ContainerStateWaiting, ContainerStatus, Pod, PodCondition, PodStatus,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, Time};
    use k8s_openapi::chrono::DateTime;
    use openshell_core::proto::compute::v1::DriverCondition;

    use super::{
        CONDITION_POD_READY, CONDITION_READY, REASON_CONTAINER_STARTING,
        REASON_DEPENDENCIES_NOT_READY, REASON_HEALTH_CHECK_STARTING, REASON_POD_FAILED,
        REASON_POD_MISSING, REASON_POD_NOT_READY, REASON_POD_READY, REASON_POD_SUCCEEDED,
        REASON_SANDBOX_READY, REASON_SUPERVISOR_FAILED, sandbox_conditions,
    };

    fn at(seconds: i64, nanos: u32) -> Time {
        Time(DateTime::from_timestamp(seconds, nanos).expect("valid timestamp"))
    }

    fn ready_condition(status: &str) -> PodCondition {
        PodCondition {
            type_: "Ready".into(),
            status: status.into(),
            ..Default::default()
        }
    }

    fn with_status(status: PodStatus) -> Pod {
        Pod {
            status: Some(status),
            ..Default::default()
        }
    }

    /// A pod in `phase` whose `Ready` condition has status `ready`.
    fn pod(phase: &str, ready: &str) -> Pod {
        with_status(PodStatus {
            phase: Some(phase.into()),
            conditions: Some(vec![ready_condition(ready)]),
            ..Default::default()
        })
    }

    fn running_ready() -> Pod {
        pod("Running", "True")
    }

    fn deleting(mut pod: Pod) -> Pod {
        pod.metadata = ObjectMeta {
            deletion_timestamp: Some(at(1, 0)),
            ..Default::default()
        };
        pod
    }

    fn waiting(reason: Option<&str>) -> ContainerStatus {
        ContainerStatus {
            state: Some(ContainerState {
                waiting: Some(ContainerStateWaiting {
                    reason: reason.map(Into::into),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn conditions_for(workload: Option<&Pod>, supervisor: Option<&Pod>) -> [DriverCondition; 2] {
        sandbox_conditions(workload, supervisor)
            .try_into()
            .expect("two conditions")
    }

    fn assert_state(condition: &DriverCondition, kind: &str, status: &str, reason: &str) {
        assert_eq!(
            (
                condition.r#type.as_str(),
                condition.status.as_str(),
                condition.reason.as_str()
            ),
            (kind, status, reason)
        );
    }

    #[test]
    fn conditions_failed_workload_is_pod_failed() {
        let [ready, _] = conditions_for(Some(&pod("Failed", "False")), Some(&running_ready()));
        assert_state(&ready, CONDITION_READY, "False", REASON_POD_FAILED);
    }

    #[test]
    fn conditions_failed_workload_wins_over_missing_supervisor() {
        let [ready, _] = conditions_for(Some(&pod("Failed", "False")), None);
        assert_state(&ready, CONDITION_READY, "False", REASON_POD_FAILED);
    }

    #[test]
    fn conditions_failed_workload_wins_over_failed_supervisor() {
        let [ready, _] =
            conditions_for(Some(&pod("Failed", "False")), Some(&pod("Failed", "False")));
        assert_state(&ready, CONDITION_READY, "False", REASON_POD_FAILED);
    }

    #[test]
    fn conditions_failed_supervisor_wins_over_missing_workload() {
        let [ready, _] = conditions_for(None, Some(&pod("Failed", "False")));
        assert_state(&ready, CONDITION_READY, "False", REASON_SUPERVISOR_FAILED);
    }

    #[test]
    fn conditions_pending_workload_wins_over_missing_supervisor() {
        let [ready, _] = conditions_for(Some(&pod("Pending", "False")), None);
        assert_state(
            &ready,
            CONDITION_READY,
            "False",
            REASON_DEPENDENCIES_NOT_READY,
        );
    }

    #[test]
    fn conditions_unready_workload_wins_over_unready_supervisor() {
        let [ready, _] = conditions_for(
            Some(&pod("Running", "False")),
            Some(&pod("Running", "False")),
        );
        assert_state(
            &ready,
            CONDITION_READY,
            "False",
            REASON_HEALTH_CHECK_STARTING,
        );
    }

    #[test]
    fn conditions_failed_workload_message_carries_status_detail() {
        let detailed = with_status(PodStatus {
            phase: Some("Failed".into()),
            reason: Some("Evicted".into()),
            message: Some("The node was low on memory.".into()),
            ..Default::default()
        });
        let [ready, _] = conditions_for(Some(&detailed), None);
        assert_eq!(
            ready.message,
            "Workload pod failed: Evicted: The node was low on memory."
        );

        let bare = pod("Failed", "False");
        let [ready, _] = conditions_for(Some(&bare), None);
        assert_eq!(ready.message, "Workload pod failed");
    }

    #[test]
    fn conditions_succeeded_workload_is_pod_succeeded() {
        let [ready, _] = conditions_for(Some(&pod("Succeeded", "False")), Some(&running_ready()));
        assert_state(&ready, CONDITION_READY, "False", REASON_POD_SUCCEEDED);
    }

    #[test]
    fn conditions_succeeded_workload_wins_over_failed_supervisor() {
        let [ready, _] = conditions_for(
            Some(&pod("Succeeded", "False")),
            Some(&pod("Failed", "False")),
        );
        assert_state(&ready, CONDITION_READY, "False", REASON_POD_SUCCEEDED);
    }

    #[test]
    fn conditions_terminal_supervisor_is_supervisor_failed() {
        let [ready, _] = conditions_for(Some(&running_ready()), Some(&pod("Failed", "False")));
        assert_state(&ready, CONDITION_READY, "False", REASON_SUPERVISOR_FAILED);
        assert_eq!(ready.message, "Supervisor pod terminated");

        let [ready, _] = conditions_for(Some(&running_ready()), Some(&pod("Succeeded", "False")));
        assert_state(&ready, CONDITION_READY, "False", REASON_SUPERVISOR_FAILED);
    }

    #[test]
    fn conditions_missing_workload_is_dependencies_not_ready() {
        let [ready, _] = conditions_for(None, Some(&running_ready()));
        assert_state(
            &ready,
            CONDITION_READY,
            "False",
            REASON_DEPENDENCIES_NOT_READY,
        );
        assert_eq!(ready.message, "Workload or supervisor pod is missing");
    }

    #[test]
    fn conditions_missing_supervisor_is_dependencies_not_ready() {
        let [ready, _] = conditions_for(Some(&running_ready()), None);
        assert_state(
            &ready,
            CONDITION_READY,
            "False",
            REASON_DEPENDENCIES_NOT_READY,
        );
    }

    #[test]
    fn conditions_deleting_workload_is_dependencies_not_ready() {
        let [ready, _] = conditions_for(Some(&deleting(running_ready())), Some(&running_ready()));
        assert_state(
            &ready,
            CONDITION_READY,
            "False",
            REASON_DEPENDENCIES_NOT_READY,
        );
        assert_eq!(ready.message, "Workload pod is being deleted");
    }

    #[test]
    fn conditions_deleting_supervisor_is_dependencies_not_ready() {
        let [ready, _] = conditions_for(Some(&running_ready()), Some(&deleting(running_ready())));
        assert_state(
            &ready,
            CONDITION_READY,
            "False",
            REASON_DEPENDENCIES_NOT_READY,
        );
        assert_eq!(ready.message, "Supervisor pod is being deleted");
    }

    #[test]
    fn conditions_deleting_pods_win_over_terminal_phases() {
        let [ready, _] = conditions_for(
            Some(&deleting(pod("Failed", "False"))),
            Some(&running_ready()),
        );
        assert_state(
            &ready,
            CONDITION_READY,
            "False",
            REASON_DEPENDENCIES_NOT_READY,
        );
        assert_eq!(ready.message, "Workload pod is being deleted");
        let [ready, _] = conditions_for(
            Some(&deleting(pod("Succeeded", "False"))),
            Some(&running_ready()),
        );
        assert_state(
            &ready,
            CONDITION_READY,
            "False",
            REASON_DEPENDENCIES_NOT_READY,
        );
        assert_eq!(ready.message, "Workload pod is being deleted");
        let [ready, _] = conditions_for(
            Some(&running_ready()),
            Some(&deleting(pod("Failed", "False"))),
        );
        assert_state(
            &ready,
            CONDITION_READY,
            "False",
            REASON_DEPENDENCIES_NOT_READY,
        );
        assert_eq!(ready.message, "Supervisor pod is being deleted");
    }

    #[test]
    fn conditions_deleting_workload_wins_over_pending_and_unready() {
        for workload in [pod("Pending", "False"), pod("Running", "False")] {
            let [ready, _] = conditions_for(Some(&deleting(workload)), Some(&running_ready()));
            assert_state(
                &ready,
                CONDITION_READY,
                "False",
                REASON_DEPENDENCIES_NOT_READY,
            );
            assert_eq!(ready.message, "Workload pod is being deleted");
        }
    }

    #[test]
    fn conditions_deleting_supervisor_wins_over_unready_supervisor() {
        let [ready, _] = conditions_for(
            Some(&running_ready()),
            Some(&deleting(pod("Running", "False"))),
        );
        assert_state(
            &ready,
            CONDITION_READY,
            "False",
            REASON_DEPENDENCIES_NOT_READY,
        );
        assert_eq!(ready.message, "Supervisor pod is being deleted");
    }

    #[test]
    fn conditions_pending_workload_is_container_starting() {
        let pending = pod("Pending", "False");
        let [ready, _] = conditions_for(Some(&pending), Some(&running_ready()));
        assert_state(&ready, CONDITION_READY, "False", REASON_CONTAINER_STARTING);
        assert_eq!(ready.message, "Waiting for containers to start");
    }

    #[test]
    fn conditions_missing_phase_is_container_starting() {
        let no_phase = with_status(PodStatus::default());
        let [ready, _] = conditions_for(Some(&no_phase), Some(&running_ready()));
        assert_state(&ready, CONDITION_READY, "False", REASON_CONTAINER_STARTING);
    }

    #[test]
    fn conditions_container_starting_reports_first_init_waiting_reason() {
        let pending = with_status(PodStatus {
            phase: Some("Pending".into()),
            init_container_statuses: Some(vec![waiting(Some("ImagePullBackOff"))]),
            container_statuses: Some(vec![waiting(Some("ErrImagePull"))]),
            ..Default::default()
        });
        let [ready, _] = conditions_for(Some(&pending), Some(&running_ready()));
        assert_state(&ready, CONDITION_READY, "False", REASON_CONTAINER_STARTING);
        assert_eq!(
            ready.message,
            "Waiting for containers to start: ImagePullBackOff"
        );
    }

    #[test]
    fn conditions_container_starting_reports_container_waiting_reason() {
        let pending = with_status(PodStatus {
            phase: Some("Pending".into()),
            container_statuses: Some(vec![waiting(Some("ContainerCreating"))]),
            ..Default::default()
        });
        let [ready, _] = conditions_for(Some(&pending), Some(&running_ready()));
        assert_eq!(
            ready.message,
            "Waiting for containers to start: ContainerCreating"
        );
    }

    #[test]
    fn conditions_container_starting_omits_empty_waiting_reason() {
        let pending = with_status(PodStatus {
            phase: Some("Pending".into()),
            container_statuses: Some(vec![waiting(None)]),
            ..Default::default()
        });
        let [ready, _] = conditions_for(Some(&pending), Some(&running_ready()));
        assert_eq!(ready.message, "Waiting for containers to start");
    }

    #[test]
    fn conditions_unready_running_workload_is_health_check_starting() {
        let [ready, _] = conditions_for(Some(&pod("Running", "False")), Some(&running_ready()));
        assert_state(
            &ready,
            CONDITION_READY,
            "False",
            REASON_HEALTH_CHECK_STARTING,
        );

        let no_ready = with_status(PodStatus {
            phase: Some("Running".into()),
            ..Default::default()
        });
        let [ready, _] = conditions_for(Some(&no_ready), Some(&running_ready()));
        assert_state(
            &ready,
            CONDITION_READY,
            "False",
            REASON_HEALTH_CHECK_STARTING,
        );
    }

    #[test]
    fn conditions_unready_supervisor_is_dependencies_not_ready() {
        let supervisor = with_status(PodStatus {
            phase: Some("Running".into()),
            ..Default::default()
        });
        let [ready, _] = conditions_for(Some(&running_ready()), Some(&supervisor));
        assert_state(
            &ready,
            CONDITION_READY,
            "False",
            REASON_DEPENDENCIES_NOT_READY,
        );
        assert_eq!(ready.message, "Supervisor pod is not ready");
    }

    #[test]
    fn conditions_ready_pods_are_sandbox_ready() {
        let [ready, pod_ready] = conditions_for(Some(&running_ready()), Some(&running_ready()));
        assert_state(&ready, CONDITION_READY, "True", REASON_SANDBOX_READY);
        assert_eq!(ready.message, "Sandbox is ready");
        assert!(ready.transition_time.is_none());
        assert_state(&pod_ready, CONDITION_POD_READY, "True", REASON_POD_READY);
    }

    #[test]
    fn conditions_non_terminal_reasons_are_gateway_transient() {
        // Copy of the gateway's non-terminal reasons (openshell-server
        // compute/mod.rs, is_terminal_failure_reason). Compared case-insensitively.
        const TRANSIENT: [&str; 8] = [
            "reconcilererror",
            "dependenciesnotready",
            "supervisornotconnected",
            "starting",
            "containerstarting",
            "containercreated",
            "healthcheckstarting",
            "inspectfailed",
        ];
        let pending = with_status(PodStatus {
            phase: Some("Pending".into()),
            ..Default::default()
        });
        let cases: Vec<(Option<Pod>, Option<Pod>)> = vec![
            (Some(pending), Some(running_ready())),
            (Some(pod("Running", "False")), Some(running_ready())),
            (Some(running_ready()), Some(pod("Running", "False"))),
            (None, Some(running_ready())),
            (Some(running_ready()), None),
            (Some(deleting(running_ready())), Some(running_ready())),
            (Some(running_ready()), Some(deleting(running_ready()))),
        ];
        for (workload, supervisor) in &cases {
            let [ready, _] = conditions_for(workload.as_ref(), supervisor.as_ref());
            assert_eq!(ready.status, "False");
            let reason = ready.reason.to_ascii_lowercase();
            assert!(
                TRANSIENT.contains(&reason.as_str()),
                "{} is not a gateway-transient reason",
                ready.reason
            );
        }
    }

    #[test]
    fn conditions_pod_ready_missing_workload_is_unknown() {
        let [_, pod_ready] = conditions_for(None, Some(&running_ready()));
        assert_state(
            &pod_ready,
            CONDITION_POD_READY,
            "Unknown",
            REASON_POD_MISSING,
        );
        assert!(pod_ready.transition_time.is_none());
    }

    #[test]
    fn conditions_pod_ready_copies_workload_ready_condition() {
        let workload = with_status(PodStatus {
            phase: Some("Running".into()),
            conditions: Some(vec![PodCondition {
                type_: "Ready".into(),
                status: "False".into(),
                reason: Some("ContainersNotReady".into()),
                message: Some("containers with unready status: [app]".into()),
                last_transition_time: Some(at(1_700_000_000, 123_456_789)),
                ..Default::default()
            }]),
            ..Default::default()
        });
        let [_, pod_ready] = conditions_for(Some(&workload), Some(&running_ready()));
        assert_state(
            &pod_ready,
            CONDITION_POD_READY,
            "False",
            "ContainersNotReady",
        );
        assert_eq!(pod_ready.message, "containers with unready status: [app]");
        let transition = pod_ready.transition_time.expect("transition time");
        assert_eq!(
            (transition.seconds, transition.nanos),
            (1_700_000_000, 123_456_789)
        );
    }

    #[test]
    fn conditions_pod_ready_reason_defaults_from_status() {
        let ready_without_reason = pod("Running", "True");
        let [_, pod_ready] = conditions_for(Some(&ready_without_reason), None);
        assert_state(&pod_ready, CONDITION_POD_READY, "True", REASON_POD_READY);

        let not_ready_empty_reason = with_status(PodStatus {
            phase: Some("Running".into()),
            conditions: Some(vec![PodCondition {
                type_: "Ready".into(),
                status: "False".into(),
                reason: Some(String::new()),
                ..Default::default()
            }]),
            ..Default::default()
        });
        let [_, pod_ready] = conditions_for(Some(&not_ready_empty_reason), None);
        assert_state(
            &pod_ready,
            CONDITION_POD_READY,
            "False",
            REASON_POD_NOT_READY,
        );
    }

    #[test]
    fn conditions_pod_ready_without_ready_condition_is_pod_not_ready() {
        let no_conditions = with_status(PodStatus {
            phase: Some("Running".into()),
            ..Default::default()
        });
        let [_, pod_ready] = conditions_for(Some(&no_conditions), None);
        assert_state(
            &pod_ready,
            CONDITION_POD_READY,
            "False",
            REASON_POD_NOT_READY,
        );
        assert!(pod_ready.transition_time.is_none());
    }
}

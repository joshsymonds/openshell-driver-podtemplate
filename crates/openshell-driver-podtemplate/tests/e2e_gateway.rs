// SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
// SPDX-License-Identifier: Apache-2.0

//! Kind-backed tests of the podtemplate driver through the stock `OpenShell` v0.1.5 gateway.
//!
//! `odp-e2e` installs the gateway with the driver sidecar, applies the fixtures and forwards the
//! gateway port to `ODP_GATEWAY_ENDPOINT` before this binary runs. `e2e_gateway_smoke` creates one
//! sandbox from the fixture `PodTemplate` through the gateway's public API, observes the objects
//! the driver made, deletes the sandbox through the gateway and observes that nothing of it
//! remains. `e2e_gateway_no_residue` creates one sandbox the same way, waits for the gateway to
//! report it `READY` and its workload pod to be Ready, records every Lease, pod, Service, Secret
//! and `EndpointSlice` that carries its labels, deletes it through the gateway and observes that,
//! once garbage collection settles, none of them remains.
//! `e2e_gateway_ready` creates one sandbox the same way, waits for the gateway to report
//! it `READY`, and checks the workload pod, its fence and its supervisor pod.
//! `e2e_gateway_probe_parity` removes and restores the fixture's `ready` file through the
//! gateway's `ExecSandbox` and observes the workload pod's `Ready` condition follow the probe,
//! while the gateway never reports the sandbox `ERROR`.
//! `e2e_gateway_credentials` creates a `PodTemplate` derived from the fixture whose main process
//! records its environment in the served emptyDir before it runs `httpd`, creates one sandbox from
//! it, and reads that record through the gateway's `ExecSandbox`, finding the fixture Secret's
//! value under `FIXTURE_TOKEN`. It then observes that neither the raw value nor its base64 form
//! occurs in any Lease, Secret, Service, `NetworkPolicy` or pod the driver made, or in the driver
//! sidecar's log.
//! `e2e_gateway_reject` creates sandboxes from the invalid `PodTemplate`s of
//! `invalid-templates.yaml`, one per `DESIGN.md` section 6 rule, and observes that the gateway
//! rejects each one and that the driver makes nothing for it.
//! `e2e_gateway_egress_allowed` creates one sandbox from the fixture `PodTemplate` with the
//! fixture policy of `deploy/fixture/policy.yaml`, and runs through `ExecSandbox` an HTTP request
//! to the HTTP echo and a raw-TCP exchange with the TCP echo, both named by that policy, and
//! observes both succeed. `e2e_gateway_egress_denied` runs an HTTP request to an unnamed Service
//! of the same echo pod and one to the pod's IP address in such a sandbox, and observes both fail.
//! `e2e_gateway_egress_init` creates a sandbox from the `PodTemplate` of
//! `podtemplate-init-egress.yaml`, observes that its init container's probe of the TCP echo was
//! recorded as failed, and observes that the same probe from an unfenced pod connects.
//! `e2e_gateway_exit_status` creates two sandboxes from `PodTemplate`s derived from the fixture,
//! whose main processes exit 0 and 3 and that have no readiness probe. It observes that the gateway
//! reports the exit-0 sandbox `Completed` and settles the exit-3 sandbox in a phase other than
//! `Provisioning` or `Ready`, and prints the gateway phase and the workload pod's phase of each.
//! `e2e_gateway_restart` creates two sandboxes and waits until both are `READY`, then sends SIGTERM
//! to the driver sidecar's PID 1 and observes its `restartCount` rise within 20 seconds, and deletes
//! the gateway pod and waits for its replacement. After each restart it observes that the gateway
//! lists each sandbox exactly once, returns it from `GetSandbox`, delivers its snapshot on
//! `WatchSandbox`, and that the driver's labelled objects keep their UIDs.
//! `e2e_gateway_stop_start` creates one sandbox and waits until it is `READY`, stops it through
//! `StopSandbox` and observes its pods and bootstrap Secrets gone and its Lease kept, then starts
//! it through `StartSandbox` and observes new pods, bootstrap Secrets of a new generation and the
//! same Lease, and prints the generation suffixes before and after the start.

#[path = "support/gateway.rs"]
mod gateway;

use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use k8s_openapi::api::coordination::v1::Lease;
use k8s_openapi::api::core::v1::{Pod, PodTemplate};
use k8s_openapi::api::networking::v1::NetworkPolicy;
use kube::api::ListParams;
use kube::{Api, Client, ResourceExt};
use openshell_core::proto::SandboxPhase;
use openshell_core::proto::open_shell_client::OpenShellClient;
use openshell_driver_podtemplate::runtime_objects::SandboxRuntimeNames;
use tonic::Code;
use tonic::transport::Channel;

/// The invalid `PodTemplate`s of `invalid-templates.yaml`, each breaking one template rule of
/// `DESIGN.md` section 6, by rule number.
const REJECTED_TEMPLATES: [(u8, &str); 9] = [
    (1, "odp-rule-1"),
    (2, "odp-rule-2"),
    (3, "odp-rule-3"),
    (4, "odp-rule-4"),
    (5, "odp-rule-5"),
    (6, "odp-rule-6"),
    (7, "odp-rule-7"),
    (8, "odp-rule-8"),
    (9, "odp-rule-9"),
];

#[tokio::test]
async fn e2e_gateway_smoke() {
    let kube = gateway::kube_client().await;
    let credential = gateway::fixture_credential(&kube).await;
    let mut client = gateway::connect(&kube).await;
    let name = gateway::sandbox_name("odp-smoke");

    let created = client
        .create_sandbox(gateway::create_request(&name, gateway::FIXTURE_TEMPLATE))
        .await
        .expect("CreateSandbox through the gateway")
        .into_inner();
    let metadata = created
        .sandbox
        .and_then(|sandbox| sandbox.metadata)
        .expect("CreateSandbox returns the sandbox");
    assert_eq!(metadata.name, name, "the sandbox keeps the requested name");
    let id = metadata.id;
    assert!(!id.is_empty(), "the gateway assigns the sandbox an ID");

    let lease: Lease = gateway::await_object(&kube, &name, "the sandbox's Lease").await;
    assert_eq!(
        lease.labels().get(gateway::LABEL_SANDBOX_ID),
        Some(&id),
        "the Lease carries the sandbox ID"
    );

    let pod: Pod = gateway::await_object(&kube, &name, "the workload pod").await;
    let runs_fixture_image = pod
        .spec
        .iter()
        .flat_map(|spec| &spec.containers)
        .any(|container| container.image.as_deref() == Some(gateway::FIXTURE_IMAGE));
    assert!(
        runs_fixture_image,
        "the workload pod runs the fixture image"
    );

    let objects = gateway::sandbox_objects(&kube, &name, &id).await;
    for expected in [format!("Lease/{name}"), format!("Pod/{name}")] {
        assert!(
            objects.iter().any(|(object, _)| *object == expected),
            "{expected} exists before the delete"
        );
    }
    assert!(
        objects
            .iter()
            .all(|(_, encoded)| !encoded.contains(&credential)),
        "no object the driver wrote carries the fixture credential"
    );

    gateway::delete_sandbox(&client, &kube, &name, &id).await;
}

#[tokio::test]
async fn e2e_gateway_no_residue() {
    let kube = gateway::kube_client().await;
    let mut client = gateway::connect(&kube).await;
    let name = gateway::sandbox_name("odp-res");

    let created = client
        .create_sandbox(gateway::create_request(&name, gateway::FIXTURE_TEMPLATE))
        .await
        .expect("CreateSandbox through the gateway")
        .into_inner();
    let id = created
        .sandbox
        .and_then(|sandbox| sandbox.metadata)
        .map(|metadata| metadata.id)
        .expect("CreateSandbox returns the sandbox");
    assert!(!id.is_empty(), "the gateway assigns the sandbox an ID");

    gateway::await_ready(&client, &name).await;
    gateway::await_ready_pod(&kube, &name).await;

    let runtime = SandboxRuntimeNames::new(&id);
    let recorded = gateway::labelled_objects(&kube, &id, &runtime.boundary_service).await;
    for expected in [
        format!("Lease/{name}"),
        format!("Pod/{name}"),
        format!("Pod/{}", runtime.supervisor_pod),
        format!("Service/{}", runtime.boundary_service),
    ] {
        assert!(
            recorded.contains(&expected),
            "{expected} carries the sandbox's labels before the delete, recorded: {recorded:?}"
        );
    }
    for secret in [&runtime.sandbox_secret, &runtime.supervisor_secret] {
        let prefix = format!("Secret/{secret}-");
        assert!(
            recorded.iter().any(|object| object.starts_with(&prefix)),
            "a {prefix}<generation> bootstrap Secret carries the sandbox's labels before the delete, recorded: {recorded:?}"
        );
    }
    let slice_prefix = format!("EndpointSlice/{}-", runtime.boundary_service);
    assert!(
        recorded
            .iter()
            .any(|object| object.starts_with(&slice_prefix)),
        "the boundary Service's EndpointSlice carries the sandbox's labels before the delete, recorded: {recorded:?}"
    );

    gateway::delete_sandbox(&client, &kube, &name, &id).await;
    gateway::await_unlabelled(&kube, &id, &runtime.boundary_service).await;
}

#[tokio::test]
async fn e2e_gateway_ready() {
    let kube = gateway::kube_client().await;
    let credential = gateway::fixture_credential(&kube).await;
    let template = Api::<PodTemplate>::namespaced(kube.clone(), gateway::SANDBOX_NAMESPACE)
        .get(gateway::FIXTURE_TEMPLATE)
        .await
        .expect("read the fixture PodTemplate");
    let mut client = gateway::connect(&kube).await;
    let name = gateway::sandbox_name("odp-ready");

    let started = Instant::now();
    let created = client
        .create_sandbox(gateway::create_request(&name, gateway::FIXTURE_TEMPLATE))
        .await
        .expect("CreateSandbox through the gateway")
        .into_inner();
    let id = created
        .sandbox
        .and_then(|sandbox| sandbox.metadata)
        .map(|metadata| metadata.id)
        .expect("CreateSandbox returns the sandbox");
    assert!(!id.is_empty(), "the gateway assigns the sandbox an ID");

    gateway::await_ready(&client, &name).await;
    let workload = gateway::await_ready_pod(&kube, &name).await;
    println!(
        "e2e_gateway_ready: sandbox {name} reached Ready {:.1} s after CreateSandbox",
        started.elapsed().as_secs_f64()
    );

    let pods = Api::<Pod>::namespaced(kube.clone(), gateway::SANDBOX_NAMESPACE);
    assert_workload_fence(&kube, &workload).await;
    let pair = id.to_ascii_lowercase();
    assert_fence_labels(&workload, &pair);
    assert_preserved_fields(&workload, &template, &pair);

    let paired = assert_one_supervisor(&pods, &pair).await;
    for pod in std::iter::once(&workload).chain(&paired) {
        let encoded = serde_json::to_string(pod).expect("encode the pod");
        assert!(
            !encoded.contains(&credential),
            "pod {} carries the fixture credential",
            pod.name_any()
        );
    }

    gateway::delete_sandbox(&client, &kube, &name, &id).await;
}

#[tokio::test]
async fn e2e_gateway_probe_parity() {
    let kube = gateway::kube_client().await;
    let mut client = gateway::connect(&kube).await;
    let name = gateway::sandbox_name("odp-probe");

    let created = client
        .create_sandbox(gateway::create_request(&name, gateway::FIXTURE_TEMPLATE))
        .await
        .expect("CreateSandbox through the gateway")
        .into_inner();
    let id = created
        .sandbox
        .and_then(|sandbox| sandbox.metadata)
        .map(|metadata| metadata.id)
        .expect("CreateSandbox returns the sandbox");
    assert!(!id.is_empty(), "the gateway assigns the sandbox an ID");

    let phases = Arc::new(Mutex::new(Vec::new()));
    let watch = tokio::spawn(gateway::watch_phases(
        client.clone(),
        name.clone(),
        Arc::clone(&phases),
    ));

    gateway::await_ready(&client, &name).await;
    let ready = gateway::await_ready_pod(&kube, &name).await;

    let removed = gateway::exec_in_sandbox(&client, &name, &["rm", "/tmp/bundle/ready"]).await;
    assert_eq!(
        removed.exit_code, 0,
        "ExecSandbox removes the ready file, output: {}",
        removed.output
    );
    let not_ready = gateway::await_unready_pod(&kube, &name).await;
    assert_eq!(
        not_ready.uid(),
        ready.uid(),
        "the pod that went NotReady is the pod that was Ready"
    );

    let restored = gateway::exec_in_sandbox(&client, &name, &["touch", "/tmp/bundle/ready"]).await;
    assert_eq!(
        restored.exit_code, 0,
        "ExecSandbox restores the ready file while the pod is NotReady, output: {}",
        restored.output
    );
    let back = gateway::await_ready_pod(&kube, &name).await;
    assert_eq!(
        back.uid(),
        ready.uid(),
        "the pod that became Ready again is the pod that was Ready"
    );

    assert!(
        !watch.is_finished(),
        "the gateway's watch of the sandbox ended before the delete"
    );
    gateway::delete_sandbox(&client, &kube, &name, &id).await;
    watch.abort();

    let observed = phases
        .lock()
        .expect("the phase record is not poisoned")
        .clone();
    assert!(
        observed.contains(&SandboxPhase::Ready),
        "the gateway reports the sandbox READY, observed {observed:?}"
    );
    assert!(
        !observed.contains(&SandboxPhase::Error),
        "the gateway never reports the sandbox ERROR, observed {observed:?}"
    );
}

/// How long a sandbox must report the same phase before the test takes that phase as settled.
const SETTLE_WINDOW: Duration = Duration::from_secs(15);

/// Creates a sandbox from a `PodTemplate` whose main process exits `exit_code`, waits until the
/// gateway settles its phase, prints the gateway phase and the workload pod's Kubernetes phase,
/// and deletes the sandbox and its template. Returns the settled gateway phase.
async fn run_exit_sandbox(
    kube: &Client,
    client: &OpenShellClient<Channel>,
    prefix: &str,
    exit_code: u8,
) -> SandboxPhase {
    let name = gateway::sandbox_name(prefix);
    let template = format!("{name}-template");
    gateway::create_exit_template(kube, &template, exit_code).await;

    let created = client
        .clone()
        .create_sandbox(gateway::create_request(&name, &template))
        .await
        .expect("CreateSandbox through the gateway")
        .into_inner();
    let id = created
        .sandbox
        .and_then(|sandbox| sandbox.metadata)
        .map(|metadata| metadata.id)
        .expect("CreateSandbox returns the sandbox");
    assert!(!id.is_empty(), "the gateway assigns the sandbox an ID");

    let phase = gateway::await_held_phase(client, &name, SETTLE_WINDOW).await;
    let pod_phase = gateway::workload_pod_phase(kube, &name).await;
    println!(
        "e2e_gateway_exit_status: main process exit {exit_code} ended in phase {phase:?} (workload pod {pod_phase})"
    );

    gateway::delete_ended_sandbox(client, kube, &name, &id).await;
    gateway::delete_template(kube, &template).await;
    phase
}

#[tokio::test]
async fn e2e_gateway_exit_status() {
    let kube = gateway::kube_client().await;
    let client = gateway::connect(&kube).await;

    let success = run_exit_sandbox(&kube, &client, "odp-exit0", 0).await;
    assert_eq!(
        success,
        SandboxPhase::Completed,
        "the sandbox whose main process exits 0 ends in Completed"
    );

    let failure = run_exit_sandbox(&kube, &client, "odp-exit3", 3).await;
    assert!(
        !matches!(failure, SandboxPhase::Provisioning | SandboxPhase::Ready),
        "the sandbox whose main process exits 3 settles in a phase other than Provisioning and Ready, got {failure:?}"
    );
}

/// Returns the `boundary-role` label of `pod`.
fn role(pod: &Pod) -> Option<&str> {
    pod.labels()
        .get(gateway::LABEL_BOUNDARY_ROLE)
        .map(String::as_str)
}

/// Asserts that the namespace workload fence selects the workload pod and allows no egress.
async fn assert_workload_fence(kube: &Client, workload: &Pod) {
    let fence = Api::<NetworkPolicy>::namespaced(kube.clone(), gateway::SANDBOX_NAMESPACE)
        .get(gateway::WORKLOAD_FENCE)
        .await
        .expect("read the workload fence");
    let spec = fence.spec.expect("the workload fence has a spec");

    let selector = spec.pod_selector.match_labels.unwrap_or_default();
    assert_eq!(
        selector
            .get(gateway::LABEL_BOUNDARY_ROLE)
            .map(String::as_str),
        Some(gateway::WORKLOAD_ROLE),
        "the workload fence selects the workload role, got {selector:?}"
    );
    assert!(
        selector
            .iter()
            .all(|(key, value)| workload.labels().get(key) == Some(value)),
        "the workload fence selector {selector:?} matches the workload pod"
    );

    let policy_types = spec.policy_types.unwrap_or_default();
    assert!(
        policy_types.iter().any(|kind| kind.as_str() == "Egress"),
        "the workload fence governs egress, got {policy_types:?}"
    );
    let egress_rules = spec.egress.unwrap_or_default();
    assert!(
        egress_rules.is_empty(),
        "the workload fence allows no egress, got {egress_rules:?}"
    );
}

/// Asserts that the workload pod carries the workload role and the pair label of its sandbox.
fn assert_fence_labels(workload: &Pod, pair: &str) {
    assert_eq!(
        role(workload),
        Some(gateway::WORKLOAD_ROLE),
        "the workload pod carries the workload role"
    );
    assert_eq!(
        workload
            .labels()
            .get(gateway::LABEL_BOUNDARY_PAIR)
            .map(String::as_str),
        Some(pair),
        "the workload pod carries the pair label of its sandbox"
    );
}

/// Asserts that the workload pod keeps the fields `DESIGN.md` section 6 lists as unchanged
/// from the fixture `PodTemplate`, and that the fixture has each field the assertion compares.
fn assert_preserved_fields(workload: &Pod, template: &PodTemplate, pair: &str) {
    let template = template
        .template
        .as_ref()
        .expect("the fixture PodTemplate has a template");
    let template_metadata = template.metadata.clone().unwrap_or_default();

    let mut expected_labels = template_metadata.labels.unwrap_or_default();
    expected_labels.insert(
        gateway::LABEL_BOUNDARY_ROLE.to_owned(),
        gateway::WORKLOAD_ROLE.to_owned(),
    );
    expected_labels.insert(gateway::LABEL_BOUNDARY_PAIR.to_owned(), pair.to_owned());
    assert_eq!(
        workload.labels(),
        &expected_labels,
        "the workload pod has the template labels and the fence labels"
    );
    assert_eq!(
        workload.annotations(),
        &template_metadata.annotations.unwrap_or_default(),
        "the workload pod has the template annotations"
    );

    let pod_spec = workload.spec.as_ref().expect("the workload pod has a spec");
    let template_spec = template
        .spec
        .as_ref()
        .expect("the fixture PodTemplate has a spec");
    assert_eq!(
        pod_spec.node_selector, template_spec.node_selector,
        "the workload pod keeps the template nodeSelector"
    );
    assert_kept(
        "toleration",
        template_spec.tolerations.as_deref(),
        pod_spec.tolerations.as_deref(),
    );
    assert_kept(
        "init container",
        template_spec.init_containers.as_deref(),
        pod_spec.init_containers.as_deref(),
    );
    assert_kept(
        "volume",
        template_spec.volumes.as_deref(),
        pod_spec.volumes.as_deref(),
    );

    let [template_container] = template_spec.containers.as_slice() else {
        panic!("the fixture PodTemplate has one container");
    };
    let container = pod_spec
        .containers
        .iter()
        .find(|container| container.name == template_container.name)
        .expect("the workload pod keeps the template container");
    let template_env = template_container.env.as_deref().unwrap_or_default();
    assert!(
        template_env.iter().any(|var| var.value_from.is_some()),
        "the fixture has an env entry that reads a Secret"
    );
    assert_kept(
        "env entry",
        template_container.env.as_deref(),
        container.env.as_deref(),
    );
    assert!(
        template_container.resources.is_some(),
        "the fixture sets container resources"
    );
    assert_eq!(
        container.resources, template_container.resources,
        "the workload pod keeps the template container resources"
    );
}

/// Asserts that each entry of the template's list appears unchanged in the pod's list.
fn assert_kept<T: PartialEq + Debug>(what: &str, template: Option<&[T]>, pod: Option<&[T]>) {
    let template = template.unwrap_or_default();
    let pod = pod.unwrap_or_default();
    assert!(!template.is_empty(), "the fixture has an {what}");
    for entry in template {
        assert!(
            pod.contains(entry),
            "the workload pod keeps the template {what} {entry:?}, pod has {pod:?}"
        );
    }
}

/// Lists the pods paired with the sandbox by `pair` and asserts that exactly one is its
/// supervisor pod. Returns the paired pods.
async fn assert_one_supervisor(pods: &Api<Pod>, pair: &str) -> Vec<Pod> {
    let paired = pods
        .list(&ListParams::default().labels(&format!("{}={pair}", gateway::LABEL_BOUNDARY_PAIR)))
        .await
        .expect("list the pods paired with the sandbox")
        .items;
    let supervisors: Vec<&str> = paired
        .iter()
        .filter(|pod| role(pod) == Some(gateway::SUPERVISOR_ROLE))
        .map(|pod| pod.metadata.name.as_deref().unwrap_or_default())
        .collect();
    assert_eq!(
        supervisors.len(),
        1,
        "the sandbox has exactly one supervisor pod, got {supervisors:?}"
    );
    paired
}

#[tokio::test]
async fn e2e_gateway_credentials() {
    let kube = gateway::kube_client().await;
    let credential = gateway::fixture_credential(&kube).await;
    let base64 = gateway::base64_form(&credential);
    let mut client = gateway::connect(&kube).await;
    let name = gateway::sandbox_name("odp-cred");
    let template = format!("{name}-template");
    gateway::create_recording_template(&kube, &template).await;

    let created = client
        .create_sandbox(gateway::create_request(&name, &template))
        .await
        .expect("CreateSandbox through the gateway")
        .into_inner();
    let id = created
        .sandbox
        .and_then(|sandbox| sandbox.metadata)
        .map(|metadata| metadata.id)
        .expect("CreateSandbox returns the sandbox");
    assert!(!id.is_empty(), "the gateway assigns the sandbox an ID");

    gateway::await_ready(&client, &name).await;

    let record =
        gateway::exec_in_sandbox(&client, &name, &["cat", gateway::ENVIRONMENT_RECORD]).await;
    assert_eq!(
        record.exit_code, 0,
        "ExecSandbox reads the environment the main process recorded, output: {}",
        record.output
    );
    let expected = format!("FIXTURE_TOKEN={credential}");
    assert!(
        record.output.lines().any(|line| line == expected),
        "the main process's environment carries FIXTURE_TOKEN with the fixture Secret's value, output: {}",
        record.output
    );

    let mut objects = gateway::driver_objects(&kube).await;
    objects.extend(gateway::sandbox_objects(&kube, &name, &id).await);
    let runtime = SandboxRuntimeNames::new(&id);
    for expected in [
        format!("Lease/{name}"),
        format!("Pod/{name}"),
        format!("Pod/{}", runtime.supervisor_pod),
        format!("Service/{}", runtime.boundary_service),
        format!("NetworkPolicy/{}", runtime.workload_policy),
        format!("NetworkPolicy/{}", runtime.supervisor_policy),
    ] {
        assert!(
            objects.iter().any(|(object, _)| *object == expected),
            "{expected} is among the objects checked for the credential"
        );
    }
    for secret in [&runtime.sandbox_secret, &runtime.supervisor_secret] {
        let prefix = format!("Secret/{secret}-");
        assert!(
            objects
                .iter()
                .any(|(object, _)| object.starts_with(&prefix)),
            "a {prefix}<generation> bootstrap Secret is among the objects checked for the credential"
        );
    }
    for (object, encoded) in &objects {
        assert!(
            !encoded.contains(&credential),
            "{object} carries the fixture credential"
        );
        assert!(
            !encoded.contains(&base64),
            "{object} carries the base64 form of the fixture credential"
        );
    }

    gateway::delete_sandbox(&client, &kube, &name, &id).await;
    gateway::delete_template(&kube, &template).await;

    let log = gateway::driver_sidecar_log(&kube).await;
    assert!(
        !log.contains(&credential),
        "the driver sidecar's log carries the fixture credential"
    );
    assert!(
        !log.contains(&base64),
        "the driver sidecar's log carries the base64 form of the fixture credential"
    );
}

#[tokio::test]
async fn e2e_gateway_reject() {
    let kube = gateway::kube_client().await;
    let mut client = gateway::connect(&kube).await;
    let driver_objects = gateway::driver_object_uids(&kube).await;

    for (rule, template) in REJECTED_TEMPLATES {
        let name = gateway::sandbox_name("odp-reject");
        let status = client
            .create_sandbox(gateway::create_request(&name, template))
            .await
            .expect_err("CreateSandbox from an invalid template is rejected");
        assert_eq!(
            status.code(),
            Code::InvalidArgument,
            "{template} is rejected as an invalid argument, got {status}"
        );
        assert!(
            status.message().starts_with(&format!("rule {rule}:")),
            "{template} is rejected by rule {rule}, got {:?}",
            status.message()
        );

        let leftovers: Vec<String> = gateway::named_objects(&kube, &name)
            .await
            .into_iter()
            .map(|(object, _)| object)
            .collect();
        assert!(
            leftovers.is_empty(),
            "the rejection of {template} makes no object named {name}, found {leftovers:?}"
        );

        let status = client
            .get_sandbox(gateway::get_request(&name))
            .await
            .expect_err("GetSandbox finds no sandbox for a rejected create");
        assert_eq!(
            status.code(),
            Code::NotFound,
            "GetSandbox for the rejected {name} is NotFound, got {status}"
        );
    }

    assert_eq!(
        gateway::driver_object_uids(&kube).await,
        driver_objects,
        "rejected creates leave the driver's labelled objects unchanged"
    );
}

#[tokio::test]
async fn e2e_gateway_egress_allowed() {
    let kube = gateway::kube_client().await;
    let mut client = gateway::connect(&kube).await;
    let name = gateway::sandbox_name("odp-egress");

    let created = client
        .create_sandbox(gateway::create_policed_request(
            &name,
            gateway::FIXTURE_TEMPLATE,
        ))
        .await
        .expect("CreateSandbox through the gateway")
        .into_inner();
    let id = created
        .sandbox
        .and_then(|sandbox| sandbox.metadata)
        .map(|metadata| metadata.id)
        .expect("CreateSandbox returns the sandbox");
    assert!(!id.is_empty(), "the gateway assigns the sandbox an ID");

    gateway::await_ready(&client, &name).await;

    let url = format!(
        "http://{}:{}/",
        gateway::ECHO_HTTP_HOST,
        gateway::ECHO_HTTP_PORT
    );
    let http =
        gateway::exec_in_sandbox(&client, &name, &["wget", "-q", "-O", "-", url.as_str()]).await;
    assert_eq!(
        http.exit_code, 0,
        "the policy-named HTTP echo is reachable from the sandbox, output: {}",
        http.output
    );
    assert_eq!(
        http.output.trim(),
        gateway::ECHO_HTTP_BODY,
        "the HTTP echo returns its body"
    );

    let script = format!(
        "printf {} | nc -w 5 {} {}",
        gateway::PROBE_PAYLOAD,
        gateway::ECHO_TCP_HOST,
        gateway::ECHO_TCP_PORT
    );
    let tcp = gateway::exec_in_sandbox(&client, &name, &["sh", "-c", script.as_str()]).await;
    assert_eq!(
        tcp.exit_code, 0,
        "the policy-named TCP echo is reachable from the sandbox, output: {}",
        tcp.output
    );
    assert_eq!(
        tcp.output.trim(),
        gateway::PROBE_PAYLOAD,
        "the TCP echo returns the bytes sent"
    );

    gateway::delete_sandbox(&client, &kube, &name, &id).await;
}

#[tokio::test]
async fn e2e_gateway_egress_denied() {
    let kube = gateway::kube_client().await;
    let mut client = gateway::connect(&kube).await;
    let name = gateway::sandbox_name("odp-denied");

    let created = client
        .create_sandbox(gateway::create_policed_request(
            &name,
            gateway::FIXTURE_TEMPLATE,
        ))
        .await
        .expect("CreateSandbox through the gateway")
        .into_inner();
    let id = created
        .sandbox
        .and_then(|sandbox| sandbox.metadata)
        .map(|metadata| metadata.id)
        .expect("CreateSandbox returns the sandbox");
    assert!(!id.is_empty(), "the gateway assigns the sandbox an ID");

    gateway::await_ready(&client, &name).await;

    let unnamed = format!(
        "http://{}:{}/",
        gateway::ECHO_UNNAMED_HOST,
        gateway::ECHO_HTTP_PORT
    );
    let through_service =
        gateway::exec_in_sandbox(&client, &name, &["wget", "-q", "-O", "-", unnamed.as_str()])
            .await;
    assert_ne!(
        through_service.exit_code, 0,
        "the sandbox cannot reach the unnamed Service, output: {}",
        through_service.output
    );
    assert!(
        !through_service.output.contains(gateway::ECHO_HTTP_BODY),
        "the unnamed Service returns no echo body, output: {}",
        through_service.output
    );

    let pod_ip = gateway::echo_pod_ip(&kube).await;
    let direct = format!("http://{pod_ip}:{}/", gateway::ECHO_HTTP_PORT);
    let direct_connection =
        gateway::exec_in_sandbox(&client, &name, &["wget", "-q", "-O", "-", direct.as_str()]).await;
    assert_ne!(
        direct_connection.exit_code, 0,
        "the sandbox cannot reach the echo pod's IP address, output: {}",
        direct_connection.output
    );
    assert!(
        !direct_connection.output.contains(gateway::ECHO_HTTP_BODY),
        "the echo pod's IP address returns no echo body, output: {}",
        direct_connection.output
    );

    gateway::delete_sandbox(&client, &kube, &name, &id).await;
}

#[tokio::test]
async fn e2e_gateway_egress_init() {
    let kube = gateway::kube_client().await;
    let mut client = gateway::connect(&kube).await;
    let name = gateway::sandbox_name("odp-init");

    let created = client
        .create_sandbox(gateway::create_policed_request(
            &name,
            gateway::EGRESS_TEMPLATE,
        ))
        .await
        .expect("CreateSandbox through the gateway")
        .into_inner();
    let id = created
        .sandbox
        .and_then(|sandbox| sandbox.metadata)
        .map(|metadata| metadata.id)
        .expect("CreateSandbox returns the sandbox");
    assert!(!id.is_empty(), "the gateway assigns the sandbox an ID");

    gateway::await_ready(&client, &name).await;

    let record = gateway::exec_in_sandbox(&client, &name, &["cat", gateway::INIT_RESULT]).await;
    assert_eq!(
        record.exit_code, 0,
        "ExecSandbox reads the init container's record, output: {}",
        record.output
    );
    assert_eq!(
        record.output.trim(),
        "failed",
        "the init container's probe of the TCP echo is recorded as failed"
    );

    let script = format!(
        "printf {} | nc -w 3 {} {}",
        gateway::PROBE_PAYLOAD,
        gateway::ECHO_TCP_ADDRESS,
        gateway::ECHO_TCP_PORT
    );
    let (phase, log) =
        gateway::run_unfenced_pod(&kube, &gateway::sandbox_name("odp-control"), &script).await;
    assert_eq!(
        phase, "Succeeded",
        "the unfenced probe of the TCP echo finishes, log: {log}"
    );
    assert_eq!(
        log.trim(),
        gateway::PROBE_PAYLOAD,
        "the unfenced probe of the TCP echo connects"
    );

    gateway::delete_sandbox(&client, &kube, &name, &id).await;
}

#[tokio::test]
async fn e2e_gateway_restart() {
    let kube = gateway::kube_client().await;
    let mut client = gateway::connect(&kube).await;
    let mut sandboxes = Vec::new();
    for prefix in ["odp-rst-a", "odp-rst-b"] {
        let name = gateway::sandbox_name(prefix);
        let created = client
            .create_sandbox(gateway::create_request(&name, gateway::FIXTURE_TEMPLATE))
            .await
            .expect("CreateSandbox through the gateway")
            .into_inner();
        let id = created
            .sandbox
            .and_then(|sandbox| sandbox.metadata)
            .map(|metadata| metadata.id)
            .expect("CreateSandbox returns the sandbox");
        assert!(!id.is_empty(), "the gateway assigns the sandbox an ID");
        sandboxes.push((name, id));
    }
    for (name, _) in &sandboxes {
        gateway::await_ready(&client, name).await;
    }
    let before = gateway::driver_object_uids(&kube).await;

    let restarts = gateway::driver_restart_count(&kube).await;
    let started = Instant::now();
    gateway::signal_driver(&kube).await;
    let restarted = gateway::await_driver_restart(&kube, restarts).await;
    println!(
        "e2e_gateway_restart: driver container restartCount {restarts} -> {restarted}, {:.1} s after SIGTERM",
        started.elapsed().as_secs_f64()
    );
    assert_restored(
        &kube,
        &client,
        &sandboxes,
        &before,
        "after the driver restart",
    )
    .await;

    gateway::replace_gateway_pod(&kube).await;
    client = gateway::connect_when_listening(&kube).await;
    assert_restored(
        &kube,
        &client,
        &sandboxes,
        &before,
        "after the gateway restart",
    )
    .await;

    for (name, id) in &sandboxes {
        gateway::delete_sandbox(&client, &kube, name, id).await;
    }
}

/// Asserts that the gateway lists each sandbox of `sandboxes` exactly once, returns it from
/// `GetSandbox` and delivers its snapshot on `WatchSandbox`, and that the driver's labelled
/// objects keep the UIDs of `before`. It prints the phase that `GetSandbox` reports for each
/// sandbox, labelled with `stage`.
async fn assert_restored(
    kube: &Client,
    client: &OpenShellClient<Channel>,
    sandboxes: &[(String, String)],
    before: &[String],
    stage: &str,
) {
    let listed = gateway::list_sandbox_ids(client).await;
    for (name, id) in sandboxes {
        let count = listed.iter().filter(|listed_id| *listed_id == id).count();
        assert_eq!(
            count, 1,
            "ListSandboxes lists {name} exactly once {stage}, listed {listed:?}"
        );

        let sandbox = client
            .clone()
            .get_sandbox(gateway::get_request(name))
            .await
            .expect("GetSandbox through the gateway")
            .into_inner()
            .sandbox
            .expect("GetSandbox returns the sandbox");
        let returned = sandbox
            .metadata
            .as_ref()
            .map(|metadata| metadata.id.as_str());
        assert_eq!(
            returned,
            Some(id.as_str()),
            "GetSandbox returns {name} {stage}"
        );
        let phase =
            SandboxPhase::try_from(sandbox.phase()).expect("the gateway reports a known phase");
        println!("e2e_gateway_restart: sandbox {name} is {phase:?} {stage}");

        gateway::await_watch_snapshot(client, name).await;
    }

    let current = gateway::driver_object_uids(kube).await;
    assert_eq!(
        current, before,
        "the driver's labelled objects keep their UIDs {stage}"
    );
}

#[tokio::test]
async fn e2e_gateway_stop_start() {
    let kube = gateway::kube_client().await;
    let mut client = gateway::connect(&kube).await;
    let name = gateway::sandbox_name("odp-stop");

    let created = client
        .create_sandbox(gateway::create_request(&name, gateway::FIXTURE_TEMPLATE))
        .await
        .expect("CreateSandbox through the gateway")
        .into_inner();
    let id = created
        .sandbox
        .and_then(|sandbox| sandbox.metadata)
        .map(|metadata| metadata.id)
        .expect("CreateSandbox returns the sandbox");
    assert!(!id.is_empty(), "the gateway assigns the sandbox an ID");

    gateway::await_ready(&client, &name).await;
    let lease_uid = gateway::await_object::<Lease>(&kube, &name, "the sandbox's Lease")
        .await
        .uid()
        .expect("the Lease has a UID");
    let first_workload = gateway::await_ready_pod(&kube, &name).await;
    let first_supervisor = supervisor_pod(&kube, &id).await;
    let first_secrets = gateway::bootstrap_secret_names(&kube, &id).await;
    assert_eq!(
        first_secrets.len(),
        2,
        "the ready sandbox has its two bootstrap Secrets, got {first_secrets:?}"
    );

    client
        .stop_sandbox(gateway::stop_request(&name))
        .await
        .expect("StopSandbox through the gateway");
    gateway::await_phase(&client, &name, SandboxPhase::Stopped).await;
    gateway::await_runtime_gone(&kube, &id).await;
    assert_lease_kept(&kube, &name, &lease_uid, "after the stop").await;

    client
        .start_sandbox(gateway::start_request(&name))
        .await
        .expect("StartSandbox through the gateway");
    gateway::await_ready(&client, &name).await;
    let second_workload = gateway::await_ready_pod(&kube, &name).await;
    let second_supervisor = supervisor_pod(&kube, &id).await;
    let second_secrets = gateway::bootstrap_secret_names(&kube, &id).await;
    assert_eq!(
        second_secrets.len(),
        2,
        "the restarted sandbox has its two bootstrap Secrets, got {second_secrets:?}"
    );

    assert_ne!(
        second_workload.uid(),
        first_workload.uid(),
        "the start recreates the workload pod"
    );
    assert_ne!(
        second_supervisor.uid(),
        first_supervisor.uid(),
        "the start recreates the supervisor pod"
    );
    assert!(
        second_secrets
            .iter()
            .all(|secret| !first_secrets.contains(secret)),
        "the start creates the bootstrap Secrets of a new generation, got {second_secrets:?} after {first_secrets:?}"
    );
    assert_lease_kept(&kube, &name, &lease_uid, "after the start").await;

    let before = generation_suffix(&first_secrets);
    let after = generation_suffix(&second_secrets);
    println!(
        "e2e_gateway_stop_start: sandbox {name} restarted from generation {before} to {after}"
    );
    assert_ne!(before, after, "the start mints a new generation");

    gateway::delete_sandbox(&client, &kube, &name, &id).await;
}

/// Asserts that the sandbox `name` still has its Lease of UID `uid`, which the stop and the start
/// keep. `stage` names the point of the test in the message.
async fn assert_lease_kept(kube: &Client, name: &str, uid: &str, stage: &str) {
    let lease = Api::<Lease>::namespaced(kube.clone(), gateway::SANDBOX_NAMESPACE)
        .get(name)
        .await
        .expect("the sandbox's Lease remains");
    assert_eq!(
        lease.uid().as_deref(),
        Some(uid),
        "the sandbox keeps its Lease {stage}"
    );
}

/// Returns the supervisor pod of the sandbox with ID `id`, which must be the sandbox's only one.
async fn supervisor_pod(kube: &Client, id: &str) -> Pod {
    let pods = Api::<Pod>::namespaced(kube.clone(), gateway::SANDBOX_NAMESPACE);
    let paired = assert_one_supervisor(&pods, &id.to_ascii_lowercase()).await;
    paired
        .into_iter()
        .find(|pod| role(pod) == Some(gateway::SUPERVISOR_ROLE))
        .expect("the sandbox has a supervisor pod")
}

/// Returns the generation suffix that the bootstrap Secret names of `secrets` end with. The
/// suffix follows the last hyphen of each name, and the two Secrets of a generation share it.
fn generation_suffix(secrets: &[String]) -> &str {
    let suffixes: Vec<&str> = secrets
        .iter()
        .map(|secret| secret.rsplit('-').next().unwrap_or_default())
        .collect();
    assert!(
        suffixes.windows(2).all(|pair| pair[0] == pair[1]),
        "the bootstrap Secrets of one generation share its suffix, got {secrets:?}"
    );
    suffixes[0]
}

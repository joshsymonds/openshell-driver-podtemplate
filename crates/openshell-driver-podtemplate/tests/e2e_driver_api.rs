// SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
// SPDX-License-Identifier: Apache-2.0

//! Kind-backed end-to-end tests of the driver's `ComputeDriver` RPCs.
//!
//! Each test starts the real driver binary on a private Unix socket with its own sandbox
//! namespace, drives it over gRPC, and reads the resulting objects from the kind API server
//! that `KUBECONFIG` names. Each test stops its driver and deletes its namespace.

mod support;

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;

use futures::StreamExt;
use k8s_openapi::ByteString;
use k8s_openapi::api::coordination::v1::Lease;
use k8s_openapi::api::core::v1::{
    Container, Pod, PodSchedulingGate, PodSpec, PodTemplate, Secret, Service, ServicePort,
    ServiceSpec,
};
use k8s_openapi::api::networking::v1::{NetworkPolicy, NetworkPolicySpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{
    DeleteParams, ListParams, Patch, PatchParams, PostParams, WatchEvent, WatchParams,
};
use kube::{Api, Client, ResourceExt};
use openshell_core::extension_protocol::{ExtensionFamily, gateway_metadata};
use openshell_core::proto::compute::v1::compute_driver_client::ComputeDriverClient;
use openshell_core::proto::compute::v1::watch_sandboxes_event::Payload;
use openshell_core::proto::compute::v1::{
    AuthenticateSandboxRequest, CreateSandboxRequest, DeleteSandboxRequest, DeleteWorkspaceRequest,
    DriverCondition, DriverSandbox, EnsureWorkspaceRequest, GetCapabilitiesRequest,
    GetSandboxRequest, ListSandboxesRequest, StartSandboxRequest, StopSandboxRequest,
    ValidateSandboxCreateRequest, WatchSandboxesEvent, WatchSandboxesRequest,
};
use openshell_core::resource_admission::DriverAdmissionConfig;
use openshell_core::sandbox_generation::SandboxGenerationId;
use openshell_driver_podtemplate::runtime_objects::SandboxRuntimeNames;
use prost::Message;
use serde_json::{Value, json};
use support::{
    Case, CreateHold, Driver, GATEWAY_TOKEN, LABEL_BOUNDARY_PAIR, LABEL_BOUNDARY_ROLE,
    LABEL_COMPONENT, LABEL_SANDBOX_ID, OnTimeout, PLAIN_ENV_VALUE, Relay, SANDBOX_IMAGE,
    SANDBOX_TOKEN, TEMPLATE_NAME, USER_SECRET_NAME, USER_SECRET_VALUE, await_gated_runtime,
    await_no_sandbox_residue, create_template, create_user_secret, encode, eventually, get,
    kube_client, launch_authentication, mentions, names, only_pod, pods, residue, secret_mentions,
    token_bound_to, valid_template_spec,
};
use tonic::transport::Channel;
use tonic::{Code, Streaming};

/// Reasons the `Ready` condition may report while a sandbox is not usable yet. Every other
/// reason is terminal.
const TRANSIENT_REASONS: [&str; 3] = [
    "ContainerStarting",
    "HealthCheckStarting",
    "DependenciesNotReady",
];
/// Audience that a sandbox credential must carry.
const GATEWAY_AUDIENCE: &str = "openshell-gateway";
/// Bound of a single watch read.
const WATCH_TIMEOUT: Duration = Duration::from_mins(2);
/// How long the pod watch waits for one more event before a failed create is judged to have
/// added no pod.
const QUIET_WINDOW: Duration = Duration::from_secs(2);
/// The admission policy the driver starts with by default.
const DEFAULT_ADMISSION: &str =
    r#"{"allow_driver_config":true,"resource_admission":{"enabled":false}}"#;

/// Returns the broken variants of the valid template, each with the rule it breaks.
fn broken_templates() -> Vec<(&'static str, Value)> {
    let mut second_container = valid_template_spec();
    second_container["containers"]
        .as_array_mut()
        .expect("containers is an array")
        .push(json!({"name": "sidecar", "image": SANDBOX_IMAGE, "command": ["/bin/true"]}));

    let mut exec_probe = valid_template_spec();
    exec_probe["containers"][0]["readinessProbe"] = json!({"exec": {"command": ["/bin/true"]}});

    let mut host_network = valid_template_spec();
    host_network["hostNetwork"] = json!(true);

    let mut privileged = valid_template_spec();
    privileged["containers"][0]["securityContext"] = json!({"privileged": true});

    let mut host_path = valid_template_spec();
    host_path["volumes"] = json!([{"name": "host", "hostPath": {"path": "/var/lib"}}]);

    let mut root_user = valid_template_spec();
    root_user["securityContext"] = json!({"runAsUser": 0});

    let mut reserved_volume = valid_template_spec();
    reserved_volume["volumes"] = json!([{"name": "openshell-runtime", "emptyDir": {}}]);

    let mut no_command = valid_template_spec();
    let container = no_command["containers"][0]
        .as_object_mut()
        .expect("container is an object");
    container.remove("command");
    container.remove("args");

    let mut other_image = valid_template_spec();
    other_image["containers"][0]["image"] = json!("registry.e2e.invalid/other:e2e");

    vec![
        ("a second container", second_container),
        ("an exec probe", exec_probe),
        ("hostNetwork", host_network),
        ("a privileged container", privileged),
        ("a hostPath volume", host_path),
        ("runAsUser 0", root_user),
        ("a reserved volume name", reserved_volume),
        ("no command", no_command),
        ("a different image", other_image),
    ]
}

/// Returns the condition of `sandbox` with type `kind`, failing when it is absent.
fn condition<'a>(sandbox: &'a DriverSandbox, kind: &str) -> &'a DriverCondition {
    sandbox
        .status
        .as_ref()
        .expect("sandbox has a status")
        .conditions
        .iter()
        .find(|condition| condition.r#type == kind)
        .unwrap_or_else(|| panic!("sandbox has no {kind} condition"))
}

/// Asserts that `sandbox` reports `Ready=False` for a transient reason and a `PodReady`
/// condition.
fn assert_transiently_not_ready(sandbox: &DriverSandbox) {
    let ready = condition(sandbox, "Ready");
    assert_eq!(ready.status, "False");
    assert!(
        TRANSIENT_REASONS.contains(&ready.reason.as_str()),
        "Ready reason {} is not transient",
        ready.reason
    );
    condition(sandbox, "PodReady");
}

/// Waits until the watch stream delivers a payload that `matches` accepts.
async fn await_payload(
    events: &mut Streaming<WatchSandboxesEvent>,
    what: &str,
    matches: impl Fn(&Payload) -> bool,
) {
    loop {
        let event = tokio::time::timeout(WATCH_TIMEOUT, events.message())
            .await
            .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
            .expect("watch stream returns no error")
            .expect("watch stream stays open");
        if event.payload.as_ref().is_some_and(&matches) {
            return;
        }
    }
}

/// Reads the events of a watch until it has reported sandbox `id`, then until it stays quiet for
/// [`QUIET_WINDOW`]. Returns every payload it delivered, in order.
async fn watch_until_quiet(events: &mut Streaming<WatchSandboxesEvent>, id: &str) -> Vec<Payload> {
    let mut payloads = Vec::new();
    let mut reported = false;
    loop {
        let bound = if reported {
            QUIET_WINDOW
        } else {
            WATCH_TIMEOUT
        };
        let Ok(message) = tokio::time::timeout(bound, events.message()).await else {
            assert!(
                reported,
                "timed out waiting for the watch to report sandbox {id}"
            );
            return payloads;
        };
        let event = message
            .expect("watch stream returns no error")
            .expect("watch stream stays open");
        let payload = event.payload.expect("the event carries a payload");
        reported |= matches!(&payload, Payload::Sandbox(sandbox_event)
            if sandbox_event.sandbox.as_ref().is_some_and(|sandbox| sandbox.id == id));
        payloads.push(payload);
    }
}

/// Splits a runtime identity `kubernetes://<namespace>/<lease UID>/<pod UID>` into its parts.
fn identity_parts(identity: &str) -> (&str, &str, &str) {
    let rest = identity
        .strip_prefix("kubernetes://")
        .expect("runtime identity uses the kubernetes scheme");
    let mut parts = rest.split('/');
    let namespace = parts.next().expect("identity names a namespace");
    let lease = parts.next().expect("identity names a lease");
    let pod = parts.next().expect("identity names a pod");
    assert!(parts.next().is_none(), "identity has exactly three parts");
    (namespace, lease, pod)
}

/// Returns the label selector that matches the objects of `case`.
fn sandbox_selector(case: &Case) -> String {
    format!("{LABEL_SANDBOX_ID}={}", case.id)
}

/// Creates the sandbox of `case` from the valid template, and returns its runtime identity.
async fn create_valid_sandbox(
    grpc: &mut ComputeDriverClient<Channel>,
    kube: &Client,
    case: &Case,
) -> String {
    create_template(kube, &case.namespace, TEMPLATE_NAME, valid_template_spec()).await;
    grpc.create_sandbox(CreateSandboxRequest {
        sandbox: Some(case.sandbox(TEMPLATE_NAME, SANDBOX_IMAGE)),
    })
    .await
    .expect("create succeeds")
    .into_inner()
    .runtime_identity
}

#[tokio::test]
async fn e2e_capabilities_report_name_flags_contract_extension_and_admission_acknowledgement() {
    let driver = Driver::start("default").await;
    let mut grpc = driver.client();
    let capabilities = grpc
        .get_capabilities(GetCapabilitiesRequest {
            gateway: Some(gateway_metadata(ExtensionFamily::Compute)),
        })
        .await
        .expect("capabilities are answered")
        .into_inner();
    drop(grpc);
    driver.stop().await;

    assert_eq!(capabilities.driver_name, "podtemplate");
    assert_eq!(capabilities.driver_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(capabilities.default_image, "");
    assert!(!capabilities.gateway_manages_lifecycle);
    assert!(capabilities.supports_sandbox_authentication);
    assert!(!capabilities.driver_reports_runtime_readiness);

    let extension = capabilities
        .extension
        .expect("extension metadata is reported");
    assert_eq!(
        extension.implementation_name,
        "openshell-driver-podtemplate"
    );
    assert_eq!(extension.implementation_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(
        extension.supported_capabilities, extension.required_capabilities,
        "the driver advertises only the compute contract"
    );
    assert_eq!(extension.supported_capabilities.len(), 1);

    assert!(
        !capabilities.resource_admission_policy.is_empty(),
        "the driver acknowledges its admission policy"
    );
    DriverAdmissionConfig::from_str(DEFAULT_ADMISSION)
        .expect("default admission policy parses")
        .verify_acknowledgement(&capabilities.resource_admission_policy)
        .expect("the acknowledgement names the default admission policy");
}

#[tokio::test]
async fn e2e_validate_and_create_reject_each_broken_template_and_create_nothing() {
    let kube = kube_client().await;
    let case = Case::start(&kube, "broken").await;
    let driver = Driver::start(&case.namespace).await;
    let mut grpc = driver.client();

    for (index, (rule, spec)) in broken_templates().into_iter().enumerate() {
        let template = format!("broken-{index}");
        create_template(&kube, &case.namespace, &template, spec).await;
        let sandbox = case.sandbox(&template, SANDBOX_IMAGE);

        let validated = grpc
            .validate_sandbox_create(ValidateSandboxCreateRequest {
                sandbox: Some(sandbox.clone()),
            })
            .await
            .expect_err(rule);
        assert_eq!(validated.code(), Code::InvalidArgument, "{rule}: validate");

        let created = grpc
            .create_sandbox(CreateSandboxRequest {
                sandbox: Some(sandbox),
            })
            .await
            .expect_err(rule);
        assert_eq!(created.code(), Code::InvalidArgument, "{rule}: create");

        let leftovers = residue(&kube, &case.namespace).await;
        assert!(leftovers.is_empty(), "{rule}: created {leftovers:?}");
    }

    drop(grpc);
    driver.stop().await;
    case.finish(&kube).await;
}

#[tokio::test]
async fn e2e_missing_pod_template_is_failed_precondition_and_creates_nothing() {
    let kube = kube_client().await;
    let case = Case::start(&kube, "missing").await;
    let driver = Driver::start(&case.namespace).await;
    let mut grpc = driver.client();
    let sandbox = case.sandbox(TEMPLATE_NAME, SANDBOX_IMAGE);

    let validated = grpc
        .validate_sandbox_create(ValidateSandboxCreateRequest {
            sandbox: Some(sandbox.clone()),
        })
        .await
        .expect_err("a missing PodTemplate is rejected");
    assert_eq!(validated.code(), Code::FailedPrecondition);

    let created = grpc
        .create_sandbox(CreateSandboxRequest {
            sandbox: Some(sandbox),
        })
        .await
        .expect_err("a missing PodTemplate is rejected");
    assert_eq!(created.code(), Code::FailedPrecondition);

    let leftovers = residue(&kube, &case.namespace).await;
    assert!(leftovers.is_empty(), "created {leftovers:?}");

    drop(grpc);
    driver.stop().await;
    case.finish(&kube).await;
}

#[tokio::test]
async fn e2e_create_sandbox_builds_fenced_lease_owned_objects_with_gates_released() {
    let kube = kube_client().await;
    let case = Case::start(&kube, "create").await;
    create_user_secret(&kube, &case.namespace).await;
    let driver = Driver::start(&case.namespace).await;
    let mut grpc = driver.client();
    let identity = create_valid_sandbox(&mut grpc, &kube, &case).await;
    drop(grpc);
    driver.stop().await;

    let ns = case.namespace.as_str();
    let lease: Lease = get(&kube, ns, &case.name).await;
    let lease_uid = lease.uid().expect("lease has a UID");
    let (workload, workload_json) = only_pod(&kube, &case, "workload").await;
    let (supervisor, supervisor_json) = only_pod(&kube, &case, "supervisor").await;

    let (identity_ns, identity_lease, identity_pod) = identity_parts(&identity);
    assert_eq!(identity_ns, ns);
    assert_eq!(identity_lease, lease_uid);
    assert_eq!(
        identity_pod,
        supervisor.uid().expect("supervisor has a UID")
    );

    for (role, pod, raw) in [
        ("workload", &workload, &workload_json),
        ("supervisor", &supervisor, &supervisor_json),
    ] {
        let gates = raw["spec"]["schedulingGates"].as_array();
        assert!(
            gates.is_none_or(Vec::is_empty),
            "{role} pod still carries a scheduling gate: {gates:?}"
        );
        let owners = pod.owner_references();
        assert!(
            owners.iter().any(|owner| owner.kind == "Lease"
                && owner.uid == lease_uid
                && owner.controller == Some(true)),
            "{role} pod is not controlled by the Lease: {owners:?}"
        );
        let labels = pod.labels();
        assert_eq!(
            labels.get(LABEL_BOUNDARY_ROLE).map(String::as_str),
            Some(role)
        );
        assert_eq!(
            labels.get(LABEL_BOUNDARY_PAIR).map(String::as_str),
            Some(case.id.as_str())
        );
    }
    assert_eq!(
        workload_json["spec"]["securityContext"]["supplementalGroupsPolicy"],
        "Strict"
    );

    let workload_fence_name = names::<NetworkPolicy>(
        &kube,
        ns,
        &format!("{LABEL_COMPONENT}=sandbox-workload-fence"),
    )
    .await;
    let supervisor_fence_name = names::<NetworkPolicy>(
        &kube,
        ns,
        &format!("{LABEL_COMPONENT}=sandbox-supervisor-egress"),
    )
    .await;
    assert_eq!(workload_fence_name.len(), 1, "the workload fence exists");
    assert_eq!(
        supervisor_fence_name.len(),
        1,
        "the supervisor fence exists"
    );
    let workload_fence: NetworkPolicy = get(&kube, ns, &workload_fence_name[0]).await;
    let supervisor_fence: NetworkPolicy = get(&kube, ns, &supervisor_fence_name[0]).await;
    let services = Api::<Service>::namespaced(kube.clone(), ns)
        .list(&ListParams::default().labels(&sandbox_selector(&case)))
        .await
        .expect("list the boundary Service")
        .items;
    assert_eq!(services.len(), 1, "one boundary Service exists");
    let service = &services[0];
    assert!(
        service
            .owner_references()
            .iter()
            .any(|owner| owner.uid == lease_uid),
        "the boundary Service is owned by the Lease"
    );

    let secrets: Vec<Secret> = Api::<Secret>::namespaced(kube.clone(), ns)
        .list(&ListParams::default().labels(&sandbox_selector(&case)))
        .await
        .expect("list the bootstrap Secrets")
        .items
        .into_iter()
        .filter(|secret| {
            matches!(
                secret.labels().get(LABEL_COMPONENT).map(String::as_str),
                Some("sandbox-bootstrap" | "supervisor-bootstrap")
            )
        })
        .collect();
    assert_eq!(secrets.len(), 2, "two bootstrap Secrets exist");
    for secret in &secrets {
        assert!(
            secret
                .owner_references()
                .iter()
                .any(|owner| owner.uid == lease_uid),
            "bootstrap Secret {} is owned by the Lease",
            secret.name_any()
        );
    }
    let supervisor_secret = secrets
        .iter()
        .find(|secret| {
            secret.labels().get(LABEL_COMPONENT).map(String::as_str) == Some("supervisor-bootstrap")
        })
        .expect("the supervisor bootstrap Secret exists");
    let sandbox_secret = secrets
        .iter()
        .find(|secret| {
            secret.labels().get(LABEL_COMPONENT).map(String::as_str) == Some("sandbox-bootstrap")
        })
        .expect("the sandbox bootstrap Secret exists");

    // The launch tokens belong to the supervisor bootstrap Secret and to no other object the
    // driver writes. The user Secret's value appears in none of them.
    assert!(
        secret_mentions(supervisor_secret, GATEWAY_TOKEN)
            && secret_mentions(supervisor_secret, SANDBOX_TOKEN),
        "the supervisor bootstrap Secret carries the launch tokens"
    );
    assert!(!secret_mentions(supervisor_secret, USER_SECRET_VALUE));
    assert!(!secret_mentions(sandbox_secret, GATEWAY_TOKEN));
    assert!(!secret_mentions(sandbox_secret, SANDBOX_TOKEN));
    assert!(!secret_mentions(sandbox_secret, USER_SECRET_VALUE));

    let objects = [
        ("Lease", encode(&lease)),
        ("boundary Service", encode(service)),
        ("workload fence", encode(&workload_fence)),
        ("supervisor fence", encode(&supervisor_fence)),
        ("workload pod", encode(&workload)),
        ("supervisor pod", encode(&supervisor)),
    ];
    for (what, text) in &objects {
        for needle in [GATEWAY_TOKEN, SANDBOX_TOKEN, USER_SECRET_VALUE] {
            assert!(!text.contains(needle), "{what} carries {needle}");
        }
    }
    assert!(!mentions(&lease.metadata.labels, PLAIN_ENV_VALUE));
    assert!(!mentions(&lease.metadata.annotations, PLAIN_ENV_VALUE));
    assert!(!mentions(&service.metadata, PLAIN_ENV_VALUE));
    assert!(!mentions(&workload_fence.metadata, PLAIN_ENV_VALUE));
    assert!(!mentions(&supervisor_fence.metadata, PLAIN_ENV_VALUE));
    assert!(!mentions(&workload.metadata, PLAIN_ENV_VALUE));
    assert!(!mentions(&supervisor.metadata, PLAIN_ENV_VALUE));
    assert!(
        mentions(&workload.spec, PLAIN_ENV_VALUE),
        "the workload pod carries its template environment"
    );

    case.finish(&kube).await;
}

#[tokio::test]
async fn e2e_stop_start_create_stores_the_start_inputs_without_launch_credentials() {
    let kube = kube_client().await;
    let case = Case::start(&kube, "startin").await;
    let driver = Driver::start(&case.namespace).await;
    let mut grpc = driver.client();
    create_valid_sandbox(&mut grpc, &kube, &case).await;
    drop(grpc);
    driver.stop().await;

    let ns = case.namespace.as_str();
    let lease: Lease = get(&kube, ns, &case.name).await;
    let lease_uid = lease.uid().expect("lease has a UID");
    let secrets = Api::<Secret>::namespaced(kube.clone(), ns)
        .list(&ListParams::default().labels(&format!(
            "{LABEL_COMPONENT}=sandbox-start-inputs,{}",
            sandbox_selector(&case)
        )))
        .await
        .expect("list the start-inputs Secret")
        .items;
    assert_eq!(secrets.len(), 1, "exactly one start-inputs Secret exists");
    let secret = &secrets[0];
    assert!(
        secret
            .owner_references()
            .iter()
            .any(|owner| owner.uid == lease_uid),
        "the start-inputs Secret is owned by the Lease"
    );
    assert_eq!(secret.immutable, Some(true));
    assert!(!secret_mentions(secret, GATEWAY_TOKEN));
    assert!(!secret_mentions(secret, SANDBOX_TOKEN));

    let data = secret
        .data
        .as_ref()
        .expect("the start-inputs Secret has data");
    assert_eq!(data.len(), 1, "the start-inputs Secret has one data key");
    let bytes = data.values().next().expect("the one data key has a value");
    let stored = DriverSandbox::decode(bytes.0.as_slice()).expect("the value decodes");
    assert_eq!(stored.id, case.id);
    assert_eq!(stored.name, case.name);
    let spec = stored
        .spec
        .as_ref()
        .expect("the stored request keeps its spec");
    let request = case.sandbox(TEMPLATE_NAME, SANDBOX_IMAGE);
    let template = request.spec.as_ref().and_then(|spec| spec.template.clone());
    assert!(
        spec.template == template,
        "the stored template is the request's"
    );
    assert!(spec.sandbox_token.is_empty(), "sandbox_token is not stored");
    assert!(
        spec.launch_authentication.is_empty(),
        "launch_authentication is not stored"
    );
}

#[tokio::test]
async fn e2e_get_and_list_report_a_created_sandbox_as_transiently_not_ready() {
    let kube = kube_client().await;
    let case = Case::start(&kube, "getlist").await;
    let driver = Driver::start(&case.namespace).await;
    let mut grpc = driver.client();
    create_valid_sandbox(&mut grpc, &kube, &case).await;

    let fetched = grpc
        .get_sandbox(GetSandboxRequest {
            sandbox_id: case.id.clone(),
            ..Default::default()
        })
        .await
        .expect("get returns the sandbox")
        .into_inner()
        .sandbox
        .expect("get carries the sandbox");
    assert_eq!(fetched.id, case.id);
    assert_eq!(fetched.name, case.name);
    assert_transiently_not_ready(&fetched);

    let listed = grpc
        .list_sandboxes(ListSandboxesRequest {})
        .await
        .expect("list returns the sandboxes")
        .into_inner()
        .sandboxes;
    let found = listed
        .iter()
        .find(|sandbox| sandbox.id == case.id)
        .expect("list includes the created sandbox");
    assert_transiently_not_ready(found);

    let missing = grpc
        .get_sandbox(GetSandboxRequest {
            sandbox_id: format!("{}-absent", case.id),
            ..Default::default()
        })
        .await
        .expect_err("an unknown sandbox is not found");
    assert_eq!(missing.code(), Code::NotFound);

    drop(grpc);
    driver.stop().await;
    case.finish(&kube).await;
}

#[tokio::test]
async fn e2e_watch_delivers_a_sandbox_event_after_create_and_a_deleted_event_after_delete() {
    let kube = kube_client().await;
    let case = Case::start(&kube, "watch").await;
    let driver = Driver::start(&case.namespace).await;
    let mut grpc = driver.client();
    create_template(&kube, &case.namespace, TEMPLATE_NAME, valid_template_spec()).await;
    let mut events = grpc
        .watch_sandboxes(WatchSandboxesRequest {})
        .await
        .expect("watch opens")
        .into_inner();

    grpc.create_sandbox(CreateSandboxRequest {
        sandbox: Some(case.sandbox(TEMPLATE_NAME, SANDBOX_IMAGE)),
    })
    .await
    .expect("create succeeds");
    let id = case.id.clone();
    await_payload(&mut events, "a sandbox event after create", |payload| {
        matches!(payload, Payload::Sandbox(event)
            if event.sandbox.as_ref().is_some_and(|sandbox| sandbox.id == id))
    })
    .await;

    let deleted = grpc
        .delete_sandbox(DeleteSandboxRequest {
            sandbox_id: case.id.clone(),
            ..Default::default()
        })
        .await
        .expect("delete succeeds")
        .into_inner()
        .deleted;
    assert!(deleted, "the first delete removes the sandbox");
    let id = case.id.clone();
    await_payload(
        &mut events,
        "a deleted event after delete",
        |payload| matches!(payload, Payload::Deleted(event) if event.sandbox_id == id),
    )
    .await;

    drop(events);
    drop(grpc);
    driver.stop().await;
    case.finish(&kube).await;
}

/// Restarts the driver while a watch is open, and deletes sandbox B while no driver runs. The
/// restarted driver lists and gets A once and never B, and its watch reports A and no deletion.
/// A keeps its Lease and pods, and no pod is added.
#[tokio::test]
async fn e2e_restart_reports_each_live_sandbox_once_and_omits_one_deleted_while_down() {
    let kube = kube_client().await;
    let case_a = Case::start(&kube, "restart-live").await;
    let case_b = case_a.sibling("restart-gone");
    let ns = case_a.namespace.clone();
    create_template(&kube, &ns, TEMPLATE_NAME, valid_template_spec()).await;
    let driver = Driver::start(&ns).await;
    let mut grpc = driver.client();
    let open = grpc
        .watch_sandboxes(WatchSandboxesRequest {})
        .await
        .expect("watch opens")
        .into_inner();
    for case in [&case_a, &case_b] {
        grpc.create_sandbox(CreateSandboxRequest {
            sandbox: Some(case.sandbox(TEMPLATE_NAME, SANDBOX_IMAGE)),
        })
        .await
        .expect("create succeeds");
    }
    let runtime_a = read_runtime(&kube, &case_a).await;
    let pods_before = names::<Pod>(&kube, &ns, "").await;

    // The driver exits on SIGTERM while the watch and the client are still open.
    driver.stop().await;
    drop(open);
    drop(grpc);
    Api::<Lease>::namespaced(kube.clone(), &ns)
        .delete(&case_b.name, &DeleteParams::default())
        .await
        .expect("delete the Lease of B while no driver runs");
    await_no_sandbox_residue(&kube, &case_b).await;

    let driver = Driver::start(&ns).await;
    let mut grpc = driver.client();
    let listed = grpc
        .list_sandboxes(ListSandboxesRequest {})
        .await
        .expect("list returns the sandboxes")
        .into_inner()
        .sandboxes;
    let listed_a = listed
        .iter()
        .filter(|sandbox| sandbox.id == case_a.id)
        .count();
    assert_eq!(listed_a, 1, "list holds A exactly once");
    assert!(
        listed.iter().all(|sandbox| sandbox.id != case_b.id),
        "list holds B"
    );

    let fetched = grpc
        .get_sandbox(GetSandboxRequest {
            sandbox_id: case_a.id.clone(),
            ..Default::default()
        })
        .await
        .expect("get returns A")
        .into_inner()
        .sandbox
        .expect("get carries A");
    assert_eq!(fetched.id, case_a.id);
    let absent = grpc
        .get_sandbox(GetSandboxRequest {
            sandbox_id: case_b.id.clone(),
            ..Default::default()
        })
        .await
        .expect_err("get of B is not found");
    assert_eq!(absent.code(), Code::NotFound);

    let mut events = grpc
        .watch_sandboxes(WatchSandboxesRequest {})
        .await
        .expect("watch opens")
        .into_inner();
    let payloads = watch_until_quiet(&mut events, &case_a.id).await;
    let only_a = payloads.iter().all(|payload| {
        matches!(payload, Payload::Sandbox(event)
            if event.sandbox.as_ref().is_some_and(|sandbox| sandbox.id == case_a.id))
    });
    assert!(
        only_a,
        "the watch reports only A, and no deletion: {payloads:?}"
    );

    assert_eq!(
        read_runtime(&kube, &case_a).await,
        runtime_a,
        "A keeps its Lease and pods"
    );
    let pods_after = names::<Pod>(&kube, &ns, "").await;
    let added: Vec<&String> = pods_after
        .iter()
        .filter(|name| !pods_before.contains(name))
        .collect();
    assert!(added.is_empty(), "pods were added: {added:?}");

    drop(events);
    drop(grpc);
    driver.stop().await;
    case_a.finish(&kube).await;
}

#[tokio::test]
async fn e2e_authenticate_sandbox_accepts_the_supervisor_and_rejects_the_workload_and_a_foreign_audience()
 {
    let kube = kube_client().await;
    let case = Case::start(&kube, "auth").await;
    let driver = Driver::start(&case.namespace).await;
    let mut grpc = driver.client();
    let identity = create_valid_sandbox(&mut grpc, &kube, &case).await;
    let ns = case.namespace.as_str();
    let (supervisor, _) = only_pod(&kube, &case, "supervisor").await;
    let (workload, _) = only_pod(&kube, &case, "workload").await;

    let supervisor_token = token_bound_to(&kube, ns, &supervisor, GATEWAY_AUDIENCE).await;
    let authenticated = grpc
        .authenticate_sandbox(AuthenticateSandboxRequest {
            credential: supervisor_token,
        })
        .await
        .expect("the supervisor credential is accepted")
        .into_inner();
    assert_eq!(authenticated.sandbox_id, case.id);
    assert_eq!(authenticated.runtime_identity, identity);

    let workload_token = token_bound_to(&kube, ns, &workload, GATEWAY_AUDIENCE).await;
    let workload_denied = grpc
        .authenticate_sandbox(AuthenticateSandboxRequest {
            credential: workload_token,
        })
        .await
        .expect_err("a credential bound to the workload pod is rejected");
    assert_eq!(workload_denied.code(), Code::PermissionDenied);

    let foreign_token = token_bound_to(&kube, ns, &supervisor, "some-other-audience").await;
    let foreign = grpc
        .authenticate_sandbox(AuthenticateSandboxRequest {
            credential: foreign_token,
        })
        .await
        .expect_err("a credential for another audience is rejected");
    assert_eq!(foreign.code(), Code::Unauthenticated);

    drop(grpc);
    driver.stop().await;
    case.finish(&kube).await;
}

/// Creates a pod in the namespace of `case` that the driver did not create. It carries the labels
/// and sandbox-ID annotation of `supervisor`, the default service account, and no Lease owner.
async fn create_intruder_pod(kube: &Client, case: &Case, supervisor: &Pod) -> Pod {
    let pod = Pod {
        metadata: ObjectMeta {
            name: Some(format!("{}-intruder", case.name)),
            namespace: Some(case.namespace.clone()),
            labels: supervisor.metadata.labels.clone(),
            annotations: Some([(LABEL_SANDBOX_ID.to_owned(), case.id.clone())].into()),
            ..Default::default()
        },
        spec: Some(PodSpec {
            service_account_name: Some("default".to_owned()),
            scheduling_gates: Some(vec![PodSchedulingGate {
                name: "odp-e2e-intruder".to_owned(),
            }]),
            containers: vec![Container {
                name: "intruder".to_owned(),
                image: Some(SANDBOX_IMAGE.to_owned()),
                ..Default::default()
            }],
            ..Default::default()
        }),
        ..Default::default()
    };
    Api::<Pod>::namespaced(kube.clone(), &case.namespace)
        .create(&PostParams::default(), &pod)
        .await
        .expect("create the intruder pod")
}

#[tokio::test]
async fn e2e_auth_binding() {
    let kube = kube_client().await;
    let case_a = Case::start(&kube, "bind-a").await;
    let case_b = case_a.sibling("bind-b");
    let ns = case_a.namespace.clone();
    let driver = Driver::start(&ns).await;
    let mut grpc = driver.client();
    let identity_a = create_valid_sandbox(&mut grpc, &kube, &case_a).await;
    let identity_b = grpc
        .create_sandbox(CreateSandboxRequest {
            sandbox: Some(case_b.sandbox(TEMPLATE_NAME, SANDBOX_IMAGE)),
        })
        .await
        .expect("the second create succeeds")
        .into_inner()
        .runtime_identity;
    assert_ne!(
        identity_a, identity_b,
        "the two sandboxes have distinct runtime identities"
    );

    let (supervisor_a, _) = only_pod(&kube, &case_a, "supervisor").await;
    let (supervisor_b, _) = only_pod(&kube, &case_b, "supervisor").await;
    let (workload_a, _) = only_pod(&kube, &case_a, "workload").await;

    let accepted_a = grpc
        .authenticate_sandbox(AuthenticateSandboxRequest {
            credential: token_bound_to(&kube, &ns, &supervisor_a, GATEWAY_AUDIENCE).await,
        })
        .await
        .expect("A's supervisor credential is accepted")
        .into_inner();
    assert_eq!(accepted_a.sandbox_id, case_a.id);
    assert_eq!(accepted_a.runtime_identity, identity_a);

    let accepted_b = grpc
        .authenticate_sandbox(AuthenticateSandboxRequest {
            credential: token_bound_to(&kube, &ns, &supervisor_b, GATEWAY_AUDIENCE).await,
        })
        .await
        .expect("B's supervisor credential is accepted")
        .into_inner();
    assert_eq!(accepted_b.sandbox_id, case_b.id);
    assert_eq!(accepted_b.runtime_identity, identity_b);
    assert_ne!(accepted_b.sandbox_id, accepted_a.sandbox_id);
    assert_ne!(accepted_b.runtime_identity, accepted_a.runtime_identity);

    let workload_denied = grpc
        .authenticate_sandbox(AuthenticateSandboxRequest {
            credential: token_bound_to(&kube, &ns, &workload_a, GATEWAY_AUDIENCE).await,
        })
        .await
        .expect_err("A's workload credential is rejected");
    assert_eq!(workload_denied.code(), Code::PermissionDenied);

    let intruder = create_intruder_pod(&kube, &case_a, &supervisor_a).await;
    let intruder_denied = grpc
        .authenticate_sandbox(AuthenticateSandboxRequest {
            credential: token_bound_to(&kube, &ns, &intruder, GATEWAY_AUDIENCE).await,
        })
        .await
        .expect_err("a pod the driver did not create is rejected");
    assert_eq!(intruder_denied.code(), Code::PermissionDenied);

    drop(grpc);
    driver.stop().await;
    case_a.finish(&kube).await;
}

#[tokio::test]
async fn e2e_delete_removes_every_object_and_a_second_delete_reports_false() {
    let kube = kube_client().await;
    let case = Case::start(&kube, "delete").await;
    let driver = Driver::start(&case.namespace).await;
    let mut grpc = driver.client();
    create_valid_sandbox(&mut grpc, &kube, &case).await;

    let deleted = grpc
        .delete_sandbox(DeleteSandboxRequest {
            sandbox_id: case.id.clone(),
            ..Default::default()
        })
        .await
        .expect("delete succeeds")
        .into_inner()
        .deleted;
    assert!(deleted, "the first delete removes the sandbox");

    let ns = case.namespace.clone();
    let owned_by_sandbox = {
        let kube = kube.clone();
        let case_id = case.id.clone();
        let namespace = ns.clone();
        move || {
            let kube = kube.clone();
            let namespace = namespace.clone();
            let selector = format!("{LABEL_SANDBOX_ID}={case_id}");
            let pair = format!("{LABEL_BOUNDARY_PAIR}={case_id}");
            async move {
                let mut left = Vec::new();
                left.extend(names::<Lease>(&kube, &namespace, &selector).await);
                left.extend(names::<Service>(&kube, &namespace, &selector).await);
                left.extend(names::<Secret>(&kube, &namespace, &selector).await);
                left.extend(
                    pods(&kube, &namespace, &pair)
                        .await
                        .into_iter()
                        .map(|(pod, _)| pod.name_any()),
                );
                left.is_empty().then_some(())
            }
        }
    };
    eventually("every object of the sandbox to disappear", owned_by_sandbox).await;

    let second = grpc
        .delete_sandbox(DeleteSandboxRequest {
            sandbox_id: case.id.clone(),
            ..Default::default()
        })
        .await
        .expect("a second delete answers")
        .into_inner()
        .deleted;
    assert!(!second, "a second delete reports nothing deleted");

    let gone = grpc
        .get_sandbox(GetSandboxRequest {
            sandbox_id: case.id.clone(),
            ..Default::default()
        })
        .await
        .expect_err("get after delete is not found");
    assert_eq!(gone.code(), Code::NotFound);

    drop(grpc);
    driver.stop().await;
    case.finish(&kube).await;
}

/// Asserts that the runtime of `case` is stopped: no pod, boundary Service or bootstrap Secret of
/// the sandbox remains. The Lease keeps `record_uid` and the start-inputs Secret keeps `start_uid`.
async fn assert_runtime_stopped(kube: &Client, case: &Case, record_uid: &str, start_uid: &str) {
    let namespace = case.namespace.as_str();
    let selector = format!("{LABEL_SANDBOX_ID}={}", case.id);
    let pair = format!("{LABEL_BOUNDARY_PAIR}={}", case.id);
    let start_name = format!("os-start-{}", case.id);

    assert!(
        pods(kube, namespace, &pair).await.is_empty(),
        "a pod of the stopped sandbox remains"
    );
    assert!(
        names::<Service>(kube, namespace, &selector)
            .await
            .is_empty(),
        "the boundary Service remains"
    );
    assert_eq!(
        names::<Secret>(kube, namespace, &selector).await,
        vec![start_name.clone()],
        "only the start-inputs Secret remains"
    );
    assert_eq!(
        names::<Lease>(kube, namespace, &selector).await,
        vec![case.name.clone()],
        "only the record remains"
    );

    let record = get::<Lease>(kube, namespace, &case.name).await;
    assert_eq!(record.metadata.uid.as_deref(), Some(record_uid));
    let start = get::<Secret>(kube, namespace, &start_name).await;
    assert_eq!(start.metadata.uid.as_deref(), Some(start_uid));
}

#[tokio::test]
async fn e2e_stop_start_stop_deletes_the_runtime_and_keeps_the_record() {
    let kube = kube_client().await;
    let case = Case::start(&kube, "stop").await;
    let driver = Driver::start(&case.namespace).await;
    let mut grpc = driver.client();
    create_valid_sandbox(&mut grpc, &kube, &case).await;

    let record_uid = get::<Lease>(&kube, &case.namespace, &case.name)
        .await
        .metadata
        .uid
        .expect("the record has a UID");
    let start_uid = get::<Secret>(&kube, &case.namespace, &format!("os-start-{}", case.id))
        .await
        .metadata
        .uid
        .expect("the start-inputs Secret has a UID");

    grpc.stop_sandbox(StopSandboxRequest {
        sandbox_id: case.id.clone(),
        ..Default::default()
    })
    .await
    .expect("stop succeeds");
    assert_runtime_stopped(&kube, &case, &record_uid, &start_uid).await;

    let stopped = grpc
        .get_sandbox(GetSandboxRequest {
            sandbox_id: case.id.clone(),
            ..Default::default()
        })
        .await
        .expect("the stopped sandbox is still returned")
        .into_inner()
        .sandbox
        .expect("the response carries the sandbox");
    assert_eq!(stopped.id, case.id);
    let status = stopped.status.expect("the sandbox has a status");
    assert!(!status.deleting, "a stopped sandbox is not deleting");
    assert!(
        status.instance_id.is_empty(),
        "a stopped sandbox has no instance"
    );

    grpc.stop_sandbox(StopSandboxRequest {
        sandbox_id: case.id.clone(),
        ..Default::default()
    })
    .await
    .expect("a second stop succeeds");
    assert_runtime_stopped(&kube, &case, &record_uid, &start_uid).await;

    let unknown = grpc
        .stop_sandbox(StopSandboxRequest {
            sandbox_id: format!("{}-unknown", case.id),
            ..Default::default()
        })
        .await
        .expect_err("stop of an unknown sandbox is not found");
    assert_eq!(unknown.code(), Code::NotFound);

    let deleted = grpc
        .delete_sandbox(DeleteSandboxRequest {
            sandbox_id: case.id.clone(),
            ..Default::default()
        })
        .await
        .expect("delete succeeds")
        .into_inner()
        .deleted;
    assert!(deleted, "delete removes the stopped sandbox");
    await_no_sandbox_residue(&kube, &case).await;

    drop(grpc);
    driver.stop().await;
    case.finish(&kube).await;
}

#[tokio::test]
async fn e2e_create_fails_on_a_preexisting_boundary_service_and_leaves_no_lease() {
    let kube = kube_client().await;
    let case = Case::start(&kube, "rollback").await;
    create_template(&kube, &case.namespace, TEMPLATE_NAME, valid_template_spec()).await;
    let boundary_service = format!("os-boundary-{}", case.id);
    let service = Service {
        metadata: ObjectMeta {
            name: Some(boundary_service.clone()),
            namespace: Some(case.namespace.clone()),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            ports: Some(vec![ServicePort {
                port: 5500,
                protocol: Some("TCP".to_owned()),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    };
    Api::<Service>::namespaced(kube.clone(), &case.namespace)
        .create(&PostParams::default(), &service)
        .await
        .expect("pre-create the boundary Service");

    let driver = Driver::start(&case.namespace).await;
    let mut grpc = driver.client();
    let failed = grpc
        .create_sandbox(CreateSandboxRequest {
            sandbox: Some(case.sandbox(TEMPLATE_NAME, SANDBOX_IMAGE)),
        })
        .await
        .expect_err("create fails while the boundary Service exists");
    assert_eq!(failed.code(), Code::AlreadyExists);
    drop(grpc);
    driver.stop().await;

    let ns = case.namespace.clone();
    let rolled_back = {
        let kube = kube.clone();
        let namespace = ns.clone();
        let name = case.name.clone();
        move || {
            let kube = kube.clone();
            let namespace = namespace.clone();
            let name = name.clone();
            async move {
                names::<Lease>(&kube, &namespace, "")
                    .await
                    .into_iter()
                    .all(|record| record != name)
                    .then_some(())
            }
        }
    };
    eventually(
        "the Lease of the failed create to be rolled back",
        rolled_back,
    )
    .await;

    let pods_left = names::<Pod>(&kube, &ns, "").await;
    assert!(pods_left.is_empty(), "no pod was created: {pods_left:?}");
    let secrets_left = names::<Secret>(&kube, &ns, "").await;
    assert!(
        secrets_left.iter().all(|name| name == "user-credential"),
        "no bootstrap Secret was created: {secrets_left:?}"
    );
    let services_left = names::<Service>(&kube, &ns, "").await;
    assert_eq!(
        services_left,
        vec![boundary_service],
        "only the pre-existing Service remains"
    );

    case.finish(&kube).await;
}

/// Holds the first bootstrap Secret create of a sandbox, cancels the create while it is held,
/// and checks that once garbage collection settles the sandbox leaves no object behind.
#[tokio::test]
async fn e2e_no_residue_after_a_create_cancelled_at_bootstrap_secret() {
    let kube = kube_client().await;
    let case = Case::start(&kube, "cancel").await;
    create_user_secret(&kube, &case.namespace).await;
    create_template(&kube, &case.namespace, TEMPLATE_NAME, valid_template_spec()).await;
    let hold = CreateHold::install::<Secret>(&kube, &case.namespace, OnTimeout::Reject).await;
    let driver = Driver::start(&case.namespace).await;
    let mut grpc = driver.client();
    let sandbox = case.sandbox(TEMPLATE_NAME, SANDBOX_IMAGE);
    let create = tokio::spawn(async move {
        grpc.create_sandbox(CreateSandboxRequest {
            sandbox: Some(sandbox),
        })
        .await
    });

    await_gated_runtime(&kube, &case).await;
    assert!(
        !create.is_finished(),
        "the create returned before the hold ended"
    );
    create.abort();
    let cancelled = create.await.expect_err("the aborted create is cancelled");
    assert!(
        cancelled.is_cancelled(),
        "the create task was not cancelled"
    );

    await_no_sandbox_residue(&kube, &case).await;
    driver.stop().await;
    hold.stop(&kube).await;
    hold.remove(&kube).await;
    case.finish(&kube).await;
}

/// Holds the first bootstrap Secret create of a sandbox until its webhook rejects it, and
/// checks that the failed create leaves no object of the sandbox behind.
#[tokio::test]
async fn e2e_no_residue_after_a_create_failed_at_bootstrap_secret() {
    let kube = kube_client().await;
    let case = Case::start(&kube, "failed").await;
    create_user_secret(&kube, &case.namespace).await;
    create_template(&kube, &case.namespace, TEMPLATE_NAME, valid_template_spec()).await;
    let hold = CreateHold::install::<Secret>(&kube, &case.namespace, OnTimeout::Reject).await;
    let driver = Driver::start(&case.namespace).await;
    let mut grpc = driver.client();
    let sandbox = case.sandbox(TEMPLATE_NAME, SANDBOX_IMAGE);
    let create = tokio::spawn(async move {
        grpc.create_sandbox(CreateSandboxRequest {
            sandbox: Some(sandbox),
        })
        .await
    });

    await_gated_runtime(&kube, &case).await;
    assert!(
        !create.is_finished(),
        "the create returned before the hold ended"
    );
    // Stopping the backend makes the API server apply failurePolicy Fail to the held create.
    hold.stop(&kube).await;
    tokio::time::timeout(WATCH_TIMEOUT, create)
        .await
        .expect("the held create returns")
        .expect("the create task finishes")
        .expect_err("the held Secret create fails the create");

    await_no_sandbox_residue(&kube, &case).await;
    driver.stop().await;
    hold.remove(&kube).await;
    case.finish(&kube).await;
}

/// Holds the Lease POST of a sandbox until the backend stops and the API server admits it, cancels
/// the create while the POST is in flight, and checks that the admitted Lease is deleted. Neither
/// the running driver nor a restarted driver reports the sandbox, and no object of it exists.
#[tokio::test]
async fn e2e_restart_leaves_no_orphan_lease_of_a_create_dropped_at_its_lease_post() {
    let kube = kube_client().await;
    let case = Case::start(&kube, "orphan").await;
    create_user_secret(&kube, &case.namespace).await;
    create_template(&kube, &case.namespace, TEMPLATE_NAME, valid_template_spec()).await;
    let hold = CreateHold::install::<Lease>(&kube, &case.namespace, OnTimeout::Admit).await;
    let leases = Api::<Lease>::namespaced(kube.clone(), &case.namespace);
    let mut lease_events = Box::pin(
        leases
            .watch(&WatchParams::default(), "0")
            .await
            .expect("watch the leases of the namespace"),
    );
    let relay = Relay::start().await;
    let driver = Driver::start_through(&case.namespace, &relay).await;
    let mut grpc = driver.client();
    let sandbox = case.sandbox(TEMPLATE_NAME, SANDBOX_IMAGE);
    let create = tokio::spawn(async move {
        grpc.create_sandbox(CreateSandboxRequest {
            sandbox: Some(sandbox),
        })
        .await
    });

    // The Lease POST follows the two fences. Once both fences exist, the settle lets the driver
    // send the POST before the create is cancelled.
    let ns = case.namespace.clone();
    eventually("both namespace fences", || {
        let kube = kube.clone();
        let ns = ns.clone();
        async move { (names::<NetworkPolicy>(&kube, &ns, "").await.len() == 2).then_some(()) }
    })
    .await;
    tokio::time::sleep(QUIET_WINDOW).await;
    assert!(
        !create.is_finished(),
        "the create returned before the Lease hold ended"
    );
    // The aborted driver closes its connection with a TLS close_notify. The relay withholds it
    // until the API server answers the held POST, so the API server keeps that POST, as it would
    // for a client that never left.
    relay.freeze_open_connections();
    create.abort();
    let cancelled = create.await.expect_err("the aborted create is cancelled");
    assert!(
        cancelled.is_cancelled(),
        "the create task was not cancelled"
    );

    // Stopping the backend makes the API server apply failurePolicy Ignore to the held POST, which
    // admits it. The driver then deletes the admitted Lease itself, as soon as the POST returns, so
    // a poll could miss the Lease. The watch records every event, and the deletion is checked only
    // after the Lease was added.
    hold.stop(&kube).await;
    let mut added = false;
    tokio::time::timeout(WATCH_TIMEOUT, async {
        while let Some(event) = lease_events.next().await {
            match event.expect("the Lease watch yields events") {
                WatchEvent::Added(lease) if lease.name_any() == case.name => added = true,
                WatchEvent::Deleted(lease) if lease.name_any() == case.name => return,
                WatchEvent::Error(error) => panic!("the Lease watch failed: {error:?}"),
                WatchEvent::Added(_)
                | WatchEvent::Modified(_)
                | WatchEvent::Deleted(_)
                | WatchEvent::Bookmark(_) => {}
            }
        }
        panic!("the Lease watch ended before the admitted Lease was deleted");
    })
    .await
    .expect("the admitted Lease of the dropped create is deleted");
    assert!(
        added,
        "the Lease was deleted before the held POST was admitted"
    );
    assert_no_object_of_the_sandbox(&kube, &case).await;
    await_not_reported(&driver, &case).await;

    driver.stop().await;
    let driver = Driver::start_through(&case.namespace, &relay).await;
    await_not_reported(&driver, &case).await;
    assert_no_object_of_the_sandbox(&kube, &case).await;
    driver.stop().await;
    hold.remove(&kube).await;
    case.finish(&kube).await;
}

/// Asserts that the namespace of `case` holds no Lease of the sandbox and no pod, Service or
/// Secret of it. The user Secret is the only Secret that may exist.
async fn assert_no_object_of_the_sandbox(kube: &Client, case: &Case) {
    let ns = case.namespace.as_str();
    let leases = names::<Lease>(kube, ns, "").await;
    assert!(
        !leases.contains(&case.name),
        "the Lease remains: {leases:?}"
    );
    let pods_left = names::<Pod>(kube, ns, "").await;
    assert!(pods_left.is_empty(), "no pod was created: {pods_left:?}");
    let services_left = names::<Service>(kube, ns, "").await;
    assert!(
        services_left.is_empty(),
        "no Service was created: {services_left:?}"
    );
    let secrets_left = names::<Secret>(kube, ns, "").await;
    assert!(
        secrets_left.iter().all(|name| name == USER_SECRET_NAME),
        "no bootstrap Secret was created: {secrets_left:?}"
    );
}

/// Waits until `driver` omits the sandbox of `case` from `ListSandboxes` and answers `NotFound`
/// to `GetSandbox`.
async fn await_not_reported(driver: &Driver, case: &Case) {
    let client = driver.client();
    eventually("the driver to stop reporting the sandbox", || {
        let mut grpc = client.clone();
        let id = case.id.clone();
        async move {
            let listed = grpc
                .list_sandboxes(ListSandboxesRequest {})
                .await
                .expect("list returns the sandboxes")
                .into_inner()
                .sandboxes;
            let fetched = grpc
                .get_sandbox(GetSandboxRequest {
                    sandbox_id: id.clone(),
                    ..Default::default()
                })
                .await;
            (listed.iter().all(|sandbox| sandbox.id != id)
                && fetched.is_err_and(|status| status.code() == Code::NotFound))
            .then_some(())
        }
    })
    .await;
}

/// Pre-creates each namespace fence in turn with a spec that does not match what the driver
/// creates, so that the create fails validating it, and checks that no pod was created before.
#[tokio::test]
async fn e2e_create_validates_each_namespace_fence_before_any_pod_exists() {
    let kube = kube_client().await;
    let case = Case::start(&kube, "fence-workload").await;
    let policy = SandboxRuntimeNames::new(&case.id).workload_policy;
    assert_no_pod_before_fence_failure(&kube, &case, &policy).await;
    case.finish(&kube).await;

    let case = Case::start(&kube, "fence-supervisor").await;
    let policy = SandboxRuntimeNames::new(&case.id).supervisor_policy;
    assert_no_pod_before_fence_failure(&kube, &case, &policy).await;
    case.finish(&kube).await;
}

/// Creates the fence `policy` with an empty spec, runs a create that must fail validating it,
/// and asserts that a Pod watch opened before the create saw no pod added.
async fn assert_no_pod_before_fence_failure(kube: &Client, case: &Case, policy: &str) {
    create_template(kube, &case.namespace, TEMPLATE_NAME, valid_template_spec()).await;
    Api::<NetworkPolicy>::namespaced(kube.clone(), &case.namespace)
        .create(
            &PostParams::default(),
            &NetworkPolicy {
                metadata: ObjectMeta {
                    name: Some(policy.to_owned()),
                    namespace: Some(case.namespace.clone()),
                    ..Default::default()
                },
                spec: Some(NetworkPolicySpec::default()),
            },
        )
        .await
        .expect("pre-create a fence that does not match the intended enforcement");

    let pods = Api::<Pod>::namespaced(kube.clone(), &case.namespace);
    let mut events = Box::pin(
        pods.watch(&WatchParams::default(), "0")
            .await
            .expect("watch the pods of the namespace"),
    );
    let driver = Driver::start(&case.namespace).await;
    let mut grpc = driver.client();
    let failed = grpc
        .create_sandbox(CreateSandboxRequest {
            sandbox: Some(case.sandbox(TEMPLATE_NAME, SANDBOX_IMAGE)),
        })
        .await
        .expect_err("create fails validating the mismatched fence");
    assert_eq!(failed.code(), Code::FailedPrecondition);
    drop(grpc);
    driver.stop().await;

    let mut added = Vec::new();
    while let Ok(Some(event)) = tokio::time::timeout(QUIET_WINDOW, events.next()).await {
        match event.expect("the pod watch stays open") {
            WatchEvent::Added(pod) => added.push(pod.name_any()),
            WatchEvent::Modified(_) | WatchEvent::Deleted(_) | WatchEvent::Bookmark(_) => {}
            WatchEvent::Error(error) => panic!("the pod watch failed: {error:?}"),
        }
    }
    assert!(
        added.is_empty(),
        "pods were created before the fence validation failed: {added:?}"
    );
}

/// The identities of one sandbox runtime, read from the API server.
#[derive(Debug, PartialEq, Eq)]
struct Runtime {
    /// UID of the record, the Lease.
    record_uid: String,
    /// UID of the start-inputs Secret.
    start_uid: String,
    /// UID of the workload pod.
    workload_uid: String,
    /// UID of the supervisor pod.
    supervisor_uid: String,
    /// Name and UID of each bootstrap Secret, sorted.
    bootstrap_secrets: Vec<(String, String)>,
}

/// Reads the identities of the runtime of `case`. Each of its pods must exist exactly once.
async fn read_runtime(kube: &Client, case: &Case) -> Runtime {
    let namespace = case.namespace.as_str();
    let (workload, _) = only_pod(kube, case, "workload").await;
    let (supervisor, _) = only_pod(kube, case, "supervisor").await;
    let selector = format!(
        "{LABEL_SANDBOX_ID}={},{LABEL_COMPONENT} in (sandbox-bootstrap,supervisor-bootstrap)",
        case.id
    );
    let mut bootstrap_secrets: Vec<(String, String)> =
        Api::<Secret>::namespaced(kube.clone(), namespace)
            .list(&ListParams::default().labels(&selector))
            .await
            .expect("list the bootstrap Secrets")
            .items
            .into_iter()
            .map(|secret| {
                (
                    secret.name_any(),
                    secret.uid().expect("the bootstrap Secret has a UID"),
                )
            })
            .collect();
    bootstrap_secrets.sort();
    Runtime {
        record_uid: get::<Lease>(kube, namespace, &case.name)
            .await
            .uid()
            .expect("the record has a UID"),
        start_uid: get::<Secret>(kube, namespace, &format!("os-start-{}", case.id))
            .await
            .uid()
            .expect("the start-inputs Secret has a UID"),
        workload_uid: workload.uid().expect("the workload pod has a UID"),
        supervisor_uid: supervisor.uid().expect("the supervisor pod has a UID"),
        bootstrap_secrets,
    }
}

/// The generation that the Start tests recreate a runtime for. Bootstrap Secret names keep the
/// first 12 alphanumerics of a generation ID, `g` and 11 of its 16 hex digits, so a generation of
/// at least `0x10_0000` is named apart from the create's generation 1.
const START_GENERATION: u64 = 0x10_0000;

/// Returns a Start request for `case` that recreates the runtime of `generation`, carrying that
/// generation's launch authentication and naming `expected_runtime_identity`.
fn start_request(
    case: &Case,
    generation: u64,
    expected_runtime_identity: &str,
) -> StartSandboxRequest {
    StartSandboxRequest {
        sandbox_id: case.id.clone(),
        name: case.name.clone(),
        launch_authentication: serde_json::to_vec(&launch_authentication(generation))
            .expect("encode the launch authentication"),
        generation_id: SandboxGenerationId::from_start_resource_version(generation).to_string(),
        expected_runtime_identity: expected_runtime_identity.to_owned(),
        ..Default::default()
    }
}

/// Asserts that a Start of `generation` recreated the runtime `before` describes, and that
/// `started_identity` is its identity.
///
/// The record and the start-inputs Secret keep their UIDs. Both pods are new, their scheduling
/// gates are released, and the identity names the record and the new supervisor pod. Only the
/// bootstrap Secrets of `generation` exist, and each of them is new.
async fn assert_recreated_runtime(
    kube: &Client,
    case: &Case,
    before: &Runtime,
    started_identity: &str,
    generation: u64,
) {
    let after = read_runtime(kube, case).await;
    assert_eq!(
        after.record_uid, before.record_uid,
        "the record keeps its UID"
    );
    assert_eq!(
        after.start_uid, before.start_uid,
        "the start-inputs Secret keeps its UID"
    );
    assert_ne!(
        after.workload_uid, before.workload_uid,
        "the workload pod is new"
    );
    assert_ne!(
        after.supervisor_uid, before.supervisor_uid,
        "the supervisor pod is new"
    );

    let (identity_ns, identity_lease, identity_pod) = identity_parts(started_identity);
    assert_eq!(identity_ns, case.namespace.as_str());
    assert_eq!(identity_lease, after.record_uid);
    assert_eq!(identity_pod, after.supervisor_uid);

    for role in ["workload", "supervisor"] {
        let (_, raw) = only_pod(kube, case, role).await;
        let gates = raw["spec"]["schedulingGates"].as_array();
        assert!(
            gates.is_none_or(Vec::is_empty),
            "{role} pod still carries a scheduling gate: {gates:?}"
        );
    }

    let names = SandboxRuntimeNames::for_generation(
        &case.id,
        &SandboxGenerationId::from_start_resource_version(generation).to_string(),
    );
    let mut expected = vec![names.sandbox_secret, names.supervisor_secret];
    expected.sort();
    let actual: Vec<String> = after
        .bootstrap_secrets
        .iter()
        .map(|(name, _)| name.clone())
        .collect();
    assert_eq!(
        actual, expected,
        "only the bootstrap Secrets of generation {generation} exist"
    );
    for (name, uid) in &after.bootstrap_secrets {
        assert!(
            !before
                .bootstrap_secrets
                .iter()
                .any(|(old_name, old_uid)| old_name == name || old_uid == uid),
            "bootstrap Secret {name} belongs to the previous generation"
        );
    }
}

#[tokio::test]
async fn e2e_stop_start_start_recreates_fresh_pods_with_a_new_generation() {
    let kube = kube_client().await;
    let case = Case::start(&kube, "restart").await;
    let driver = Driver::start(&case.namespace).await;
    let mut grpc = driver.client();
    let created_identity = create_valid_sandbox(&mut grpc, &kube, &case).await;
    let before = read_runtime(&kube, &case).await;

    grpc.stop_sandbox(StopSandboxRequest {
        sandbox_id: case.id.clone(),
        ..Default::default()
    })
    .await
    .expect("stop succeeds");
    let started_identity = grpc
        .start_sandbox(start_request(&case, START_GENERATION, &created_identity))
        .await
        .expect("start succeeds")
        .into_inner()
        .runtime_identity;
    drop(grpc);
    driver.stop().await;

    assert_recreated_runtime(&kube, &case, &before, &started_identity, START_GENERATION).await;
    case.finish(&kube).await;
}

#[tokio::test]
async fn e2e_start_without_stop_replaces_the_runtime() {
    let kube = kube_client().await;
    let case = Case::start(&kube, "restartnostop").await;
    let driver = Driver::start(&case.namespace).await;
    let mut grpc = driver.client();
    let created_identity = create_valid_sandbox(&mut grpc, &kube, &case).await;
    let before = read_runtime(&kube, &case).await;

    let started_identity = grpc
        .start_sandbox(start_request(&case, START_GENERATION, &created_identity))
        .await
        .expect("start succeeds on a running sandbox")
        .into_inner()
        .runtime_identity;
    drop(grpc);
    driver.stop().await;

    assert_recreated_runtime(&kube, &case, &before, &started_identity, START_GENERATION).await;
    case.finish(&kube).await;
}

#[tokio::test]
async fn e2e_start_rejects_each_invalid_request_and_changes_nothing() {
    let kube = kube_client().await;
    let case = Case::start(&kube, "startrejects").await;
    let driver = Driver::start(&case.namespace).await;
    let mut grpc = driver.client();
    let identity = create_valid_sandbox(&mut grpc, &kube, &case).await;
    let before = read_runtime(&kube, &case).await;
    let (namespace, lease, pod) = identity_parts(&identity);

    let rejected = [
        (
            "an empty sandbox ID",
            StartSandboxRequest {
                sandbox_id: String::new(),
                ..start_request(&case, START_GENERATION, &identity)
            },
            Code::InvalidArgument,
        ),
        (
            "an unknown sandbox",
            StartSandboxRequest {
                sandbox_id: format!("{}-unknown", case.id),
                ..start_request(&case, START_GENERATION, &identity)
            },
            Code::NotFound,
        ),
        (
            "an identity of another namespace",
            start_request(
                &case,
                START_GENERATION,
                &format!("kubernetes://other-{namespace}/{lease}/{pod}"),
            ),
            Code::FailedPrecondition,
        ),
        (
            "an identity of another record",
            start_request(
                &case,
                START_GENERATION,
                &format!("kubernetes://{namespace}/other-{lease}/{pod}"),
            ),
            Code::FailedPrecondition,
        ),
        (
            "a generation that differs from the launch authentication",
            StartSandboxRequest {
                generation_id: SandboxGenerationId::from_start_resource_version(1).to_string(),
                ..start_request(&case, START_GENERATION, &identity)
            },
            Code::InvalidArgument,
        ),
    ];
    for (rule, request, code) in rejected {
        let status = grpc.start_sandbox(request).await.expect_err(rule);
        assert_eq!(status.code(), code, "{rule}");
        assert_eq!(
            read_runtime(&kube, &case).await,
            before,
            "{rule} changes the runtime"
        );
    }

    Api::<PodTemplate>::namespaced(kube.clone(), &case.namespace)
        .delete(TEMPLATE_NAME, &DeleteParams::default())
        .await
        .expect("delete the PodTemplate");
    let missing = grpc
        .start_sandbox(start_request(&case, START_GENERATION, &identity))
        .await
        .expect_err("a start whose PodTemplate is gone is rejected");
    assert_eq!(missing.code(), Code::FailedPrecondition);
    assert_eq!(
        read_runtime(&kube, &case).await,
        before,
        "a start whose PodTemplate is gone changes the runtime"
    );

    drop(grpc);
    driver.stop().await;
    case.finish(&kube).await;
}

#[tokio::test]
async fn e2e_start_rejects_a_forged_start_inputs_secret() {
    let kube = kube_client().await;
    let case = Case::start(&kube, "startforged").await;
    let driver = Driver::start(&case.namespace).await;
    let mut grpc = driver.client();
    let identity = create_valid_sandbox(&mut grpc, &kube, &case).await;
    let record_uid = get::<Lease>(&kube, &case.namespace, &case.name)
        .await
        .uid()
        .expect("the record has a UID");
    grpc.stop_sandbox(StopSandboxRequest {
        sandbox_id: case.id.clone(),
        ..Default::default()
    })
    .await
    .expect("stop succeeds");

    // The start-inputs Secret is immutable, so the forgery replaces it. The forgery keeps the
    // sandbox ID label, and it names no Lease as its controller.
    let start_name = format!("os-start-{}", case.id);
    let secrets = Api::<Secret>::namespaced(kube.clone(), &case.namespace);
    secrets
        .delete(&start_name, &DeleteParams::default())
        .await
        .expect("delete the start-inputs Secret");
    let forged = Secret {
        metadata: ObjectMeta {
            name: Some(start_name),
            namespace: Some(case.namespace.clone()),
            labels: Some(BTreeMap::from([
                (LABEL_SANDBOX_ID.to_owned(), case.id.clone()),
                (
                    LABEL_COMPONENT.to_owned(),
                    "sandbox-start-inputs".to_owned(),
                ),
            ])),
            ..Default::default()
        },
        immutable: Some(true),
        data: Some(BTreeMap::from([(
            "driver-sandbox.pb".to_owned(),
            ByteString(case.sandbox(TEMPLATE_NAME, SANDBOX_IMAGE).encode_to_vec()),
        )])),
        ..Default::default()
    };
    let forged_uid = secrets
        .create(&PostParams::default(), &forged)
        .await
        .expect("create the forged start-inputs Secret")
        .uid()
        .expect("the forged Secret has a UID");

    let status = grpc
        .start_sandbox(start_request(&case, START_GENERATION, &identity))
        .await
        .expect_err("a start that reads a forged start-inputs Secret is rejected");
    assert_eq!(status.code(), Code::FailedPrecondition);
    drop(grpc);
    driver.stop().await;

    assert_runtime_stopped(&kube, &case, &record_uid, &forged_uid).await;
    case.finish(&kube).await;
}

#[tokio::test]
async fn e2e_start_rejects_a_deleting_record() {
    let kube = kube_client().await;
    let case = Case::start(&kube, "startdeleting").await;
    let driver = Driver::start(&case.namespace).await;
    let mut grpc = driver.client();
    let identity = create_valid_sandbox(&mut grpc, &kube, &case).await;

    // A finalizer keeps the record in place after the driver's delete, so the start meets a
    // record that is being deleted. The finalizer is released before the namespace is removed.
    let leases = Api::<Lease>::namespaced(kube.clone(), &case.namespace);
    leases
        .patch(
            &case.name,
            &PatchParams::default(),
            &Patch::Merge(&json!({"metadata": {"finalizers": ["odp-e2e/hold"]}})),
        )
        .await
        .expect("hold the record");
    let deleted = grpc
        .delete_sandbox(DeleteSandboxRequest {
            sandbox_id: case.id.clone(),
            ..Default::default()
        })
        .await
        .expect("delete succeeds")
        .into_inner()
        .deleted;
    assert!(deleted, "the delete starts deleting the record");

    let rejected = grpc
        .start_sandbox(start_request(&case, START_GENERATION, &identity))
        .await
        .expect_err("a start of a deleting record is rejected");
    assert_eq!(rejected.code(), Code::FailedPrecondition);
    drop(grpc);
    driver.stop().await;

    leases
        .patch(
            &case.name,
            &PatchParams::default(),
            &Patch::Merge(&json!({"metadata": {"finalizers": null}})),
        )
        .await
        .expect("release the record");
    await_no_sandbox_residue(&kube, &case).await;
    case.finish(&kube).await;
}

#[tokio::test]
async fn e2e_ensure_workspace_and_delete_workspace_are_unimplemented() {
    let driver = Driver::start("default").await;
    let mut grpc = driver.client();

    let ensure = grpc
        .ensure_workspace(EnsureWorkspaceRequest::default())
        .await
        .expect_err("ensure workspace is not implemented");
    assert_eq!(ensure.code(), Code::Unimplemented);

    let delete = grpc
        .delete_workspace(DeleteWorkspaceRequest::default())
        .await
        .expect_err("delete workspace is not implemented");
    assert_eq!(delete.code(), Code::Unimplemented);

    drop(grpc);
    driver.stop().await;
}

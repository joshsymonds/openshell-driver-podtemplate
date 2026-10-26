// SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
// SPDX-License-Identifier: Apache-2.0

//! Helpers for the gateway tests: the public API client, the fixture's names and the
//! Kubernetes reads that observe what the driver made and what remains.
//!
//! `e2e_gateway.rs` includes this file as its `gateway` module. Every item here is used there.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use k8s_openapi::ByteString;
use k8s_openapi::api::coordination::v1::Lease;
use k8s_openapi::api::core::v1::{
    Capabilities, Container, EphemeralContainer, Pod, PodSpec, PodTemplate, SeccompProfile, Secret,
    SecurityContext, Service,
};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::NetworkPolicy;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::serde::Serialize;
use k8s_openapi::serde::de::DeserializeOwned;
use kube::api::{DeleteParams, ListParams, LogParams, Patch, PatchParams, PostParams};
use kube::core::NamespaceResourceScope;
use kube::{Api, Client, Resource, ResourceExt};
use openshell_core::driver_utils::LABEL_MANAGED_BY;
use openshell_core::proto::open_shell_client::OpenShellClient;
use openshell_core::proto::{
    CreateSandboxRequest, DeleteSandboxRequest, DeletionOutcome, ExecSandboxRequest,
    GetSandboxRequest, ListSandboxesRequest, SandboxPhase, SandboxSpec, SandboxTemplate,
    StartSandboxRequest, StopSandboxRequest, WatchSandboxRequest, exec_sandbox_event,
    sandbox_stream_event, workspace_selector,
};
use openshell_policy::parse_sandbox_policy;
use prost_types::value::Kind;
use prost_types::{Struct, Value as ProtoValue};
use serde_json::json;
use tonic::Code;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

/// Environment variable that names the gateway endpoint the script forwards to the host.
pub const GATEWAY_ENDPOINT_ENV: &str = "ODP_GATEWAY_ENDPOINT";
/// Namespace of the gateway, the driver's sandboxes and the fixture.
pub const SANDBOX_NAMESPACE: &str = "openshell";
/// Gateway workspace that the requests select.
pub const WORKSPACE: &str = "default";
/// Secret holding the client certificate the gateway client presents.
pub const CLIENT_TLS_SECRET: &str = "openshell-client-tls";
/// Label that names the sandbox ID of a managed object.
pub const LABEL_SANDBOX_ID: &str = "openshell.ai/sandbox-id";
/// Label that names the role of a sandbox pod, workload or supervisor.
pub const LABEL_BOUNDARY_ROLE: &str = "openshell.ai/boundary-role";
/// Label that pairs a workload pod with its supervisor pod by the lowercased sandbox ID.
pub const LABEL_BOUNDARY_PAIR: &str = "openshell.ai/boundary-pair";
/// Label that names the Service an `EndpointSlice` belongs to.
pub const LABEL_SERVICE_NAME: &str = "kubernetes.io/service-name";
/// Label that names the component of a managed Secret.
const LABEL_COMPONENT: &str = "openshell.ai/component";
/// Component label value of the sandbox container's generation bootstrap Secret.
const SANDBOX_BOOTSTRAP_COMPONENT: &str = "sandbox-bootstrap";
/// Component label value of the supervisor container's generation bootstrap Secret.
const SUPERVISOR_BOOTSTRAP_COMPONENT: &str = "supervisor-bootstrap";
/// Value of the boundary role label on the workload pod.
pub const WORKLOAD_ROLE: &str = "workload";
/// Value of the boundary role label on the supervisor pod.
pub const SUPERVISOR_ROLE: &str = "supervisor";
/// Namespace `NetworkPolicy` that fences every workload pod.
pub const WORKLOAD_FENCE: &str = "openshell-sandbox-workloads";
/// Driver name the gateway selects a `driver_config` block by.
pub const DRIVER_NAME: &str = "podtemplate";
/// `PodTemplate` in the sandbox namespace that the sandbox is created from.
pub const FIXTURE_TEMPLATE: &str = "odp-fixture";
/// Image of the fixture's sandbox container, which the request must name.
pub const FIXTURE_IMAGE: &str = "docker.io/library/busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e";
/// Secret the fixture's `secretKeyRef` names.
pub const FIXTURE_CREDENTIAL: &str = "odp-fixture-credential";
/// Key of the fixture Secret that holds the credential value.
pub const FIXTURE_CREDENTIAL_KEY: &str = "token";
/// Pod of the gateway `StatefulSet`, which runs the driver sidecar.
pub const DRIVER_POD: &str = "openshell-0";
/// Container of the gateway pod that runs the podtemplate driver.
pub const DRIVER_CONTAINER: &str = "podtemplate-driver";
/// UID that the driver container runs as. The signalling container runs as the same UID.
const DRIVER_UID: i64 = 1000;
/// Name of the ephemeral container that sends SIGTERM to the driver's PID 1.
const SIGNAL_CONTAINER: &str = "odp-term";
/// File that the recording `PodTemplate`'s main process writes its environment to, in the served
/// emptyDir.
pub const ENVIRONMENT_RECORD: &str = "/tmp/bundle/environment";
/// Sandbox policy of the egress tests, which allows the echo Services the policy names.
const FIXTURE_POLICY: &str = include_str!("../../../../deploy/fixture/policy.yaml");
/// `PodTemplate` whose init container probes the TCP echo before the sandbox runtime starts.
pub const EGRESS_TEMPLATE: &str = "odp-fixture-egress";
/// File in the served emptyDir where the egress init container records `connected` or `failed`.
pub const INIT_RESULT: &str = "/tmp/bundle/init-result";
/// Pod of `echo.yaml` that serves the HTTP and TCP echoes.
pub const ECHO_POD: &str = "odp-echo";
/// In-cluster name of the HTTP echo Service that the fixture policy names.
pub const ECHO_HTTP_HOST: &str = "odp-echo-http.openshell.svc.cluster.local";
/// Port of the HTTP echo.
pub const ECHO_HTTP_PORT: u16 = 8080;
/// Body that the HTTP echo serves.
pub const ECHO_HTTP_BODY: &str = "odp-echo-http";
/// In-cluster name of the TCP echo Service that the fixture policy names.
pub const ECHO_TCP_HOST: &str = "odp-echo-tcp.openshell.svc.cluster.local";
/// Port of the TCP echo.
pub const ECHO_TCP_PORT: u16 = 9000;
/// Fixed `ClusterIP` of the TCP echo Service, for probes that run before the sandbox runtime
/// resolves names.
pub const ECHO_TCP_ADDRESS: &str = "10.96.200.9";
/// In-cluster name of the HTTP echo Service that the fixture policy does not name.
pub const ECHO_UNNAMED_HOST: &str = "odp-echo-unnamed.openshell.svc.cluster.local";
/// Bytes that a TCP probe sends to the TCP echo, which returns them.
pub const PROBE_PAYLOAD: &str = "odp-init-probe";

/// How long a test waits for a Kubernetes state to appear or disappear.
const WAIT_TIMEOUT: Duration = Duration::from_mins(2);
/// How long a test waits for the gateway to report a cold-started sandbox `READY`. A cold
/// start pulls images, which takes minutes on a fresh cluster.
pub const READY_TIMEOUT: Duration = Duration::from_mins(5);
/// How long the driver container may take to restart after SIGTERM. It exits at once on SIGTERM,
/// even while the gateway holds a watch open.
const DRIVER_RESTART_TIMEOUT: Duration = Duration::from_secs(20);
/// Interval between two reads while waiting.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Returns a Kubernetes client for the kind cluster that `KUBECONFIG` names.
pub async fn kube_client() -> Client {
    Client::try_default().await.expect("read KUBECONFIG")
}

/// Returns the fixture credential's value. No object the driver writes may carry it.
pub async fn fixture_credential(kube: &Client) -> String {
    let secret = Api::<Secret>::namespaced(kube.clone(), SANDBOX_NAMESPACE)
        .get(FIXTURE_CREDENTIAL)
        .await
        .expect("read the fixture credential Secret");
    let value = secret
        .data
        .unwrap_or_default()
        .remove(FIXTURE_CREDENTIAL_KEY)
        .expect("the fixture credential has a token");
    String::from_utf8(value.0).expect("the fixture credential is UTF-8")
}

/// Connects to the gateway at `ODP_GATEWAY_ENDPOINT`, presenting the client certificate of the
/// `CLIENT_TLS_SECRET` Secret and trusting its CA. The endpoint host is the TLS domain.
pub async fn connect(kube: &Client) -> OpenShellClient<Channel> {
    try_connect(kube).await.expect("connect to the gateway")
}

/// Connects like [`connect`] and returns the transport error when the gateway does not answer,
/// so that a caller can retry while the port-forward to the gateway is down.
pub async fn try_connect(
    kube: &Client,
) -> Result<OpenShellClient<Channel>, tonic::transport::Error> {
    let endpoint = std::env::var(GATEWAY_ENDPOINT_ENV)
        .unwrap_or_else(|_| panic!("{GATEWAY_ENDPOINT_ENV} names the gateway endpoint"));
    let secret = Api::<Secret>::namespaced(kube.clone(), SANDBOX_NAMESPACE)
        .get(CLIENT_TLS_SECRET)
        .await
        .expect("read the client TLS Secret");
    let data = secret.data.unwrap_or_default();
    let material = |key: &str| {
        data.get(key)
            .unwrap_or_else(|| panic!("{CLIENT_TLS_SECRET} has no {key}"))
            .0
            .clone()
    };
    let tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(material("ca.crt")))
        .identity(Identity::from_pem(material("tls.crt"), material("tls.key")));
    let channel = Endpoint::from_shared(endpoint)
        .expect("the gateway endpoint is a URI")
        .tls_config(tls)
        .expect("configure TLS for the gateway")
        .connect()
        .await?;
    Ok(OpenShellClient::new(channel))
}

/// Connects to the gateway like [`connect`], retrying until the port-forward to a replaced gateway
/// pod answers. Fails after `WAIT_TIMEOUT`.
pub async fn connect_when_listening(kube: &Client) -> OpenShellClient<Channel> {
    eventually("the gateway to accept connections", WAIT_TIMEOUT, || {
        let kube = kube.clone();
        async move { try_connect(&kube).await.ok() }
    })
    .await
}

/// Returns a fresh sandbox name that starts with `prefix`. The gateway limits names to 19
/// characters, so `prefix` may be at most 10 characters long.
pub fn sandbox_name(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after the epoch")
        .subsec_nanos();
    format!("{prefix}-{nanos:x}")
}

/// Returns a `CreateSandbox` request that names `template` as the `PodTemplate` under the driver's
/// `driver_config` block, runs the fixture image, and names `name` as the sandbox.
pub fn create_request(name: &str, template: &str) -> CreateSandboxRequest {
    let podtemplate = Struct {
        fields: BTreeMap::from([("template".to_owned(), string_value(template))]),
    };
    let driver_config = Struct {
        fields: BTreeMap::from([(
            DRIVER_NAME.to_owned(),
            ProtoValue {
                kind: Some(Kind::StructValue(podtemplate)),
            },
        )]),
    };
    CreateSandboxRequest {
        workspace_scope: Some(workspace_selector(WORKSPACE)),
        spec: Some(SandboxSpec {
            template: Some(SandboxTemplate {
                image: FIXTURE_IMAGE.to_owned(),
                driver_config: Some(driver_config),
                ..Default::default()
            }),
            ..Default::default()
        }),
        name: name.to_owned(),
        ..Default::default()
    }
}

/// Returns the `CreateSandbox` request of [`create_request`] with the fixture sandbox policy.
pub fn create_policed_request(name: &str, template: &str) -> CreateSandboxRequest {
    let mut request = create_request(name, template);
    let spec = request.spec.get_or_insert_with(SandboxSpec::default);
    spec.policy = Some(parse_sandbox_policy(FIXTURE_POLICY).expect("the fixture policy parses"));
    request
}

/// Returns a `DeleteSandbox` request for the sandbox `name`.
pub fn delete_request(name: &str) -> DeleteSandboxRequest {
    DeleteSandboxRequest {
        workspace_scope: Some(workspace_selector(WORKSPACE)),
        name: name.to_owned(),
        ..Default::default()
    }
}

/// Returns a `GetSandbox` request for the sandbox `name`.
pub fn get_request(name: &str) -> GetSandboxRequest {
    GetSandboxRequest {
        workspace_scope: Some(workspace_selector(WORKSPACE)),
        name: name.to_owned(),
    }
}

/// Returns a `StopSandbox` request for the sandbox `name`.
pub fn stop_request(name: &str) -> StopSandboxRequest {
    StopSandboxRequest {
        workspace_scope: Some(workspace_selector(WORKSPACE)),
        name: name.to_owned(),
        ..Default::default()
    }
}

/// Returns a `StartSandbox` request for the sandbox `name`.
pub fn start_request(name: &str) -> StartSandboxRequest {
    StartSandboxRequest {
        workspace_scope: Some(workspace_selector(WORKSPACE)),
        name: name.to_owned(),
        ..Default::default()
    }
}

/// Creates the `PodTemplate` `name` in the sandbox namespace, derived from the fixture's: the
/// same spec, so the same `secretKeyRef` env entry, with a main command that writes the process's
/// environment to `ENVIRONMENT_RECORD` and then runs `httpd` with the fixture's arguments.
pub async fn create_recording_template(kube: &Client, name: &str) {
    let record = format!("env > {ENVIRONMENT_RECORD} && exec \"$0\" \"$@\"");
    create_derived_template(kube, name, &["sh", "-c", record.as_str(), "httpd"], true).await;
}

/// Creates the `PodTemplate` `name` in the sandbox namespace, derived from the fixture's with its
/// main command replaced by `sh -c "exit <exit_code>"` and its readiness probe removed, so that the
/// main process ends with `exit_code` and no probe waits for a server.
pub async fn create_exit_template(kube: &Client, name: &str, exit_code: u8) {
    let script = format!("exit {exit_code}");
    create_derived_template(kube, name, &["sh", "-c", script.as_str()], false).await;
}

/// Creates the `PodTemplate` `name` in the sandbox namespace from the fixture's spec, with the main
/// container's command set to `command`. The readiness probe is kept when `readiness_probe` is set
/// and removed otherwise.
async fn create_derived_template(
    kube: &Client,
    name: &str,
    command: &[&str],
    readiness_probe: bool,
) {
    let fixture = Api::<PodTemplate>::namespaced(kube.clone(), SANDBOX_NAMESPACE)
        .get(FIXTURE_TEMPLATE)
        .await
        .expect("read the fixture PodTemplate");
    let mut template = fixture
        .template
        .expect("the fixture PodTemplate has a template");
    let spec = template
        .spec
        .as_mut()
        .expect("the fixture PodTemplate has a spec");
    let [container] = spec.containers.as_mut_slice() else {
        panic!("the fixture PodTemplate has one container");
    };
    container.command = Some(command.iter().map(|arg| (*arg).to_owned()).collect());
    if !readiness_probe {
        container.readiness_probe = None;
    }
    let derived = PodTemplate {
        metadata: ObjectMeta {
            name: Some(name.to_owned()),
            ..ObjectMeta::default()
        },
        template: Some(template),
    };
    Api::<PodTemplate>::namespaced(kube.clone(), SANDBOX_NAMESPACE)
        .create(&PostParams::default(), &derived)
        .await
        .expect("create the derived PodTemplate");
}

/// Deletes the `PodTemplate` `name` from the sandbox namespace.
pub async fn delete_template(kube: &Client, name: &str) {
    Api::<PodTemplate>::namespaced(kube.clone(), SANDBOX_NAMESPACE)
        .delete(name, &DeleteParams::default())
        .await
        .expect("delete the derived PodTemplate");
}

/// Returns the base64 form that `value` takes in the JSON encoding of a Secret.
pub fn base64_form(value: &str) -> String {
    serde_json::to_string(&ByteString(value.as_bytes().to_vec()))
        .expect("encode the value")
        .trim_matches('"')
        .to_owned()
}

/// Returns the log of the driver sidecar container in the gateway pod.
pub async fn driver_sidecar_log(kube: &Client) -> String {
    Api::<Pod>::namespaced(kube.clone(), SANDBOX_NAMESPACE)
        .logs(
            DRIVER_POD,
            &LogParams {
                container: Some(DRIVER_CONTAINER.to_owned()),
                ..LogParams::default()
            },
        )
        .await
        .expect("read the driver sidecar's log")
}

/// Returns the `restartCount` of the driver container in the gateway pod.
pub async fn driver_restart_count(kube: &Client) -> i32 {
    Api::<Pod>::namespaced(kube.clone(), SANDBOX_NAMESPACE)
        .get(DRIVER_POD)
        .await
        .expect("read the gateway pod")
        .status
        .and_then(|status| status.container_statuses)
        .unwrap_or_default()
        .iter()
        .find(|status| status.name == DRIVER_CONTAINER)
        .expect("the gateway pod reports the driver container")
        .restart_count
}

/// Sends SIGTERM to PID 1 of the driver container in the gateway pod. An ephemeral container that
/// targets the driver container joins its process namespace, where PID 1 is the driver. The
/// ephemeral container runs as the driver's UID under the restricted profile that the driver
/// sidecar uses, and the driver exits 0 on SIGTERM, so kubelet restarts it.
pub async fn signal_driver(kube: &Client) {
    let signaller = EphemeralContainer {
        name: SIGNAL_CONTAINER.to_owned(),
        image: Some(FIXTURE_IMAGE.to_owned()),
        command: Some(vec![
            "sh".to_owned(),
            "-c".to_owned(),
            "kill -TERM 1".to_owned(),
        ]),
        target_container_name: Some(DRIVER_CONTAINER.to_owned()),
        security_context: Some(SecurityContext {
            allow_privilege_escalation: Some(false),
            capabilities: Some(Capabilities {
                drop: Some(vec!["ALL".to_owned()]),
                ..Capabilities::default()
            }),
            run_as_non_root: Some(true),
            run_as_user: Some(DRIVER_UID),
            seccomp_profile: Some(SeccompProfile {
                type_: "RuntimeDefault".to_owned(),
                localhost_profile: None,
            }),
            ..SecurityContext::default()
        }),
        ..EphemeralContainer::default()
    };
    let patch = json!({"spec": {"ephemeralContainers": [signaller]}});
    Api::<Pod>::namespaced(kube.clone(), SANDBOX_NAMESPACE)
        .patch_ephemeral_containers(
            DRIVER_POD,
            &PatchParams::default(),
            &Patch::Strategic(patch),
        )
        .await
        .expect("attach the signalling ephemeral container to the gateway pod");
}

/// Waits until the driver container in the gateway pod has restarted, so that its `restartCount`
/// exceeds `previous`, and returns the new `restartCount`. Fails after `DRIVER_RESTART_TIMEOUT`.
pub async fn await_driver_restart(kube: &Client, previous: i32) -> i32 {
    eventually(
        "the driver container to restart",
        DRIVER_RESTART_TIMEOUT,
        || {
            let kube = kube.clone();
            async move {
                let count = driver_restart_count(&kube).await;
                (count > previous).then_some(count)
            }
        },
    )
    .await
}

/// Deletes the gateway pod and waits until the `StatefulSet` has replaced it with a Ready pod of
/// another UID. Fails after `READY_TIMEOUT`.
pub async fn replace_gateway_pod(kube: &Client) {
    let pods = Api::<Pod>::namespaced(kube.clone(), SANDBOX_NAMESPACE);
    let previous = pods
        .get(DRIVER_POD)
        .await
        .expect("read the gateway pod")
        .uid()
        .expect("the gateway pod has a UID");
    pods.delete(DRIVER_POD, &DeleteParams::default())
        .await
        .expect("delete the gateway pod");
    eventually(
        "the gateway pod to be replaced by a Ready pod",
        READY_TIMEOUT,
        || {
            let pods = pods.clone();
            let previous = previous.clone();
            async move {
                pods.get_opt(DRIVER_POD)
                    .await
                    .expect("read the gateway pod")
                    .filter(|pod| {
                        pod.uid().as_deref() != Some(previous.as_str()) && pod_is_ready(pod)
                    })
                    .map(|_| ())
            }
        },
    )
    .await;
}

/// Returns the pod IP address of the echo pod.
pub async fn echo_pod_ip(kube: &Client) -> String {
    Api::<Pod>::namespaced(kube.clone(), SANDBOX_NAMESPACE)
        .get(ECHO_POD)
        .await
        .expect("read the echo pod")
        .status
        .and_then(|status| status.pod_ip)
        .expect("the echo pod has a pod IP")
}

/// Runs `script` with `sh -c` in a pod named `name` that no namespace fence selects, waits for
/// the pod to finish, deletes it and returns its phase and its log.
pub async fn run_unfenced_pod(kube: &Client, name: &str, script: &str) -> (String, String) {
    let pods = Api::<Pod>::namespaced(kube.clone(), SANDBOX_NAMESPACE);
    let pod = Pod {
        metadata: ObjectMeta {
            name: Some(name.to_owned()),
            ..ObjectMeta::default()
        },
        spec: Some(PodSpec {
            restart_policy: Some("Never".to_owned()),
            containers: vec![Container {
                name: "probe".to_owned(),
                image: Some(FIXTURE_IMAGE.to_owned()),
                command: Some(vec!["sh".to_owned(), "-c".to_owned(), script.to_owned()]),
                ..Container::default()
            }],
            ..PodSpec::default()
        }),
        ..Pod::default()
    };
    pods.create(&PostParams::default(), &pod)
        .await
        .expect("create the unfenced pod");
    let phase = eventually("the unfenced pod to finish", WAIT_TIMEOUT, || {
        let pods = pods.clone();
        let name = name.to_owned();
        async move {
            let phase = pods
                .get(&name)
                .await
                .expect("read the unfenced pod")
                .status
                .and_then(|status| status.phase)?;
            matches!(phase.as_str(), "Succeeded" | "Failed").then_some(phase)
        }
    })
    .await;
    let log = pods
        .logs(name, &LogParams::default())
        .await
        .expect("read the unfenced pod's log");
    pods.delete(name, &DeleteParams::default())
        .await
        .expect("delete the unfenced pod");
    (phase, log)
}

/// Returns a string `Value` that holds `text`.
fn string_value(text: &str) -> ProtoValue {
    ProtoValue {
        kind: Some(Kind::StringValue(text.to_owned())),
    }
}

/// Waits until the gateway reports the sandbox `name` as `READY`. A gateway that reports
/// `ERROR` fails the wait at once, with the sandbox's status.
pub async fn await_ready(client: &OpenShellClient<Channel>, name: &str) {
    eventually("the sandbox to report READY", READY_TIMEOUT, || {
        let mut client = client.clone();
        let name = name.to_owned();
        async move {
            let sandbox = client
                .get_sandbox(get_request(&name))
                .await
                .expect("GetSandbox through the gateway")
                .into_inner()
                .sandbox
                .expect("GetSandbox returns the sandbox");
            match SandboxPhase::try_from(sandbox.phase()) {
                Ok(SandboxPhase::Ready) => Some(()),
                Ok(SandboxPhase::Error) => {
                    panic!(
                        "the gateway reports the sandbox ERROR: {:?}",
                        sandbox.status
                    )
                }
                _ => None,
            }
        }
    })
    .await;
}

/// Waits until the gateway reports the sandbox `name` as `phase`. A gateway that reports
/// `ERROR` fails the wait at once, with the sandbox's status.
pub async fn await_phase(client: &OpenShellClient<Channel>, name: &str, phase: SandboxPhase) {
    eventually(
        &format!("the sandbox to report {phase:?}"),
        READY_TIMEOUT,
        || {
            let mut client = client.clone();
            let name = name.to_owned();
            async move {
                let sandbox = client
                    .get_sandbox(get_request(&name))
                    .await
                    .expect("GetSandbox through the gateway")
                    .into_inner()
                    .sandbox
                    .expect("GetSandbox returns the sandbox");
                let current = SandboxPhase::try_from(sandbox.phase())
                    .expect("the gateway reports a known phase");
                assert!(
                    current != SandboxPhase::Error,
                    "the gateway reports the sandbox ERROR: {:?}",
                    sandbox.status
                );
                (current == phase).then_some(())
            }
        },
    )
    .await;
}

/// Deletes the sandbox `name` with ID `id` through the gateway, then waits until the gateway
/// no longer reports it and no object of it remains.
pub async fn delete_sandbox(
    client: &OpenShellClient<Channel>,
    kube: &Client,
    name: &str,
    id: &str,
) {
    delete_sandbox_with(client, kube, name, id, false).await;
}

/// Deletes the sandbox `name` with ID `id` like [`delete_sandbox`], for a sandbox that may already
/// be gone: the gateway deletes a sandbox whose main process has ended on its own, and then
/// `DeleteSandbox` answers `NotFound`.
pub async fn delete_ended_sandbox(
    client: &OpenShellClient<Channel>,
    kube: &Client,
    name: &str,
    id: &str,
) {
    delete_sandbox_with(client, kube, name, id, true).await;
}

/// Deletes the sandbox `name` with ID `id` through the gateway, then waits until the gateway
/// no longer reports it and no object of it remains. With `may_be_gone` set, a `NotFound` answer
/// to the deletion counts as the deletion having happened.
async fn delete_sandbox_with(
    client: &OpenShellClient<Channel>,
    kube: &Client,
    name: &str,
    id: &str,
    may_be_gone: bool,
) {
    let mut client = client.clone();
    let deleted = match client.delete_sandbox(delete_request(name)).await {
        Ok(response) => Some(response.into_inner()),
        Err(status) if may_be_gone && status.code() == Code::NotFound => None,
        Err(status) => panic!("DeleteSandbox through the gateway failed: {status}"),
    };
    if let Some(deleted) = deleted {
        assert!(
            matches!(
                deleted.outcome(),
                DeletionOutcome::Completed | DeletionOutcome::Accepted
            ),
            "DeleteSandbox accepts the deletion, got {:?}",
            deleted.outcome()
        );
    }

    eventually(
        "GetSandbox to report the sandbox gone",
        WAIT_TIMEOUT,
        || {
            let mut client = client.clone();
            let name = name.to_owned();
            async move {
                match client.get_sandbox(get_request(&name)).await {
                    Ok(_) => None,
                    Err(status) if status.code() == Code::NotFound => Some(()),
                    Err(status) => panic!("GetSandbox failed: {status}"),
                }
            }
        },
    )
    .await;
    await_removed(kube, name, id).await;
}

/// Waits until the gateway reports the sandbox `name` in a phase other than `Provisioning` and
/// keeps reporting that phase for `hold`, and returns that phase. A phase that changes within
/// `hold` restarts the wait. Fails when the sandbox does not settle within `READY_TIMEOUT`.
pub async fn await_held_phase(
    client: &OpenShellClient<Channel>,
    name: &str,
    hold: Duration,
) -> SandboxPhase {
    let mut client = client.clone();
    let deadline = Instant::now() + READY_TIMEOUT;
    let mut current: Option<(SandboxPhase, Instant)> = None;
    loop {
        let sandbox = client
            .get_sandbox(get_request(name))
            .await
            .expect("GetSandbox through the gateway")
            .into_inner()
            .sandbox
            .expect("GetSandbox returns the sandbox");
        let phase =
            SandboxPhase::try_from(sandbox.phase()).expect("the gateway reports a known phase");
        let since = match current {
            Some((previous, since)) if previous == phase => since,
            _ => Instant::now(),
        };
        current = Some((phase, since));
        if phase != SandboxPhase::Provisioning && since.elapsed() >= hold {
            return phase;
        }
        assert!(
            Instant::now() < deadline,
            "timed out after {READY_TIMEOUT:?} waiting for the sandbox to settle, last reported {phase:?}: {:?}",
            sandbox.status
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Returns the Kubernetes phase of the workload pod `name` in the sandbox namespace, or `absent`
/// when the pod does not exist.
pub async fn workload_pod_phase(kube: &Client, name: &str) -> String {
    Api::<Pod>::namespaced(kube.clone(), SANDBOX_NAMESPACE)
        .get_opt(name)
        .await
        .expect("read the workload pod")
        .map_or_else(
            || "absent".to_owned(),
            |pod| {
                pod.status
                    .and_then(|status| status.phase)
                    .unwrap_or_else(|| "unknown".to_owned())
            },
        )
}

/// Waits until the pod `name` in the sandbox namespace reports its `Ready` condition as
/// `True`, and returns it. The gateway reports `READY` once the supervisor runs the main
/// process, which can precede the workload pod's readiness probe passing.
pub async fn await_ready_pod(kube: &Client, name: &str) -> Pod {
    await_pod_readiness(kube, name, true).await
}

/// Waits until the pod `name` in the sandbox namespace reports its `Ready` condition as
/// anything but `True`, and returns it.
pub async fn await_unready_pod(kube: &Client, name: &str) -> Pod {
    await_pod_readiness(kube, name, false).await
}

/// Waits until the pod `name` in the sandbox namespace has its `Ready` condition `True` when
/// `ready` is set and not `True` otherwise, and returns it.
async fn await_pod_readiness(kube: &Client, name: &str, ready: bool) -> Pod {
    let pods = Api::<Pod>::namespaced(kube.clone(), SANDBOX_NAMESPACE);
    let what = if ready {
        "the workload pod to be Ready"
    } else {
        "the workload pod to be NotReady"
    };
    eventually(what, READY_TIMEOUT, || {
        let pods = pods.clone();
        let name = name.to_owned();
        async move {
            pods.get_opt(&name)
                .await
                .expect("read the workload pod")
                .filter(|pod| pod_is_ready(pod) == ready)
        }
    })
    .await
}

/// Returns whether the pod reports its `Ready` condition as `True`.
fn pod_is_ready(pod: &Pod) -> bool {
    pod.status
        .iter()
        .flat_map(|status| status.conditions.iter().flatten())
        .any(|condition| condition.type_ == "Ready" && condition.status == "True")
}

/// The result of an `ExecSandbox` call: the command's exit code and its output.
pub struct ExecOutcome {
    /// The exit code the command reported.
    pub exit_code: i32,
    /// The stdout and stderr chunks of the command, in the order they arrived.
    pub output: String,
}

/// Runs `command` in the sandbox `name` through the gateway's `ExecSandbox`, without a login
/// shell, and returns its exit code and output. Fails when the stream closes before the command
/// reports its exit code.
pub async fn exec_in_sandbox(
    client: &OpenShellClient<Channel>,
    name: &str,
    command: &[&str],
) -> ExecOutcome {
    let request = ExecSandboxRequest {
        workspace_scope: Some(workspace_selector(WORKSPACE)),
        sandbox: name.to_owned(),
        command: command.iter().map(|arg| (*arg).to_owned()).collect(),
        no_login_shell: true,
        ..Default::default()
    };
    let mut stream = client
        .clone()
        .exec_sandbox(request)
        .await
        .expect("ExecSandbox through the gateway")
        .into_inner();

    let mut output = String::new();
    let mut exit_code = None;
    while let Some(event) = stream.message().await.expect("the ExecSandbox stream") {
        match event.payload {
            Some(exec_sandbox_event::Payload::Stdout(chunk)) => {
                output.push_str(&String::from_utf8_lossy(&chunk.data));
            }
            Some(exec_sandbox_event::Payload::Stderr(chunk)) => {
                output.push_str(&String::from_utf8_lossy(&chunk.data));
            }
            Some(exec_sandbox_event::Payload::Exit(exit)) => exit_code = Some(exit.exit_code),
            None => {}
        }
    }
    ExecOutcome {
        exit_code: exit_code.expect("ExecSandbox reports the command's exit code"),
        output,
    }
}

/// Watches the sandbox `name` through the gateway's `WatchSandbox` and appends the phase of each
/// status snapshot to `phases`, until the stream ends. The caller aborts the task to stop the
/// watch, and checks that the task still runs before it deletes the sandbox.
pub async fn watch_phases(
    mut client: OpenShellClient<Channel>,
    name: String,
    phases: Arc<Mutex<Vec<SandboxPhase>>>,
) {
    let mut stream = client
        .watch_sandbox(WatchSandboxRequest {
            workspace_scope: Some(workspace_selector(WORKSPACE)),
            sandbox: name,
            follow_status: true,
            ..Default::default()
        })
        .await
        .expect("WatchSandbox through the gateway")
        .into_inner();
    while let Some(event) = stream.message().await.expect("the WatchSandbox stream") {
        if let Some(sandbox_stream_event::Payload::Sandbox(sandbox)) = event.payload {
            let phase =
                SandboxPhase::try_from(sandbox.phase()).expect("the gateway reports a known phase");
            phases
                .lock()
                .expect("the phase record is not poisoned")
                .push(phase);
        }
    }
}

/// Opens a `WatchSandbox` stream of the sandbox `name` and waits until the gateway delivers its
/// first status snapshot. Fails after `WAIT_TIMEOUT`.
pub async fn await_watch_snapshot(client: &OpenShellClient<Channel>, name: &str) {
    let mut stream = client
        .clone()
        .watch_sandbox(WatchSandboxRequest {
            workspace_scope: Some(workspace_selector(WORKSPACE)),
            sandbox: name.to_owned(),
            follow_status: true,
            ..Default::default()
        })
        .await
        .expect("WatchSandbox through the gateway")
        .into_inner();
    let delivered = tokio::time::timeout(WAIT_TIMEOUT, async {
        while let Some(event) = stream.message().await.expect("the WatchSandbox stream") {
            if matches!(
                event.payload,
                Some(sandbox_stream_event::Payload::Sandbox(_))
            ) {
                return true;
            }
        }
        false
    })
    .await
    .expect("WatchSandbox delivers a snapshot of the sandbox within the wait bound");
    assert!(
        delivered,
        "the WatchSandbox stream of {name} ended before its snapshot"
    );
}

/// Returns the ID of each sandbox that the gateway lists in the workspace, following every page
/// of the listing.
pub async fn list_sandbox_ids(client: &OpenShellClient<Channel>) -> Vec<String> {
    let mut ids = Vec::new();
    let mut page_token = String::new();
    loop {
        let page = client
            .clone()
            .list_sandboxes(ListSandboxesRequest {
                workspace_scope: Some(workspace_selector(WORKSPACE)),
                page_token: page_token.clone(),
                ..Default::default()
            })
            .await
            .expect("ListSandboxes through the gateway")
            .into_inner();
        ids.extend(
            page.sandboxes
                .into_iter()
                .filter_map(|sandbox| sandbox.metadata)
                .map(|metadata| metadata.id),
        );
        if page.next_page_token.is_empty() {
            return ids;
        }
        page_token = page.next_page_token;
    }
}

/// Returns the Leases, pods, Services and Secrets of the sandbox `name` with ID `id`, each as
/// `kind/name` with its JSON encoding. Objects are matched by name and by the sandbox ID label.
pub async fn sandbox_objects(kube: &Client, name: &str, id: &str) -> Vec<(String, String)> {
    let mut found = named_objects(kube, name).await;
    let by_id = ListParams::default().labels(&format!("{LABEL_SANDBOX_ID}={id}"));
    found.extend(objects_matching(kube, &by_id).await);
    found
}

/// Returns the Leases, pods, Services and Secrets named `name` in the sandbox namespace, each as
/// `kind/name` with its JSON encoding. It finds the objects of that name whether or not the
/// gateway assigned the sandbox an ID.
pub async fn named_objects(kube: &Client, name: &str) -> Vec<(String, String)> {
    let by_name = ListParams::default().fields(&format!("metadata.name={name}"));
    objects_matching(kube, &by_name).await
}

/// Lists the Leases, pods, Services and Secrets that match `params`, encoded as
/// [`sandbox_objects`] describes.
async fn objects_matching(kube: &Client, params: &ListParams) -> Vec<(String, String)> {
    let mut found = Vec::new();
    found.extend(list::<Lease>(kube, params, "Lease").await);
    found.extend(list::<Pod>(kube, params, "Pod").await);
    found.extend(list::<Service>(kube, params, "Service").await);
    found.extend(list_secrets(kube, params).await);
    found
}

/// Returns each Lease, pod, Service, Secret and `NetworkPolicy` in the sandbox namespace that
/// carries the driver's managed-by label, encoded as [`sandbox_objects`] describes. The namespace
/// fence `NetworkPolicy`s are among them.
pub async fn driver_objects(kube: &Client) -> Vec<(String, String)> {
    let params = ListParams::default().labels(LABEL_MANAGED_BY);
    let mut found = Vec::new();
    found.extend(list::<Lease>(kube, &params, "Lease").await);
    found.extend(list::<Pod>(kube, &params, "Pod").await);
    found.extend(list::<Service>(kube, &params, "Service").await);
    found.extend(list_secrets(kube, &params).await);
    found.extend(list::<NetworkPolicy>(kube, &params, "NetworkPolicy").await);
    found
}

/// Returns `kind/name uid` for each Lease, pod, Service, Secret and `NetworkPolicy` in the sandbox
/// namespace that carries the driver's managed-by label, sorted. Two equal lists mean that no
/// such object was created, deleted or replaced between the reads.
pub async fn driver_object_uids(kube: &Client) -> Vec<String> {
    let params = ListParams::default().labels(LABEL_MANAGED_BY);
    let mut found = Vec::new();
    found.extend(uids::<Lease>(kube, &params, "Lease").await);
    found.extend(uids::<Pod>(kube, &params, "Pod").await);
    found.extend(uids::<Service>(kube, &params, "Service").await);
    found.extend(uids::<Secret>(kube, &params, "Secret").await);
    found.extend(uids::<NetworkPolicy>(kube, &params, "NetworkPolicy").await);
    found.sort();
    found
}

/// Lists the objects of kind `K` in the sandbox namespace that match `params`, and returns each
/// as `kind/name uid`.
async fn uids<K>(kube: &Client, params: &ListParams, kind: &str) -> Vec<String>
where
    K: Resource<Scope = NamespaceResourceScope> + Clone + DeserializeOwned + Debug,
    K::DynamicType: Default,
{
    Api::<K>::namespaced(kube.clone(), SANDBOX_NAMESPACE)
        .list(params)
        .await
        .expect("list the driver's objects")
        .items
        .into_iter()
        .map(|object| {
            let uid = object.uid().unwrap_or_default();
            format!("{kind}/{} {uid}", object.name_any())
        })
        .collect()
}

/// Lists the objects of kind `K` in the sandbox namespace that match `params`, and encodes each
/// as `kind/name` with its JSON.
async fn list<K>(kube: &Client, params: &ListParams, kind: &str) -> Vec<(String, String)>
where
    K: Resource<Scope = NamespaceResourceScope> + Clone + DeserializeOwned + Debug + Serialize,
    K::DynamicType: Default,
{
    Api::<K>::namespaced(kube.clone(), SANDBOX_NAMESPACE)
        .list(params)
        .await
        .expect("list the sandbox's objects")
        .items
        .into_iter()
        .map(|object| {
            let encoded = serde_json::to_string(&object).expect("encode the object");
            (format!("{kind}/{}", object.name_any()), encoded)
        })
        .collect()
}

/// Lists the Secrets in the sandbox namespace that match `params` like [`list`], and appends
/// each Secret's decoded data values to its encoding, which carries them only in base64.
async fn list_secrets(kube: &Client, params: &ListParams) -> Vec<(String, String)> {
    Api::<Secret>::namespaced(kube.clone(), SANDBOX_NAMESPACE)
        .list(params)
        .await
        .expect("list the sandbox's Secrets")
        .items
        .into_iter()
        .map(|secret| {
            let mut encoded = serde_json::to_string(&secret).expect("encode the Secret");
            for value in secret.data.iter().flat_map(BTreeMap::values) {
                encoded.push('\n');
                encoded.push_str(&String::from_utf8_lossy(&value.0));
            }
            (format!("Secret/{}", secret.name_any()), encoded)
        })
        .collect()
}

/// Waits until the object `name` of kind `K` exists in the sandbox namespace, and returns it.
pub async fn await_object<K>(kube: &Client, name: &str, what: &str) -> K
where
    K: Resource<Scope = NamespaceResourceScope> + Clone + DeserializeOwned + Debug,
    K::DynamicType: Default,
{
    let objects = Api::<K>::namespaced(kube.clone(), SANDBOX_NAMESPACE);
    eventually(what, WAIT_TIMEOUT, || {
        let objects = objects.clone();
        let name = name.to_owned();
        async move { objects.get_opt(&name).await.expect("read the object") }
    })
    .await
}

/// Returns the names of the sandbox `id`'s two generation bootstrap Secrets, sorted. A stopped
/// sandbox has none.
pub async fn bootstrap_secret_names(kube: &Client, id: &str) -> Vec<String> {
    let params = ListParams::default().labels(&format!(
        "{LABEL_SANDBOX_ID}={id},{LABEL_COMPONENT} in ({SANDBOX_BOOTSTRAP_COMPONENT},{SUPERVISOR_BOOTSTRAP_COMPONENT})"
    ));
    let mut names: Vec<String> = Api::<Secret>::namespaced(kube.clone(), SANDBOX_NAMESPACE)
        .list(&params)
        .await
        .expect("list the bootstrap Secrets")
        .items
        .iter()
        .map(ResourceExt::name_any)
        .collect();
    names.sort();
    names
}

/// Waits until no pod and no bootstrap Secret of the sandbox with ID `id` remains. The sandbox's
/// Lease and start-inputs Secret stay.
pub async fn await_runtime_gone(kube: &Client, id: &str) {
    let pods = Api::<Pod>::namespaced(kube.clone(), SANDBOX_NAMESPACE);
    let by_pair = ListParams::default().labels(&format!(
        "{LABEL_BOUNDARY_PAIR}={}",
        id.to_ascii_lowercase()
    ));
    eventually("the sandbox's pods to be gone", WAIT_TIMEOUT, || {
        let pods = pods.clone();
        let by_pair = by_pair.clone();
        async move {
            pods.list(&by_pair)
                .await
                .expect("list the sandbox's pods")
                .items
                .is_empty()
                .then_some(())
        }
    })
    .await;
    eventually(
        "the sandbox's bootstrap Secrets to be gone",
        WAIT_TIMEOUT,
        || async move {
            bootstrap_secret_names(kube, id)
                .await
                .is_empty()
                .then_some(())
        },
    )
    .await;
}

/// Waits until no Lease, pod, Service or Secret of the sandbox `name` with ID `id` remains. On
/// timeout it fails with the `kind/name` of each object that is still present.
pub async fn await_removed(kube: &Client, name: &str, id: &str) {
    let deadline = Instant::now() + WAIT_TIMEOUT;
    loop {
        let remaining: Vec<String> = sandbox_objects(kube, name, id)
            .await
            .into_iter()
            .map(|(object, _)| object)
            .collect();
        if remaining.is_empty() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "objects of the sandbox remain: {remaining:?}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Returns `kind/name` for each Lease, pod, Service, Secret and `EndpointSlice` that carries one of
/// the sandbox `id`'s labels. The sandbox ID labels the Leases, Services, Secrets and
/// `EndpointSlice` of the boundary Service `boundary_service`, and the boundary pair labels the
/// pods. The workload pod carries the pair label only.
pub async fn labelled_objects(kube: &Client, id: &str, boundary_service: &str) -> Vec<String> {
    let by_id = ListParams::default().labels(&format!("{LABEL_SANDBOX_ID}={id}"));
    let by_pair = ListParams::default().labels(&format!(
        "{LABEL_BOUNDARY_PAIR}={}",
        id.to_ascii_lowercase()
    ));
    let by_service =
        ListParams::default().labels(&format!("{LABEL_SERVICE_NAME}={boundary_service}"));
    let mut found = Vec::new();
    found.extend(names::<Lease>(kube, &by_id, "Lease").await);
    found.extend(names::<Pod>(kube, &by_id, "Pod").await);
    found.extend(names::<Pod>(kube, &by_pair, "Pod").await);
    found.extend(names::<Service>(kube, &by_id, "Service").await);
    found.extend(names::<Secret>(kube, &by_id, "Secret").await);
    found.extend(names::<EndpointSlice>(kube, &by_id, "EndpointSlice").await);
    found.extend(names::<EndpointSlice>(kube, &by_service, "EndpointSlice").await);
    found.sort();
    found.dedup();
    found
}

/// Lists the objects of kind `K` in the sandbox namespace that match `params`, and returns each
/// as `kind/name`.
async fn names<K>(kube: &Client, params: &ListParams, kind: &str) -> Vec<String>
where
    K: Resource<Scope = NamespaceResourceScope> + Clone + DeserializeOwned + Debug,
    K::DynamicType: Default,
{
    Api::<K>::namespaced(kube.clone(), SANDBOX_NAMESPACE)
        .list(params)
        .await
        .expect("list the sandbox's labelled objects")
        .items
        .into_iter()
        .map(|object| format!("{kind}/{}", object.name_any()))
        .collect()
}

/// Waits until no object that carries one of the sandbox `id`'s labels remains. On timeout it
/// fails with the `kind/name` of each object that is still present.
pub async fn await_unlabelled(kube: &Client, id: &str, boundary_service: &str) {
    let deadline = Instant::now() + WAIT_TIMEOUT;
    loop {
        let remaining = labelled_objects(kube, id, boundary_service).await;
        if remaining.is_empty() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "objects carrying the sandbox's labels remain: {remaining:?}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Polls `attempt` until it returns `Some`, and returns that value. Fails after `bound`.
async fn eventually<T, Fut>(what: &str, bound: Duration, mut attempt: impl FnMut() -> Fut) -> T
where
    Fut: Future<Output = Option<T>>,
{
    let deadline = Instant::now() + bound;
    loop {
        if let Some(value) = attempt().await {
            return value;
        }
        assert!(
            Instant::now() < deadline,
            "timed out after {bound:?} waiting for {what}"
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

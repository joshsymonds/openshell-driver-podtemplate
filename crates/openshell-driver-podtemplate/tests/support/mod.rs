// SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
// SPDX-License-Identifier: Apache-2.0

//! Shared harness for the kind-backed e2e suite.
//!
//! [`Driver`] runs the real driver binary on a private Unix socket and holds a gRPC channel to
//! it. [`Case`] is one test's namespace and sandbox identity. The remaining functions read the
//! Kubernetes objects the suite asserts on, and build the template and sandbox fixtures.

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use k8s_openapi::ByteString;
use k8s_openapi::api::admissionregistration::v1::ValidatingWebhookConfiguration;
use k8s_openapi::api::authentication::v1::TokenRequest;
use k8s_openapi::api::coordination::v1::Lease;
use k8s_openapi::api::core::v1::{Namespace, Pod, PodTemplate, Secret, Service, ServiceAccount};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::NetworkPolicy;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::serde::Serialize;
use k8s_openapi::serde::de::DeserializeOwned;
use kube::api::{DeleteParams, DynamicObject, ListParams, LogParams, PostParams};
use kube::config::Kubeconfig;
use kube::core::{ApiResource, NamespaceResourceScope};
use kube::{Api, Client, Config, Resource, ResourceExt};
use openshell_core::SandboxSessionId;
use openshell_core::jwt::{
    CredentialEpoch, SandboxLaunchAuthentication, SecretJwt, SessionRotation,
    SessionVerificationKey, SupervisorAuthBundle,
};
use openshell_core::proto::compute::v1::compute_driver_client::ComputeDriverClient;
use openshell_core::proto::compute::v1::{DriverSandbox, DriverSandboxSpec, DriverSandboxTemplate};
use openshell_core::sandbox_generation::SandboxGenerationId;
use openshell_driver_podtemplate::runtime_objects::SandboxRuntimeNames;
use prost_types::value::Kind;
use prost_types::{Struct, Value as ProtoValue};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tonic::transport::{Channel, Endpoint, Uri};

/// Gateway identifier the driver is started with, and the launch authentication names.
pub const GATEWAY_ID: &str = "e2e-gateway";
/// Sandbox image that the valid template and every sandbox request name.
pub const SANDBOX_IMAGE: &str = "registry.e2e.invalid/agent:e2e";
/// Plain environment value of the template. It may appear in the workload pod's spec only.
pub const PLAIN_ENV_VALUE: &str = "plain-env-value-7f3a9c";
/// Name of the user Secret that the template's `secretKeyRef` names.
pub const USER_SECRET_NAME: &str = "user-credential";
/// Value of the user Secret. No driver-written object may carry it.
pub const USER_SECRET_VALUE: &str = "user-credential-value-5e1d8b";
/// Gateway session token inside the launch authentication.
pub const GATEWAY_TOKEN: &str = "gateway-token-e2e-4c7a";
/// Sandbox session token inside the launch authentication.
pub const SANDBOX_TOKEN: &str = "sandbox-token-e2e-9d2b";
/// Name of the `PodTemplate` that the valid cases create.
pub const TEMPLATE_NAME: &str = "agent-template";
/// Label that names the sandbox ID of a managed object.
pub const LABEL_SANDBOX_ID: &str = "openshell.ai/sandbox-id";
/// Label that names the boundary role of a pod.
pub const LABEL_BOUNDARY_ROLE: &str = "openshell.ai/boundary-role";
/// Label that pairs a workload pod with its supervisor pod.
pub const LABEL_BOUNDARY_PAIR: &str = "openshell.ai/boundary-pair";
/// Label that names the component a managed object belongs to.
pub const LABEL_COMPONENT: &str = "openshell.ai/component";

/// How long a test waits for the driver socket, a Kubernetes state, or a watch event.
const WAIT_TIMEOUT: Duration = Duration::from_mins(2);
/// Interval between two reads while waiting.
const POLL_INTERVAL: Duration = Duration::from_millis(250);
/// How long [`Driver::stop`] waits for the driver to exit after SIGTERM.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
/// Image of the hold backend, which provides `openssl` and `sh`. It is pinned by digest.
const HOLD_IMAGE: &str = "docker.io/alpine/openssl:3.5.8@sha256:3f25da71f70eba788067daac3f3df03bd1de7a7c52ed89fa93b94ad2c92d986b";
/// Port that the hold backend listens on. Its Service maps the webhook port to it.
const HOLD_PORT: u16 = 8443;
/// Timeout of the hold webhook. It is the largest value the API server accepts.
const HOLD_TIMEOUT: Duration = Duration::from_secs(30);
/// Timeout of the probe webhook, which matches only the probe and so proves the hold in a second.
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
/// Label that marks the object [`CreateHold::install`] creates to prove the hold is in effect.
/// The hold webhook does not match an object that carries it.
const HOLD_PROBE_LABEL: &str = "odp.invalid/hold-probe";
/// Name of the object that [`CreateHold::install`] creates to prove the hold is in effect.
const HOLD_PROBE: &str = "hold-probe";
/// First line of a PEM certificate, which the hold backend prints to its log.
const PEM_CERTIFICATE_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
/// Last line of a PEM certificate.
const PEM_CERTIFICATE_END: &str = "-----END CERTIFICATE-----";
/// Expiry of the launch authentication tokens: 2100-01-01, far beyond any test run.
const FAR_FUTURE_EXPIRY: i64 = 4_102_444_800;
/// A PEM-shaped verification key. The driver reads it as bytes and never checks its signature.
const VERIFICATION_KEY_PEM: &[u8] =
    b"-----BEGIN PUBLIC KEY-----\ne2e-verification-key\n-----END PUBLIC KEY-----\n";

/// A running driver process and the gRPC channel to its socket.
pub struct Driver {
    child: Option<Child>,
    channel: Option<Channel>,
    _directory: tempfile::TempDir,
}

impl Driver {
    /// Starts the driver binary with its sandbox namespace set to `namespace`, and connects to
    /// its socket once the socket is bound. The driver reads the API server that `KUBECONFIG`
    /// names.
    pub async fn start(namespace: &str) -> Self {
        Self::launch(namespace, None).await
    }

    /// Starts the driver binary as [`Driver::start`] does, with a `KUBECONFIG` that names `relay`
    /// in place of the API server.
    pub async fn start_through(namespace: &str, relay: &Relay) -> Self {
        Self::launch(namespace, Some(relay.kubeconfig())).await
    }

    /// Starts the driver binary with `kubeconfig` as its `KUBECONFIG`, when one is given.
    async fn launch(namespace: &str, kubeconfig: Option<&Path>) -> Self {
        let directory = tempfile::tempdir().expect("create driver directory");
        let socket = directory.path().join("driver.sock");
        let mut command = Command::new(env!("CARGO_BIN_EXE_openshell-driver-podtemplate"));
        command
            .arg("--bind-socket")
            .arg(&socket)
            .arg("--sandbox-namespace")
            .arg(namespace)
            .arg("--gateway-id")
            .arg(GATEWAY_ID)
            .arg("--grpc-endpoint")
            .arg("http://gateway.e2e.invalid:8080")
            .arg("--probe-helper-image")
            .arg("registry.e2e.invalid/odp-probe:e2e")
            .arg("--supervisor-image")
            .arg("registry.e2e.invalid/supervisor:e2e")
            .arg("--sandbox-runtime-image")
            .arg("registry.e2e.invalid/runtime:e2e");
        if let Some(kubeconfig) = kubeconfig {
            command.env("KUBECONFIG", kubeconfig);
        }
        let mut child = command.spawn().expect("start the driver binary");
        wait_for_socket(&mut child, &socket).await;
        let channel = connect(socket).await;
        Self {
            child: Some(child),
            channel: Some(channel),
            _directory: directory,
        }
    }

    /// Returns a `ComputeDriver` client on this driver's channel. A client or watch stream may
    /// stay open across [`Driver::stop`], because the driver ends its open watches on shutdown.
    pub fn client(&self) -> ComputeDriverClient<Channel> {
        ComputeDriverClient::new(self.channel.clone().expect("driver channel is open"))
    }

    /// Stops the driver with SIGTERM and asserts that it exits successfully within
    /// [`SHUTDOWN_TIMEOUT`].
    pub async fn stop(mut self) {
        drop(self.channel.take());
        let mut child = self.child.take().expect("driver is running");
        let pid = child.id();
        let signalled = Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .status()
            .expect("run kill");
        assert!(signalled.success(), "kill -TERM {pid} failed");
        let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
        let status = loop {
            if let Some(status) = child.try_wait().expect("poll the driver") {
                break status;
            }
            if Instant::now() >= deadline {
                child.kill().expect("kill the driver that did not exit");
                panic!("driver {pid} did not exit within {SHUTDOWN_TIMEOUT:?}");
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        };
        assert!(status.success(), "driver exited with {status}");
    }
}

impl Drop for Driver {
    fn drop(&mut self) {
        // Reached only when a test panics before `stop`. The process is killed so that it does
        // not outlive the test.
        if let Some(child) = self.child.as_mut() {
            if let Err(error) = child.kill() {
                eprintln!("could not kill the driver: {error}");
            }
            if let Err(error) = child.wait() {
                eprintln!("could not reap the driver: {error}");
            }
        }
    }
}

/// A TCP relay between a driver and the API server, which the driver reaches through
/// [`Driver::start_through`].
///
/// The relay forwards bytes both ways. When the driver closes a connection, the relay does not
/// close the upstream connection, which stays open until the API server closes it. A frozen
/// connection also withholds the driver's bytes, the TLS `close_notify` of a close included, so the
/// API server does not read the driver's close as a client that left.
pub struct Relay {
    _directory: tempfile::TempDir,
    kubeconfig: PathBuf,
    generation: Arc<AtomicUsize>,
}

impl Relay {
    /// Starts the relay to the API server that `KUBECONFIG` names, and writes a kubeconfig that
    /// names the relay in its place. The API server's certificate covers `127.0.0.1`, the relay's
    /// address.
    pub async fn start() -> Self {
        let upstream = Config::infer().await.expect("read KUBECONFIG").cluster_url;
        let host = upstream
            .host()
            .expect("the API server URL has a host")
            .to_owned();
        let port = upstream.port_u16().unwrap_or(443);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the relay");
        let address = listener.local_addr().expect("the relay has an address");
        let generation = Arc::new(AtomicUsize::new(0));
        let accepting = Arc::clone(&generation);
        tokio::spawn(async move {
            loop {
                let (client, _) = listener.accept().await.expect("accept a driver connection");
                let upstream = TcpStream::connect((host.as_str(), port))
                    .await
                    .expect("connect the relay to the API server");
                let born = accepting.load(Ordering::SeqCst);
                tokio::spawn(relay(client, upstream, Arc::clone(&accepting), born));
            }
        });

        let mut kubeconfig = Kubeconfig::read().expect("read KUBECONFIG");
        for named in &mut kubeconfig.clusters {
            if let Some(cluster) = named.cluster.as_mut() {
                cluster.server = Some(format!("https://{address}"));
            }
        }
        let directory = tempfile::tempdir().expect("create relay directory");
        let path = directory.path().join("kubeconfig");
        let encoded = serde_json::to_vec(&kubeconfig).expect("encode the relay kubeconfig");
        std::fs::write(&path, encoded).expect("write the relay kubeconfig");
        Self {
            _directory: directory,
            kubeconfig: path,
            generation,
        }
    }

    /// Freezes the connections open now, until the API server answers on each of them. Connections
    /// opened after this call are relayed as usual.
    pub fn freeze_open_connections(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
    }

    /// Returns the kubeconfig that names this relay.
    fn kubeconfig(&self) -> &Path {
        &self.kubeconfig
    }
}

/// Relays one driver connection to the API server, which was opened in freeze generation `born`.
/// The driver's close of its side is not passed upstream: the upstream side stays open, and what
/// it still sends is discarded once the driver has gone. The API server's close of its side closes
/// the driver's side.
///
/// A connection frozen by [`Relay::freeze_open_connections`] withholds the driver's bytes until the
/// API server first answers on it. That answer is the response to the request the driver
/// abandoned, so the driver's later requests on the connection are relayed again.
async fn relay(client: TcpStream, upstream: TcpStream, generation: Arc<AtomicUsize>, born: usize) {
    let (mut client_read, mut client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();
    let thawed = AtomicBool::new(false);
    let frozen = || generation.load(Ordering::SeqCst) != born && !thawed.load(Ordering::SeqCst);
    let to_upstream = async {
        let mut buffer = vec![0; 16 * 1024];
        loop {
            match client_read.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    if !frozen() && upstream_write.write_all(&buffer[..read]).await.is_err() {
                        break;
                    }
                }
            }
        }
    };
    let to_client = async {
        let mut buffer = vec![0; 16 * 1024];
        let mut driver_open = true;
        loop {
            match upstream_read.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    if generation.load(Ordering::SeqCst) != born {
                        thawed.store(true, Ordering::SeqCst);
                    }
                    if driver_open && client_write.write_all(&buffer[..read]).await.is_err() {
                        driver_open = false;
                    }
                }
            }
        }
        let _ = client_write.shutdown().await;
    };
    tokio::join!(to_upstream, to_client);
}

/// Waits until the driver has bound `socket`, and fails if the driver exits first.
async fn wait_for_socket(child: &mut Child, socket: &Path) {
    let deadline = Instant::now() + WAIT_TIMEOUT;
    while !socket.exists() {
        assert!(
            child.try_wait().expect("poll the driver").is_none(),
            "driver exited before binding {}",
            socket.display()
        );
        assert!(
            Instant::now() < deadline,
            "driver did not bind {}",
            socket.display()
        );
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Connects a gRPC channel to the Unix socket at `socket`.
async fn connect(socket: impl AsRef<Path>) -> Channel {
    let socket = socket.as_ref().to_path_buf();
    Endpoint::from_static("http://[::]:50051")
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let socket = socket.clone();
            async move {
                UnixStream::connect(socket)
                    .await
                    .map(hyper_util::rt::TokioIo::new)
            }
        }))
        .await
        .expect("connect to the driver socket")
}

/// Returns a Kubernetes client for the kind cluster that `KUBECONFIG` names.
pub async fn kube_client() -> Client {
    Client::try_default().await.expect("read KUBECONFIG")
}

/// One test's namespace and sandbox identity. [`Case::start`] creates the namespace and
/// [`Case::finish`] deletes it.
pub struct Case {
    /// Namespace the driver creates sandboxes in.
    pub namespace: String,
    /// Sandbox ID, lowercase, that every per-sandbox object is labelled with.
    pub id: String,
    /// Sandbox name, which is also the workload pod and the Lease name.
    pub name: String,
}

impl Case {
    /// Creates a namespace for test `tag` and waits until its `default` `ServiceAccount` exists.
    pub async fn start(client: &Client, tag: &str) -> Self {
        let suffix = unique_suffix();
        let case = Self {
            namespace: format!("odp-e2e-{tag}-{suffix}"),
            id: format!("{tag}-{suffix}"),
            name: format!("{tag}-{suffix}"),
        };
        let namespaces = Api::<Namespace>::all(client.clone());
        namespaces
            .create(
                &PostParams::default(),
                &Namespace {
                    metadata: ObjectMeta {
                        name: Some(case.namespace.clone()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await
            .expect("create the test namespace");
        let accounts = Api::<ServiceAccount>::namespaced(client.clone(), &case.namespace);
        eventually("the default ServiceAccount", || {
            let accounts = accounts.clone();
            async move {
                accounts
                    .get_opt("default")
                    .await
                    .expect("read the default ServiceAccount")
                    .map(|_| ())
            }
        })
        .await;
        case
    }

    /// Returns a second sandbox identity in the namespace of this case, named with `tag`. It
    /// shares the namespace and creates nothing, so the two sandboxes of one driver can be
    /// told apart.
    pub fn sibling(&self, tag: &str) -> Self {
        let suffix = unique_suffix();
        Self {
            namespace: self.namespace.clone(),
            id: format!("{tag}-{suffix}"),
            name: format!("{tag}-{suffix}"),
        }
    }

    /// Deletes the namespace and waits until it is gone.
    pub async fn finish(self, client: &Client) {
        let namespaces = Api::<Namespace>::all(client.clone());
        namespaces
            .delete(&self.namespace, &DeleteParams::default())
            .await
            .expect("delete the test namespace");
        eventually("namespace deletion", || {
            let namespaces = namespaces.clone();
            let namespace = self.namespace.clone();
            async move {
                namespaces
                    .get_opt(&namespace)
                    .await
                    .expect("read the test namespace")
                    .is_none()
                    .then_some(())
            }
        })
        .await;
    }

    /// Returns a sandbox request for this case, naming `template` and carrying `image`.
    pub fn sandbox(&self, template: &str, image: &str) -> DriverSandbox {
        DriverSandbox {
            id: self.id.clone(),
            name: self.name.clone(),
            namespace: self.namespace.clone(),
            spec: Some(DriverSandboxSpec {
                template: Some(DriverSandboxTemplate {
                    image: image.to_owned(),
                    driver_config: Some(Struct {
                        fields: BTreeMap::from([(
                            "template".to_owned(),
                            ProtoValue {
                                kind: Some(Kind::StringValue(template.to_owned())),
                            },
                        )]),
                    }),
                    ..Default::default()
                }),
                launch_authentication: serde_json::to_vec(&launch_authentication(1))
                    .expect("encode the launch authentication"),
                ..Default::default()
            }),
            ..Default::default()
        }
    }
}

/// Returns a short suffix that is unique to this test process and moment.
fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock is after the epoch")
        .subsec_nanos();
    format!("{:x}{nanos:x}", std::process::id())
}

/// Returns the launch authentication the gateway hands a create or a start of `generation`, with
/// distinctive tokens.
pub fn launch_authentication(generation: u64) -> SandboxLaunchAuthentication {
    SandboxLaunchAuthentication {
        supervisor: SupervisorAuthBundle {
            session_id: SandboxSessionId::new(),
            runtime_generation: SandboxGenerationId::from_start_resource_version(generation),
            session_rotation: SessionRotation::new(1).expect("session rotation is nonzero"),
            auth_epoch: CredentialEpoch::new(1).expect("credential epoch is nonzero"),
            gateway_token: SecretJwt::parse(GATEWAY_TOKEN).expect("gateway token is a token"),
            gateway_expires_at: FAR_FUTURE_EXPIRY,
            sandbox_token: SecretJwt::parse(SANDBOX_TOKEN).expect("sandbox token is a token"),
            sandbox_expires_at: FAR_FUTURE_EXPIRY,
            ssh_host_private_key: None,
            ocsf_otlp_headers: None,
        },
        gateway_id: GATEWAY_ID.to_owned(),
        verification_keys: vec![SessionVerificationKey {
            key_id: "e2e-key".to_owned(),
            public_key_pem: VERIFICATION_KEY_PEM.to_vec(),
        }],
    }
}

/// Returns the `PodTemplate` spec that every valid case uses: one sandbox container with a
/// command, an `httpGet` readiness probe, a plain environment value and a `secretKeyRef`.
pub fn valid_template_spec() -> Value {
    json!({
        "containers": [{
            "name": "agent",
            "image": SANDBOX_IMAGE,
            "command": ["/usr/local/bin/agent"],
            "args": ["--serve"],
            "ports": [{"name": "http", "containerPort": 8080}],
            "env": [
                {"name": "PLAIN", "value": PLAIN_ENV_VALUE},
                {"name": "FROM_SECRET", "valueFrom": {
                    "secretKeyRef": {"name": USER_SECRET_NAME, "key": "token"}
                }}
            ],
            "readinessProbe": {"httpGet": {"path": "/healthz", "port": 8080}}
        }]
    })
}

/// Creates the `PodTemplate` `name` in `namespace` from `spec`.
pub async fn create_template(client: &Client, namespace: &str, name: &str, spec: Value) {
    let template: PodTemplate = serde_json::from_value(json!({
        "metadata": {"name": name, "namespace": namespace},
        "template": {"spec": spec}
    }))
    .expect("PodTemplate fixture");
    Api::<PodTemplate>::namespaced(client.clone(), namespace)
        .create(&PostParams::default(), &template)
        .await
        .expect("create the PodTemplate");
}

/// Creates the user Secret that the template's `secretKeyRef` names.
pub async fn create_user_secret(client: &Client, namespace: &str) {
    let secret: Secret = serde_json::from_value(json!({
        "metadata": {"name": USER_SECRET_NAME, "namespace": namespace},
        "stringData": {"token": USER_SECRET_VALUE}
    }))
    .expect("user Secret fixture");
    Api::<Secret>::namespaced(client.clone(), namespace)
        .create(&PostParams::default(), &secret)
        .await
        .expect("create the user Secret");
}

/// Requests a token for the `default` `ServiceAccount` of `namespace`, bound to `pod` and to
/// `audience`.
pub async fn token_bound_to(client: &Client, namespace: &str, pod: &Pod, audience: &str) -> String {
    let request = json!({
        "apiVersion": "authentication.k8s.io/v1",
        "kind": "TokenRequest",
        "spec": {
            "audiences": [audience],
            "expirationSeconds": 600,
            "boundObjectRef": {
                "apiVersion": "v1",
                "kind": "Pod",
                "name": pod.name_any(),
                "uid": pod.uid().expect("pod has a UID"),
            }
        }
    });
    let accounts = Api::<ServiceAccount>::namespaced(client.clone(), namespace);
    let issued: TokenRequest = accounts
        .create_subresource(
            "token",
            "default",
            &PostParams::default(),
            serde_json::to_vec(&request).expect("encode the token request"),
        )
        .await
        .expect("request a service account token");
    issued.status.expect("token request has a status").token
}

/// Returns the object `name` of kind `K` in `namespace`, failing when it is absent.
pub async fn get<K>(client: &Client, namespace: &str, name: &str) -> K
where
    K: Resource<Scope = NamespaceResourceScope> + Clone + DeserializeOwned + Debug,
    K::DynamicType: Default,
{
    Api::<K>::namespaced(client.clone(), namespace)
        .get(name)
        .await
        .expect("read the object")
}

/// Returns the names of the objects of kind `K` in `namespace` that match `selector`.
pub async fn names<K>(client: &Client, namespace: &str, selector: &str) -> Vec<String>
where
    K: Resource<Scope = NamespaceResourceScope> + Clone + DeserializeOwned + Debug,
    K::DynamicType: Default,
{
    Api::<K>::namespaced(client.clone(), namespace)
        .list(&ListParams::default().labels(selector))
        .await
        .expect("list the objects")
        .items
        .into_iter()
        .map(|object| object.name_any())
        .collect()
}

/// Returns the pods of `namespace` that match `selector`, as the typed pod and as the raw JSON
/// that carries the fields the typed pod does not have.
pub async fn pods(client: &Client, namespace: &str, selector: &str) -> Vec<(Pod, Value)> {
    let resource = ApiResource::erase::<Pod>(&());
    Api::<DynamicObject>::namespaced_with(client.clone(), namespace, &resource)
        .list(&ListParams::default().labels(selector))
        .await
        .expect("list the pods")
        .items
        .into_iter()
        .map(|object| {
            let raw = serde_json::to_value(&object).expect("encode the pod");
            let typed = serde_json::from_value(raw.clone()).expect("decode the pod");
            (typed, raw)
        })
        .collect()
}

/// Returns the pod of the sandbox `case` with boundary role `role`, failing unless exactly one
/// exists.
pub async fn only_pod(client: &Client, case: &Case, role: &str) -> (Pod, Value) {
    let selector = format!(
        "{LABEL_BOUNDARY_PAIR}={},{LABEL_BOUNDARY_ROLE}={role}",
        case.id.to_ascii_lowercase()
    );
    let mut found = pods(client, &case.namespace, &selector).await;
    assert_eq!(found.len(), 1, "exactly one {role} pod for {}", case.id);
    found.remove(0)
}

/// Returns the names of the Leases, pods, Services, `NetworkPolicies` and Secrets of `namespace`,
/// leaving out the user Secret.
pub async fn residue(client: &Client, namespace: &str) -> Vec<String> {
    let mut leftovers = Vec::new();
    leftovers.extend(names::<Lease>(client, namespace, "").await);
    leftovers.extend(names::<Pod>(client, namespace, "").await);
    leftovers.extend(names::<Service>(client, namespace, "").await);
    leftovers.extend(
        names::<Secret>(client, namespace, "")
            .await
            .into_iter()
            .filter(|name| name != USER_SECRET_NAME),
    );
    leftovers.extend(names::<NetworkPolicy>(client, namespace, "").await);
    leftovers
}

/// Returns the label selector of the pods of the sandbox `id`.
fn pair_selector(id: &str) -> String {
    format!("{LABEL_BOUNDARY_PAIR}={}", id.to_ascii_lowercase())
}

/// Returns the names of the objects that carry the labels of the sandbox `id` in `namespace`:
/// the Lease, pods, Services and Secrets, and the `EndpointSlices` of its boundary Service.
async fn sandbox_residue(client: &Client, namespace: &str, id: &str) -> Vec<String> {
    let selector = format!("{LABEL_SANDBOX_ID}={id}");
    let boundary = SandboxRuntimeNames::new(id).boundary_service;
    let mut leftovers = Vec::new();
    leftovers.extend(names::<Lease>(client, namespace, &selector).await);
    leftovers.extend(names::<Service>(client, namespace, &selector).await);
    leftovers.extend(names::<Secret>(client, namespace, &selector).await);
    leftovers.extend(
        pods(client, namespace, &pair_selector(id))
            .await
            .into_iter()
            .map(|(pod, _)| pod.name_any()),
    );
    leftovers.extend(
        names::<EndpointSlice>(
            client,
            namespace,
            &format!("kubernetes.io/service-name={boundary}"),
        )
        .await,
    );
    leftovers
}

/// Waits until no object carrying the labels of the sandbox of `case` remains.
pub async fn await_no_sandbox_residue(client: &Client, case: &Case) {
    let client = client.clone();
    let namespace = case.namespace.clone();
    let id = case.id.clone();
    eventually(
        "the objects of the sandbox to be garbage collected",
        move || {
            let client = client.clone();
            let namespace = namespace.clone();
            let id = id.clone();
            async move {
                sandbox_residue(&client, &namespace, &id)
                    .await
                    .is_empty()
                    .then_some(())
            }
        },
    )
    .await;
}

/// Waits until the Lease of `case` exists with both of its pods, and each pod still carries a
/// scheduling gate. The create of `case` has then built everything before its bootstrap Secrets.
pub async fn await_gated_runtime(client: &Client, case: &Case) {
    let client = client.clone();
    let namespace = case.namespace.clone();
    let id = case.id.clone();
    eventually("the Lease and both gated pods", move || {
        let client = client.clone();
        let namespace = namespace.clone();
        let id = id.clone();
        async move {
            let leases =
                names::<Lease>(&client, &namespace, &format!("{LABEL_SANDBOX_ID}={id}")).await;
            let found = pods(&client, &namespace, &pair_selector(&id)).await;
            let all_gated = found.iter().all(|(_, raw)| {
                raw["spec"]["schedulingGates"]
                    .as_array()
                    .is_some_and(|gates| !gates.is_empty())
            });
            (leases.len() == 1 && found.len() == 2 && all_gated).then_some(())
        }
    })
    .await;
}

/// What the API server does with a held create once the hold webhook times out.
#[derive(Clone, Copy)]
pub enum OnTimeout {
    /// Rejects the create, through `failurePolicy: Fail`.
    Reject,
    /// Admits the create, through `failurePolicy: Ignore`.
    Admit,
}

impl OnTimeout {
    /// Returns the `failurePolicy` of the hold webhook that this outcome needs.
    fn failure_policy(self) -> &'static str {
        match self {
            Self::Reject => "Fail",
            Self::Admit => "Ignore",
        }
    }

    /// Returns whether the API server admits a create that the hold times out on.
    fn admits(self) -> bool {
        matches!(self, Self::Admit)
    }
}

/// A webhook that holds every create of the resource `K` in one namespace until its timeout, then
/// applies the [`OnTimeout`] it was installed with.
///
/// The backend is a TLS server that completes the handshake and never answers, behind a Service
/// in a namespace of its own. The API server abandons a webhook whose TLS handshake takes more
/// than 10 seconds, so a backend that only accepted TCP would hold for 10 seconds, not the
/// timeout. The API server waits out the timeout, then rejects or admits the create, unless
/// [`CreateHold::stop`] ends the backend first: the API server then applies the failurePolicy at
/// once. The webhook and the backend namespace are removed by [`CreateHold::remove`].
pub struct CreateHold {
    name: String,
    backend: Case,
}

impl CreateHold {
    /// Starts the backend, installs the webhook for creates of `K` in `namespace`, and returns
    /// once a create of `K` in `namespace` is held by it.
    ///
    /// The backend generates its own certificate for its Service name and prints it to its log,
    /// and the webhook trusts that certificate. The hold has two entries: one holds every create
    /// without [`HOLD_PROBE_LABEL`] for [`HOLD_TIMEOUT`], and one holds only the probe, for
    /// [`PROBE_TIMEOUT`]. Each probe proves the hold: it fails on the probe entry when the hold
    /// rejects, and it is admitted when the hold admits. A create that finishes at once, because
    /// the backend is not yet listening, is retried.
    pub async fn install<K>(client: &Client, namespace: &str, on_timeout: OnTimeout) -> Self
    where
        K: Resource<Scope = NamespaceResourceScope, DynamicType = ()>
            + Clone
            + Debug
            + DeserializeOwned
            + Serialize
            + Send
            + Sync,
    {
        let backend = Case::start(client, "hold").await;
        let backend_namespace = backend.namespace.clone();
        let script = format!(
            "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
             -subj /CN=hold -addext subjectAltName=DNS:hold.{backend_namespace}.svc \
             -keyout /tmp/key.pem -out /tmp/cert.pem && cat /tmp/cert.pem && \
             sleep 86400 | openssl s_server -accept {HOLD_PORT} -cert /tmp/cert.pem \
             -key /tmp/key.pem -quiet"
        );
        let pod: Pod = serde_json::from_value(json!({
            "metadata": {"name": "hold", "namespace": backend_namespace, "labels": {"app": "hold"}},
            "spec": {"containers": [{
                "name": "hold",
                "image": HOLD_IMAGE,
                "command": ["sh", "-c", script]
            }]}
        }))
        .expect("hold backend pod fixture");
        let backend_pods = Api::<Pod>::namespaced(client.clone(), &backend_namespace);
        backend_pods
            .create(&PostParams::default(), &pod)
            .await
            .expect("create the hold backend pod");
        let service: Service = serde_json::from_value(json!({
            "metadata": {"name": "hold", "namespace": backend_namespace},
            "spec": {
                "selector": {"app": "hold"},
                "ports": [{"port": 443, "targetPort": HOLD_PORT, "protocol": "TCP"}]
            }
        }))
        .expect("hold backend Service fixture");
        Api::<Service>::namespaced(client.clone(), &backend_namespace)
            .create(&PostParams::default(), &service)
            .await
            .expect("create the hold backend Service");
        let certificate = eventually("the hold backend's certificate", || {
            let backend_pods = backend_pods.clone();
            async move {
                let logs = backend_pods
                    .logs("hold", &LogParams::default())
                    .await
                    .ok()?;
                let begin = logs.find(PEM_CERTIFICATE_BEGIN)?;
                let end = logs[begin..].find(PEM_CERTIFICATE_END)? + begin;
                Some(logs[begin..end + PEM_CERTIFICATE_END.len()].to_owned())
            }
        })
        .await;

        let group = K::group(&()).into_owned();
        let version = K::version(&()).into_owned();
        let plural = K::plural(&()).into_owned();
        let name = format!("{namespace}-{plural}-hold");
        let webhook_name = format!("hold.{namespace}.odp.invalid");
        let probe_webhook_name = format!("probe.{namespace}.odp.invalid");
        let entry = |webhook: &str, timeout: Duration, object_selector: Value| {
            json!({
                "name": webhook,
                "clientConfig": {
                    "service": {
                        "namespace": backend_namespace,
                        "name": "hold",
                        "port": 443,
                        "path": "/hold"
                    },
                    "caBundle": ByteString(certificate.clone().into_bytes())
                },
                "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": namespace}},
                "objectSelector": object_selector,
                "rules": [{
                    "apiGroups": [group],
                    "apiVersions": [version],
                    "operations": ["CREATE"],
                    "resources": [plural],
                    "scope": "Namespaced"
                }],
                "failurePolicy": on_timeout.failure_policy(),
                "sideEffects": "None",
                "admissionReviewVersions": ["v1"],
                "timeoutSeconds": timeout.as_secs()
            })
        };
        let configuration: ValidatingWebhookConfiguration = serde_json::from_value(json!({
            "metadata": {"name": name},
            "webhooks": [
                entry(
                    &webhook_name,
                    HOLD_TIMEOUT,
                    json!({"matchExpressions": [{
                        "key": HOLD_PROBE_LABEL,
                        "operator": "DoesNotExist"
                    }]})
                ),
                entry(
                    &probe_webhook_name,
                    PROBE_TIMEOUT,
                    json!({"matchLabels": {HOLD_PROBE_LABEL: "true"}})
                )
            ]
        }))
        .expect("hold webhook fixture");
        Api::<ValidatingWebhookConfiguration>::all(client.clone())
            .create(&PostParams::default(), &configuration)
            .await
            .expect("install the hold webhook");

        let creates = Api::<K>::namespaced(client.clone(), namespace);
        let probe: K = serde_json::from_value(json!({
            "metadata": {
                "name": HOLD_PROBE,
                "namespace": namespace,
                "labels": {HOLD_PROBE_LABEL: "true"}
            }
        }))
        .expect("hold probe fixture");
        eventually("the hold webhook to hold a create", || {
            let creates = creates.clone();
            let probe = probe.clone();
            let probe_webhook_name = probe_webhook_name.clone();
            async move {
                let started = Instant::now();
                match creates.create(&PostParams::default(), &probe).await {
                    Ok(_) => {
                        creates
                            .delete(HOLD_PROBE, &DeleteParams::default())
                            .await
                            .expect("delete the hold probe");
                        (on_timeout.admits() && started.elapsed() >= PROBE_TIMEOUT).then_some(())
                    }
                    Err(err) => (started.elapsed() >= PROBE_TIMEOUT
                        && err.to_string().contains(&probe_webhook_name))
                    .then_some(()),
                }
            }
        })
        .await;
        Self { name, backend }
    }

    /// Stops the backend, so that the API server settles every held create by the failurePolicy
    /// at once, rather than when the hold times out.
    ///
    /// The pod is deleted with no grace period, so its connections close at once. A backend left
    /// running would keep a create held until its timeout, and it would hold the namespace for its
    /// termination grace period.
    pub async fn stop(&self, client: &Client) {
        Api::<Pod>::namespaced(client.clone(), &self.backend.namespace)
            .delete(
                "hold",
                &DeleteParams {
                    grace_period_seconds: Some(0),
                    ..DeleteParams::default()
                },
            )
            .await
            .expect("stop the hold backend");
    }

    /// Deletes the webhook, then deletes the backend namespace and waits until it is gone. Call
    /// [`CreateHold::stop`] first, because the namespace waits for a running backend to terminate.
    pub async fn remove(self, client: &Client) {
        Api::<ValidatingWebhookConfiguration>::all(client.clone())
            .delete(&self.name, &DeleteParams::default())
            .await
            .expect("delete the hold webhook");
        self.backend.finish(client).await;
    }
}

/// Polls `attempt` until it returns `Some`, and returns that value. Fails after the wait bound.
pub async fn eventually<T, Fut>(what: &str, mut attempt: impl FnMut() -> Fut) -> T
where
    Fut: Future<Output = Option<T>>,
{
    let deadline = Instant::now() + WAIT_TIMEOUT;
    loop {
        if let Some(value) = attempt().await {
            return value;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Returns the JSON encoding of `object`.
pub fn encode<T: Serialize>(object: &T) -> String {
    serde_json::to_string(object).expect("encode the object")
}

/// Reports whether the JSON encoding of `object` contains `needle`.
pub fn mentions<T: Serialize>(object: &T, needle: &str) -> bool {
    encode(object).contains(needle)
}

/// Reports whether any value of `secret` contains `needle` once its bytes are decoded.
pub fn secret_mentions(secret: &Secret, needle: &str) -> bool {
    secret
        .data
        .iter()
        .flatten()
        .any(|(_, value)| String::from_utf8_lossy(&value.0).contains(needle))
}

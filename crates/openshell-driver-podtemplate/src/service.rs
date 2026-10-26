// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
// SPDX-License-Identifier: Apache-2.0

//! The `ComputeDriver` gRPC service served on a private Unix socket.
//!
//! [`PodTemplateDriver`] answers the twelve RPCs from the driver modules. [`serve`] binds the
//! socket and serves until its shutdown future resolves. The workspace RPCs report
//! `Unimplemented`.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;

use futures::StreamExt;
use futures::stream::BoxStream;
use openshell_core::external_driver_socket::{SameUidUnixIncoming, SocketCleanup, bind_private};
use openshell_core::proto::compute::v1::compute_driver_server::{
    ComputeDriver, ComputeDriverServer,
};
use openshell_core::proto::compute::v1::{
    AuthenticateSandboxRequest, AuthenticateSandboxResponse, CreateSandboxRequest,
    CreateSandboxResponse, DeleteSandboxRequest, DeleteSandboxResponse, DeleteWorkspaceRequest,
    DeleteWorkspaceResponse, EnsureWorkspaceRequest, EnsureWorkspaceResponse,
    GetCapabilitiesRequest, GetCapabilitiesResponse, GetSandboxRequest, GetSandboxResponse,
    ListSandboxesRequest, ListSandboxesResponse, StartSandboxRequest, StartSandboxResponse,
    StopSandboxRequest, StopSandboxResponse, ValidateSandboxCreateRequest,
    ValidateSandboxCreateResponse, WatchSandboxesEvent, WatchSandboxesRequest,
};
use tokio::sync::watch;
use tonic::{Request, Response, Status};

use crate::capabilities::{capabilities, negotiate};
use crate::config::Config;
use crate::error::DriverError;
use crate::registry::Registry;
use crate::{auth, create, delete};

/// The driver's `ComputeDriver` service. The sandbox RPCs read or change the sandboxes of
/// one gateway through the Kubernetes API.
#[derive(Clone)]
pub struct PodTemplateDriver {
    client: kube::Client,
    config: Arc<Config>,
    registry: Registry,
    /// Becomes `true` when serving shuts down, which ends every open `WatchSandboxes` stream.
    shutdown: Arc<watch::Sender<bool>>,
}

impl PodTemplateDriver {
    /// Returns a driver that uses `client` for the Kubernetes API and `config` for its settings.
    pub fn new(client: kube::Client, config: Config) -> Self {
        let config = Arc::new(config);
        let registry = Registry::new(
            client.clone(),
            config.namespace.clone(),
            config.gateway_id.clone(),
        );
        let (shutdown, _) = watch::channel(false);
        Self {
            client,
            config,
            registry,
            shutdown: Arc::new(shutdown),
        }
    }
}

/// Resolves once the driver is shut down. A dropped sender also resolves it.
async fn shutdown_signal(mut shutdown: watch::Receiver<bool>) {
    let _ = shutdown.wait_for(|stopped| *stopped).await;
}

#[tonic::async_trait]
impl ComputeDriver for PodTemplateDriver {
    async fn get_capabilities(
        &self,
        request: Request<GetCapabilitiesRequest>,
    ) -> Result<Response<GetCapabilitiesResponse>, Status> {
        let response = capabilities(&self.config.admission);
        negotiate(&response, request.into_inner().gateway)?;
        Ok(Response::new(response))
    }

    async fn authenticate_sandbox(
        &self,
        request: Request<AuthenticateSandboxRequest>,
    ) -> Result<Response<AuthenticateSandboxResponse>, Status> {
        let credential = request.into_inner().credential;
        let (sandbox_id, runtime_identity) =
            auth::authenticate_sandbox(&self.client, &self.config, &credential).await?;
        Ok(Response::new(AuthenticateSandboxResponse {
            sandbox_id,
            runtime_identity,
        }))
    }

    async fn validate_sandbox_create(
        &self,
        request: Request<ValidateSandboxCreateRequest>,
    ) -> Result<Response<ValidateSandboxCreateResponse>, Status> {
        let sandbox = request
            .into_inner()
            .sandbox
            .ok_or_else(|| Status::invalid_argument("sandbox is required"))?;
        create::validate_sandbox_create(&self.client, &self.config, &sandbox).await?;
        Ok(Response::new(ValidateSandboxCreateResponse {}))
    }

    async fn get_sandbox(
        &self,
        request: Request<GetSandboxRequest>,
    ) -> Result<Response<GetSandboxResponse>, Status> {
        let sandbox_id = request.into_inner().sandbox_id;
        if sandbox_id.is_empty() {
            return Err(Status::invalid_argument("sandbox_id is required"));
        }
        let sandbox = self
            .registry
            .get_sandbox(&sandbox_id)
            .await?
            .ok_or(DriverError::NotFound)?;
        Ok(Response::new(GetSandboxResponse {
            sandbox: Some(sandbox),
        }))
    }

    async fn list_sandboxes(
        &self,
        _request: Request<ListSandboxesRequest>,
    ) -> Result<Response<ListSandboxesResponse>, Status> {
        let sandboxes = self.registry.list_sandboxes().await?;
        Ok(Response::new(ListSandboxesResponse { sandboxes }))
    }

    async fn create_sandbox(
        &self,
        request: Request<CreateSandboxRequest>,
    ) -> Result<Response<CreateSandboxResponse>, Status> {
        let sandbox = request
            .into_inner()
            .sandbox
            .ok_or_else(|| Status::invalid_argument("sandbox is required"))?;
        let runtime_identity = create::create_sandbox(&self.client, &self.config, &sandbox).await?;
        Ok(Response::new(CreateSandboxResponse { runtime_identity }))
    }

    async fn stop_sandbox(
        &self,
        request: Request<StopSandboxRequest>,
    ) -> Result<Response<StopSandboxResponse>, Status> {
        let sandbox_id = request.into_inner().sandbox_id;
        if sandbox_id.is_empty() {
            return Err(Status::invalid_argument("sandbox_id is required"));
        }
        let record = self
            .registry
            .find_record(&sandbox_id)
            .await?
            .ok_or(DriverError::NotFound)?;
        delete::stop_runtime(&self.client, &record).await?;
        Ok(Response::new(StopSandboxResponse {}))
    }

    async fn start_sandbox(
        &self,
        request: Request<StartSandboxRequest>,
    ) -> Result<Response<StartSandboxResponse>, Status> {
        let request = request.into_inner();
        if request.sandbox_id.is_empty() {
            return Err(Status::invalid_argument("sandbox_id is required"));
        }
        let record = self
            .registry
            .find_record(&request.sandbox_id)
            .await?
            .ok_or(DriverError::NotFound)?;
        let runtime_identity = create::start_sandbox(
            &self.client,
            &self.config,
            &record,
            &request.generation_id,
            &request.launch_authentication,
            &request.expected_runtime_identity,
        )
        .await?;
        Ok(Response::new(StartSandboxResponse { runtime_identity }))
    }

    async fn delete_sandbox(
        &self,
        request: Request<DeleteSandboxRequest>,
    ) -> Result<Response<DeleteSandboxResponse>, Status> {
        let sandbox_id = request.into_inner().sandbox_id;
        if sandbox_id.is_empty() {
            return Err(Status::invalid_argument("sandbox_id is required"));
        }
        let deleted = match self.registry.find_record(&sandbox_id).await? {
            Some(record) => delete::delete_record(&self.client, &record).await?,
            None => false,
        };
        Ok(Response::new(DeleteSandboxResponse { deleted }))
    }

    type WatchSandboxesStream = BoxStream<'static, Result<WatchSandboxesEvent, Status>>;

    /// Streams the sandbox events of this gateway. The stream ends when the driver shuts down.
    async fn watch_sandboxes(
        &self,
        _request: Request<WatchSandboxesRequest>,
    ) -> Result<Response<Self::WatchSandboxesStream>, Status> {
        let events = self
            .registry
            .watch_sandboxes()
            .map(|event| event.map_err(Status::from))
            .take_until(shutdown_signal(self.shutdown.subscribe()))
            .boxed();
        Ok(Response::new(events))
    }

    async fn ensure_workspace(
        &self,
        _request: Request<EnsureWorkspaceRequest>,
    ) -> Result<Response<EnsureWorkspaceResponse>, Status> {
        Err(Status::unimplemented(
            "the podtemplate driver does not manage workspaces",
        ))
    }

    async fn delete_workspace(
        &self,
        _request: Request<DeleteWorkspaceRequest>,
    ) -> Result<Response<DeleteWorkspaceResponse>, Status> {
        Err(Status::unimplemented(
            "the podtemplate driver does not manage workspaces",
        ))
    }
}

/// Binds a private Unix socket at `socket_path` and serves `driver` on it until `shutdown`
/// resolves. Only clients with the driver's own effective UID are served. The socket is
/// removed when serving ends.
///
/// Resolving `shutdown` also ends every open `WatchSandboxes` stream, so serving returns
/// without waiting for a client to close its watch.
///
/// Adapted from v0.1.5 `crates/openshell-driver-kubernetes/src/main.rs` (lines 340-352).
///
/// # Errors
///
/// Returns an error when the socket cannot be bound or the server fails.
pub async fn serve(
    driver: PodTemplateDriver,
    socket_path: &Path,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), DriverError> {
    let listener = bind_private(socket_path).map_err(DriverError::Message)?;
    let _cleanup = SocketCleanup::new(socket_path.to_path_buf());
    let watches = driver.shutdown.clone();
    let shutdown = async move {
        shutdown.await;
        watches.send_replace(true);
    };
    tonic::transport::Server::builder()
        .add_service(ComputeDriverServer::new(driver))
        .serve_with_incoming_shutdown(SameUidUnixIncoming::new(listener), shutdown)
        .await
        .map_err(|error| DriverError::Message(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use clap::Parser;
    use openshell_core::extension_protocol::{ExtensionFamily, gateway_metadata};
    use openshell_core::proto::compute::v1::compute_driver_client::ComputeDriverClient;
    use openshell_core::proto::compute::v1::compute_driver_server::ComputeDriver;
    use openshell_core::proto::compute::v1::{
        CreateSandboxRequest, DeleteSandboxRequest, DeleteWorkspaceRequest, EnsureWorkspaceRequest,
        GetCapabilitiesRequest, GetSandboxRequest, StartSandboxRequest, StopSandboxRequest,
        ValidateSandboxCreateRequest, WatchSandboxesRequest,
    };
    use tokio::net::UnixStream;
    use tonic::transport::Channel;
    use tonic::{Code, Request};

    use super::{PodTemplateDriver, serve};
    use crate::capabilities::DRIVER_NAME;
    use crate::config::{Args, Config};
    use crate::error::DriverError;

    fn driver() -> PodTemplateDriver {
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
        let config = Config::try_from(args).expect("config builds");
        let client = kube::Client::try_from(kube::Config::new(
            "http://127.0.0.1:1".parse().expect("loopback uri"),
        ))
        .expect("client");
        PodTemplateDriver::new(client, config)
    }

    #[tokio::test]
    async fn service_get_capabilities_accepts_a_compatible_gateway() {
        let response = driver()
            .get_capabilities(Request::new(GetCapabilitiesRequest {
                gateway: Some(gateway_metadata(ExtensionFamily::Compute)),
            }))
            .await
            .expect("compatible gateway is accepted")
            .into_inner();
        assert_eq!(response.driver_name, DRIVER_NAME);
    }

    #[tokio::test]
    async fn service_get_capabilities_rejects_a_missing_gateway_with_failed_precondition() {
        let status = driver()
            .get_capabilities(Request::new(GetCapabilitiesRequest { gateway: None }))
            .await
            .expect_err("missing gateway is rejected");
        assert_eq!(status.code(), Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn service_validate_sandbox_create_requires_a_sandbox() {
        let status = driver()
            .validate_sandbox_create(Request::new(ValidateSandboxCreateRequest { sandbox: None }))
            .await
            .expect_err("missing sandbox is rejected");
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), "sandbox is required");
    }

    #[tokio::test]
    async fn service_create_sandbox_requires_a_sandbox() {
        let status = driver()
            .create_sandbox(Request::new(CreateSandboxRequest { sandbox: None }))
            .await
            .expect_err("missing sandbox is rejected");
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), "sandbox is required");
    }

    #[tokio::test]
    async fn service_get_sandbox_requires_a_sandbox_id() {
        let status = driver()
            .get_sandbox(Request::new(GetSandboxRequest {
                sandbox_id: String::new(),
                ..Default::default()
            }))
            .await
            .expect_err("empty sandbox ID is rejected");
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), "sandbox_id is required");
    }

    #[tokio::test]
    async fn service_delete_sandbox_requires_a_sandbox_id() {
        let status = driver()
            .delete_sandbox(Request::new(DeleteSandboxRequest {
                sandbox_id: String::new(),
                ..Default::default()
            }))
            .await
            .expect_err("empty sandbox ID is rejected");
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), "sandbox_id is required");
    }

    #[tokio::test]
    async fn service_stop_sandbox_requires_a_sandbox_id() {
        let status = driver()
            .stop_sandbox(Request::new(StopSandboxRequest {
                sandbox_id: String::new(),
                ..Default::default()
            }))
            .await
            .expect_err("empty sandbox ID is rejected");
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), "sandbox_id is required");
    }

    #[tokio::test]
    async fn service_start_sandbox_requires_a_sandbox_id() {
        let status = driver()
            .start_sandbox(Request::new(StartSandboxRequest {
                sandbox_id: String::new(),
                ..Default::default()
            }))
            .await
            .expect_err("empty sandbox ID is rejected");
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(status.message(), "sandbox_id is required");
    }

    #[tokio::test]
    async fn service_ensure_workspace_is_unimplemented() {
        let status = driver()
            .ensure_workspace(Request::new(EnsureWorkspaceRequest::default()))
            .await
            .expect_err("ensure workspace is not implemented");
        assert_eq!(status.code(), Code::Unimplemented);
        assert_eq!(
            status.message(),
            "the podtemplate driver does not manage workspaces"
        );
    }

    #[tokio::test]
    async fn service_delete_workspace_is_unimplemented() {
        let status = driver()
            .delete_workspace(Request::new(DeleteWorkspaceRequest::default()))
            .await
            .expect_err("delete workspace is not implemented");
        assert_eq!(status.code(), Code::Unimplemented);
        assert_eq!(
            status.message(),
            "the podtemplate driver does not manage workspaces"
        );
    }

    /// Serves `driver()` on a socket in a fresh directory. Returns the socket path, the
    /// directory that keeps it alive, the sender that shuts the server down, and the task
    /// that runs `serve`. The socket is bound before this returns.
    async fn serve_driver() -> (
        PathBuf,
        tempfile::TempDir,
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<Result<(), DriverError>>,
    ) {
        let directory = tempfile::tempdir().expect("create temporary directory");
        let socket_path = directory.path().join("driver").join("compute.sock");
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn({
            let socket_path = socket_path.clone();
            async move {
                serve(driver(), &socket_path, async {
                    let _ = stopped.await;
                })
                .await
            }
        });

        tokio::time::timeout(Duration::from_secs(5), async {
            while !socket_path.exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("driver socket is bound");
        (socket_path, directory, stop, server)
    }

    /// Connects a `ComputeDriver` client to the driver socket at `socket_path`.
    async fn connect_driver(socket_path: &Path) -> ComputeDriverClient<Channel> {
        let connector_path = socket_path.to_path_buf();
        let channel = tonic::transport::Endpoint::from_static("http://[::]:50051")
            .connect_with_connector(tower::service_fn(move |_: tonic::transport::Uri| {
                let connector_path = connector_path.clone();
                async move {
                    UnixStream::connect(connector_path)
                        .await
                        .map(hyper_util::rt::TokioIo::new)
                }
            }))
            .await
            .expect("connect to driver socket");
        ComputeDriverClient::new(channel)
    }

    #[tokio::test]
    async fn service_serve_returns_after_shutdown_with_an_open_watch() {
        let (socket_path, _directory, stop, server) = serve_driver().await;
        let mut client = connect_driver(&socket_path).await;
        let mut watch = client
            .watch_sandboxes(WatchSandboxesRequest::default())
            .await
            .expect("watch opened over the socket")
            .into_inner();

        stop.send(()).expect("server is still running");
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("serve returns while a watch is open")
            .expect("server task does not panic")
            .expect("serve returns Ok after shutdown");

        let ended = tokio::time::timeout(Duration::from_secs(5), watch.message())
            .await
            .expect("watch stream ends after shutdown")
            .expect("watch stream ends without an error");
        assert!(ended.is_none(), "watch stream ends with no further event");
    }

    #[tokio::test]
    async fn service_serve_answers_get_capabilities_over_uds_and_returns_after_shutdown() {
        let (socket_path, _directory, stop, server) = serve_driver().await;
        let mut client = connect_driver(&socket_path).await;
        let response = client
            .get_capabilities(GetCapabilitiesRequest {
                gateway: Some(gateway_metadata(ExtensionFamily::Compute)),
            })
            .await
            .expect("capabilities answered over the socket")
            .into_inner();
        assert_eq!(response.driver_name, DRIVER_NAME);
        drop(client);

        stop.send(()).expect("server is still running");
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("serve returns after shutdown")
            .expect("server task does not panic")
            .expect("serve returns Ok after shutdown");
    }
}

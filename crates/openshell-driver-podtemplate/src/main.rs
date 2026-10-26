// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
// SPDX-License-Identifier: Apache-2.0

//! Command-line entry point for the `openshell-driver-podtemplate` binary.
//!
//! Reads the command line into a validated configuration, then serves the `ComputeDriver`
//! gRPC service on the configured Unix socket until SIGINT or SIGTERM.
//!
//! Adapted from v0.1.5 `crates/openshell-driver-kubernetes/src/main.rs` (lines 211-232 for
//! the shutdown signals, 340-352 for the socket serving).

use std::error::Error;
use std::process::ExitCode;

use clap::Parser;
use openshell_driver_podtemplate::banner;
use openshell_driver_podtemplate::config::{Args, Config};
use openshell_driver_podtemplate::service::{PodTemplateDriver, serve};
use tokio::signal::unix::{SignalKind, signal};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("openshell-driver-podtemplate: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Builds the configuration from `args`, then serves the driver until a shutdown signal.
async fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let config = Config::try_from(args)?;
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_new(&config.log_level)?)
        .init();
    info!("{}", banner());

    let client = kube::Client::try_default().await?;
    let socket_path = config.socket_path.clone();
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let shutdown = async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
    };

    info!(socket = %socket_path.display(), "starting podtemplate compute driver");
    serve(
        PodTemplateDriver::new(client, config),
        &socket_path,
        shutdown,
    )
    .await?;
    info!("podtemplate compute driver stopped");
    Ok(())
}

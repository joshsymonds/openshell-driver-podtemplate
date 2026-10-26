// SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
// SPDX-License-Identifier: Apache-2.0

//! Rewrites `httpGet` and `tcpSocket` probes into exec probes that run the
//! `odp-probe` helper from inside the sandbox container.

use k8s_openapi::api::core::v1::{ContainerPort, ExecAction, Probe};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

use super::validate::TemplateError;

/// Name of the volume that carries the `odp-probe` helper into the sandbox container.
pub const PROBE_HELPER_VOLUME_NAME: &str = "odp-probe";

/// Directory in the sandbox container where the `odp-probe` volume is mounted.
pub const PROBE_HELPER_MOUNT_PATH: &str = "/.openshell/probe";

/// Path of the `odp-probe` helper binary inside the sandbox container.
pub const PROBE_HELPER_BINARY: &str = "/.openshell/probe/odp-probe";

/// Name of the init container that installs the `odp-probe` helper.
pub const PROBE_HELPER_CONTAINER_NAME: &str = "odp-probe-install";

/// Rewrites one probe of the sandbox container into an exec probe.
///
/// `ports` are the sandbox container's declared ports, used to resolve named probe ports.
/// `httpGet` and `tcpSocket` probes become exec probes that run the helper; every other
/// probe, including `grpc`, is returned unchanged.
pub fn rewrite(probe: Probe, ports: &[ContainerPort]) -> Result<Probe, TemplateError> {
    let command = if let Some(http) = &probe.http_get {
        let mut command = vec![
            PROBE_HELPER_BINARY.to_owned(),
            "http-get".to_owned(),
            "--port".to_owned(),
            resolve_port(&http.port, ports)?,
        ];
        if let Some(path) = http.path.as_deref().filter(|path| !path.is_empty()) {
            push_flag(&mut command, "--path", path);
        }
        if let Some(scheme) = &http.scheme {
            push_flag(&mut command, "--scheme", scheme);
        }
        if let Some(host) = http.host.as_deref().filter(|host| !host.is_empty()) {
            push_flag(&mut command, "--host", host);
        }
        for header in http.http_headers.iter().flatten() {
            let pair = format!("{}:{}", header.name, header.value);
            push_flag(&mut command, "--header", &pair);
        }
        command
    } else if let Some(tcp) = &probe.tcp_socket {
        vec![
            PROBE_HELPER_BINARY.to_owned(),
            "tcp".to_owned(),
            "--port".to_owned(),
            resolve_port(&tcp.port, ports)?,
        ]
    } else {
        return Ok(probe);
    };

    Ok(Probe {
        exec: Some(ExecAction {
            command: Some(command),
        }),
        http_get: None,
        tcp_socket: None,
        ..probe
    })
}

/// Resolves a probe port to the number the helper dials. A name must be declared by
/// the sandbox container; a number is used as written.
fn resolve_port(port: &IntOrString, ports: &[ContainerPort]) -> Result<String, TemplateError> {
    match port {
        IntOrString::Int(number) => Ok(number.to_string()),
        IntOrString::String(name) => ports
            .iter()
            .find(|declared| declared.name.as_deref() == Some(name.as_str()))
            .map(|declared| declared.container_port.to_string())
            .ok_or_else(|| TemplateError::UnknownProbePort(name.clone())),
    }
}

/// Appends `flag` and its `value` to the helper command line.
fn push_flag(command: &mut Vec<String>, flag: &str, value: &str) {
    command.push(flag.to_owned());
    command.push(value.to_owned());
}

#[cfg(test)]
mod tests {
    use k8s_openapi::api::core::v1::{
        ContainerPort, ExecAction, GRPCAction, HTTPGetAction, HTTPHeader, Probe, TCPSocketAction,
    };
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

    use super::{PROBE_HELPER_BINARY, PROBE_HELPER_MOUNT_PATH, rewrite};
    use crate::template::validate::TemplateError;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    fn port(name: &str, number: i32) -> ContainerPort {
        ContainerPort {
            name: Some(name.to_owned()),
            container_port: number,
            ..ContainerPort::default()
        }
    }

    fn exec(command: Vec<String>) -> ExecAction {
        ExecAction {
            command: Some(command),
        }
    }

    #[test]
    fn probe_binary_is_mount_path_plus_odp_probe() {
        assert_eq!(
            PROBE_HELPER_BINARY,
            format!("{PROBE_HELPER_MOUNT_PATH}/odp-probe")
        );
    }

    #[test]
    fn probe_http_get_becomes_exec_with_every_flag_and_keeps_timing_fields() {
        let probe = Probe {
            http_get: Some(HTTPGetAction {
                path: Some("/healthz".to_owned()),
                port: IntOrString::String("http".to_owned()),
                scheme: Some("HTTP".to_owned()),
                host: Some("localhost".to_owned()),
                http_headers: Some(vec![
                    HTTPHeader {
                        name: "X-A".to_owned(),
                        value: "1".to_owned(),
                    },
                    HTTPHeader {
                        name: "X-B".to_owned(),
                        value: "2".to_owned(),
                    },
                ]),
            }),
            period_seconds: Some(5),
            failure_threshold: Some(3),
            ..Probe::default()
        };

        let rewritten = rewrite(probe, &[port("http", 8080)]);

        assert_eq!(
            rewritten,
            Ok(Probe {
                exec: Some(exec(argv(&[
                    PROBE_HELPER_BINARY,
                    "http-get",
                    "--port",
                    "8080",
                    "--path",
                    "/healthz",
                    "--scheme",
                    "HTTP",
                    "--host",
                    "localhost",
                    "--header",
                    "X-A:1",
                    "--header",
                    "X-B:2",
                ]))),
                period_seconds: Some(5),
                failure_threshold: Some(3),
                ..Probe::default()
            })
        );
    }

    #[test]
    fn probe_http_get_omits_empty_path_and_host_and_takes_numeric_port() {
        let probe = Probe {
            http_get: Some(HTTPGetAction {
                path: Some(String::new()),
                port: IntOrString::Int(9090),
                scheme: None,
                host: Some(String::new()),
                http_headers: None,
            }),
            ..Probe::default()
        };

        let rewritten = rewrite(probe, &[]);

        assert_eq!(
            rewritten,
            Ok(Probe {
                exec: Some(exec(argv(&[
                    PROBE_HELPER_BINARY,
                    "http-get",
                    "--port",
                    "9090",
                ]))),
                ..Probe::default()
            })
        );
    }

    #[test]
    fn probe_tcp_socket_resolves_named_port_and_ignores_host() {
        let probe = Probe {
            tcp_socket: Some(TCPSocketAction {
                host: Some("10.0.0.9".to_owned()),
                port: IntOrString::String("admin".to_owned()),
            }),
            timeout_seconds: Some(2),
            ..Probe::default()
        };

        let rewritten = rewrite(probe, &[port("http", 8080), port("admin", 9000)]);

        assert_eq!(
            rewritten,
            Ok(Probe {
                exec: Some(exec(argv(&[PROBE_HELPER_BINARY, "tcp", "--port", "9000"]))),
                timeout_seconds: Some(2),
                ..Probe::default()
            })
        );
    }

    #[test]
    fn probe_rejects_named_port_the_container_does_not_declare() {
        let probe = Probe {
            http_get: Some(HTTPGetAction {
                path: None,
                port: IntOrString::String("nope".to_owned()),
                scheme: None,
                host: None,
                http_headers: None,
            }),
            ..Probe::default()
        };

        assert_eq!(
            rewrite(probe, &[port("http", 8080)]),
            Err(TemplateError::UnknownProbePort("nope".to_owned()))
        );
    }

    #[test]
    fn probe_leaves_grpc_and_handlerless_probes_unchanged() {
        let grpc = Probe {
            grpc: Some(GRPCAction {
                port: 9000,
                service: None,
            }),
            ..Probe::default()
        };
        let empty = Probe::default();

        assert_eq!(rewrite(grpc.clone(), &[]), Ok(grpc));
        assert_eq!(rewrite(empty.clone(), &[]), Ok(empty));
    }
}

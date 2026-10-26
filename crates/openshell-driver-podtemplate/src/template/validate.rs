// SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
// SPDX-License-Identifier: Apache-2.0

//! Validation of a `PodTemplate` against the rules in `DESIGN.md` section 6.

use std::path::Path;

use k8s_openapi::api::core::v1::{Container, PodSpec, PodTemplateSpec, Probe, Volume};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use openshell_core::driver_mounts::paths_overlap;

use super::probes::{
    PROBE_HELPER_CONTAINER_NAME, PROBE_HELPER_VOLUME_NAME, rewrite as rewrite_probe,
};
use super::upstream::{
    RESERVED_VOLUME_NAMES, SANDBOX_BOOTSTRAP_CONTAINER_NAME, SANDBOX_CONTROL_ROOT,
};

/// Control root under `/run`, protected by rule 8 alongside `/.openshell`.
const RESERVED_RUN_ROOT: &str = "/run/openshell";

/// A reason a template is rejected.
///
/// The `Rule N` labels follow the `DESIGN.md` section 6 rules, and the first failing check is
/// the one reported. Rule 8 also covers reserved container names and unnormalized mount paths,
/// which those rules do not list. `UnknownProbePort` is checked last and is not one of the
/// rules.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum TemplateError {
    /// Rule 1: the template has other than one regular container and no native sidecar.
    /// Carries the count, native sidecars included.
    #[error(
        "rule 1: template has {0} containers including native sidecars; exactly one regular container and no native sidecar is allowed"
    )]
    ContainerCount(usize),
    /// Rule 2: the sandbox container has no command, or an empty program. Carries the container name.
    #[error("rule 2: container `{0}` has no command with a program")]
    MissingCommand(String),
    /// Rule 3: the sandbox container has an exec probe. Carries the probe field name.
    #[error("rule 3: {0} is an exec probe, which runs outside the sandbox boundary")]
    ExecProbe(String),
    /// Rule 4: the pod sets `hostNetwork`, `hostPID`, `hostIPC` or `shareProcessNamespace`.
    /// Carries the field name.
    #[error("rule 4: pod sets {0}")]
    HostNamespace(String),
    /// Rule 5: a container is privileged. Carries the container name.
    #[error("rule 5: container `{0}` is privileged")]
    Privileged(String),
    /// Rule 5: a container adds capabilities. Carries the container name.
    #[error("rule 5: container `{0}` adds capabilities")]
    AddedCapabilities(String),
    /// Rule 5: a container allows privilege escalation. Carries the container name.
    #[error("rule 5: container `{0}` allows privilege escalation")]
    PrivilegeEscalation(String),
    /// Rule 6: a volume is a `hostPath` volume. Carries the volume name.
    #[error("rule 6: volume `{0}` is a hostPath volume")]
    HostPathVolume(String),
    /// Rule 6: a volume projects a service account token. Carries the volume name.
    #[error("rule 6: volume `{0}` projects a service account token")]
    ServiceAccountTokenVolume(String),
    /// Rule 6: the pod sets `automountServiceAccountToken: true`.
    #[error("rule 6: pod sets automountServiceAccountToken: true")]
    AutomountServiceAccountToken,
    /// Rule 7: the pod security context or a container runs as uid or gid 0. Carries
    /// `pod` or the container name.
    #[error("rule 7: `{0}` runs as uid or gid 0")]
    RootIdentity(String),
    /// Rule 8: a volume or volume mount names a reserved volume. Carries the volume name.
    #[error("rule 8: volume name `{0}` is reserved")]
    ReservedVolumeName(String),
    /// Rule 8: a container or init container has a reserved name. Carries the container name.
    #[error("rule 8: container name `{0}` is reserved")]
    ReservedContainerName(String),
    /// Rule 8: a mount path is not absolute and normalized, or overlaps `/.openshell` or
    /// `/run/openshell`. Carries the mount path.
    #[error("rule 8: mount path `{0}` is not normalized or overlaps /.openshell or /run/openshell")]
    ProtectedMountPath(String),
    /// Rule 9: the sandbox container's image differs from the sandbox image. Carries the image.
    #[error("rule 9: image `{0}` differs from the sandbox image")]
    ImageMismatch(String),
    /// A named probe port is not declared by the sandbox container. Carries the port name.
    #[error("probe names undeclared container port `{0}`")]
    UnknownProbePort(String),
}

/// A template that passed every rule, with its `httpGet` and `tcpSocket` probes rewritten
/// to `odp-probe` exec probes.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedTemplate {
    metadata: ObjectMeta,
    spec: PodSpec,
    main_process_command: Vec<String>,
}

impl ValidatedTemplate {
    /// Returns the template metadata, or empty metadata when the template had none.
    pub fn metadata(&self) -> &ObjectMeta {
        &self.metadata
    }

    /// Returns the pod spec, with exactly one container whose probes are rewritten.
    pub fn spec(&self) -> &PodSpec {
        &self.spec
    }

    /// Returns the sandbox container's `command` followed by its `args`.
    pub fn main_process_command(&self) -> &[String] {
        &self.main_process_command
    }
}

/// Checks `template` against the `DESIGN.md` section 6 rules for `sandbox_image`, and against
/// the extra checks listed on `TemplateError`.
///
/// Returns the template with its `httpGet` and `tcpSocket` probes rewritten, or the first
/// failing check.
pub fn validate(
    template: &PodTemplateSpec,
    sandbox_image: &str,
) -> Result<ValidatedTemplate, TemplateError> {
    let metadata = template.metadata.clone().unwrap_or_default();
    let mut spec = template.spec.clone().unwrap_or_default();
    let mut sandbox = take_sandbox_container(&mut spec)?;

    check_command(&sandbox)?;
    check_exec_probes(&sandbox)?;
    check_host_namespaces(&spec)?;
    for container in all_containers(&sandbox, &spec) {
        check_privilege(container)?;
    }
    check_volumes(&spec)?;
    check_identity(&spec, &sandbox)?;
    check_reserved_names_and_mounts(&spec, &sandbox)?;
    if sandbox.image.as_deref() != Some(sandbox_image) {
        return Err(TemplateError::ImageMismatch(
            sandbox.image.clone().unwrap_or_default(),
        ));
    }

    let main_process_command: Vec<String> = sandbox
        .command
        .iter()
        .flatten()
        .chain(sandbox.args.iter().flatten())
        .cloned()
        .collect();
    rewrite_probes(&mut sandbox)?;
    spec.containers = vec![sandbox];

    Ok(ValidatedTemplate {
        metadata,
        spec,
        main_process_command,
    })
}

/// Rule 1: takes the one regular container out of `spec`. A native sidecar, an init
/// container with `restartPolicy: Always`, counts as a container.
fn take_sandbox_container(spec: &mut PodSpec) -> Result<Container, TemplateError> {
    let sidecars = spec
        .init_containers
        .iter()
        .flatten()
        .filter(|init| init.restart_policy.as_deref() == Some("Always"))
        .count();
    let count = spec.containers.len() + sidecars;
    let containers = std::mem::take(&mut spec.containers);
    match <[Container; 1]>::try_from(containers) {
        Ok([sandbox]) if sidecars == 0 => Ok(sandbox),
        _ => Err(TemplateError::ContainerCount(count)),
    }
}

/// Rule 2: the sandbox container needs an explicit command whose program is not empty.
fn check_command(sandbox: &Container) -> Result<(), TemplateError> {
    match sandbox.command.as_ref().and_then(|command| command.first()) {
        Some(program) if !program.is_empty() => Ok(()),
        _ => Err(TemplateError::MissingCommand(sandbox.name.clone())),
    }
}

/// Rule 3: no probe of the sandbox container may be an exec probe.
fn check_exec_probes(sandbox: &Container) -> Result<(), TemplateError> {
    let probes: [(&str, &Option<Probe>); 3] = [
        ("livenessProbe", &sandbox.liveness_probe),
        ("readinessProbe", &sandbox.readiness_probe),
        ("startupProbe", &sandbox.startup_probe),
    ];
    for (field, probe) in probes {
        if probe.as_ref().is_some_and(|probe| probe.exec.is_some()) {
            return Err(TemplateError::ExecProbe(field.to_owned()));
        }
    }
    Ok(())
}

/// Rule 4: the pod must not set `hostNetwork`, `hostPID`, `hostIPC` or `shareProcessNamespace`.
fn check_host_namespaces(spec: &PodSpec) -> Result<(), TemplateError> {
    let flags = [
        ("hostNetwork", spec.host_network),
        ("hostPID", spec.host_pid),
        ("hostIPC", spec.host_ipc),
        ("shareProcessNamespace", spec.share_process_namespace),
    ];
    for (field, set) in flags {
        if set == Some(true) {
            return Err(TemplateError::HostNamespace(field.to_owned()));
        }
    }
    Ok(())
}

/// Rule 5: a container must not be privileged, add capabilities, or allow privilege escalation.
fn check_privilege(container: &Container) -> Result<(), TemplateError> {
    let Some(security) = &container.security_context else {
        return Ok(());
    };
    if security.privileged == Some(true) {
        return Err(TemplateError::Privileged(container.name.clone()));
    }
    if security
        .capabilities
        .as_ref()
        .and_then(|capabilities| capabilities.add.as_ref())
        .is_some_and(|added| !added.is_empty())
    {
        return Err(TemplateError::AddedCapabilities(container.name.clone()));
    }
    if security.allow_privilege_escalation == Some(true) {
        return Err(TemplateError::PrivilegeEscalation(container.name.clone()));
    }
    Ok(())
}

/// Rule 6: no `hostPath` volume, no projected service account token, and no automounted token.
fn check_volumes(spec: &PodSpec) -> Result<(), TemplateError> {
    for volume in spec.volumes.iter().flatten() {
        if volume.host_path.is_some() {
            return Err(TemplateError::HostPathVolume(volume.name.clone()));
        }
        if projects_service_account_token(volume) {
            return Err(TemplateError::ServiceAccountTokenVolume(
                volume.name.clone(),
            ));
        }
    }
    if spec.automount_service_account_token == Some(true) {
        return Err(TemplateError::AutomountServiceAccountToken);
    }
    Ok(())
}

/// Returns whether `volume` is a projected volume with a `serviceAccountToken` source.
fn projects_service_account_token(volume: &Volume) -> bool {
    volume
        .projected
        .as_ref()
        .and_then(|projected| projected.sources.as_ref())
        .is_some_and(|sources| {
            sources
                .iter()
                .any(|source| source.service_account_token.is_some())
        })
}

/// Rule 7: neither the pod nor any container may run as uid or gid 0.
fn check_identity(spec: &PodSpec, sandbox: &Container) -> Result<(), TemplateError> {
    if let Some(security) = &spec.security_context
        && runs_as_root(security.run_as_user, security.run_as_group)
    {
        return Err(TemplateError::RootIdentity("pod".to_owned()));
    }
    for container in all_containers(sandbox, spec) {
        if let Some(security) = &container.security_context
            && runs_as_root(security.run_as_user, security.run_as_group)
        {
            return Err(TemplateError::RootIdentity(container.name.clone()));
        }
    }
    Ok(())
}

/// Returns whether a user or group ID of 0 is set.
fn runs_as_root(user: Option<i64>, group: Option<i64>) -> bool {
    user == Some(0) || group == Some(0)
}

/// Rule 8: no reserved volume or container name, and every mount path is absolute,
/// normalized, and clear of the control trees.
fn check_reserved_names_and_mounts(
    spec: &PodSpec,
    sandbox: &Container,
) -> Result<(), TemplateError> {
    for volume in spec.volumes.iter().flatten() {
        if is_reserved_volume(&volume.name) {
            return Err(TemplateError::ReservedVolumeName(volume.name.clone()));
        }
    }
    for container in all_containers(sandbox, spec) {
        if is_reserved_container(&container.name) {
            return Err(TemplateError::ReservedContainerName(container.name.clone()));
        }
        for mount in container.volume_mounts.iter().flatten() {
            if is_reserved_volume(&mount.name) {
                return Err(TemplateError::ReservedVolumeName(mount.name.clone()));
            }
            if !is_normalized(&mount.mount_path) || overlaps_control_tree(&mount.mount_path) {
                return Err(TemplateError::ProtectedMountPath(mount.mount_path.clone()));
            }
        }
    }
    Ok(())
}

fn is_reserved_volume(name: &str) -> bool {
    RESERVED_VOLUME_NAMES.contains(&name) || name == PROBE_HELPER_VOLUME_NAME
}

fn is_reserved_container(name: &str) -> bool {
    name == SANDBOX_BOOTSTRAP_CONTAINER_NAME || name == PROBE_HELPER_CONTAINER_NAME
}

/// Returns whether `path` is absolute and has no empty, `.` or `..` segment. One
/// trailing `/` is allowed, as upstream's normalization trims it.
fn is_normalized(path: &str) -> bool {
    path.strip_prefix('/').is_some_and(|rest| {
        rest.strip_suffix('/')
            .unwrap_or(rest)
            .split('/')
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
    })
}

/// Returns whether `path` is, lies under, or contains a protected control root.
fn overlaps_control_tree(path: &str) -> bool {
    [SANDBOX_CONTROL_ROOT, RESERVED_RUN_ROOT]
        .iter()
        .any(|root| paths_overlap(Path::new(path), Path::new(root)))
}

/// Yields the sandbox container followed by the init containers.
fn all_containers<'a>(
    sandbox: &'a Container,
    spec: &'a PodSpec,
) -> impl Iterator<Item = &'a Container> {
    std::iter::once(sandbox).chain(spec.init_containers.iter().flatten())
}

/// Rewrites the sandbox container's `httpGet` and `tcpSocket` probes into `odp-probe` exec probes.
fn rewrite_probes(sandbox: &mut Container) -> Result<(), TemplateError> {
    let ports = sandbox.ports.as_deref().unwrap_or(&[]);
    for probe in [
        &mut sandbox.liveness_probe,
        &mut sandbox.readiness_probe,
        &mut sandbox.startup_probe,
    ] {
        if let Some(current) = probe.take() {
            *probe = Some(rewrite_probe(current, ports)?);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use k8s_openapi::api::core::v1::{
        Capabilities, Container, ContainerPort, EmptyDirVolumeSource, EnvVar, EnvVarSource,
        ExecAction, HTTPGetAction, HostPathVolumeSource, PodSecurityContext, PodSpec,
        PodTemplateSpec, Probe, ProjectedVolumeSource, SecretKeySelector, SecurityContext,
        ServiceAccountTokenProjection, TCPSocketAction, Volume, VolumeMount, VolumeProjection,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;

    use super::{TemplateError, validate};
    use crate::template::probes::PROBE_HELPER_BINARY;

    const IMAGE: &str = "sandbox:1";

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    fn container() -> Container {
        Container {
            name: "sandbox".to_owned(),
            image: Some(IMAGE.to_owned()),
            command: Some(vec!["/bin/sh".to_owned()]),
            ..Container::default()
        }
    }

    fn spec_with(sandbox: Container) -> PodSpec {
        PodSpec {
            containers: vec![sandbox],
            ..PodSpec::default()
        }
    }

    fn rejected(spec: PodSpec) -> TemplateError {
        let template = PodTemplateSpec {
            metadata: None,
            spec: Some(spec),
        };
        validate(&template, IMAGE).expect_err("template should be rejected")
    }

    fn accepted_mount(path: &str) -> Result<(), TemplateError> {
        let sandbox = Container {
            volume_mounts: Some(vec![VolumeMount {
                name: "data".to_owned(),
                mount_path: path.to_owned(),
                ..VolumeMount::default()
            }]),
            ..container()
        };
        let template = PodTemplateSpec {
            metadata: None,
            spec: Some(spec_with(sandbox)),
        };
        validate(&template, IMAGE).map(|_| ())
    }

    #[test]
    fn validate_rejects_zero_containers() {
        assert_eq!(
            rejected(PodSpec::default()),
            TemplateError::ContainerCount(0)
        );
    }

    #[test]
    fn validate_rejects_two_containers() {
        let second = Container {
            name: "second".to_owned(),
            ..container()
        };
        let spec = PodSpec {
            containers: vec![container(), second],
            ..PodSpec::default()
        };

        assert_eq!(rejected(spec), TemplateError::ContainerCount(2));
    }

    #[test]
    fn validate_rejects_native_sidecar_as_a_second_container() {
        let sidecar = Container {
            name: "sidecar".to_owned(),
            restart_policy: Some("Always".to_owned()),
            ..Container::default()
        };
        let spec = PodSpec {
            init_containers: Some(vec![sidecar]),
            ..spec_with(container())
        };

        assert_eq!(rejected(spec), TemplateError::ContainerCount(2));
    }

    #[test]
    fn validate_rejects_missing_or_empty_command() {
        for command in [None, Some(Vec::new()), Some(vec![String::new()])] {
            let sandbox = Container {
                command,
                ..container()
            };

            assert_eq!(
                rejected(spec_with(sandbox)),
                TemplateError::MissingCommand("sandbox".to_owned())
            );
        }
    }

    #[test]
    fn validate_rejects_exec_probe_on_each_probe_kind() {
        let exec = Probe {
            exec: Some(ExecAction {
                command: Some(argv(&["true"])),
            }),
            ..Probe::default()
        };
        let cases = [
            (
                Container {
                    liveness_probe: Some(exec.clone()),
                    ..container()
                },
                "livenessProbe",
            ),
            (
                Container {
                    readiness_probe: Some(exec.clone()),
                    ..container()
                },
                "readinessProbe",
            ),
            (
                Container {
                    startup_probe: Some(exec),
                    ..container()
                },
                "startupProbe",
            ),
        ];

        for (sandbox, field) in cases {
            assert_eq!(
                rejected(spec_with(sandbox)),
                TemplateError::ExecProbe(field.to_owned())
            );
        }
    }

    #[test]
    fn validate_rejects_each_host_namespace_flag() {
        let cases = [
            (
                PodSpec {
                    host_network: Some(true),
                    ..spec_with(container())
                },
                "hostNetwork",
            ),
            (
                PodSpec {
                    host_pid: Some(true),
                    ..spec_with(container())
                },
                "hostPID",
            ),
            (
                PodSpec {
                    host_ipc: Some(true),
                    ..spec_with(container())
                },
                "hostIPC",
            ),
            (
                PodSpec {
                    share_process_namespace: Some(true),
                    ..spec_with(container())
                },
                "shareProcessNamespace",
            ),
        ];

        for (spec, field) in cases {
            assert_eq!(
                rejected(spec),
                TemplateError::HostNamespace(field.to_owned())
            );
        }
    }

    #[test]
    fn validate_rejects_privileged_sandbox_container() {
        let sandbox = Container {
            security_context: Some(SecurityContext {
                privileged: Some(true),
                ..SecurityContext::default()
            }),
            ..container()
        };

        assert_eq!(
            rejected(spec_with(sandbox)),
            TemplateError::Privileged("sandbox".to_owned())
        );
    }

    #[test]
    fn validate_rejects_privileged_init_container() {
        let init = Container {
            name: "init".to_owned(),
            security_context: Some(SecurityContext {
                privileged: Some(true),
                ..SecurityContext::default()
            }),
            ..Container::default()
        };
        let spec = PodSpec {
            init_containers: Some(vec![init]),
            ..spec_with(container())
        };

        assert_eq!(rejected(spec), TemplateError::Privileged("init".to_owned()));
    }

    #[test]
    fn validate_rejects_added_capabilities() {
        let sandbox = Container {
            security_context: Some(SecurityContext {
                capabilities: Some(Capabilities {
                    add: Some(vec!["SYS_ADMIN".to_owned()]),
                    drop: None,
                }),
                ..SecurityContext::default()
            }),
            ..container()
        };

        assert_eq!(
            rejected(spec_with(sandbox)),
            TemplateError::AddedCapabilities("sandbox".to_owned())
        );
    }

    #[test]
    fn validate_rejects_allowed_privilege_escalation() {
        let sandbox = Container {
            security_context: Some(SecurityContext {
                allow_privilege_escalation: Some(true),
                ..SecurityContext::default()
            }),
            ..container()
        };

        assert_eq!(
            rejected(spec_with(sandbox)),
            TemplateError::PrivilegeEscalation("sandbox".to_owned())
        );
    }

    #[test]
    fn validate_rejects_host_path_volume() {
        let spec = PodSpec {
            volumes: Some(vec![Volume {
                name: "host".to_owned(),
                host_path: Some(HostPathVolumeSource {
                    path: "/".to_owned(),
                    type_: None,
                }),
                ..Volume::default()
            }]),
            ..spec_with(container())
        };

        assert_eq!(
            rejected(spec),
            TemplateError::HostPathVolume("host".to_owned())
        );
    }

    #[test]
    fn validate_rejects_projected_service_account_token_volume() {
        let spec = PodSpec {
            volumes: Some(vec![Volume {
                name: "token".to_owned(),
                projected: Some(ProjectedVolumeSource {
                    sources: Some(vec![VolumeProjection {
                        service_account_token: Some(ServiceAccountTokenProjection {
                            path: "token".to_owned(),
                            ..ServiceAccountTokenProjection::default()
                        }),
                        ..VolumeProjection::default()
                    }]),
                    ..ProjectedVolumeSource::default()
                }),
                ..Volume::default()
            }]),
            ..spec_with(container())
        };

        assert_eq!(
            rejected(spec),
            TemplateError::ServiceAccountTokenVolume("token".to_owned())
        );
    }

    #[test]
    fn validate_rejects_automounted_service_account_token() {
        let spec = PodSpec {
            automount_service_account_token: Some(true),
            ..spec_with(container())
        };

        assert_eq!(rejected(spec), TemplateError::AutomountServiceAccountToken);
    }

    #[test]
    fn validate_rejects_root_pod_security_context() {
        let spec = PodSpec {
            security_context: Some(PodSecurityContext {
                run_as_user: Some(0),
                ..PodSecurityContext::default()
            }),
            ..spec_with(container())
        };

        assert_eq!(
            rejected(spec),
            TemplateError::RootIdentity("pod".to_owned())
        );
    }

    #[test]
    fn validate_rejects_root_container_group() {
        let sandbox = Container {
            security_context: Some(SecurityContext {
                run_as_group: Some(0),
                ..SecurityContext::default()
            }),
            ..container()
        };

        assert_eq!(
            rejected(spec_with(sandbox)),
            TemplateError::RootIdentity("sandbox".to_owned())
        );
    }

    #[test]
    fn validate_rejects_reserved_pod_volume_name() {
        for name in ["openshell-runtime", "workspace", "odp-probe"] {
            let spec = PodSpec {
                volumes: Some(vec![Volume {
                    name: name.to_owned(),
                    ..Volume::default()
                }]),
                ..spec_with(container())
            };

            assert_eq!(
                rejected(spec),
                TemplateError::ReservedVolumeName(name.to_owned())
            );
        }
    }

    #[test]
    fn validate_rejects_reserved_volume_mount_name() {
        let sandbox = Container {
            volume_mounts: Some(vec![VolumeMount {
                name: "workspace".to_owned(),
                mount_path: "/data".to_owned(),
                ..VolumeMount::default()
            }]),
            ..container()
        };

        assert_eq!(
            rejected(spec_with(sandbox)),
            TemplateError::ReservedVolumeName("workspace".to_owned())
        );
    }

    #[test]
    fn validate_rejects_reserved_container_name() {
        for name in ["openshell-sandbox-bootstrap", "odp-probe-install"] {
            let init = Container {
                name: name.to_owned(),
                ..Container::default()
            };
            let spec = PodSpec {
                init_containers: Some(vec![init]),
                ..spec_with(container())
            };

            assert_eq!(
                rejected(spec),
                TemplateError::ReservedContainerName(name.to_owned())
            );
        }
    }

    #[test]
    fn validate_rejects_protected_mount_paths() {
        for path in [
            "/",
            "/run",
            "/run/openshell",
            "/run/openshell/x",
            "/.openshell",
            "/.openshell/y",
            "/.openshell/",
            "/a/../.openshell",
            "/data//x",
        ] {
            let sandbox = Container {
                volume_mounts: Some(vec![VolumeMount {
                    name: "data".to_owned(),
                    mount_path: path.to_owned(),
                    ..VolumeMount::default()
                }]),
                ..container()
            };

            assert_eq!(
                rejected(spec_with(sandbox)),
                TemplateError::ProtectedMountPath(path.to_owned())
            );
        }
    }

    #[test]
    fn validate_accepts_mount_beside_protected_roots() {
        assert_eq!(accepted_mount("/run/x"), Ok(()));
        assert_eq!(accepted_mount("/data/"), Ok(()));
    }

    #[test]
    fn validate_rejects_sandbox_image_mismatch() {
        let sandbox = Container {
            image: Some("other:1".to_owned()),
            ..container()
        };

        assert_eq!(
            rejected(spec_with(sandbox)),
            TemplateError::ImageMismatch("other:1".to_owned())
        );
    }

    #[test]
    fn validate_rejects_probe_port_name_the_container_does_not_declare() {
        let sandbox = Container {
            readiness_probe: Some(Probe {
                http_get: Some(HTTPGetAction {
                    path: None,
                    port: IntOrString::String("missing".to_owned()),
                    scheme: None,
                    host: None,
                    http_headers: None,
                }),
                ..Probe::default()
            }),
            ..container()
        };

        assert_eq!(
            rejected(spec_with(sandbox)),
            TemplateError::UnknownProbePort("missing".to_owned())
        );
    }

    #[test]
    fn validate_accepts_template_and_rewrites_probes() {
        let sandbox = Container {
            args: Some(argv(&["-c", "serve"])),
            env: Some(vec![EnvVar {
                name: "TOKEN".to_owned(),
                value: None,
                value_from: Some(EnvVarSource {
                    secret_key_ref: Some(SecretKeySelector {
                        key: "token".to_owned(),
                        name: "creds".to_owned(),
                        optional: None,
                    }),
                    ..EnvVarSource::default()
                }),
            }]),
            ports: Some(vec![ContainerPort {
                name: Some("http".to_owned()),
                container_port: 8080,
                ..ContainerPort::default()
            }]),
            liveness_probe: Some(Probe {
                http_get: Some(HTTPGetAction {
                    path: Some("/healthz".to_owned()),
                    port: IntOrString::String("http".to_owned()),
                    scheme: None,
                    host: None,
                    http_headers: None,
                }),
                period_seconds: Some(5),
                ..Probe::default()
            }),
            readiness_probe: Some(Probe {
                tcp_socket: Some(TCPSocketAction {
                    host: Some("10.0.0.1".to_owned()),
                    port: IntOrString::Int(8080),
                }),
                ..Probe::default()
            }),
            ..container()
        };
        let init = Container {
            name: "init".to_owned(),
            image: Some(IMAGE.to_owned()),
            ..Container::default()
        };
        let scratch = Volume {
            name: "scratch".to_owned(),
            empty_dir: Some(EmptyDirVolumeSource::default()),
            ..Volume::default()
        };
        let spec = PodSpec {
            init_containers: Some(vec![init.clone()]),
            volumes: Some(vec![scratch.clone()]),
            ..spec_with(sandbox.clone())
        };
        let template = PodTemplateSpec {
            metadata: Some(ObjectMeta {
                name: Some("sandbox-pod".to_owned()),
                ..ObjectMeta::default()
            }),
            spec: Some(spec),
        };

        let validated = validate(&template, IMAGE).expect("valid template");

        assert_eq!(validated.metadata().name.as_deref(), Some("sandbox-pod"));
        assert_eq!(validated.spec().containers.len(), 1);
        assert_eq!(
            validated.main_process_command(),
            argv(&["/bin/sh", "-c", "serve"])
        );
        let rewritten = &validated.spec().containers[0];
        assert_eq!(
            rewritten.liveness_probe,
            Some(Probe {
                exec: Some(ExecAction {
                    command: Some(argv(&[
                        PROBE_HELPER_BINARY,
                        "http-get",
                        "--port",
                        "8080",
                        "--path",
                        "/healthz",
                    ])),
                }),
                period_seconds: Some(5),
                ..Probe::default()
            })
        );
        assert_eq!(
            rewritten.readiness_probe,
            Some(Probe {
                exec: Some(ExecAction {
                    command: Some(argv(&[PROBE_HELPER_BINARY, "tcp", "--port", "8080"])),
                }),
                ..Probe::default()
            })
        );
        assert_eq!(rewritten.env, sandbox.env);
        assert_eq!(validated.spec().init_containers, Some(vec![init]));
        assert_eq!(validated.spec().volumes, Some(vec![scratch]));
    }
}

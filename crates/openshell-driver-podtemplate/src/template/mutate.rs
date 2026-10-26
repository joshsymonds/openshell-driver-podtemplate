// SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
// SPDX-License-Identifier: Apache-2.0

//! Builds the workload pod from a validated template, per `DESIGN.md` section 6.

use k8s_openapi::api::core::v1::{
    Container, EmptyDirVolumeSource, Pod, PodSchedulingGate, PodSpec, SecurityContext, Volume,
    VolumeMount,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

use super::probes::{
    PROBE_HELPER_CONTAINER_NAME, PROBE_HELPER_MOUNT_PATH, PROBE_HELPER_VOLUME_NAME,
};
use super::upstream::{
    BOUNDARY_PAIR_LABEL, BOUNDARY_ROLE_LABEL, SANDBOX_BOOTSTRAP_SCHEDULING_GATE, WORKLOAD_ROLE,
    apply_workload_env, sandbox_bootstrap_init_container, sandbox_control_port,
    sandbox_runtime_command, sandbox_runtime_volume_mounts, sandbox_runtime_volumes,
    workload_container_security_context, workload_dns_config, workload_pod_security_context,
};
use super::validate::ValidatedTemplate;

/// Per-sandbox values the workload pod is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationParams {
    /// Pod name, which is the sandbox name.
    pub name: String,
    /// Namespace the pod is created in.
    pub namespace: String,
    /// Value of the boundary pair label that binds this pod to its supervisor pod.
    pub pair_label: String,
    /// Name of the Secret that carries the bootstrap material, mounted into the bootstrap container.
    pub bootstrap_secret_name: String,
    /// Image of the runtime bootstrap container that stages the sandbox runtime binary.
    pub runtime_image: String,
    /// Image pull policy of the runtime bootstrap container, such as `Always`.
    pub runtime_image_pull_policy: Option<String>,
    /// Image of the `odp-probe` installer init container. Used only when a probe is rewritten.
    pub probe_helper_image: String,
    /// Image pull policy of the `odp-probe` installer init container.
    pub probe_helper_image_pull_policy: Option<String>,
    /// Port of the sandbox control channel.
    pub boundary_port: u16,
    /// User ID the sandbox runs as.
    pub uid: u32,
    /// Group ID the sandbox runs as.
    pub gid: u32,
}

/// Builds the fenced workload pod for `template`.
///
/// The pod carries the boundary role and pair labels and the bootstrap scheduling gate.
/// The fence overwrites the host namespace flags, DNS, scheduling gates, security context,
/// service account token automount and restart policy. Other pod fields, such as
/// `nodeSelector`, are kept as they are, and volumes and init containers are appended to the
/// template's own. Its `valueFrom` env entries are matched by name only, so their values are
/// never read.
#[must_use]
pub fn mutate(template: &ValidatedTemplate, params: &MutationParams) -> Pod {
    let helper = template.spec().containers.iter().any(has_exec_probe);
    let bootstrap = sandbox_bootstrap_init_container(
        &params.runtime_image,
        params.runtime_image_pull_policy.as_deref(),
        params.uid,
        params.gid,
    );

    let mut spec = template.spec().clone();
    let containers = std::mem::take(&mut spec.containers);
    spec.containers = containers
        .into_iter()
        .map(|sandbox| workload_container(sandbox, params, helper))
        .collect();
    set_pod_fence(&mut spec, params);

    let mut volumes = spec.volumes.take().unwrap_or_default();
    volumes.extend(sandbox_runtime_volumes(&params.bootstrap_secret_name));
    let mut init_containers = spec.init_containers.take().unwrap_or_default();
    if helper {
        volumes.push(probe_helper_volume());
        init_containers.push(probe_helper_installer(
            params,
            bootstrap.security_context.clone(),
        ));
    }
    init_containers.push(bootstrap);
    spec.volumes = Some(volumes);
    spec.init_containers = Some(init_containers);

    let metadata = template.metadata();
    let mut labels = metadata.labels.clone().unwrap_or_default();
    labels.insert(BOUNDARY_ROLE_LABEL.to_owned(), WORKLOAD_ROLE.to_owned());
    labels.insert(BOUNDARY_PAIR_LABEL.to_owned(), params.pair_label.clone());

    Pod {
        metadata: ObjectMeta {
            name: Some(params.name.clone()),
            namespace: Some(params.namespace.clone()),
            labels: Some(labels),
            annotations: metadata.annotations.clone(),
            ..ObjectMeta::default()
        },
        spec: Some(spec),
        ..Pod::default()
    }
}

/// Returns whether any probe of `container` is an exec probe, which is how a rewritten
/// probe shows that the `odp-probe` helper is needed.
fn has_exec_probe(container: &Container) -> bool {
    [
        &container.liveness_probe,
        &container.readiness_probe,
        &container.startup_probe,
    ]
    .into_iter()
    .flatten()
    .any(|probe| probe.exec.is_some())
}

/// Sets the pod-level fence and the runtime's pod settings.
fn set_pod_fence(spec: &mut PodSpec, params: &MutationParams) {
    spec.host_network = Some(false);
    spec.host_pid = Some(false);
    spec.host_ipc = Some(false);
    spec.share_process_namespace = Some(false);
    spec.dns_policy = Some("None".to_owned());
    spec.dns_config = Some(workload_dns_config());
    spec.scheduling_gates = Some(vec![PodSchedulingGate {
        name: SANDBOX_BOOTSTRAP_SCHEDULING_GATE.to_owned(),
    }]);
    spec.security_context = Some(workload_pod_security_context(params.uid, params.gid));
    spec.automount_service_account_token = Some(false);
    spec.restart_policy = Some("Never".to_owned());
}

/// Rewrites the sandbox container into the runtime's main container: the runtime command
/// with `args` cleared, the control port only, the workload security context, the runtime
/// mounts and the `OpenShell` env.
fn workload_container(mut sandbox: Container, params: &MutationParams, helper: bool) -> Container {
    let mut env = sandbox.env.take().unwrap_or_default();
    apply_workload_env(&mut env, params.uid, params.gid);
    sandbox.env = Some(env);

    sandbox.command = Some(sandbox_runtime_command());
    sandbox.args = None;
    sandbox.security_context = Some(workload_container_security_context(params.uid, params.gid));
    sandbox.ports = Some(vec![sandbox_control_port(params.boundary_port)]);

    let mut mounts = sandbox.volume_mounts.take().unwrap_or_default();
    mounts.extend(sandbox_runtime_volume_mounts());
    if helper {
        mounts.push(probe_helper_mount());
    }
    sandbox.volume_mounts = Some(mounts);
    sandbox
}

/// The memory-backed volume that carries the `odp-probe` helper from the installer into
/// the sandbox container.
fn probe_helper_volume() -> Volume {
    Volume {
        name: PROBE_HELPER_VOLUME_NAME.to_owned(),
        empty_dir: Some(EmptyDirVolumeSource {
            medium: Some("Memory".to_owned()),
            size_limit: None,
        }),
        ..Volume::default()
    }
}

/// Mounts the `odp-probe` volume read-only in the sandbox container.
fn probe_helper_mount() -> VolumeMount {
    VolumeMount {
        name: PROBE_HELPER_VOLUME_NAME.to_owned(),
        mount_path: PROBE_HELPER_MOUNT_PATH.to_owned(),
        read_only: Some(true),
        ..VolumeMount::default()
    }
}

/// Init container that copies the `odp-probe` helper into the shared volume. It runs with
/// the runtime bootstrap container's security context.
fn probe_helper_installer(
    params: &MutationParams,
    security_context: Option<SecurityContext>,
) -> Container {
    Container {
        name: PROBE_HELPER_CONTAINER_NAME.to_owned(),
        image: Some(params.probe_helper_image.clone()),
        image_pull_policy: params.probe_helper_image_pull_policy.clone(),
        command: Some(vec![
            "/odp-probe".to_owned(),
            "install".to_owned(),
            PROBE_HELPER_MOUNT_PATH.to_owned(),
        ]),
        security_context,
        volume_mounts: Some(vec![VolumeMount {
            name: PROBE_HELPER_VOLUME_NAME.to_owned(),
            mount_path: PROBE_HELPER_MOUNT_PATH.to_owned(),
            ..VolumeMount::default()
        }]),
        ..Container::default()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use k8s_openapi::api::core::v1::{
        Container, ContainerPort, EmptyDirVolumeSource, EnvVar, EnvVarSource, ExecAction,
        HTTPGetAction, Pod, PodSpec, PodTemplateSpec, Probe, SecretKeySelector, TCPSocketAction,
        Volume, VolumeMount,
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
    use openshell_core::{sandbox_env, telemetry};

    use super::{MutationParams, mutate};
    use crate::template::probes::{
        PROBE_HELPER_BINARY, PROBE_HELPER_CONTAINER_NAME, PROBE_HELPER_MOUNT_PATH,
        PROBE_HELPER_VOLUME_NAME,
    };
    use crate::template::upstream::{
        BOUNDARY_PAIR_LABEL, BOUNDARY_ROLE_LABEL, SANDBOX_BOOTSTRAP_CONTAINER_NAME,
        SANDBOX_BOOTSTRAP_SCHEDULING_GATE, SANDBOX_CONTROL_PORT_NAME, WORKLOAD_ROLE,
        sandbox_bootstrap_init_container, sandbox_control_port, sandbox_runtime_command,
        sandbox_runtime_volume_mounts, sandbox_runtime_volumes,
        workload_container_security_context, workload_dns_config, workload_pod_security_context,
    };
    use crate::template::{ValidatedTemplate, validate};

    const IMAGE: &str = "sandbox:1";
    const PROBE_IMAGE: &str = "probe-helper:1";
    const RUNTIME_IMAGE: &str = "runtime:1";
    const PAIR: &str = "pair-1";

    fn params() -> MutationParams {
        MutationParams {
            name: "sandbox-1".to_owned(),
            namespace: "agents".to_owned(),
            pair_label: PAIR.to_owned(),
            bootstrap_secret_name: "bootstrap-secret".to_owned(),
            runtime_image: RUNTIME_IMAGE.to_owned(),
            runtime_image_pull_policy: Some("Always".to_owned()),
            probe_helper_image: PROBE_IMAGE.to_owned(),
            probe_helper_image_pull_policy: Some("IfNotPresent".to_owned()),
            boundary_port: 2222,
            uid: 1000,
            gid: 1001,
        }
    }

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|part| (*part).to_owned()).collect()
    }

    fn sandbox_container() -> Container {
        Container {
            name: "sandbox".to_owned(),
            image: Some(IMAGE.to_owned()),
            command: Some(argv(&["/bin/sh"])),
            args: Some(argv(&["-c", "serve"])),
            ..Container::default()
        }
    }

    /// Validates a template with one sandbox container built from `sandbox`, plus the
    /// given pod-level parts.
    fn template_with(
        sandbox: Container,
        spec: PodSpec,
        labels: Option<BTreeMap<String, String>>,
    ) -> ValidatedTemplate {
        let template = PodTemplateSpec {
            metadata: Some(ObjectMeta {
                name: Some("ignored-template-name".to_owned()),
                labels,
                annotations: Some(BTreeMap::from([(
                    "example.com/owner".to_owned(),
                    "team-a".to_owned(),
                )])),
                ..ObjectMeta::default()
            }),
            spec: Some(PodSpec {
                containers: vec![sandbox],
                ..spec
            }),
        };
        validate(&template, IMAGE).expect("template is valid")
    }

    fn plain_template() -> ValidatedTemplate {
        template_with(sandbox_container(), PodSpec::default(), None)
    }

    fn metadata_free_template() -> ValidatedTemplate {
        let template = PodTemplateSpec {
            metadata: None,
            spec: Some(PodSpec {
                containers: vec![sandbox_container()],
                ..PodSpec::default()
            }),
        };
        validate(&template, IMAGE).expect("template is valid")
    }

    fn exec_probe(command: Vec<String>) -> Probe {
        Probe {
            exec: Some(ExecAction {
                command: Some(command),
            }),
            ..Probe::default()
        }
    }

    fn probed_template() -> ValidatedTemplate {
        let sandbox = Container {
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
                ..Probe::default()
            }),
            ..sandbox_container()
        };
        template_with(sandbox, PodSpec::default(), None)
    }

    fn pod_spec(pod: &Pod) -> &PodSpec {
        pod.spec.as_ref().expect("pod has a spec")
    }

    fn sandbox_of(pod: &Pod) -> &Container {
        &pod_spec(pod).containers[0]
    }

    fn helper_volume() -> Volume {
        Volume {
            name: PROBE_HELPER_VOLUME_NAME.to_owned(),
            empty_dir: Some(EmptyDirVolumeSource {
                medium: Some("Memory".to_owned()),
                size_limit: None,
            }),
            ..Volume::default()
        }
    }

    fn helper_mount() -> VolumeMount {
        VolumeMount {
            name: PROBE_HELPER_VOLUME_NAME.to_owned(),
            mount_path: PROBE_HELPER_MOUNT_PATH.to_owned(),
            read_only: Some(true),
            ..VolumeMount::default()
        }
    }

    #[test]
    fn mutate_sets_pod_identity_and_keeps_only_name_namespace_labels_and_annotations() {
        let template = template_with(
            sandbox_container(),
            PodSpec::default(),
            Some(BTreeMap::from([("app".to_owned(), "agent".to_owned())])),
        );

        let pod = mutate(&template, &params());

        assert_eq!(pod.metadata.name.as_deref(), Some("sandbox-1"));
        assert_eq!(pod.metadata.namespace.as_deref(), Some("agents"));
        assert_eq!(
            pod.metadata.labels,
            Some(BTreeMap::from([
                ("app".to_owned(), "agent".to_owned()),
                (BOUNDARY_ROLE_LABEL.to_owned(), WORKLOAD_ROLE.to_owned()),
                (BOUNDARY_PAIR_LABEL.to_owned(), PAIR.to_owned()),
            ]))
        );
        assert_eq!(
            pod.metadata.annotations,
            Some(BTreeMap::from([(
                "example.com/owner".to_owned(),
                "team-a".to_owned()
            )]))
        );
        assert_eq!(pod.metadata.generate_name, None);
    }

    #[test]
    fn mutate_fence_labels_override_template_labels_of_the_same_key() {
        let template = template_with(
            sandbox_container(),
            PodSpec::default(),
            Some(BTreeMap::from([
                (BOUNDARY_ROLE_LABEL.to_owned(), "supervisor".to_owned()),
                (BOUNDARY_PAIR_LABEL.to_owned(), "forged".to_owned()),
            ])),
        );

        let labels = mutate(&template, &params()).metadata.labels;

        assert_eq!(
            labels,
            Some(BTreeMap::from([
                (BOUNDARY_ROLE_LABEL.to_owned(), WORKLOAD_ROLE.to_owned()),
                (BOUNDARY_PAIR_LABEL.to_owned(), PAIR.to_owned()),
            ]))
        );
    }

    #[test]
    fn mutate_pod_metadata_without_template_labels_or_annotations_still_carries_the_fence() {
        let pod = mutate(&metadata_free_template(), &params());

        assert_eq!(
            pod.metadata.labels,
            Some(BTreeMap::from([
                (BOUNDARY_ROLE_LABEL.to_owned(), WORKLOAD_ROLE.to_owned()),
                (BOUNDARY_PAIR_LABEL.to_owned(), PAIR.to_owned()),
            ]))
        );
        assert_eq!(pod.metadata.annotations, None);
    }

    #[test]
    fn mutate_forces_host_namespace_flags_false() {
        let spec = pod_spec(&mutate(&plain_template(), &params())).clone();

        assert_eq!(spec.host_network, Some(false));
        assert_eq!(spec.host_pid, Some(false));
        assert_eq!(spec.host_ipc, Some(false));
        assert_eq!(spec.share_process_namespace, Some(false));
    }

    #[test]
    fn mutate_sets_vendored_dns_and_gates_on_the_bootstrap_scheduling_gate() {
        let spec = pod_spec(&mutate(&plain_template(), &params())).clone();

        assert_eq!(spec.dns_policy.as_deref(), Some("None"));
        assert_eq!(spec.dns_config, Some(workload_dns_config()));
        assert_eq!(
            spec.scheduling_gates,
            Some(vec![k8s_openapi::api::core::v1::PodSchedulingGate {
                name: SANDBOX_BOOTSTRAP_SCHEDULING_GATE.to_owned(),
            }])
        );
    }

    #[test]
    fn mutate_sets_vendored_pod_security_context_and_disables_service_account_token() {
        let spec = pod_spec(&mutate(&plain_template(), &params())).clone();

        assert_eq!(
            spec.security_context,
            Some(workload_pod_security_context(1000, 1001))
        );
        assert_eq!(spec.automount_service_account_token, Some(false));
        assert_eq!(spec.restart_policy.as_deref(), Some("Never"));
    }

    #[test]
    fn mutate_rewrites_sandbox_container_command_security_context_and_ports() {
        let container = sandbox_of(&mutate(&plain_template(), &params())).clone();

        assert_eq!(container.command, Some(sandbox_runtime_command()));
        assert_eq!(container.args, None);
        assert_eq!(
            container.security_context,
            Some(workload_container_security_context(1000, 1001))
        );
        assert_eq!(container.ports, Some(vec![sandbox_control_port(2222)]));
        assert_eq!(
            container
                .ports
                .as_ref()
                .and_then(|ports| ports[0].name.as_deref()),
            Some(SANDBOX_CONTROL_PORT_NAME)
        );
    }

    #[test]
    fn mutate_appends_runtime_volumes_after_template_volumes() {
        let scratch = Volume {
            name: "scratch".to_owned(),
            empty_dir: Some(EmptyDirVolumeSource::default()),
            ..Volume::default()
        };
        let template = template_with(
            sandbox_container(),
            PodSpec {
                volumes: Some(vec![scratch.clone()]),
                ..PodSpec::default()
            },
            None,
        );

        let volumes = pod_spec(&mutate(&template, &params())).volumes.clone();

        let mut expected = vec![scratch];
        expected.extend(sandbox_runtime_volumes("bootstrap-secret"));
        assert_eq!(volumes, Some(expected));
    }

    #[test]
    fn mutate_appends_runtime_mounts_after_template_mounts() {
        let data = VolumeMount {
            name: "data".to_owned(),
            mount_path: "/data".to_owned(),
            ..VolumeMount::default()
        };
        let sandbox = Container {
            volume_mounts: Some(vec![data.clone()]),
            ..sandbox_container()
        };
        let template = template_with(sandbox, PodSpec::default(), None);

        let mounts = sandbox_of(&mutate(&template, &params()))
            .volume_mounts
            .clone();

        let mut expected = vec![data];
        expected.extend(sandbox_runtime_volume_mounts());
        assert_eq!(mounts, Some(expected));
    }

    #[test]
    fn mutate_appends_runtime_bootstrap_init_container_after_template_init_containers() {
        let init = Container {
            name: "template-init".to_owned(),
            image: Some(IMAGE.to_owned()),
            ..Container::default()
        };
        let template = template_with(
            sandbox_container(),
            PodSpec {
                init_containers: Some(vec![init.clone()]),
                ..PodSpec::default()
            },
            None,
        );

        let init_containers = pod_spec(&mutate(&template, &params()))
            .init_containers
            .clone();

        assert_eq!(
            init_containers,
            Some(vec![
                init,
                sandbox_bootstrap_init_container(RUNTIME_IMAGE, Some("Always"), 1000, 1001),
            ])
        );
        assert_eq!(
            init_containers
                .as_ref()
                .and_then(|init| init.last())
                .map(|init| init.name.as_str()),
            Some(SANDBOX_BOOTSTRAP_CONTAINER_NAME)
        );
    }

    #[test]
    fn mutate_applies_env_rules_and_keeps_value_from_entries_byte_identical() {
        let secret_entry = EnvVar {
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
        };
        let sandbox = Container {
            env: Some(vec![
                EnvVar {
                    name: "OPENSHELL_SANDBOX_UID".to_owned(),
                    value: Some("0".to_owned()),
                    value_from: None,
                },
                EnvVar {
                    name: sandbox_env::LOG_LEVEL.to_owned(),
                    value: Some("debug".to_owned()),
                    value_from: None,
                },
                secret_entry.clone(),
            ]),
            ..sandbox_container()
        };
        let template = template_with(sandbox, PodSpec::default(), None);

        let env = sandbox_of(&mutate(&template, &params())).env.clone();

        assert_eq!(
            env,
            Some(vec![
                EnvVar {
                    name: sandbox_env::LOG_LEVEL.to_owned(),
                    value: Some("debug".to_owned()),
                    value_from: None,
                },
                secret_entry,
                EnvVar {
                    name: sandbox_env::TELEMETRY_ENABLED.to_owned(),
                    value: Some(telemetry::enabled_env_value().to_owned()),
                    value_from: None,
                },
                EnvVar {
                    name: sandbox_env::OCI_IMAGE_USER.to_owned(),
                    value: Some(String::new()),
                    value_from: None,
                },
                EnvVar {
                    name: sandbox_env::SANDBOX_UID.to_owned(),
                    value: Some("1000".to_owned()),
                    value_from: None,
                },
                EnvVar {
                    name: sandbox_env::SANDBOX_GID.to_owned(),
                    value: Some("1001".to_owned()),
                    value_from: None,
                },
            ])
        );
    }

    #[test]
    fn mutate_keeps_other_sandbox_container_fields_and_preserved_pod_fields() {
        let sandbox = Container {
            image_pull_policy: Some("Always".to_owned()),
            resources: Some(k8s_openapi::api::core::v1::ResourceRequirements::default()),
            env_from: Some(vec![k8s_openapi::api::core::v1::EnvFromSource::default()]),
            ..sandbox_container()
        };
        let spec = PodSpec {
            node_selector: Some(BTreeMap::from([("zone".to_owned(), "a".to_owned())])),
            priority_class_name: Some("high".to_owned()),
            runtime_class_name: Some("gvisor".to_owned()),
            service_account_name: Some("agent".to_owned()),
            ..PodSpec::default()
        };
        let template = template_with(sandbox.clone(), spec.clone(), None);

        let pod = mutate(&template, &params());
        let container = sandbox_of(&pod);

        assert_eq!(container.name, sandbox.name);
        assert_eq!(container.image, sandbox.image);
        assert_eq!(container.image_pull_policy, sandbox.image_pull_policy);
        assert_eq!(container.resources, sandbox.resources);
        assert_eq!(container.env_from, sandbox.env_from);
        assert_eq!(pod_spec(&pod).node_selector, spec.node_selector);
        assert_eq!(pod_spec(&pod).priority_class_name, spec.priority_class_name);
        assert_eq!(pod_spec(&pod).runtime_class_name, spec.runtime_class_name);
        assert_eq!(
            pod_spec(&pod).service_account_name,
            spec.service_account_name
        );
    }

    #[test]
    fn mutate_adds_no_helper_parts_when_no_probe_is_rewritten() {
        let pod = mutate(&plain_template(), &params());
        let spec = pod_spec(&pod);

        assert!(
            !spec
                .volumes
                .iter()
                .flatten()
                .any(|volume| volume.name == PROBE_HELPER_VOLUME_NAME)
        );
        assert!(
            !spec
                .init_containers
                .iter()
                .flatten()
                .any(|init| init.name == PROBE_HELPER_CONTAINER_NAME)
        );
        assert!(
            !sandbox_of(&pod)
                .volume_mounts
                .iter()
                .flatten()
                .any(|mount| mount.name == PROBE_HELPER_VOLUME_NAME)
        );
    }

    #[test]
    fn mutate_adds_memory_probe_volume_when_a_probe_is_rewritten() {
        let spec = pod_spec(&mutate(&probed_template(), &params())).clone();

        assert_eq!(
            spec.volumes.as_ref().and_then(|volumes| volumes.last()),
            Some(&helper_volume())
        );
    }

    #[test]
    fn mutate_adds_probe_installer_before_bootstrap_when_a_probe_is_rewritten() {
        let spec = pod_spec(&mutate(&probed_template(), &params())).clone();
        let installer = Container {
            name: PROBE_HELPER_CONTAINER_NAME.to_owned(),
            image: Some(PROBE_IMAGE.to_owned()),
            image_pull_policy: Some("IfNotPresent".to_owned()),
            command: Some(argv(&["/odp-probe", "install", PROBE_HELPER_MOUNT_PATH])),
            security_context: sandbox_bootstrap_init_container(
                RUNTIME_IMAGE,
                Some("Always"),
                1000,
                1001,
            )
            .security_context,
            volume_mounts: Some(vec![VolumeMount {
                name: PROBE_HELPER_VOLUME_NAME.to_owned(),
                mount_path: PROBE_HELPER_MOUNT_PATH.to_owned(),
                ..VolumeMount::default()
            }]),
            ..Container::default()
        };

        let init = spec.init_containers.expect("init containers");

        assert_eq!(init.len(), 2);
        assert_eq!(init[0], installer);
        assert_eq!(init[1].name, SANDBOX_BOOTSTRAP_CONTAINER_NAME);
    }

    #[test]
    fn mutate_mounts_probe_helper_read_only_when_a_probe_is_rewritten() {
        let container = sandbox_of(&mutate(&probed_template(), &params())).clone();

        assert_eq!(
            container
                .volume_mounts
                .as_ref()
                .and_then(|mounts| mounts.last()),
            Some(&helper_mount())
        );
    }

    #[test]
    fn mutate_rewritten_probe_runs_the_helper_binary() {
        let container = sandbox_of(&mutate(&probed_template(), &params())).clone();

        assert_eq!(
            container.liveness_probe,
            Some(exec_probe(argv(&[
                PROBE_HELPER_BINARY,
                "http-get",
                "--port",
                "8080",
                "--path",
                "/healthz",
            ])))
        );
    }

    #[test]
    fn mutate_tcp_probe_alone_adds_helper_volume_and_installer() {
        let sandbox = Container {
            readiness_probe: Some(Probe {
                tcp_socket: Some(TCPSocketAction {
                    host: None,
                    port: IntOrString::Int(9000),
                }),
                ..Probe::default()
            }),
            ..sandbox_container()
        };
        let template = template_with(sandbox, PodSpec::default(), None);

        let pod = mutate(&template, &params());

        assert_eq!(
            sandbox_of(&pod).readiness_probe,
            Some(exec_probe(argv(&[
                PROBE_HELPER_BINARY,
                "tcp",
                "--port",
                "9000"
            ])))
        );
        assert!(
            pod_spec(&pod)
                .volumes
                .iter()
                .flatten()
                .any(|volume| volume.name == PROBE_HELPER_VOLUME_NAME)
        );
        assert!(
            pod_spec(&pod)
                .init_containers
                .iter()
                .flatten()
                .any(|init| init.name == PROBE_HELPER_CONTAINER_NAME)
        );
    }

    #[test]
    fn mutate_grpc_probe_alone_adds_no_helper_parts() {
        let sandbox = Container {
            startup_probe: Some(Probe {
                grpc: Some(k8s_openapi::api::core::v1::GRPCAction {
                    port: 9000,
                    service: None,
                }),
                ..Probe::default()
            }),
            ..sandbox_container()
        };
        let template = template_with(sandbox.clone(), PodSpec::default(), None);

        let pod = mutate(&template, &params());

        assert_eq!(sandbox_of(&pod).startup_probe, sandbox.startup_probe);
        assert!(
            !pod_spec(&pod)
                .volumes
                .iter()
                .flatten()
                .any(|volume| volume.name == PROBE_HELPER_VOLUME_NAME)
        );
    }
}

<!--
SPDX-FileCopyrightText: Copyright (c) 2026 Josh Symonds
SPDX-License-Identifier: Apache-2.0
-->

# Design notes: a PodTemplate compute driver for OpenShell

Research notes for an out-of-tree OpenShell compute driver that runs each sandbox as a single-use pod cloned from a user-supplied `PodTemplate`. Answers are taken from source and cited `path:line`; anything not confirmed is marked **unverified**.

## Sources

| Repository | Ref | SHA |
| --- | --- | --- |
| NVIDIA/OpenShell | `main` (surveyed) | `c4688aa8715ea75d6c39fe468361dbbc16c691fa` |
| NVIDIA/OpenShell | `v0.1.5` (pinned for the driver) | `bdb956f2cd65a635f1294fccf1d138d263bf650f` |
| NVIDIA/OpenShell | PR #3508 head (warm pools, open) | `d70a7633538a03d133408d4bca976d300a107be7` |
| kubernetes-sigs/agent-sandbox | `main` | `f83f2d87c1aeeb90407d8cfe9a0c1fad74044304` |
| kubernetes-sigs/agent-sandbox | `v1.0.3` (OpenShell's e2e pin) | `527d9346fe1d237dea5c003f3c720531c7bab1df` |
| NVIDIA/NemoClaw | `main` | `b60c91f7b762dbfc4c86385172783bc45efa0119` |

Citations are against OpenShell `main` unless they say `v0.1.5`. The two differ in the Kubernetes driver: `main` adds runtime-initiated control (#4656) and a shared supervisor (#4702), and `isolation.rs` grew by 344 lines after `v0.1.5`.

## Corrections to the starting assumptions

| Assumption | What the source says |
| --- | --- |
| The k8s driver bakes per-sandbox identity into the workload pod spec | The supervisor runs in a **separate pod**. `OPENSHELL_SANDBOX_ID` and `OPENSHELL_MAIN_PROCESS_SPEC` are set on the supervisor pod (`crates/openshell-driver-kubernetes/src/sandbox_runtime.rs:350-352`). The workload reads one bootstrap bundle and its own pod UID, once, then deletes them (`crates/openshell-sandbox/src/boundary_server.rs:224-237`). |
| An external driver can pair workloads with the shared supervisor (`supervisor_topology = "gateway"`) | Shared supervision is an in-process Rust API handed to the in-tree driver (`crates/openshell-driver-kubernetes/src/shared_supervisor.rs:25`, `crates/openshell-server/src/lib.rs:1708`), and its host protocol is "version-locked" to that driver (`proto/supervisor_host.proto:5-11`). An external driver gets a dedicated supervisor per sandbox. |
| The proto is enough to write a driver | `BoundaryConfig`, `SandboxRuntimeDescriptor` and the provisioning-evidence digest are Rust serde structs with `deny_unknown_fields` (`crates/openshell-sandbox-backend/src/boundary_protocol.rs:486-488, 541-543`), not proto messages. |
| Late binding can live in the driver | It needs gateway changes: PR #3508 adds a `RegisterSupervisor` flow, an allocation-claims table and new driver RPCs. |
| RFC 0001: the gateway launches third-party drivers | The gateway connects to a socket and does not start or supervise the driver (`docs/extensibility/drivers.mdx:42-43`). Only the VM driver is spawned (`crates/openshell-gateway/src/vm.rs:531-594`). |
| The claim controller waits 2 s before cold fallback | Confirmed: `DefaultWarmCandidateGracePeriod = 2 * time.Second`, measured from the claim's creation timestamp (agent-sandbox `extensions/controllers/sandboxclaim_controller.go:67, 2068-2077`). |

## 1. Driver contract

`proto/compute_driver.proto` defines 12 RPCs. The capability flags in `GetCapabilitiesResponse` change what the gateway expects.

| RPC | What the driver must do | Gateway caller | Optional? |
| --- | --- | --- | --- |
| `GetCapabilities` | Report capabilities; reject unmet gateway requirements (`proto:68-70`) | startup and before each validate/create/start (`crates/openshell-server/src/compute/mod.rs:565-590, 814-822`) | No |
| `AuthenticateSandbox` | Verify an opaque credential, return `sandbox_id` and a stable `runtime_identity` (`proto:113-125`) | `compute/mod.rs:1144-1162`; identity compared at `crates/openshell-server/src/grpc/auth_rpc.rs:134-140` | Only if `supports_sandbox_authentication` |
| `ValidateSandboxCreate` | Reject unprovisionable specs | `compute/mod.rs:1222-1270` | No (UNIMPLEMENTED is not tolerated) |
| `CreateSandbox` | Provision; return `runtime_identity` when auth is advertised (`proto:424-433`) | `compute/mod.rs:1543`; only AlreadyExists/FailedPrecondition pass through, other codes become Internal (`:1563-1565`) | No |
| `GetSandbox` / `ListSandboxes` | Platform-observed snapshots | reconcile every minute (`compute/mod.rs:397, 4844, 6109`) | No |
| `StopSandbox` / `StartSandbox` | Idempotent stop keeping persistent state; start with fresh launch auth and generation (`proto:435-470`) | `compute/mod.rs:1961, 2003` | No |
| `DeleteSandbox` | Delete; report whether anything was deleted (`proto:473-483`) | `compute/mod.rs:2944` | No |
| `WatchSandboxes` | Stream of sandbox / deleted / platform events (`proto:485-513`) | `compute/mod.rs:4293-4337`, restarted after 2 s on error | No |
| `EnsureWorkspace` / `DeleteWorkspace` | Idempotent workspace setup | UNIMPLEMENTED is treated as success (`compute/mod.rs:1196, 1217`) | Yes |

| Capability | Effect |
| --- | --- |
| `gateway_manages_lifecycle` | Gateway stops compute at shutdown and restarts persisted running intent at startup (`compute/mod.rs:3539-3541, 3674-3676`). |
| `supports_sandbox_authentication` | Enables `AuthenticateSandbox`; create, start and restart must return a runtime identity (`compute/mod.rs:1592-1596, 2270-2273`). |
| `driver_reports_runtime_readiness` | When false, Ready also requires the supervisor session (`compute/mod.rs:7279-7310`). |
| `extension` | Must declare protocol 1.0, `openshell.compute.contract`, and `openshell.compute.isolation-backend` to register an isolation backend (`crates/openshell-core/src/extension_protocol.rs:23, 425, 454`). |
| `resource_admission_policy` | Exact-match handshake with the gateway's admission config (`crates/openshell-core/src/resource_admission.rs:63-81`). |

**State ownership.** The gateway persists every sandbox record (phase, runtime identity, isolation-backend pin, provisioning deadlines, lifecycle intent) as protobuf in its own SQLite or Postgres store (`crates/openshell-server/migrations/sqlite/001_create_objects.sql:1-11`). The driver is the observer of platform state. After a gateway restart the gateway replays persisted intent, then reconciles with `ListSandboxes` and `GetSandbox`; store records missing from the driver are pruned after a five-minute grace (`compute/mod.rs:412, 4870-4882`). The gateway is the only allocator of sandbox IDs.

## 2. Third-party drivers

Implemented at both `main` and `v0.1.5`. The gateway connects to a named driver over a Unix socket set by `--compute-driver-socket` or `[openshell.drivers.<name>] socket_path` (`v0.1.5:crates/openshell-server/src/cli.rs:180`, `v0.1.5:crates/openshell-server/src/compute/driver_config.rs:111-123`). The transport is UDS only, so an external driver runs beside the gateway, for example as a sidecar. An out-of-tree Apple `container` driver passes the conformance suite (issue #4640). Selection is per gateway, not per sandbox (`crates/openshell-server/src/lib.rs:1601-1638`).

**Driver-config passthrough (RFC 0006, implemented).** The caller's `template.driver_config` is keyed by driver name; only the active driver's block is forwarded (`compute/mod.rs:6597-6613`), gated by `allow_driver_config`, default false (`crates/openshell-server/src/compute/driver_config.rs:76-97`).

**The stock k8s driver cannot take a PodTemplate.** Its `driver_config` accepts only node selector, runtime class, tolerations, priority class, agent resources and PVC volumes (`crates/openshell-driver-kubernetes/src/driver.rs:509-581`). Init containers, emptyDir/ConfigMap/Secret volumes, `valueFrom` env, extra containers and probes cannot be expressed.

## 3. Language

A driver must emit `BoundaryConfig`, `SandboxRuntimeDescriptor`, `SandboxLaunchAuthentication` handling and a `ProvisioningEvidence` digest that the runtime and supervisor parse with `deny_unknown_fields` (`crates/openshell-isolation-interface/src/contract.rs:233-245`, `proto/sandbox_protocol.proto:324-327`). These are Rust types in `openshell-sandbox-backend`, `openshell-isolation-interface` and `openshell-core`.

| | Rust | Go |
| --- | --- | --- |
| Protocol types | Link the upstream crates, pinned to the runtime/supervisor release | Reimplement serde structs and digests byte-for-byte; silent drift on every release |
| Reuse | The public `isolation` module (fence, policies, boundary provisioning) is reusable (`v0.1.5:crates/openshell-driver-kubernetes/src/isolation.rs:80-217`) | None |
| Cost | Version lock: driver, runtime image and supervisor image move together | Same lock, without the compiler checking it |

Rust wins.

## 4. Identity and authentication

**Supervisor.** The supervisor pod mounts a projected ServiceAccount token with audience `openshell-gateway` (`sandbox_runtime.rs:398-411`) and presents it on `IssueSandboxToken`. The gateway forwards it to `AuthenticateSandbox`; the k8s driver runs TokenReview, checks the pod UID, the owning resource and the supervisor role, and returns `kubernetes://<ns>/<owner UID>/<pod UID>` (`driver.rs:1141-1209, 6106-6148`). The gateway compares that identity with the one recorded at create and mints a session JWT (`auth_rpc.rs:63-180`).

**Workload.** It has no ServiceAccount token (`driver.rs:2745-2760`). It is a TLS server pinned by a per-session trust anchor and checks a gateway-signed EdDSA JWT on every request (`crates/openshell-sandbox-backend/src/sandbox_auth.rs:93-119`, `crates/openshell-core/src/jwt.rs:813-830`).

Everything per-sandbox, which late binding would have to deliver:

| Value | Consumer | Delivered via | When |
| --- | --- | --- | --- |
| Sandbox ID, name, main-process spec, gateway endpoint | supervisor | pod env (`sandbox_runtime.rs:344-352`) | at supervisor pod create |
| Launch auth bundle (gateway token, sandbox token) | supervisor | Secret `auth.json` (`driver.rs:3550-3560`) | after pods exist |
| Runtime descriptor, proxy CA | supervisor | same Secret | after pods exist |
| Projected SA token | supervisor | projected volume | at pod create |
| `BoundaryConfig`: boundary ID, generation, session, auth epoch, verification keys, listener, resource claims (incl. workload pod UID), evidence, child env | workload runtime | immutable Secret `boundary.json` (`sandbox_runtime.rs:601-630`) | after the workload pod UID is known (`driver.rs:3419-3541`) |
| Boundary TLS certificate and key | workload runtime | same Secret | same |
| Workload pod UID | workload runtime | downward API file, checked once at startup (`boundary_server.rs:472-491`) | kubelet |
| Main-process command | workload runtime | `StartAgent` from the supervisor (`boundary_server.rs:2962-3072`) | after attach |

The workload command is never in the pod spec, so a runtime can sit attached and idle before its workload is chosen.

## 5. Late-binding mechanisms

The runtime reads its bundle once and has no wait, poll or watch for configuration; a missing bundle is an immediate error (`crates/openshell-sandbox/src/main.rs:1515-1611`, `boundary_server.rs:224-237`).

| Mechanism | Verdict |
| --- | --- |
| Downward-API volume projecting pod annotations | Updates in place: **measured 0.3–1.2 s** from `kubectl annotate` to file change on k3s v1.32 (four trials). Usable as a bind signal, but the runtime would need a new wait phase. |
| Secret or ConfigMap mounted after the claim | The bootstrap Secret is immutable and its name is fixed in the pod spec (`sandbox_runtime.rs:629`, `driver.rs:7066-7068`). A pre-named Secret could be created at claim time, but kubelet holds the pod in `ContainerCreating` until it exists (Kubernetes semantics, unverified here), so the pod is not warm. |
| UDS or HTTP handshake from the supervisor | What PR #3508 does, in-band: a prepared workload boots with an empty `boundary_id`, pinned only to its physical UIDs; the first gateway-signed JWT whose `resource_binding` matches those UIDs assigns the logical sandbox permanently (`pr-3508:crates/openshell-sandbox-backend/src/sandbox_auth.rs`, `SandboxProtocolAuthenticator::unassigned`). About 60 runtime lines. |
| Init step that waits on a file | Possible with a wrapper before `openshell-sandbox`, but the bundle is bound to the pod UID and must be generated per pod anyway; it adds nothing over the in-band binding. |

**What changes in `openshell-sandbox`:** for warm pools, the unassigned authenticator from #3508. For cold start, nothing.

## 6. Runtime staging

A trusted init container from the gateway-configured runtime image runs `/openshell-sandbox bootstrap`. It copies itself into a memory-backed emptyDir and stages the three bootstrap files (`main.rs:1539-1592`). The agent container's command becomes `openshell-sandbox --bootstrap …/boundary.json` (`driver.rs:7106-7113`). The k8s driver also forces: a scheduling gate (`driver.rs:7014-7016`), boundary role and pair labels (`:6973-6996`), `dnsPolicy: None` with `127.0.0.53`, no host namespaces, `RuntimeDefault` seccomp (`:6999-7041`), `automountServiceAccountToken: false` (`:7631-7634`) and `restartPolicy: Never` (`:7637`), and it strips `OPENSHELL_*` user env except `OPENSHELL_LOG_LEVEL` (`:7865-7880`).

**Generic against an arbitrary PodTemplate:** yes, under the rules below.

### Template rules

The driver rejects a template with `InvalidArgument`, creating nothing, when it:

1. has more than one container (a second container would share the fence but run outside the sandbox);
2. has no explicit `command` on that container (an empty command means "login shell", not the image's `CMD`; `v0.1.5:crates/openshell-core/src/sandbox_env.rs:74-99`);
3. has an exec probe (kubelet exec runs outside the sandbox boundary);
4. sets `hostNetwork`, `hostPID`, `hostIPC` or `shareProcessNamespace`;
5. sets `privileged`, adds capabilities, or allows privilege escalation;
6. mounts a `hostPath` volume or a projected ServiceAccount token, or sets `automountServiceAccountToken: true`;
7. runs as uid or gid 0;
8. uses a reserved volume name or mounts under `/.openshell` or `/run/openshell`;
9. names an image different from the sandbox's `template.image`.

The driver keeps, unchanged: labels, annotations, init containers, volumes, env (including `valueFrom`), resources, `nodeSelector`, `tolerations`, `affinity`, `priorityClassName`, `runtimeClassName` and `serviceAccountName`.

The driver changes: the pod name (the sandbox name), a scheduling gate, the boundary role and pair labels, the runtime init container, the container `command` (the runtime becomes PID 1 and the template command becomes the main process), DNS, `automountServiceAccountToken: false`, `restartPolicy: Never`, and `httpGet`/`tcpSocket` probes, which become exec probes against `127.0.0.1` (the runtime binds workload sockets to loopback: `v0.1.5:crates/openshell-sandbox/src/linux/socket_confinement.rs:6-29`).

`valueFrom` env stays on the container: the child inherits the container env with only `OPENSHELL_*` removed (`v0.1.5:crates/openshell-sandbox/src/process.rs:204-226`).

## 7. Supervisor topology and fencing

`v0.1.5` offers only a dedicated supervisor pod per sandbox that dials the workload's boundary port through a per-sandbox Service. `main` adds runtime-initiated control and a shared supervisor; the latter is unavailable to external drivers (section "Corrections").

| Policy | Selects | Rule |
| --- | --- | --- |
| Namespace workload fence `openshell-sandbox-workloads` | `openshell.ai/boundary-role=workload` | ingress only from supervisor-role pods on the boundary port; **egress `[]`**, deny-all (`crates/openshell-driver-kubernetes/src/isolation.rs:141-190`) |
| Namespace supervisor egress `openshell-sandbox-supervisors` | `boundary-role=supervisor` | all egress (`isolation.rs:192-197`) |
| Per-pair control (`main`, runtime-initiated) | `openshell.ai/boundary-pair=<id>` | workload → own supervisor on the control port (`isolation.rs:244-290`) |

**Egress policy.** Workload traffic leaves only through the supervisor's proxy, which evaluates OpenShell policy. Endpoints may be HTTP-inspected or uninspected TCP (`protocol: tcp`; `v0.1.5:crates/openshell-policy-schema/src/lib.rs:1117`), so non-HTTP protocols such as a raw TCP service can be allowed. Link-local addresses are always blocked, whatever the policy says (`crates/openshell-core/src/net.rs:62`).

**Can the fence key on a label applied at claim time?** It needs no claim-time label: the namespace fence keys on the role label, which is set when the pod is created, so a warm pod is fenced from birth. The driver checks the policy's UID and generation every 30 s and suspends on mismatch (`driver.rs:4658-4684`). Pair labels are physical (the pair, not the logical sandbox), so they also need no rebinding.

## 8. agent-sandbox warm pools

- `SandboxWarmPool` creates pool-owned `Sandbox` CRs by `GenerateName`; the core controller creates a pod named after each (`extensions/controllers/sandboxwarmpool_controller.go:1160-1215`, `controllers/sandbox_controller.go:1830-1841`).
- `SandboxClaim` pops a candidate, prefers a Ready one with pod IPs, transfers the controller ownerRef to the claim and patches labels and annotations onto the existing pod; nothing is re-created (`sandboxclaim_controller.go:1135-1430`).
- Cold fallback: immediate with no candidates, after the 2 s grace with only pending ones, and always when the claim sets `env` or `volumeClaimTemplates` (`:2251-2281`).
- Double claims: queue pop under a mutex plus an optimistic-lock merge patch with a re-read on 409 (`queue/simple_sandbox_queue.go:183-205`, `sandboxclaim_controller.go:1422-1560`). No Lease.
- Identity on claim: labels and annotations only; no env, Secret or downward API is injected after start (`docs/configuration.md:303-317`).
- Enabled by `--extensions` on the same controller binary (`cmd/agent-sandbox-controller/main.go:104, 487-566`).
- **OpenShell does not use the extension CRDs** at `main` or `v0.1.5`. PR #3508 builds its own pool on core `Sandbox` resources.

## 9. Prior art

| Item | State | Relevance |
| --- | --- | --- |
| #2157 warm-pool provisioning for k8s | open, canonical | names late-bound identity as the main design change |
| PR #3508 template-driven warm pooling (grs) | open, +10.7K, rebased 2026-10-16 | the upstream answer: prepared pairs, gateway allocation claims, `RegisterSupervisor`, signed resource binding, new driver RPCs `SelectWarmPair`/`SyncWarmPools` |
| PR #2460 SandboxClaim warm pools | closed for #3508 | earlier one-pod design |
| #1447, #1879 warm pools | closed as duplicates | design history; #1447 comment proposes a downward-API bind signal, validated on GKE |
| #2787 emptyDir workspaces | open | the PVC is a stopgap (`driver.rs:847`, `crates/openshell-driver-kubernetes/README.md:289`) |
| #2680 template and API cleanup | open | separates workload shape from policy and providers |
| #2061, #4640, #4848 external drivers | closed / closed / open | external model is first-class; conformance for external drivers in progress |
| #3556 lifecycle RPCs carry an ambiguous `name` | open | treat `sandbox_id` as authoritative |

No upstream work proposes a PodTemplate-based driver.

## Experiments

Run on kind v0.31 (k8s v1.35, kindnet, rootless podman) with OpenShell `v0.1.5` from its published chart and agent-sandbox `v1.0.3`.

| Question | Result |
| --- | --- |
| Does kindnet enforce NetworkPolicy? | Yes. Fenced egress and disallowed ingress time out; node-to-pod traffic is exempt. |
| Are a sandboxed child's listeners reachable by kubelet probes? | **No.** A child listening on `[::]:9090` refuses connections from the node, while a plain pod under the same fence answers. An exec in the container reaches `127.0.0.1:9090`. RFC 0017 routes inbound traffic only through the supervisor relay. |
| What does main-process exit 0 do? | Gateway phase `Completed` within ~5 s; the pod stays `Running` (the runtime keeps PID 1). |
| Cold create to Ready | ~12 s including image pulls. |
| Downward-API annotation update latency (k3s v1.32) | 0.3–1.2 s. |

## Designs

Each design covers cold start, a warm pool and late binding.

### A. Identity bound at create, no driver pool (recommended)

- **Cold start:** the driver clones the PodTemplate, stages the runtime, pairs a dedicated supervisor and applies the fence.
- **Warm pool:** none in the driver or in OpenShell; a sandbox created ahead of demand is a complete, ordinary sandbox.
- **Late binding:** none at the OpenShell level; each sandbox has its identity from create.
- **OpenShell changes:** none; everything is in the driver.
- **Failure modes:** a pod dying is reported by Watch as a sandbox failure; there is no claim step, so there is no double claim; a gateway restart relists and sandboxes keep running; node loss surfaces as `Error`.

### B. Driver-owned warm pool on PR #3508's contract

- **Cold start:** as A.
- **Warm pool:** the driver implements `SyncWarmPools` and `SelectWarmPair`, preparing unassigned workload/supervisor pairs from the template.
- **Late binding:** the unassigned runtime accepts the first gateway-signed JWT whose resource binding matches its physical UIDs; the supervisor receives credentials in memory through `RegisterSupervisor`.
- **OpenShell changes:** #3508 (gateway, proto, runtime), merged or carried.
- **Failure modes:** a pod dying before claim is retired and replaced; after claim it is an ordinary sandbox failure; double claims are prevented by the gateway's allocation-claims primary key; uncertain claims stay pending across a gateway restart; node loss retires idle pairs.

### C. Downward-API bind signal

- **Cold start:** as A.
- **Warm pool:** agent-sandbox `SandboxWarmPool`/`SandboxClaim`.
- **Late binding:** the claim writes the sandbox ID as an annotation; a new runtime phase waits on the projected file, then runs the normal bootstrap.
- **OpenShell changes:** a wait phase in the runtime and supervisor, plus a gateway path that accepts a pod it did not create; the bootstrap bundle is still bound to the pod UID, so it must be minted per pod after the claim.
- **Failure modes:** a stale or missing annotation leaves a pod parked; the 0.3–1.2 s projection lag sits on the claim path; double claims rely on agent-sandbox's optimistic patch.

**Recommendation:** A now. It reaches the goal on a stock release with no upstream changes. B is the upgrade path once #3508 merges, and its driver RPCs are what an external driver would implement. C loses to B: it needs comparable upstream changes without B's in-band, signed binding.

## First-cut scope (cold start)

Acceptance criteria:

1. A stock `v0.1.5` gateway uses the driver by name over UDS and creates and deletes sandboxes through it.
2. A sandbox created from a PodTemplate keeps the template's labels, annotations, init containers, volumes, env (including `secretKeyRef`), resources, node selector and tolerations, is paired with one dedicated supervisor, and reaches Ready.
3. Pod readiness tracks the template's `httpGet` probe.
4. Unsupported templates (more than one container, exec probes, host namespaces, privileged or added capabilities, hostPath, projected tokens, uid/gid 0, reserved names, no command) are rejected and create nothing.
5. Workload egress goes only through the supervisor: allowed HTTP and raw TCP work; direct and disallowed connections fail, from init containers too.
6. Secret values reach the workload env and nothing the driver writes.
7. Exit 0 ends in `Completed`; delete and failed creates leave no residue; driver and gateway restarts neither orphan nor duplicate sandboxes.
8. Quality: upstream's clippy table with `-D warnings`, ≥90% line coverage, `cargo deny`, documented public API, README and architecture diagrams.

**Phase two (warm pool)** adds design B: implement `SyncWarmPools` and `SelectWarmPair`; prepare unassigned pairs from the template; accept `supervisor_registration` in `AuthenticateSandbox`; prove claim latency, pool replenishment, single-use retirement and recovery of uncertain claims.

## Open questions

- Does a non-zero main-process exit map to a distinct gateway phase?
- Will #3508 merge in a form whose driver RPCs match the current branch?

# Spike: NVIDIA OpenShell as toto's sandbox

- Date: 2026-10-21
- Result: **it works.** toto's full pipeline runs on OpenShell unchanged, including a networked project whose egress rules OpenShell enforces per request.
- Outcome: ADR 17 makes OpenShell toto's one sandbox, shipped with toto and run through a private gateway toto manages. The contributor setup described below is now done by toto (`src/openshell_gateway.rs`); this page records the spike as it was.
- Code: `src/openshell.rs`, the `openshell` sandbox kind in `src/config.rs`, the proxy's keyed TCP listener in `src/proxy.rs`, `agent::with_external_egress`. Tests: `openshell_unit` (always), `the_same_pipeline_runs_on_openshell` and `a_projects_egress_rules_are_enforced_by_openshell` (live, behind `TOTO_OPENSHELL_BIN_DIR` and `TOTO_OPENSHELL_NET=1`; see `openshell_sandbox` in `src/tests.rs`).

## Why look at it

toto's Docker sandbox has two gaps:
- **Networked agents run only on Linux.** Their network fence is iptables on a Linux Docker host, so on macOS and Windows those projects are refused.
- **There's no VM-strength boundary on a Mac.** gVisor is Linux-only.

OpenShell has the same shape as toto: a network-less workload, and a trusted side that mediates every connection. It enforces per-host, per-request rules on every platform, and it offers a MicroVM driver.

## What was tested

- **Environment:** Linux x86_64, Docker 29.6, kernel with Landlock ABI 7, no KVM.
- **OpenShell build:** built from source at `main` (`0.0.1-dev.1+gd22394370`). Release assets and GHCR images were not reachable from the test environment.
- **Gateway:** run locally with the Docker driver and the package's local mTLS setup (`openshell-gateway generate-certs`).
- **Workload image:** the same Omnigent image the Docker end-to-end test uses.

| Question | Answer |
|---|---|
| Does it run a project's own image? | Yes. Any image works: OpenShell places a static runtime in it. A sandbox from toto's Omnigent image was ready in about 2 s. |
| Does toto's pipeline work unchanged? | Yes. The whole sequence ran: a signed task, the approved image and agent with a skill, 4.5 MB of inputs, Omnigent running a shell tool, model calls metered through toto's proxy, only the changed file returned, and a signed result. It took 27 s, against 22 s on toto's Docker sandbox. |
| Can a sandbox reach toto's credential proxy on the host? | Yes. A policy rule for `host.openshell.internal:<port>` works, and other ports are refused. The connection arrives from **127.0.0.1**, because the Docker driver's supervisor shares the host's network. So toto's proxy listens on loopback only. |
| Does the credential stay out of OpenShell? | Yes. toto does not use OpenShell's providers. The agent holds a per-run 256-bit key for toto's proxy, which refuses any request without it. The real credential is added only in toto's proxy. |
| Confinement | The workload runs as uid 65534. All capabilities are dropped, with `no-new-privileges` and no network interface. Landlock is a hard requirement, the whole image is read-only, and only `/work` and `/tmp` are writable. PID 1 is OpenShell's runtime. |
| Network without a rule | Every connect fails with `EACCES`, including raw TCP and DNS. |
| A project's egress rules | `GET pypi.org/simple/**` returned 200. Another path on the same host got 403 `policy_denied`, and so did another method. An unlisted host was refused. The rules are enforced in the supervisor, on any OS. |
| Disk | Per-sandbox tmpfs mounts cap `/work` at 512 MiB and `/tmp` at 256 MiB, as in toto's Docker sandbox. A 600 MB write stops at the cap. |
| CPU and memory | `--cpu` and `--memory` are applied. |

## How toto uses it

```
agent ──HTTP, per-run key──▶ host.openshell.internal:<port> ──supervisor (policy)──▶ 127.0.0.1:<port>
                                                                                      toto proxy: checks the key,
                                                                                      adds the credential, meters,
                                                                                      reads rate limits ──▶ provider
```

- **The proxy.** `AuthProxy::listen_tcp` serves the same proxy on a loopback TCP port, and only requests carrying the key get through. The Unix socket and the relay remain for the Docker sandbox.
- **The policy** (`OpenShellSandbox::policy_yaml`):
  - the image is read-only;
  - `/work` and `/tmp` are writable;
  - Landlock is a `hard_requirement`;
  - the workload runs as uid and gid 65534;
  - the network allows one rule for toto's proxy, plus the project's Omnigent egress rules, each translated to a `protocol: rest` endpoint on port 443 with `enforcement: enforce`.
- **The work directory** is toto's own size-capped tmpfs at `/work`, because OpenShell reserves `/sandbox`. Commands run through `openshell sandbox exec` with `--workdir` and `--env`.
- **Inputs** go in over `exec` stdin. Bundles over 3 MiB are sent in pieces, because `sandbox upload` needs an ssh client on the host and stdin is capped at 4 MiB per call. Outputs come back as a tar stream on stdout, through the same code as Docker.
- **Omnigent's own network sandbox is turned off.** Omnigent will only run with egress rules if it enforces them itself with bubblewrap, and bubblewrap cannot start inside an OpenShell workload (no user namespaces, as it should be). So toto replaces `os_env.sandbox` with `{type: none}` (plus `allow_network: true` for a networked agent), and OpenShell enforces the same approved rules from outside. Everything else in the approved agent directory is unchanged.

## What a contributor needs

- OpenShell installed (`install.sh`, Homebrew on macOS) and its local gateway running. The package sets up the local mTLS that Docker sandboxes require.
- `allow_driver_config = true` under `[openshell.drivers.docker]` in the gateway's config. Without it, toto cannot cap the task's disk, so toto refuses to start the task and says why.
- `"sandbox": {"kind": "openshell"}` in toto's config. Optionally add `gateway` (the CLI's gateway name) and `proxy_bind` (default `127.0.0.1`).
- Behind a TLS-intercepting corporate proxy, the gateway needs four settings:
  - `https_proxy`;
  - `proxy_ca_bundle`;
  - `proxy_connect_by_hostname`, if the proxy allows by hostname;
  - `no_proxy` including `host.openshell.internal`, without which toto's proxy is unreachable.

## Caveats

- **Young software.** OpenShell is at 0.1.x, with breaking changes between releases (its gateway config is at schema version 2). toto drives the CLI, so pin a version and test upgrades.
- **One more trusted component.** The supervisor sits on the host's network, terminates TLS and parses the agent's HTTP. It is in the same position as toto's proxy, but it is NVIDIA's code and NVIDIA's images. It runs unprivileged, read-only, with no capabilities, as uid 65534. It never sees the provider credential, only toto's per-run key, on a plain-HTTP loopback hop.
- **The pid limit is set per gateway** (default 2048), not per sandbox. toto's Docker sandbox uses 256.
- **Projects whose agents need a network but declare no egress rules are refused.** OpenShell grants destinations one by one, and that is the point.
- **Network-path port.** The proxy port is open to any local process on loopback, guarded only by the key. That's comparable to toto's UI token. On a shared machine, another user's process could try keys, but 256 bits is beyond guessing.

## Not tested

- **macOS** with Docker Desktop and with the **MicroVM** driver (Hypervisor.framework). This is the case that motivates the backend; no KVM or Mac was available.
- Windows (WSL 2, experimental upstream), Podman, and the Kubernetes driver.
- Pulling a published image by digest. Only local images were used here.

## Next steps

1. Run the two live tests on a Mac:
   - first with Docker Desktop;
   - then with the MicroVM driver (`compute_driver = "vm"`), which also needs its own way to cap disk, because driver config is Docker-specific.
2. Teach `toto doctor` to read the gateway's settings: driver config allowed, Landlock ABI, driver type.
3. Show contributors, at approval, when a project's egress rules will be enforced by OpenShell rather than by Omnigent.
4. If those hold, write an ADR making OpenShell the default sandbox on macOS. Docker stays the default on Linux, where its fence and gVisor already work.

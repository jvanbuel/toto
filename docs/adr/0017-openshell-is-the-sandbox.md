# 17. NVIDIA OpenShell is toto's sandbox, shipped with toto

- Status: Accepted (implemented 2026-10-21: `src/openshell.rs`, `src/openshell_gateway.rs`, `src/openshell_pin.rs`, `openshell.lock.toml`, `.github/workflows/release.yml`; tested on Linux with the Docker driver, not yet on macOS)
- Date: 2026-10-21
- Supersedes: the sandbox part of ADR 13 (hardened Docker run, `netfence`, Omnigent's nested bubblewrap). ADR 13's dev container and agent directory, and ADR 12's credential proxy, are kept.
- Evidence: `docs/spikes/openshell.md`

## Context

toto's sandbox until now was its own hardened `docker run` with these parts:
- a read-only image, no capabilities, uid 65534 and size-capped tmpfs mounts;
- `netfence`, an iptables-fenced Docker network for agents that need a network;
- Omnigent's bubblewrap sandbox nested inside the container, to enforce a project's egress rules.

It works on Linux, but two gaps hit most contributors:

- **Networked agents run only on Linux.** The fence is iptables on the Docker host. On macOS and Windows that host is a VM toto cannot add rules to, so those projects were refused.
- **Three mechanisms, all toto's to maintain.** The container hardening, the iptables fence and a seccomp profile that lets a nested bubblewrap start.

The spike (`docs/spikes/openshell.md`) ran toto's full pipeline on NVIDIA OpenShell, unchanged:
- a network-less workload;
- Landlock (as a hard requirement) and seccomp;
- every connection mediated by a supervisor against a per-sandbox policy, with per-request method and path rules on any OS.

The spike also showed what OpenShell needs from its user:
- a gateway process with local mTLS;
- one non-default setting, `allow_driver_config`;
- pinned images;
- care across versions, because it is at 0.1.x.

That setup is the part contributors would get wrong.

## Decision

**OpenShell is toto's one sandbox, and toto ships and runs it.** Contributors install toto and never set up OpenShell.

- **Pinned.** `openshell.lock.toml` names the version, its release URL, the SHA-256 of each release archive per platform (`x86_64-linux`, `aarch64-linux`, `aarch64-macos`), and the supervisor and sandbox-runtime images by digest. It is compiled into toto.
  - toto refuses an image pinned by tag, and refuses to install an archive whose checksum is not pinned or does not match.
  - `scripts/pin-openshell.sh <version>` fills the lock from the release; `--check` fails if anything is unpinned.
  - Upgrading OpenShell is a reviewed change to that file, plus a run of the live tests.
- **Shipped together.** The release workflow builds toto for each platform and runs `toto openshell install --dest`, which downloads and verifies the pinned OpenShell. It then packs both into one archive, with OpenShell's licence.
  - `scripts/install.sh` puts the archive in its own directory and links only `toto` onto the PATH, so an OpenShell the contributor installed themselves is untouched.
  - `toto openshell install` fetches the same pinned binaries for a toto built from source.
- **A private, managed gateway.** The daemon starts its own gateway and stops it on exit.
  - Its state lives under `<state_dir>/openshell/gateway`: mTLS material, config, database, log, and the CLI's registration in an isolated `XDG_CONFIG_HOME`.
  - It listens on loopback (port 17717, health on 17718).
  - It runs the pinned images and allows driver config, so toto can cap `/work` and `/tmp`.
  - It labels its sandboxes `toto-<hash of the state dir>`. An OpenShell gateway cleans up whatever carries its label when it starts, so two gateways on one Docker must not share a label. The spike found this when two ran at once.
  - A second toto process, such as `toto doctor` while the daemon runs, uses the running gateway instead of replacing it. A gateway left behind by a killed toto is stopped on the next start.
  - Behind an HTTP proxy, `upstream_proxy` passes `https_proxy`, `proxy_ca_bundle` and `proxy_connect_by_hostname` to the gateway, and keeps toto's own proxy reachable directly.
- **toto's credential proxy stays in the path** (ADR 12, ADR 14). It listens on a loopback TCP port, and only requests carrying a per-run 256-bit key get through. The sandbox policy allows that one endpoint, plus the project's approved egress rules, which OpenShell enforces per request. No provider credential is ever given to OpenShell.
- **Omnigent's own network sandbox is turned off.** bubblewrap cannot start in an OpenShell workload. The approved egress rules are enforced by OpenShell from outside instead.
- **One release of overlap.** `"sandbox": {"kind": "docker"}` keeps working for one release, with a deprecation warning from `toto doctor`, then it is removed together with `netfence`, the nested-userns seccomp profile and the Unix-socket relay. `toto init` writes `openshell`.
- **An escape hatch:** `"gateway": "<name>"` uses a gateway the contributor runs. toto then checks neither its version nor its images, and `toto doctor` says so.

## Consequences

- **Networked agents can run on every OS OpenShell supports.** Egress rules are enforced per request, not per host as the fence did. A networked agent must list its destinations; "any destination" is no longer offered.
- **More trusted code from NVIDIA.** The supervisor runs on the host network, terminates TLS for rule enforcement and parses the agent's HTTP. It runs unprivileged and read-only, and only ever sees toto's per-run key, never the provider credential.
- **Upgrades are toto's work.** OpenShell is young: its gateway config is at schema version 2 and keys have been renamed. Every bump goes through the lock, the live tests and a release.
- **Docker is still required** with the Docker driver, which is the default. The MicroVM driver (Hypervisor.framework or KVM) is installed with `--vm`. It is not yet wired up, because its disk caps need their own mechanism.
- **Prebuilds** of projects that publish no image still need the fenced Docker network, so they keep working only on the deprecated `docker` sandbox until they move into an OpenShell sandbox too.

## Not yet verified

- A run on macOS (Docker Desktop, then the MicroVM driver). This is the case that motivated the change.
- The pinned 0.1.5 release binaries. The spike and the live tests used OpenShell built from source at `main`. The 0.1.5 tag's source was checked for every CLI flag and config key toto uses.
- The release workflow itself, which first runs on the first tag. Release downloads were not reachable from the development environment, so the lock's archive checksums are still empty, and `pin-openshell.sh --check` fails the release until they are filled.

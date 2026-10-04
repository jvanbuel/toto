# Seccomp profiles

`seccomp-nested-userns.json` is Docker's default seccomp profile
(<https://github.com/moby/profiles/blob/main/seccomp/default.json>, Apache-2.0) plus six
syscalls that a nested bubblewrap needs: `clone` (without the namespace-flag filter), `unshare`,
`mount`, `umount2`, `pivot_root`, `sethostname`. Regenerate it with `scripts/make-seccomp-profile.py`.

It is **opt-in** (`"nested_userns": true` in the docker sandbox config). Everything else about the
container stays as hardened: all capabilities dropped, `no-new-privileges`, unprivileged user, no
network, read-only root. The added calls only succeed inside a user namespace that bwrap itself
creates (the container has no capability in its own namespace), but they make more kernel code
reachable from inside the container, which is the cost. gVisor cannot run a nested bwrap; hosts with
AppArmor's `docker-default` profile may also need an AppArmor adjustment (untested here).

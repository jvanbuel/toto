#!/usr/bin/env python3
"""Builds profiles/seccomp-nested-userns.json: Docker's default seccomp profile plus the few
syscalls a nested bubblewrap needs (so Omnigent's own sandbox can run inside a toto container).

Base: https://github.com/moby/profiles/blob/main/seccomp/default.json (Apache-2.0).
Usage: make-seccomp-profile.py <path to moby default.json> > profiles/seccomp-nested-userns.json

Added, unconditionally (Docker's default allows them only with CAP_SYS_ADMIN, or with an argument
filter that forbids namespace flags): clone (no flag filter), unshare, mount, umount2, pivot_root,
sethostname. The kernel still requires the matching capability, which the container does not have in
its own namespace; they only succeed inside a user namespace that bwrap itself creates. `clone3` stays
blocked (ENOSYS), as in Docker's default. The cost is more kernel code reachable from the container
(user namespaces), which is why this profile is opt-in.
"""
import json, sys

ADD = ["clone", "unshare", "mount", "umount2", "pivot_root", "sethostname"]

base = json.load(open(sys.argv[1]))
base["syscalls"].append({
    "names": ADD,
    "action": "SCMP_ACT_ALLOW",
    "comment": "toto: allow a nested bubblewrap (unprivileged user namespaces) inside the container",
})
json.dump(base, sys.stdout, indent="\t")
print()

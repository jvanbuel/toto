# Reproduces the Omnigent v0.16.0 sandbox checks in ADR 5. Needs Python 3.12, `pip install omnigent`, bwrap.
# Setup: mkdir -p /tmp/ot/home/.claude /tmp/ot/ws; put a fake secret in /tmp/ot/home/.claude/.credentials.json;
# /tmp/ot/stub-claude is `cat "$HOME/.claude/.credentials.json"`. Run with the venv python.
import os, subprocess, pathlib, sys
os.environ["HOME"] = "/tmp/ot/home"
os.chdir("/tmp/ot/ws")
from omnigent.inner.datamodel import OSEnvSpec, OSEnvSandboxSpec
from omnigent.inner import claude_sdk_executor as c
from omnigent.inner.sandbox import resolve_sandbox, get_backend

def spec(net):
    return OSEnvSpec(type="caller_process", cwd="/tmp/ot/ws",
                     sandbox=OSEnvSandboxSpec(type="linux_bwrap", allow_network=net))

for net in (True, False):
    p = c.prepare_claude_cli_path("/tmp/ot/stub-claude", spec(net))
    print(f"allow_network={net}: native_tools={p.enable_native_tools}, wrapped={p.cli_path != '/tmp/ot/stub-claude'}")
    out = subprocess.run([p.cli_path], capture_output=True, text=True, env={**os.environ})
    print("   stub CLI sees credentials:", "SECRET-TOKEN-123" in out.stdout, "|", (out.stdout + out.stderr).strip()[:100].replace("\n"," "))

# sys_os-style helper: a command wrapped by the backend with network denied
cwd = pathlib.Path("/tmp/ot/ws")
sb = resolve_sandbox(spec(False), cwd)
argv = get_backend(sb.backend_type).wrap_launcher_argv(
    ["/bin/sh", "-c", 'cat $HOME/.claude/.credentials.json /tmp/ot/home/.claude/.credentials.json 2>&1; echo net:; cat /proc/net/dev | tail -n +3 | cut -d: -f1'],
    sb, cwd, target="/bin/sh")
out = subprocess.run(argv, capture_output=True, text=True)
print("helper (net denied) sees credentials:", "SECRET-TOKEN-123" in out.stdout, "|", out.stdout.strip().replace("\n"," / ")[:200], out.stderr.strip()[:200])

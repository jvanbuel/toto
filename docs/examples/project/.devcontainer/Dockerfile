# The environment tasks run in: the harness, your tools, nothing else. Built by your developers'
# dev container tooling, and prebuilt and published by CI (.github/workflows/toto-image.yml:
# `toto project image --push`, which also runs onCreateCommand). You carry the safety burden of
# what is in here: tasks run it as an unprivileged user, read-only, offline except for the egress
# rules in your agent config, and the contributor's credential is never inside. See
# docs/project-owner-guide.md.
FROM python:3.12-slim

ENV PIP_ROOT_USER_ACTION=ignore PIP_NO_CACHE_DIR=1
# The agent harness. `claude-agent-sdk` bundles the Claude Code binary.
RUN pip install omnigent claude-agent-sdk

# Your tools: whatever the task needs.
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# No bubblewrap needed for egress rules: toto's sandbox (OpenShell) enforces them from outside.
# Your developers' own `omnigent run` with a linux_bwrap sandbox does need it locally.

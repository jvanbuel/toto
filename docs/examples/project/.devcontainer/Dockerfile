# The environment tasks run in: the harness, your tools, nothing else. Built by your developers'
# dev container tooling and by CI (.github/workflows/toto-image.yml: `devcontainer build --push`).
# You carry the safety burden of what is in here: tasks run it as an unprivileged user, read-only,
# offline unless your agent config asks for a network, and the contributor's credential is never
# inside. See docs/project-owner-guide.md.
FROM python:3.12-slim

ENV PIP_ROOT_USER_ACTION=ignore PIP_NO_CACHE_DIR=1
# The agent harness. `claude-agent-sdk` bundles the Claude Code binary.
RUN pip install omnigent claude-agent-sdk

# Your tools: whatever the task needs.
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Only if your agent config uses Omnigent's own sandbox (os_env.sandbox.type: linux_bwrap) for
# egress rules: bubblewrap, and the marker that lets it mount /proc inside a container.
# RUN apt-get update && apt-get install -y --no-install-recommends bubblewrap && rm -rf /var/lib/apt/lists/*
# RUN mkdir -p /run/lakebox

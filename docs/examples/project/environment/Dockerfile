# The environment tasks run in. Built and pushed by your CI (.github/workflows/toto-image.yml).
# You carry the safety burden of what is in here: tasks run it as an unprivileged user, read-only,
# with no network unless the contributor accepted your egress rules, and the contributor's
# credential is never inside. See docs/project-owner-guide.md.
FROM python:3.12-slim

ENV PIP_ROOT_USER_ACTION=ignore PIP_NO_CACHE_DIR=1
# The agent harness. `claude-agent-sdk` bundles the Claude Code binary.
RUN pip install omnigent claude-agent-sdk

# Your tools: whatever the task needs, nothing else.
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Optional, only if your tasks carry egress rules (Omnigent enforces them in a nested sandbox):
# RUN apt-get update && apt-get install -y --no-install-recommends bubblewrap && rm -rf /var/lib/apt/lists/*
# RUN mkdir -p /run/lakebox

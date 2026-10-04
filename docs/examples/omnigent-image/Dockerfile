# Reference image for the "Omnigent preinstalled in the project image" variant (ADR 12).
# Build: docker build -t toto-omnigent-test docs/examples/omnigent-image
# (behind a TLS-intercepting proxy, also COPY its CA bundle and set PIP_CERT/SSL_CERT_FILE.)
# `claude-agent-sdk` ships the Claude Code binary; the agent CLI therefore comes from the image,
# not from the contributor's own install.
FROM python:3.12-slim
ENV PIP_ROOT_USER_ACTION=ignore PIP_NO_CACHE_DIR=1
RUN pip install omnigent claude-agent-sdk
# Project layers add their own tools and MCP servers below, e.g.:
# RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

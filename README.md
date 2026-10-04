# togra

The local runner for **Tokens of Gratitude**: donate unused capacity from your own AI subscriptions or API keys to vetted public-good projects, without your credentials ever leaving your machine.

`togra` pulls signed tasks from a shared queue, runs them in a sandbox with your own AI tools, and returns signed results — within the caps and policies you set.

> *Togra* is Irish for "project, proposal, endeavour".

## Status

Early design plus a runner spike. See [docs/design.md](docs/design.md) for the full design doc.

Implemented so far (milestone 1, offline): manifest signing/verification, policy engine (caps, shares, quiet hours, sandbox limits), usage meter, result packaging and signing, audit log, and the task lifecycle against an in-memory queue. Docker/microVM sandbox, the Omnigent harness, the HTTP queue client and the TUI are stubbed behind traits.

```
cargo test
cargo run -- demo
```

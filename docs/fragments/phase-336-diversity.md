# Phase 336 – Security Hardening

- **Capabilities** – Drop privilege to UID/GID 65534 after opening the AF_PACKET socket.
- **Seccomp** – Load a seccomp profile (placeholder) that restricts syscalls.
- **Poll Timeout** – `OptPollTimeout(100ms)` to avoid a shutdown hang.
- **Metrics** – Optional Prometheus server started by `--metrics-addr`.
- **Panic Recovery** – `tap.Recover` called from the sensor goroutine.
- **Makefile** – `tap-build` target for the standalone binary.

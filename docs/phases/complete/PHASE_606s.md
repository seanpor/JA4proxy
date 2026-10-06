# Proxy Server Package Extraction (cmd/ja4pd -> internal/server)

## Goal
Extract the core unexported `proxy` struct and server loop from `cmd/ja4pd/main.go` (2,236 lines, `package main`) into a clean, reusable `internal/server` package. Establish modular component isolation so test suites (`606b`, `606c`, `606f`, `606g`) can test the server directly without reaching into `package main`.

---

## Read These First
- `cmd/ja4pd/main.go` (unexported `proxy` struct, `newProxy`, `serve`, `handleConn`, `forward`, `tarpit`, `reload`, `drain`)
- `cmd/ja4pd/lifecycle_test.go` (`newTestProxy`, `startEchoServer`)

---

## Verified API Surface
- `newProxy(cfg, cfgPath, log)` — `cmd/ja4pd/main.go:237`
- `(p *proxy) serve(ctx)` — `cmd/ja4pd/main.go:419`
- `(p *proxy) handleConn(ctx, conn)` — `cmd/ja4pd/main.go:537`
- `(p *proxy) reload()` — `cmd/ja4pd/main.go:1092`

---

## Refactoring Plan

1. **Create Package `internal/server`**:
   - Move `proxy` struct and exported constructor `New(cfg *config.Config, log *logrus.Logger) (*Server, error)`.
   - Export server methods: `Start()`, `Stop()`, `Reload()`, `ServeListener(l net.Listener)`.
2. **Update `cmd/ja4pd/main.go`**:
   - `main()` instantiates `server.New()` and calls `srv.Start()`.
   - `cmd/ja4pd/main.go` drops to $< 300$ lines.
3. **Update Test Harnesses**:
   - Update `cmd/ja4pd/lifecycle_test.go` and existing integration tests to consume `internal/server`.

---

## Test Commands

- **Run Server Unit Tests:**
  `GOROOT=/snap/go/current /snap/go/current/bin/go test -v ./internal/server`
- **Run Full Gate:**
  `make preflight`

---

## Acceptance Criteria

- [ ] `internal/server` created and exported clean API surface.
- [ ] `cmd/ja4pd/main.go` refactored to consume `internal/server`.
- [ ] All existing 30+ pentest and regression test suites in `cmd/ja4pd/` updated and passing.
- [ ] News fragment created in `docs/fragments/phase-606s-server-extraction.md`.
- [ ] `make preflight` passes 100% green with 0 regressions.

---

## Out of Scope
- Changing proxy forwarding or TLS reassembly logic.
- Modifying security pipeline behavior.

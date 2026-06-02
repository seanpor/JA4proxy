# Phase 125: Advanced Resilience & Runtime Monitoring

> **Status:** IN_PROGRESS
> **Size:** 3x SMALL SUB-PHASES
> **Depends on:** Phase 123, 124
> **Owner:** Gemini CLI

## Goal
Advanced hardening with procedural steps for automated testing and confinement.

---

### Phase 125a: Automated Testing (SMALL)

#### Execution Guide (125a)
1. **Fuzzing**:
   - File: `internal/tls/fuzz_test.go`.
   - Template:
     ```go
     func FuzzTLSParser(f *testing.F) {
         f.Add([]byte{...}) // Add valid ClientHello seeds
         f.Fuzz(func(t *testing.T, data []byte) {
             ParseClientHello(data)
         })
     }
     ```
   - Run: `go test -fuzz=FuzzTLSParser -fuzztime=1m`.
2. **CVE-2025-65637**:
   - Command: `go get github.com/sirupsen/logrus@v1.9.5`.
   - Verify: Check `go.sum` to ensure the version is pinned.

---

### Phase 125b: State & Metrics Integrity (SMALL)

#### Execution Guide (125b)
1. **Drift Worker**:
   - Create a background goroutine that polls Redis every 60 seconds.
   - It should calculate the hash of `config:dial` + `config:whitelist` and compare it to a "known good" hash stored in memory at startup.
2. **Cardinality**:
   - In the Prometheus collector, use a `map` with a fixed size limit (e.g., 1000) for dynamic labels like SNI. If the limit is reached, collapse all new SNIs into an `other` label.

---

### Phase 125c: Advanced Confinement (SMALL)

#### Execution Guide (125c)
1. **Seccomp**:
   - Use `strace -c ./proxy` during a load test to identify the minimum set of syscalls.
   - Update `config/seccomp/proxy.json` (or create it) with this allowlist.
2. **AppArmor**:
   - Create `/etc/apparmor.d/usr.bin.ja4proxy`.
   - Include `capability net_bind_service`, `deny network raw`, and limited `owner /var/log/ja4proxy/ rw`.
   - Test with `aa-complain` before `aa-enforce`.

# Phase 124: Production Security Remediation

> **Status:** IN_PROGRESS
> **Size:** 4x SMALL SUB-PHASES
> **Depends on:** Phase 123
> **Owner:** Gemini CLI

## Goal
Remediate specific audit findings with detailed technical guidance for a junior developer.

---

### Phase 124a: Protocol & JA4 Compliance (SMALL)

#### Execution Guide (124a)
1. **JA4 Alignment**:
   - File: `internal/ja4/ja4.go` (or similar).
   - Change: Ensure the ALPN list is *excluded* from the hash per FoxIO spec.
   - Change: Cap the count of extensions/ciphers at `99` in the string representation.
2. **TLS Version**:
   - File: `internal/tls/parser.go`.
   - Change: Do not rely on the `legacy_version` field (0x0303). Instead, parse the `supported_versions` extension to find the actual ClientHello version.
3. **Record Bounds**:
   - Add a check: `if recordLen > 16384 { return ErrRecordTooLarge }`.

---

### Phase 124b: TLS Fragmentation (SMALL)

#### Execution Guide (124b)
1. **Reassembly**:
   - Modify the `Read()` loop in the proxy to buffer bytes until the full handshake (indicated by the 3-byte length field in the TLS record) is received.
   - Use `io.ReadFull` to ensure you don't process a partial ClientHello.
2. **Testing**:
   - Create `cmd/proxy/pentest_fragmentation_regression_test.go`.
   - Use a `net.Conn` to send a ClientHello split into 100-byte chunks and verify the proxy still computes the correct JA4.

---

### Phase 124c: Control Plane Integrity (SMALL)

#### Execution Guide (124c)
1. **Signed Dial**:
   - When reading the `config:dial` key from Redis, also read a `config:dial:sig` key.
   - Verify: `hmac(dial_value, secret) == sig_value`.
   - Secret should be loaded via `ENVIRONMENT` variable or secret file.
2. **Mesh Safety**:
   - File: `cmd/syncagent/main.go`.
   - Add: `if cfg.IntegrityKeyFile == "" { log.Fatal("Integrity key required for sync mesh") }`.

---

### Phase 124d: Core Logic & Safety (SMALL)

#### Execution Guide (124d)
1. **Data Race**:
   - File: `internal/proxy/handler.go` (or where `handleConn` lives).
   - Code: Instead of accessing `p.cfg` directly inside goroutines, pass it as an argument: `go handleConn(conn, p.cfg)`.
2. **SNI Sanitization**:
   - Use `regexp.MustCompile("^[a-zA-Z0-9.-]+$")` to validate SNI strings before logging or using them in metrics.
3. **Webhook SSRF**:
   - In the webhook dispatcher, check the target IP.
   - Reject if `ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified()`.

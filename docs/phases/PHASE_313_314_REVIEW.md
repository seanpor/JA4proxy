# Expert Review & Implementation Blueprint: Phase 313 & Phase 314

This document consolidates the expert architectural and systems engineering reviews of **Phase 313 (Go Backup/Restore)** and **Phase 314 (Go TAP/SPAN Passive Sensor)**. It outlines the specific technical vulnerabilities identified in the current designs and provides concrete implementation blueprints (code patterns, configuration snippets, and CLI commands) to guide developers in implementing the fixes.

---

## 1. Phase 313: Redis Backup & Restore

### A. Cryptography & Key Management (PHASE_313a)

#### 1. Secure AES-256-GCM Nonce (IV) Generation
*   **Vulnerability:** The current draft specifies using AES-256-GCM but leaves the initialization vector (nonce) generation undefined. GCM mode requires a cryptographically secure, unique 12-byte nonce for every write. Nonce reuse breaks GCM confidentiality and integrity guarantees.
*   **Implementation Blueprint:**
    Implement the following encryption helper in Go (`internal/backup/crypto.go`):
    ```go
    package backup

    import (
        "crypto/aes"
        "crypto/cipher"
        "crypto/rand"
        "io"
    )

    func EncryptPayload(plaintext []byte, key []byte) ([]byte, error) {
        block, err := aes.NewCipher(key)
        if err != nil {
            return nil, err
        }
        aesgcm, err := cipher.NewGCM(block)
        if err != nil {
            return nil, err
        }
        // Nonce must be 12 bytes and cryptographically secure
        nonce := make([]byte, aesgcm.NonceSize())
        if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
            return nil, err
        }
        // Seal appends the ciphertext and 16-byte tag to the nonce (prefix)
        ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)
        return ciphertext, nil
    }

    func DecryptPayload(ciphertext []byte, key []byte) ([]byte, error) {
        block, err := aes.NewCipher(key)
        if err != nil {
            return nil, err
        }
        aesgcm, err := cipher.NewGCM(block)
        if err != nil {
            return nil, err
        }
        nonceSize := aesgcm.NonceSize()
        if len(ciphertext) < nonceSize {
            return nil, io.ErrUnexpectedEOF
        }
        // Extract the prefixed nonce and the actual ciphertext
        nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
        return aesgcm.Open(nil, nonce, actualCiphertext, nil)
    }
    ```

#### 2. Key Derivation from Passphrases
*   **Vulnerability:** Using a raw, variable-length passphrase directly as an AES key will cause runtime errors (AES-256 requires exactly 32 bytes).
*   **Implementation Blueprint:**
    Derive the 256-bit key using PBKDF2:
    ```go
    import (
        "crypto/sha256"
        "golang.org/x/crypto/pbkdf2"
    )

    func DeriveKey(passphrase string, salt []byte) []byte {
        // Use PBKDF2 with SHA-256 and 100,000 iterations to derive a 32-byte key
        return pbkdf2.Key([]byte(passphrase), salt, 100000, 32, sha256.New)
    }
    ```

#### 3. Support for Mounted Secrets
*   **Vulnerability:** Passing secrets via the `JA4PROXY_BACKUP_KEY` environment variable exposes the key in process environment lists (visible via `/proc/<pid>/environ`) and container configuration commands.
*   **Implementation Blueprint:**
    Add a command-line flag (`--key-file`) to read the key from a mounted file (e.g., Docker secrets at `/run/secrets/ja4proxy_backup_key`):
    ```yaml
    # docker-compose.poc.yml snippet
    services:
      backup-job:
        image: ja4proxy-backup:1.0.0
        secrets:
          - ja4proxy_backup_key
    secrets:
      ja4proxy_backup_key:
        file: ./config/secrets/backup_key.bin
    ```

---

### B. GDPR Compliance & Tombstone Persistence (PHASE_313b)

#### 1. Out-of-Redis Tombstone Storage
*   **Vulnerability:** Restoring a database using `FLUSHDB` and `RESTORE` wipes the Redis keyspace. If the list of GDPR-erased users is stored solely in Redis (e.g. `management:gdpr_erasure_log`), it will be destroyed before the check runs, resurrecting the erased PII.
*   **Implementation Blueprint:**
    The restore utility must read GDPR tombstones from an external file on the host filesystem (configured via `--tombstone-file`), which is updated by the management API during erase actions.
    ```go
    // In internal/backup/restore.go:
    type Tombstone struct {
        IP        string `json:"ip"`
        ErasedAt  string `json:"erased_at"`
    }

    func LoadTombstones(filePath string) (map[string]bool, error) {
        tombstones := make(map[string]bool)
        file, err := os.Open(filePath)
        if err != nil {
            if os.IsNotExist(err) {
                return tombstones, nil // No tombstones yet is valid
            }
            return nil, err
        }
        defer file.Close()

        var list []Tombstone
        if err := json.NewDecoder(file).Decode(&list); err != nil {
            return nil, err
        }
        for _, t := range list {
            tombstones[t.IP] = true
        }
        return tombstones, nil
    }
    ```

---

### C. Performance & Single-Thread Blocking (PHASE_313a / PHASE_313b)

#### 1. Pipelining and Pacing key DUMPs
*   **Vulnerability:** Running `SCAN`, `PTTL`, and `DUMP` sequentially per key causes head-of-line blocking on high-traffic Redis instances, blocking the proxy hot-path.
*   **Implementation Blueprint:**
    Execute key scans and dumps in batches using pipelining, and sleep briefly between batches:
    ```go
    func BackupKeyspace(ctx context.Context, rdb *redis.Client, batchSize int, delay time.Duration) ([]KeyBackup, error) {
        var cursor uint64
        var allBackups []KeyBackup

        for {
            keys, nextCursor, err := rdb.Scan(ctx, cursor, "*", int64(batchSize)).Result()
            if err != nil {
                return nil, err
            }
            cursor = nextCursor

            if len(keys) > 0 {
                // Pipeline PTTL and DUMP calls
                pipe := rdb.Pipeline()
                dumpCmds := make([]*redis.StringCmd, len(keys))
                ttlCmds := make([]*redis.DurationCmd, len(keys))

                for i, key := range keys {
                    ttlCmds[i] = pipe.PTTL(ctx, key)
                    dumpCmds[i] = pipe.Dump(ctx, key)
                }

                _, err = pipe.Exec(ctx)
                if err != nil && err != redis.Nil {
                    return nil, err
                }

                for i, key := range keys {
                    dumpVal, err := dumpCmds[i].Result()
                    if err != nil {
                        continue // Handle key deleted between SCAN and DUMP
                    }
                    ttlVal, _ := ttlCmds[i].Result()
                    
                    // Convert TTL to milliseconds for RESTORE command compatibility
                    var ttlMs int64
                    if ttlVal > 0 {
                        ttlMs = int64(ttlVal / time.Millisecond)
                    }

                    allBackups = append(allBackups, KeyBackup{
                        Key:      key,
                        Payload:  []byte(dumpVal),
                        TTLMs:    ttlMs,
                    })
                }
            }

            if cursor == 0 {
                break
            }
            // Sleep to yield Redis execution thread to incoming proxy traffic
            time.Sleep(delay)
        }
        return allBackups, nil
    }
    ```

#### 2. Throttling Restores
During restores, use similar rate-limited pipelines:
```go
func RestoreKeys(ctx context.Context, rdb *redis.Client, backups []KeyBackup, batchSize int, delay time.Duration) error {
    for i := 0; i < len(backups); i += batchSize {
        end := i + batchSize
        if end > len(backups) {
            end = len(backups)
        }

        pipe := rdb.Pipeline()
        for _, b := range backups[i:end] {
            // RESTORE key ttl_ms serialized_value [REPLACE]
            pipe.RestoreReplace(ctx, b.Key, time.Duration(b.TTLMs)*time.Millisecond, string(b.Payload))
        }
        
        _, err := pipe.Exec(ctx)
        if err != nil {
            return err
        }
        time.Sleep(delay)
    }
    return nil
}
```

---

## 2. Phase 314: TAP / SPAN Passive Sensor

### A. TCP Reassembly & Performance (PHASE_314a)

#### 1. Restricting Reassembly Depth
*   **Vulnerability:** Holding flow packets in memory indefinitely causes memory leaks and leaves the system vulnerable to SYN flood attacks.
*   **Implementation Blueprint:**
    Implement a byte-counter inside the stream handler to stop assembly once the TLS handshake boundary (16KB) is reached:
    ```go
    type TLSStream struct {
        bytesReceived int64
        handshakeDone bool
        // ...
    }

    func (s *TLSStream) Reassemble(data []byte) {
        if s.handshakeDone || s.bytesReceived > 16384 {
            // Already parsed or exceeded capture window; ignore further packets
            return
        }
        s.bytesReceived += int64(len(data))
        
        // Parse TLS ClientHello / ServerHello
        // If parsed successfully:
        // s.handshakeDone = true
        // s.Evict()
    }
    ```

#### 2. Memory Allocation Optimization
*   **Vulnerability:** At 10,000 pps, allocating new structures per packet will trigger high GC utilization.
*   **Implementation Blueprint:**
    Use `sync.Pool` to reuse slice buffers and packet trackers:
    ```go
    var bufferPool = sync.Pool{
        New: func() interface{} {
            b := make([]byte, 65536)
            return &b
        },
    }

    func processPacket(packetData []byte) {
        bufPtr := bufferPool.Get().(*[]byte)
        defer bufferPool.Put(bufPtr)
        
        // Copy data and process
        copy(*bufPtr, packetData)
    }
    ```

---

### B. Sandboxing & Privilege Model (PHASE_314a)

#### 1. Post-Socket Privilege Dropping
*   **Vulnerability:** The container needs `CAP_NET_RAW` to open a socket for sniffing, but keeping this capability indefinitely exposes the host if the container is compromised.
*   **Implementation Blueprint:**
    Open the socket, then drop capabilities and change UID/GID:
    ```go
    package main

    import (
        "log"
        "os"
        "syscall"
    )

    func dropPrivileges(targetUID, targetGID int) {
        // Drop filesystem privileges by changing UIDs/GIDs
        if err := syscall.Setregid(targetGID, targetGID); err != nil {
            log.Fatalf("Failed to drop GID: %v", err)
        }
        if err := syscall.Setreuid(targetUID, targetUID); err != nil {
            log.Fatalf("Failed to drop UID: %v", err)
        }
        
        // Confirm drop
        if os.Getuid() == 0 || os.Getgid() == 0 {
            log.Fatalf("Privilege drop failed: still running as root")
        }
    }
    ```

#### 2. Restrictive Redis User Configuration (ACL)
*   **Vulnerability:** If the sensor container has default Redis write access, a compromise would allow an attacker to modify proxy blocking rules or clear allowlists.
*   **Implementation Blueprint:**
    Apply the following Redis ACL user policy specifically for the sensor in `redis.conf` / `users.acl`:
    ```acl
    user tap_sensor on >my_secure_tap_sensor_password ~fp:os:ip:* ~fp:ip:* ~fp:conn:* +set +expire -@all
    ```
    This grants the sensor access *only* to write fingerprints and set TTL expirations, blocking all read operations.

---

### C. NAT & Middlebox Evasion (PHASE_314b)

#### 1. OS Classifier Normalization
*   **Operational Risk:** NAT gateways rewrite TTL and TCP Options, causing false OS-mismatch alerts when ClientHello and SYN headers diverge.
*   **Implementation Blueprint:**
    Implement Option set checking to label rewritten packets as `other/unknown`:
    ```go
    func ClassifyOS(ttl uint8, tcpOptions []byte) string {
        // Detect common proxy/middlebox Option patterns (e.g. F5 or AWS ALB normalization)
        if isNormalizedMiddlebox(tcpOptions) {
            return "other" // Prevents mismatch logic triggers downstream
        }
        
        // Standard classification
        if ttl == 64 {
            return "linux" // or macos
        } else if ttl == 128 {
            return "windows"
        }
        return "other"
    }
    ```

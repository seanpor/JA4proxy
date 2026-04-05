# Phase 35 — Security and Correctness Review

**Reviewer:** Critical Review Agent
**Date:** 2026-04-05
**Branch:** feat/phase-35-apt-integrity-ebpf
**Files reviewed:**
- `src/security/integrity_monitor.py`
- `scripts/config-signer.py`
- `scripts/redis-to-ebpf.py`
- `tests/unit/security/test_integrity_monitor.py`
- `tests/unit/test_config_signer.py`
- `tests/unit/security/test_ebpf_sync.py`

---

## CRITICAL Issues

### CRITICAL-1: Hash chain encoding mismatch between implementation and tests

**File:** `src/security/integrity_monitor.py` (lines 305–315) vs `tests/unit/security/test_integrity_monitor.py` (lines 279–283, 302–305)

**Problem:**

The implementation hashes the raw bytes of the previous log line **including the trailing `\n`**:

```python
# integrity_monitor.py, _read_last_line_hash
lines = fh.read().splitlines(keepends=True)   # keepends=True → bytes include \n
last_line = lines[-1]
return hashlib.sha256(last_line).hexdigest()  # hashes bytes WITH \n
```

The tests compute the expected hash by reading the file as text, stripping it, then encoding:

```python
# test_integrity_monitor.py, lines 278–280
lines = log_path.read_text().strip().splitlines()  # strips, no \n on lines
first_raw = lines[0]
expected_prev_hash = hashlib.sha256(first_raw.encode()).hexdigest()  # hashes WITHOUT \n
```

`"line content\n".encode()` and `"line content".encode()` produce different SHA-256
digests. Every hash-chain test will fail because they test different things.

**Fix required:** Choose one representation and apply it consistently:

- **Option A (recommended):** Implementation hashes the line WITHOUT the newline.
  Change `_read_last_line_hash` to strip the newline before hashing:
  ```python
  return hashlib.sha256(last_line.rstrip(b"\n")).hexdigest()
  ```

- **Option B:** Tests hash with newline:
  ```python
  expected_prev_hash = hashlib.sha256((first_raw + "\n").encode()).hexdigest()
  ```

The docstring on `append_audit_log` (line 191) says "SHA-256 hex of the raw bytes of
the previous entry" — this is ambiguous. Pick one and document it precisely:
"SHA-256 of the previous line's bytes including the terminating newline" or
"SHA-256 of the previous line's bytes excluding the terminating newline."


### CRITICAL-2: Constructor signature mismatch — tests will all fail

**File:** `tests/unit/security/test_integrity_monitor.py` (lines 79, 97, 121, 143, 165, 180, 196, 218, 228, 249, 262, 274, 290, 315, 348, 379, 424, 457, 485, 524)

**Problem:**

Every test constructs `IntegrityMonitor()` with no arguments:
```python
monitor = IntegrityMonitor()
```

The implementation requires a `config` argument:
```python
def __init__(self, config: Dict) -> None:
```

Every single test in `test_integrity_monitor.py` will fail with a `TypeError` before
any assertion is reached.

**Fix required (choose one):**

- Make `config` optional with a default: `def __init__(self, config: Dict = None) -> None:`
- Or update all tests to pass `IntegrityMonitor({})`.

The first option is better for real usage where the monitor is constructed without
config for simple integrity checks.


### CRITICAL-3: CLI flag mismatch — all `test_config_signer.py` tests will fail

**File:** `tests/unit/test_config_signer.py` (lines 85, 100, 117, 136, 147, 166, 178, 190, 213, 231) vs `scripts/config-signer.py` (line 201)

**Problem:**

Every test passes `--key` to the CLI:
```python
_run_signer("sign", str(config_file), "--key", str(privkey_path))
```

The CLI defines `--privkey` (not `--key`):
```python
parser.add_argument("--privkey", type=Path, default=DEFAULT_PRIVKEY, ...)
```

Every sign test will fail with `argparse` error 2 (unrecognized argument).

**Fix required:** Either:
- Add `--key` as an alias in the CLI: `parser.add_argument("--key", "--privkey", ...)`
- Or update all tests to use `--privkey`.

The CLI also expects `--pubkey` for verify, and tests use `--pubkey` correctly for
`verify` — but the `sign` subcommand uses `--key` in tests and `--privkey` in the CLI.
This is a single consistent rename needed.


### CRITICAL-4: Key format incompatibility — integration test will fail

**File:** `tests/unit/test_config_signer.py` (lines 37–57) vs `src/security/integrity_monitor.py` (lines 332–364)

**Problem:**

The integration test `test_signed_file_verifiable_by_integrity_monitor` writes keys in
PEM/PKCS8 format:
```python
privkey_path.write_bytes(privkey.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
))
pubkey_path.write_bytes(pubkey.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
))
```

But `config-signer.py` (`_load_private_key`, line 109) expects a base64-encoded raw
32-byte key, not PEM/PKCS8. When the test passes the PEM private key path to
`config-signer.py`, `_load_private_key` will try to `base64.b64decode` the PEM blob,
get something other than 32 bytes, and call `sys.exit(1)`.

Additionally, the `sign` subcommand reads the signature from `config-signer.py` which
writes base64-encoded signatures, but `_sign_file` in the test helper writes **raw
bytes** to the sig file. So `test_signed_file_verifiable_by_integrity_monitor` will
sign with config-signer (producing base64 sig), then `IntegrityMonitor` will try to
`base64.b64decode` it — which will work correctly in that direction. But the round-trip
through config-signer fails before that because the PEM key is the wrong format.

**Fix required:** Either:
- The `_generate_keypair_files` helper in `test_config_signer.py` must write the same
  base64-of-raw-32-byte format that `config-signer.py` actually produces.
- Or change `config-signer.py` to accept PEM keys.

The simplest fix: use `_run_signer("genkey", "--out", str(tmp_path))` in the test
(once genkey is implemented) so the test always uses the format the tool produces.


### CRITICAL-5: `test_sig_file_is_valid_ed25519_signature` checks wrong thing

**File:** `tests/unit/test_config_signer.py` (lines 94–106)

**Problem:**

The test checks that the `.sig` file is exactly 64 bytes:
```python
sig_bytes = sig_file.read_bytes()
assert len(sig_bytes) == 64
```

But `config-signer.py` writes the signature as **base64-encoded** bytes plus a newline
(line 154: `sig_path.write_bytes(base64.b64encode(signature) + b"\n")`).
A 64-byte Ed25519 signature base64-encodes to 88 bytes plus `\n` = 89 bytes total.

The test will always fail because it expects 64 bytes but gets 89 bytes.

**Fix required:** The test should check the *decoded* bytes are 64 bytes:
```python
import base64
sig_bytes = base64.b64decode(sig_file.read_bytes().strip())
assert len(sig_bytes) == 64
```

---

## HIGH Severity Issues

### HIGH-1: `verify_on_startup` default not enforced in code

**File:** `src/security/integrity_monitor.py` — not present

**Problem:**

The spec and CLAUDE.md both say `verify_on_startup: false` must be the default (fail
open on first deploy). The `verify_config_signature` method exists but there is no
config path through `ProxyServer.__init__` that calls it. There is no config key check
like `if self._integrity_cfg.get("verify_on_startup", False):`. The spec requirement
that the proxy exits 1 if the signature is invalid on startup is unimplemented.

Additionally, `config/proxy.yml` should document the `integrity` section with this
default, per the cross-cutting config-driven requirement in CLAUDE.md.

**Fix required:**
1. Add startup verification logic gated by `verify_on_startup: false` default.
2. Document the `integrity:` block in `config/proxy.yml`.


### HIGH-2: Background monitor doesn't expose `violation_counter` attribute

**File:** `src/security/integrity_monitor.py` (class `IntegrityMonitor`) vs `tests/unit/security/test_integrity_monitor.py` (lines 393, 433, 467, etc.)

**Problem:**

Tests access `monitor.violation_counter`:
```python
violation_counter = monitor.violation_counter
before = violation_counter._value.get()
```

The implementation exposes `INTEGRITY_VIOLATIONS` as a module-level counter, not as an
instance attribute. `IntegrityMonitor` has no `violation_counter` attribute. Tests will
fail with `AttributeError`.

**Fix required:** Add `self.violation_counter = INTEGRITY_VIOLATIONS` in `__init__`, or
restructure so the counter is an instance attribute. The latter is cleaner for testing.


### HIGH-3: No deletion of stale entries triggers Prometheus `INTEGRITY_VIOLATIONS`

**File:** `src/security/integrity_monitor.py` (lines 297–302)

**Problem:**

When a file is deleted from the monitored tree, the code increments
`INTEGRITY_VIOLATIONS` but the label used will be the path of the deleted file.
This means `_compare_and_alert` may call `.labels(path=path).inc()` for both modified
files AND deleted files. The Prometheus counter has a `path` label — monitoring
environments with high file churn will create unbounded cardinality in this counter.

The spec says the metric is `ja4proxy_integrity_violation_total` with label `path`.
Unbounded label cardinality will crash Prometheus.

**Fix required:** Either:
- Remove the `path` label from the counter and use a reason label instead.
- Limit the `path` label to a fixed set of critical paths (config, main binary).
- Use a Gauge with path info only in log messages, not as a label.


### HIGH-4: Audit log can be truncated — hash chain bypass

**File:** `src/security/integrity_monitor.py` (lines 181–212)

**Problem:**

The log is opened with `open(log_path, "a")` which is correct for appending.
However, on Linux, any process with write permission to the log directory can:
1. Truncate the file to zero: `truncate --size=0 /var/log/ja4proxy/integrity.log`
2. Replace the file entirely: `mv evil.log /var/log/ja4proxy/integrity.log`

The hash chain only detects *in-flight* tampering of existing lines. It cannot detect
truncation because after truncation, the new first entry has `prev_hash = ""` — which
is indistinguishable from the legitimate first entry.

This is a design limitation worth documenting explicitly.

**Fix required:** Document in the class docstring and in the audit log spec that the
hash chain detects line-level tampering but cannot detect truncation. If truncation
resistance is needed, write the log to a filesystem with append-only attributes (Linux
`chattr +a`) or ship logs to a remote syslog/SIEM in real time.

This should be noted as a known limitation rather than treated as a blocking bug, since
full append-only resistance requires OS-level controls outside the code's scope.


### HIGH-5: `PermissionError` not handled in `_bpftool_update` / `_bpftool_delete`

**File:** `scripts/redis-to-ebpf.py` (lines 97–142, 145–161)

**Problem:**

`_bpftool_update` catches `FileNotFoundError`, `CalledProcessError`, and
`TimeoutExpired`, but not `PermissionError`. When running without `CAP_BPF`, the
kernel returns EPERM, which Python's subprocess surfaces as `PermissionError` (not
`CalledProcessError`). The test `test_bpftool_permission_error_does_not_raise`
explicitly tests this scenario.

A `PermissionError` from `subprocess.run` will propagate uncaught, escape
`_bpftool_update`, and bubble up through `_sync_loop` to be caught by the broad
`except Exception` at line 309 — but this increments `EBPF_SYNC_ERRORS` and logs an
error on every 5-second poll cycle forever, flooding logs and metrics.

**Fix required:** Add `PermissionError` to the caught exceptions in both
`_bpftool_update` and `_bpftool_delete`. The first occurrence should log a WARNING with
`effect=eBPF sync disabled` and subsequent occurrences should be suppressed (e.g., use
a `_bpftool_available` flag that disables further calls after first permanent failure).


### HIGH-6: `_collect_blocked_ips` uses async Redis but tests use sync mock

**File:** `scripts/redis-to-ebpf.py` (line 223) vs `tests/unit/security/test_ebpf_sync.py` (line 43)

**Problem:**

`_collect_blocked_ips` is an `async` function using `aioredis` with `scan_iter` (async
iterator). The test mocks use synchronous `MagicMock` objects with `.smembers()` and
`.keys()`. The tests check `mock_redis.smembers.assert_called_with("ja4:blacklist")`
— but the implementation **does not call `.smembers("ja4:blacklist")`** at all. It
calls `scan_iter("ban:*")` and `.smembers("ip:blacklist")`.

This means:
1. Tests that assert `mock_redis.smembers.assert_called_with("ja4:blacklist")` will
   fail because the implementation calls `smembers("ip:blacklist")`, not `"ja4:blacklist"`.
2. Tests that assert `mock_redis.keys.assert_called_with("ban:*")` will fail because
   the implementation uses `scan_iter`, not `keys`.

The tests are testing an interface that doesn't exist in the implementation.

**Fix required:** Either:
- Update the implementation to use `smembers("ja4:blacklist")` and `keys("ban:*")` to
  match what the tests expect (and the Redis schema documented in CLAUDE.md).
- Or update the tests to mock `scan_iter` and `smembers("ip:blacklist")` correctly.

Note: The Redis schema in CLAUDE.md says the blacklist is `ja4:blacklist` (a SET of JA4
fingerprints, not IPs). The implementation correctly notes this in a comment (line
217–218) and skips it. But there is no `ip:blacklist` key in the documented schema —
this is an undocumented key that the implementation invents. The sync service should
only read `ban:{ip}` keys per the documented schema.

---

## MEDIUM Severity Issues

### MEDIUM-1: Private key created insecurely (TOCTOU window)

**File:** `scripts/config-signer.py` (lines 102–105)

**Problem:**

`_write_key` writes the key file and then calls `os.chmod`:
```python
path.write_bytes(data + b"\n")   # File created with umask-default permissions
os.chmod(path, mode)              # Then restricted — brief window of exposure
```

Between `write_bytes` and `chmod`, the private key exists on disk with default
permissions (typically 0o644), readable by all users on the system.

**Fix required:** Write the file atomically with correct permissions using `os.open`:
```python
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
try:
    os.write(fd, data + b"\n")
finally:
    os.close(fd)
```

This creates the file with `mode` permissions atomically, with no window.


### MEDIUM-2: `genkey` does not protect against existing key overwrite in odd conditions

**File:** `scripts/config-signer.py` (lines 241–248)

**Problem:**

The `genkey` check is:
```python
if args.privkey.exists() or args.pubkey.exists():
    print("Keys already exist ... Delete them first to regenerate.")
    sys.exit(0)
_generate_keypair(args.privkey, args.pubkey)
```

There is a TOCTOU race between the existence check and `_generate_keypair` writing the
files. If another process creates `args.privkey` after the check but before the write,
`_write_key` will overwrite it. `path.write_bytes()` is not atomic and does not set the
O_EXCL flag.

This is low-probability but means `genkey` could silently overwrite a key created by a
parallel process.

**Fix required:** Use `O_CREAT | O_EXCL` in `_write_key` and catch `FileExistsError`.


### MEDIUM-3: `_compare_and_alert` mutates the baseline dict passed to it

**File:** `src/security/integrity_monitor.py` (lines 265–302)

**Problem:**

When a new file is detected (not in the baseline), `_compare_and_alert` mutates the
`baseline` dict directly:
```python
baseline[path] = digest
```

This is `self._baseline` being passed by reference. Silently mutating the baseline
means new files are treated as "known good" after the first scan — which is probably
the intended behavior, but it is undocumented and could lead to confusion. More
importantly, the deleted file handling at lines 297–302 checks `if path not in current`
but does NOT remove the path from `baseline`, so a deleted file will trigger
`INTEGRITY_VIOLATIONS` on every subsequent scan cycle, flooding alerts.

**Fix required:** When a file is deleted and reported, remove it from `baseline`:
```python
for path in list(baseline.keys()):
    if path not in current:
        INTEGRITY_VIOLATIONS.labels(path=path).inc()
        logger.error("integrity | event=file_deleted | path=%s", path)
        del baseline[path]   # ADD THIS LINE — stop alerting on every cycle
```


### MEDIUM-4: `config-signer.py` `keygen` subcommand not implemented

**File:** `scripts/config-signer.py` (the `genkey` subcommand exists, but tests expect `keygen`)

**Problem:**

`test_config_signer.py` tests `keygen --out <dir>` (line 271: `_run_signer("keygen",
"--out", str(tmp_path))`). The CLI implements `genkey`, not `keygen`. The test
gracefully handles both outcomes (returncode 0 or non-zero) but the test description
says "keygen subcommand" which doesn't match.

More importantly, `keygen` takes `--out <dir>` but `genkey` takes `--privkey` and
`--pubkey` as global flags with defaults. These have incompatible interfaces.

**Fix required:** Decide on one subcommand name (`genkey` is in the implementation,
`keygen` is in the test). Document the chosen interface and make both consistent.


### MEDIUM-5: IPv6 not handled in eBPF sync — not documented as known limitation

**File:** `scripts/redis-to-ebpf.py` (lines 85–94)

**Problem:**

`_ip_to_hex` returns `None` for IPv6 addresses (line 93: `return None`), which causes
the IP to be silently skipped in `_sync_loop`. IPv6 bans in Redis (`ban:2001:db8::1`)
will never be populated into the BPF map, providing no kernel-level enforcement for
IPv6-banned hosts.

The spec (PHASE_35.md) says IPv6 requires a separate map — this is correct — but the
code's behavior (silent skip) is not documented in either the docstring or a log
message. An operator who bans an IPv6 address will see no effect from the eBPF layer
with no indication why.

**Fix required:** When `_ip_to_hex` returns None, log at DEBUG:
```python
logger.debug("ebpf | event=ipv6_skip | ip=%s | effect=XDP map only supports IPv4", ip)
```

Also add a startup WARNING if any IPv6 addresses are in the blocked set.

Document in the module docstring that IPv6 is not currently enforced at the XDP layer.


### MEDIUM-6: Prometheus counter cardinality risk in `_read_drop_counters`

**File:** `scripts/redis-to-ebpf.py` (lines 164–202)

**Problem:**

`_read_drop_counters` reads from a BPF per-CPU array map and updates `EBPF_DROPS`.
The counter uses delta tracking (`delta = max(0, total - prev)`). However, if the BPF
map is reset (e.g., after XDP program reload), `total` will be less than `prev`,
causing `delta = 0` — the reset is silently ignored and previous drop counts are never
re-reported. This is correct behavior (avoid double-counting) but should be documented.

Also: the BPF map format assumed (`key_raw[0]` as reason index, `value` as list of
per-CPU counts) is brittle and tied to a specific `ja4block.c` map layout. If the C
program changes its map layout, the counter reader breaks silently.

**Fix required:** Add a comment documenting the BPF map layout dependency and the
reset behavior. Consider logging when `total < prev` (unexpected reset).

---

## LOW Severity Issues

### LOW-1: `_hash_paths` hashes `__pycache__` and `.pyc` files

**File:** `src/security/integrity_monitor.py` (lines 229–261)

**Problem:**

When monitoring `src/` (a directory), `_hash_paths` recursively hashes all files
including `__pycache__/*.pyc` files. Python regenerates `.pyc` files automatically
during normal operation. This means the monitor will fire `INTEGRITY_VIOLATIONS` for
normal Python bytecode recompilation, creating false positives.

**Fix required:** Skip non-source files:
```python
for child in sorted(p.rglob("*")):
    if child.is_file() and child.suffix not in (".pyc", ".pyo"):
        if "__pycache__" not in child.parts:
            ...
```


### LOW-2: `verify_config_signature` fail-open on import error is documented but risky

**File:** `src/security/integrity_monitor.py` (lines 73–84)

**Problem:**

The docstring explicitly documents that the function returns `True` when `cryptography`
is not installed ("fail-open with a WARNING"). This is the correct architecture decision
for a library that should not be a hard dependency. However:

1. The WARNING log format does not match the system standard from CLAUDE.md, which
   requires `WARN | policy | event=... | effect=...` format.
2. There is no Prometheus counter for this event, so it is invisible to monitoring.

**Fix required:**
- Use the standard log format: `WARN | integrity | event=cryptography_missing | effect=signature_verification_skipped`
- Increment a counter: `ja4proxy_integrity_skip_total{reason="cryptography_missing"}`


### LOW-3: `config-signer.py` genkey prints `f"Generated keypair:"` (plain print, not logger)

**File:** `scripts/config-signer.py` (lines 97–99)

**Problem:**

The script uses `print()` for all output rather than the structured log format. This is
a CLI tool (not a daemon), so print is acceptable for user-facing output. However, the
success/failure messages are inconsistent — `sign` prints `f"Signed {target} -> {sig_path}"`
but verify prints `f"OK: {target} — signature valid"`. No common format.

**Fix required:** Minor — standardize the output format. Not a blocker.


### LOW-4: No test for `shutdown_on_violation` behavior

**File:** `src/security/integrity_monitor.py` (lines 288–294) — `_compare_and_alert`

**Problem:**

The `shutdown_on_violation` config option calls `sys.exit(1)`. There is no test that
verifies this behavior. It is also dangerous in tests — if any test triggers this code
path, it will kill the entire test runner process.

**Fix required:** Add a test that patches `sys.exit` and verifies it is called when
`shutdown_on_violation: true` and a violation is detected.


### LOW-5: `test_ebpf_sync.py` tests will all skip silently

**File:** `tests/unit/security/test_ebpf_sync.py` (lines 69–98, 106–131, etc.)

**Problem:**

Every test in `test_ebpf_sync.py` begins with:
```python
try:
    mod = _import_redis_to_ebpf()
except Exception as exc:
    pytest.skip(f"redis-to-ebpf.py not yet implemented: {exc}")
```

After the script can be imported, the tests then check for `sync_once`, `EbpfSyncer`,
or `RedisToEbpf` attributes that don't exist in the implementation. When none are
found, the tests call `pytest.skip()` — so every test that *can* import the module will
then skip anyway.

The implementation provides `_sync_loop` (a module-level async function) and
`_bpftool_update`/`_bpftool_delete` (module-level functions) — but none of the public
names the tests probe for (`sync_once`, `EbpfSyncer`, `RedisToEbpf`). The entire test
class `TestDeduplication` will always skip.

**Fix required:** Either:
- Expose a public API (`EbpfSyncer` class or `sync_once` function) in the
  implementation that the tests can use.
- Or rewrite tests to test the actual module-level functions `_ip_to_hex`,
  `_bpftool_update`, `_collect_blocked_ips`, `_sync_loop` directly.

The test file header comment says "The implementation does NOT exist yet" — this is
stale. The implementation *does* exist but has a different API than the tests expect.


### LOW-6: `test_ebpf_sync.py` Redis mock uses synchronous interface for async client

**File:** `tests/unit/security/test_ebpf_sync.py` (lines 42–52)

**Problem:**

`_make_mock_redis` returns a synchronous `MagicMock`. The implementation uses
`redis.asyncio` (`aioredis`) with async iteration (`async for key in redis_client.scan_iter`).
Patching the actual `aioredis` client with a sync mock will cause coroutine await
errors when the async `_collect_blocked_ips` tries to use `async for` on a sync mock.

**Fix required:** Use `AsyncMock` and mock `scan_iter` as an async generator:
```python
async def _mock_scan_iter(pattern):
    for key in ban_keys:
        yield key.encode()
r.scan_iter = _mock_scan_iter
r.smembers = AsyncMock(return_value=blacklist_ips)
```

---

## Spec Compliance Gaps

### SPEC-1: `verify_on_startup: false` not implemented anywhere

The spec (PHASE_35.md) requires that startup verification is integrated into
`ProxyServer.__init__`. No such integration exists. The `IntegrityMonitor` class is
standalone and not wired into the proxy startup sequence. This is the primary Phase 35a
deliverable and it is not done.

### SPEC-2: `config/geoip.mmdb.sig` not supported by config-signer

The spec says: "Sign `config/proxy.yml` and GeoIP databases." The `config-signer.py`
can sign any arbitrary file (the `sign` command takes any `FILE`), so technically it
can sign `.mmdb` files. However, there is no documentation or example for signing GeoIP
databases, no test that covers `.mmdb` signing, and no startup verification for the
GeoIP database.

### SPEC-3: eBPF/XDP C program (`ebpf/ja4block.c`) not written

The spec requires a C XDP program. This is not present. The sync service
(`redis-to-ebpf.py`) assumes it exists. Without `ja4block.c`, the entire eBPF layer
is inert. This may be intentional (C program is a separate deliverable), but it should
be noted.

### SPEC-4: No Grafana panel or Alertmanager rule (35c)

Phase 35c deliverables (Grafana panel, Alertmanager rule) are not present. These may
be deferred but should be tracked.

---

## Summary Table

| ID | Severity | File | Issue |
|----|----------|------|-------|
| CRITICAL-1 | Critical | `integrity_monitor.py` + test | Hash chain encoding mismatch (with vs without `\n`) |
| CRITICAL-2 | Critical | test | `IntegrityMonitor()` takes 0 args in tests, 1 in impl |
| CRITICAL-3 | Critical | test | `--key` flag in tests, `--privkey` in CLI |
| CRITICAL-4 | Critical | test | PEM key format in tests, base64-raw in `config-signer.py` |
| CRITICAL-5 | Critical | test | Sig file size check: 64 bytes expected, 89 actually written |
| HIGH-1 | High | impl | `verify_on_startup: false` default not implemented |
| HIGH-2 | High | test | `monitor.violation_counter` attribute does not exist |
| HIGH-3 | High | impl | Unbounded Prometheus cardinality from `path` label |
| HIGH-4 | High | impl | Hash chain cannot detect log truncation (document) |
| HIGH-5 | High | impl | `PermissionError` not caught in `_bpftool_update` |
| HIGH-6 | High | test | Tests use sync mock for async Redis client |
| MEDIUM-1 | Medium | impl | TOCTOU on private key file permissions |
| MEDIUM-2 | Medium | impl | TOCTOU on genkey existence check |
| MEDIUM-3 | Medium | impl | Deleted files alert on every cycle (missing `del baseline[path]`) |
| MEDIUM-4 | Medium | test+impl | `keygen` vs `genkey` subcommand name mismatch |
| MEDIUM-5 | Medium | impl | IPv6 skip not logged or documented |
| MEDIUM-6 | Medium | impl | BPF counter reset behavior silent |
| LOW-1 | Low | impl | `__pycache__` hashing causes false positives |
| LOW-2 | Low | impl | Log format for cryptography_missing doesn't match standard |
| LOW-3 | Low | impl | CLI output format inconsistent |
| LOW-4 | Low | test | No test for `shutdown_on_violation` behavior |
| LOW-5 | Low | test | All `test_ebpf_sync.py` tests will skip (no public API) |
| LOW-6 | Low | test | Sync Redis mock for async client |

---

## Priority Fix Order

1. **CRITICAL-2** — `IntegrityMonitor(config)` constructor mismatch. Nothing runs until this is fixed.
2. **CRITICAL-3** — `--key` vs `--privkey`. All sign tests fail.
3. **CRITICAL-1** — Hash chain encoding. Hash chain tests fail even if constructors are fixed.
4. **CRITICAL-5** — Sig size check. Test checks raw bytes but impl writes base64.
5. **CRITICAL-4** — Key format mismatch in integration test.
6. **HIGH-2** — `violation_counter` attribute missing.
7. **HIGH-5** — `PermissionError` in bpftool.
8. **HIGH-6 / LOW-6** — Async Redis mock.
9. **LOW-5** — Expose public API for ebpf sync tests.
10. **MEDIUM-3** — Deleted files alert flooding.
11. **MEDIUM-1** — TOCTOU on private key write.

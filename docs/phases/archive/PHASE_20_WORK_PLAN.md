# Phase 20 TDD Work Plan: Passive TAP/SPAN Mode + Phase 19 Gap Remediation

> **Purpose:** Actionable, ordered implementation guide. Read `PHASE_20.md` for
> architecture rationale and acceptance criteria. This file tells you *what to build,
> in what order, and how to test it*.
>
> **Rule:** Write the test first. Each group lists tests before implementation notes.
> Do not start Group N+1 until all tests in Group N are green.

---

## Dependency Order

```
Group 0 (Phase 19 gaps)  ← independent, do first
Group 1 (infra / mode switch)
Group 2 (TAP HTTP server)
Group 3 (packet capture)
Group 4 (TCP reassembler)
Group 5 (fingerprint extractors — all parallel-safe)
Group 6 (TAP pipeline + risk scoring)
Group 7 (fingerprint store)
Group 8 (enforcement bridge)
Group 9 (intelligence export)
Group 10 (lifecycle management)
Group 11 (observability)
Group 12 (security hardening)
Group 13 (test infrastructure — PCAP corpus + SyntheticPacketBuilder)
Group 14 (config files + scripts)
Group 15 (documentation)
```

---

## Group 0: Phase 19 Gap Remediation

**Files to modify:** `src/backup/backup_manager.py`
**Files to create:** `tests/unit/test_backup_scheduler.py`,
  `tests/unit/test_backup_pipeline_batching.py`,
  `tests/unit/test_backup_restore_error.py`,
  `tests/integration/test_backup_roundtrip.py`

These gaps are independent of TAP mode. Implement and green all tests before Group 1.

### G0-A: Backup schedule executor (P19-G1)

Add to `BackupManager`:
```python
async def start_scheduler(self) -> None: ...
async def stop_scheduler(self) -> None: ...
async def _interval_loop(self, interval_s: int) -> None: ...
async def _cron_loop(self, cron_expr: str) -> None: ...
```

Config additions (`config/proxy.yml`):
```yaml
backup:
  schedule:
    enabled: false
    interval_s: 86400   # or use cron below
    cron: null          # e.g. "0 2 * * *"
```

Tests in `tests/unit/test_backup_scheduler.py`:
```python
async def test_scheduler_starts_when_enabled()
async def test_scheduler_does_not_start_when_disabled()
async def test_scheduler_fires_backup_after_interval()
async def test_scheduler_logs_warn_on_backup_failure_not_raise()
async def test_stop_scheduler_cancels_task_cleanly()
async def test_scheduler_fires_immediately_after_first_interval()
```

### G0-B: Pipeline batching in backup loop (P19-G3)

Add to `BackupManager`:
```python
PIPELINE_BATCH_SIZE = 1000

async def _dump_keys_batched(
    self, keys: list[str]
) -> dict[str, bytes | None]: ...
```

Modify `run_backup()` to call `_dump_keys_batched()` instead of individual `redis.dump()`.

Tests in `tests/unit/test_backup_pipeline_batching.py`:
```python
def test_1001_keys_split_into_2_batches()
async def test_pipeline_called_once_per_batch_not_once_per_key()
async def test_expired_key_mid_backup_returns_none_not_exception()
async def test_pipeline_error_on_one_key_does_not_abort_batch()
```

### G0-C: RestoreError on key-failure threshold (P19-G4)

Add to `src/backup/backup_manager.py`:
```python
class RestoreError(Exception):
    def __init__(self, failed: int, total: int, threshold: float) -> None: ...
```

Modify `restore()` to:
1. Count keys that fail to restore (exception from `redis.restore()`)
2. Raise `RestoreError` if `failed / total > threshold` (default 0.05)
3. Always log `event=restore_complete | total={n} | restored={n} | failed={n}`

Config addition:
```yaml
backup:
  restore_error_threshold: 0.05   # raise RestoreError if >5% of keys fail
```

Tests in `tests/unit/test_backup_restore_error.py`:
```python
async def test_restore_raises_restore_error_when_failures_exceed_threshold()
async def test_restore_succeeds_when_failures_at_threshold()
async def test_restore_succeeds_when_no_failures()
async def test_restore_error_message_contains_failed_and_total_counts()
async def test_restore_threshold_zero_means_any_failure_raises()
async def test_restore_logs_final_counts_even_on_success()
```

### G0-D: Fakeredis encode→backup→restore round-trip (P19-G6)

Tests in `tests/integration/test_backup_roundtrip.py`:
```python
async def test_roundtrip_string_key_with_ttl()
async def test_roundtrip_set_key()
async def test_roundtrip_hash_key()
async def test_roundtrip_sorted_set_key()
async def test_roundtrip_all_proxy_key_types()
async def test_backup_file_is_deterministic()
async def test_restore_preserves_ttl_within_2s()
async def test_restore_into_nonempty_db_overwrites_existing_keys()
```

---

## Group 1: Infrastructure & Mode Switching

**Files to create:** `src/tap/__init__.py`, `src/tap/tap_sensor.py`
**Files to modify:** `proxy.py`, `src/config/loader.py`

### G1-A: `src/tap/__init__.py`

Empty. Makes `src/tap` a package.

### G1-B: `src/tap/tap_sensor.py` — TapSensor class

```python
class TapSensor:
    """Top-level orchestrator for TAP mode.

    Instantiated by proxy.py when mode=tap. Owns and starts:
    - PacketCapture (or PcapReplay)
    - StreamWorker × N
    - WorkerWatchdog
    - TapPipeline
    - FingerprintStore
    - EnforcementBridge
    - ExportManager
    - TapHttpServer
    - ScheduledBackupManager (from Group 0)

    Runs until SIGTERM or SIGINT.
    """

    def __init__(self, config: ProxyConfig, redis: Redis) -> None: ...

    async def run(self) -> None:
        """Start all components; block until shutdown event."""
        ...

    async def shutdown(self) -> None:
        """Ordered 10-step drain sequence (see PHASE_20.md §11a.1)."""
        ...
```

### G1-C: `proxy.py` mode branch

Modify `main()` to:
```python
match config.mode:
    case "passthrough":
        server = ProxyServer(config)
        await server.start(shutdown_event)
    case "tap":
        sensor = TapSensor(config, redis)
        await sensor.run()
    case _:
        logger.critical("startup | event=invalid_mode | mode=%r", config.mode)
        sys.exit(1)
```

Tests in `tests/unit/test_mode_switch.py`:
```python
def test_passthrough_mode_creates_proxy_server()
def test_tap_mode_creates_tap_sensor()
def test_invalid_mode_exits_1()
def test_missing_mode_defaults_to_passthrough()
```

### G1-D: Config validation for `mode` key

Modify `src/config/loader.py` to validate `mode` at load time:
- Raise `ConfigError` for unknown values
- Log `startup | event=mode_selected | mode={mode}` at INFO

Tests in `tests/unit/test_config_loader.py` (additions):
```python
def test_mode_passthrough_is_valid()
def test_mode_tap_is_valid()
def test_mode_invalid_raises_config_error()
def test_mode_defaults_to_passthrough_when_absent()
```

---

## Group 2: TAP HTTP Server

**Files to create:** `src/tap/http_server.py`
**Files to create:** `tests/unit/tap/test_http_server.py`

Implements the lightweight aiohttp server for TAP-mode-only endpoints (see
PHASE_20.md §18). This is the Phase 13 substitute for TAP mode.

### G2-A: `src/tap/http_server.py`

```python
class TapHttpServer:
    """Lightweight aiohttp HTTP server for TAP-mode endpoints.

    Port: tap.http_port (default 8090). Starts automatically when mode=tap.
    When Phase 13 management server is implemented, these routes migrate to it.
    """

    def __init__(
        self,
        config: TapConfig,
        redis: Redis,
        edl_server: EDLServer,
        taxii_server: TaxiiServer,
        sensor: TapSensor,
    ) -> None: ...

    async def start(self) -> None: ...
    async def stop(self) -> None: ...

    # Route handlers
    async def _handle_mode(self, request: web.Request) -> web.Response:
        """GET /api/v1/mode → JSON with mode, interface, stream counts, pkt counts."""
        ...

    async def _handle_fp_ip(self, request: web.Request) -> web.Response:
        """GET /api/v1/fingerprints/ip/{ip} → JSON connection history."""
        ...

    async def _handle_fp_ja4(self, request: web.Request) -> web.Response:
        """GET /api/v1/fingerprints/ja4/{fingerprint} → JSON usage stats."""
        ...

    async def _handle_health(self, request: web.Request) -> web.Response:
        """GET /health → JSON TAP health struct (PHASE_20.md §13.4)."""
        ...
```

Tests in `tests/unit/tap/test_http_server.py`:
```python
async def test_mode_endpoint_returns_tap_mode()
async def test_mode_endpoint_includes_interface_and_stream_counts()
async def test_health_endpoint_returns_healthy_when_all_subsystems_ok()
async def test_health_endpoint_returns_degraded_when_one_exporter_down()
async def test_health_endpoint_returns_unhealthy_when_redis_down()
async def test_fp_ip_endpoint_returns_connection_history()
async def test_fp_ip_endpoint_returns_404_for_unknown_ip()
async def test_fp_ja4_endpoint_returns_usage_stats()
async def test_server_starts_on_configured_port()
async def test_server_shuts_down_cleanly()
```

---

## Group 3: Packet Capture Engine

**Files to create:** `src/tap/capture.py`
**Files to create:** `tests/unit/tap/test_capture.py`
**Files to create:** `tests/tap/__init__.py`, `tests/tap/unit/__init__.py`

### G3-A: Core classes

```python
@dataclass
class ParsedPacket:
    """Decoded packet ready for reassembler consumption."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str           # "tcp" | "udp"
    seq: int             # TCP sequence number
    ack: int             # TCP ACK number
    flags: int           # TCP flags (SYN=0x02, ACK=0x10, FIN=0x01, RST=0x04)
    data: bytes          # payload bytes (after TCP header)
    timestamp: float     # seconds since epoch (kernel or hardware)
    tcp_options_raw: bytes  # raw TCP options bytes (from SYN/SYN-ACK only)
    window_size: int
    ip_ttl: int
    ip_df: bool          # Don't Fragment bit
    ip_id: int           # IP identification field

class PacketCapture:
    """AF_PACKET TPACKET_V3 capture engine (see PHASE_20.md §5)."""

    def __init__(self, config: TapConfig, workers: list["StreamWorker"]) -> None: ...
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    def _setup_socket(self) -> socket.socket: ...
    def _set_bpf_filter(self, sock: socket.socket, expr: str) -> None: ...
    def _poll_ring(self) -> None:
        """Runs in dedicated OS thread via asyncio.to_thread()."""
        ...
    def _dispatch(self, frame: memoryview) -> None: ...
    def _parse_ethernet_frame(self, frame: memoryview) -> ParsedPacket | None:
        """Handles: plain Ethernet, 802.1q VLAN, QinQ, VxLAN, GENEVE."""
        ...
    def _dedup_check(self, pkt: ParsedPacket) -> bool:
        """True if duplicate (should be discarded). Uses LRU with time eviction."""
        ...

class PcapReplay:
    """Replays a PCAP file into the worker pipeline. API-compatible with PacketCapture."""

    def __init__(
        self,
        pcap_path: Path,
        workers: list["StreamWorker"],
        realtime: bool = False,
    ) -> None: ...
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
```

Tests in `tests/unit/tap/test_capture.py` (uses `PcapReplay`, not live socket):
```python
def test_parse_plain_ethernet_ipv4_tcp()
def test_parse_802_1q_vlan_tag_stripped()
def test_parse_qinq_double_tag_stripped()
def test_parse_vxlan_encapsulated_ipv4()
def test_parse_geneve_encapsulated_ipv4()
def test_parse_ipv6_tcp()
def test_parse_ipv4_fragment_first_and_last()
def test_dedup_filters_identical_packet_within_window()
def test_dedup_allows_identical_packet_after_window_expires()
def test_bpf_filter_compilation_error_raises_config_error()
def test_dispatch_same_stream_always_goes_to_same_worker()
def test_pcap_replay_emits_all_packets_from_file()
def test_pcap_replay_fast_mode_no_inter_packet_delay()
def test_parse_truncated_ethernet_frame_returns_none()
def test_parse_unknown_ethertype_returns_none()
```

---

## Group 4: TCP Stream Reassembler

**Files to create:** `src/tap/reassembler.py`
**Files to create:** `tests/unit/tap/test_reassembler.py`

### G4-A: Core classes

```python
StreamKey = tuple[str, int, str, int]  # (src_ip, src_port, dst_ip, dst_port)

@dataclass
class TCPStream:
    key: StreamKey
    conn_id: str               # UUID, generated at SYN
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    state: str                 # "SYN_RCVD" | "ESTABLISHED" | "CLOSING" | "CLOSED"
    client_seq: int
    server_seq: int
    client_buf: SortedList     # [(seq, data), ...] out-of-order buffer
    server_buf: SortedList
    client_data: bytearray     # assembled bytes, capped at max_stream_buffer_bytes
    server_data: bytearray
    syn_ts: float | None
    synack_ts: float | None
    ack_ts: float | None
    syn_tcp_opts: bytes
    synack_tcp_opts: bytes
    last_activity: float       # for timeout eviction
    fingerprints: dict[str, str | None]
    score_emitted: bool

class StreamReassembler:
    """Tracks TCP streams for one worker shard (see PHASE_20.md §6)."""

    def __init__(
        self, extractor: "FingerprintExtractor", config: TapConfig
    ) -> None: ...

    def on_packet(self, pkt: ParsedPacket) -> None: ...

    def _get_or_create(self, key: StreamKey) -> TCPStream: ...
    def _on_syn(self, stream: TCPStream, pkt: ParsedPacket) -> None: ...
    def _on_synack(self, stream: TCPStream, pkt: ParsedPacket) -> None: ...
    def _on_data(self, stream: TCPStream, pkt: ParsedPacket) -> None: ...
    def _on_fin_rst(self, stream: TCPStream, pkt: ParsedPacket) -> None: ...
    def _append_data(
        self, stream: TCPStream, data: bytes, direction: str
    ) -> None: ...
    def _flush_reorder_buf(self, stream: TCPStream, direction: str) -> None: ...
    def expire_idle(self) -> int:
        """Evict streams silent for > stream_timeout_s. Returns eviction count."""
        ...
    def evict_oldest(self, n: int) -> int:
        """Evict n oldest streams when stream table reaches max_streams."""
        ...
```

Tests in `tests/unit/tap/test_reassembler.py`:
```python
def test_syn_creates_stream_in_syn_rcvd_state()
def test_synack_transitions_to_established()
def test_in_order_segments_assembled_correctly()
def test_out_of_order_segment_buffered_then_flushed()
def test_1000_out_of_order_permutations_all_produce_correct_assembly()  # property test
def test_retransmitted_segment_discarded_no_duplicate_data()
def test_rst_closes_stream_and_calls_extractor()
def test_fin_closes_stream_after_fin_ack()
def test_idle_stream_expired_after_stream_timeout_s()
def test_stream_buffer_cap_drops_stream_not_crash()
def test_max_streams_evicts_oldest_on_new_syn()
def test_ipv4_fragment_reassembly_before_tcp_parsing()
def test_ipv6_fragment_extension_header_walked()
def test_stream_table_sharding_routes_same_4_tuple_to_same_worker()
```

---

## Group 5: Fingerprint Extractors

**Files to create:** `src/tap/fingerprints/__init__.py` plus one file per extractor.

Each extractor is a **pure function** (no I/O, no async) that takes bytes and returns a
typed dataclass or `None`. They must never raise on malformed input — return `None`.

### G5-A: `src/tap/fingerprints/ja4.py`

```python
def extract_ja4(client_hello: bytes) -> JA4Result | None:
    """Parse raw TLS ClientHello bytes → JA4 fingerprint + rich detail."""
    ...

@dataclass
class JA4Result:
    fingerprint: str
    tls_version_offered: str
    ciphers: list[int]
    extensions: list[int]
    alpn_list: list[str]
    sni: str | None
    key_share_groups: list[int]
    psk_modes: list[int]
    supported_groups: list[int]
    signature_algorithms: list[int]
    session_ticket_present: bool
    session_ticket_len: int
    grease_values: list[int]
    padding_ext_len: int | None
    compress_cert_present: bool
```

Tests in `tests/unit/tap/test_ja4.py`:
```python
def test_extract_ja4_from_chrome_120_bytes()
def test_extract_ja4_from_firefox_121_bytes()
def test_extract_ja4_from_curl_bytes()
def test_returns_none_on_truncated_input()
def test_returns_none_on_non_tls_bytes()
def test_grease_values_identified()
def test_alpn_h2_captured()
def test_sni_extracted()
def test_fingerprint_matches_reference_tool_output()  # golden-file test
```

### G5-B: `src/tap/fingerprints/ja4s.py`

```python
def extract_ja4s(server_hello: bytes) -> JA4SResult | None: ...

@dataclass
class JA4SResult:
    fingerprint: str
    tls_version_negotiated: str
    cipher_chosen: int
    alpn_chosen: str | None
    extensions: list[int]
    session_id_present: bool
    supported_versions_ext: list[int]
```

Tests in `tests/unit/tap/test_ja4s.py`:
```python
def test_extract_ja4s_from_nginx_server_hello()
def test_extract_ja4s_from_openssl_server_hello()
def test_returns_none_on_truncated_server_hello()
def test_session_id_presence_detected()
def test_fingerprint_format_matches_spec()
```

### G5-C: `src/tap/fingerprints/ja4t.py`

```python
def extract_ja4t_from_syn(syn_tcp_opts: bytes, window_size: int) -> JA4TResult: ...

@dataclass
class JA4TResult:
    fingerprint: str           # e.g. "65535_1460_MSTNW_8"
    window_size: int
    mss: int | None
    options_order: str
    window_scale: int | None
    sack_permitted: bool
    timestamps: bool
    raw_options_hex: str
```

Tests in `tests/unit/tap/test_ja4t.py`:
```python
def test_linux_default_syn_options()
def test_windows_10_syn_options()
def test_macos_syn_options()
def test_no_options_produces_valid_fingerprint()
def test_unknown_option_type_included_as_decimal()
```

### G5-D: `src/tap/fingerprints/ja4h.py`

```python
def extract_ja4h(http_request: bytes) -> JA4HResult | None:
    """Returns None if headers not complete (no \\r\\n\\r\\n yet) or non-HTTP."""
    ...

@dataclass
class JA4HResult:
    fingerprint: str
    method: str
    http_version: str
    headers: dict[str, str]
    accept_language: str | None
    user_agent: str | None
    cookie_count: int
    referer: str | None
```

Tests in `tests/unit/tap/test_ja4h.py`:
```python
def test_get_request_with_standard_browser_headers()
def test_post_request_with_cookie()
def test_referer_present_in_fingerprint()
def test_returns_none_on_incomplete_headers()
def test_returns_none_on_non_http_bytes()
def test_header_order_preserved_in_hash()
def test_language_hash_included()
```

### G5-E: `src/tap/fingerprints/ja4l.py`

```python
def extract_ja4l(
    syn_ts: float, synack_ts: float, ack_ts: float
) -> JA4LResult: ...

@dataclass
class JA4LResult:
    fingerprint: str
    client_distance_km: float
    server_distance_km: float
    rtt_client_ms: float
    rtt_server_ms: float
    geoip_distance_km: float | None
    distance_mismatch: bool
```

Tests in `tests/unit/tap/test_ja4l.py`:
```python
def test_known_rtt_produces_expected_distance()
def test_zero_rtt_produces_zero_distance()
def test_distance_mismatch_false_when_within_500km()
def test_distance_mismatch_true_when_exceeds_500km()
def test_negative_rtt_handled_gracefully()
```

### G5-F: `src/tap/fingerprints/ja4x.py`

```python
def extract_ja4x(certificate_message: bytes) -> JA4XResult | None: ...

@dataclass
class JA4XResult:
    fingerprint: str
    issuer_dn: str
    subject_dn: str
    key_type: str
    not_before: datetime
    not_after: datetime
    san_domains: list[str]
    san_ips: list[str]
    self_signed: bool
    serial: str
    sha256: str
```

Tests in `tests/unit/tap/test_ja4x.py`:
```python
def test_rsa2048_cert_key_type_identified()
def test_ec256_cert_key_type_identified()
def test_self_signed_cert_detected()
def test_san_domains_and_ips_extracted()
def test_fingerprint_matches_manual_openssl_calculation()
def test_returns_none_on_truncated_certificate_message()
def test_expired_cert_not_before_after_correct()
```

### G5-G: `src/tap/fingerprints/ja4ssh.py`

```python
def extract_ja4ssh(
    kexinit_payload: bytes, direction: str
) -> JA4SSHResult | None:
    """direction: 'client' | 'server'"""
    ...

@dataclass
class JA4SSHResult:
    fingerprint: str
    direction: str
    kex_algorithms: list[str]
    host_key_algorithms: list[str]
    encryption_client_to_server: list[str]
    encryption_server_to_client: list[str]
    mac_client_to_server: list[str]
    mac_server_to_client: list[str]
    compression_client_to_server: list[str]
```

Tests in `tests/unit/tap/test_ja4ssh.py`:
```python
def test_openssh_8x_client_fingerprint()
def test_paramiko_client_fingerprint()
def test_server_direction_produces_different_fingerprint()
def test_returns_none_on_truncated_kexinit()
def test_algorithm_counts_in_fingerprint()
```

### G5-H: `src/tap/fingerprints/tls_ext_values.py`

```python
def extract_tls_ext_values(ja4_result: JA4Result) -> JA4TLSExtValues:
    """Extracts rich detail from the already-parsed JA4Result (no new parsing)."""
    ...

@dataclass
class JA4TLSExtValues:
    supported_groups: list[int]
    key_share_groups: list[int]
    sig_algs: list[int]
    psk_modes: list[int]
    grease_values: list[int]
    has_compress_cert: bool
    has_alps: bool
    padding_len: int | None
    session_ticket_len: int
```

Tests in `tests/unit/tap/test_tls_ext_values.py`:
```python
def test_grease_values_extracted_from_chrome()
def test_no_grease_in_python_requests()
def test_alps_detected_in_chrome()
def test_compress_cert_detected_in_modern_browser()
def test_key_share_groups_in_order()
```

### G5-I: `src/tap/fingerprints/os_fingerprint.py`

```python
def load_os_database(path: Path) -> list[OSSignature]: ...

def match_os(
    syn_tcp_opts: bytes,
    window_size: int,
    ttl: int,
    df: bool,
    database: list[OSSignature],
) -> OSFingerprintResult: ...

@dataclass
class OSFingerprintResult:
    fingerprint_id: str
    label: str
    confidence: float
    ttl: int
    df: bool
    window_size: int
    mss: int | None
    wscale: int | None
    options_str: str
    raw_hash: str
```

Tests in `tests/unit/tap/test_os_fingerprint.py`:
```python
def test_linux_5x_default_identified_with_high_confidence()
def test_windows_10_identified_with_high_confidence()
def test_macos_identified()
def test_unknown_os_returns_unknown_with_low_confidence()
def test_database_loaded_from_yaml()
def test_multiple_window_sizes_in_database_match_any()
```

### G5-J: `src/tap/fingerprints/h2_fingerprint.py`

```python
def extract_h2_fingerprint(
    http2_stream: bytes, database: list[H2Signature]
) -> H2FingerprintResult | None: ...

@dataclass
class H2FingerprintResult:
    fingerprint: str
    settings: dict[str, int]
    settings_order: list[str]
    window_update_increment: int | None
    matched_client: str | None
    confidence: float
```

Tests in `tests/unit/tap/test_h2_fingerprint.py`:
```python
def test_chrome_120_settings_match_database_entry()
def test_firefox_121_settings_identified()
def test_curl_minimal_settings_identified()
def test_settings_order_preserved()
def test_returns_none_on_non_h2_stream()
def test_returns_none_on_incomplete_preface()
```

### G5-K: `src/tap/fingerprints/quic_fingerprint.py`

```python
def extract_quic_fingerprint(udp_payload: bytes) -> QUICFingerprintResult | None: ...

@dataclass
class QUICFingerprintResult:
    quic_version: int
    dcid_len: int
    token_len: int
    embedded_ja4: str | None
    fingerprint: str
```

Tests in `tests/unit/tap/test_quic_fingerprint.py`:
```python
def test_quic_v1_version_extracted()
def test_embedded_ja4_computed_from_crypto_frame()
def test_returns_none_on_short_udp_payload()
def test_returns_none_on_non_quic_header()
```

### G5-L: `src/tap/fingerprints/correlation.py`

```python
@dataclass
class ConnectionFingerprints:
    conn_id: str
    timestamp: datetime
    client_ip: str
    server_ip: str
    server_port: int
    ja4: str | None
    ja4s: str | None
    ja4t: str | None
    ja4ts: str | None
    ja4h: str | None
    ja4l: str | None
    ja4x: str | None
    ja4ssh: str | None
    h2_fingerprint: str | None
    quic_fingerprint: str | None
    os_fingerprint: str | None
    tls_ext_values: JA4TLSExtValues | None
    os_detail: OSFingerprintResult | None
    risk_score: int
    action: str
    signals: list[dict]

    def to_redis_dict(self) -> dict[str, str]: ...

    @classmethod
    def from_redis_dict(cls, d: dict[str, str]) -> "ConnectionFingerprints": ...
```

Tests in `tests/unit/tap/test_correlation.py`:
```python
def test_to_redis_dict_serialises_all_fields()
def test_from_redis_dict_round_trips_correctly()
def test_none_fields_omitted_from_redis_dict()
def test_conn_id_is_uuid_format()
```

---

## Group 6: TAP Pipeline & Risk Scoring Integration

**Files to create:** `src/tap/tap_pipeline.py`
**Files to create:** `tests/unit/tap/test_tap_pipeline.py`

```python
class FingerprintExtractor:
    """Coordinates all extractors; called by StreamReassembler when stream data arrives."""

    def __init__(
        self,
        config: TapConfig,
        os_database: list[OSSignature],
        h2_database: list[H2Signature],
    ) -> None: ...

    def on_stream_data(
        self, stream: TCPStream
    ) -> None:
        """Called incrementally as data arrives. Extracts fingerprints opportunistically."""
        ...

    def on_stream_close(
        self, stream: TCPStream
    ) -> ConnectionFingerprints:
        """Called when stream closes (FIN/RST/timeout). Returns final fingerprint record."""
        ...

class TapPipeline:
    """Integrates fingerprints with RiskScorer and ActionDecider."""

    def __init__(
        self,
        config: ProxyConfig,
        scorer: RiskScorer,
        decider: ActionDecider,
        redis: Redis,
        export_manager: "ExportManager",
    ) -> None: ...

    async def process(self, fp: ConnectionFingerprints) -> None:
        """Convert fingerprints to RiskSignals, score, determine TAP action, signal."""
        ...

    def _fingerprints_to_signals(
        self, fp: ConnectionFingerprints
    ) -> list[RiskSignal]:
        """Map each fingerprint type to RiskSignals (see PHASE_20.md §9.2)."""
        ...

    def _score_to_tap_action(self, score: int) -> str:
        """Map 0–100 score to TAP action: observe/flag/signal_slow/signal_block/signal_ban."""
        ...
```

Tests in `tests/unit/tap/test_tap_pipeline.py`:
```python
async def test_chrome_fingerprints_produce_low_score()
async def test_nmap_fingerprints_produce_high_score()
async def test_signal_ban_writes_ban_redis_key()
async def test_signal_block_writes_block_decision_redis_key()
async def test_observe_action_writes_no_ban_key()
async def test_ja4l_mismatch_adds_20_to_score()
async def test_os_ua_mismatch_adds_15_to_score()
async def test_no_grease_adds_10_to_score()
async def test_scanner_ja4_adds_20_to_score()
async def test_expired_cert_adds_15_to_score()
async def test_h2_settings_mismatch_adds_15_to_score()
async def test_ssh_attack_tool_adds_25_to_score()
async def test_score_0_to_19_maps_to_observe()
async def test_score_70_to_84_maps_to_signal_block()
async def test_score_85_to_100_maps_to_signal_ban()
```

---

## Group 7: Fingerprint Store

**Files to modify:** `src/tap/tap_pipeline.py` (add store writes)
**Files to create:** `tests/unit/tap/test_fingerprint_store.py`

All `fp:*` Redis key patterns (see PHASE_20.md §8.2):
- `fp:conn:{conn_id}` — JSON, TTL 7 days
- `fp:ip:{client_ip}` — ZSET, trim to 1000, TTL 30 days
- `fp:ja4:hll:{fingerprint}` — PFADD, TTL 30 days
- `fp:ja4:count:{fingerprint}` — INCR, TTL 30 days
- `fp:os:count:{fingerprint_id}` — INCR, TTL 30 days
- `fp:os:ip:{client_ip}` — STRING, TTL 24 hours
- `fp:ja4_to_ja4s:{ja4}` — HSET {ja4s: count}, TTL 7 days

```python
class FingerprintStore:
    """Writes ConnectionFingerprints to Redis fp:* keys."""

    def __init__(self, redis: Redis) -> None: ...

    async def write(self, fp: ConnectionFingerprints) -> None:
        """Write all fp:* keys for one connection. Fire-and-forget from hot path."""
        ...

    async def get_ip_history(
        self, ip: str, limit: int = 10
    ) -> list[ConnectionFingerprints]:
        """Read fp:ip:{ip} ZSET and hydrate connection records."""
        ...

    async def get_ja4_stats(self, fingerprint: str) -> dict: ...
```

Tests in `tests/unit/tap/test_fingerprint_store.py`:
```python
async def test_write_creates_fp_conn_key_with_7_day_ttl()
async def test_write_adds_to_fp_ip_sorted_set()
async def test_fp_ip_sorted_set_trimmed_to_1000()
async def test_write_pfadd_to_ja4_hll()
async def test_write_incr_ja4_count()
async def test_get_ip_history_returns_last_10_connections()
async def test_get_ja4_stats_returns_count_and_hll_estimate()
async def test_ja4_to_ja4s_correlation_updated()
```

---

## Group 8: Enforcement Bridge

**Files to create:** `src/tap/enforcement_bridge.py`,
  `src/tap/enforcement_bridge_process.py`
**Files to create:** `tests/unit/tap/test_enforcement_bridge.py`,
  `tests/chaos/test_tap_enforcement_resilience.py`

```python
class EnforcementBridge:
    """Subscribes to Redis bans and dispatches to enforcement backends."""

    def __init__(self, config: TapEnforcementConfig, redis: Redis) -> None: ...

    async def start(self) -> None: ...
    async def close(self) -> None: ...

    async def _on_ban(self, ip: str, ttl: int, reason: str) -> None:
        """asyncio.gather() all enabled backends; log individual failures."""
        ...

    async def _iptables_ban(self, ip: str, ttl: int) -> None:
        """asyncio.create_subprocess_exec(['ipset', 'add', ...])"""
        ...

    async def _bgp_announce(self, ip: str) -> None:
        """Write ExaBGP announce command to named pipe."""
        ...

    async def _webhook_ban(self, ip: str, ttl: int, reason: str) -> None:
        """POST with HMAC-SHA256 signature header; retry on 5xx."""
        ...
```

Tests in `tests/unit/tap/test_enforcement_bridge.py`:
```python
async def test_iptables_ban_calls_ipset_add_with_timeout()
async def test_iptables_ban_uses_create_subprocess_exec_not_shell()
async def test_bgp_announce_writes_correct_command_to_pipe()
async def test_bgp_prefix_length_guard_rejects_slash_16()
async def test_bgp_prefix_length_guard_rejects_ipv6_slash_32()
async def test_webhook_includes_hmac_sha256_header()
async def test_webhook_retries_on_5xx_up_to_retry_count()
async def test_webhook_stops_retrying_after_max_retries()
async def test_ban_ttl_passed_to_iptables_timeout()
```

Tests in `tests/chaos/test_tap_enforcement_resilience.py`:
```python
async def test_iptables_failure_does_not_prevent_bgp_enforcement()
async def test_bgp_pipe_missing_increments_error_metric_not_crash()
async def test_webhook_failure_does_not_prevent_iptables_enforcement()
async def test_all_backends_failing_logs_error_not_crash()
async def test_redis_pubsub_reconnects_after_disconnect()
```

---

## Group 9: Intelligence Export

**Files to create:** `src/tap/export/__init__.py` and one file per exporter.

### G9-A: `src/tap/export/export_manager.py`

```python
class ExportManager:
    """Orchestrates all enabled exporters. Called by TapPipeline on each event."""

    def __init__(self, config: IntelligenceExportConfig, redis: Redis) -> None: ...

    async def start(self) -> None:
        """Start all enabled exporters (EDL rebuild loop, F5 sync loop, etc.)."""
        ...

    async def on_fingerprint(self, fp: ConnectionFingerprints) -> None:
        """Fire-and-forget: dispatch to all enabled streaming exporters."""
        ...

    async def on_ban(self, ip: str, score: int, ttl: int, reason: str) -> None:
        """Push to all enabled ban exporters (F5, PA, Kafka bans, MISP, BGP)."""
        ...

    async def close(self) -> None: ...
```

### G9-B: `src/tap/export/edl_server.py`

(See PHASE_20.md §10.5.1 for full spec.)

```python
class EDLServer:
    async def _rebuild_lists(self) -> None: ...
    async def handle_edl_request(
        self, list_name: str, request: web.Request
    ) -> web.Response: ...
```

Tests in `tests/unit/tap/test_edl_server.py`:
```python
async def test_banned_ips_list_contains_active_bans_only()
async def test_entries_older_than_max_age_excluded()
async def test_entries_below_min_score_excluded()
async def test_etag_returned_with_response()
async def test_304_returned_when_etag_matches()
async def test_403_when_api_key_missing()
async def test_403_when_source_ip_not_in_allowed_ips()
async def test_comments_included_when_include_comments_true()
async def test_combined_list_is_union_of_banned_ips_and_cidrs()
```

### G9-C: `src/tap/export/f5_client.py`

```python
class F5Client:
    async def full_sync(self) -> None: ...
    async def delta_push(self, ip: str, action: str) -> None: ...
    async def _patch_data_group(self, name: str, records: list[dict]) -> None: ...
```

Tests in `tests/unit/tap/test_f5_client.py`:
```python
async def test_full_sync_patches_all_configured_data_groups()
async def test_delta_push_adds_single_ip()
async def test_delta_push_fires_within_5s_of_ban_pubsub()
async def test_max_rps_respected()
async def test_retry_on_429()
async def test_retry_on_503()
```

### G9-D: `src/tap/export/palo_alto_client.py`

```python
class PaloAltoClient:
    async def register_ip(self, ip: str, tags: list[str]) -> None: ...
    async def unregister_ip(self, ip: str, tags: list[str]) -> None: ...
    async def full_sync(self) -> None: ...
```

Tests in `tests/unit/tap/test_palo_alto_client.py`:
```python
async def test_register_ip_calls_xml_api_with_correct_tag()
async def test_unregister_ip_removes_tag()
async def test_full_sync_registers_all_banned_ips()
async def test_verify_tls_false_emits_warn()
```

### G9-E: `src/tap/export/kafka_producer.py`

```python
class KafkaExporter:
    async def start(self) -> None: ...
    async def close(self) -> None: ...
    async def flush(self, timeout: float) -> None: ...
    async def send_fingerprint(self, fp: ConnectionFingerprints) -> None: ...
    async def send_ban(self, event: str, ip: str, score: int, ttl: int, reason: str) -> None: ...
```

Tests in `tests/unit/tap/test_kafka_producer.py`:
```python
async def test_fingerprint_message_schema_v1_valid()
async def test_ban_event_message_schema_valid()
async def test_message_key_is_client_ip()
async def test_batch_flushed_when_batch_size_reached()
async def test_batch_flushed_after_linger_ms()
async def test_broker_unavailable_logs_warn_not_crash()
```

### G9-F: `src/tap/export/syslog_exporter.py`

```python
class SyslogExporter:
    def close(self) -> None: ...
    def send(self, event: str, ip: str, score: int, action: str, ja4: str | None) -> None: ...
    def _format_cef(self, ...) -> str: ...
    def _format_rfc5424(self, ...) -> str: ...
```

Tests in `tests/unit/tap/test_syslog_exporter.py`:
```python
def test_cef_format_is_valid()
def test_cef_severity_mapping_signal_ban_is_9()
def test_cef_severity_mapping_observe_is_3()
def test_rfc5424_format_valid()
def test_low_volume_event_types_not_sent_when_disabled()
```

### G9-G: `src/tap/export/taxii_server.py`

```python
class TaxiiServer:
    async def handle_taxii_request(self, path: str, request: web.Request) -> web.Response: ...
    def _build_stix_indicator(self, ip: str, score: int, reason: str, ja4: str | None) -> dict: ...
```

Tests in `tests/unit/tap/test_taxii_server.py`:
```python
async def test_taxii_discovery_returns_valid_json()
async def test_collections_endpoint_returns_configured_collection()
async def test_objects_endpoint_returns_stix_bundle()
async def test_added_after_filter_works()
async def test_api_key_required()
async def test_stix_indicator_has_correct_pattern_type()
```

### G9-H: `src/tap/export/misp_client.py`

```python
class MISPClient:
    async def push_ban(self, ip: str, score: int, reason: str, ja4: str | None) -> None: ...
    async def _get_or_create_daily_event(self) -> str: ...
    async def _add_attribute(self, event_id: str, type_: str, value: str, comment: str) -> None: ...
```

Tests in `tests/unit/tap/test_misp_client.py`:
```python
async def test_push_ban_creates_attribute_with_ip_dst_type()
async def test_daily_event_reused_for_same_day()
async def test_duplicate_attribute_not_created()
async def test_ja4_attribute_added_as_other_type()
async def test_misp_api_error_logs_warn_not_crash()
```

**Chaos tests in `tests/chaos/test_tap_export_resilience.py`:**
```python
async def test_kafka_failure_does_not_affect_syslog()
async def test_f5_failure_does_not_affect_misp()
async def test_pa_failure_does_not_affect_kafka()
async def test_misp_failure_does_not_affect_taxii()
async def test_all_exporters_failing_logs_errors_not_crash()
```

**Integration tests in `tests/tap/integration/test_export_integration.py`:**
```python
async def test_ban_event_reaches_all_enabled_exporters()
async def test_fingerprint_event_reaches_kafka_and_syslog()
async def test_edl_rebuild_reflects_new_ban_within_refresh_interval()
```

---

## Group 10: Lifecycle Management

**Files to create:** `src/tap/watchdog.py`
**Files to modify:** `src/tap/tap_sensor.py`

```python
class WorkerWatchdog:
    """Monitors capture worker tasks; restarts crashed workers."""

    def __init__(self, sensor: TapSensor) -> None: ...

    async def watch(self, worker_id: int, task: asyncio.Task) -> None: ...
    async def _evict_shard(self, shard_id: int) -> None: ...
```

Tests in `tests/unit/tap/test_watchdog.py`:
```python
async def test_crashed_worker_is_restarted()
async def test_worker_restart_increments_metric()
async def test_shard_streams_evicted_after_worker_crash()
async def test_rapid_crash_loop_emits_warn_after_3_in_60s()
async def test_watchdog_does_not_restart_after_clean_shutdown()
```

Tests in `tests/unit/tap/test_graceful_shutdown.py`:
```python
async def test_shutdown_stops_capture_first()
async def test_shutdown_drains_workers_before_scoring()
async def test_shutdown_flushes_kafka_before_closing_redis()
async def test_shutdown_completes_within_15s_under_normal_load()
async def test_shutdown_force_closes_streams_after_drain_timeout()
```

Tests in `tests/unit/tap/test_hot_reload.py`:
```python
def test_stream_timeout_s_hot_reloadable()
def test_tap_interface_change_logs_warn_and_is_ignored()
def test_ring_buffer_mb_change_logs_warn_and_is_ignored()
def test_fingerprint_type_enable_disable_hot_reloadable()
def test_enforcement_config_hot_reloadable()
```

---

## Group 11: Observability

**Files to create:** `src/tap/metrics.py`
**Files to modify:** `src/tap/capture.py`, `src/tap/reassembler.py`,
  `src/tap/tap_pipeline.py`, `src/tap/enforcement_bridge.py`,
  `src/tap/export/export_manager.py`

Define all Prometheus metrics at module level in `src/tap/metrics.py` (same pattern as
existing phases — one module, all counters/gauges/histograms imported by submodules).

All 30+ metrics from PHASE_20.md §13.1 must be defined here. Naming:
`ja4proxy_tap_{subsystem}_{metric}_{unit}`.

Tests in `tests/unit/tap/test_tap_metrics.py`:
```python
def test_all_capture_metrics_defined()
def test_all_reassembly_metrics_defined()
def test_all_fingerprint_metrics_defined()
def test_all_enforcement_metrics_defined()
def test_all_export_metrics_defined()
def test_no_stale_metric_names()  # regex check, same pattern as Phase 14e
def test_ring_buffer_fill_gauge_updated_on_poll()
def test_packets_dropped_counter_increments_on_overflow()
def test_worker_restarts_counter_increments_on_crash()
```

Create `deploy/monitoring/grafana/dashboards/tap_sensor.json` (5 rows per §13.3).
Create `deploy/monitoring/alertmanager/rules/tap.yml` (7 alert rules per §13.2).

---

## Group 12: Security Hardening

**Files to create:** `src/tap/security.py`, `config/seccomp_tap.json`
**Files to modify:** `src/tap/capture.py` (call `drop_cap_net_raw()` after bind)

```python
# src/tap/security.py

def drop_cap_net_raw() -> None:
    """Drop CAP_NET_RAW from effective and permitted sets via libcap."""
    ...

def apply_seccomp_profile(profile_path: Path) -> None:
    """Load and apply seccomp filter from JSON profile file."""
    ...

def validate_pcap_path(path: str, allowed_dirs: list[str]) -> Path:
    """Resolve and check path is within allowed_dirs; raises ConfigError if not."""
    ...
```

Tests in `tests/unit/tap/test_security.py`:
```python
def test_validate_pcap_path_allows_valid_path()
def test_validate_pcap_path_rejects_path_traversal()
def test_validate_pcap_path_rejects_absolute_path_outside_allowed()
def test_drop_cap_net_raw_called_after_socket_bind()
def test_webhook_tls_false_emits_startup_warn()
def test_bgp_slash_16_rejected_logs_error_no_pipe_write()
def test_bgp_rate_limit_prevents_more_than_max_announcements_per_minute()
```

Tests in `tests/unit/tap/test_gdpr.py`:
```python
async def test_gdpr_delete_removes_fp_ip_key()
async def test_gdpr_delete_removes_all_fp_conn_keys_for_ip()
async def test_gdpr_delete_does_not_remove_other_ip_keys()
```

---

## Group 13: Test Infrastructure

### G13-A: `tests/tap/conftest.py` — fixtures

```python
@pytest.fixture
def pcap_replay(tmp_path):
    """Factory: pcap_replay('chrome_120.pcap') → PcapReplay instance."""
    ...

@pytest.fixture
def synthetic_packets():
    """Return SyntheticPacketBuilder."""
    ...

@pytest.fixture
async def mock_redis():
    """fakeredis.aioredis.FakeRedis() — pre-seeded with test data."""
    ...

@pytest.fixture
def tap_config(tmp_path):
    """Minimal valid TapConfig for unit tests."""
    ...

@pytest.fixture
def tap_pipeline(mock_redis, tap_config):
    """Fully wired TapPipeline with mock exporters."""
    ...
```

### G13-B: `SyntheticPacketBuilder` (in `tests/tap/conftest.py`)

```python
class SyntheticPacketBuilder:
    def syn(self, src: str, sport: int, dst: str, dport: int, **tcp_opts) -> Self: ...
    def synack(self, **tcp_opts) -> Self: ...
    def ack(self) -> Self: ...
    def tls_client_hello(self, ciphers: list[int], extensions: list[int], sni: str | None, **kw) -> Self: ...
    def tls_server_hello(self, cipher: int, extensions: list[int], **kw) -> Self: ...
    def http_request(self, method: str, headers: dict[str, str], body: bytes = b"") -> Self: ...
    def fin(self) -> Self: ...
    def rst(self) -> Self: ...
    def build(self) -> list[ParsedPacket]: ...
```

Tests in `tests/unit/tap/test_synthetic_builder.py`:
```python
def test_syn_synack_ack_sequence_valid()
def test_tls_client_hello_parseable_by_extractor()
def test_out_of_order_build_produces_shuffled_packets()
def test_rst_produces_rst_flag_set()
```

### G13-C: PCAP corpus (`tests/tap/pcap_corpus/`)

Generate synthetic PCAPs using `scripts/generate_test_pcap.py`:
- `chrome_120.pcap`
- `firefox_121.pcap`
- `safari_17.pcap`
- `curl_8x.pcap`
- `python_requests.pcap`
- `scanner_nmap.pcap`
- `scanner_masscan.pcap`
- `ssh_openssh.pcap`
- `ssh_putty.pcap`
- `http2_chrome.pcap`
- `quic_chrome.pcap`
- `mixed_clients.pcap`
- `vxlan_encapsulated.pcap`
- `ipv6_clients.pcap`

Tests in `tests/tap/fp_corpus/test_fingerprint_accuracy.py`:
```python
@pytest.mark.parametrize("pcap_name,expected", KNOWN_FINGERPRINTS.items())
def test_fingerprint_extraction_accuracy(pcap_name, expected, pcap_replay)
```

Tests in `tests/tap/fp_corpus/test_fingerprint_fp_rate.py`:
```python
def test_fp_rate_tranco_top10k_below_0_5_percent()
```

Tests in `tests/tap/chaos/test_tap_resilience.py`:
```python
def test_ring_buffer_overflow_increments_dropped_counter()
def test_corrupt_ethernet_frame_skipped_without_crash()
def test_truncated_tls_record_returns_none_not_exception()
def test_stream_table_at_max_capacity_evicts_oldest()
def test_worker_crash_triggers_watchdog_restart()
```

---

## Group 14: Config Files and Scripts

**Files to create:**
- `config/os_fingerprints.yml` — p0f-style OS signature database (see PHASE_20.md §7.9)
- `config/h2_fingerprints.yml` — known HTTP/2 SETTINGS per browser/client
- `config/seccomp_tap.json` — seccomp allowlist for TAP process
- `scripts/generate_test_pcap.py` — synthetic PCAP generator
- `scripts/tap_benchmark.py` — throughput benchmark (see PHASE_20.md §12.9)
- `scripts/reconcile_ipset.py` — iptables/ipset drift reconciliation (see §15.7)

Add to `Makefile`:
```makefile
test-tap:
	@python3 -m pytest tests/tap/ -n $(WORKERS) --dist=loadfile --timeout=60 --tb=short $(ARGS)

test-tap-live:
	@[ -n "$(INTERFACE)" ] || (echo "Usage: make test-tap-live INTERFACE=eth1"; exit 1)
	@sudo python3 -m pytest tests/tap/integration/ --timeout=120 -k requires_tap_interface -v $(ARGS)

test-tap-perf:
	@python3 scripts/tap_benchmark.py --interface $(INTERFACE) --pcap $(PCAP)

gdpr-delete:
	@[ -n "$(IP)" ] || (echo "Usage: make gdpr-delete IP=1.2.3.4"; exit 1)
	@python3 scripts/gdpr_delete.py --ip $(IP)
```

---

## Group 15: Documentation

**In this order:**

1. `docs/REDIS_SCHEMA.md` — add `fp:*` key patterns under new section "TAP Mode"
2. `docs/decisions/ADR-020.md` — AF_PACKET vs pcap/Scapy vs PF_RING/DPDK
3. `docs/decisions/ADR-021.md` — EDL pull vs push for external firewall integration
4. `docs/decisions/ADR-022.md` — TAP HTTP server: standalone for Phase 20, migrates to Phase 13
5. `docs/runbooks/tap_mode.md` — full operator runbook (see PHASE_20.md §15)
6. `CHANGELOG.md` — add entry per PHASE_20.md §16
7. `docs/phases/manifest.yaml` — set Phase 20 `status: COMPLETE`; close gaps P19-G1, G3, G4, G6
8. Run `python3 scripts/sync-roadmap.py`
9. Commit all four files atomically: code + CHANGELOG + manifest + TODO + PROJECT_STATUS

---

## Final Checklist Before Phase Complete

- [ ] `make test` green (all existing + all new TAP tests via PCAP replay)
- [ ] All acceptance criteria in PHASE_20.md §17a–17l checked off
- [ ] Test-to-code ratio ≥ 1.3× for `src/tap/` (verify with `make lint-coverage`)
- [ ] Phase 19 gaps P19-G1, G3, G4, G6 green
- [ ] `scripts/tap_benchmark.py` shows ≥ 500k pps without drops
- [ ] Two-instance test: passthrough + TAP sharing Redis; TAP ban enforced by passthrough
- [ ] `manifest.yaml` updated; `sync-roadmap.py` run; commit is atomic

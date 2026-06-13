# Event Stream Contract Alignment

## Goal

Resolve the contract mismatch between the Go proxy daemon and the Python management console. Standarise on `events:connection` as the single source of truth for proxy events. Implement the ECS key mapping in the console's stream consumer, ensuring it correctly reads the nested JSON event structure and uses the standard action enum: `allow, flag, rate_limit, tarpit, block, ban`.

---

## A — Event Stream Schema Definition

Verify and document the Go proxy's JSON event structure. The Go proxy writes to
the `events:connection` stream. Each `XADD` adds **one stream field named
`event`** whose value is a JSON string (see `cmd/ja4pd/main.go` `handleConn()` /
`streamEventWorker`, currently around lines 671–685 and the `XAdd` at ~1279).

> ⚠️ **Ground truth — the keys are FLAT, dot-delimited ECS field names, not
> nested JSON objects.** Do not assume `source.ip` is `{"source":{"ip":...}}`;
> it is a single string key `"source.ip"`. There is **no** `tls.ja4` key (the
> JA4 lives under `ja4proxy.fingerprint.ja4`) and **no** `event.score` (the
> score is `event.risk_score`). Copy the field names below verbatim from the Go
> source rather than inferring them.

```json
{
  "@timestamp": "2026-06-12T12:00:00.123456789Z",
  "event.action": "allow",
  "event.risk_score": 0,
  "source.ip": "1.2.3.4",
  "source.port": 54321,
  "destination.ip": "10.0.0.5",
  "destination.port": 443,
  "network.transport": "tcp",
  "network.protocol": "tls",
  "service.name": "ja4proxy",
  "ja4proxy.fingerprint.ja4": "t13d1516h2_86f5c22de260_...",
  "ja4proxy.sni": "example.com",
  "ja4proxy.dial_setting": 0
}
```

---

## B — Console Stream Consumer Update

Modify the Python management console's consumer loop (a new dedicated stream
listener — see "Files to Modify"; the existing `src/analytics/stream_consumer.py`
is a separate analytics consumer and should be used as a reference pattern, not
edited here) to:
1. Listen on `events:connection` instead of `ja4proxy:events`.
2. Read the stream entry's `event` field (the only field on the entry).
3. Deserialise that JSON string into a dict.
4. Map the **flat** dot-delimited ECS keys to the flat fields the UI templates
   expect — index with the literal dotted string, e.g. `payload["source.ip"]`,
   never `payload["source"]["ip"]`:
   - `payload["source.ip"]` -> `ip`
   - `payload["ja4proxy.fingerprint.ja4"]` -> `ja4`
   - `payload["event.action"]` -> `action_taken` (values are exactly `allow, flag, rate_limit, tarpit, block, ban`)
   - `payload["event.risk_score"]` -> `risk_score`

Use `dict.get(...)` with safe defaults so a missing key or a malformed JSON
string is logged and skipped rather than crashing the consumer loop.

---

## C — Consumer Testing

Add unit and integration tests under `tests/unit/management/` and `tests/integration/` to assert the event consumption and ECS mapping logic works correctly against mock Redis streams.

---

## Acceptance Criteria

- [ ] The Python stream consumer successfully consumes synthetic events from the `events:connection` Redis stream.
- [ ] Nested ECS JSON fields are correctly mapped to flat variables for UI rendering.
- [ ] No unmapped action names (e.g. `monitor` or `challenge`) are introduced.
- [ ] `make test` executes with zero errors.

---

## Files to Modify

| File | Change |
|------|--------|
| `management/stream_consumer.py` | New file — console stream consumer reading `events:connection` with flat ECS parsing / mapping (the console lives at top-level `management/`, not `src/management/`) |
| `management/tests/test_stream_consumer.py` | New file — Unit tests validating flat-key ECS deserialization and mapping |
| `CHANGELOG.md` | Add Phase 321 entry |

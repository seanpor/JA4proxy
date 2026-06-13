# Event Stream Contract Alignment

## Goal

Resolve the contract mismatch between the Go proxy daemon and the Python management console. Standarise on `events:connection` as the single source of truth for proxy events. Implement the ECS key mapping in the console's stream consumer, ensuring it correctly reads the nested JSON event structure and uses the standard action enum: `allow, flag, rate_limit, tarpit, block, ban`.

---

## A — Event Stream Schema Definition

Verify and document the Go proxy's JSON event structure. The Go proxy currently writes to `events:connection` using ECS keys. The schema of each entry is a JSON blob stored in the `event` field.

```json
{
  "timestamp": "2026-06-12T12:00:00Z",
  "source": {
    "ip": "1.2.3.4",
    "port": 54321
  },
  "destination": {
    "ip": "10.0.0.5",
    "port": 443
  },
  "tls": {
    "ja4": "t13d1516h2_86f5c22de260_..."
  },
  "event": {
    "action": "allow",
    "score": 0
  }
}
```

---

## B — Console Stream Consumer Update

Modify the Python management console's consumer loop (typically in `src/management/app.py` or dedicated stream listener) to:
1. Listen on `events:connection` instead of `ja4proxy:events`.
2. Extract the `event` field from each stream payload.
3. Deserialise the JSON string.
4. Safely map nested ECS paths to flat fields needed by UI templates:
   - `event["source"]["ip"]` -> `ip`
   - `event["tls"]["ja4"]` -> `ja4`
   - `event["event"]["action"]` -> `action_taken` (ensure values map exactly to `allow, flag, rate_limit, tarpit, block, ban`)
   - `event["event"]["score"]` -> `risk_score`

Ensure the stream reader fails gracefully if keys are missing or parsing fails, avoiding process crashes.

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
| `src/management/stream_consumer.py` | Modify stream key to `events:connection` and add ECS parsing / mapping |
| `tests/unit/management/test_stream_consumer.py` | New file — Unit tests validating ECS deserialization and mapping |
| `CHANGELOG.md` | Add Phase 321 entry |

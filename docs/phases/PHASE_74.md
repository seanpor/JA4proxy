# PHASE 74 — Docker Isolation: Shared Assets & Tooling

## Status: OPEN

---

## Goal

Optimize the shared resource footprint and update administrative tools to support the multi-agent isolated environment.

---

## 74a. Shared GeoIP Asset Optimization

### Implementation

To save memory and disk, all agent stacks will mount the single `geoip/` directory as a read-only volume. This allows the OS to share the page cache for the memory-mapped `.BIN` file.

### Code Change: `docker-compose.poc.yml`

```yaml
services:
  proxy:
    volumes:
      - ./geoip:/app/geoip:ro  # Shared read-only asset
```

---

## 74b. Admin Tool Multi-Agent Support

### Implementation

Update `ja4-admin.sh` and `benchmark.py` to support an `--agent <name>` flag. The tools will then automatically source the corresponding `.env.<name>` to find the correct `AGENT_BIND_IP` and `REDIS_PASSWORD`.

### Code Example: `ja4-admin.sh` refinement

```bash
if [ "$1" == "--agent" ]; then
    AGENT=$2
    source .env.${AGENT}
    REDIS_HOST=${AGENT_BIND_IP}
fi
```

---

## Acceptance Criteria

- [ ] GeoIP shared as a read-only volume across all running agent stacks.
- [ ] `ja4-admin.sh` status command works with `--agent gemini`.
- [ ] `benchmark.py` correctly targets the isolated agent Proxy.
- [ ] `Makefile` includes `make agent-up NAME=...` target.

---

## Files to Modify

| File | Change |
|------|--------|
| `docker-compose.poc.yml` | Implement shared GeoIP volume |
| `Makefile` | Add multi-agent management targets |
| `scripts/ja4-admin.sh` | Add `--agent` flag support |
| `scripts/benchmark.py` | Add multi-agent targeting logic |
| `CHANGELOG.md` | Phase 74 entry |

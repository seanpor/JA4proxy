# PHASE 74 — Docker Isolation: Shared Assets & Tooling

## Status: OPEN

---

## Goal

Optimise the shared resource footprint and update administrative tools to support the
multi-agent isolated environment.

---

## 74a. Shared GeoIP Asset Optimisation

Mount the single `geoip/` directory as read-only across all agent stacks, allowing the
OS to share the page cache for the memory-mapped `.BIN` file.

```yaml
services:
  proxy:
    volumes:
      - ./config:/app/config:ro
      - ./logs:/app/logs
      - redis-sock:/var/run/redis
      - ./geoip:/app/geoip:ro    # shared read-only asset
```

The `geoip/` directory is at the repo root and is the same path for all agents (they all
mount the host repo). No per-agent copy needed — OS page cache handles sharing.

---

## 74b. Makefile Multi-Agent Targets

Add the following targets to `Makefile`. They wrap `docker compose` with the correct
project name and env file derived from `NAME=`.

```makefile
# ── Multi-Agent Lifecycle ──────────────────────────────────────────────────────
# Usage: make agent-up NAME=claude
#        make agent-down NAME=claude
#        make agent-status

agent-up:
	@[ -n "$(NAME)" ] || (echo "Usage: make agent-up NAME=<agent>"; exit 1)
	@[ -f ".env.$(NAME)" ] || (echo "→ No .env.$(NAME) found — generating..."; ./scripts/agent-env.sh $(NAME))
	docker compose --project-name ja4_$(NAME) --env-file .env.$(NAME) up -d
	@echo "✓ Agent $(NAME) started"
	@grep AGENT_BIND_IP .env.$(NAME) | awk -F= '{print "  Ingress:   https://" $$2 ":443"}'
	@grep AGENT_BIND_IP .env.$(NAME) | awk -F= '{print "  Analytics: http://" $$2 ":8080"}'

agent-down:
	@[ -n "$(NAME)" ] || (echo "Usage: make agent-down NAME=<agent>"; exit 1)
	@[ -f ".env.$(NAME)" ] || (echo "No .env.$(NAME) — is agent $(NAME) configured?"; exit 1)
	docker compose --project-name ja4_$(NAME) --env-file .env.$(NAME) down

agent-status:
	@echo "Running ja4_* projects:"
	@docker compose ls --filter name=ja4_ 2>/dev/null || docker ps --format '{{.Names}}' | grep '^ja4_' | sed 's/-[0-9]*$$//' | sort -u
```

Add `agent-up agent-down agent-status` to the `.PHONY` line.

Add to the `help` target echo block:

```makefile
	@echo "── Multi-Agent ──────────────────────────────────────────────────────"
	@echo "  agent-up   NAME=<agent>  - Start isolated agent environment"
	@echo "  agent-down NAME=<agent>  - Stop isolated agent environment"
	@echo "  agent-status             - List all running agent environments"
	@echo "  (agents: gemini | claude | ollama | mistral)"
```

---

## 74c. `ja4-admin.sh` Multi-Agent Support

`ja4-admin.sh` derives three runtime values from the environment:

| Variable | Default | Multi-agent override |
|----------|---------|---------------------|
| `ENV_FILE` | `.env` | `.env.<agent>` |
| `REDIS_CONTAINER` | `ja4proxy-redis` | `ja4_<agent>-redis-1` |
| `METRICS_URL` | `http://localhost:9090/metrics` | `http://<AGENT_BIND_IP>:9090/metrics` |

### Implementation

Add `--agent <name>` as the first two arguments, parsed before all other logic. Place
this block immediately after the variable defaults, before any command dispatch:

```bash
# ── Multi-agent support ────────────────────────────────────────────────────────
# Parse --agent flag if present (must be first two args)
if [[ "${1:-}" == "--agent" ]]; then
    AGENT_NAME="${2:?--agent requires a name (gemini|claude|ollama|mistral)}"
    shift 2
    ENV_FILE=".env.${AGENT_NAME}"
    [ -f "$ENV_FILE" ] || die "No $ENV_FILE found — run: ./scripts/agent-env.sh ${AGENT_NAME}"
    AGENT_BIND_IP=$(grep '^AGENT_BIND_IP=' "$ENV_FILE" | cut -d= -f2)
    [ -n "$AGENT_BIND_IP" ] || die "AGENT_BIND_IP not set in $ENV_FILE"
    REDIS_CONTAINER="ja4_${AGENT_NAME}-redis-1"
    METRICS_URL="http://${AGENT_BIND_IP}:9090/metrics"
fi
```

After this block, all existing commands (`status`, `top`, `block-ja4`, etc.) work
unchanged — they read `REDIS_CONTAINER`, `METRICS_URL`, and `ENV_FILE` which are now
pointing to the correct agent.

### Usage examples after change

```bash
# Default (no agent — uses .env, ja4proxy-redis, localhost:9090)
./scripts/ja4-admin.sh status

# Claude agent
./scripts/ja4-admin.sh --agent claude status
./scripts/ja4-admin.sh --agent gemini block-ja4 t13d190900_9dc949149365_97f8aa674fd9
./scripts/ja4-admin.sh --agent ollama top 5
```

### Impact on existing users

The `--agent` flag is optional and positional-first. All existing invocations without
`--agent` are 100% backward-compatible — no existing scripts or Makefile targets break.

---

## Acceptance Criteria

- [ ] `./geoip:/app/geoip:ro` volume present in proxy service.
- [ ] `make agent-up NAME=gemini` starts the stack if `.env.gemini` exists, or generates it first.
- [ ] `make agent-down NAME=gemini` stops and removes containers for that agent.
- [ ] `make agent-status` lists running `ja4_*` projects.
- [ ] `./scripts/ja4-admin.sh --agent gemini status` connects to the correct Redis container and metrics URL.
- [ ] `./scripts/ja4-admin.sh status` (no flag) still works identically to before.

---

## Files to Modify

| File | Change |
|------|--------|
| `docker-compose.poc.yml` | Add `./geoip:/app/geoip:ro` volume to proxy service |
| `Makefile` | Add `agent-up`, `agent-down`, `agent-status` targets and help text |
| `scripts/ja4-admin.sh` | Add `--agent` flag parsing block (exact code above) |
| `CHANGELOG.md` | Phase 74 entry |

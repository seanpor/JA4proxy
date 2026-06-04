# PHASE 74 — Docker Isolation: Shared Assets & Tooling

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

## 74b. Makefile Multi-Agent Targets and `.current-agent`

### The `.current-agent` file

`make agent-up NAME=<agent>` writes the agent name (e.g. `claude`) to `.current-agent`
in the repo root. This file acts as a local "active agent" pointer so you don't have to
repeat `NAME=` on every subsequent command.

| File | Purpose |
|------|---------|
| `.env.<agent>` | Per-agent secrets and config (IP, CPU set, passwords) |
| `.current-agent` | One-line file: the name of the most recently started agent |

Both files are gitignored (they contain machine-specific state and secrets).

**Priority order for targeting an agent:**
1. Explicit `NAME=<agent>` argument (always wins)
2. `.current-agent` file (set by the last `agent-up`)
3. Error — ask user to specify

### Makefile targets

Add the following targets to `Makefile`. They wrap `docker compose` with the correct
project name and env file derived from `NAME=`.

```makefile
# ── Multi-Agent Lifecycle ──────────────────────────────────────────────────────
# agent-up writes .current-agent so subsequent commands default to this agent.
# agent-down reads .current-agent if NAME= is not given.

agent-up:
	@[ -n "$(NAME)" ] || (echo "Usage: make agent-up NAME=<agent>"; exit 1)
	@[ -f ".env.$(NAME)" ] || (echo "→ No .env.$(NAME) found — generating..."; ./scripts/agent-env.sh $(NAME))
	docker compose --project-name ja4_$(NAME) --env-file .env.$(NAME) up -d
	@echo "$(NAME)" > .current-agent
	@echo "✓ Agent $(NAME) started (saved to .current-agent)"
	@grep AGENT_BIND_IP .env.$(NAME) | awk -F= '{print "  Ingress:   https://" $$2 ":443"}'
	@grep AGENT_BIND_IP .env.$(NAME) | awk -F= '{print "  Analytics: http://" $$2 ":8080"}'
	@grep AGENT_BIND_IP .env.$(NAME) | awk -F= '{print "  Metrics:   http://" $$2 ":9090/metrics"}'
	@echo "  Admin:     ./scripts/ja4-admin.sh status  (uses .current-agent automatically)"

agent-down:
	$(eval _NAME := $(or $(NAME),$(shell cat .current-agent 2>/dev/null)))
	@[ -n "$(_NAME)" ] || (echo "Usage: make agent-down NAME=<agent>"; exit 1)
	@[ -f ".env.$(_NAME)" ] || (echo "No .env.$(_NAME) found"; exit 1)
	docker compose --project-name ja4_$(_NAME) --env-file .env.$(_NAME) down
	@if [ "$$(cat .current-agent 2>/dev/null)" = "$(_NAME)" ]; then rm -f .current-agent; fi

agent-status:
	@echo "Running ja4_* agent environments:"
	@docker compose ls 2>/dev/null | grep '^ja4_' || echo "  (none running)"
	@if [ -f .current-agent ]; then echo "Current (.current-agent): $$(cat .current-agent)"; fi
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
# Default (no agent, no .current-agent — uses .env, ja4proxy-redis, localhost:9090)
./scripts/ja4-admin.sh status

# After make agent-up NAME=claude — .current-agent auto-used, no flag needed
./scripts/ja4-admin.sh status
./scripts/ja4-admin.sh top 5
./scripts/ja4-admin.sh block-ja4 t13d190900_9dc949149365_97f8aa674fd9

# Explicit override (ignores .current-agent)
./scripts/ja4-admin.sh --agent gemini status
./scripts/ja4-admin.sh --agent ollama top 5
```

### Agent resolution priority

| Condition | Env file used | Redis container | Metrics URL |
|-----------|--------------|-----------------|-------------|
| `--agent claude` passed | `.env.claude` | `ja4_claude-redis-1` | `127.0.0.11:9090` |
| `.current-agent` = `claude` | `.env.claude` | `ja4_claude-redis-1` | `127.0.0.11:9090` |
| Neither | `.env` | `ja4proxy-redis` | `localhost:9090` |

### Impact on existing users

The `--agent` flag and `.current-agent` fallback are both optional. All existing
invocations without `--agent` and without a `.current-agent` file are 100%
backward-compatible.

---

## Acceptance Criteria

- [x] `./geoip:/app/geoip:ro` volume present in proxy service.
- [x] `make agent-up NAME=gemini` starts the stack if `.env.gemini` exists, or generates it first.
- [x] `make agent-down NAME=gemini` stops and removes containers for that agent.
- [x] `make agent-status` lists running `ja4_*` projects.
- [x] `make agent-up NAME=claude` creates `.current-agent` containing `claude`.
- [x] `make agent-down` (no NAME) reads `.current-agent` and brings down the correct stack; clears `.current-agent`.
- [x] `make agent-down NAME=gemini` brings down gemini regardless of `.current-agent`.
- [x] `./scripts/ja4-admin.sh status` after `make agent-up NAME=claude` auto-targets claude via `.current-agent`.
- [x] `./scripts/ja4-admin.sh --agent gemini status` overrides `.current-agent` and targets gemini.
- [x] `./scripts/ja4-admin.sh status` with no `.current-agent` still works identically to before.

---

## Files to Modify

| File | Change |
|------|--------|
| `docker/docker-compose.poc.yml` | Add `./geoip:/app/geoip:ro` volume to proxy service |
| `Makefile` | Add `agent-up`, `agent-down`, `agent-status` targets and help text |
| `scripts/ja4-admin.sh` | Add `--agent` flag parsing block (exact code above) |
| `CHANGELOG.md` | Phase 74 entry |

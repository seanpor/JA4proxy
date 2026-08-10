"""Two-state regression test for Phase 814k — Redis ACL coverage + stream-key drift.

JA4PROXY-2026-0098  — analytics ACL user could not read the connection stream it
                      must consume (`~analytics:*` only; `xgroup_create` on the
                      real stream → NoPermissionError → crash-loop).
JA4PROXY-2026-0099  — proxy ACL user under-scoped: no `+script|load`, no
                      `~proxy:*`/`~concurrent:*`/`~audit:*`/`~events:connection`
                      patterns → rate limiting, audit trail, event stream and
                      pub/sub hot-reload all SILENTLY dead.
JA4PROXY-2026-0100  — stream-key drift: analytics consumed the retired
                      `ja4proxy:events`; the Go proxy writes `events:connection`.
JA4PROXY-2026-0101  — GDPR purge + PCI pack targeted `ja4proxy:events`, never
                      touching the PII-bearing `events:connection` stream.

This is a TWO-STATE test:
  * Pre-fix: the template granted none of the required proxy/analytics grants and
    purge/analytics pointed at different stream keys — these assertions FAIL.
  * Post-fix: all pass.

The canonical allow-lists below are verified against the Go proxy's actual Redis
usage (internal/redis/client.go, internal/security/*, internal/cluster/sync,
internal/webhook, internal/redis/pubsub.go, cmd/ja4pd) and the analytics node
(src/analytics, management/compliance).
"""

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TEMPLATE = REPO / "config" / "redis_acl.conf.template"
SETUP_SH = REPO / "scripts" / "redis-acl-setup.sh"
ANALYTICS_YAML = REPO / "config" / "analytics.yaml"
PROXY_YML = REPO / "config" / "proxy.yml"
PURGE_PY = REPO / "management" / "compliance" / "purge.py"
PACK_BUILDER_PY = REPO / "management" / "compliance" / "pack_builder.py"

STREAM_KEY = "events:connection"

# Canonical command set the Go proxy actually issues (verified from code).
PROXY_COMMANDS = frozenset(
    {
        "+get",
        "+set",
        "+del",
        "+expire",
        "+ttl",
        "+exists",
        "+incr",
        "+scan",
        "+zadd",
        "+zrange",
        "+zrangebyscore",
        "+zremrangebyscore",
        "+zcard",
        "+zincrby",
        "+sadd",
        "+srem",
        "+sismember",
        "+smembers",
        "+hset",
        "+hget",
        "+hincrby",
        "+hgetall",
        "+pfadd",
        "+pfcount",
        "+xadd",
        "+xread",
        "+xgroup",
        "+xreadgroup",
        "+xack",
        "+evalsha",
        "+eval",
        "+script|load",
        "+ping",
        "+subscribe",
    }
)

# Canonical key patterns the Go proxy actually touches (verified from code).
PROXY_KEYS = frozenset(
    {
        "~ratelimit:*",
        "~ban:*",
        "~ban_cidr:*",
        "~beacon:*",
        "~dns:*",
        "~abuseipdb:*",
        "~rdap:*",
        "~ja4:*",
        "~config:*",
        "~analytics:*",
        "~proxy:*",
        "~session:*",
        "~lifespan:*",
        "~concurrent:*",
        "~behavioral:burst:*",
        "~audit:*",
        "~offense:*",
        "~return_visitor:*",
        "~fp:*",
        "~geoip:*",
        "~events:connection",
        "~webhooks:dlq",
        "~ja4proxy:dc:*:sync:*",
    }
)

# Canonical key patterns the analytics node needs (its own output keys + the
# stream it consumes + the threat-intel feed state keys it writes).
ANALYTICS_KEYS = frozenset(
    {
        "~analytics:*",
        "~events:connection",
        "~ti_feed:*",
    }
)

# Canonical command set the analytics node actually issues (verified from code:
# src/analytics/stream_consumer.py, ti_feeds/state.py, security_hardening.py,
# monitoring.py). Explicit whitelist — NOT +@read/+@write, which would grant
# FLUSHALL/FLUSHDB/KEYS and other @keyspace/@write commands (verified live).
ANALYTICS_COMMANDS = frozenset(
    {
        "+get",
        "+set",
        "+hset",
        "+hget",
        "+hgetall",
        "+hdel",
        "+del",
        "+expire",
        "+incr",
        "+sadd",
        "+srem",
        "+smembers",
        "+zadd",
        "+zcard",
        "+zremrangebyrank",
        "+xadd",
        "+xrevrange",
        "+xread",
        "+xgroup",
        "+xreadgroup",
        "+xack",
        "+pfadd",
        "+ping",
        "+multi",
        "+exec",
        "+discard",
    }
)

# Commands analytics must never hold (categories that +@read/+@write would
# grant transitively). FLUSHALL is the load-bearing one — it returns OK with
# the broad categories, erasing ~*-protected shared keys.
ANALYTICS_BANNED_COMMANDS = frozenset(
    {
        "+flushall",
        "+flushdb",
        "+keys",
        "+dbsize",
        "+config",
        "+eval",
        "+evalsha",
        "+script",
        "+publish",
        "+subscribe",
        "+shutdown",
    }
)


def _acl_users_block() -> dict[str, set[str]]:
    """Parse the template into {user: set(acl tokens)}."""
    users: dict[str, set[str]] = {}
    for raw in TEMPLATE.read_text().splitlines():
        line = raw.strip()
        if not line.startswith("user "):
            continue
        tokens = line.split()
        # tokens[0]=user, tokens[1]=name, tokens[2]=on/off
        if len(tokens) >= 3 and tokens[1] in {"proxy", "analytics"}:
            users.setdefault(tokens[1], set()).update(tokens[3:])
    return users


def _setup_sh_acl_tokens(user: str) -> set[str]:
    """Extract the ACL SETUSER token set for a user from redis-acl-setup.sh.

    The script invokes ``redis-cli ... ACL SETUSER <user> on \\`` followed by
    one or more quoted token args (``"~pattern"``, ``"+CMD"``, ``"&chan"``)
    until the next redis-cli invocation or blank line. Tokens are case-
    normalised to lower-case to match the template's representation.
    """
    lines = SETUP_SH.read_text().splitlines()
    in_block = False
    tokens: set[str] = set()
    for line in lines:
        stripped = line.strip()
        if f"ACL SETUSER {user} on" in stripped:
            in_block = True
            continue
        if in_block:
            if "ACL SETUSER" in stripped or stripped.startswith("echo "):
                break
            for token in _quoted_tokens(stripped):
                tokens.add(token.lower())
    return tokens


def _quoted_tokens(line: str) -> list[str]:
    """Split a line into its double-quoted token args, handling continuation."""
    tokens: list[str] = []
    for part in line.split('"'):
        part = part.strip()
        if not part:
            continue
        if part.endswith("\\"):
            part = part[:-1].strip()
        if part:
            tokens.append(part)
    return tokens


def test_template_has_proxy_and_analytics_users():
    users = _acl_users_block()
    assert "proxy" in users, "template must define the proxy ACL user"
    assert "analytics" in users, "template must define the analytics ACL user"


KNOWN_UNKNOWN_ACL_COMMANDS = frozenset(
    {
        # Tokens that LOOK like Redis commands but are not resolvable in
        # Redis 7.4's ACL subsystem, so a single occurrence aborts the whole
        # ACL file at startup (verified live against redis:7.4.9-alpine).
        # go-redis's ZRangeWithScores issues plain ZRANGE ... WITHSCORES —
        # there is no separate zrangewithscores command.
        "+zrangewithscores",
    }
)


def test_no_unknown_acl_command_tokens():
    """No ACL token may reference a non-existent Redis command.

    Redis fails the ENTIRE ACL file (all users) if any one token is unknown,
    so an invalid token hidden in a grant makes every user unreachable and the
    container crash-loops. This pins the exact bug class of the redis recreate
    that exposed JA4PROXY-2026-0098's fix going live (the invalid token passed
    template-vs-setup.sh parity because it was present in BOTH).
    """
    for user in ("proxy", "analytics"):
        tokens = _acl_users_block().get(user, set())
        bad = KNOWN_UNKNOWN_ACL_COMMANDS & tokens
        assert not bad, (
            f"{user} ACL references non-existent Redis command(s): "
            f"{sorted(bad)} — Redis aborts the whole ACL file on these"
        )
        setup_tokens = _setup_sh_acl_tokens(user)
        bad_unit = {t.upper() for t in KNOWN_UNKNOWN_ACL_COMMANDS} & setup_tokens
        assert not bad_unit, (
            f"scripts/redis-acl-setup.sh {user} grant references non-existent "
            f"Redis command(s): {sorted(bad_unit)}"
        )


def test_proxy_acl_grants_every_command_the_go_proxy_uses():
    users = _acl_users_block()
    tokens = users["proxy"]
    missing = PROXY_COMMANDS - tokens
    assert not missing, (
        "proxy ACL is missing commands the Go proxy actually issues "
        f"(JA4PROXY-2026-0099): {sorted(missing)}"
    )


def test_proxy_acl_grants_every_key_the_go_proxy_touches():
    users = _acl_users_block()
    tokens = users["proxy"]
    missing = PROXY_KEYS - tokens
    assert not missing, (
        "proxy ACL is missing key patterns the Go proxy actually touches "
        f"(JA4PROXY-2026-0099): {sorted(missing)}"
    )


def test_analytics_acl_grants_stream_and_output_keys():
    users = _acl_users_block()
    tokens = users["analytics"]
    missing = ANALYTICS_KEYS - tokens
    assert not missing, (
        "analytics ACL is missing key patterns the analytics node needs "
        f"(JA4PROXY-2026-0098): {sorted(missing)}"
    )


def test_analytics_acl_grants_every_command_the_node_issues():
    users = _acl_users_block()
    tokens = users["analytics"]
    missing = ANALYTICS_COMMANDS - tokens
    assert not missing, (
        "analytics ACL is missing commands the node issues "
        f"(JA4PROXY-2026-0098): {sorted(missing)}"
    )


def test_analytics_acl_has_no_broad_categories_or_dangerous_commands():
    """Least privilege: analytics must not use category grants (+@read/+@write
    transitively allow FLUSHALL/FLUSHDB/KEYS etc.) nor hold dangerous commands
    outright. The broad categories passed the pre-fix suite because the old
    grant was too NARROW; they were removed in favour of an explicit
    whitelist after live validation showed FLUSHALL returned OK."""
    users = _acl_users_block()
    tokens = users["analytics"]
    for banned in ("+@all", "+@read", "+@write", "+@admin", "+@keyspace"):
        assert banned not in tokens, (
            f"analytics ACL must not use category grant {banned} "
            "(least privilege violated)"
        )
    for banned in ANALYTICS_BANNED_COMMANDS:
        assert banned not in tokens, (
            f"analytics ACL must not grant {banned} (least privilege violated)"
        )


def test_analytics_acl_preserves_least_privilege():
    """Analytics must NOT gain blanket key access (no `~*`, no `config:*`)."""
    users = _acl_users_block()
    tokens = users["analytics"]
    for banned in ("~*", "~config:*", "~ja4:*", "~ban:*"):
        assert banned not in tokens, (
            f"analytics ACL must not grant {banned} (least privilege violated)"
        )


def _without_passwords(tokens: set[str]) -> set[str]:
    """Drop password-token entries (``>${VAR}`` / ``>$PASS``) whose literal
    values legitimately differ between the template and the setup script."""
    return {t for t in tokens if not t.startswith(">")}


def test_setup_sh_proxy_grant_matches_template():
    """scripts/redis-acl-setup.sh (standalone path) must mirror the template."""
    template_tokens = _without_passwords(_acl_users_block()["proxy"])
    setup_tokens = _without_passwords(_setup_sh_acl_tokens("proxy"))
    missing = template_tokens - setup_tokens
    assert not missing, (
        "scripts/redis-acl-setup.sh proxy grant is missing template grants "
        f"(JA4PROXY-2026-0099): {sorted(missing)}"
    )


def test_setup_sh_analytics_grant_matches_template():
    template_tokens = _without_passwords(_acl_users_block()["analytics"])
    setup_tokens = _without_passwords(_setup_sh_acl_tokens("analytics"))
    missing = template_tokens - setup_tokens
    assert not missing, (
        "scripts/redis-acl-setup.sh analytics grant is missing template grants "
        f"(JA4PROXY-2026-0098): {sorted(missing)}"
    )


def test_all_stream_references_agree_on_events_connection():
    """Analytics, GDPR purge, PCI pack and proxy config must all use the same
    stream key — the one the Go proxy actually writes (JA4PROXY-2026-0100/0101)."""
    analytics_yaml = ANALYTICS_YAML.read_text()
    assert STREAM_KEY in analytics_yaml, (
        "config/analytics.yaml must reference events:connection (JA4PROXY-2026-0100)"
    )

    purge_src = PURGE_PY.read_text()
    assert STREAM_KEY in purge_src, (
        "management/compliance/purge.py must purge events:connection "
        "(JA4PROXY-2026-0101)"
    )
    assert "ja4proxy:events" not in purge_src, (
        "management/compliance/purge.py must not target the retired "
        "ja4proxy:events stream (JA4PROXY-2026-0101)"
    )

    pack_src = PACK_BUILDER_PY.read_text()
    assert STREAM_KEY in pack_src, (
        "management/compliance/pack_builder.py must read events:connection "
        "(JA4PROXY-2026-0101)"
    )
    assert "ja4proxy:events" not in pack_src, (
        "management/compliance/pack_builder.py must not read the retired "
        "ja4proxy:events stream (JA4PROXY-2026-0101)"
    )

    proxy_yml = PROXY_YML.read_text()
    assert STREAM_KEY in proxy_yml, (
        "config/proxy.yml must reference events:connection (Go proxy stream)"
    )


def test_purge_stream_key_constant_is_events_connection():
    """GDPRPurge.STREAM_KEY must be the real PII-bearing stream."""
    purge_src = PURGE_PY.read_text()
    assert '_STREAM_KEY = "events:connection"' in purge_src, (
        "purge.py _STREAM_KEY must be events:connection (JA4PROXY-2026-0101)"
    )

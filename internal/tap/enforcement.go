package tap

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

// Enforcement key prefixes and default TTLs (Phase 316d).
const (
	// banIntentKeyPrefix holds the advisory watchlist key the sensor always
	// writes for a blocklisted client. It lives under the fp:* namespace so the
	// sensor's least-privilege Redis ACL (~fp:* +set +expire) already permits it
	// — recording an intent never requires arming or a wider grant.
	banIntentKeyPrefix = "fp:ban_intent:ip:"
	// banKeyPrefix is the canonical operator-ban key the inline proxy already
	// hard-blocks on (internal/security/pipeline.go, phase-231a). Writing it is
	// the ONLY enforcing action the sensor takes, and only when armed — which
	// also requires the operator to widen the sensor's ACL to ~ban:*.
	banKeyPrefix = "ban:"
	// tapEnforcedBanValuePrefix marks a ban:{ip} value this sensor wrote, so a
	// re-check (D-001, or internal/security/pipeline.go on the read side) can
	// distinguish it from an operator ban without a separate key namespace.
	// internal/security/pipeline.go duplicates this exact string by contract
	// (the two packages don't share an import) — keep both sides in sync.
	tapEnforcedBanValuePrefix = "tap_enforce:"

	// defaultBanTTL bounds a sensor-written ban:{ip}. Short by the core
	// asymmetry: a blocked real user is the expensive error, so an enforced ban
	// expires quickly and the system fails open. Long enough to catch follow-up
	// connections from the same client; short enough to self-heal a misfire.
	defaultBanTTL = 5 * time.Minute
	// defaultIntentTTL bounds an advisory fp:ban_intent:ip watchlist entry. It
	// is longer than the ban TTL because the watchlist is for human/dashboard
	// review, not enforcement, so freshness matters less than the ban.
	defaultIntentTTL = time.Hour
)

// EnforcerConfig configures out-of-band enforcement. The zero value is the safe
// default: not armed, empty blocklist — Consider classifies and counts but
// writes nothing, so a passive misclassification can never produce a ban out of
// the box (the §"Safety" non-negotiable in PHASE_316d).
type EnforcerConfig struct {
	// Armed gates active blocking. When false (default), a blocklisted client is
	// recorded to the fp:ban_intent watchlist ONLY — nothing blocks; the
	// operator reviews the watchlist first (this is the monitor-first mode for
	// sensor enforcement). When true, a match ALSO writes ban:{ip}, which the
	// inline proxy enforces on the client's NEXT connection. Arming is a
	// conscious two-step: this flag AND a widened Redis ACL (~ban:*).
	Armed bool
	// JA4TBlocklist is the set of JA4T fingerprints that trigger enforcement.
	// Empty (default) → Consider can never fire. This mirrors the 316c advisory
	// consumer: zero entries means zero false positives, by construction.
	JA4TBlocklist map[string]bool
	// BanTTL bounds a sensor-written ban:{ip}. 0 → defaultBanTTL.
	BanTTL time.Duration
	// IntentTTL bounds an advisory fp:ban_intent:ip entry. 0 → defaultIntentTTL.
	IntentTTL time.Duration
}

// redisSetterGetter extends redisSetter with a Get, letting the Enforcer
// check for an existing ban before writing its own (D-001) without every
// other tap writer (Store) having to satisfy a wider interface.
type redisSetterGetter interface {
	redisSetter
	Get(ctx context.Context, key string) (string, error)
}

// Enforcer turns a blocklisted passive observation into an out-of-band ban
// intent. It writes through the same narrow redisSetter the Store uses, is
// fire-and-forget, and is fail-open in every branch: a Redis error is counted
// and dropped, never propagated and never escalated into a block.
type Enforcer struct {
	cfg   EnforcerConfig
	redis redisSetterGetter

	// blocklistMu guards blocklist (F-016). JA4TBlocklist is only ever set
	// once today (parseBlocklist at startup), but Wave 3's config-reload
	// support (R-009) makes a live-updated blocklist a near-term reality, and
	// a bare map read racing a reload's write is a runtime panic
	// (`concurrent map read and map write`), not a benign data race.
	blocklistMu sync.RWMutex
	blocklist   map[string]bool
}

// NewEnforcer builds an Enforcer over the given setter (nil for offline replay,
// in which case Consider counts but writes nothing). It normalises zero TTLs to
// their defaults and publishes the armed gauge so a scrape always reflects the
// running posture.
func NewEnforcer(cfg EnforcerConfig, r redisSetterGetter) *Enforcer {
	if cfg.BanTTL <= 0 {
		cfg.BanTTL = defaultBanTTL
	}
	if cfg.IntentTTL <= 0 {
		cfg.IntentTTL = defaultIntentTTL
	}
	if cfg.Armed {
		EnforcementArmed.Set(1)
	} else {
		EnforcementArmed.Set(0)
	}
	return &Enforcer{cfg: cfg, redis: r, blocklist: cfg.JA4TBlocklist}
}

// SetBlocklist atomically replaces the enforcement blocklist. Safe to call
// concurrently with Consider (e.g. from a config-reload handler) — see F-016.
func (e *Enforcer) SetBlocklist(bl map[string]bool) {
	if e == nil {
		return
	}
	e.blocklistMu.Lock()
	e.blocklist = bl
	e.blocklistMu.Unlock()
}

// Consider evaluates one observed connection. When the client's JA4T is on the
// enforcement blocklist it records a ban intent: always to the advisory
// fp:ban_intent:ip watchlist, and ALSO to ban:{ip} when armed. A non-matching
// JA4T, an empty blocklist, an empty ja4t (no SYN), an unparsable IP, or a nil
// backend all do nothing but count. The caller passes a deadline-bounded ctx so
// a slow Redis can never stall the capture drain.
func (e *Enforcer) Consider(ctx context.Context, clientIP, ja4t string) {
	if e == nil {
		return
	}
	// Cheapest rejections first — and the empty-blocklist short-circuit is what
	// makes the default configuration provably incapable of producing a ban.
	e.blocklistMu.RLock()
	blocked := ja4t != "" && e.blocklist[ja4t]
	empty := len(e.blocklist) == 0
	e.blocklistMu.RUnlock()
	if empty || ja4t == "" || !blocked {
		EnforcementActionsTotal.WithLabelValues(enfSkipped).Inc()
		return
	}
	ip := canonicalIP(clientIP)
	if ip == "" {
		EnforcementActionsTotal.WithLabelValues(enfError).Inc()
		return
	}
	if e.redis == nil {
		// Offline replay / dry run: a match is observable via the metric, but
		// there is nowhere to record it. Count as skipped, not error.
		EnforcementActionsTotal.WithLabelValues(enfSkipped).Inc()
		return
	}

	// Advisory watchlist write — always, even when armed: it is the audit trail
	// and the monitor-first surface. The value carries provenance.
	if err := e.redis.Set(ctx, banIntentKeyPrefix+ip, "ja4t="+ja4t, e.cfg.IntentTTL); err != nil {
		// Redis is unhealthy; do not attempt the (more dangerous) ban write.
		// A circuit-breaker skip (R-002) is a deliberate non-attempt, not an
		// observed failure -- count it as skipped, not error.
		if errors.Is(err, ErrRedisCircuitOpen) {
			EnforcementActionsTotal.WithLabelValues(enfSkipped).Inc()
		} else {
			EnforcementActionsTotal.WithLabelValues(enfError).Inc()
		}
		return
	}

	if !e.cfg.Armed {
		EnforcementActionsTotal.WithLabelValues(enfWatchlist).Inc()
		return
	}

	// D-001: don't clobber an operator's own ban:{ip}. An operator ban is
	// typically much longer-lived (hours to days) than the sensor's own
	// defaultBanTTL (5min); overwriting it here would silently shorten it
	// the moment this same client's next SYN arrives. If Redis can't be
	// queried (error or circuit open), fail safe by skipping the sensor's
	// write rather than risking an overwrite we can't rule out.
	existing, err := e.redis.Get(ctx, banKeyPrefix+ip)
	if err != nil {
		if errors.Is(err, ErrRedisCircuitOpen) {
			EnforcementActionsTotal.WithLabelValues(enfSkipped).Inc()
		} else {
			EnforcementActionsTotal.WithLabelValues(enfError).Inc()
		}
		return
	}
	if existing != "" && !strings.HasPrefix(existing, tapEnforcedBanValuePrefix) {
		EnforcementActionsTotal.WithLabelValues(enfOperatorOverride).Inc()
		return
	}

	// Armed: escalate to an enforceable ban the inline proxy reads on the next
	// connection from this IP. Value carries provenance so the ban is
	// attributable (and redactable — see internal/logging/redactor.go).
	if err := e.redis.Set(ctx, banKeyPrefix+ip, tapEnforcedBanValuePrefix+"ja4t="+ja4t, e.cfg.BanTTL); err != nil {
		if errors.Is(err, ErrRedisCircuitOpen) {
			EnforcementActionsTotal.WithLabelValues(enfSkipped).Inc()
		} else {
			EnforcementActionsTotal.WithLabelValues(enfError).Inc()
		}
		return
	}
	EnforcementActionsTotal.WithLabelValues(enfBanned).Inc()
}

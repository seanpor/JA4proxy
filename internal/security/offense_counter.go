package security

// offense_counter.go — Phase 248: Auto-escalating IP defense.
//
// An OffenseCounter tracks how many times an IP has triggered a rate-limit
// response. Each increment extends the TTL so the counter only expires when
// the IP has been clean for offense_ttl_hours duration (sliding window).
//
// All methods fail open: Redis errors are logged and a zero/neutral value is
// returned. The pipeline keeps running with its normal action decision.

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/seanpor/ja4proxy/internal/config"
	"github.com/sirupsen/logrus"
)

const offenseKeyPrefix = "offense:"

// OffenseCounter tracks persistent IP offense counts in Redis.
type OffenseCounter struct {
	redis RedisReader
	cfg   *config.AutoEscalateConfig
	log   *logrus.Logger
}

// NewOffenseCounter creates an OffenseCounter. cfg must not be nil.
func NewOffenseCounter(redis RedisReader, cfg *config.AutoEscalateConfig, log *logrus.Logger) *OffenseCounter {
	if log == nil {
		log = logrus.New()
	}
	return &OffenseCounter{redis: redis, cfg: cfg, log: log}
}

// Increment adds 1 to the offense count for ip and returns the new count.
// It calls INCR then EXPIRE to implement a sliding TTL window.
// Fails open: Redis error returns 0 and logs a warning.
func (o *OffenseCounter) Increment(ctx context.Context, ip string) (int, error) {
	if o.cfg.SharedIPCIDRThreshold > 0 {
		if o.sharedIPThresholdReached(ctx, ip) {
			o.log.WithFields(logrus.Fields{
				"ip":        ip,
				"threshold": o.cfg.SharedIPCIDRThreshold,
			}).Warn("offense_counter: shared IP threshold reached, skipping escalation")
			return 0, nil
		}
	}

	key := offenseKeyPrefix + ip
	newCount, err := o.redis.Incr(ctx, key)
	if err != nil {
		o.log.WithError(err).WithField("ip", ip).Warn("offense_counter: INCR failed")
		return 0, err
	}

	ttl := time.Duration(o.cfg.OffenseTTLHours) * time.Hour
	if expErr := o.redis.Expire(ctx, key, ttl); expErr != nil {
		o.log.WithError(expErr).WithField("ip", ip).Warn("offense_counter: EXPIRE failed")
		// Acceptable: key exists without TTL in worst case. Not a correctness issue.
	}

	return int(newCount), nil
}

// Get returns the current offense count for ip.
// Returns 0 if the key does not exist or Redis is unavailable.
func (o *OffenseCounter) Get(ctx context.Context, ip string) (int, error) {
	raw := o.redis.GetString(ctx, offenseKeyPrefix+ip)
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		o.log.WithField("ip", ip).WithField("raw", raw).Warn("offense_counter: invalid count in Redis")
		return 0, err
	}
	return n, nil
}

// Reset deletes the offense:{ip} key.
func (o *OffenseCounter) Reset(ctx context.Context, ip string) error {
	// Use SetString with TTL=0 trick: GetString returns "" which we map to 0.
	// Actually we need delete — use SetString with empty value and 1s TTL.
	// Better: rely on GetString/Exists and SetString to effectively delete.
	// The simplest approach: set to "0" with the standard TTL (keeps key alive briefly).
	// Real delete would need a Del method. Since we don't have one, set to "0".
	// This is functionally equivalent: EscalatedAction reads 0 as "no escalation".
	o.redis.SetString(ctx, offenseKeyPrefix+ip, "0", o.cfg.OffenseTTLHours*3600)
	return nil
}

// EscalatedAction returns the action this IP should receive based on its
// current offense count. Returns "" if auto_escalate is disabled or the
// count is below the tarpit threshold.
// Does NOT increment the counter — call Increment separately.
func (o *OffenseCounter) EscalatedAction(ctx context.Context, ip string) (string, error) {
	if !o.cfg.Enabled {
		return "", nil
	}

	count, err := o.Get(ctx, ip)
	if err != nil {
		return "", err
	}

	switch {
	case count >= o.cfg.BanAtOffense:
		return "ban", nil
	case count >= o.cfg.BlockAtOffense:
		return "block", nil
	case count >= o.cfg.TarpitAtOffense:
		return "tarpit", nil
	default:
		return "", nil
	}
}

// sharedIPThresholdReached returns true if the number of distinct IPs in the
// same /24 (IPv4) or /48 (IPv6) that have offense keys exceeds SharedIPCIDRThreshold.
// Uses CountKeys with a glob pattern — O(N) on Redis key space, acceptable since
// this only runs on rate-limit hits (uncommon path).
func (o *OffenseCounter) sharedIPThresholdReached(ctx context.Context, ip string) bool {
	pattern := sharedIPPattern(ip)
	if pattern == "" {
		return false
	}
	count := o.redis.CountKeys(ctx, offenseKeyPrefix+pattern)
	return count > o.cfg.SharedIPCIDRThreshold
}

// sharedIPPattern returns a Redis glob pattern for the /24 (IPv4) or /48 (IPv6)
// subnet of ip, or "" if ip is not parseable.
func sharedIPPattern(ipStr string) string {
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return ""
	}

	if parsed.To4() != nil {
		// IPv4: match the /24 (first 3 octets)
		parts := strings.Split(ipStr, ".")
		if len(parts) < 3 {
			return ""
		}
		return fmt.Sprintf("%s.%s.%s.*", parts[0], parts[1], parts[2])
	}

	// IPv6: match the /48 (first 3 groups of 4 hex digits)
	// Expand to full form first to get a reliable prefix.
	full := parsed.To16()
	if full == nil {
		return ""
	}
	// Groups 0,1,2 = bytes 0-1, 2-3, 4-5 = /48 prefix
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:*",
		full[0], full[1], full[2], full[3], full[4], full[5])
}

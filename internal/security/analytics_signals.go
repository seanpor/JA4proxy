package security

import (
	"context"
	"fmt"
	"net"

	"github.com/sirupsen/logrus"
)

// GetAnalyticsSignals returns risk signals from pre-computed analytics findings.
// Reads Redis keys written by the Python analytics container.
// Always returns complete slice or empty slice — never partial (fail open).
func GetAnalyticsSignals(ctx context.Context, redis RedisReader, clientIP string, log *logrus.Logger) []RiskSignal {
	if redis == nil {
		return nil
	}
	subnet := deriveSubnet(clientIP)
	if subnet == "" {
		return nil
	}

	var signals []RiskSignal
	if redis.Exists(ctx, fmt.Sprintf("analytics:campaign:%s", subnet)) {
		signals = append(signals, RiskSignal{
			Name:   "analytics_campaign",
			Score:  35,
			Reason: "subnet flagged as part of coordinated campaign",
			Weight: 1.0,
		})
	}
	if redis.Exists(ctx, fmt.Sprintf("analytics:slowscan:%s", subnet)) {
		signals = append(signals, RiskSignal{
			Name:   "analytics_slowscan",
			Score:  30,
			Reason: "subnet flagged for slow-scan activity",
			Weight: 1.0,
		})
	}
	return signals
}

// deriveSubnet returns the /24 (IPv4) or /48 (IPv6) subnet for an IP.
func deriveSubnet(clientIP string) string {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return ""
	}
	if ip.To4() != nil {
		mask := net.CIDRMask(24, 32)
		return fmt.Sprintf("%s/24", ip.Mask(mask).String())
	}
	mask := net.CIDRMask(48, 128)
	return fmt.Sprintf("%s/48", ip.Mask(mask).String())
}

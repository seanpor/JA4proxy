package security

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/yl2chen/cidranger"
)

// BlocklistFeedConfig configures one blocklist feed.
type BlocklistFeedConfig struct {
	Name    string
	Enabled bool
	Path    string
	IsBlock bool // true = hard block; false = scored signal
	Score   int
}

// BlocklistConfig holds all feed configurations.
type BlocklistConfig struct {
	Feeds []BlocklistFeedConfig
}

type blocklistFeed struct {
	name    string
	isBlock bool
	score   int
	ranger  cidranger.Ranger
}

// BlocklistManager holds in-process CIDR tries for all configured feeds.
type BlocklistManager struct {
	feeds []blocklistFeed
	log   *logrus.Logger
}

// NewBlocklistManager loads all enabled feeds from disk.
// Missing feed files are skipped (fail open).
func NewBlocklistManager(cfg *BlocklistConfig, log *logrus.Logger) *BlocklistManager {
	if log == nil {
		log = logrus.New()
	}
	m := &BlocklistManager{log: log}
	if cfg == nil {
		return m
	}
	for _, fc := range cfg.Feeds {
		if !fc.Enabled {
			continue
		}
		ranger := cidranger.NewPCTrieRanger()
		loaded := 0
		if fc.Path != "" {
			f, err := os.Open(fc.Path)
			if err != nil {
				log.WithError(err).WithField("feed", fc.Name).Debug("blocklist: feed file not found; skipping")
				continue
			}
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
					continue
				}
				// Handle plain IPs (add /32 or /128)
				if !strings.Contains(line, "/") {
					if strings.Contains(line, ":") {
						line = line + "/128"
					} else {
						line = line + "/32"
					}
				}
				_, network, err := net.ParseCIDR(line)
				if err != nil {
					continue
				}
				ranger.Insert(cidranger.NewBasicRangerEntry(*network))
				loaded++
			}
			f.Close()
		}
		log.WithFields(logrus.Fields{"feed": fc.Name, "cidrs": loaded}).Debug("blocklist: feed loaded")
		m.feeds = append(m.feeds, blocklistFeed{
			name: fc.Name, isBlock: fc.IsBlock, score: fc.Score, ranger: ranger,
		})
	}
	return m
}

// Check returns (signals, hardBlock) for the client IP.
// hardBlock=true means block immediately; signals will be nil.
// Returns (nil, false) if no feed matched.
func (m *BlocklistManager) Check(clientIP string) (signals []RiskSignal, hardBlock bool) {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return nil, false
	}
	for _, feed := range m.feeds {
		contains, err := feed.ranger.Contains(ip)
		if err != nil || !contains {
			continue
		}
		if feed.isBlock {
			return nil, true
		}
		return []RiskSignal{{
			Name:   fmt.Sprintf("blocklist_%s", feed.name),
			Score:  feed.score,
			Reason: fmt.Sprintf("IP matched blocklist feed: %s", feed.name),
			Weight: 1.0,
		}}, false
	}
	return nil, false
}

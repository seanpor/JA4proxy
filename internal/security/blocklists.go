package security

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/seanpor/ja4proxy/internal/metrics"
	"github.com/sirupsen/logrus"
	"github.com/yl2chen/cidranger"
)

// BlocklistFeedConfig configures one blocklist feed.
type BlocklistFeedConfig struct {
	Name                   string
	Enabled                bool
	URL                    string
	Format                 string
	IsBypass               bool
	Action                 string
	Score                  int
	RefreshIntervalSeconds int
	Path                   string // Local cache path for warm-start / persisted downloads
}

// BlocklistConfig holds all feed configurations.
type BlocklistConfig struct {
	Feeds []BlocklistFeedConfig
}

// rangerBox wraps a Ranger so the live trie can be swapped atomically while
// Check() reads it lock-free. cidranger.Ranger is an interface, so we box it to
// get a concrete pointer type for atomic.Pointer.
type rangerBox struct {
	ranger cidranger.Ranger
}

type blocklistFeed struct {
	name     string
	isBypass bool
	action   string
	score    int
	ranger   atomic.Pointer[rangerBox]
}

// BlocklistManager holds in-process CIDR tries for all configured feeds. Each
// feed's trie can be atomically replaced at runtime by the feed downloader
// (phase-309 WP-6) without locking the Check() hot path.
type BlocklistManager struct {
	feeds []*blocklistFeed
	log   *logrus.Logger
}

// NewBlocklistManager creates a manager with one entry per enabled feed. Each
// feed starts with an empty trie; if a warm-start cache file exists at Path it
// is loaded immediately. Feeds are always registered (even with an empty trie)
// so the downloader can populate them later. Fail open: a missing or unreadable
// cache file is logged and skipped, never fatal.
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
		feed := &blocklistFeed{
			name:     fc.Name,
			isBypass: fc.IsBypass,
			action:   fc.Action,
			score:    fc.Score,
		}
		feed.ranger.Store(&rangerBox{ranger: cidranger.NewPCTrieRanger()})

		if fc.Path != "" {
			if f, err := os.Open(fc.Path); err != nil {
				log.WithError(err).WithField("feed", fc.Name).Debug("blocklist: cache file not found; starting empty")
			} else {
				ranger, loaded, perr := BuildRanger(f, fc.Format)
				if cerr := f.Close(); cerr != nil {
					log.WithError(cerr).Warn("blocklist: error closing cache file")
				}
				if perr != nil {
					log.WithError(perr).WithField("feed", fc.Name).Warn("blocklist: failed to parse cache file")
				} else {
					feed.ranger.Store(&rangerBox{ranger: ranger})
					log.WithFields(logrus.Fields{"feed": fc.Name, "cidrs": loaded}).Debug("blocklist: warm-started from cache")
				}
			}
		}
		m.feeds = append(m.feeds, feed)
	}
	return m
}

// BuildRanger parses CIDR/IP entries from r into a fresh trie. format selects
// the line grammar: "spamhaus"/"cidr"/"" take the first whitespace token as the
// CIDR (Spamhaus DROP lines look like "1.2.3.0/24 ; SBL123"); "ipset" takes the
// CIDR from an `add <set> <cidr>` save line. Bare IPs are promoted to /32 (v4)
// or /128 (v6). Unparseable lines are skipped. Returns the trie and the count
// of inserted entries.
func BuildRanger(r io.Reader, format string) (cidranger.Ranger, int, error) {
	ranger := cidranger.NewPCTrieRanger()
	loaded := 0
	scanner := bufio.NewScanner(r)
	// Allow long lines (some feeds annotate generously).
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		token, ok := parseFeedLine(scanner.Text(), format)
		if !ok {
			continue
		}
		_, network, err := net.ParseCIDR(token)
		if err != nil {
			continue
		}
		if err := ranger.Insert(cidranger.NewBasicRangerEntry(*network)); err != nil {
			continue
		}
		loaded++
	}
	if err := scanner.Err(); err != nil {
		return ranger, loaded, err
	}
	return ranger, loaded, nil
}

// parseFeedLine extracts a CIDR token from a single feed line, or returns
// ok=false for blank/comment/unusable lines. The returned token always contains
// a prefix length (bare IPs are promoted to /32 or /128).
func parseFeedLine(raw, format string) (string, bool) {
	line := strings.TrimSpace(raw)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return "", false
	}
	fields := strings.Fields(line)
	var token string
	switch strings.ToLower(format) {
	case "ipset":
		// `add <setname> <cidr> [options...]`
		if len(fields) < 3 || !strings.EqualFold(fields[0], "add") {
			return "", false
		}
		token = fields[2]
	default:
		// spamhaus / cidr / plain: first token is the address.
		token = fields[0]
	}
	if !strings.Contains(token, "/") {
		if strings.Contains(token, ":") {
			token += "/128"
		} else {
			token += "/32"
		}
	}
	return token, true
}

// ReplaceFeed atomically swaps the live trie for the named feed. Returns false
// if no feed with that name is registered. Safe to call concurrently with
// Check(); readers see either the old or new trie, never a partial one.
func (m *BlocklistManager) ReplaceFeed(name string, ranger cidranger.Ranger) bool {
	for _, feed := range m.feeds {
		if feed.name == name {
			feed.ranger.Store(&rangerBox{ranger: ranger})
			return true
		}
	}
	return false
}

// Check returns (signals, hardBlock) for the client IP.
// hardBlock=true means block immediately; signals will be nil.
// Returns (nil, false) if no feed matched.
func (m *BlocklistManager) Check(ip net.IP) (signals []RiskSignal, hardBlock bool) {
	start := time.Now()
	defer func() {
		metrics.PipelineDurationSeconds.Observe(float64(time.Since(start).Seconds()))
	}()
	if ip == nil {
		return nil, false
	}
	for _, feed := range m.feeds {
		box := feed.ranger.Load()
		if box == nil {
			continue
		}
		contains, err := box.ranger.Contains(ip)
		if err != nil || !contains {
			continue
		}
		if feed.isBypass && feed.action == "block" {
			return nil, true
		}
		metrics.BlocklistMatchesTotal.WithLabelValues(feed.name).Inc()
		return []RiskSignal{{
			Name:   fmt.Sprintf("blocklist_%s", feed.name),
			Score:  feed.score,
			Reason: fmt.Sprintf("IP matched blocklist feed: %s", feed.name),
			Weight: 1.0,
		}}, false
	}
	return nil, false
}

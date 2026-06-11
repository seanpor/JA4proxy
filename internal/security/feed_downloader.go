package security

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/seanpor/ja4proxy/internal/metrics"
	"github.com/sirupsen/logrus"
)

const (
	// maxFeedBytes bounds a single feed download so a hostile or misbehaving
	// origin cannot OOM the proxy. Spamhaus DROP/EDROP are well under 1 MiB;
	// 64 MiB is a generous ceiling for any sane CIDR feed.
	maxFeedBytes = 64 << 20
	// minRefreshInterval clamps the configured interval so a typo
	// (refresh_interval_seconds: 1) cannot turn into a self-inflicted DoS on
	// the feed origin. Spamhaus asks downloaders not to poll more than hourly.
	minRefreshInterval = 60 * time.Second
	// defaultRefreshInterval matches config/proxy.yml (12h) when unset.
	defaultRefreshInterval = 12 * time.Hour
)

// FeedDownloader periodically downloads blocklist feeds and atomically swaps
// the parsed CIDR tries into a BlocklistManager. Each feed refreshes on its own
// timer; a transport/parse failure keeps the last-good trie (fail safe — we
// never blank out an existing blocklist because a single fetch failed).
//
// phase-309 WP-6. There is deliberately no leader election: every proxy
// instance downloads independently. Spamhaus permits hourly polling and the
// feeds are small, so N instances fetching every 12h is well within limits, and
// independence means a feed stays fresh even if a would-be "leader" is down.
// See docs/decisions/ADR-204.md.
type FeedDownloader struct {
	feeds   []BlocklistFeedConfig
	manager *BlocklistManager
	http    *http.Client
	log     *logrus.Logger

	mu    sync.Mutex
	etags map[string]string
}

// NewFeedDownloader builds a downloader for the enabled, URL-bearing feeds in
// cfg. Feeds without a URL (warm-start-from-disk only) are ignored here.
func NewFeedDownloader(feeds []BlocklistFeedConfig, manager *BlocklistManager, log *logrus.Logger) *FeedDownloader {
	if log == nil {
		log = logrus.New()
	}
	return &FeedDownloader{
		feeds:   feeds,
		manager: manager,
		log:     log,
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
		etags: make(map[string]string),
	}
}

// Start launches one refresh goroutine per downloadable feed. Each does an
// immediate refresh at boot (so blocking is live without waiting a full
// interval) and then refreshes on its interval until ctx is cancelled.
func (d *FeedDownloader) Start(ctx context.Context) {
	if d == nil || d.manager == nil {
		return
	}
	for i := range d.feeds {
		fc := d.feeds[i]
		if !fc.Enabled || fc.URL == "" {
			continue
		}
		go d.runFeed(ctx, fc)
	}
}

func (d *FeedDownloader) runFeed(ctx context.Context, fc BlocklistFeedConfig) {
	interval := time.Duration(fc.RefreshIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = defaultRefreshInterval
	}
	if interval < minRefreshInterval {
		d.log.WithFields(logrus.Fields{"feed": fc.Name, "configured_seconds": fc.RefreshIntervalSeconds}).
			Warn("blocklist: refresh interval below minimum; clamping to 60s")
		interval = minRefreshInterval
	}

	d.Refresh(ctx, fc)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.Refresh(ctx, fc)
		}
	}
}

// Refresh downloads one feed and swaps it into the manager on success. It is
// safe to call directly (the tests do). All failure paths are non-fatal: the
// download-error counter is incremented and the previous trie is retained.
func (d *FeedDownloader) Refresh(ctx context.Context, fc BlocklistFeedConfig) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fc.URL, nil)
	if err != nil {
		d.fail(fc.Name, err, "request build failed")
		return
	}
	d.mu.Lock()
	if etag := d.etags[fc.Name]; etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	d.mu.Unlock()

	resp, err := d.http.Do(req)
	if err != nil {
		d.fail(fc.Name, err, "download failed")
		return
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxFeedBytes))
		_ = resp.Body.Close()
	}()

	// 304: our cached copy is still current. That counts as a successful
	// refresh for staleness purposes — the data we are serving is confirmed
	// up to date.
	if resp.StatusCode == http.StatusNotModified {
		metrics.BlocklistLastRefreshSuccessSeconds.WithLabelValues(fc.Name).Set(float64(time.Now().Unix()))
		d.log.WithField("feed", fc.Name).Debug("blocklist: feed unchanged (304)")
		return
	}
	if resp.StatusCode != http.StatusOK {
		d.fail(fc.Name, fmt.Errorf("unexpected status %d", resp.StatusCode), "bad status")
		return
	}

	// Read the body once (bounded), so we can both parse it and persist the
	// raw bytes for warm restart. cidranger is not enumerable, so we cache the
	// source text rather than the trie.
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes))
	if err != nil {
		d.fail(fc.Name, err, "read failed")
		return
	}
	ranger, loaded, err := BuildRanger(bytes.NewReader(data), fc.Format)
	if err != nil {
		d.fail(fc.Name, err, "parse failed")
		return
	}
	// A zero-entry result almost always means a truncated or corrupted
	// download (Spamhaus DROP is never empty). Refuse to swap in an empty
	// trie — keep the last-good data rather than silently disabling the feed.
	if loaded == 0 {
		d.fail(fc.Name, fmt.Errorf("feed parsed to 0 entries"), "empty feed")
		return
	}

	d.manager.ReplaceFeed(fc.Name, ranger)
	if etag := resp.Header.Get("ETag"); etag != "" {
		d.mu.Lock()
		d.etags[fc.Name] = etag
		d.mu.Unlock()
	}
	d.persist(fc, data)
	metrics.BlocklistLastRefreshSuccessSeconds.WithLabelValues(fc.Name).Set(float64(time.Now().Unix()))
	d.log.WithFields(logrus.Fields{"feed": fc.Name, "cidrs": loaded}).Info("blocklist: feed refreshed")
}

// fail records a download failure: bump the error counter, log a warning, and
// leave the existing trie untouched.
func (d *FeedDownloader) fail(feed string, err error, msg string) {
	metrics.BlocklistDownloadErrorsTotal.WithLabelValues(feed).Inc()
	d.log.WithError(err).WithField("feed", feed).Warn("blocklist: " + msg + "; keeping last-good data")
}

// persist writes the raw feed body to the feed's cache path for warm restart,
// via a temp file + atomic rename so a crash mid-write never leaves a truncated
// cache. Best-effort: a missing path or any I/O error is logged, never fatal.
func (d *FeedDownloader) persist(fc BlocklistFeedConfig, data []byte) {
	if fc.Path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(fc.Path), 0o755); err != nil {
		d.log.WithError(err).WithField("feed", fc.Name).Warn("blocklist: could not create cache dir")
		return
	}
	tmp := fc.Path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		d.log.WithError(err).WithField("feed", fc.Name).Warn("blocklist: could not write cache file")
		return
	}
	if err := os.Rename(tmp, fc.Path); err != nil {
		d.log.WithError(err).WithField("feed", fc.Name).Warn("blocklist: could not rename cache file")
		_ = os.Remove(tmp)
	}
}

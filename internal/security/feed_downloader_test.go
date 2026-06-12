package security

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/seanpor/ja4proxy/internal/metrics"
)

// spamhausBody mimics a real Spamhaus DROP file: CIDRs followed by a
// "; SBLnnn" annotation, plus comment lines the parser must skip.
const spamhausBody = `; Spamhaus DROP List test fixture
; updated whenever
1.2.3.0/24 ; SBL12345
10.0.0.0/8 ; SBL67890
`

func newDownloadableFeed(name, url, path string) BlocklistFeedConfig {
	return BlocklistFeedConfig{
		Name:                   name,
		Enabled:                true,
		URL:                    url,
		Format:                 "spamhaus",
		Action:                 "score",
		Score:                  50,
		RefreshIntervalSeconds: 43200,
		Path:                   path,
	}
}

func TestFeedDownloader_RefreshPopulatesTrie(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte(spamhausBody))
	}))
	defer srv.Close()

	cachePath := filepath.Join(t.TempDir(), "drop.txt")
	feed := newDownloadableFeed("spamhaus_drop", srv.URL, cachePath)
	mgr := NewBlocklistManager(&BlocklistConfig{Feeds: []BlocklistFeedConfig{feed}}, nil)

	// Nothing loaded yet.
	if sigs, _ := mgr.Check(net.ParseIP("1.2.3.4")); len(sigs) != 0 {
		t.Fatalf("pre-refresh: expected no match, got %d signals", len(sigs))
	}

	before := testutil.ToFloat64(metrics.BlocklistLastRefreshSuccessSeconds.WithLabelValues("spamhaus_drop"))
	d := NewFeedDownloader([]BlocklistFeedConfig{feed}, mgr, nil)
	d.Refresh(context.Background(), feed)

	sigs, hard := mgr.Check(net.ParseIP("1.2.3.4"))
	if hard {
		t.Fatal("score feed should not hard-block")
	}
	if len(sigs) != 1 || sigs[0].Score != 50 {
		t.Fatalf("post-refresh: expected one score-50 signal, got %+v", sigs)
	}
	if after := testutil.ToFloat64(metrics.BlocklistLastRefreshSuccessSeconds.WithLabelValues("spamhaus_drop")); after <= before {
		t.Errorf("last_refresh_success gauge not advanced: before=%v after=%v", before, after)
	}
	// Cache file persisted for warm restart.
	if _, err := os.Stat(cachePath); err != nil {
		t.Errorf("cache file not written: %v", err)
	}
	// ETag remembered.
	if d.etags["spamhaus_drop"] != `"v1"` {
		t.Errorf("etag not stored, got %q", d.etags["spamhaus_drop"])
	}
}

func TestFeedDownloader_NotModifiedKeepsData(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		_, _ = w.Write([]byte(spamhausBody))
	}))
	defer srv.Close()

	feed := newDownloadableFeed("spamhaus_drop", srv.URL, "")
	mgr := NewBlocklistManager(&BlocklistConfig{Feeds: []BlocklistFeedConfig{feed}}, nil)
	d := NewFeedDownloader([]BlocklistFeedConfig{feed}, mgr, nil)

	d.Refresh(context.Background(), feed) // 200, populates + stores etag
	errsBefore := testutil.ToFloat64(metrics.BlocklistDownloadErrorsTotal.WithLabelValues("spamhaus_drop"))
	d.Refresh(context.Background(), feed) // 304, data retained

	if calls != 2 {
		t.Fatalf("expected 2 server calls, got %d", calls)
	}
	if sigs, _ := mgr.Check(net.ParseIP("10.1.2.3")); len(sigs) != 1 {
		t.Errorf("after 304: data should be retained, got %d signals", len(sigs))
	}
	if errs := testutil.ToFloat64(metrics.BlocklistDownloadErrorsTotal.WithLabelValues("spamhaus_drop")); errs != errsBefore {
		t.Errorf("304 must not count as a download error: before=%v after=%v", errsBefore, errs)
	}
}

func TestFeedDownloader_ErrorKeepsLastGood(t *testing.T) {
	fail := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(spamhausBody))
	}))
	defer srv.Close()

	feed := newDownloadableFeed("err_feed", srv.URL, "")
	mgr := NewBlocklistManager(&BlocklistConfig{Feeds: []BlocklistFeedConfig{feed}}, nil)
	d := NewFeedDownloader([]BlocklistFeedConfig{feed}, mgr, nil)

	d.Refresh(context.Background(), feed) // good
	errsBefore := testutil.ToFloat64(metrics.BlocklistDownloadErrorsTotal.WithLabelValues("err_feed"))

	fail = true
	d.Refresh(context.Background(), feed) // 500

	if errs := testutil.ToFloat64(metrics.BlocklistDownloadErrorsTotal.WithLabelValues("err_feed")); errs != errsBefore+1 {
		t.Errorf("download error not counted: before=%v after=%v", errsBefore, errs)
	}
	// Last-good trie must still match.
	if sigs, _ := mgr.Check(net.ParseIP("1.2.3.4")); len(sigs) != 1 {
		t.Errorf("after failed refresh: last-good data must be retained, got %d signals", len(sigs))
	}
}

func TestFeedDownloader_EmptyFeedRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("; only comments\n; nothing parseable\n"))
	}))
	defer srv.Close()

	feed := newDownloadableFeed("empty_feed", srv.URL, "")
	mgr := NewBlocklistManager(&BlocklistConfig{Feeds: []BlocklistFeedConfig{feed}}, nil)
	d := NewFeedDownloader([]BlocklistFeedConfig{feed}, mgr, nil)

	errsBefore := testutil.ToFloat64(metrics.BlocklistDownloadErrorsTotal.WithLabelValues("empty_feed"))
	d.Refresh(context.Background(), feed)

	if errs := testutil.ToFloat64(metrics.BlocklistDownloadErrorsTotal.WithLabelValues("empty_feed")); errs != errsBefore+1 {
		t.Errorf("empty feed should count as a download error: before=%v after=%v", errsBefore, errs)
	}
}

func TestFeedDownloader_WarmStartFromCache(t *testing.T) {
	dir := t.TempDir()
	cachePath := filepath.Join(dir, "drop.txt")
	if err := os.WriteFile(cachePath, []byte(spamhausBody), 0o644); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	feed := BlocklistFeedConfig{
		Name: "warm", Enabled: true, Format: "spamhaus",
		Action: "score", Score: 50, Path: cachePath,
	}
	mgr := NewBlocklistManager(&BlocklistConfig{Feeds: []BlocklistFeedConfig{feed}}, nil)

	if sigs, _ := mgr.Check(net.ParseIP("1.2.3.4")); len(sigs) != 1 {
		t.Errorf("warm-start: expected feed loaded from cache, got %d signals", len(sigs))
	}
}

func TestParseFeedLine(t *testing.T) {
	cases := []struct {
		raw, format, want string
		ok                bool
	}{
		{"1.2.3.0/24 ; SBL123", "spamhaus", "1.2.3.0/24", true},
		{"  2001:db8::/32 ; SBL9", "spamhaus", "2001:db8::/32", true},
		{"9.9.9.9", "cidr", "9.9.9.9/32", true},
		{"::1", "cidr", "::1/128", true},
		{"add myset 5.6.7.0/24 timeout 0", "ipset", "5.6.7.0/24", true},
		{"# comment", "spamhaus", "", false},
		{"; comment", "spamhaus", "", false},
		{"", "spamhaus", "", false},
		{"add myset", "ipset", "", false},
	}
	for _, c := range cases {
		got, ok := parseFeedLine(c.raw, c.format)
		if ok != c.ok || got != c.want {
			t.Errorf("parseFeedLine(%q,%q) = (%q,%v), want (%q,%v)", c.raw, c.format, got, ok, c.want, c.ok)
		}
	}
}

package security

import (
	"net"
	"os"
	"testing"
)

func writeTempBlocklist(t *testing.T, lines string) string {
	t.Helper()
	f, err := os.CreateTemp("", "blocklist_*.txt")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if _, err := f.WriteString(lines); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}
	t.Cleanup(func() { os.Remove(f.Name()) })
	return f.Name()
}

func TestBlocklists_NoFeeds_NoBlock(t *testing.T) {
	m := NewBlocklistManager(&BlocklistConfig{Feeds: nil}, nil)
	sigs, hardBlock := m.Check(net.ParseIP("1.2.3.4"))
	if hardBlock {
		t.Error("no feeds: expected no hard block")
	}
	if len(sigs) != 0 {
		t.Errorf("no feeds: expected no signals, got %d", len(sigs))
	}
}

func TestBlocklists_IPInHardBlockFeed_HardBlock(t *testing.T) {
	path := writeTempBlocklist(t, "1.2.3.0/24\n")
	m := NewBlocklistManager(&BlocklistConfig{
		Feeds: []BlocklistFeedConfig{
			{Name: "spamhaus", Enabled: true, Path: path, IsBypass: true, Action: "block", Score: 0},
		},
	}, nil)
	sigs, hardBlock := m.Check(net.ParseIP("1.2.3.4"))
	if !hardBlock {
		t.Error("hard block feed: expected hard block")
	}
	if len(sigs) != 0 {
		t.Errorf("hard block feed: expected no signals, got %d", len(sigs))
	}
}

func TestBlocklists_IPInSoftSignalFeed_Signal(t *testing.T) {
	path := writeTempBlocklist(t, "10.0.0.0/8\n")
	m := NewBlocklistManager(&BlocklistConfig{
		Feeds: []BlocklistFeedConfig{
			{Name: "internal_bad", Enabled: true, Path: path, IsBypass: false, Score: 45},
		},
	}, nil)
	sigs, hardBlock := m.Check(net.ParseIP("10.1.2.3"))
	if hardBlock {
		t.Error("soft signal feed: expected no hard block")
	}
	if len(sigs) != 1 {
		t.Fatalf("soft signal feed: expected 1 signal, got %d", len(sigs))
	}
	if sigs[0].Score != 45 {
		t.Errorf("soft signal feed: expected score 45, got %d", sigs[0].Score)
	}
	if sigs[0].Name != "blocklist_internal_bad" {
		t.Errorf("soft signal feed: expected name blocklist_internal_bad, got %s", sigs[0].Name)
	}
}

func TestBlocklists_IPv6_Match(t *testing.T) {
	path := writeTempBlocklist(t, "2001:db8::/32\n")
	m := NewBlocklistManager(&BlocklistConfig{
		Feeds: []BlocklistFeedConfig{
			{Name: "ipv6_bad", Enabled: true, Path: path, IsBypass: false, Score: 20},
		},
	}, nil)
	sigs, hardBlock := m.Check(net.ParseIP("2001:db8::1"))
	if hardBlock {
		t.Error("IPv6: expected no hard block")
	}
	if len(sigs) != 1 {
		t.Fatalf("IPv6: expected 1 signal, got %d", len(sigs))
	}
}

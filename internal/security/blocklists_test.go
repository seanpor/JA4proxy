package security

import (
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
	sigs, hardBlock := m.Check("1.2.3.4")
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
			{Name: "spamhaus", Enabled: true, Path: path, IsBlock: true, Score: 0},
		},
	}, nil)
	sigs, hardBlock := m.Check("1.2.3.4")
	if !hardBlock {
		t.Error("hard block feed: expected hard block")
	}
	if len(sigs) != 0 {
		t.Errorf("hard block feed: expected no signals, got %d", len(sigs))
	}
}

func TestBlocklists_IPInScoredFeed_Signal(t *testing.T) {
	path := writeTempBlocklist(t, "10.0.0.0/8\n")
	m := NewBlocklistManager(&BlocklistConfig{
		Feeds: []BlocklistFeedConfig{
			{Name: "reputation", Enabled: true, Path: path, IsBlock: false, Score: 30},
		},
	}, nil)
	sigs, hardBlock := m.Check("10.1.2.3")
	if hardBlock {
		t.Error("scored feed: expected no hard block")
	}
	if len(sigs) == 0 {
		t.Fatal("scored feed: expected signal")
	}
	if sigs[0].Score != 30 {
		t.Errorf("expected score=30, got %d", sigs[0].Score)
	}
}

func TestBlocklists_IPv6_Matched(t *testing.T) {
	path := writeTempBlocklist(t, "2001:db8::/32\n")
	m := NewBlocklistManager(&BlocklistConfig{
		Feeds: []BlocklistFeedConfig{
			{Name: "ipv6_block", Enabled: true, Path: path, IsBlock: true, Score: 0},
		},
	}, nil)
	_, hardBlock := m.Check("2001:db8::1")
	if !hardBlock {
		t.Error("IPv6: expected hard block for 2001:db8::1 in 2001:db8::/32")
	}
}

func TestBlocklists_IPNotInAnyFeed_Clean(t *testing.T) {
	path := writeTempBlocklist(t, "192.168.0.0/16\n")
	m := NewBlocklistManager(&BlocklistConfig{
		Feeds: []BlocklistFeedConfig{
			{Name: "private", Enabled: true, Path: path, IsBlock: true, Score: 0},
		},
	}, nil)
	sigs, hardBlock := m.Check("8.8.8.8")
	if hardBlock {
		t.Error("clean IP: expected no hard block")
	}
	if len(sigs) != 0 {
		t.Errorf("clean IP: expected no signals, got %d", len(sigs))
	}
}

func TestBlocklists_DisabledFeed_NotChecked(t *testing.T) {
	path := writeTempBlocklist(t, "1.2.3.0/24\n")
	m := NewBlocklistManager(&BlocklistConfig{
		Feeds: []BlocklistFeedConfig{
			{Name: "disabled", Enabled: false, Path: path, IsBlock: true, Score: 0},
		},
	}, nil)
	_, hardBlock := m.Check("1.2.3.4")
	if hardBlock {
		t.Error("disabled feed: should not be checked")
	}
}

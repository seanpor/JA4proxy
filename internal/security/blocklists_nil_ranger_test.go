package security

import (
	"net"
	"testing"
)

// TestBlocklists_NilRanger_NoPanic_JA4PROXY_2026_0091 is the regression for the
// nil-Ranger crash class (Hunter 2026-06-24-0031). ReplaceFeed already rejects a
// nil ranger at the write side; this pins the read-side guard in Check() so a
// box holding a nil Ranger interface can never turn a blocklist lookup into a
// panic. If the guard is removed, box.ranger.Contains(ip) panics and this test
// fails.
func TestBlocklists_NilRanger_NoPanic_JA4PROXY_2026_0091(t *testing.T) {
	path := writeTempBlocklist(t, "1.2.3.0/24\n")
	m := NewBlocklistManager(&BlocklistConfig{
		Feeds: []BlocklistFeedConfig{
			{Name: "spamhaus", Enabled: true, Path: path, IsBypass: true, Action: "block", Score: 0},
		},
	}, nil)

	// Force the pathological state directly (ReplaceFeed would refuse a nil
	// ranger): a live box whose Ranger interface is nil.
	m.feeds[0].ranger.Store(&rangerBox{ranger: nil})

	// Must not panic; the feed with the nil ranger is skipped → no match.
	sigs, hardBlock := m.Check(net.ParseIP("1.2.3.4"))
	if hardBlock || len(sigs) != 0 {
		t.Fatalf("nil-ranger feed should be skipped, got hardBlock=%v sigs=%d", hardBlock, len(sigs))
	}
}

// TestBlocklists_ReplaceFeedRejectsNil_JA4PROXY_2026_0091 pins the write-side
// guard: ReplaceFeed must refuse a nil ranger rather than store it.
func TestBlocklists_ReplaceFeedRejectsNil_JA4PROXY_2026_0091(t *testing.T) {
	path := writeTempBlocklist(t, "1.2.3.0/24\n")
	m := NewBlocklistManager(&BlocklistConfig{
		Feeds: []BlocklistFeedConfig{
			{Name: "spamhaus", Enabled: true, Path: path, IsBypass: true, Action: "block", Score: 0},
		},
	}, nil)
	if m.ReplaceFeed("spamhaus", nil) {
		t.Fatal("ReplaceFeed must reject a nil ranger")
	}
	// The pre-existing trie must still be intact and matching.
	if _, hardBlock := m.Check(net.ParseIP("1.2.3.4")); !hardBlock {
		t.Fatal("rejecting a nil ReplaceFeed must leave the existing trie intact")
	}
}

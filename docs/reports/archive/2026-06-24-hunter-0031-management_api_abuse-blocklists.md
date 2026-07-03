# ReplaceFeed — crash

**File:** `internal/security/blocklists.go`
**Lines:** 171-179
**Bug Class:** Management API & Admin Endpoint Abuse
**Severity:** 8/10
**Impact:** 8/10
**Score (S×I):** 64

## Trigger

A management API endpoint that accepts user-supplied CIDR data to replace a blocklist feed receives a request that results in a nil `cidranger.Ranger` interface value being passed to `ReplaceFeed`.

## Vulnerable Code

```go
func (m *BlocklistManager) ReplaceFeed(name string, ranger cidranger.Ranger) bool {
	for _, feed := range m.feeds {
		if feed.name == name {
			feed.ranger.Store(&rangerBox{ranger: ranger})
			return true
		}
	}
	return false
}
```

## Execution Trace

  1. Step 1: An unauthenticated attacker sends a request to the management API endpoint that invokes `ReplaceFeed("blocklist_feed_name", nil)` (or with data that yields a nil ranger after parsing).
  2. Step 2: `ReplaceFeed` finds the matching feed and executes `feed.ranger.Store(&rangerBox{ranger: nil})`, storing a `rangerBox` struct where the `ranger` field is a nil interface.
  3. Step 3: A subsequent legitimate HTTP request triggers the `Check(ip)` method on the same `BlocklistManager`.
  4. Step 4: Inside `Check`, `box := feed.ranger.Load()` retrieves the stored `*rangerBox` which is non-nil.
  5. Step 5: `box.ranger` is a nil interface, so calling `box.ranger.Contains(ip)` attempts to invoke the `Contains` method on a nil interface, causing a panic: "runtime error: invalid memory address or nil pointer dereference".
  6. Step 6: The panic crashes the goroutine handling the HTTP request; if not recovered, it may crash the entire process depending on the HTTP server's recovery middleware.

## Consequence

Crash

---
*Filed by [Hunter](https://github.com/seanpor/hunter) — adversarial AI bug-hunting agent.*

## Disposition (archived 2026-07-03)

Triaged into `docs/security/findings.yaml` as `JA4PROXY-2026-0091`, status
`FIXED`, closed commit `accdfff0`. Verified against current code:
`ReplaceFeed` already rejects `nil` (write-side guard pre-existing); this
report's "unauthenticated management endpoint" trigger was inaccurate —
`ReplaceFeed` is only called internally from `feed_downloader.go`. Phase 515
added a read-side guard in `Check()` (`box.ranger == nil -> continue`) as
defense-in-depth so no future store path can crash. Regression test:
`internal/security/blocklists_nil_ranger_test.go`. Archived here rather than
left at the repo root now that the finding is closed.

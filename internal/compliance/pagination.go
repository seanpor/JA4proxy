package compliance

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
)

// ConnectionEvent is a single event record returned by GET /api/v1/connections.
type ConnectionEvent struct {
	IP          string `json:"ip"`
	JA4         string `json:"ja4"`
	RiskScore   string `json:"risk_score"`
	ActionTaken string `json:"action_taken"`
	Timestamp   string `json:"timestamp"`
}

// connectionsPage is the raw API response for one page of GET /api/v1/connections.
type connectionsPage struct {
	Connections   []ConnectionEvent `json:"connections"`
	Count         int               `json:"count"`
	HasMore       bool              `json:"has_more"`
	NextPageToken *string           `json:"next_page_token"`
	TotalInWindow int               `json:"total_in_window"`
}

// ConnectionQuery holds the parameters for a paginated connection fetch.
type ConnectionQuery struct {
	Since  string // ISO 8601 lower bound (inclusive)
	Until  string // ISO 8601 upper bound (exclusive)
	IP     string // optional IP filter
	JA4    string // optional JA4 filter
	Action string // optional action_taken filter
	Limit  int    // page size; default 500 if zero
}

// APIGetter is the interface used by PageIterator to fetch pages.
// *client.Client satisfies this via its Get method.
type APIGetter interface {
	Get(ctx context.Context, path string, out interface{}) error
}

// PageIterator iterates over all pages of a compliance connection export.
// It is safe to cancel the context between calls to Next.
//
//	iter := NewPageIterator(c, query)
//	for iter.Next(ctx) {
//	    for _, ev := range iter.Page() { ... }
//	}
//	if err := iter.Err(); err != nil { ... }
type PageIterator struct {
	c         APIGetter
	query     ConnectionQuery
	pageToken string
	page      []ConnectionEvent
	done      bool
	err       error
	fetched   bool // false before the very first fetch
}

// NewPageIterator creates a new PageIterator for the given query.
func NewPageIterator(c APIGetter, query ConnectionQuery) *PageIterator {
	if query.Limit <= 0 {
		query.Limit = 500
	}
	return &PageIterator{c: c, query: query}
}

// Next fetches the next page and returns true if events are available.
// Returns false when all pages have been consumed or an error occurs.
func (p *PageIterator) Next(ctx context.Context) bool {
	if p.done {
		return false
	}
	// On first call, fetched is false; subsequent calls use the token from the
	// previous response.  A non-empty pageToken means there are more pages.
	if p.fetched && p.pageToken == "" {
		p.done = true
		return false
	}

	path := p.buildPath()
	var resp connectionsPage
	if err := p.c.Get(ctx, path, &resp); err != nil {
		p.err = fmt.Errorf("fetching connections page: %w", err)
		p.done = true
		return false
	}

	p.fetched = true
	p.page = resp.Connections

	if resp.HasMore && resp.NextPageToken != nil {
		p.pageToken = *resp.NextPageToken
	} else {
		p.pageToken = ""
		p.done = true // last page
	}

	return len(p.page) > 0
}

// Page returns the current page of events (valid only after a successful Next call).
func (p *PageIterator) Page() []ConnectionEvent {
	return p.page
}

// Err returns the first error encountered, or nil.
func (p *PageIterator) Err() error {
	return p.err
}

// buildPath constructs the query string for the connections endpoint.
func (p *PageIterator) buildPath() string {
	q := url.Values{}
	q.Set("limit", strconv.Itoa(p.query.Limit))
	if p.query.Since != "" {
		q.Set("since", p.query.Since)
	}
	if p.query.Until != "" {
		q.Set("until", p.query.Until)
	}
	if p.query.IP != "" {
		q.Set("ip", p.query.IP)
	}
	if p.query.JA4 != "" {
		q.Set("ja4", p.query.JA4)
	}
	if p.query.Action != "" {
		q.Set("action", p.query.Action)
	}
	if p.pageToken != "" {
		q.Set("page_token", p.pageToken)
	}
	return "/api/v1/connections?" + q.Encode()
}

// CollectAll is a convenience function that drains a PageIterator and returns all
// events in a single slice.  Caller is responsible for memory — use only when the
// result set is known to be bounded.
func CollectAll(ctx context.Context, iter *PageIterator) ([]ConnectionEvent, error) {
	var all []ConnectionEvent
	for iter.Next(ctx) {
		all = append(all, iter.Page()...)
	}
	return all, iter.Err()
}

// DecodePageToken decodes a base64-encoded page token into its component fields.
// Returns zero values and false if the token is malformed.
func DecodePageToken(token string) (offset int, since, until string, ok bool) {
	raw, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		// Try without padding (urlsafe_b64decode in Python strips padding)
		raw, err = base64.RawURLEncoding.DecodeString(token)
		if err != nil {
			return 0, "", "", false
		}
	}
	var m struct {
		Offset int    `json:"offset"`
		Since  string `json:"since"`
		Until  string `json:"until"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return 0, "", "", false
	}
	return m.Offset, m.Since, m.Until, true
}

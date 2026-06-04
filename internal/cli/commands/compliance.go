package commands

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/seanpor/ja4proxy/internal/cli/client"
	"github.com/seanpor/ja4proxy/internal/compliance"
)

// ── DSAR ─────────────────────────────────────────────────────────────────────

// DSARResult is the JSON payload returned by GET /api/v1/compliance/dsar/{ip}.
type DSARResult struct {
	IP            string        `json:"ip"`
	Events        []interface{} `json:"events"`
	BeaconingKeys []string      `json:"beaconing_keys"`
	ReturnVisitor interface{}   `json:"return_visitor"`
	ActiveBan     interface{}   `json:"active_ban"`
}

// DSAREraseResult is the response from DELETE /api/v1/compliance/dsar/{ip}.
type DSAREraseResult struct {
	IP       string   `json:"ip"`
	Erased   []string `json:"erased"`
	Skipped  []string `json:"skipped"`
	AuditRef string   `json:"audit_ref"`
}

// RunDSARExport fetches all held data for an IP via GET /api/v1/compliance/dsar/{ip}.
func RunDSARExport(ctx context.Context, c *client.Client, ip string) (*DSARResult, error) {
	var result DSARResult
	if err := c.Get(ctx, "/api/v1/compliance/dsar/"+ip, &result); err != nil {
		return nil, fmt.Errorf("DSAR export for %s: %w", ip, err)
	}
	return &result, nil
}

// RunDSARErase issues DELETE /api/v1/compliance/dsar/{ip} to purge an IP's data.
// A ticket reference is required for the audit log.
func RunDSARErase(ctx context.Context, c *client.Client, ip, ticket string) (*DSAREraseResult, error) {
	path := "/api/v1/compliance/dsar/" + ip
	if ticket != "" {
		path += "?ticket=" + ticket
	}
	var result DSAREraseResult
	if err := c.Delete(ctx, path); err != nil {
		return nil, fmt.Errorf("DSAR erase for %s: %w", ip, err)
	}
	// DELETE returns a body — re-fetch summary via the audit log is impractical,
	// so we return a minimal confirmation.
	result.IP = ip
	result.AuditRef = ticket
	return &result, nil
}

// ── Purge ─────────────────────────────────────────────────────────────────────

// PurgeResult is the response from POST /api/v1/compliance/purge-expired.
type PurgeResult struct {
	StreamEventsPurged  int      `json:"stream_events_purged"`
	BeaconingKeysPurged int      `json:"beaconing_keys_purged"`
	RVHashesPurged      int      `json:"rv_hashes_purged"`
	MonthlyAggsPurged   int      `json:"monthly_aggs_purged"`
	Errors              []string `json:"errors"`
	CompletedAt         string   `json:"completed_at"`
}

// RunPurgeExpired triggers GDPR retention enforcement via POST /api/v1/compliance/purge-expired.
func RunPurgeExpired(ctx context.Context, c *client.Client) (*PurgeResult, error) {
	var result PurgeResult
	if err := c.Post(ctx, "/api/v1/compliance/purge-expired", nil, &result); err != nil {
		return nil, fmt.Errorf("purge-expired: %w", err)
	}
	return &result, nil
}

// ── PCI-DSS pack ─────────────────────────────────────────────────────────────

// RunPCIDSSPack requests a PCI-DSS evidence pack ZIP from the Management API and
// writes it to outPath.  If outPath is empty a timestamped filename is generated
// in the current directory.
func RunPCIDSSPack(ctx context.Context, c *client.Client, since, until, outPath string) (string, error) {
	body := map[string]interface{}{
		"since": since,
		"until": until,
	}
	data, contentType, err := c.PostBinaryResponse(ctx, "/api/v1/compliance/pci-dss-pack", body)
	if err != nil {
		return "", fmt.Errorf("pci-dss-pack: %w", err)
	}
	if contentType == "application/json" {
		// API returned an error body as JSON — surface it.
		return "", fmt.Errorf("pci-dss-pack: API error: %s", string(data))
	}

	if outPath == "" {
		ts := time.Now().UTC().Format("20060102T150405Z")
		outPath = fmt.Sprintf("pci-dss-pack-%s.zip", ts)
	}

	// Ensure the parent directory exists.
	if dir := filepath.Dir(outPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return "", fmt.Errorf("creating output directory: %w", err)
		}
	}

	if err := os.WriteFile(outPath, data, 0o600); err != nil { //nolint:gosec // compliance pack is non-sensitive config export
		return "", fmt.Errorf("writing pack to %s: %w", outPath, err)
	}
	return outPath, nil
}

// ── Report ────────────────────────────────────────────────────────────────────

// ReportFormat is the requested output format for a compliance report.
type ReportFormat string

const (
	ReportFormatHTML ReportFormat = "html"
	ReportFormatPDF  ReportFormat = "pdf"
)

// RunReportGenerate generates a compliance report and writes it to out.
// format must be "html" or "pdf".
func RunReportGenerate(ctx context.Context, c *client.Client, since, until string, format ReportFormat, out io.Writer) error {
	body := map[string]interface{}{
		"since":  since,
		"until":  until,
		"format": string(format),
	}
	data, _, err := c.PostBinaryResponse(ctx, "/api/v1/compliance/report", body)
	if err != nil {
		return fmt.Errorf("report generate: %w", err)
	}
	_, err = out.Write(data)
	return err
}

// ── Signal categories ─────────────────────────────────────────────────────────

// SignalCategoriesResult mirrors the response from GET /api/v1/compliance/signal-categories.
type SignalCategoriesResult struct {
	Categories map[string]struct {
		Category string `json:"category"`
		Weight   int    `json:"weight"`
	} `json:"categories"`
}

// RunSignalCategories fetches the active signal→category mapping.
func RunSignalCategories(ctx context.Context, c *client.Client) (*SignalCategoriesResult, error) {
	var result SignalCategoriesResult
	if err := c.Get(ctx, "/api/v1/compliance/signal-categories", &result); err != nil {
		return nil, fmt.Errorf("signal-categories: %w", err)
	}
	return &result, nil
}

// ── Connections export ────────────────────────────────────────────────────────

// ConnectionsExportResult is the total count of exported events.
type ConnectionsExportResult struct {
	TotalEvents int
	OutputPath  string
}

// RunConnectionsExport pages through all connection events in [since, until) and
// writes them as JSONL to outPath.  Returns the number of events written.
func RunConnectionsExport(ctx context.Context, c *client.Client, since, until, outPath string) (*ConnectionsExportResult, error) {
	if outPath == "" {
		ts := time.Now().UTC().Format("20060102T150405Z")
		outPath = fmt.Sprintf("connections-export-%s.jsonl", ts)
	}

	f, err := os.Create(outPath) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("creating output file: %w", err)
	}
	defer f.Close()

	query := compliance.ConnectionQuery{
		Since: since,
		Until: until,
		Limit: 500,
	}
	iter := compliance.NewPageIterator(c, query)
	total := 0
	for iter.Next(ctx) {
		for _, ev := range iter.Page() {
			line := fmt.Sprintf(
				`{"ip":%q,"ja4":%q,"risk_score":%q,"action_taken":%q,"timestamp":%q}`,
				ev.IP, ev.JA4, ev.RiskScore, ev.ActionTaken, ev.Timestamp,
			)
			if _, err := fmt.Fprintln(f, line); err != nil {
				return nil, fmt.Errorf("writing event: %w", err)
			}
			total++
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating connections: %w", err)
	}

	return &ConnectionsExportResult{TotalEvents: total, OutputPath: outPath}, nil
}

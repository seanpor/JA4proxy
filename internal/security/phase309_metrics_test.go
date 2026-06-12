package security

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/seanpor/ja4proxy/internal/metrics"
)

// suspectRedis tracks the beacon:suspects ZSET membership so ZCard returns a
// real cardinality, and serves low-CV timestamps for the beacon detection key.
type suspectRedis struct {
	mockRedis
	scores   map[string][]float64
	members  map[string]map[string]struct{} // key -> set of members
	zaddKeys []string
}

func newSuspectRedis(beaconKey string, ts []float64) *suspectRedis {
	return &suspectRedis{
		scores:  map[string][]float64{beaconKey: ts},
		members: map[string]map[string]struct{}{},
	}
}

func (m *suspectRedis) ZRangeScores(_ context.Context, key string, _, _ int64) []float64 {
	return m.scores[key]
}

func (m *suspectRedis) ZAdd(_ context.Context, key string, _ float64, member string) {
	m.zaddKeys = append(m.zaddKeys, key)
	if m.members[key] == nil {
		m.members[key] = map[string]struct{}{}
	}
	m.members[key][member] = struct{}{}
}

func (m *suspectRedis) ZRemRangeByScore(_ context.Context, _ string, _, _ float64) {}

func (m *suspectRedis) ZCard(_ context.Context, key string) int64 {
	return int64(len(m.members[key]))
}

func TestBeaconing_DetectionRecordsSuspectAndGauge(t *testing.T) {
	metrics.BeaconingSuspects.Set(0)
	ts := makeTimestamps(20, 60) // perfectly regular → CV ~0 → detected
	r := newSuspectRedis("beacon:1.2.3.4:t13d1234", ts)
	d := NewBeaconingDetector(defaultBeaconingCfg(), r, nil)

	sig := d.GetSignal(context.Background(), &ConnectionContext{
		ParsedIP: net.ParseIP("1.2.3.4"), ClientIP: "1.2.3.4", JA4: "t13d1234",
	})
	if sig == nil {
		t.Fatal("expected a beaconing signal for a regular pattern")
	}
	// Suspect recorded on the leaderboard.
	if _, ok := r.members[beaconSuspectsKey]["1.2.3.4:t13d1234"]; !ok {
		t.Errorf("suspect not added to %s; members=%v", beaconSuspectsKey, r.members[beaconSuspectsKey])
	}
	// Gauge reflects the leaderboard cardinality.
	if got := testutil.ToFloat64(metrics.BeaconingSuspects); got != 1 {
		t.Errorf("BeaconingSuspects gauge = %v, want 1", got)
	}
}

func TestBeaconing_NoDetectionNoSuspect(t *testing.T) {
	// High-variance arrivals → not beaconing → no leaderboard write.
	r := newSuspectRedis("beacon:9.9.9.9:t13d9999", makeJitteredTimestamps(20))
	d := NewBeaconingDetector(defaultBeaconingCfg(), r, nil)
	sig := d.GetSignal(context.Background(), &ConnectionContext{
		ParsedIP: net.ParseIP("9.9.9.9"), ClientIP: "9.9.9.9", JA4: "t13d9999",
	})
	if sig != nil {
		t.Fatalf("expected no signal for jittered arrivals, got %v", sig)
	}
	if len(r.members[beaconSuspectsKey]) != 0 {
		t.Errorf("no detection should not record a suspect, got %v", r.members[beaconSuspectsKey])
	}
}

// abuseQuotaCfg mirrors defaultAbuseIPDBCfg but is local to this file.
func abuseQuotaCfg(url string) *AbuseIPDBConfig {
	return &AbuseIPDBConfig{
		Enabled: true, APIKey: "test-key", ScoreCap: 40,
		SharedIPThreshold: 50, LocalCacheSize: 100, Workers: 1, APIURL: url,
	}
}

func TestAbuseIPDB_QuotaExhaustedOn429(t *testing.T) {
	metrics.AbuseIPDBQuotaExhausted.Set(0)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	a := NewAbuseIPDB(abuseQuotaCfg(srv.URL), newMockRedisRW(), nil)
	a.http = srv.Client()
	a.lookup(context.Background(), "1.2.3.4")

	if got := testutil.ToFloat64(metrics.AbuseIPDBQuotaExhausted); got != 1 {
		t.Errorf("after 429: quota gauge = %v, want 1", got)
	}
}

func TestAbuseIPDB_QuotaGaugeClearsOnSuccess(t *testing.T) {
	metrics.AbuseIPDBQuotaExhausted.Set(1) // pretend it was exhausted
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "950")
		_, _ = w.Write([]byte(`{"data":{"abuseConfidenceScore":10}}`))
	}))
	defer srv.Close()

	a := NewAbuseIPDB(abuseQuotaCfg(srv.URL), newMockRedisRW(), nil)
	a.http = srv.Client()
	a.lookup(context.Background(), "1.2.3.4")

	if got := testutil.ToFloat64(metrics.AbuseIPDBQuotaExhausted); got != 0 {
		t.Errorf("after success with quota remaining: gauge = %v, want 0", got)
	}
}

func TestAbuseIPDB_QuotaGaugeSetOnLastUnit(t *testing.T) {
	metrics.AbuseIPDBQuotaExhausted.Set(0)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		_, _ = w.Write([]byte(`{"data":{"abuseConfidenceScore":10}}`))
	}))
	defer srv.Close()

	a := NewAbuseIPDB(abuseQuotaCfg(srv.URL), newMockRedisRW(), nil)
	a.http = srv.Client()
	a.lookup(context.Background(), "1.2.3.4")

	if got := testutil.ToFloat64(metrics.AbuseIPDBQuotaExhausted); got != 1 {
		t.Errorf("after success with 0 remaining: gauge = %v, want 1", got)
	}
}

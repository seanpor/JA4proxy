package redis

// Phase 201a — TLS + Username contract tests for the Go Redis client.
//
// REQUIRES (Coder must add before these tests go green):
//   - Config fields:  Username string;  SSL bool
//   - Unexported helpers in client.go:
//        buildStandaloneOptions(cfg Config) *goredis.Options
//        buildFailoverOptions(cfg Config) *goredis.FailoverOptions
//   - New(cfg, log) wires opts.Username and opts.TLSConfig (MinVersion TLS 1.2)
//     from cfg.Username and cfg.SSL respectively, in both Sentinel and
//     standalone branches.
//   - New() must preserve fail-open: on TLS/handshake failure it logs ERROR
//     but returns a non-nil *Client so the caller can still serve from local
//     cache.
//
// If any of the symbols above are missing, this file will FAIL TO COMPILE —
// that is the correct TDD red-phase signal.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	logrustest "github.com/sirupsen/logrus/hooks/test"
)

// dialTLSTestClient constructs a *Client against a TLS harness, installing the
// harness's RootCAs onto the default tls.Config for that dial. Because the
// current Coder plan uses the system CA pool and does NOT expose a RootCAs
// knob in Config, this helper uses a test seam: it temporarily patches
// tls.Dial via a custom Dialer plumbed through buildStandaloneOptions. To keep
// the test surface small we instead piggy-back on the already-existing
// goredis.Options tree by injecting a TLSConfig with our rootCAs directly on
// the options returned by buildStandaloneOptions — see tlsClientForHarness.
func tlsClientForHarness(t *testing.T, addr string, rootCAs *x509.CertPool, ssl bool, username, password string) (*Client, *logrustest.Hook) {
	t.Helper()
	host, port := splitHostPort(t, addr)
	log, hook := logrustest.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)

	cfg := Config{
		Host:     host,
		Port:     port,
		SSL:      ssl,
		Username: username,
		Password: password,
		Timeout:  2 * time.Second,
	}
	// When SSL is requested and we have rootCAs (trusted-CA case) we inject a
	// full tls.Config via the options builder so tests aren't at the mercy of
	// the host system CA pool. For the "wrong CA" case callers pass rootCAs=nil
	// and SSL=true — which is exactly the misconfig case we want to verify.
	opts := buildStandaloneOptions(cfg)
	if ssl && rootCAs != nil {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: rootCAs, ServerName: "127.0.0.1"}
	}
	// Bypass New()'s internal dial-options construction so our patched
	// TLSConfig is honoured. We still exercise loadScripts and the fail-open
	// log paths that New() installs.
	c := newFromOptions(opts, log)
	return c, hook
}

func TestClient_TLS_RealHandshake_Succeeds(t *testing.T) {
	addr, pool, _, _ := newTLSMiniredis(t)
	c, _ := tlsClientForHarness(t, addr, pool, true, "", "")
	if c == nil {
		t.Fatal("New returned nil client")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	c.Set(ctx, "k", "v", 5*time.Second)
	got, err := c.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get after TLS Set: %v", err)
	}
	if got != "v" {
		t.Errorf("Get: got %q, want %q", got, "v")
	}
}

func TestClient_TLS_WrongCA_Fails(t *testing.T) {
	addr, _, _, _ := newTLSMiniredis(t)
	// rootCAs=nil → the injected TLSConfig is NOT set, so buildStandaloneOptions'
	// TLSConfig (system CA pool, MinVersion 1.2) is used. The self-signed cert
	// is untrusted → handshake fails.
	c, hook := tlsClientForHarness(t, addr, nil, true, "", "")
	if c == nil {
		t.Fatal("fail-open broken: New returned nil on TLS misconfig")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.Ping(ctx); err == nil {
		t.Fatal("Ping should fail against server with untrusted self-signed cert")
	}

	// Expect an ERROR or WARN log entry mentioning TLS.
	saw := false
	for _, e := range hook.AllEntries() {
		if (e.Level == logrus.ErrorLevel || e.Level == logrus.WarnLevel) &&
			(strings.Contains(strings.ToLower(e.Message), "tls") || containsFieldSubstring(e.Data, "tls")) {
			saw = true
			break
		}
	}
	if !saw {
		t.Errorf("expected a WARN/ERROR log mentioning TLS; got entries: %+v", hook.AllEntries())
	}
}

func TestClient_TLS_PlainServerRejectsTLSClient(t *testing.T) {
	addr, _, _ := newPlainMiniredis(t)
	// SSL=true, but server is plain — handshake cannot complete.
	host, port := splitHostPort(t, addr)
	log, _ := logrustest.NewNullLogger()
	cfg := Config{Host: host, Port: port, SSL: true, Timeout: 2 * time.Second}
	opts := buildStandaloneOptions(cfg)
	c := newFromOptions(opts, log)
	if c == nil {
		t.Fatal("fail-open broken: New returned nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.Ping(ctx); err == nil {
		t.Fatal("Ping should fail: TLS client, plaintext server")
	}
}

func TestClient_TLS_TLSServerRejectsPlainClient(t *testing.T) {
	addr, _, _, _ := newTLSMiniredis(t)
	host, port := splitHostPort(t, addr)
	log, _ := logrustest.NewNullLogger()
	cfg := Config{Host: host, Port: port, SSL: false, Timeout: 2 * time.Second}
	opts := buildStandaloneOptions(cfg)
	c := newFromOptions(opts, log)
	if c == nil {
		t.Fatal("fail-open broken: New returned nil")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.Ping(ctx); err == nil {
		t.Fatal("Ping should fail: plain client, TLS server")
	}
}

func TestClient_Options_StandaloneTLS(t *testing.T) {
	cfg := Config{Host: "127.0.0.1", Port: 6379, SSL: true, Username: "alice", Timeout: time.Second}
	opts := buildStandaloneOptions(cfg)
	if opts == nil {
		t.Fatal("buildStandaloneOptions returned nil")
	}
	if opts.TLSConfig == nil {
		t.Error("standalone TLS: TLSConfig should be non-nil when SSL=true")
	} else if opts.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("standalone TLS: MinVersion got 0x%x, want 0x%x (TLS 1.2)",
			opts.TLSConfig.MinVersion, tls.VersionTLS12)
	}
	if opts.Username != "alice" {
		t.Errorf("standalone: Username got %q, want %q", opts.Username, "alice")
	}
}

func TestClient_Options_SentinelTLS(t *testing.T) {
	cfg := Config{
		MasterName: "mymaster",
		Sentinels:  []string{"127.0.0.1:26379"},
		SSL:        true,
		Username:   "bob",
		Timeout:    time.Second,
	}
	opts := buildFailoverOptions(cfg)
	if opts == nil {
		t.Fatal("buildFailoverOptions returned nil")
	}
	if opts.TLSConfig == nil {
		t.Error("failover TLS: TLSConfig should be non-nil when SSL=true")
	} else if opts.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("failover TLS: MinVersion got 0x%x, want 0x%x",
			opts.TLSConfig.MinVersion, tls.VersionTLS12)
	}
	if opts.Username != "bob" {
		t.Errorf("failover: Username got %q, want %q", opts.Username, "bob")
	}
	if opts.MasterName != "mymaster" {
		t.Errorf("failover: MasterName got %q, want %q", opts.MasterName, "mymaster")
	}
}

func TestClient_Username_PassedThrough(t *testing.T) {
	cfg := Config{Host: "127.0.0.1", Port: 6379, Username: "alice", Timeout: time.Second}
	opts := buildStandaloneOptions(cfg)
	if opts.Username != "alice" {
		t.Errorf("standalone: Username not propagated: got %q", opts.Username)
	}
}

func TestClient_PasswordNeverLogged(t *testing.T) {
	const secret = "s3cret-do-not-log"
	addr, pool, _, _ := newTLSMiniredis(t)
	host, port := splitHostPort(t, addr)

	log, hook := logrustest.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)

	cfg := Config{
		Host:     host,
		Port:     port,
		SSL:      true,
		Password: secret,
		Timeout:  2 * time.Second,
	}
	opts := buildStandaloneOptions(cfg)
	opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: "127.0.0.1"}
	c := newFromOptions(opts, log)
	if c == nil {
		t.Fatal("New returned nil")
	}
	// Drive some activity so any debug lines are emitted.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = c.Ping(ctx)

	for _, e := range hook.AllEntries() {
		if strings.Contains(e.Message, secret) {
			t.Errorf("password leaked in log message: %q", e.Message)
		}
		for k, v := range e.Data {
			if strings.Contains(toStr(v), secret) {
				t.Errorf("password leaked in log field %q: %v", k, v)
			}
		}
	}
}

// TestClient_New_SSLTrue_PlainServer_LogsErrorAndFailsOpen exercises New()
// DIRECTLY (not newFromOptions) with SSL=true against a plain miniredis. This
// is the exact production misconfig scenario — operator flips ssl: true but
// Redis server is plain. Expected behaviour: New returns a non-nil *Client
// (fail-open), log contains ERROR line "redis: TLS ping failed; continuing
// fail-open". Covers the cfg.SSL branch in New() (phase-201a QA backfill).
func TestClient_New_SSLTrue_PlainServer_LogsErrorAndFailsOpen(t *testing.T) {
	addr, _, _ := newPlainMiniredis(t)
	host, port := splitHostPort(t, addr)

	log, hook := logrustest.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)

	c := New(Config{
		Host:    host,
		Port:    port,
		SSL:     true,
		Timeout: 2 * time.Second,
	}, log)
	if c == nil {
		t.Fatal("fail-open broken: New returned nil on TLS misconfig")
	}

	sawTLSError := false
	sawDialOpts := false
	for _, e := range hook.AllEntries() {
		if e.Level == logrus.ErrorLevel && strings.Contains(e.Message, "TLS ping failed") {
			sawTLSError = true
		}
		if e.Level == logrus.InfoLevel && e.Message == "redis: dial options configured" {
			sawDialOpts = true
			if e.Data["ssl"] != true {
				t.Errorf("dial options log: ssl field got %v, want true", e.Data["ssl"])
			}
			if e.Data["username"] != false {
				t.Errorf("dial options log: username field got %v, want false", e.Data["username"])
			}
		}
	}
	if !sawTLSError {
		t.Errorf("expected ERROR log 'redis: TLS ping failed; continuing fail-open'; got: %+v", hook.AllEntries())
	}
	if !sawDialOpts {
		t.Errorf("expected INFO log 'redis: dial options configured'")
	}
}

// TestClient_New_NoSSL_NoTLSPingAttempted confirms that when cfg.SSL=false, New()
// does NOT attempt a TLS sanity ping (no spurious ERROR log on healthy plain
// Redis). Guards against a regression that would fire TLS pings unconditionally.
func TestClient_New_NoSSL_NoTLSPingAttempted(t *testing.T) {
	addr, _, _ := newPlainMiniredis(t)
	host, port := splitHostPort(t, addr)

	log, hook := logrustest.NewNullLogger()
	log.SetLevel(logrus.DebugLevel)

	c := New(Config{Host: host, Port: port, SSL: false, Timeout: 2 * time.Second}, log)
	if c == nil {
		t.Fatal("New returned nil on healthy plain Redis")
	}
	for _, e := range hook.AllEntries() {
		if strings.Contains(e.Message, "TLS ping failed") {
			t.Errorf("unexpected TLS-ping ERROR when SSL=false: %q", e.Message)
		}
	}
}

// containsFieldSubstring reports whether any string-valued log field contains
// the lowercase-compared substring s.
func containsFieldSubstring(data logrus.Fields, s string) bool {
	s = strings.ToLower(s)
	for _, v := range data {
		if strings.Contains(strings.ToLower(toStr(v)), s) {
			return true
		}
	}
	return false
}

func toStr(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case error:
		return x.Error()
	default:
		return ""
	}
}

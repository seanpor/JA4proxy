package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/seanpor/ja4proxy/internal/config"
	"github.com/seanpor/ja4proxy/internal/redis"
	"github.com/sirupsen/logrus"
)

// TestSignEvent_ProducesValidSignature verifies signEvent produces a signature
// that verifySignature accepts.
func TestSignEvent_ProducesValidSignature(t *testing.T) {
	agent, _, mr := newTestAgent(t)
	defer mr.Close()

	// Generate ephemeral keys
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	agent.privKey = priv
	agent.pubKey = pub

	event := &SyncEvent{
		Op:       "set",
		Key:      "ban:10.0.0.1",
		Value:    "test",
		OriginTS: time.Now().UnixMilli(),
		OriginDC: "dc-test",
	}

	agent.signEvent(event)

	if event.Signature == "" {
		t.Fatal("signEvent did not set Signature")
	}

	// Verify the signature
	if !agent.verifySignature(*event) {
		t.Error("verifySignature rejected a validly signed event")
	}
}

// TestVerifySignature_RejectsTamperedEvent verifies that modifying the event
// after signing causes verification to fail.
func TestVerifySignature_RejectsTamperedEvent(t *testing.T) {
	agent, _, mr := newTestAgent(t)
	defer mr.Close()

	pub, priv, _ := ed25519.GenerateKey(nil)
	agent.privKey = priv
	agent.pubKey = pub

	event := &SyncEvent{
		Op:       "set",
		Key:      "ban:10.0.0.1",
		Value:    "original",
		OriginTS: time.Now().UnixMilli(),
		OriginDC: "dc-test",
	}

	agent.signEvent(event)

	// Tamper with the event
	event.Value = "tampered"

	if agent.verifySignature(*event) {
		t.Error("verifySignature should reject tampered event")
	}
}

// TestVerifySignature_EmptySignature verifies that an empty signature is rejected.
func TestVerifySignature_EmptySignature(t *testing.T) {
	agent, _, mr := newTestAgent(t)
	defer mr.Close()

	pub, priv, _ := ed25519.GenerateKey(nil)
	agent.privKey = priv
	agent.pubKey = pub

	event := SyncEvent{
		Op:        "set",
		Key:       "ban:10.0.0.1",
		Value:     "test",
		Signature: "",
	}

	if agent.verifySignature(event) {
		t.Error("verifySignature should reject empty signature")
	}
}

// TestVerifySignature_InvalidBase64 verifies rejection of invalid base64.
func TestVerifySignature_InvalidBase64(t *testing.T) {
	agent, _, mr := newTestAgent(t)
	defer mr.Close()

	pub, priv, _ := ed25519.GenerateKey(nil)
	agent.privKey = priv
	agent.pubKey = pub

	event := SyncEvent{
		Op:        "set",
		Key:       "ban:10.0.0.1",
		Value:     "test",
		Signature: "not-valid-base64!!!",
	}

	if agent.verifySignature(event) {
		t.Error("verifySignature should reject invalid base64")
	}
}

// TestSignDialRequest_VerifyDialSignature verifies the dial request signing
// and verification round-trip.
func TestSignDialRequest_VerifyDialSignature(t *testing.T) {
	agent, _, mr := newTestAgent(t)
	defer mr.Close()

	pub, priv, _ := ed25519.GenerateKey(nil)
	agent.privKey = priv
	agent.pubKey = pub

	req := &DialRequest{
		Dial:     42,
		OriginDC: "dc-test",
		OriginTS: time.Now().UnixMilli(),
	}

	agent.signDialRequest(req)

	if req.Signature == "" {
		t.Fatal("signDialRequest did not set Signature")
	}

	if !agent.verifyDialSignature(*req) {
		t.Error("verifyDialSignature rejected a validly signed request")
	}
}

// TestVerifyDialSignature_RejectsTampered verifies tampered dial request is rejected.
func TestVerifyDialSignature_RejectsTampered(t *testing.T) {
	agent, _, mr := newTestAgent(t)
	defer mr.Close()

	pub, priv, _ := ed25519.GenerateKey(nil)
	agent.privKey = priv
	agent.pubKey = pub

	req := &DialRequest{
		Dial:     42,
		OriginDC: "dc-test",
		OriginTS: time.Now().UnixMilli(),
	}
	agent.signDialRequest(req)

	// Tamper
	req.Dial = 100

	if agent.verifyDialSignature(*req) {
		t.Error("verifyDialSignature should reject tampered request")
	}
}

// TestVerifyDialSignature_EmptySignature verifies empty signature rejection.
func TestVerifyDialSignature_EmptySignature(t *testing.T) {
	agent, _, mr := newTestAgent(t)
	defer mr.Close()

	pub, priv, _ := ed25519.GenerateKey(nil)
	agent.privKey = priv
	agent.pubKey = pub

	req := DialRequest{
		Dial:      42,
		OriginDC:  "dc-test",
		Signature: "",
	}
	if agent.verifyDialSignature(req) {
		t.Error("should reject empty signature")
	}
}

// TestLoadIntegrityKeys_GeneratesEphemeral verifies that when no key file is
// configured, ephemeral keys are generated.
func TestLoadIntegrityKeys_GeneratesEphemeral(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	rc := redis.New(redis.Config{Host: mr.Host(), Port: mr.Server().Addr().Port}, log)

	cfg := &config.Config{}
	cfg.Sync.IntegrityKeyFile = "" // no file
	agent := NewSyncAgent(cfg, rc, log.WithField("test", true))

	err := agent.loadIntegrityKeys()
	if err != nil {
		t.Fatalf("loadIntegrityKeys error: %v", err)
	}
	if agent.privKey == nil {
		t.Error("private key should be generated")
	}
	if agent.pubKey == nil {
		t.Error("public key should be generated")
	}
}

// TestLoadIntegrityKeys_FromFile verifies loading keys from a base64-encoded file.
func TestLoadIntegrityKeys_FromFile(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	rc := redis.New(redis.Config{Host: mr.Host(), Port: mr.Server().Addr().Port}, log)

	// Generate a key and write to file
	_, priv, _ := ed25519.GenerateKey(nil)
	keyData := base64.StdEncoding.EncodeToString(priv)
	keyFile := filepath.Join(t.TempDir(), "integrity.key")
	if err := os.WriteFile(keyFile, []byte(keyData), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Sync.IntegrityKeyFile = keyFile
	agent := NewSyncAgent(cfg, rc, log.WithField("test", true))

	err := agent.loadIntegrityKeys()
	if err != nil {
		t.Fatalf("loadIntegrityKeys error: %v", err)
	}
	if agent.privKey == nil {
		t.Error("private key should be loaded")
	}
	if agent.pubKey == nil {
		t.Error("public key should be derived")
	}
}

// TestLoadIntegrityKeys_InvalidFile verifies error for nonexistent key file.
func TestLoadIntegrityKeys_InvalidFile(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	rc := redis.New(redis.Config{Host: mr.Host(), Port: mr.Server().Addr().Port}, log)

	cfg := &config.Config{}
	cfg.Sync.IntegrityKeyFile = "/nonexistent/key.pem"
	agent := NewSyncAgent(cfg, rc, log.WithField("test", true))

	err := agent.loadIntegrityKeys()
	if err == nil {
		t.Fatal("expected error for nonexistent key file")
	}
}

// TestLoadIntegrityKeys_InvalidBase64 verifies error for invalid base64 content.
func TestLoadIntegrityKeys_InvalidBase64(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	rc := redis.New(redis.Config{Host: mr.Host(), Port: mr.Server().Addr().Port}, log)

	keyFile := filepath.Join(t.TempDir(), "bad.key")
	if err := os.WriteFile(keyFile, []byte("not-valid-base64!!!"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Sync.IntegrityKeyFile = keyFile
	agent := NewSyncAgent(cfg, rc, log.WithField("test", true))

	err := agent.loadIntegrityKeys()
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
}

// TestLoadServerTLSConfig_MissingCert verifies error when cert files are missing.
func TestLoadServerTLSConfig_MissingCert(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	rc := redis.New(redis.Config{Host: mr.Host(), Port: mr.Server().Addr().Port}, log)

	cfg := &config.Config{}
	cfg.Sync.CertFile = ""
	cfg.Sync.KeyFile = ""
	agent := NewSyncAgent(cfg, rc, log.WithField("test", true))

	_, err := agent.loadServerTLSConfig()
	if err == nil {
		t.Fatal("expected error for missing cert/key files")
	}
}

// TestLoadServerTLSConfig_MissingCA verifies error when CA file is missing.
func TestLoadServerTLSConfig_MissingCA(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	rc := redis.New(redis.Config{Host: mr.Host(), Port: mr.Server().Addr().Port}, log)

	cfg := &config.Config{}
	cfg.Sync.CertFile = "some-cert.pem" // will fail at LoadX509KeyPair but not at the first check
	cfg.Sync.KeyFile = "some-key.pem"
	cfg.Sync.CAFile = ""
	agent := NewSyncAgent(cfg, rc, log.WithField("test", true))

	_, err := agent.loadServerTLSConfig()
	if err == nil {
		t.Fatal("expected error for missing CA file")
	}
}

// TestLoadClientTLSConfig_MissingCert verifies error when cert files are missing.
func TestLoadClientTLSConfig_MissingCert(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	rc := redis.New(redis.Config{Host: mr.Host(), Port: mr.Server().Addr().Port}, log)

	cfg := &config.Config{}
	cfg.Sync.CertFile = ""
	cfg.Sync.KeyFile = ""
	agent := NewSyncAgent(cfg, rc, log.WithField("test", true))

	_, err := agent.loadClientTLSConfig()
	if err == nil {
		t.Fatal("expected error for missing cert/key files")
	}
}

// TestProcessInbound_SRem verifies the srem operation removes members from a set.
func TestProcessInbound_SRem(t *testing.T) {
	agent, _, mr := newTestAgent(t)
	defer mr.Close()

	// Pre-populate
	mr.SAdd("ja4:blacklist", "fp-to-remove")

	event := SyncEvent{
		Op:    "srem",
		Key:   "ja4:blacklist",
		Value: "fp-to-remove",
	}
	agent.processInbound(event)

	if ok, _ := mr.SIsMember("ja4:blacklist", "fp-to-remove"); ok {
		t.Error("fp-to-remove should have been removed")
	}
}

// TestProcessInbound_ConfigDial verifies that setting config:dial works.
func TestProcessInbound_ConfigDial(t *testing.T) {
	agent, _, mr := newTestAgent(t)
	defer mr.Close()

	event := SyncEvent{
		Op:    "set",
		Key:   "config:dial",
		Value: "50",
	}
	agent.processInbound(event)

	val, err := mr.Get("config:dial")
	if err != nil {
		t.Fatalf("expected config:dial to be set: %v", err)
	}
	if val != "50" {
		t.Errorf("config:dial = %q; want 50", val)
	}
}

// TestProcessInbound_SAdd verifies sadd operation adds to a set.
func TestProcessInbound_SAdd(t *testing.T) {
	agent, _, mr := newTestAgent(t)
	defer mr.Close()

	event := SyncEvent{
		Op:    "sadd",
		Key:   "ja4:blacklist",
		Value: "fp-new",
	}
	agent.processInbound(event)

	if ok, _ := mr.SIsMember("ja4:blacklist", "fp-new"); !ok {
		t.Error("fp-new should be in ja4:blacklist")
	}
}

// TestVerifyInboundEvent_DCMismatch verifies events from wrong DC are rejected.
func TestVerifyInboundEvent_DCMismatch(t *testing.T) {
	agent, _, mr := newTestAgent(t)
	defer mr.Close()

	pub, priv, _ := ed25519.GenerateKey(nil)
	agent.privKey = priv
	agent.pubKey = pub

	event := SyncEvent{
		Op:       "set",
		Key:      "ban:1.1.1.1",
		Value:    "test",
		OriginDC: "dc-attacker", // doesn't match peerCN
		OriginTS: time.Now().UnixMilli(),
	}
	agent.signEvent(&event)

	result := agent.verifyInboundEvent(event, "dc-legitimate")
	if result {
		t.Error("should reject event with DC mismatch")
	}
}

// TestVerifyInboundEvent_FutureTimestamp verifies events with timestamps too far
// in the future are rejected.
func TestVerifyInboundEvent_FutureTimestamp(t *testing.T) {
	agent, _, mr := newTestAgent(t)
	defer mr.Close()

	pub, priv, _ := ed25519.GenerateKey(nil)
	agent.privKey = priv
	agent.pubKey = pub

	event := SyncEvent{
		Op:       "set",
		Key:      "ban:1.1.1.1",
		Value:    "test",
		OriginDC: "dc-test",
		OriginTS: time.Now().UnixMilli() + 120000, // 2 minutes in the future
	}
	agent.signEvent(&event)

	result := agent.verifyInboundEvent(event, "dc-test")
	if result {
		t.Error("should reject event with future timestamp")
	}
}

// TestVerifyInboundEvent_ValidEvent verifies a properly signed event passes.
func TestVerifyInboundEvent_ValidEvent(t *testing.T) {
	agent, _, mr := newTestAgent(t)
	defer mr.Close()

	pub, priv, _ := ed25519.GenerateKey(nil)
	agent.privKey = priv
	agent.pubKey = pub

	event := SyncEvent{
		Op:       "set",
		Key:      "ban:1.1.1.1",
		Value:    "test",
		OriginDC: "dc-test",
		OriginTS: time.Now().UnixMilli(),
	}
	agent.signEvent(&event)

	result := agent.verifyInboundEvent(event, "dc-test")
	if !result {
		t.Error("should accept valid signed event with matching DC")
	}
}

// TestVerifyInboundEvent_InvalidSignature verifies events with bad signatures
// are rejected.
func TestVerifyInboundEvent_InvalidSignature(t *testing.T) {
	agent, _, mr := newTestAgent(t)
	defer mr.Close()

	pub, priv, _ := ed25519.GenerateKey(nil)
	agent.privKey = priv
	agent.pubKey = pub

	event := SyncEvent{
		Op:        "set",
		Key:       "ban:1.1.1.1",
		Value:     "test",
		OriginDC:  "dc-test",
		OriginTS:  time.Now().UnixMilli(),
		Signature: base64.StdEncoding.EncodeToString([]byte("invalid-sig-bytes-pad-to-64-bytes-for-ed25519-signature-lengthx")),
	}

	result := agent.verifyInboundEvent(event, "dc-test")
	if result {
		t.Error("should reject event with invalid signature")
	}
}

// TestVerifyDialSignature_InvalidBase64 verifies rejection of invalid base64 in dial sig.
func TestVerifyDialSignature_InvalidBase64(t *testing.T) {
	agent, _, mr := newTestAgent(t)
	defer mr.Close()

	pub, priv, _ := ed25519.GenerateKey(nil)
	agent.privKey = priv
	agent.pubKey = pub

	req := DialRequest{
		Dial:      10,
		OriginDC:  "dc-test",
		Signature: "not-valid-base64!!!",
	}
	if agent.verifyDialSignature(req) {
		t.Error("should reject invalid base64 in dial signature")
	}
}

// TestLoadServerTLSConfig_InvalidCertPath verifies error for non-existent cert files
// (hits the tls.LoadX509KeyPair path).
func TestLoadServerTLSConfig_InvalidCertPath(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	rc := redis.New(redis.Config{Host: mr.Host(), Port: mr.Server().Addr().Port}, log)

	cfg := &config.Config{}
	cfg.Sync.CertFile = "/nonexistent/cert.pem"
	cfg.Sync.KeyFile = "/nonexistent/key.pem"
	cfg.Sync.CAFile = "/nonexistent/ca.pem"
	agent := NewSyncAgent(cfg, rc, log.WithField("test", true))

	_, err := agent.loadServerTLSConfig()
	if err == nil {
		t.Fatal("expected error for nonexistent cert files")
	}
}

// TestLoadClientTLSConfig_InvalidCertPath verifies error for non-existent cert.
func TestLoadClientTLSConfig_InvalidCertPath(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	rc := redis.New(redis.Config{Host: mr.Host(), Port: mr.Server().Addr().Port}, log)

	cfg := &config.Config{}
	cfg.Sync.CertFile = "/nonexistent/cert.pem"
	cfg.Sync.KeyFile = "/nonexistent/key.pem"
	cfg.Sync.CAFile = "/nonexistent/ca.pem"
	agent := NewSyncAgent(cfg, rc, log.WithField("test", true))

	_, err := agent.loadClientTLSConfig()
	if err == nil {
		t.Fatal("expected error for nonexistent cert files")
	}
}

// TestProcessInbound_SAddToWhitelist verifies sadd to whitelist.
func TestProcessInbound_SAddToWhitelist(t *testing.T) {
	agent, _, mr := newTestAgent(t)
	defer mr.Close()

	event := SyncEvent{
		Op:    "sadd",
		Key:   "ja4:whitelist",
		Value: "whitelisted-fp",
	}
	agent.processInbound(event)
	if ok, _ := mr.SIsMember("ja4:whitelist", "whitelisted-fp"); !ok {
		t.Error("expected whitelisted-fp to be in ja4:whitelist")
	}
}

// TestProcessInbound_ForbiddenKey verifies that forbidden keys are not processed.
func TestProcessInbound_ForbiddenKey(t *testing.T) {
	agent, _, mr := newTestAgent(t)
	defer mr.Close()

	event := SyncEvent{
		Op:    "set",
		Key:   "sensitive:data",
		Value: "should-not-be-set",
	}
	agent.processInbound(event)

	if mr.Exists("sensitive:data") {
		t.Error("forbidden key should not be set")
	}
}

// TestLoadTLSConfig_WithRealCerts verifies server and client TLS config loads
// successfully with valid self-signed certificates.
func TestLoadTLSConfig_WithRealCerts(t *testing.T) {
	certDir := t.TempDir()
	// Generate self-signed cert+key with openssl
	certFile := filepath.Join(certDir, "cert.pem")
	keyFile := filepath.Join(certDir, "key.pem")
	caFile := filepath.Join(certDir, "ca.pem")

	// Generate CA key and cert
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048",
		"-keyout", keyFile, "-out", certFile,
		"-days", "1", "-nodes", "-subj", "/CN=test-dc")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("openssl not available: %v\n%s", err, out)
	}
	// Use same cert as CA for testing
	data, _ := os.ReadFile(certFile)
	os.WriteFile(caFile, data, 0o644)

	mr, _ := miniredis.Run()
	defer mr.Close()
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	rc := redis.New(redis.Config{Host: mr.Host(), Port: mr.Server().Addr().Port}, log)

	cfg := &config.Config{}
	cfg.Sync.CertFile = certFile
	cfg.Sync.KeyFile = keyFile
	cfg.Sync.CAFile = caFile
	agent := NewSyncAgent(cfg, rc, log.WithField("test", true))

	serverTLS, err := agent.loadServerTLSConfig()
	if err != nil {
		t.Fatalf("loadServerTLSConfig error: %v", err)
	}
	if serverTLS == nil {
		t.Fatal("server TLS config is nil")
	}
	if serverTLS.MinVersion != 0x0304 { // TLS 1.3
		t.Errorf("MinVersion = %#x; want TLS 1.3 (0x0304)", serverTLS.MinVersion)
	}

	clientTLS, err := agent.loadClientTLSConfig()
	if err != nil {
		t.Fatalf("loadClientTLSConfig error: %v", err)
	}
	if clientTLS == nil {
		t.Fatal("client TLS config is nil")
	}
}

// TestLoadServerTLSConfig_InvalidCA verifies error for invalid CA content.
func TestLoadServerTLSConfig_InvalidCA(t *testing.T) {
	certDir := t.TempDir()
	certFile := filepath.Join(certDir, "cert.pem")
	keyFile := filepath.Join(certDir, "key.pem")
	caFile := filepath.Join(certDir, "ca.pem")

	// Generate real cert
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048",
		"-keyout", keyFile, "-out", certFile,
		"-days", "1", "-nodes", "-subj", "/CN=test-dc")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("openssl not available: %v\n%s", err, out)
	}
	// Write invalid CA
	os.WriteFile(caFile, []byte("not a pem"), 0o644)

	mr, _ := miniredis.Run()
	defer mr.Close()
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	rc := redis.New(redis.Config{Host: mr.Host(), Port: mr.Server().Addr().Port}, log)

	cfg := &config.Config{}
	cfg.Sync.CertFile = certFile
	cfg.Sync.KeyFile = keyFile
	cfg.Sync.CAFile = caFile
	agent := NewSyncAgent(cfg, rc, log.WithField("test", true))

	_, err := agent.loadServerTLSConfig()
	if err == nil {
		t.Fatal("expected error for invalid CA content")
	}
}

// TestNewSyncAgent_Defaults verifies NewSyncAgent creates an agent with sane defaults.
func TestNewSyncAgent_Defaults(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	rc := redis.New(redis.Config{Host: mr.Host(), Port: mr.Server().Addr().Port}, log)

	cfg := &config.Config{}
	cfg.Sync.DCID = "dc-1"
	cfg.Sync.ListenAddr = ":7379"

	agent := NewSyncAgent(cfg, rc, log.WithField("test", true))
	if agent == nil {
		t.Fatal("NewSyncAgent returned nil")
	}
	if agent.cfg.Sync.DCID != "dc-1" {
		t.Errorf("DCID = %q; want dc-1", agent.cfg.Sync.DCID)
	}
}

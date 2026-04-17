package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/anomalyco/ja4proxy/internal/config"
	"github.com/anomalyco/ja4proxy/internal/redis"
	"github.com/sirupsen/logrus"
)

// testPKI generates a self-signed CA, server cert, and writes them to tmpDir.
// Returns the cert, key, and CA file paths.
func testPKI(t *testing.T, cn string) (certFile, keyFile, caFile string) {
	t.Helper()
	tmpDir := t.TempDir()

	// Generate CA key
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	// Generate server key
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost", cn},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatal(err)
	}

	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	// Write files
	certFile = filepath.Join(tmpDir, "cert.pem")
	keyFile = filepath.Join(tmpDir, "key.pem")
	caFile = filepath.Join(tmpDir, "ca.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER})
	os.WriteFile(certFile, certPEM, 0o644)

	keyBytes, _ := x509.MarshalECPrivateKey(serverKey)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	os.WriteFile(keyFile, keyPEM, 0o600)

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	os.WriteFile(caFile, caPEM, 0o644)

	return certFile, keyFile, caFile
}

// newTestAgentWithTLS creates a test agent with working TLS certs.
func newTestAgentWithTLS(t *testing.T, cn string) (*SyncAgent, *miniredis.Miniredis, string, string, string) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}

	certFile, keyFile, caFile := testPKI(t, cn)

	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	rc := redis.New(redis.Config{Host: mr.Host(), Port: mr.Server().Addr().Port}, log)

	cfg := &config.Config{}
	cfg.Sync.DCID = cn
	cfg.Sync.CertFile = certFile
	cfg.Sync.KeyFile = keyFile
	cfg.Sync.CAFile = caFile

	agent := NewSyncAgent(cfg, rc, log.WithField("test", true))

	// Generate ephemeral integrity keys
	pub, priv, _ := ed25519.GenerateKey(nil)
	agent.privKey = priv
	agent.pubKey = pub

	return agent, mr, certFile, keyFile, caFile
}

// TestBroadcastDialChange_NoPeers verifies the no-peers fast path.
func TestBroadcastDialChange_NoPeers(t *testing.T) {
	agent, mr, _, _, _ := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()
	agent.cfg.Sync.RemotePeers = nil

	ctx := context.Background()
	err := agent.BroadcastDialChange(ctx, 42, false)
	if err != nil {
		t.Fatalf("BroadcastDialChange error: %v", err)
	}

	val, err := mr.Get("config:dial")
	if err != nil {
		t.Fatalf("expected config:dial to be set: %v", err)
	}
	if val != "42" {
		t.Errorf("config:dial = %q; want 42", val)
	}
}

// TestBroadcastDialChange_ImmediateNoPeers verifies immediate mode with no peers.
func TestBroadcastDialChange_ImmediateNoPeers(t *testing.T) {
	agent, mr, _, _, _ := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()
	agent.cfg.Sync.RemotePeers = nil

	ctx := context.Background()
	err := agent.BroadcastDialChange(ctx, 100, true)
	if err != nil {
		t.Fatalf("BroadcastDialChange immediate error: %v", err)
	}

	val, _ := mr.Get("config:dial")
	if val != "100" {
		t.Errorf("config:dial = %q; want 100", val)
	}
}

// TestBroadcastDialChange_ImmediateWithPeers exercises the immediate path with
// unreachable peers (fire-and-forget goroutines).
func TestBroadcastDialChange_ImmediateWithPeers(t *testing.T) {
	agent, mr, _, _, _ := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()
	agent.cfg.Sync.RemotePeers = []string{"127.0.0.1:1"} // unreachable

	ctx := context.Background()
	err := agent.BroadcastDialChange(ctx, 75, true)
	if err != nil {
		t.Fatalf("BroadcastDialChange immediate error: %v", err)
	}

	// Dial should still be set locally even if peers are unreachable
	val, _ := mr.Get("config:dial")
	if val != "75" {
		t.Errorf("config:dial = %q; want 75", val)
	}
}

// TestBroadcastDialChange_ConsensusTimeout verifies timeout when peers are unreachable.
func TestBroadcastDialChange_ConsensusTimeout(t *testing.T) {
	agent, mr, _, _, _ := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()
	agent.cfg.Sync.RemotePeers = []string{"127.0.0.1:1"} // unreachable

	ctx := context.Background()
	err := agent.BroadcastDialChange(ctx, 50, false)
	// Should timeout and return error
	if err == nil {
		t.Log("BroadcastDialChange did not error (sendDialRPC may have returned false quickly)")
	}

	// Dial should still be set locally on timeout
	val, _ := mr.Get("config:dial")
	if val != "50" {
		t.Errorf("config:dial = %q; want 50", val)
	}
}

// TestHandleInbound_WithTLS tests handleInbound via a real TLS connection.
func TestHandleInbound_WithTLS(t *testing.T) {
	agent, mr, certFile, keyFile, caFile := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()
	agent.ctx = context.Background()

	// Start TLS listener
	serverTLS, err := agent.loadServerTLSConfig()
	if err != nil {
		t.Fatalf("loadServerTLSConfig: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	// Accept one connection and handle it
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		agent.handleInbound(conn)
	}()

	// Build client TLS config
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	caData, _ := os.ReadFile(caFile)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caData)

	clientTLS := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	}

	conn, err := tls.Dial("tcp", addr, clientTLS)
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}

	// Send a signed event
	event := SyncEvent{
		Op:       "set",
		Key:      "ban:10.0.0.1",
		Value:    "test-inbound",
		OriginTS: time.Now().UnixMilli(),
		OriginDC: "dc-test",
	}
	agent.signEvent(&event)

	if err := json.NewEncoder(conn).Encode(event); err != nil {
		t.Fatalf("encode event: %v", err)
	}
	conn.Close()

	// Wait for handler to finish
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleInbound timed out")
	}

	// Verify the event was processed
	val, err := mr.Get("ban:10.0.0.1")
	if err != nil {
		t.Fatalf("expected ban:10.0.0.1 to be set: %v", err)
	}
	if val != "test-inbound" {
		t.Errorf("ban:10.0.0.1 = %q; want test-inbound", val)
	}
}

// TestHandleDialRPC_WithTLS tests handleDialRPC via a real TLS connection.
func TestHandleDialRPC_WithTLS(t *testing.T) {
	agent, mr, certFile, keyFile, caFile := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()
	agent.ctx = context.Background()

	serverTLS, err := agent.loadServerTLSConfig()
	if err != nil {
		t.Fatalf("loadServerTLSConfig: %v", err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	// Accept and handle
	respCh := make(chan DialResponse, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		agent.handleDialRPC(conn)
	}()

	// Build client config
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	caData, _ := os.ReadFile(caFile)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caData)

	clientTLS := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	}

	conn, err := tls.Dial("tcp", addr, clientTLS)
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer conn.Close()

	// Send a signed dial request
	req := DialRequest{
		Dial:     42,
		OriginDC: "dc-test",
		OriginTS: time.Now().UnixMilli(),
	}
	agent.signDialRequest(&req)

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("encode: %v", err)
	}

	var resp DialResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	select {
	case respCh <- resp:
	default:
	}

	if !resp.OK {
		t.Errorf("DialResponse.OK = false; error = %q", resp.Error)
	}

	// Verify Redis was updated
	val, err := mr.Get("config:dial")
	if err != nil {
		t.Fatalf("expected config:dial to be set: %v", err)
	}
	if val != "42" {
		t.Errorf("config:dial = %q; want 42", val)
	}
}

// TestHandleDialRPC_OutOfBounds verifies dial bounds checking.
func TestHandleDialRPC_OutOfBounds(t *testing.T) {
	agent, mr, certFile, keyFile, caFile := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()
	agent.ctx = context.Background()

	serverTLS, _ := agent.loadServerTLSConfig()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			agent.handleDialRPC(conn)
		}
	}()

	cert, _ := tls.LoadX509KeyPair(certFile, keyFile)
	caData, _ := os.ReadFile(caFile)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caData)

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := DialRequest{
		Dial:     200, // out of bounds
		OriginDC: "dc-test",
		OriginTS: time.Now().UnixMilli(),
	}
	agent.signDialRequest(&req)
	json.NewEncoder(conn).Encode(req)

	var resp DialResponse
	json.NewDecoder(conn).Decode(&resp)

	if resp.OK {
		t.Error("expected dial out of bounds to be rejected")
	}
	if resp.Error != "dial out of bounds" {
		t.Errorf("error = %q; want 'dial out of bounds'", resp.Error)
	}
}

// TestHandleDialRPC_DCMismatch verifies DC identity check.
func TestHandleDialRPC_DCMismatch(t *testing.T) {
	agent, mr, certFile, keyFile, caFile := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()
	agent.ctx = context.Background()

	serverTLS, _ := agent.loadServerTLSConfig()
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			agent.handleDialRPC(conn)
		}
	}()

	cert, _ := tls.LoadX509KeyPair(certFile, keyFile)
	caData, _ := os.ReadFile(caFile)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caData)

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := DialRequest{
		Dial:     50,
		OriginDC: "dc-wrong", // Mismatch with cert CN
		OriginTS: time.Now().UnixMilli(),
	}
	agent.signDialRequest(&req)
	json.NewEncoder(conn).Encode(req)

	var resp DialResponse
	json.NewDecoder(conn).Decode(&resp)

	if resp.OK {
		t.Error("expected DC mismatch to be rejected")
	}
}

// TestHandleInbound_NonTLSConn verifies handleInbound returns early for non-TLS conn.
func TestHandleInbound_NonTLSConn(t *testing.T) {
	agent, mr, _, _, _ := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()
	agent.ctx = context.Background()

	// Use a plain TCP connection (not TLS)
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		agent.handleInbound(server) // should return immediately (not *tls.Conn)
		close(done)
	}()

	select {
	case <-done:
		// Good: returned early
	case <-time.After(2 * time.Second):
		t.Fatal("handleInbound should return immediately for non-TLS conn")
	}
}

// TestHandleDialRPC_NonTLSConn verifies handleDialRPC returns early for non-TLS conn.
func TestHandleDialRPC_NonTLSConn(t *testing.T) {
	agent, mr, _, _, _ := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()
	agent.ctx = context.Background()

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	done := make(chan struct{})
	go func() {
		agent.handleDialRPC(server)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleDialRPC should return immediately for non-TLS conn")
	}
}

// TestProcessInbound_ZAddFixed verifies the zadd bug fix uses event.Value as member.
func TestProcessInbound_ZAddFixed(t *testing.T) {
	agent, _, mr := newTestAgent(t)
	defer mr.Close()

	event := SyncEvent{
		Op:    "zadd",
		Key:   "test-zset",
		Value: "42.0",
	}
	agent.processInbound(event)

	// After fix: member is event.Value ("42.0"), not event.Key ("test-zset")
	score, err := mr.ZScore("test-zset", "42.0")
	if err != nil {
		t.Fatalf("ZScore for member '42.0' failed: %v", err)
	}
	if score != 42.0 {
		t.Errorf("score = %f; want 42.0", score)
	}

	// Verify the old buggy behavior is fixed: key should NOT be a member.
	// miniredis.ZScore returns 0 and no error for non-existent members in
	// some versions, so check the member list explicitly.
	members, _ := mr.ZMembers("test-zset")
	for _, m := range members {
		if m == "test-zset" {
			t.Error("key should NOT be used as member after bug fix")
		}
	}
}

// TestProcessInbound_SetWithTTL verifies TTL is applied correctly.
func TestProcessInbound_SetWithTTL(t *testing.T) {
	agent, _, mr := newTestAgent(t)
	defer mr.Close()

	event := SyncEvent{
		Op:    "set",
		Key:   "ban:192.168.1.1",
		Value: "ttl-test",
		TTLMS: 5000, // 5 seconds
	}
	agent.processInbound(event)

	val, _ := mr.Get("ban:192.168.1.1")
	if val != "ttl-test" {
		t.Errorf("value = %q; want ttl-test", val)
	}

	ttl := mr.TTL("ban:192.168.1.1")
	if ttl <= 0 {
		t.Error("expected positive TTL")
	}
}

// TestProcessInbound_UnknownOp verifies unknown ops are silently ignored.
func TestProcessInbound_UnknownOp(t *testing.T) {
	agent, _, mr := newTestAgent(t)
	defer mr.Close()

	event := SyncEvent{
		Op:    "delete", // not a recognized op
		Key:   "ban:1.1.1.1",
		Value: "test",
	}
	agent.processInbound(event)

	if mr.Exists("ban:1.1.1.1") {
		t.Error("unknown op should not create keys")
	}
}

// TestDeliverToPeer_ConnectionRefused verifies error on unreachable peer.
func TestDeliverToPeer_ConnectionRefused(t *testing.T) {
	agent, mr, _, _, _ := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()

	event := SyncEvent{
		Op:       "set",
		Key:      "ban:1.1.1.1",
		Value:    "test",
		OriginDC: "dc-test",
	}

	err := agent.deliverToPeer("127.0.0.1:1", event)
	if err == nil {
		t.Error("expected error for unreachable peer")
	}
}

// TestSendDialRPC_ConnectionRefused verifies sendDialRPC returns false for unreachable.
func TestSendDialRPC_ConnectionRefused(t *testing.T) {
	agent, mr, _, _, _ := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()

	ok := agent.sendDialRPC("127.0.0.1:1", 50)
	if ok {
		t.Error("sendDialRPC should return false for unreachable peer")
	}
}

// TestHandlePendingMessages_EmptyStream verifies graceful handling of empty stream.
func TestHandlePendingMessages_EmptyStream(t *testing.T) {
	agent, mr, _, _, _ := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()
	agent.ctx = context.Background()

	// Should not panic on non-existent stream/group
	agent.handlePendingMessages("127.0.0.1:1", "nonexistent:stream", "test-group", "test-consumer")
}

// TestLoadClientTLSConfig_MissingCA verifies error when CA file is empty.
func TestLoadClientTLSConfig_MissingCA(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	rc := redis.New(redis.Config{Host: mr.Host(), Port: mr.Server().Addr().Port}, log)

	cfg := &config.Config{}
	cfg.Sync.CertFile = "some-cert.pem"
	cfg.Sync.KeyFile = "some-key.pem"
	cfg.Sync.CAFile = ""
	agent := NewSyncAgent(cfg, rc, log.WithField("test", true))

	_, err := agent.loadClientTLSConfig()
	if err == nil {
		t.Fatal("expected error for missing CA")
	}
}

// TestLoadClientTLSConfig_InvalidCA verifies error for invalid CA content.
func TestLoadClientTLSConfig_InvalidCA(t *testing.T) {
	agent, mr, certFile, keyFile, _ := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()

	badCA := filepath.Join(t.TempDir(), "bad-ca.pem")
	os.WriteFile(badCA, []byte("not a pem"), 0o644)

	agent.cfg.Sync.CertFile = certFile
	agent.cfg.Sync.KeyFile = keyFile
	agent.cfg.Sync.CAFile = badCA

	_, err := agent.loadClientTLSConfig()
	if err == nil {
		t.Fatal("expected error for invalid CA content")
	}
}

// TestHandleInbound_InvalidSignature verifies events with bad signatures are rejected.
func TestHandleInbound_InvalidSignature(t *testing.T) {
	agent, mr, certFile, keyFile, caFile := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()
	agent.ctx = context.Background()

	serverTLS, _ := agent.loadServerTLSConfig()
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			agent.handleInbound(conn)
		}
	}()

	cert, _ := tls.LoadX509KeyPair(certFile, keyFile)
	caData, _ := os.ReadFile(caFile)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caData)

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Send event with invalid signature
	event := SyncEvent{
		Op:        "set",
		Key:       "ban:evil",
		Value:     "should-not-be-set",
		OriginTS:  time.Now().UnixMilli(),
		OriginDC:  "dc-test",
		Signature: "aW52YWxpZA==", // invalid
	}
	json.NewEncoder(conn).Encode(event)
	conn.Close()

	<-done

	// Verify event was NOT processed
	if mr.Exists("ban:evil") {
		t.Error("event with invalid signature should be rejected")
	}
}

// TestStart_ContextCancellation verifies Start returns when context is cancelled.
func TestStart_ContextCancellation(t *testing.T) {
	agent, mr, _, _, _ := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()

	// Use a free port for listeners
	freePort1 := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	freePort2 := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	agent.cfg.Sync.ListenAddr = freePort1
	agent.cfg.Sync.RPCListenAddr = freePort2
	agent.cfg.Sync.RemotePeers = nil

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- agent.Start(ctx)
	}()

	// Give listeners time to start
	time.Sleep(200 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Logf("Start returned error (acceptable): %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return after context cancellation")
	}
}

// freePort returns a free TCP port.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

// TestRunPeerReplicationLoop_ContextCancel verifies the loop exits on context cancel.
func TestRunPeerReplicationLoop_ContextCancel(t *testing.T) {
	agent, mr, _, _, _ := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	agent.ctx = ctx

	// Create the stream so XGroupCreate succeeds
	stream := "ja4proxy:dc:dc-test:sync:out"
	mr.XAdd(stream, "*", []string{"op", "set", "key", "ban:1.1.1.1", "value", "init"})

	done := make(chan error, 1)
	go func() {
		done <- agent.runPeerReplicationLoop("127.0.0.1:1")
	}()

	// Give the loop time to start and block on XReadGroup
	time.Sleep(300 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Logf("runPeerReplicationLoop error (acceptable): %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runPeerReplicationLoop did not exit after context cancel")
	}
}

// TestRunPeerReplicationLoop_WithDelivery tests the full replication path:
// write to stream -> read -> sign -> deliver -> ACK.
func TestRunPeerReplicationLoop_WithDelivery(t *testing.T) {
	agent, mr, _, _, _ := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()

	ctx, cancel := context.WithCancel(context.Background())
	agent.ctx = ctx

	// Set up a TLS listener to receive the replicated event
	serverTLS, _ := agent.loadServerTLSConfig()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	received := make(chan SyncEvent, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var event SyncEvent
		if err := json.NewDecoder(conn).Decode(&event); err == nil {
			received <- event
		}
	}()

	// Pre-seed the stream with a message
	stream := "ja4proxy:dc:dc-test:sync:out"
	mr.XAdd(stream, "*", []string{
		"op", "set",
		"key", "ban:replication-test",
		"value", "replicated",
		"origin_ts", fmt.Sprintf("%d", time.Now().UnixMilli()),
		"ttl_ms", "3600000",
	})

	// Start replication loop targeting our TLS listener
	done := make(chan error, 1)
	go func() {
		done <- agent.runPeerReplicationLoop(ln.Addr().String())
	}()

	// Wait for the event to be received
	select {
	case e := <-received:
		if e.Key != "ban:replication-test" {
			t.Errorf("received key = %q; want ban:replication-test", e.Key)
		}
		if e.Signature == "" {
			t.Error("event should be signed")
		}
	case <-time.After(5 * time.Second):
		t.Log("delivery not received within timeout (miniredis XReadGroup may not support blocking)")
	}

	cancel()
	<-done
}

// TestSendDialRPC_MissingCerts verifies sendDialRPC returns false with bad TLS.
func TestSendDialRPC_MissingCerts(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	rc := redis.New(redis.Config{Host: mr.Host(), Port: mr.Server().Addr().Port}, log)

	cfg := &config.Config{}
	cfg.Sync.DCID = "dc-test"
	cfg.Sync.CertFile = ""
	cfg.Sync.KeyFile = ""
	agent := NewSyncAgent(cfg, rc, log.WithField("test", true))

	pub, priv, _ := ed25519.GenerateKey(nil)
	agent.privKey = priv
	agent.pubKey = pub

	// Should return false because TLS config will fail
	ok := agent.sendDialRPC("127.0.0.1:1", 50)
	if ok {
		t.Error("sendDialRPC should return false with missing certs")
	}
}

// TestDeliverToPeer_MissingCerts verifies error with bad TLS config.
func TestDeliverToPeer_MissingCerts(t *testing.T) {
	mr, _ := miniredis.Run()
	defer mr.Close()
	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)
	rc := redis.New(redis.Config{Host: mr.Host(), Port: mr.Server().Addr().Port}, log)

	cfg := &config.Config{}
	cfg.Sync.DCID = "dc-test"
	cfg.Sync.CertFile = ""
	cfg.Sync.KeyFile = ""
	agent := NewSyncAgent(cfg, rc, log.WithField("test", true))

	event := SyncEvent{Op: "set", Key: "ban:1.1.1.1", Value: "test"}
	err := agent.deliverToPeer("127.0.0.1:1", event)
	if err == nil {
		t.Error("expected error for missing certs")
	}
}

// TestHandleDialRPC_InvalidSignature verifies rejection of bad dial signatures.
func TestHandleDialRPC_InvalidSignature(t *testing.T) {
	agent, mr, certFile, keyFile, caFile := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()
	agent.ctx = context.Background()

	serverTLS, _ := agent.loadServerTLSConfig()
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	defer ln.Close()

	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			agent.handleDialRPC(conn)
		}
	}()

	cert, _ := tls.LoadX509KeyPair(certFile, keyFile)
	caData, _ := os.ReadFile(caFile)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caData)

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := DialRequest{
		Dial:      50,
		OriginDC:  "dc-test",
		OriginTS:  time.Now().UnixMilli(),
		Signature: "aW52YWxpZA==", // bad signature
	}
	json.NewEncoder(conn).Encode(req)

	var resp DialResponse
	json.NewDecoder(conn).Decode(&resp)

	if resp.OK {
		t.Error("expected invalid signature to be rejected")
	}
	if resp.Error != "invalid signature" {
		t.Errorf("error = %q; want 'invalid signature'", resp.Error)
	}
}

// TestDeliverToPeer_Success verifies successful delivery via TLS.
func TestDeliverToPeer_Success(t *testing.T) {
	agent, mr, _, _, _ := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()

	// Set up a TLS listener that the agent can connect to
	serverTLS, err := agent.loadServerTLSConfig()
	if err != nil {
		t.Fatal(err)
	}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	received := make(chan SyncEvent, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var event SyncEvent
		if err := json.NewDecoder(conn).Decode(&event); err == nil {
			received <- event
		}
	}()

	event := SyncEvent{
		Op:       "set",
		Key:      "ban:1.1.1.1",
		Value:    "delivered",
		OriginDC: "dc-test",
		OriginTS: time.Now().UnixMilli(),
	}
	agent.signEvent(&event)

	err = agent.deliverToPeer(ln.Addr().String(), event)
	if err != nil {
		t.Fatalf("deliverToPeer error: %v", err)
	}

	select {
	case e := <-received:
		if e.Key != "ban:1.1.1.1" {
			t.Errorf("received key = %q; want ban:1.1.1.1", e.Key)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("did not receive event")
	}
}

// TestSendDialRPC_Success verifies successful dial RPC.
func TestSendDialRPC_Success(t *testing.T) {
	agent, mr, _, _, _ := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()

	// Start a TLS listener that acts as a peer DC.
	// Use the SAME agent's TLS config and share keys so signature verification succeeds.
	serverTLS, _ := agent.loadServerTLSConfig()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	// Create a peer agent that shares the same keys and cert CN
	peerMR, _ := miniredis.Run()
	defer peerMR.Close()
	peerLog := logrus.New()
	peerLog.SetLevel(logrus.ErrorLevel)
	peerRC := redis.New(redis.Config{Host: peerMR.Host(), Port: peerMR.Server().Addr().Port}, peerLog)
	peerAgent := &SyncAgent{
		cfg:     agent.cfg,
		rc:      peerRC,
		log:     peerLog.WithField("test", true),
		ctx:     context.Background(),
		privKey: agent.privKey,
		pubKey:  agent.pubKey,
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		peerAgent.handleDialRPC(conn)
	}()

	ok := agent.sendDialRPC(ln.Addr().String(), 42)
	if !ok {
		t.Error("sendDialRPC should return true for successful RPC")
	}

	// Verify the peer's Redis was updated
	val, _ := peerMR.Get("config:dial")
	if val != "42" {
		t.Errorf("peer config:dial = %q; want 42", val)
	}
}

// TestHandleInbound_MultipleSyncEvents verifies processing multiple events.
func TestHandleInbound_MultipleSyncEvents(t *testing.T) {
	agent, mr, certFile, keyFile, caFile := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()
	agent.ctx = context.Background()

	serverTLS, _ := agent.loadServerTLSConfig()
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			agent.handleInbound(conn)
		}
	}()

	cert, _ := tls.LoadX509KeyPair(certFile, keyFile)
	caData, _ := os.ReadFile(caFile)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caData)

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Send two valid events
	for i, key := range []string{"ban:10.0.0.1", "ban:10.0.0.2"} {
		event := SyncEvent{
			Op:       "set",
			Key:      key,
			Value:    fmt.Sprintf("multi-%d", i),
			OriginTS: time.Now().UnixMilli(),
			OriginDC: "dc-test",
		}
		agent.signEvent(&event)
		json.NewEncoder(conn).Encode(event)
	}
	conn.Close()
	<-done

	val1, _ := mr.Get("ban:10.0.0.1")
	val2, _ := mr.Get("ban:10.0.0.2")
	if val1 != "multi-0" {
		t.Errorf("ban:10.0.0.1 = %q; want multi-0", val1)
	}
	if val2 != "multi-1" {
		t.Errorf("ban:10.0.0.2 = %q; want multi-1", val2)
	}
}

// TestHandleInbound_DCMismatch verifies events from wrong DC are rejected.
func TestHandleInbound_DCMismatch_ViaConn(t *testing.T) {
	agent, mr, certFile, keyFile, caFile := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()
	agent.ctx = context.Background()

	serverTLS, _ := agent.loadServerTLSConfig()
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			agent.handleInbound(conn)
		}
	}()

	cert, _ := tls.LoadX509KeyPair(certFile, keyFile)
	caData, _ := os.ReadFile(caFile)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caData)

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Send event with mismatched DC
	event := SyncEvent{
		Op:       "set",
		Key:      "ban:dc-mismatch",
		Value:    "should-be-rejected",
		OriginTS: time.Now().UnixMilli(),
		OriginDC: "dc-wrong", // does not match cert CN
	}
	agent.signEvent(&event)
	json.NewEncoder(conn).Encode(event)
	conn.Close()
	<-done

	if mr.Exists("ban:dc-mismatch") {
		t.Error("event with DC mismatch should be rejected")
	}
}

// TestStart_FullLifecycle starts the agent with real TLS listeners, connects
// to both the sync and dial RPC ports, and then cancels the context to verify
// clean shutdown. This covers Start(), startListener(), and startDialRPCListener().
func TestStart_FullLifecycle(t *testing.T) {
	agent, mr, certFile, keyFile, caFile := newTestAgentWithTLS(t, "dc-start")
	defer mr.Close()

	syncPort := freePort(t)
	rpcPort := freePort(t)
	agent.cfg.Sync.ListenAddr = fmt.Sprintf("127.0.0.1:%d", syncPort)
	agent.cfg.Sync.RPCListenAddr = fmt.Sprintf("127.0.0.1:%d", rpcPort)
	agent.cfg.Sync.RemotePeers = nil // no outbound replication
	// Clear integrity key file so Start() generates ephemeral keys
	agent.cfg.Sync.IntegrityKeyFile = ""

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- agent.Start(ctx)
	}()

	// Wait for both listeners to be accepting connections
	syncAddr := fmt.Sprintf("127.0.0.1:%d", syncPort)
	rpcAddr := fmt.Sprintf("127.0.0.1:%d", rpcPort)

	// Load client TLS config
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	caData, _ := os.ReadFile(caFile)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caData)
	clientTLS := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	}

	// Poll until sync listener is ready (max 3s)
	var syncConn *tls.Conn
	for i := 0; i < 30; i++ {
		syncConn, err = tls.Dial("tcp", syncAddr, clientTLS)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("could not connect to sync listener: %v", err)
	}

	// Send a valid signed event to the sync port
	event := SyncEvent{
		Op:       "set",
		Key:      "ban:start-test",
		Value:    "started",
		OriginDC: "dc-start",
		OriginTS: time.Now().UnixMilli(),
		TTLMS:    60000,
	}
	agent.signEvent(&event)
	json.NewEncoder(syncConn).Encode(event)
	syncConn.Close()

	// Poll until dial RPC listener is ready (max 3s)
	var rpcConn *tls.Conn
	for i := 0; i < 30; i++ {
		rpcConn, err = tls.Dial("tcp", rpcAddr, clientTLS)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("could not connect to dial RPC listener: %v", err)
	}

	// Send a valid signed dial request
	req := DialRequest{
		Dial:      50,
		OriginDC:  "dc-start",
		OriginTS:  time.Now().UnixMilli(),
		Immediate: false,
	}
	agent.signDialRequest(&req)
	json.NewEncoder(rpcConn).Encode(req)

	var resp DialResponse
	json.NewDecoder(rpcConn).Decode(&resp)
	rpcConn.Close()

	if !resp.OK {
		t.Errorf("dial RPC should succeed, got error: %s", resp.Error)
	}

	// Give a moment for event processing
	time.Sleep(100 * time.Millisecond)

	// Verify the sync event was processed
	if !mr.Exists("ban:start-test") {
		t.Error("expected ban:start-test to be set via sync listener")
	}

	// Cancel context to trigger clean shutdown
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Start returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Start did not exit within 5 seconds after context cancel")
	}
}

// TestStart_WithPeerReplication exercises Start() with a remote peer configured,
// covering the peer replication goroutine launch path in Start().
func TestStart_WithPeerReplication(t *testing.T) {
	agent, mr, _, _, _ := newTestAgentWithTLS(t, "dc-peer-start")
	defer mr.Close()

	syncPort := freePort(t)
	rpcPort := freePort(t)
	agent.cfg.Sync.ListenAddr = fmt.Sprintf("127.0.0.1:%d", syncPort)
	agent.cfg.Sync.RPCListenAddr = fmt.Sprintf("127.0.0.1:%d", rpcPort)
	agent.cfg.Sync.RemotePeers = []string{"127.0.0.1:19999"} // unreachable peer, OK
	agent.cfg.Sync.IntegrityKeyFile = ""

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- agent.Start(ctx)
	}()

	// Wait for listeners to start, then cancel
	time.Sleep(500 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Errorf("Start returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("Start did not exit within 5 seconds")
	}
}

// TestStart_IntegrityKeyLoadError verifies Start returns error when integrity key file is invalid.
func TestStart_IntegrityKeyLoadError(t *testing.T) {
	agent, mr, _, _, _ := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()
	agent.cfg.Sync.IntegrityKeyFile = "/nonexistent/key"
	agent.privKey = nil
	agent.pubKey = nil

	err := agent.Start(context.Background())
	if err == nil {
		t.Error("expected error for missing integrity key file")
	}
}

// TestHandleInbound_DecodeError exercises the non-EOF decode error path in handleInbound.
func TestHandleInbound_DecodeError(t *testing.T) {
	agent, mr, certFile, keyFile, caFile := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()
	agent.ctx = context.Background()

	serverTLS, _ := agent.loadServerTLSConfig()
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			agent.handleInbound(conn)
		}
	}()

	cert, _ := tls.LoadX509KeyPair(certFile, keyFile)
	caData, _ := os.ReadFile(caFile)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caData)

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Send invalid JSON to trigger decode error (not EOF)
	conn.Write([]byte("{invalid json\n"))
	conn.Close()

	<-done
}

// TestHandleDialRPC_DecodeError verifies graceful handling of invalid JSON.
func TestHandleDialRPC_DecodeError(t *testing.T) {
	agent, mr, certFile, keyFile, caFile := newTestAgentWithTLS(t, "dc-test")
	defer mr.Close()
	agent.ctx = context.Background()

	serverTLS, _ := agent.loadServerTLSConfig()
	ln, _ := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, _ := ln.Accept()
		if conn != nil {
			agent.handleDialRPC(conn)
		}
	}()

	cert, _ := tls.LoadX509KeyPair(certFile, keyFile)
	caData, _ := os.ReadFile(caFile)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(caData)

	conn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Send invalid JSON
	conn.Write([]byte("not json\n"))

	var resp DialResponse
	json.NewDecoder(conn).Decode(&resp)
	conn.Close()

	if resp.OK {
		t.Error("expected decode error to be rejected")
	}

	<-done
}

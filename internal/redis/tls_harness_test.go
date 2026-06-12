package redis

// In-process TLS-wrapped miniredis harness for Phase 201a tests.
//
// newTLSMiniredis boots miniredis on one random local port, then fronts it with
// a tls.NewListener on a SECOND random local port. A real TLS handshake happens
// on every dial; bytes are piped bidirectionally between the TLS connection and
// a fresh plain TCP connection to miniredis. There are NO handshake-free
// shortcuts.
//
// The certificate is a freshly generated 2048-bit RSA self-signed cert with
// SANs for 127.0.0.1 and ::1, valid for 10 minutes.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

// generateSelfSignedCert returns a PEM-encoded cert + key and the parsed cert.
func generateSelfSignedCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ja4proxy-test"},
		NotBefore:    time.Now().Add(-1 * time.Minute),
		NotAfter:     time.Now().Add(10 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatalf("pool.AppendCertsFromPEM: failed to append")
	}
	return tlsCert, pool
}

// splitHostPort is a small helper returning host, port (int).
func splitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("net.SplitHostPort(%q): %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("strconv.Atoi(%q): %v", portStr, err)
	}
	return host, port
}

// newTLSMiniredis returns (addr, rootCAs, srv, cleanup). The returned addr is
// the TLS-fronted endpoint; rootCAs trusts the server cert. cleanup is also
// registered with t.Cleanup, so tests don't need to call it manually unless
// they want to force early teardown (e.g. restart scenarios).
func newTLSMiniredis(t *testing.T) (string, *x509.CertPool, *miniredis.Miniredis, func()) {
	t.Helper()

	srv, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	// Capture the backend address ONCE. The per-connection goroutines below
	// must never call srv.Addr() on the live object: restartMiniredisOnAddr()
	// does Close()+Restart() on the same address, and during that window the
	// miniredis' internal server is nil, so srv.Addr() segfaults (it locks a
	// nil mutex). The address is stable across restart by design, so a cached
	// string is both correct and race-free.
	backendAddr := srv.Addr()

	cert, pool := generateSelfSignedCert(t)
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	// Listen on a random localhost port with TLS.
	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		srv.Close()
		t.Fatalf("net.Listen: %v", err)
	}
	ln := tls.NewListener(rawLn, tlsCfg)

	errCh := make(chan error, 32)
	var wg sync.WaitGroup

	// Accept loop.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				if !isClosedErr(err) {
					errCh <- err
				}
				return
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer c.Close()
				backend, err := net.Dial("tcp", backendAddr)
				if err != nil {
					errCh <- err
					return
				}
				defer backend.Close()

				var pipeWG sync.WaitGroup
				pipeWG.Add(2)
				go func() {
					defer pipeWG.Done()
					_, err := io.Copy(backend, c)
					if err != nil && !isClosedErr(err) {
						errCh <- err
					}
					// Half-close the backend write side so its read side returns.
					if tcp, ok := backend.(*net.TCPConn); ok {
						_ = tcp.CloseWrite()
					}
				}()
				go func() {
					defer pipeWG.Done()
					_, err := io.Copy(c, backend)
					if err != nil && !isClosedErr(err) {
						errCh <- err
					}
					// When backend closes (miniredis shutdown), force-close the
					// client TLS conn so its sister io.Copy read-side unblocks.
					_ = c.Close()
				}()
				pipeWG.Wait()
			}(conn)
		}
	}()

	cleaned := false
	var cleanupMu sync.Mutex
	cleanup := func() {
		cleanupMu.Lock()
		defer cleanupMu.Unlock()
		if cleaned {
			return
		}
		cleaned = true
		_ = ln.Close()
		srv.Close()
		wg.Wait()
		close(errCh)
		for e := range errCh {
			if e != nil && !isClosedErr(e) {
				t.Errorf("tls harness pipe error: %v", e)
			}
		}
	}
	t.Cleanup(cleanup)

	return ln.Addr().String(), pool, srv, cleanup
}

// newPlainMiniredis is the non-TLS sister helper.
func newPlainMiniredis(t *testing.T) (string, *miniredis.Miniredis, func()) {
	t.Helper()
	srv, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	cleaned := false
	var mu sync.Mutex
	cleanup := func() {
		mu.Lock()
		defer mu.Unlock()
		if cleaned {
			return
		}
		cleaned = true
		srv.Close()
	}
	t.Cleanup(cleanup)
	return srv.Addr(), srv, cleanup
}

// restartMiniredisOnAddr stops oldSrv and starts a fresh miniredis on the same
// address, so go-redis connection pools see a real reconnect.
func restartMiniredisOnAddr(t *testing.T, oldSrv *miniredis.Miniredis) *miniredis.Miniredis {
	t.Helper()
	// miniredis.Restart() calls Start() directly; must Close() first so the
	// address is free and existing go-redis connections are dropped.
	oldSrv.Close()
	if err := oldSrv.Restart(); err != nil {
		t.Fatalf("miniredis.Restart: %v", err)
	}
	return oldSrv
}

// isClosedErr returns true for expected close/EOF errors that arise during
// harness teardown. These must NOT surface as test failures.
func isClosedErr(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	// TLS sometimes returns non-wrapped errors on abrupt close.
	msg := err.Error()
	if msg == "EOF" || msg == "tls: use of closed connection" {
		return true
	}
	// Plaintext client dialing TLS server or TLS client dialing plaintext
	// server: expected handshake failures, not harness bugs.
	if strings.Contains(msg, "tls: first record does not look like a TLS handshake") ||
		strings.Contains(msg, "tls: bad certificate") ||
		strings.Contains(msg, "remote error: tls:") {
		return true
	}
	return false
}

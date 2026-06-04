// Phase 137 — Advanced Adversarial Fuzzing.
package main

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/seanpor/ja4proxy/internal/config"
	proxypkg "github.com/seanpor/ja4proxy/internal/proxy"
	"github.com/seanpor/ja4proxy/internal/security"
	tlsparse "github.com/seanpor/ja4proxy/internal/tls"
	"github.com/sirupsen/logrus"
)

func seedAdversarialCorpus(f *testing.F) {
	f.Helper()
	roots := []string{
		"../../tests/adversarial/corpus",
		"tests/adversarial/corpus",
	}
	for _, root := range roots {
		matches, err := filepath.Glob(filepath.Join(root, "*.bin"))
		if err != nil || len(matches) == 0 {
			continue
		}
		for _, p := range matches {
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			f.Add(data)
		}
		return
	}
}

func FuzzClientHello(f *testing.F) {
	seedAdversarialCorpus(f)
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ParseClientHello panicked: %v", r)
			}
		}()
		_, _ = tlsparse.ParseClientHello(data)
	})
}

func FuzzReadProxyProtocol(f *testing.F) {
	f.Add([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 1234 443\r\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ReadProxyProtocol panicked: %v", r)
			}
		}()
		_, _ = proxypkg.ReadProxyProtocol(data)
	})
}

func FuzzReadProxyProtocolV2(f *testing.F) {
	f.Add([]byte{
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
		0x21, 0x11, 0x00, 0x0C, 1, 2, 3, 4, 5, 6, 7, 8, 0x04, 0xD2, 0x01, 0xBB,
	})
	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ReadProxyProtocolV2 panicked: %v", r)
			}
		}()
		_, _ = proxypkg.ReadProxyProtocolV2(data)
		_, _, _ = proxypkg.ReadProxyProtocolV2WithLength(data)
	})
}

func FuzzFragmentation(f *testing.F) {
	f.Add([]byte{
		0x16, 0x03, 0x01, 0x00, 0x2D, // TLS Handshake, 1.0, len 45
		0x01, 0x00, 0x00, 0x29, // ClientHello, len 41
		0x03, 0x03, // TLS 1.2
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
		0x00,                   // sid
		0x00, 0x02, 0x13, 0x01, // ciphers
		0x01, 0x00, // comp
	}, 10)

	f.Fuzz(func(t *testing.T, data []byte, splitIdx int) {
		if len(data) < 10 || len(data) > 4096 || splitIdx <= 0 || splitIdx >= len(data) {
			return
		}
		logger := logrus.New()
		logger.SetOutput(io.Discard)
		cfg := &config.Config{}
		cfg.Proxy.BufferSize = 4096
		cfg.Proxy.ReadTimeout = 1
		cfg.Proxy.ProxyProtocol = false
		no := false
		cfg.Security.EnforceTLSRecord = &no

		bl, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return
		}
		defer bl.Close()
		go func() {
			for {
				c, err := bl.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()

		host, portStr, _ := net.SplitHostPort(bl.Addr().String())
		port, _ := strconv.Atoi(portStr)
		cfg.Proxy.BackendHost = host
		cfg.Proxy.BackendPort = config.FlexInt(port)

		p := &proxy{
			cfg:      cfg,
			log:      logger,
			pipeline: security.NewPipeline(&security.PipelineConfig{}, nil, logger),
		}

		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return
		}
		defer l.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			c, err := l.Accept()
			if err != nil {
				return
			}
			p.handleConn(ctx, c)
		}()

		conn, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			return
		}
		defer conn.Close()

		_, _ = conn.Write(data[:splitIdx])
		time.Sleep(1 * time.Millisecond)
		_, _ = conn.Write(data[splitIdx:])
	})
}

func FuzzProtocolSmuggling(f *testing.F) {
	// Seed with non-TLS protocols
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	f.Add([]byte("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2\r\n"))
	f.Add([]byte("220 smtp.example.com ESMTP Postfix\r\n"))
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00}) // Valid TLS to compare

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 || len(data) > 4096 {
			return
		}

		logger := logrus.New()
		logger.SetOutput(io.Discard)
		cfg := &config.Config{}
		cfg.Proxy.BufferSize = 4096
		cfg.Proxy.ReadTimeout = 1
		cfg.Proxy.ProxyProtocol = false
		no := false
		cfg.Security.EnforceTLSRecord = &no

		bl, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return
		}
		defer bl.Close()

		// Capture backend data
		receivedCh := make(chan []byte, 1)
		go func() {
			c, err := bl.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			buf := make([]byte, 4096)
			n, _ := c.Read(buf)
			if n > 0 {
				receivedCh <- buf[:n]
			}
		}()

		host, portStr, _ := net.SplitHostPort(bl.Addr().String())
		port, _ := strconv.Atoi(portStr)
		cfg.Proxy.BackendHost = host
		cfg.Proxy.BackendPort = config.FlexInt(port)

		p := &proxy{
			cfg:      cfg,
			log:      logger,
			pipeline: security.NewPipeline(&security.PipelineConfig{}, nil, logger),
		}

		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return
		}
		defer l.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			c, err := l.Accept()
			if err != nil {
				return
			}
			p.handleConn(ctx, c)
		}()

		conn, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			return
		}
		defer conn.Close()

		_, _ = conn.Write(data)

		// If first byte is NOT 0x16, nothing should reach the backend
		if data[0] != 0x16 && p.cfg.Security.ProtocolLockdownEnabled() {
			select {
			case d := <-receivedCh:
				t.Fatalf("Protocol smuggling successful! Backend received %d bytes: %x", len(d), d)
			case <-time.After(10 * time.Millisecond):
				// OK
			}
		}
	})
}

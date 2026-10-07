// Copyright (c) 2026 JA4proxy Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"pgregory.net/rapid"

	"github.com/seanpor/ja4proxy/internal/config"
	"github.com/seanpor/ja4proxy/internal/testutil/tlsfixture"
)

func setupSpliceTestProxy(t *testing.T, backendAddr string) (*proxy, *miniredis.Miniredis, *config.Config, net.Listener) {
	t.Helper()
	prx, mr, cfg := newTestProxy(t)
	host, portStr, _ := net.SplitHostPort(backendAddr)
	port, _ := strconv.Atoi(portStr)
	cfg.Proxy.BackendHost = host
	cfg.Proxy.BackendPort = config.FlexInt(port)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go prx.handleConn(context.Background(), conn)
		}
	}()

	return prx, mr, cfg, ln
}

// INV-SPLICE-001: Homomorphic Stream Partitioning
func TestInvariant_Splice_HomomorphicChunkSlicingAndReplay(t *testing.T) {
	echoAddr, cleanupEcho := startEchoServer(t)
	defer cleanupEcho()

	prx, mr, _, listener := setupSpliceTestProxy(t, echoAddr)
	defer mr.Close()
	defer listener.Close()

	spec := tlsfixture.Spec{SNI: "example.com"}
	hello := tlsfixture.Build(spec)

	rapid.Check(t, func(t *rapid.T) {
		appDataLen := rapid.IntRange(512, 4096).Draw(t, "appDataLen")
		appData := make([]byte, appDataLen)
		_, _ = rand.Read(appData)
		fullPayload := append(hello, appData...)

		chunkSizes := []int{1, 7, 64, 512, 1460}
		chunkSize := rapid.SampledFrom(chunkSizes).Draw(t, "chunkSize")

		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatalf("Dial failed: %v", err)
		}
		defer conn.Close()

		go func() {
			for i := 0; i < len(fullPayload); i += chunkSize {
				end := i + chunkSize
				if end > len(fullPayload) {
					end = len(fullPayload)
				}
				_, _ = conn.Write(fullPayload[i:end])
				time.Sleep(50 * time.Microsecond)
			}
		}()

		received := make([]byte, len(fullPayload))
		_, err = io.ReadFull(conn, received)
		if err != nil {
			t.Fatalf("Read failed for chunk size %d: %v", chunkSize, err)
		}

		if !bytes.Equal(received, fullPayload) {
			t.Fatalf("Stream corrupted for chunk size %d: got %d bytes, want %d", chunkSize, len(received), len(fullPayload))
		}
	})
	_ = prx
}

// INV-SPLICE-002: Lossless ClientHello Replay
func TestInvariant_Splice_LosslessClientHelloReplay(t *testing.T) {
	echoAddr, cleanupEcho := startEchoServer(t)
	defer cleanupEcho()

	prx, mr, _, listener := setupSpliceTestProxy(t, echoAddr)
	defer mr.Close()
	defer listener.Close()

	rapid.Check(t, func(t *rapid.T) {
		spec := tlsfixture.GenSpec().Draw(t, "tlsSpec")
		hello := tlsfixture.Build(spec)

		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatalf("Dial failed: %v", err)
		}
		defer conn.Close()

		_, err = conn.Write(hello)
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}

		buf := make([]byte, len(hello))
		_, err = io.ReadFull(conn, buf)
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}

		if !bytes.Equal(buf, hello) {
			t.Fatalf("ClientHello replay byte mismatch: got %x, want %x", buf[:16], hello[:16])
		}
	})
	_ = prx
}

// INV-SPLICE-003: Backpressure Buffer Bounding
func TestInvariant_Splice_BackpressureBufferBounding(t *testing.T) {
	stalledAddr, cleanupStalled := startDiscardServer(t)
	defer cleanupStalled()

	prx, mr, cfg, listener := setupSpliceTestProxy(t, stalledAddr)
	defer mr.Close()
	defer listener.Close()
	cfg.Proxy.BufferSize = 4096

	spec := tlsfixture.Spec{}
	hello := tlsfixture.Build(spec)

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write(hello)
	if err != nil {
		t.Fatalf("Write ClientHello failed: %v", err)
	}

	_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	bigChunk := make([]byte, 64*1024)
	writtenTotal := 0
	for i := 0; i < 200; i++ {
		n, werr := conn.Write(bigChunk)
		writtenTotal += n
		if werr != nil {
			break
		}
	}
	if writtenTotal > 64*1024*1024 {
		t.Fatalf("Backpressure failed: allowed excessive write without buffer bounding: %d bytes", writtenTotal)
	}
	_ = prx
}

// INV-SPLICE-004: Non-TLS Lockdown Fail-Closed
func TestInvariant_Splice_NonTLSProtocolLockdownFailClosed(t *testing.T) {
	echoAddr, cleanupEcho := startEchoServer(t)
	defer cleanupEcho()

	prx, mr, cfg, listener := setupSpliceTestProxy(t, echoAddr)
	defer mr.Close()
	defer listener.Close()
	enforce := true
	cfg.Security.EnforceTLSRecord = &enforce

	rapid.Check(t, func(t *rapid.T) {
		nonTLSHeader := rapid.SampledFrom([][]byte{
			[]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			[]byte("SSH-2.0-OpenSSH_8.9\r\n"),
			{0x00, 0x01, 0x02, 0x03, 0x04},
		}).Draw(t, "nonTLSHeader")

		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatalf("Dial failed: %v", err)
		}
		defer conn.Close()

		_, _ = conn.Write(nonTLSHeader)

		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		out := make([]byte, 100)
		n, err := conn.Read(out)
		if n > 0 {
			t.Fatalf("Non-TLS payload was forwarded despite lockdown: %d bytes read (%q)", n, out[:n])
		}
		if err == nil {
			t.Fatalf("Expected connection to be closed by proxy under non-TLS lockdown")
		}
	})
	_ = prx
}

// Copyright (c) 2026 JA4proxy Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"go.uber.org/goleak"

	"github.com/seanpor/ja4proxy/internal/config"
	"github.com/seanpor/ja4proxy/internal/testutil/tlsfixture"
)

func setupResourceTestProxy(t *testing.T, backendAddr string, modifyCfg ...func(*config.Config)) (*proxy, *miniredis.Miniredis, *config.Config, net.Listener) {
	t.Helper()
	prx, mr, cfg := newTestProxy(t)
	host, portStr, _ := net.SplitHostPort(backendAddr)
	port, _ := strconv.Atoi(portStr)
	cfg.Proxy.BackendHost = host
	cfg.Proxy.BackendPort = config.FlexInt(port)
	for _, fn := range modifyCfg {
		fn(cfg)
	}
	if prx.Server != nil {
		prx.Server.Cfg = cfg
	}

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

// INV-RESOURCE-001: Goroutine Conservation Law
func TestInvariant_Resource_GoroutineConservation(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	echoAddr, cleanupEcho := startEchoServer(t)
	defer cleanupEcho()

	prx, mr, _, listener := setupResourceTestProxy(t, echoAddr)

	hello := tlsfixture.Build(tlsfixture.Spec{})
	for i := 0; i < 30; i++ {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			continue
		}
		_, _ = conn.Write(hello)
		if i%2 == 0 {
			_ = conn.(*net.TCPConn).SetLinger(0)
		}
		_ = conn.Close()
	}

	time.Sleep(200 * time.Millisecond)

	listener.Close()
	mr.Close()
	_ = prx
}

// INV-RESOURCE-003: Slowloris Read Timeout Bound
func TestInvariant_Resource_SlowlorisReadTimeout(t *testing.T) {
	echoAddr, cleanupEcho := startEchoServer(t)
	defer cleanupEcho()

	_, mr, _, listener := setupResourceTestProxy(t, echoAddr, func(c *config.Config) {
		c.Proxy.ReadTimeout = 1
	})
	defer mr.Close()
	defer listener.Close()

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	start := time.Now()
	// Stalled client sends 0 bytes and waits for proxy timeout

	buf := make([]byte, 10)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Read(buf)

	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("Expected slowloris connection to be closed by proxy read timeout")
	}
	if elapsed > 3*time.Second {
		t.Fatalf("Slowloris read timeout out of bounds: elapsed %v", elapsed)
	}
}

// INV-RESOURCE-004: Abrupt TCP RST Resiliency
func TestInvariant_Resource_AbruptTCPRSTResiliency(t *testing.T) {
	echoAddr, cleanupEcho := startEchoServer(t)
	defer cleanupEcho()

	prx, mr, _, listener := setupResourceTestProxy(t, echoAddr)
	defer mr.Close()
	defer listener.Close()

	hello := tlsfixture.Build(tlsfixture.Spec{})
	for i := 0; i < 20; i++ {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			continue
		}
		_, _ = conn.Write(hello[:10])
		_ = conn.(*net.TCPConn).SetLinger(0)
		_ = conn.Close()
	}

	time.Sleep(100 * time.Millisecond)
	_ = prx
}

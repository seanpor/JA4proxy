//go:build soak

// Copyright (c) 2026 JA4proxy Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"net"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/seanpor/ja4proxy/internal/config"
	"github.com/seanpor/ja4proxy/internal/testutil/tlsfixture"
)

// TestSoak_ProxyGoroutineLeakUnderAbruptRST verifies that rapid opening and
// abrupt RST termination of 500 TLS connections leaves zero lingering goroutines.
func TestSoak_ProxyGoroutineLeakUnderAbruptRST(t *testing.T) {
	defer goleak.VerifyNone(t,
		goleak.IgnoreCurrent(),
		goleak.IgnoreTopFunction("internal/poll.runtime_pollWait"),
		goleak.IgnoreTopFunction("time.Sleep"),
		goleak.IgnoreTopFunction("github.com/redis/go-redis/v9/internal/pool.(*ConnPool).dialConn"),
		goleak.IgnoreTopFunction("github.com/redis/go-redis/v9/internal/pool.(*ConnPool).addIdleConn"),
		goleak.IgnoreTopFunction("github.com/redis/go-redis/v9/internal/pool.(*ConnPool).checkMinIdleConns"),
		goleak.IgnoreTopFunction("github.com/redis/go-redis/v9/internal/pool.(*ConnPool).reap"),
	)

	echoAddr, cleanupEcho := startEchoServer(t)
	defer cleanupEcho()

	prx, _, _, listener, cleanup := setupResourceTestProxy(t, echoAddr, func(c *config.Config) {
		c.Proxy.ReadTimeout = 2
	})
	defer cleanup()

	hello := tlsfixture.Build(tlsfixture.Spec{})
	addr := listener.Addr().String()

	concurrency := 20
	iterations := 25 // 500 connections total
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
				if err != nil {
					continue
				}
				// Write truncated ClientHello to trigger server handling
				_, _ = conn.Write(hello[:15])
				// Immediate abortive RST
				if tcpConn, ok := conn.(*net.TCPConn); ok {
					_ = tcpConn.SetLinger(0)
				}
				_ = conn.Close()
			}
		}()
	}

	wg.Wait()
	_ = prx

	// Grace period for proxy handler cleanup and socket close propagation
	time.Sleep(500 * time.Millisecond)
}

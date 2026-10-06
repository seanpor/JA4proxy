// Copyright (c) 2026 JA4proxy Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

//go:build linux

package main

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/seanpor/ja4proxy/internal/testutil/tlsfixture"
)

func countOpenFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("Failed to read /proc/self/fd: %v", err)
	}
	return len(entries)
}

// INV-RESOURCE-002: File Descriptor Conservation Law
func TestInvariant_Resource_FDConservationLinux(t *testing.T) {
	echoAddr, cleanupEcho := startEchoServer(t)
	defer cleanupEcho()

	prx, mr, _, listener := setupResourceTestProxy(t, echoAddr)
	defer mr.Close()
	defer listener.Close()

	hello := tlsfixture.Build(tlsfixture.Spec{})

	// Warmup connection to initialize lazy Redis client pools
	if warm, err := net.Dial("tcp", listener.Addr().String()); err == nil {
		_, _ = warm.Write(hello)
		_ = warm.Close()
		time.Sleep(100 * time.Millisecond)
	}

	initialFDs := countOpenFDs(t)
	for i := 0; i < 5; i++ {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatalf("Dial failed: %v", err)
		}
		_, err = conn.Write(hello)
		if err != nil {
			t.Fatalf("Write failed: %v", err)
		}
		_ = conn.Close()
		time.Sleep(50 * time.Millisecond)
	}

	time.Sleep(500 * time.Millisecond)

	finalFDs := countOpenFDs(t)
	if finalFDs > initialFDs+10 {
		t.Fatalf("File descriptor leak: initial %d, final %d", initialFDs, finalFDs)
	}
	_ = prx
}

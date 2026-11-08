// 30 s at 1,000 CPS against one 4-tuple on the real host, to test the Phase 867
// report's claim that ephemeral-port exhaustion produces a cliff at
// N_ports/lambda seconds (report §3.3: "after 28 seconds ... EADDRNOTAVAIL").
//
// Run on the host (this machine: tcp_tw_reuse=2, port range 32768-60999,
// tcp_fin_timeout=60):  go run .
//
// Observed (host_dial_loop.transcript.txt): 28,096 successful connections in 30 s,
// zero errors — numerically at the report's N_ports but with no cliff and no
// EADDRNOTAVAIL at all. An earlier pass measured 28,637 with the same verdict.
package main

import (
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	b, _ := os.ReadFile("/proc/sys/net/ipv4/tcp_tw_reuse")
	pr, _ := os.ReadFile("/proc/sys/net/ipv4/ip_local_port_range")
	fmt.Printf("tw_reuse=%s port_range=%s\n", string(b), string(pr))

	ln, err := net.Listen("tcp", "127.0.0.1:19002")
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { _ = c.Close() }(c)
		}
	}()
	time.Sleep(100 * time.Millisecond)

	var ok, fail int
	var firstErr error
	start := time.Now()
	tick := time.NewTicker(time.Millisecond) // 1,000 CPS
	defer tick.Stop()
	deadline := start.Add(30 * time.Second)
	for t := range tick.C {
		if t.After(deadline) {
			break
		}
		c, err := net.Dial("tcp", "127.0.0.1:19002")
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("at %v: %w", time.Since(start).Truncate(time.Second), err)
			}
			fail++
			continue
		}
		ok++
		_ = c.Close() // client closes first -> client holds the TIME_WAIT socket
	}
	fmt.Printf("30s @1000CPS: ok=%d fail=%d firstErr=%v\n", ok, fail, firstErr)
}

// One-shot dial-churn probe: how many connections to a single 4-tuple before
// connect() fails with EADDRNOTAVAIL ("cannot assign requested address"), and at
// what n. Run it inside a container network namespace so the host's sysctls are
// untouched:
//
//   docker run --rm \
//     --sysctl net.ipv4.ip_local_port_range="32768 34768" \
//     --sysctl net.ipv4.tcp_tw_reuse=0 \
//     -v "$PWD":/src -w /src golang:1.27.3-alpine go run .
//
// Observed at 2,001 ports, 8,000 attempts (transcript in this directory; re-runs vary
// by a handful of connections, so both passes are listed):
//   tcp_tw_reuse=0             -> netns_tw_reuse_0.transcript.txt   ok=2007 (earlier pass 2009)
//   tcp_tw_reuse=2             -> netns_tw_reuse_2.transcript.txt   ok=4013 (earlier pass 4831)
//   tcp_tw_reuse=0, fin_timeout=5 -> netns_tw_reuse0_fin5.transcript.txt ok=2017
// The client closes first, so the client side holds the TIME_WAIT socket.
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

	ln, err := net.Listen("tcp", "127.0.0.1:19003")
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
	t0 := time.Now()
	for i := 0; i < 8000; i++ {
		c, err := net.Dial("tcp", "127.0.0.1:19003")
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("n=%d at t=%v: %w", i, time.Since(t0).Truncate(time.Millisecond), err)
			}
			fail++
			continue
		}
		ok++
		_ = c.Close()
	}
	fmt.Printf("ok=%d fail=%d elapsed=%v firstErr=%v\n",
		ok, fail, time.Since(t0).Truncate(time.Millisecond), firstErr)
}

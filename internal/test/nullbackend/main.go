// Copyright (c) 2026 JA4proxy Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" { port = "443" }
	
	// Load certs
	cert, err := tls.LoadX509KeyPair("deploy/ssl/certs/backend.crt", "deploy/ssl/private/backend.key")
	if err != nil {
		log.Fatalf("failed to load keypair: %v", err)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	ln, err := tls.Listen("tcp", ":"+port, config)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	log.Printf("Go Null-Backend (High Perf) listening on :%s", port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	t4 := time.Now()
	if os.Getenv("JA4PROXY_FORENSIC") == "true" {
		_, lport, _ := net.SplitHostPort(conn.RemoteAddr().String())
		fmt.Printf("TRACE [B] port=%s T4=%d\n", lport, t4.UnixNano())
	}
	defer conn.Close()
	
	// Read request line
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	t5 := time.Now()
	if os.Getenv("JA4PROXY_FORENSIC") == "true" {
		_, lport, _ := net.SplitHostPort(conn.RemoteAddr().String())
		fmt.Printf("TRACE [B] port=%s T5=%d\n", lport, t5.UnixNano())
	}

	if err != nil {
		return
	}

	if line != "" {
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	}
}

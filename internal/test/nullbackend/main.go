// Copyright (c) 2026 JA4proxy Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"crypto/tls"
	"io"
	"log"
	"net"
	"os"
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
	defer conn.Close()
	
	// Read request line
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	// Simple response for health or any GET
	if line != "" {
		io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	}
}

package main

import (
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

	config := &tls.Config{Certificates: []tls.Certificate{cert}}
	ln, err := tls.Listen("tcp", ":"+port, config)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	log.Printf("Go Null-Backend listening on :%s", port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	defer conn.Close()
	// Consume data and close as fast as possible
	io.Copy(io.Discard, conn)
}

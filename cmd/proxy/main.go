//go:build !test

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/anomalyco/ja4proxy/internal/config"
)

func main() {
	cfg, err := config.Load("config/proxy.yml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	server, err := NewProxy(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize proxy: %v\n", err)
		os.Exit(1)
	}

	go server.Run()
	setupInterruptHandler(server)
}

func setupInterruptHandler(server *Proxy) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	<-sigChan
	server.Close()
	os.Exit(0)
}

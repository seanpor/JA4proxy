package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/seanpor/ja4proxy/internal/config"
	"github.com/sirupsen/logrus"
)

func TestRunDaemonLifecycle(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()

	// Free local port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	cfg := config.DefaultConfig()
	cfg.Redis.Host = mr.Host()
	cfg.Redis.Port = config.FlexInt(mr.Server().Addr().Port)
	cfg.Redis.Password = "test-secret"
	cfg.Redis.ACLUsers.Enabled = true
	cfg.Redis.ACLUsers.ProxyUser = "ja4proxy_app"
	cfg.Proxy.BindHost = "127.0.0.1"
	cfg.Proxy.BindPort = config.FlexInt(port)
	cfg.Metrics.Enabled = false

	log := logrus.New()
	log.SetLevel(logrus.ErrorLevel)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)

	go func() {
		done <- RunDaemon(ctx, cfg, "", log)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("RunDaemon returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RunDaemon did not terminate on context cancellation")
	}
}

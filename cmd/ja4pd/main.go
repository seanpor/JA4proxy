// Copyright (c) 2026 JA4proxy Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

// JA4proxy — Go TLS-aware passthrough security proxy binary daemon.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/seanpor/ja4proxy/internal/config"
	"github.com/seanpor/ja4proxy/internal/metrics"
	"github.com/seanpor/ja4proxy/internal/server"
)



func main() {
	cfgPath := os.Getenv("CONFIG_PATH")
	if cfgPath == "" {
		cfgPath = "config/proxy.yml"
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	log := server.NewLogger(cfg)
	log.WithFields(logrus.Fields{
		"version": config.Version,
		"built":   config.BuildDate,
		"commit":  config.GitCommit,
	}).Info("JA4proxy daemon starting")

	if os.Getenv("ENVIRONMENT") == "production" && os.Getenv("ALLOW_UNAUTH_REDIS") == "true" {
		log.Fatal("Insecure Redis config blocked in production")
	}

	metrics.Register()
	server.UpdateTLSCertExpiryGauge(os.Getenv("JA4PROXY_TLS_CERT_FILE"), log)

	srv, err := server.NewWithConfigPath(cfg, cfgPath, log)
	if err != nil {
		log.WithError(err).Fatal("failed to initialise proxy")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	go func() {
		for sig := range sigChan {
			switch sig {
			case syscall.SIGHUP:
				log.Info("SIGHUP received — reloading configuration")
				if err := srv.Reload(); err != nil {
					log.WithError(err).Error("failed to reload configuration")
				}
			case syscall.SIGINT, syscall.SIGTERM:
				log.WithField("signal", sig).Info("shutdown signal received")
				cancel()
				srv.Drain(cfg.Proxy.DrainTimeoutSeconds)
				os.Exit(0)
			}
		}
	}()

	srv.Serve(ctx)
}

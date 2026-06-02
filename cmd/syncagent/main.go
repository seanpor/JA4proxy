package main

import (
	"context"
	"flag"
	"os/signal"
	"syscall"
	"time"

	"github.com/anomalyco/ja4proxy/internal/config"
	"github.com/anomalyco/ja4proxy/internal/logging"
	"github.com/anomalyco/ja4proxy/internal/redis"
	"github.com/sirupsen/logrus"
)

func main() {
	configPath := flag.String("config", "config/proxy.yml", "Path to proxy.yml")
	flag.Parse()

	log := logrus.New()
	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// Logging Setup (Phase 80 ECS support)
	if cfg.Logging.Format == "ecs" {
		log.SetFormatter(&logging.ECSFormatter{})
	}
	level, _ := logrus.ParseLevel(cfg.Logging.Level)
	log.SetLevel(level)

	baseLog := log.WithFields(logrus.Fields{
		"service.name": "ja4proxy-syncagent",
		"service.id":   cfg.Sync.DCID,
	})

	baseLog.WithFields(logrus.Fields{
		"dc":   cfg.Sync.DCID,
		"addr": cfg.Sync.ListenAddr,
	}).Info("ja4proxy-syncagent starting")

	// JA4PROXY-2026-0041: Mesh Integrity (Fail Closed)
	if cfg.Sync.IntegrityKeyFile == "" {
		baseLog.Fatal("Integrity key required for sync mesh (JA4PROXY-2026-0041)")
	}

	// Redis Setup
	redisCfg := redis.Config{
		Host:       cfg.Redis.Host,
		Port:       cfg.Redis.Port.Int(),
		MasterName: cfg.Redis.MasterName,
		Sentinels:  cfg.Redis.Sentinels,
		DB:         cfg.Redis.DB,
		Password:   cfg.Redis.Password,
		Username:   cfg.Redis.Username,
		SSL:        cfg.Redis.SSL,
		Timeout:    time.Duration(cfg.Redis.Timeout.Int()) * time.Second,
	}
	rc := redis.New(redisCfg, log)
	defer rc.Close()

	agent := NewSyncAgent(cfg, rc, baseLog)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := agent.Start(ctx); err != nil {
		baseLog.WithError(err).Fatal("syncagent failed")
	}

	baseLog.Info("ja4proxy-syncagent stopped")
}

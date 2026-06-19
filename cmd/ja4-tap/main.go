// Command ja4-tap is the standalone JA4proxy passive TAP/SPAN sensor
// (PHASE_316a). It reads mirrored traffic — from a live interface or an offline
// .pcap file — reassembles each TCP connection, and reports the ClientHello /
// ServerHello bytes of every TLS handshake. It computes no fingerprints and
// writes nothing to Redis (that is 316b onward); this binary proves the capture
// and reassembly foundation end to end.
//
// It is deliberately a separate binary from the inline proxy (cmd/ja4pd): the
// sensor needs CAP_NET_RAW and promiscuous mode, which the proxy must never
// carry (PHASE_316a §3b).
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"

	"github.com/seanpor/ja4proxy/internal/tap"
)

// redisAdapter adapts a go-redis client to tap.redisSetter (Set returning an
// error). It is the only Redis surface the sensor needs: a least-privilege
// deployment grants the tap user write access to fp:* and nothing else.
type redisAdapter struct{ rdb *redis.Client }

func (a redisAdapter) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return a.rdb.Set(ctx, key, value, ttl).Err()
}

// storeWriteTimeout bounds each fire-and-forget fingerprint write so a slow or
// unreachable Redis can never stall the event drain (and thus, indirectly, the
// capture path). On timeout the write is dropped and counted — fail-open.
const storeWriteTimeout = 100 * time.Millisecond

func main() {
	var (
		pcapFile    = flag.String("pcap-file", "", "offline .pcap file to replay (no privileges required)")
		iface       = flag.String("interface", "", "live capture interface (Linux AF_PACKET; needs CAP_NET_RAW)")
		frameSize   = flag.Int("frame-size", 0, "AF_PACKET frame size (0 = library default)")
		quiet       = flag.Bool("quiet", false, "suppress per-handshake output; print only the final summary")
		redisURL    = flag.String("redis-url", "", "Redis URL to write passive fingerprints to fp:os:ip and fp:ja4t:ip (empty = classify-and-log only, no writes)")
		enforce     = flag.Bool("enforce", false, "ARM active blocking: write enforceable ban:{ip} keys for blocklisted clients (off = advisory fp:ban_intent watchlist only; arming also needs a widened Redis ACL ~ban:*)")
		ja4tBlock   = flag.String("ja4t-blocklist", "", "comma-separated JA4T fingerprints that trigger an out-of-band ban intent (empty = enforcement can never fire)")
		banTTL      = flag.Duration("ban-ttl", 5*time.Minute, "TTL for a sensor-written ban:{ip} (kept short by the fail-open asymmetry)")
		intentTTL   = flag.Duration("intent-ttl", time.Hour, "TTL for an advisory fp:ban_intent:ip watchlist entry")
		metricsAddr = flag.String("metrics-addr", "", "HTTP address for Prometheus metrics and /health (empty = disabled)")
	)
	flag.Parse()

	log := logrus.New()
	prometheus.MustRegister(tap.Collectors()...)
	startMetricsServer(log, *metricsAddr)
	enfCfg := tap.EnforcerConfig{
		Armed:         *enforce,
		JA4TBlocklist: parseBlocklist(*ja4tBlock),
		BanTTL:        *banTTL,
		IntentTTL:     *intentTTL,
	}
	if err := run(*pcapFile, *iface, *frameSize, *quiet, *redisURL, enfCfg, log); err != nil {
		log.WithError(err).Error("ja4-tap exited with error")
		os.Exit(1)
	}
}

// parseBlocklist splits a comma-separated flag into a set, trimming whitespace
// and dropping empties so a trailing comma or blank entry is harmless.
func parseBlocklist(csv string) map[string]bool {
	out := map[string]bool{}
	for _, p := range strings.Split(csv, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out[p] = true
		}
	}
	return out
}

func run(pcapFile, iface string, frameSize int, quiet bool, redisURL string, enfCfg tap.EnforcerConfig, log *logrus.Logger) error {
	if (pcapFile == "") == (iface == "") {
		return fmt.Errorf("exactly one of --pcap-file or --interface must be set")
	}

	store, enforcer, err := buildBackends(redisURL, enfCfg, log)
	if err != nil {
		return err
	}
	// Apply post-bind security hardening before starting the capture loop.
	if err := tap.DropCapabilities(); err != nil {
		log.WithError(err).Warn("failed to drop capabilities; proceeding with current UID/GID")
	}
	if err := tap.LoadSeccomp(); err != nil {
		log.WithError(err).Warn("failed to load seccomp profile; proceeding without seccomp")
	}
	warnEnforcementPosture(redisURL, enfCfg, log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if pcapFile != "" {
		src, lt, closeFn, err := tap.OpenPcapFile(pcapFile)
		if err != nil {
			return fmt.Errorf("open pcap: %w", err)
		}
		return drive(ctx, tap.NewSensor(lt, 1024), src, closeFn, store, enforcer, quiet, log)
	}

	// Live capture. Capability drop + seccomp + kernel BPF are deferred to
	// 316a increment 2; warn loudly so this isn't mistaken for hardened.
	log.Warn("live capture: capability-drop, seccomp and kernel BPF are not yet wired (316a increment 2) — run with NET_RAW only")
	src, lt, closeFn, err := tap.NewLiveSource(iface, frameSize)
	if err != nil {
		return fmt.Errorf("open live interface %q: %w", iface, err)
	}
	return drive(ctx, tap.NewSensor(lt, 1024), src, func() error { closeFn(); return nil }, store, enforcer, quiet, log)
}

// warnEnforcementPosture emits the startup WARN + records the posture the same
// way the inline proxy warns on every armed high-risk bypass. It also catches
// the two foot-guns: armed with nowhere to write, and armed with nothing to
// match.
func warnEnforcementPosture(redisURL string, cfg tap.EnforcerConfig, log *logrus.Logger) {
	if !cfg.Armed {
		log.WithField("blocklist_size", len(cfg.JA4TBlocklist)).
			Info("enforcement advisory-only: blocklisted clients are recorded to fp:ban_intent, nothing is blocked (--enforce to arm)")
		return
	}
	log.WithFields(logrus.Fields{
		"blocklist_size": len(cfg.JA4TBlocklist),
		"ban_ttl":        cfg.BanTTL.String(),
	}).Warn("ENFORCEMENT ARMED: matched clients will be written as enforceable ban:{ip} keys — needs Redis ACL ~ban:*; verify monitor-first review of fp:ban_intent before relying on this")
	if redisURL == "" {
		log.Warn("enforcement armed but no --redis-url: no ban can be written (no-op)")
	}
	if len(cfg.JA4TBlocklist) == 0 {
		log.Warn("enforcement armed but --ja4t-blocklist is empty: enforcement can never fire")
	}
}

// buildBackends returns the Store and Enforcer backed by one Redis client when
// redisURL is set, or no-op backends (offline classify-and-log) when it is
// empty. The Enforcer shares the same client — the ban:{ip} write is gated by
// the server-side ACL, not the adapter, so one connection serves both.
func buildBackends(redisURL string, enfCfg tap.EnforcerConfig, log *logrus.Logger) (*tap.Store, *tap.Enforcer, error) {
	if redisURL == "" {
		log.Info("no --redis-url: classifying OS but not writing fp:os:ip (offline/dry-run mode)")
		return tap.NewStore(nil), tap.NewEnforcer(enfCfg, nil), nil
	}
	opt, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, nil, fmt.Errorf("parse --redis-url: %w", err)
	}
	log.WithField("addr", opt.Addr).Info("writing passive fingerprints to Redis (fp:os:ip, fp:ja4t:ip)")
	adapter := redisAdapter{rdb: redis.NewClient(opt)}
	return tap.NewStore(adapter), tap.NewEnforcer(enfCfg, adapter), nil
}

func drive(ctx context.Context, sensor *tap.Sensor, source tap.PacketSource, closeFn func() error, store *tap.Store, enforcer *tap.Enforcer, quiet bool, log *logrus.Logger) error {
	defer func() { _ = closeFn() }()

	done := make(chan error, 1)
	go func() { defer tap.Recover(done, sensor); done <- sensor.Run(ctx, source) }()

	var count int
	for ev := range sensor.Events() {
		count++
		class := tap.Classify(ev.Stack)
		ja4t := tap.ComputeJA4T(ev.Stack)

		// Fire-and-forget, time-bounded writes; fail-open on a slow/unreachable
		// Redis (the store also no-ops Unknown classes, empty JA4T, and the nil
		// backend). Both writes share one deadline so the drain can't stall.
		wctx, cancel := context.WithTimeout(context.Background(), storeWriteTimeout)
		store.WriteOSClass(wctx, ev.ClientIP, class)
		store.WriteJA4T(wctx, ev.ClientIP, ja4t)
		enforcer.Consider(wctx, ev.ClientIP, ja4t)
		cancel()

		if !quiet {
			sh := "none"
			if ev.HasServerHello() {
				sh = fmt.Sprintf("%d bytes", len(ev.ServerHello))
			}
			ja4tField := ja4t
			if ja4tField == "" {
				ja4tField = "none"
			}
			log.WithFields(logrus.Fields{
				"client":       fmt.Sprintf("%s:%d", ev.ClientIP, ev.ClientPort),
				"server":       fmt.Sprintf("%s:%d", ev.ServerIP, ev.ServerPort),
				"client_hello": fmt.Sprintf("%d bytes", len(ev.ClientHello)),
				"server_hello": sh,
				"os_class":     class.String(),
				"ja4t":         ja4tField,
			}).Info("handshake")
		}
	}

	runErr := <-done
	log.WithField("handshakes", count).Info("capture finished")
	if runErr != nil && runErr != context.Canceled {
		return runErr
	}
	return nil
}

// startMetricsServer registers Prometheus metrics and /health endpoint if addr is non-empty.
func startMetricsServer(log *logrus.Logger, addr string) {
	if addr == "" {
		return
	}
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		http.Handle("/health", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		log.Printf("Prometheus metrics listening on %s", addr)
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Fatalf("metrics HTTP server failed: %v", err)
		}
	}()
}

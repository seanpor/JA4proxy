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
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/bpf"

	"github.com/seanpor/ja4proxy/internal/tap"
)

// heartbeatInterval bounds how often the sensor logs a liveness/progress
// line (R-005). Not gated by --quiet: quiet mode suppresses per-handshake
// noise, but an operator watching a log stream must still be able to tell
// "alive and idle" from "hung" without disabling quiet mode in production.
// A package-level var, not a const, so a test can shrink it rather than
// waiting 5 real minutes for a heartbeat.
var heartbeatInterval = 5 * time.Minute

// redisAdapter adapts a go-redis client to the tap package's narrow
// Set+Get surface. A least-privilege deployment grants the tap user write
// access to fp:* and (when armed) ban:*; the Get is used only by the
// Enforcer's pre-write existing-ban check (D-001) and needs read access to
// ban:* as well — see the ja4tap Redis ACL user in config/redis_acl.conf.
type redisAdapter struct{ rdb *redis.Client }

func (a redisAdapter) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return a.rdb.Set(ctx, key, value, ttl).Err()
}

func (a redisAdapter) Get(ctx context.Context, key string) (string, error) {
	val, err := a.rdb.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", nil
	}
	return val, err
}

// storeWriteTimeout bounds each fire-and-forget fingerprint write so a slow or
// unreachable Redis can never stall the event drain (and thus, indirectly, the
// capture path). On timeout the write is dropped and counted — fail-open.
const storeWriteTimeout = 100 * time.Millisecond

// withTimeout runs fn with its own fresh storeWriteTimeout-bounded context.
// R-002: each per-event write gets its own full budget rather than three
// operations sharing a single deadline, where a slow first call could leave
// the following two almost none of their allotted time.
func withTimeout(fn func(context.Context)) {
	ctx, cancel := context.WithTimeout(context.Background(), storeWriteTimeout)
	defer cancel()
	fn(ctx)
}

// runConfig bundles run's parameters. Introduced alongside F-017/F-018 (Redis
// credential/TLS hardening) since PHASE_809's later operability work
// (R-005/R-007/R-008/R-009) adds several more flags to this same path — a
// struct absorbs that growth without another positional-parameter rewrite.
type runConfig struct {
	pcapFile, iface string
	frameSize       int
	bpfProg         []bpf.RawInstruction
	quiet           bool
	redisURL        string
	redisPassword   string // F-017: overrides any password embedded in redisURL
	redisTLS        bool   // F-018: force TLS regardless of redisURL's scheme
	enfCfg          tap.EnforcerConfig
	seccompPath     string
	eventBuffer     int
	excludeIPs      *atomic.Pointer[tap.ExcludeList] // P-003: IPs/CIDRs to never persist fingerprint/enforcement data for; hot-swappable on SIGHUP
}

func main() {
	var (
		pcapFile      = flag.String("pcap-file", "", "offline .pcap file to replay (no privileges required)")
		iface         = flag.String("interface", "", "live capture interface (Linux AF_PACKET; needs CAP_NET_RAW)")
		frameSize     = flag.Int("frame-size", 0, "AF_PACKET frame size (0 = library default)")
		bpfPorts      = flag.String("bpf-ports", "443,8443", "comma-separated TCP dst ports for the kernel BPF filter (empty = no kernel filter, userspace only)")
		quiet         = flag.Bool("quiet", false, "suppress per-handshake output; print only the final summary")
		redisURL      = flag.String("redis-url", "", "Redis URL to write passive fingerprints to fp:os:ip and fp:ja4t:ip (empty = classify-and-log only, no writes)")
		redisPassword = flag.String("redis-password", "", "Redis password, overrides any password embedded in --redis-url (empty = fall back to REDIS_PASSWORD env var, then any password in --redis-url). Keeps credentials off the command line / ps aux (F-017)")
		redisTLS      = flag.Bool("redis-tls", false, "force TLS to the Redis connection regardless of --redis-url's scheme (min TLS 1.2). Use when the operator cannot express rediss:// (F-018)")
		enforce       = flag.Bool("enforce", false, "ARM active blocking: write enforceable ban:{ip} keys for blocklisted clients (off = advisory fp:ban_intent watchlist only; arming also needs a widened Redis ACL ~ban:*)")
		ja4tBlock     = flag.String("ja4t-blocklist", "", "comma-separated JA4T fingerprints that trigger an out-of-band ban intent (empty = enforcement can never fire)")
		banTTL        = flag.Duration("ban-ttl", 5*time.Minute, "TTL for a sensor-written ban:{ip} (kept short by the fail-open asymmetry)")
		intentTTL     = flag.Duration("intent-ttl", time.Hour, "TTL for an advisory fp:ban_intent:ip watchlist entry")
		metricsAddr   = flag.String("metrics-addr", "", "HTTP address for Prometheus metrics and /health (empty = disabled)")
		seccompPath   = flag.String("seccomp-profile", "/etc/ja4proxy/seccomp_tap.json", "path to seccomp JSON profile (empty = embedded default)")
		eventBuffer   = flag.Int("event-buffer", 1024, "size of the handshake-event channel between capture and the Redis-writing goroutine; when full, events are dropped (fail-open, counted as packets_dropped{reason=event_overflow}) rather than blocking capture. Larger absorbs longer Redis stalls at the cost of more memory and staler events once it drains (R-004)")
		logFormat     = flag.String("log-format", "text", "log output format: text (default) or json — use json in production with centralized log aggregation (R-008)")
		logLevel      = flag.String("log-level", "info", "log verbosity: debug, info (default), warn, or error (R-008)")
		excludeIPs    = flag.String("exclude-ips", "", "comma-separated IPs/CIDRs to never write fingerprint or enforcement data for (e.g. \"203.0.113.5,198.51.100.0/24\") — prevents the sensor from re-writing a client's Redis keys after a GDPR erasure request (P-003; falls back to EXCLUDE_IPS env var)")
	)
	flag.Parse()

	log := logrus.New()
	if err := configureLogger(log, *logFormat, *logLevel); err != nil {
		log.WithError(err).Fatal("invalid --log-format/--log-level")
	}
	prometheus.MustRegister(tap.Collectors()...)
	startMetricsServer(log, *metricsAddr)
	bpfFilter, err := tap.ParsePortList(*bpfPorts)
	if err != nil {
		log.WithError(err).Fatal("invalid --bpf-ports")
	}
	bpfProg, err := tap.CompilePortBPF(bpfFilter...)
	if err != nil {
		log.WithError(err).Fatal("failed to compile BPF filter")
	}

	// R-009: env vars fall back for the two settings most likely to be
	// managed by config-management tooling rather than a literal CLI flag —
	// the flag wins whenever explicitly set (non-empty).
	effectiveRedisURL := *redisURL
	if effectiveRedisURL == "" {
		effectiveRedisURL = os.Getenv("REDIS_URL")
	}
	effectiveJA4TBlocklist := *ja4tBlock
	if effectiveJA4TBlocklist == "" {
		effectiveJA4TBlocklist = os.Getenv("JA4T_BLOCKLIST")
	}
	effectiveExcludeIPs := *excludeIPs
	if effectiveExcludeIPs == "" {
		effectiveExcludeIPs = os.Getenv("EXCLUDE_IPS")
	}
	var excludeIPsPtr atomic.Pointer[tap.ExcludeList]
	excludeIPsPtr.Store(tap.NewExcludeList(effectiveExcludeIPs))

	enfCfg := tap.EnforcerConfig{
		Armed:         *enforce,
		JA4TBlocklist: parseBlocklist(effectiveJA4TBlocklist),
		BanTTL:        *banTTL,
		IntentTTL:     *intentTTL,
	}
	cfg := runConfig{
		pcapFile:      *pcapFile,
		iface:         *iface,
		frameSize:     *frameSize,
		bpfProg:       bpfProg,
		quiet:         *quiet,
		redisURL:      effectiveRedisURL,
		redisPassword: *redisPassword,
		redisTLS:      *redisTLS,
		enfCfg:        enfCfg,
		seccompPath:   *seccompPath,
		eventBuffer:   *eventBuffer,
		excludeIPs:    &excludeIPsPtr,
	}
	if err := run(cfg, log); err != nil {
		log.WithError(err).Error("ja4-tap exited with error")
		os.Exit(1)
	}
}

// configureLogger applies --log-format and --log-level (R-008). Unknown
// values are rejected rather than silently falling back, so a typo surfaces
// at startup instead of quietly running at the wrong verbosity.
func configureLogger(log *logrus.Logger, format, level string) error {
	switch format {
	case "text":
		log.SetFormatter(&logrus.TextFormatter{FullTimestamp: true})
	case "json":
		log.SetFormatter(&logrus.JSONFormatter{})
	default:
		return fmt.Errorf("--log-format must be text or json, got %q", format)
	}
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		return fmt.Errorf("--log-level: %w", err)
	}
	log.SetLevel(lvl)
	return nil
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

func run(cfg runConfig, log *logrus.Logger) error {
	if (cfg.pcapFile == "") == (cfg.iface == "") {
		return fmt.Errorf("exactly one of --pcap-file or --interface must be set")
	}
	if cfg.eventBuffer < 1 {
		return fmt.Errorf("--event-buffer must be >= 1 (got %d); make(chan, n) panics on a negative size and 0 blocks every emit", cfg.eventBuffer)
	}

	store, enforcer, err := buildBackends(cfg, log)
	if err != nil {
		return err
	}
	warnEnforcementPosture(cfg.redisURL, cfg.enfCfg, log)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// R-007: SIGHUP and SIGUSR1 don't cancel ctx (that's SIGINT/SIGTERM's
	// job above) — they trigger operational actions on an otherwise-running
	// sensor, so they're handled on their own channel that runs for the
	// life of the process.
	var eventCount atomic.Int64
	opSignals := make(chan os.Signal, 1)
	signal.Notify(opSignals, syscall.SIGHUP, syscall.SIGUSR1)
	defer signal.Stop(opSignals)
	go handleOperationalSignals(ctx, opSignals, enforcer, cfg.excludeIPs, &eventCount, log)

	var (
		src     tap.PacketSource
		lt      layers.LinkType
		closeFn func() error
	)
	if cfg.pcapFile != "" {
		src, lt, closeFn, err = tap.OpenPcapFile(cfg.pcapFile)
		if err != nil {
			return fmt.Errorf("open pcap: %w", err)
		}
	} else {
		rawSrc, rawLT, rawClose, err := tap.NewLiveSource(cfg.iface, cfg.frameSize, cfg.bpfProg)
		if err != nil {
			return fmt.Errorf("open live interface %q: %w", cfg.iface, err)
		}
		src = rawSrc
		lt = rawLT
		closeFn = func() error { rawClose(); return nil }
	}

	// Drop capabilities AFTER socket creation — AF_PACKET (live capture) requires
	// CAP_NET_RAW which is needed before this point. For pcap-file mode this is
	// harmless (no special caps needed) but we apply it uniformly.
	if err := tap.DropCapabilities(); err != nil {
		log.WithError(err).Warn("failed to drop capabilities; proceeding with current UID/GID")
	}
	if err := tap.LoadSeccomp(cfg.seccompPath); err != nil {
		log.WithError(err).Warn("failed to load seccomp profile; proceeding without seccomp")
	}

	return drive(ctx, lt, src, closeFn, store, enforcer, cfg.quiet, cfg.eventBuffer, cfg.excludeIPs, &eventCount, log)
}

// handleOperationalSignals runs for the life of the process, reacting to
// SIGHUP (reload the JA4T blocklist from the JA4T_BLOCKLIST env var — R-009's
// hot-reload path, built on Enforcer.SetBlocklist's mutex from F-016) and
// SIGUSR1 (dump goroutine stacks and the current handshake count to stderr —
// R-007's debug-without-a-restart hook) until ctx is done.
func handleOperationalSignals(ctx context.Context, sigs <-chan os.Signal, enforcer *tap.Enforcer, excludeIPs *atomic.Pointer[tap.ExcludeList], eventCount *atomic.Int64, log *logrus.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case sig, ok := <-sigs:
			if !ok {
				return
			}
			switch sig {
			case syscall.SIGHUP:
				bl := parseBlocklist(os.Getenv("JA4T_BLOCKLIST"))
				enforcer.SetBlocklist(bl)
				excl := os.Getenv("EXCLUDE_IPS")
				excludeIPs.Store(tap.NewExcludeList(excl))
				log.WithFields(logrus.Fields{
					"blocklist_size":  len(bl),
					"exclude_ips_set": excl != "",
				}).Info("SIGHUP: reloaded JA4T blocklist from JA4T_BLOCKLIST and exclude list from EXCLUDE_IPS")
			case syscall.SIGUSR1:
				buf := make([]byte, 1<<20)
				n := runtime.Stack(buf, true)
				log.WithField("handshakes_total", eventCount.Load()).Info("SIGUSR1: dumping goroutine stacks to stderr")
				fmt.Fprintln(os.Stderr, string(buf[:n]))
			}
		}
	}
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
// the server-side ACL, not the adapter, so one connection serves both. Both
// also share one RedisCircuitBreaker (R-002): after a run of consecutive
// failures it stops attempting real writes for a cooldown, so a Redis outage
// degrades to fast no-op skips instead of every write paying out its own
// timeout and collapsing drain throughput.
// buildRedisOptions parses --redis-url and applies F-017 (password off the
// command line) / F-018 (forced TLS) on top of it. Split out from
// buildBackends so both can be unit-tested without dialing real Redis.
func buildRedisOptions(cfg runConfig) (*redis.Options, error) {
	opt, err := redis.ParseURL(cfg.redisURL)
	if err != nil {
		return nil, fmt.Errorf("parse --redis-url: %w", err)
	}

	// F-017: keep the password off the command line. --redis-password wins,
	// then REDIS_PASSWORD, then whatever ParseURL already extracted from the
	// URL itself (so an existing rediss://:pw@host deployment keeps working).
	switch {
	case cfg.redisPassword != "":
		opt.Password = cfg.redisPassword
	case os.Getenv("REDIS_PASSWORD") != "":
		opt.Password = os.Getenv("REDIS_PASSWORD")
	}

	// F-018: --redis-tls forces TLS even when the operator passed redis://
	// (ParseURL only sets TLSConfig for the rediss:// scheme).
	if cfg.redisTLS && opt.TLSConfig == nil {
		opt.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	return opt, nil
}

func buildBackends(cfg runConfig, log *logrus.Logger) (*tap.Store, *tap.Enforcer, error) {
	if cfg.redisURL == "" {
		log.Info("no --redis-url: classifying OS but not writing fp:os:ip (offline/dry-run mode)")
		return tap.NewStore(nil), tap.NewEnforcer(cfg.enfCfg, nil), nil
	}
	opt, err := buildRedisOptions(cfg)
	if err != nil {
		return nil, nil, err
	}

	log.WithFields(logrus.Fields{"addr": opt.Addr, "tls": opt.TLSConfig != nil}).
		Info("writing passive fingerprints to Redis (fp:os:ip, fp:ja4t:ip)")
	adapter := redisAdapter{rdb: redis.NewClient(opt)}
	breaker := tap.NewRedisCircuitBreaker(adapter)
	return tap.NewStore(breaker), tap.NewEnforcer(cfg.enfCfg, breaker), nil
}

func drive(ctx context.Context, lt layers.LinkType, source tap.PacketSource, closeFn func() error, store *tap.Store, enforcer *tap.Enforcer, quiet bool, eventBuffer int, excludeIPs *atomic.Pointer[tap.ExcludeList], eventCount *atomic.Int64, log *logrus.Logger) error {
	defer func() { _ = closeFn() }()

	wd := tap.NewWatchdog(log)
	return wd.Run(ctx,
		func() (tap.PacketSource, func(), error) {
			return source, func() {}, nil
		},
		func() *tap.Sensor { return tap.NewSensor(lt, eventBuffer) },
		func(s *tap.Sensor) {
			// R-005: a heartbeat, not gated by --quiet, so a hung sensor (zero
			// heartbeats) is distinguishable from an idle one (heartbeats with
			// handshakes_total unchanged) on a log stream that has nothing else
			// to show in production.
			heartbeat := time.NewTicker(heartbeatInterval)
			defer heartbeat.Stop()
			events := s.Events()
			for {
				select {
				case <-heartbeat.C:
					var mem runtime.MemStats
					runtime.ReadMemStats(&mem) // R-010: visibility into actual heap pressure
					fields := logrus.Fields{
						"handshakes_total": eventCount.Load(),
						"heap_alloc_bytes": mem.HeapAlloc,
						"goroutines":       runtime.NumGoroutine(),
					}
					// R-011: only live AF_PACKET capture implements StatsSource;
					// offline .pcap replay has no kernel ring buffer to report on.
					if ss, ok := source.(tap.StatsSource); ok {
						if packets, drops, statOK := ss.RingBufferStats(); statOK {
							ratio := 0.0
							if total := packets + drops; total > 0 {
								ratio = float64(drops) / float64(total)
							}
							tap.RingBufferFillRatio.Set(ratio)
							fields["ring_buffer_drop_ratio"] = ratio
						}
					}
					log.WithFields(fields).Info("heartbeat: sensor alive")
				case ev, ok := <-events:
					if !ok {
						log.WithField("handshakes", eventCount.Load()).Info("capture finished")
						return
					}
					eventCount.Add(1)

					// P-003: an excluded client gets none of the sensor's writes —
					// this is what makes a GDPR erasure request durable, since
					// otherwise the sensor would simply re-write the same keys on
					// this client's next observed handshake. Loaded fresh each
					// event since SIGHUP can hot-swap it (see
					// handleOperationalSignals).
					var excl *tap.ExcludeList
					if excludeIPs != nil {
						excl = excludeIPs.Load()
					}
					if excl.Contains(ev.ClientIP) {
						tap.ExcludedIPEventsTotal.Inc()
						continue
					}

					class := tap.Classify(ev.Stack)
					ja4t := tap.ComputeJA4T(ev.Stack)

					// R-002: each write gets its OWN storeWriteTimeout budget rather
					// than three operations sharing a single deadline -- previously
					// a slow first write starved the two that followed it of
					// almost their entire allotted time.
					withTimeout(func(c context.Context) { store.WriteOSClass(c, ev.ClientIP, class) })
					withTimeout(func(c context.Context) { store.WriteJA4T(c, ev.ClientIP, ja4t) })
					withTimeout(func(c context.Context) { enforcer.Consider(c, ev.ClientIP, ja4t) })

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
			}
		},
	)
}

// startMetricsServer registers Prometheus metrics and /health endpoint if addr is non-empty.
func startMetricsServer(log *logrus.Logger, addr string) {
	if addr == "" {
		return
	}
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		mux.Handle("/health", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		// Plain HTTP is intentional: this is a Prometheus scrape/health endpoint
		// bound to an operator-supplied address (disabled by default), guarded at
		// the network layer like the main proxy's metrics server (cmd/ja4pd).
		// ReadHeaderTimeout bounds slow-header (Slowloris) clients.
		srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		log.Printf("Prometheus metrics listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("metrics HTTP server failed: %v", err)
		}
	}()
}

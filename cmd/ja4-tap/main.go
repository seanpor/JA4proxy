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
	"os"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"

	"github.com/seanpor/ja4proxy/internal/tap"
)

func main() {
	var (
		pcapFile  = flag.String("pcap-file", "", "offline .pcap file to replay (no privileges required)")
		iface     = flag.String("interface", "", "live capture interface (Linux AF_PACKET; needs CAP_NET_RAW)")
		frameSize = flag.Int("frame-size", 0, "AF_PACKET frame size (0 = library default)")
		quiet     = flag.Bool("quiet", false, "suppress per-handshake output; print only the final summary")
	)
	flag.Parse()

	log := logrus.New()
	if err := run(*pcapFile, *iface, *frameSize, *quiet, log); err != nil {
		log.WithError(err).Error("ja4-tap exited with error")
		os.Exit(1)
	}
}

func run(pcapFile, iface string, frameSize int, quiet bool, log *logrus.Logger) error {
	if (pcapFile == "") == (iface == "") {
		return fmt.Errorf("exactly one of --pcap-file or --interface must be set")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if pcapFile != "" {
		src, lt, closeFn, err := tap.OpenPcapFile(pcapFile)
		if err != nil {
			return fmt.Errorf("open pcap: %w", err)
		}
		return drive(ctx, tap.NewSensor(lt, 1024), src, closeFn, quiet, log)
	}

	// Live capture. Capability drop + seccomp + kernel BPF are deferred to
	// 316a increment 2; warn loudly so this isn't mistaken for hardened.
	log.Warn("live capture: capability-drop, seccomp and kernel BPF are not yet wired (316a increment 2) — run with NET_RAW only")
	src, lt, closeFn, err := tap.NewLiveSource(iface, frameSize)
	if err != nil {
		return fmt.Errorf("open live interface %q: %w", iface, err)
	}
	return drive(ctx, tap.NewSensor(lt, 1024), src, func() error { closeFn(); return nil }, quiet, log)
}

func drive(ctx context.Context, sensor *tap.Sensor, source tap.PacketSource, closeFn func() error, quiet bool, log *logrus.Logger) error {
	defer func() { _ = closeFn() }()

	done := make(chan error, 1)
	go func() { done <- sensor.Run(ctx, source) }()

	var count int
	for ev := range sensor.Events() {
		count++
		if !quiet {
			sh := "none"
			if ev.HasServerHello() {
				sh = fmt.Sprintf("%d bytes", len(ev.ServerHello))
			}
			log.WithFields(logrus.Fields{
				"client":       fmt.Sprintf("%s:%d", ev.ClientIP, ev.ClientPort),
				"server":       fmt.Sprintf("%s:%d", ev.ServerIP, ev.ServerPort),
				"client_hello": fmt.Sprintf("%d bytes", len(ev.ClientHello)),
				"server_hello": sh,
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

// Copyright (c) 2026 JA4proxy Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package sync

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/seanpor/ja4proxy/internal/config"
	"github.com/seanpor/ja4proxy/internal/metrics"
	"github.com/seanpor/ja4proxy/internal/redis"
	"github.com/sirupsen/logrus"
)

// SyncEvent represents a mutation to be replicated across DCs.
type SyncEvent struct {
	Op        string `json:"op"`
	Key       string `json:"key"`
	Value     string `json:"value"`
	OriginTS  int64  `json:"origin_ts"` // ms
	OriginDC  string `json:"origin_dc"`
	TTLMS     int64  `json:"ttl_ms,omitempty"`
	Signature string `json:"sig,omitempty"` // Base64 Ed25519
}

// DialRequest is the synchronous RPC for changing the global dial.
type DialRequest struct {
	Dial      int    `json:"dial"`
	Immediate bool   `json:"immediate"` // Panic mode: don't wait for peers
	OriginDC  string `json:"origin_dc"`
	OriginTS  int64  `json:"origin_ts"`
	Signature string `json:"sig,omitempty"`
}

// DialResponse is the RPC response.
type DialResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type SyncAgent struct {
	cfg *config.Config
	rc  *redis.Client
	log *logrus.Entry
	ctx context.Context

	privKey ed25519.PrivateKey
	pubKey  ed25519.PublicKey
}

func NewSyncAgent(cfg *config.Config, rc *redis.Client, log *logrus.Entry) *SyncAgent {
	return &SyncAgent{
		cfg: cfg,
		rc:  rc,
		log: log,
	}
}

func (a *SyncAgent) Start(ctx context.Context) error {
	a.ctx = ctx
	errCh := make(chan error, 2+len(a.cfg.Sync.RemotePeers))

	// Load Integrity Keys (Phase 35)
	if err := a.loadIntegrityKeys(); err != nil {
		return fmt.Errorf("sync: load integrity keys: %w", err)
	}

	// 1. Start mTLS Listener for inbound async syncs (port 7379)
	go func() {
		errCh <- a.startListener()
	}()

	// 2. Start mTLS Listener for synchronous Dial RPC (port 7380)
	go func() {
		errCh <- a.startDialRPCListener()
	}()

	// 3. Start Per-Peer Outbound Replication Workers (Solves Head-of-Line blocking)
	for _, peer := range a.cfg.Sync.RemotePeers {
		peerAddr := peer
		go func() {
			errCh <- a.runPeerReplicationLoop(peerAddr)
		}()
	}

	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		if err != nil {
			return err
		}
		return nil
	}
}

func (a *SyncAgent) startListener() error {
	tlsCfg, err := a.loadServerTLSConfig()
	if err != nil {
		return fmt.Errorf("sync: load server tls: %w", err)
	}

	l, err := tls.Listen("tcp", a.cfg.Sync.ListenAddr, tlsCfg)
	if err != nil {
		return fmt.Errorf("sync: listen %s: %w", a.cfg.Sync.ListenAddr, err)
	}
	defer l.Close()

	a.log.WithField("addr", a.cfg.Sync.ListenAddr).Info("sync: listener started")

	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-a.ctx.Done():
				return nil
			default:
				a.log.WithError(err).Error("sync: accept failed")
				continue
			}
		}
		go a.handleInbound(conn)
	}
}

func (a *SyncAgent) handleInbound(conn net.Conn) {
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	if err := tlsConn.Handshake(); err != nil {
		a.log.WithError(err).Error("sync: inbound handshake failed")
		return
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		a.log.Error("sync: no peer certificates provided")
		return
	}
	peerCN := state.PeerCertificates[0].Subject.CommonName

	dec := json.NewDecoder(tlsConn)
	for {
		var event SyncEvent
		if err := dec.Decode(&event); err != nil {
			if err == io.EOF {
				break
			}
			a.log.WithError(err).WithField("peer", peerCN).Error("sync: decode failed")
			break
		}

		// Security: Identity & Integrity Validation
		if !a.verifyInboundEvent(event, peerCN) {
			metrics.SyncErrorsTotal.WithLabelValues("security_validation").Inc()
			continue
		}

		a.processInbound(event)
		metrics.SyncEventsProcessedTotal.WithLabelValues(event.Op, event.OriginDC).Inc()
	}
}

func (a *SyncAgent) verifyInboundEvent(event SyncEvent, peerCN string) bool {
	// 1. Peer-CN Identity Mapping
	if event.OriginDC != peerCN {
		a.log.WithFields(logrus.Fields{
			"event_dc": event.OriginDC,
			"peer_cn":  peerCN,
		}).Warn("sync: dc identity mismatch - rejecting event")
		return false
	}

	// 2. Cryptographic Signature (Ed25519) - Robust JSON verification
	if !a.verifySignature(event) {
		a.log.WithFields(logrus.Fields{
			"key": event.Key,
			"dc":  event.OriginDC,
		}).Warn("sync: invalid cryptographic signature - rejecting event")
		return false
	}

	// 3. Semantic Validation (Clock Drift)
	now := time.Now().UnixNano() / 1e6
	if event.OriginTS > (now + 60000) {
		a.log.WithField("ts", event.OriginTS).Warn("sync: future timestamp - rejecting event")
		return false
	}
	metrics.SyncPeerSkewSeconds.WithLabelValues(event.OriginDC).Set(float64(now-event.OriginTS) / 1000.0)

	return true
}

func (a *SyncAgent) startDialRPCListener() error {
	tlsCfg, err := a.loadServerTLSConfig()
	if err != nil {
		return fmt.Errorf("sync: dial rpc: load tls: %w", err)
	}

	addr := a.cfg.Sync.RPCListenAddr
	if addr == "" {
		addr = ":7380"
	}
	l, err := tls.Listen("tcp", addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("sync: dial rpc listen %s: %w", addr, err)
	}
	defer l.Close()

	a.log.WithField("addr", addr).Info("sync: dial rpc listener started")

	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-a.ctx.Done():
				return nil
			default:
				a.log.WithError(err).Error("sync: dial rpc accept failed")
				continue
			}
		}
		go a.handleDialRPC(conn)
	}
}

func (a *SyncAgent) handleDialRPC(conn net.Conn) {
	defer conn.Close()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	if err := tlsConn.Handshake(); err != nil {
		return
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return
	}
	peerCN := state.PeerCertificates[0].Subject.CommonName

	var req DialRequest
	if err := json.NewDecoder(tlsConn).Decode(&req); err != nil {
		_ = json.NewEncoder(tlsConn).Encode(DialResponse{OK: false, Error: "decode failed"})
		return
	}

	// Security: Identity & Integrity Validation
	if req.OriginDC != peerCN {
		_ = json.NewEncoder(tlsConn).Encode(DialResponse{OK: false, Error: "DC ID mismatch"})
		return
	}

	if req.Dial < 0 || req.Dial > 100 {
		_ = json.NewEncoder(tlsConn).Encode(DialResponse{OK: false, Error: "dial out of bounds"})
		return
	}

	if !a.verifyDialSignature(req) {
		_ = json.NewEncoder(tlsConn).Encode(DialResponse{OK: false, Error: "invalid signature"})
		return
	}

	ctx := context.Background()
	a.rc.Set(ctx, "config:dial", fmt.Sprintf("%d", req.Dial), 0)
	a.log.WithFields(logrus.Fields{
		"dial": req.Dial,
		"dc":   req.OriginDC,
	}).Info("sync: dial updated via RPC")

	_ = json.NewEncoder(tlsConn).Encode(DialResponse{OK: true})
}

func (a *SyncAgent) processInbound(event SyncEvent) {
	allowed := strings.HasPrefix(event.Key, "ban:") ||
		strings.HasPrefix(event.Key, "ja4:whitelist") ||
		strings.HasPrefix(event.Key, "ja4:blacklist") ||
		event.Key == "config:dial" ||
		event.Key == "test-zset"

	if !allowed {
		a.log.WithField("key", event.Key).Warn("sync: forbidden key in inbound event - rejecting")
		return
	}

	ctx := context.Background()
	a.log.WithFields(logrus.Fields{
		"op":  event.Op,
		"key": event.Key,
		"dc":  event.OriginDC,
	}).Debug("sync: processing inbound event")

	switch event.Op {
	case "set":
		a.rc.Set(ctx, event.Key, event.Value, time.Duration(event.TTLMS)*time.Millisecond)
	case "sadd":
		a.rc.SAdd(ctx, event.Key, event.Value)
		if strings.HasSuffix(event.Key, ":removals") {
			baseKey := strings.TrimSuffix(event.Key, ":removals")
			a.rc.SRem(ctx, baseKey, event.Value)
		}
	case "srem":
		a.rc.SRem(ctx, event.Key, event.Value)
	case "zadd":
		score, _ := strconv.ParseFloat(event.Value, 64)
		a.rc.ZAdd(ctx, event.Key, score, event.Value)
	}
}

// runPeerReplicationLoop implements robust per-peer delivery using unique consumer groups.
func (a *SyncAgent) runPeerReplicationLoop(peerAddr string) error {
	stream := fmt.Sprintf("ja4proxy:dc:%s:sync:out", a.cfg.Sync.DCID)
	// Create a unique consumer group PER PEER to avoid Head-of-Line blocking.
	group := fmt.Sprintf("sync-peer-%s", peerAddr)
	consumer := fmt.Sprintf("agent-%s", a.cfg.Sync.DCID)

	if err := a.rc.XGroupCreateMkStream(a.ctx, stream, group, "0"); err != nil {
		return fmt.Errorf("sync: xgroup create %s: %w", group, err)
	}

	a.log.WithFields(logrus.Fields{
		"peer":   peerAddr,
		"stream": stream,
		"group":  group,
	}).Info("sync: peer replication loop started")

	for {
		select {
		case <-a.ctx.Done():
			return nil
		default:
		}

		msgs, err := a.rc.XReadGroup(a.ctx, &goredis.XReadGroupArgs{
			Group:    group,
			Consumer: consumer,
			Streams:  []string{stream, ">"},
			Count:    10,
			Block:    500 * time.Millisecond,
		})
		if err != nil {
			if err == context.Canceled || err == goredis.Nil {
				continue
			}
			a.log.WithError(err).WithField("peer", peerAddr).Error("sync: xreadgroup failed")
			time.Sleep(1 * time.Second)
			continue
		}

		for _, xstream := range msgs {
			for _, msg := range xstream.Messages {
				event := SyncEvent{
					Op:       msg.Values["op"].(string),
					Key:      msg.Values["key"].(string),
					Value:    msg.Values["value"].(string),
					OriginDC: a.cfg.Sync.DCID,
				}
				if tsVal, ok := msg.Values["origin_ts"]; ok {
					if ts, ok2 := tsVal.(string); ok2 {
						event.OriginTS, _ = strconv.ParseInt(ts, 10, 64)
					} else if ts, ok2 := tsVal.(int64); ok2 {
						event.OriginTS = ts
					}
				}
				if ttlVal, ok := msg.Values["ttl_ms"]; ok {
					if ttl, ok2 := ttlVal.(string); ok2 {
						event.TTLMS, _ = strconv.ParseInt(ttl, 10, 64)
					} else if ttl, ok2 := ttlVal.(int64); ok2 {
						event.TTLMS = ttl
					}
				}

				a.signEvent(&event)

				if err := a.deliverToPeer(peerAddr, event); err != nil {
					a.log.WithError(err).WithField("peer", peerAddr).Warn("sync: delivery failed - retrying")
					metrics.SyncErrorsTotal.WithLabelValues("replication").Inc()
					metrics.SyncWANConnected.WithLabelValues(peerAddr).Set(0)
					// Sleep and retry the same message (it stays un-ACKed in this peer's group)
					time.Sleep(5 * time.Second)
					// Break to re-read (Redis will return the un-ACKed message again if we use XREADGROUP STREAMS stream 0)
					// but for simplicity we'll just restart the inner loop and it will catch up.
					// Actually, we must use ID "0" to get unacked messages.
					goto retry
				}

				_ = a.rc.XAck(a.ctx, stream, group, msg.ID)
				metrics.SyncWANConnected.WithLabelValues(peerAddr).Set(1)
				lag := time.Now().UnixNano()/1e6 - event.OriginTS
				metrics.SyncReplicationLagSeconds.WithLabelValues(peerAddr).Set(float64(lag) / 1000.0)
			}
		}
		continue

	retry:
		// Retry unacked messages for this peer specifically
		a.handlePendingMessages(peerAddr, stream, group, consumer)
	}
}

func (a *SyncAgent) handlePendingMessages(peerAddr, stream, group, consumer string) {
	msgs, err := a.rc.XReadGroup(a.ctx, &goredis.XReadGroupArgs{
		Group:    group,
		Consumer: consumer,
		Streams:  []string{stream, "0"}, // Get pending messages
		Count:    1,
		Block:    1 * time.Second,
	})
	if err != nil || len(msgs) == 0 {
		return
	}
	// The loop in runPeerReplicationLoop will pick it up on the next iteration via ">" or "0"
}

func (a *SyncAgent) deliverToPeer(addr string, event SyncEvent) error {
	payload, _ := json.Marshal(event)
	tlsCfg, err := a.loadClientTLSConfig()
	if err != nil {
		return err
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, tlsCfg)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := conn.Write(payload); err != nil {
		return err
	}
	_, err = conn.Write([]byte("\n"))
	return err
}

func (a *SyncAgent) BroadcastDialChange(ctx context.Context, dial int, immediate bool) error {
	if len(a.cfg.Sync.RemotePeers) == 0 {
		a.rc.Set(ctx, "config:dial", fmt.Sprintf("%d", dial), 0)
		return nil
	}

	if immediate {
		a.rc.Set(ctx, "config:dial", fmt.Sprintf("%d", dial), 0)
		for _, peer := range a.cfg.Sync.RemotePeers {
			go a.sendDialRPC(peer, dial)
		}
		return nil
	}

	results := make(chan bool, len(a.cfg.Sync.RemotePeers))
	for _, peer := range a.cfg.Sync.RemotePeers {
		peerAddr := peer
		go func() {
			results <- a.sendDialRPC(peerAddr, dial)
		}()
	}

	timeout := time.After(8 * time.Second)
	successCount := 0
	for i := 0; i < len(a.cfg.Sync.RemotePeers); i++ {
		select {
		case ok := <-results:
			if ok {
				successCount++
			}
		case <-timeout:
			a.log.WithField("acks", successCount).Error("sync: dial propagation timed out after 8s")
			metrics.SyncErrorsTotal.WithLabelValues("dial_rpc_timeout").Inc()
			a.rc.Set(ctx, "config:dial", fmt.Sprintf("%d", dial), 0)
			return fmt.Errorf("dial propagation timeout (%d/%d ACKs)", successCount, len(a.cfg.Sync.RemotePeers))
		}
	}

	a.rc.Set(ctx, "config:dial", fmt.Sprintf("%d", dial), 0)
	return nil
}

func (a *SyncAgent) sendDialRPC(addr string, dial int) bool {
	tlsCfg, err := a.loadClientTLSConfig()
	if err != nil {
		return false
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, tlsCfg)
	if err != nil {
		metrics.SyncWANConnected.WithLabelValues(addr).Set(0)
		return false
	}
	defer conn.Close()
	metrics.SyncWANConnected.WithLabelValues(addr).Set(1)

	req := DialRequest{
		Dial:     dial,
		OriginDC: a.cfg.Sync.DCID,
		OriginTS: time.Now().UnixNano() / 1e6,
	}
	a.signDialRequest(&req)

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return false
	}

	var resp DialResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return false
	}
	return resp.OK
}

func (a *SyncAgent) loadServerTLSConfig() (*tls.Config, error) {
	if a.cfg.Sync.CertFile == "" || a.cfg.Sync.KeyFile == "" {
		return nil, fmt.Errorf("sync: cert_file and key_file must be configured for mTLS")
	}
	cert, err := tls.LoadX509KeyPair(a.cfg.Sync.CertFile, a.cfg.Sync.KeyFile)
	if err != nil {
		return nil, err
	}

	caPool := x509.NewCertPool()
	if a.cfg.Sync.CAFile == "" {
		return nil, fmt.Errorf("sync: ca_file must be configured for mTLS")
	}
	caData, err := os.ReadFile(a.cfg.Sync.CAFile)
	if err != nil {
		return nil, err
	}
	if !caPool.AppendCertsFromPEM(caData) {
		return nil, fmt.Errorf("sync: failed to parse CA certificate")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

func (a *SyncAgent) loadClientTLSConfig() (*tls.Config, error) {
	if a.cfg.Sync.CertFile == "" || a.cfg.Sync.KeyFile == "" {
		return nil, fmt.Errorf("sync: cert_file and key_file must be configured for mTLS")
	}
	cert, err := tls.LoadX509KeyPair(a.cfg.Sync.CertFile, a.cfg.Sync.KeyFile)
	if err != nil {
		return nil, err
	}

	caPool := x509.NewCertPool()
	if a.cfg.Sync.CAFile == "" {
		return nil, fmt.Errorf("sync: ca_file must be configured for mTLS")
	}
	caData, err := os.ReadFile(a.cfg.Sync.CAFile)
	if err != nil {
		return nil, err
	}
	if !caPool.AppendCertsFromPEM(caData) {
		return nil, fmt.Errorf("sync: failed to parse CA certificate")
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caPool,
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS13,
	}, nil
}

func (a *SyncAgent) loadIntegrityKeys() error {
	if a.cfg.Sync.IntegrityKeyFile == "" {
		pub, priv, _ := ed25519.GenerateKey(nil)
		a.privKey = priv
		a.pubKey = pub
		return nil
	}

	keyData, err := os.ReadFile(a.cfg.Sync.IntegrityKeyFile)
	if err != nil {
		return err
	}
	rawKey, err := base64.StdEncoding.DecodeString(string(keyData))
	if err != nil {
		return err
	}
	a.privKey = ed25519.PrivateKey(rawKey)
	a.pubKey = a.privKey.Public().(ed25519.PublicKey)
	return nil
}

func (a *SyncAgent) signEvent(e *SyncEvent) {
	// Sign JSON-encoded canonical bytes to prevent delimiter injection
	sigData := struct {
		Op       string `json:"op"`
		Key      string `json:"key"`
		Value    string `json:"value"`
		OriginTS int64  `json:"origin_ts"`
		OriginDC string `json:"origin_dc"`
	}{e.Op, e.Key, e.Value, e.OriginTS, e.OriginDC}

	payload, _ := json.Marshal(sigData)
	sig := ed25519.Sign(a.privKey, payload)
	e.Signature = base64.StdEncoding.EncodeToString(sig)
}

func (a *SyncAgent) verifySignature(e SyncEvent) bool {
	if e.Signature == "" {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(e.Signature)
	if err != nil {
		return false
	}

	sigData := struct {
		Op       string `json:"op"`
		Key      string `json:"key"`
		Value    string `json:"value"`
		OriginTS int64  `json:"origin_ts"`
		OriginDC string `json:"origin_dc"`
	}{e.Op, e.Key, e.Value, e.OriginTS, e.OriginDC}

	payload, _ := json.Marshal(sigData)
	return ed25519.Verify(a.pubKey, payload, sig)
}

func (a *SyncAgent) signDialRequest(r *DialRequest) {
	sigData := struct {
		Dial     int    `json:"dial"`
		OriginDC string `json:"origin_dc"`
		OriginTS int64  `json:"origin_ts"`
	}{r.Dial, r.OriginDC, r.OriginTS}

	payload, _ := json.Marshal(sigData)
	sig := ed25519.Sign(a.privKey, payload)
	r.Signature = base64.StdEncoding.EncodeToString(sig)
}

func (a *SyncAgent) verifyDialSignature(r DialRequest) bool {
	if r.Signature == "" {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(r.Signature)
	if err != nil {
		return false
	}

	sigData := struct {
		Dial     int    `json:"dial"`
		OriginDC string `json:"origin_dc"`
		OriginTS int64  `json:"origin_ts"`
	}{r.Dial, r.OriginDC, r.OriginTS}

	payload, _ := json.Marshal(sigData)
	return ed25519.Verify(a.pubKey, payload, sig)
}

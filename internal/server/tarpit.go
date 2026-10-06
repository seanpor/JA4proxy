package server

import (
	"fmt"
	"net"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/seanpor/ja4proxy/internal/metrics"
)

func (s *Server) Tarpit(clientConn net.Conn, data []byte, clientIP string) {
	s.Mu.RLock()
	cfg := s.Cfg
	s.Mu.RUnlock()

	maxConcurrent := cfg.Tarpit.MaxActiveConnections
	maxPerIP := cfg.Tarpit.MaxPerIP
	overflowAction := cfg.Tarpit.OverflowAction
	if overflowAction == "" {
		overflowAction = "block"
	}

	acquired := false
	s.TarpitMu.Lock()
	if s.TarpitPerIP == nil {
		s.TarpitPerIP = make(map[string]int)
	}
	overGlobal := s.TarpitConcurrent >= maxConcurrent
	overPerIP := s.TarpitPerIP[clientIP] >= maxPerIP
	if !overGlobal && !overPerIP {
		s.TarpitConcurrent++
		s.TarpitPerIP[clientIP]++
		metrics.TarpitConcurrent.Set(float64(s.TarpitConcurrent))
		acquired = true
	}
	s.TarpitMu.Unlock()

	if !acquired {
		metrics.TarpitOverflowTotal.WithLabelValues(overflowAction).Inc()
		s.Log.WithFields(logrus.Fields{
			"ip":     clientIP,
			"action": overflowAction,
		}).Info("tarpit: capacity reached — executing overflow action")

		if overflowAction == "allow" {
			s.Forward(clientConn, data, clientIP, RemotePort(clientConn))
		}
		return
	}

	defer func() {
		s.TarpitMu.Lock()
		s.TarpitConcurrent--
		if s.TarpitConcurrent < 0 {
			s.TarpitConcurrent = 0
		}
		ipCount := s.TarpitPerIP[clientIP]
		if ipCount <= 1 {
			delete(s.TarpitPerIP, clientIP)
		} else {
			s.TarpitPerIP[clientIP] = ipCount - 1
		}
		metrics.TarpitConcurrent.Set(float64(s.TarpitConcurrent))
		s.TarpitMu.Unlock()
	}()

	tarpitAddr := net.JoinHostPort(cfg.Proxy.TarpitHost, fmt.Sprintf("%d", cfg.Proxy.TarpitPort.Int()))
	tarpitConn, err := net.DialTimeout("tcp", tarpitAddr, 5*time.Second)
	if err != nil {
		s.Log.WithError(err).Debug("proxy: tarpit connect failed; closing connection")
		return
	}
	defer tarpitConn.Close()

	if _, err := tarpitConn.Write(data); err != nil {
		s.Log.WithError(err).Debug("proxy: write to tarpit failed")
		return
	}

	inactivity := time.Duration(cfg.Tarpit.InactivityTimeoutSeconds) * time.Second
	lifetime := time.Duration(cfg.Tarpit.MaxLifetimeSeconds) * time.Second
	deadline := time.Now().Add(lifetime)
	if lifetime > 0 {
		_ = clientConn.SetDeadline(deadline)
		_ = tarpitConn.SetDeadline(deadline)
	}

	done := make(chan struct{}, 2)
	copyOne := func(dst, src net.Conn) {
		buf := make([]byte, 512)
		for {
			if inactivity > 0 {
				_ = src.SetReadDeadline(time.Now().Add(inactivity))
			}
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}
	go copyOne(tarpitConn, clientConn)
	go copyOne(clientConn, tarpitConn)

	<-done
	_ = clientConn.Close()
	_ = tarpitConn.Close()
	<-done
}

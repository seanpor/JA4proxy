package server

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/seanpor/ja4proxy/internal/metrics"
	proxypkg "github.com/seanpor/ja4proxy/internal/proxy"
)

var BufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32768)
		return &b
	},
}

func (s *Server) Forward(clientConn net.Conn, initialData []byte, srcIP string, srcPort int) {
	s.Mu.RLock()
	cfg := s.Cfg
	s.Mu.RUnlock()

	backendAddr := net.JoinHostPort(cfg.Proxy.BackendHost, fmt.Sprintf("%d", cfg.Proxy.BackendPort.Int()))

	t3 := time.Now()
	backendConn, err := net.DialTimeout("tcp", backendAddr,
		time.Duration(cfg.Proxy.ConnectionTimeout)*time.Second)
	t6 := time.Now()
	if os.Getenv("JA4PROXY_FORENSIC") == "true" {
		_, lport, _ := net.SplitHostPort(clientConn.RemoteAddr().String())
		if err == nil {
			_, bp, _ := net.SplitHostPort(backendConn.LocalAddr().String())
			s.Log.Warnf("TRACE [P] port=%s outbound=%s T3=%d T6=%d", lport, bp, t3.UnixNano(), t6.UnixNano())
		} else {
			s.Log.Warnf("TRACE [P] port=%s T3=%d T6=%d", lport, t3.UnixNano(), t6.UnixNano())
		}
	}
	if err != nil {
		metrics.ConnectionErrorsTotal.WithLabelValues(ClassifyConnError("backend_dial", err)).Inc()
		s.Log.WithError(err).WithField("backend", backendAddr).Warn("proxy: backend connect failed")
		return
	}
	defer backendConn.Close()

	if cfg.Proxy.WriteProxyProtocol {
		var dstIP net.IP
		dstPort := 0
		if la, ok := clientConn.LocalAddr().(*net.TCPAddr); ok {
			dstIP = la.IP
			dstPort = la.Port
		}
		hdr := proxypkg.BuildBackendProxyHeader(cfg.Proxy.WriteProxyProtocolVersion, net.ParseIP(srcIP), srcPort, dstIP, dstPort)
		if _, err := backendConn.Write(hdr); err != nil {
			metrics.ConnectionErrorsTotal.WithLabelValues(ClassifyConnError("backend_proxy_header", err)).Inc()
			s.Log.WithError(err).Warn("proxy: write PROXY header to backend failed")
			return
		}
	}

	if _, err := backendConn.Write(initialData); err != nil {
		s.Log.WithError(err).Warn("proxy: write initial data to backend failed")
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		bp := BufferPool.Get().(*[]byte)
		defer BufferPool.Put(bp)
		buf := *bp
		for {
			_ = src.SetReadDeadline(time.Now().Add(time.Duration(cfg.Proxy.ReadTimeout) * time.Second))
			n, rerr := src.Read(buf)
			if n > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(time.Duration(cfg.Proxy.WriteTimeout) * time.Second))
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if rerr != nil {
				break
			}
		}
		_ = dst.Close()
		_ = src.Close()
	}

	go cp(backendConn, clientConn)
	go cp(clientConn, backendConn)
	wg.Wait()
}

func (s *Server) ReassembleClientHello(clientConn net.Conn, data, buf []byte) []byte {
	if len(data) < 5 {
		return data
	}

	recordLen := int(data[3])<<8 | int(data[4])
	want := 5 + recordLen
	const firstRecordCap = 65536
	if want > firstRecordCap {
		want = firstRecordCap
	}

	deadline := time.Now().Add(200 * time.Millisecond)
	for len(data) < want {
		if time.Now().After(deadline) {
			break
		}
		_ = clientConn.SetReadDeadline(deadline)
		offset := len(data)
		if offset >= cap(buf) {
			break
		}
		end := want
		if end > cap(buf) {
			end = cap(buf)
		}
		m, err := clientConn.Read(buf[offset:end])
		if m > 0 {
			data = buf[:offset+m]
		}
		if err != nil {
			break
		}
	}

	if len(data) >= 9 && data[0] == 0x16 && data[5] == 0x01 {
		handshakeLen := int(data[6])<<16 | int(data[7])<<8 | int(data[8])
		totalHandshakeWanted := 4 + handshakeLen
		currentHandshake := len(data) - 5

		const maxReassemblyBytes = 65536

		for currentHandshake < totalHandshakeWanted {
			if len(data) >= maxReassemblyBytes || time.Now().After(deadline) {
				break
			}

			_ = clientConn.SetReadDeadline(deadline)
			header := make([]byte, 5)
			if _, err := io.ReadFull(clientConn, header); err != nil {
				break
			}

			if header[0] != 0x16 {
				s.Log.WithField("content_type", header[0]).
					Debug("reassembly: non-handshake record during fragment assembly")
				break
			}

			nextLen := int(header[3])<<8 | int(header[4])
			if nextLen == 0 || nextLen > 16384 {
				break
			}

			body := make([]byte, nextLen)
			if _, err := io.ReadFull(clientConn, body); err != nil {
				break
			}

			data = append(data, header...)
			data = append(data, body...)
			currentHandshake += nextLen
		}
	}

	_ = clientConn.SetReadDeadline(time.Time{})
	return data
}

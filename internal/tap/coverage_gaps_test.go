package tap

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/sirupsen/logrus"
)

// eofSource is a PacketSource that returns EOF immediately.
type eofSource struct{}

func (eofSource) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	return nil, gopacket.CaptureInfo{}, io.EOF
}

// TestHandshakeEvent_HasServerHello covers both branches.
func TestHandshakeEvent_HasServerHello(t *testing.T) {
	e := &HandshakeEvent{}
	if e.HasServerHello() {
		t.Error("empty ServerHello should return false")
	}
	e.ServerHello = []byte{0x16, 0x03, 0x03}
	if !e.HasServerHello() {
		t.Error("non-empty ServerHello should return true")
	}
}

// TestRecover_NoPanic verifies Recover is a no-op when there is no panic.
func TestRecover_NoPanic(t *testing.T) {
	done := make(chan error, 1)
	s := NewSensor(layers.LinkTypeEthernet, 1)
	// No panic was triggered, so Recover should not send to done.
	Recover(done, s)
	select {
	case err := <-done:
		t.Errorf("Recover without panic should not send to done; got %v", err)
	default:
		// expected: nothing sent
	}
}

// TestRecover_NilDone verifies Recover handles a nil done channel.
func TestRecover_NilDone(t *testing.T) {
	s := NewSensor(layers.LinkTypeEthernet, 1)
	// Should not panic even with nil done channel.
	Recover(nil, s)
}

// TestSensor_LinkType verifies the LinkType getter.
func TestSensor_LinkType(t *testing.T) {
	s := NewSensor(layers.LinkTypeEthernet, 1)
	if s.LinkType() != layers.LinkTypeEthernet {
		t.Errorf("LinkType() = %v, want Ethernet", s.LinkType())
	}
}

// TestSensor_Deliver_FullChannel verifies deliver drops events without blocking.
func TestSensor_Deliver_FullChannel(t *testing.T) {
	s := NewSensor(layers.LinkTypeEthernet, 0) // buffer=0, always full
	// deliver should not block.
	done := make(chan struct{})
	go func() {
		s.deliver(HandshakeEvent{})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("deliver blocked on full channel")
	}
}

// TestSensor_Run_EOF verifies Run returns nil on EOF from source.
func TestSensor_Run_EOF(t *testing.T) {
	s := NewSensor(layers.LinkTypeEthernet, 10)
	ctx := context.Background()
	err := s.Run(ctx, eofSource{})
	if err != nil {
		t.Errorf("Run with EOF source should return nil, got %v", err)
	}
}

// TestWatchdog_NewWatchdog verifies the constructor.
func TestWatchdog_NewWatchdog(t *testing.T) {
	log := logrus.New()
	w := NewWatchdog(log)
	if w == nil {
		t.Fatal("NewWatchdog returned nil")
	}
}

// TestWatchdog_Run_SrcFactoryError verifies Run returns the source factory error.
func TestWatchdog_Run_SrcFactoryError(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.PanicLevel)
	w := NewWatchdog(log)

	sentinel := io.ErrUnexpectedEOF
	src := func() (PacketSource, func(), error) {
		return nil, func() {}, sentinel
	}
	sensorFact := func() *Sensor { return NewSensor(layers.LinkTypeEthernet, 1) }

	err := w.Run(context.Background(), src, sensorFact, func(_ *Sensor) {})
	if err != sentinel {
		t.Errorf("Run should return srcFactory error %v, got %v", sentinel, err)
	}
}

// TestWatchdog_Run_ContextCancel verifies Run exits cleanly on cancel.
func TestWatchdog_Run_ContextCancel(t *testing.T) {
	log := logrus.New()
	log.SetLevel(logrus.PanicLevel)
	w := NewWatchdog(log)

	ctx, cancel := context.WithCancel(context.Background())

	callCount := 0
	src := func() (PacketSource, func(), error) {
		callCount++
		return eofSource{}, func() {}, nil
	}
	sensorFact := func() *Sensor { return NewSensor(layers.LinkTypeEthernet, 1) }
	drain := func(s *Sensor) {
		for range s.Events() {
		}
		cancel() // cancel after first sensor drains
	}

	err := w.Run(ctx, src, sensorFact, drain)
	// err should be context.Canceled (nil from sensor, then ctx.Err())
	if err != nil && err != context.Canceled {
		t.Errorf("Run should return nil or context.Canceled, got %v", err)
	}
}

// TestMarkGap covers both client and server gap paths.
func TestMarkGap(t *testing.T) {
	s := &tlsStream{}

	// Mark a gap on the client side.
	s.markGap(true)
	if !s.clientDone {
		t.Error("markGap(true) should set clientDone")
	}

	// Second call should be a no-op (already done).
	s.markGap(true)

	// Mark a gap on the server side.
	s.markGap(false)
	if !s.serverDone {
		t.Error("markGap(false) should set serverDone")
	}
}

package redis

// phase-104: Coverage tests for PubSubHandler.

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

func TestNewPubSubHandler(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	reloadCalled := false
	refreshCalled := false
	h := NewPubSubHandler(c, nil,
		func() { reloadCalled = true },
		func() { refreshCalled = true },
	)
	if h == nil {
		t.Fatal("NewPubSubHandler: returned nil")
	}
	if h.log == nil {
		t.Error("NewPubSubHandler with nil logger: log should be non-nil")
	}
	_ = reloadCalled
	_ = refreshCalled
}

func TestPubSubHandler_HandleMessage_ConfigReload(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	var reloadCount int32
	var refreshCount int32
	h := NewPubSubHandler(c, logrus.New(),
		func() { atomic.AddInt32(&reloadCount, 1) },
		func() { atomic.AddInt32(&refreshCount, 1) },
	)

	// Test config reload channel
	h.handleMessage(&goredis.Message{Channel: ChannelConfigReload, Payload: "1"})
	if atomic.LoadInt32(&reloadCount) != 1 {
		t.Errorf("ChannelConfigReload: reload called %d times, want 1", reloadCount)
	}
	if atomic.LoadInt32(&refreshCount) != 0 {
		t.Errorf("ChannelConfigReload: refresh called %d times, want 0", refreshCount)
	}
}

func TestPubSubHandler_HandleMessage_DialChange(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	var reloadCount int32
	h := NewPubSubHandler(c, logrus.New(),
		func() { atomic.AddInt32(&reloadCount, 1) },
		func() {},
	)

	h.handleMessage(&goredis.Message{Channel: ChannelDialChange, Payload: "50"})
	if atomic.LoadInt32(&reloadCount) != 1 {
		t.Errorf("ChannelDialChange: reload called %d times, want 1", reloadCount)
	}
}

func TestPubSubHandler_HandleMessage_BlacklistAdd(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	var refreshCount int32
	h := NewPubSubHandler(c, logrus.New(),
		func() {},
		func() { atomic.AddInt32(&refreshCount, 1) },
	)

	h.handleMessage(&goredis.Message{Channel: ChannelBlacklistAdd, Payload: "fp1"})
	if atomic.LoadInt32(&refreshCount) != 1 {
		t.Errorf("ChannelBlacklistAdd: refresh called %d times, want 1", refreshCount)
	}
}

func TestPubSubHandler_HandleMessage_BlacklistRemove(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	var refreshCount int32
	h := NewPubSubHandler(c, logrus.New(),
		func() {},
		func() { atomic.AddInt32(&refreshCount, 1) },
	)

	h.handleMessage(&goredis.Message{Channel: ChannelBlacklistRemove, Payload: "fp1"})
	if atomic.LoadInt32(&refreshCount) != 1 {
		t.Errorf("ChannelBlacklistRemove: refresh called %d times, want 1", refreshCount)
	}
}

func TestPubSubHandler_HandleMessage_WhitelistAdd(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	var refreshCount int32
	h := NewPubSubHandler(c, logrus.New(),
		func() {},
		func() { atomic.AddInt32(&refreshCount, 1) },
	)

	h.handleMessage(&goredis.Message{Channel: ChannelWhitelistAdd, Payload: "fp2"})
	if atomic.LoadInt32(&refreshCount) != 1 {
		t.Errorf("ChannelWhitelistAdd: refresh called %d times, want 1", refreshCount)
	}
}

func TestPubSubHandler_HandleMessage_WhitelistRemove(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	var refreshCount int32
	h := NewPubSubHandler(c, logrus.New(),
		func() {},
		func() { atomic.AddInt32(&refreshCount, 1) },
	)

	h.handleMessage(&goredis.Message{Channel: ChannelWhitelistRemove, Payload: "fp2"})
	if atomic.LoadInt32(&refreshCount) != 1 {
		t.Errorf("ChannelWhitelistRemove: refresh called %d times, want 1", refreshCount)
	}
}

func TestPubSubHandler_HandleMessage_CIDRUpdate(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	var refreshCount int32
	h := NewPubSubHandler(c, logrus.New(),
		func() {},
		func() { atomic.AddInt32(&refreshCount, 1) },
	)

	h.handleMessage(&goredis.Message{Channel: ChannelCIDRUpdate, Payload: "192.168.0.0/24"})
	if atomic.LoadInt32(&refreshCount) != 1 {
		t.Errorf("ChannelCIDRUpdate: refresh called %d times, want 1", refreshCount)
	}
}

func TestPubSubHandler_HandleMessage_UnknownChannel(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	var reloadCount, refreshCount int32
	h := NewPubSubHandler(c, logrus.New(),
		func() { atomic.AddInt32(&reloadCount, 1) },
		func() { atomic.AddInt32(&refreshCount, 1) },
	)

	h.handleMessage(&goredis.Message{Channel: "unknown:channel", Payload: "data"})
	if atomic.LoadInt32(&reloadCount) != 0 || atomic.LoadInt32(&refreshCount) != 0 {
		t.Error("Unknown channel: no handler should have been called")
	}
}

func TestPubSubHandler_HandleMessage_NilCallbacks(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	// Both callbacks nil — should not panic
	h := NewPubSubHandler(c, logrus.New(), nil, nil)
	h.handleMessage(&goredis.Message{Channel: ChannelConfigReload, Payload: ""})
	h.handleMessage(&goredis.Message{Channel: ChannelBlacklistAdd, Payload: ""})
}

func TestPubSubHandler_Run_ContextCancel(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	h := NewPubSubHandler(c, logrus.New(), func() {}, func() {})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		h.Run(ctx)
		close(done)
	}()

	// Give it a moment to subscribe, then cancel
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// good
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not exit within 3s of context cancellation")
	}
}

func TestPubSubHandler_RunOnce_ContextCancel(t *testing.T) {
	c, mr := newTestClient(t)
	defer mr.Close()

	h := NewPubSubHandler(c, logrus.New(), func() {}, func() {})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		h.runOnce(ctx)
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("runOnce did not exit within 3s of context cancellation")
	}
}

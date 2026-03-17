package redis

import (
	"context"
	"time"

	rdb "github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

const (
	// ChannelConfigReload is the pub/sub channel used to trigger config hot-reload.
	// The Python proxy publishes to this channel on SIGHUP or Management UI reload.
	ChannelConfigReload = "config:reload"
	// ChannelDialChange is published when the dial value is updated.
	ChannelDialChange = "config:dial:change"
)

// PubSubHandler listens on Redis pub/sub channels and calls registered handlers.
type PubSubHandler struct {
	client   *Client
	log      *logrus.Logger
	onReload func()
}

// NewPubSubHandler creates a handler that calls onReload when a config:reload
// or config:dial:change message arrives.
func NewPubSubHandler(client *Client, log *logrus.Logger, onReload func()) *PubSubHandler {
	if log == nil {
		log = logrus.New()
	}
	return &PubSubHandler{
		client:   client,
		log:      log,
		onReload: onReload,
	}
}

// Run subscribes to config channels and blocks until ctx is cancelled.
// Reconnects automatically on connection failures (fail open).
func (h *PubSubHandler) Run(ctx context.Context) {
	backoff := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		h.runOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
			if backoff < 30*time.Second {
				backoff = backoff * 2
			}
		}
	}
}

func (h *PubSubHandler) runOnce(ctx context.Context) {
	sub := h.client.rdb.Subscribe(ctx, ChannelConfigReload, ChannelDialChange)
	defer sub.Close()
	ch := sub.Channel()
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				h.log.Warn("pubsub: channel closed; will reconnect")
				return
			}
			h.handleMessage(msg)
		}
	}
}

func (h *PubSubHandler) handleMessage(msg *rdb.Message) {
	h.log.WithFields(logrus.Fields{
		"channel": msg.Channel,
		"payload": msg.Payload,
	}).Debug("pubsub: received message")

	switch msg.Channel {
	case ChannelConfigReload, ChannelDialChange:
		if h.onReload != nil {
			h.onReload()
		}
	default:
		h.log.WithField("channel", msg.Channel).Debug("pubsub: unknown channel; ignoring")
	}
}

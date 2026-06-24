package redis

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	// JA4 and CIDR update channels (parity with Python)
	ChannelBlacklistAdd    = "ja4:blacklist:add"
	ChannelBlacklistRemove = "ja4:blacklist:remove"
	ChannelWhitelistAdd    = "ja4:whitelist:add"
	ChannelWhitelistRemove = "ja4:whitelist:remove"
	ChannelCIDRUpdate      = "geoip:cidr:update"
)

// criticalChannels is the set of channels whose messages are HMAC-verified
// when a secret is configured. JA4PROXY-2026-0019 — without HMAC, anyone
// with Redis PUBLISH access can flip the dial to 0, whitelist malicious
// JA4s, or force config reloads as a DoS primitive. These channels mutate
// security-critical state, so unsigned messages on them are dropped.
var criticalChannels = map[string]struct{}{
	ChannelConfigReload:    {},
	ChannelDialChange:      {},
	ChannelBlacklistAdd:    {},
	ChannelBlacklistRemove: {},
	ChannelWhitelistAdd:    {},
	ChannelWhitelistRemove: {},
	ChannelCIDRUpdate:      {},
}

// signedPubSubMessage matches the JSON envelope produced by src/pubsub.py.
// Data signed = "<type>:<value>" as utf-8, HMAC-SHA256, hex-encoded.
// The `type` field duplicates routing semantics for multi-type channels;
// on single-purpose channels we fall back to the channel name as the type.
type signedPubSubMessage struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Signature string `json:"signature"`
}

// PubSubHandler listens on Redis pub/sub channels and calls registered handlers.
type PubSubHandler struct {
	client     *Client
	log        *logrus.Logger
	onReload   func()
	onRefresh  func() // Refresh JA4/CIDR lists
	hmacSecret []byte // JA4PROXY-2026-0019 — nil/empty means "no verification"
}

// NewPubSubHandler creates a handler that calls onReload or onRefresh when
// Redis messages arrive.
func NewPubSubHandler(client *Client, log *logrus.Logger, onReload, onRefresh func()) *PubSubHandler {
	if log == nil {
		log = logrus.New()
	}
	return &PubSubHandler{
		client:    client,
		log:       log,
		onReload:  onReload,
		onRefresh: onRefresh,
	}
}

// SetHMACSecret configures HMAC verification for critical pub/sub channels.
// An empty string disables verification — in that mode the handler logs a
// one-line WARN on construction so operators are aware the escape hatch is
// engaged. The secret should match the Python publisher's signing_key.
func (h *PubSubHandler) SetHMACSecret(secret string) {
	if secret == "" {
		h.hmacSecret = nil
		h.log.Warn("pubsub: HMAC secret not configured; unsigned messages on critical channels will be accepted (JA4PROXY-2026-0019)")
		return
	}
	h.hmacSecret = []byte(secret)
}

// Run subscribes to config channels and blocks until ctx is cancelled.
// Reconnects automatically on connection failures (fail open) with exponential backoff.
func (h *PubSubHandler) Run(ctx context.Context) {
	const (
		minBackoff = 100 * time.Millisecond
		maxBackoff = 30 * time.Second
	)
	backoff := time.Duration(0)

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		start := time.Now()
		h.runOnce(ctx)

		// If we stayed connected for more than 10 seconds, reset backoff
		if time.Since(start) > 10*time.Second {
			backoff = 0
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
			if backoff == 0 {
				backoff = minBackoff
			} else {
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
			}
		}
	}
}

func (h *PubSubHandler) runOnce(ctx context.Context) {
	h.log.Info("pubsub: subscribing to config channels")
	sub := h.client.rdb.Subscribe(ctx,
		ChannelConfigReload,
		ChannelDialChange,
		ChannelBlacklistAdd,
		ChannelBlacklistRemove,
		ChannelWhitelistAdd,
		ChannelWhitelistRemove,
		ChannelCIDRUpdate,
	)
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

	if _, critical := criticalChannels[msg.Channel]; critical && len(h.hmacSecret) > 0 {
		if err := verifyPubSubHMAC(h.hmacSecret, msg.Channel, msg.Payload); err != nil {
			h.log.WithFields(logrus.Fields{
				"channel": msg.Channel,
				"reason":  err.Error(),
			}).Warn("pubsub: HMAC verification failed; dropping message (JA4PROXY-2026-0019)")
			return
		}
	}

	switch msg.Channel {
	case ChannelConfigReload, ChannelDialChange:
		if h.onReload != nil {
			h.onReload()
		}
	case ChannelBlacklistAdd, ChannelBlacklistRemove, ChannelWhitelistAdd, ChannelWhitelistRemove, ChannelCIDRUpdate:
		if h.onRefresh != nil {
			h.onRefresh()
		}
	default:
		h.log.WithField("channel", msg.Channel).Debug("pubsub: unknown channel; ignoring")
	}
}

// verifyPubSubHMAC parses the JSON envelope produced by src/pubsub.py and
// recomputes HMAC-SHA256(secret, "<type>:<value>"). Returns nil on a match.
// A missing/empty signature, a malformed envelope, or any mismatch returns
// an error — do NOT pass the message to the handler in those cases.
func verifyPubSubHMAC(secret []byte, channel, payload string) error {
	if payload == "" {
		return fmt.Errorf("empty payload")
	}
	var env signedPubSubMessage
	if err := json.Unmarshal([]byte(payload), &env); err != nil {
		return fmt.Errorf("malformed JSON envelope: %w", err)
	}
	if env.Signature == "" {
		return fmt.Errorf("signature missing")
	}
	msgType := env.Type
	if msgType == "" {
		// Single-purpose channels may omit the type field; fall back to the
		// channel name so the Go subscriber can verify payloads that the
		// Python publisher currently writes verbatim.
		msgType = channel
	}
	want, err := hex.DecodeString(env.Signature)
	if err != nil {
		return fmt.Errorf("signature not hex: %w", err)
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(msgType + ":" + env.Value))
	if !hmac.Equal(mac.Sum(nil), want) {
		return fmt.Errorf("HMAC mismatch")
	}
	return nil
}

// SignPubSubMessage produces the JSON envelope the Python publisher emits,
// and is used by tests (and by any future Go publisher) to build a message
// that the verifier will accept. Returns the JSON string ready to PUBLISH.
func SignPubSubMessage(secret []byte, msgType, value string) (string, error) {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(msgType + ":" + value))
	env := signedPubSubMessage{
		Type:      msgType,
		Value:     value,
		Signature: hex.EncodeToString(mac.Sum(nil)),
	}
	b, err := json.Marshal(env)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

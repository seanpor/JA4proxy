package redis

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync/atomic"
	"testing"

	rdb "github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"pgregory.net/rapid"
)

// ---------------------------------------------------------------------------
// Native Go Fuzz Targets
// ---------------------------------------------------------------------------

// FuzzVerifyPubSubHMAC tests that verifyPubSubHMAC never panics on arbitrary
// payloads, channel names, or secrets, and properly validates envelopes.
func FuzzVerifyPubSubHMAC(f *testing.F) {
	seeds := []struct {
		secret  string
		channel string
		payload string
	}{
		{"secret123", ChannelConfigReload, `{"type":"config:reload","value":"reload","signature":"abc"}`},
		{"", ChannelDialChange, ""},
		{"key", ChannelBlacklistAdd, `{"type":"","value":"test","signature":""}`},
		{"test-secret", "random-channel", `malformed json`},
		{"mysecret", ChannelCIDRUpdate, `{"type":"geoip:cidr:update","value":"192.168.1.0/24","signature":"badhex"}`},
	}
	for _, s := range seeds {
		f.Add([]byte(s.secret), s.channel, s.payload)
	}

	f.Fuzz(func(t *testing.T, secret []byte, channel, payload string) {
		// Totality guarantee: must never panic regardless of arbitrary payload, channel, or secret.
		_ = verifyPubSubHMAC(secret, channel, payload)
	})
}

// FuzzPubSubEnvelopeRoundtrip verifies that SignPubSubMessage produces valid envelopes
// that always verify successfully under matching secrets, and fail under mismatched secrets.
func FuzzPubSubEnvelopeRoundtrip(f *testing.F) {
	f.Add([]byte("secret1"), "config:reload", "100")
	f.Add([]byte("my-hmac-key"), "ja4:blacklist:add", "t13d1516h2_8daaf6152771_b186095e22b6")
	f.Add([]byte("short"), "custom:type", "")

	f.Fuzz(func(t *testing.T, secret []byte, msgType, value string) {
		if len(secret) == 0 {
			return
		}
		signed, err := SignPubSubMessage(secret, msgType, value)
		if err != nil {
			// Expected rejection when inputs contain invalid UTF-8 bytes that cannot safely round-trip JSON
			return
		}

		// When channel matches msgType, verification must always succeed.
		if err := verifyPubSubHMAC(secret, msgType, signed); err != nil {
			t.Fatalf("verifyPubSubHMAC failed on freshly signed message: %v", err)
		}

		// Mismatched secret must fail verification (unless value/type are empty and secrets behave identically).
		wrongSecret := append(secret, byte('!'))
		if err := verifyPubSubHMAC(wrongSecret, msgType, signed); err == nil {
			t.Fatalf("verifyPubSubHMAC unexpectedly succeeded with wrong secret")
		}
	})
}

// FuzzPubSubHandlerDispatch tests that PubSubHandler.handleMessage handles arbitrary
// channel strings and payloads safely without panicking across combinations of HMAC secret and allowUnsigned.
func FuzzPubSubHandlerDispatch(f *testing.F) {
	f.Add(ChannelConfigReload, "payload", "secret", false)
	f.Add(ChannelDialChange, `{"type":"config:dial:change","value":"50"}`, "", true)
	f.Add("unknown:channel", "{}", "secret", false)

	nullLogger := logrus.New()
	if !testing.Verbose() {
		nullLogger.SetOutput(&nullWriter{})
	}

	f.Fuzz(func(t *testing.T, channel, payload, secret string, allowUnsigned bool) {
		var reloadCalled, refreshCalled atomic.Int64

		handler := NewPubSubHandler(nil, nullLogger, func() {
			reloadCalled.Add(1)
		}, func() {
			refreshCalled.Add(1)
		})
		handler.SetHMACSecret(secret)
		handler.SetAllowUnsigned(allowUnsigned)

		msg := &rdb.Message{
			Channel: channel,
			Payload: payload,
		}

		// Must never panic
		handler.handleMessage(msg)
	})
}

type nullWriter struct{}

func (nullWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

// ---------------------------------------------------------------------------
// Rapid Property-Based Invariant Tests
// ---------------------------------------------------------------------------

// TestProperty_HMAC_SignatureTamperingSensitivity verifies that altering any byte
// in the payload, type, value, or signature causes verification to fail.
func TestProperty_HMAC_SignatureTamperingSensitivity(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		secretBytes := rapid.SliceOfN(rapid.Byte(), 8, 32).Draw(rt, "secret")
		msgType := rapid.StringMatching(`[a-zA-Z0-9_:]{1,30}`).Draw(rt, "type")
		msgVal := rapid.StringMatching(`[a-zA-Z0-9_\-./]{0,50}`).Draw(rt, "value")

		signed, err := SignPubSubMessage(secretBytes, msgType, msgVal)
		if err != nil {
			rt.Fatalf("SignPubSubMessage failed: %v", err)
		}

		// Valid signature passes
		if err := verifyPubSubHMAC(secretBytes, msgType, signed); err != nil {
			rt.Fatalf("valid message failed verification: %v", err)
		}

		// Parse envelope to tamper with fields
		var env signedPubSubMessage
		if err := json.Unmarshal([]byte(signed), &env); err != nil {
			rt.Fatalf("unmarshal error: %v", err)
		}

		tamperTarget := rapid.IntRange(0, 2).Draw(rt, "tamperTarget")
		switch tamperTarget {
		case 0: // Tamper with Type
			env.Type = env.Type + "tampered"
		case 1: // Tamper with Value
			env.Value = env.Value + "x"
		case 2: // Corrupt Signature
			sigBytes, _ := hex.DecodeString(env.Signature)
			if len(sigBytes) > 0 {
				sigBytes[0] ^= 0xFF
				env.Signature = hex.EncodeToString(sigBytes)
			}
		}

		tamperedJSON, err := json.Marshal(env)
		if err != nil {
			rt.Fatalf("marshal error: %v", err)
		}

		// Verification MUST fail on tampered message
		if err := verifyPubSubHMAC(secretBytes, msgType, string(tamperedJSON)); err == nil {
			rt.Fatalf("tampered message passed verification: %s", string(tamperedJSON))
		}
	})
}

// TestProperty_CriticalChannelEnforcement verifies that critical channels strictly
// reject unsigned or invalid messages when secret is set, and reject unsigned messages
// when secret is unset unless allowUnsigned is explicitly true.
func TestProperty_CriticalChannelEnforcement(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		criticalChanList := []string{
			ChannelConfigReload,
			ChannelDialChange,
			ChannelBlacklistAdd,
			ChannelBlacklistRemove,
			ChannelWhitelistAdd,
			ChannelWhitelistRemove,
			ChannelCIDRUpdate,
		}
		chIdx := rapid.IntRange(0, len(criticalChanList)-1).Draw(rt, "chanIdx")
		channel := criticalChanList[chIdx]

		secret := rapid.StringMatching(`[a-zA-Z0-9]{8,16}`).Draw(rt, "secret")
		hasSecret := rapid.Bool().Draw(rt, "hasSecret")
		allowUnsigned := rapid.Bool().Draw(rt, "allowUnsigned")

		var callbackTriggered atomic.Int64
		handler := NewPubSubHandler(nil, logrus.New(), func() {
			callbackTriggered.Add(1)
		}, func() {
			callbackTriggered.Add(1)
		})

		if hasSecret {
			handler.SetHMACSecret(secret)
		} else {
			handler.SetHMACSecret("")
		}
		handler.SetAllowUnsigned(allowUnsigned)

		// Case 1: Raw unsigned text payload
		rawMsg := &rdb.Message{
			Channel: channel,
			Payload: "reload_command_unauthenticated",
		}
		handler.handleMessage(rawMsg)

		if hasSecret {
			// With secret configured, raw message without valid HMAC must NEVER trigger callback
			if callbackTriggered.Load() > 0 {
				rt.Fatalf("raw unsigned message triggered callback on critical channel with secret set")
			}
		} else {
			// Without secret: only triggers if allowUnsigned is true
			if !allowUnsigned && callbackTriggered.Load() > 0 {
				rt.Fatalf("unsigned message on critical channel triggered callback without allowUnsigned")
			}
		}
	})
}

// TestProperty_SinglePurposeChannelTypeFallback verifies that when the JSON envelope's
// "type" field is empty, verifyPubSubHMAC falls back to channel name cleanly.
func TestProperty_SinglePurposeChannelTypeFallback(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		secret := rapid.SliceOfN(rapid.Byte(), 16, 32).Draw(rt, "secret")
		channel := rapid.SampledFrom([]string{
			ChannelConfigReload,
			ChannelDialChange,
			ChannelCIDRUpdate,
		}).Draw(rt, "channel")
		value := rapid.StringMatching(`[0-9a-zA-Z.:/-]{1,32}`).Draw(rt, "value")

		// Compute HMAC directly against channel:value
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(channel + ":" + value))
		expectedSig := hex.EncodeToString(mac.Sum(nil))

		// Envelope with empty Type
		env := signedPubSubMessage{
			Type:      "",
			Value:     value,
			Signature: expectedSig,
		}
		payloadBytes, err := json.Marshal(env)
		if err != nil {
			rt.Fatalf("marshal error: %v", err)
		}

		// Must verify successfully via fallback
		if err := verifyPubSubHMAC(secret, channel, string(payloadBytes)); err != nil {
			rt.Fatalf("fallback verification failed: %v", err)
		}

		// Mismatched channel must fail fallback
		otherChannel := "wrong:channel"
		if err := verifyPubSubHMAC(secret, otherChannel, string(payloadBytes)); err == nil {
			rt.Fatalf("fallback verification unexpectedly succeeded on wrong channel")
		}
	})
}

// ---------------------------------------------------------------------------
// Micro-benchmarks
// ---------------------------------------------------------------------------

func BenchmarkVerifyPubSubHMAC(b *testing.B) {
	secret := []byte("secret-key-32-bytes-long-benchmark!")
	channel := ChannelDialChange
	payload, err := SignPubSubMessage(secret, channel, "75")
	if err != nil {
		b.Fatalf("sign error: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := verifyPubSubHMAC(secret, channel, payload); err != nil {
			b.Fatalf("verify failed: %v", err)
		}
	}
}

func BenchmarkSignPubSubMessage(b *testing.B) {
	secret := []byte("secret-key-32-bytes-long-benchmark!")
	msgType := ChannelBlacklistAdd
	value := "t13d1516h2_8daaf6152771_b186095e22b6"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := SignPubSubMessage(secret, msgType, value)
		if err != nil {
			b.Fatalf("sign failed: %v", err)
		}
	}
}

func BenchmarkPubSubHandlerDispatch(b *testing.B) {
	secret := []byte("secret-key-32-bytes-long-benchmark!")
	channel := ChannelConfigReload
	payload, err := SignPubSubMessage(secret, channel, "reload")
	if err != nil {
		b.Fatalf("sign error: %v", err)
	}

	nullLog := logrus.New()
	nullLog.SetOutput(nullWriter{})

	handler := NewPubSubHandler(nil, nullLog, func() {}, func() {})
	handler.SetHMACSecret(string(secret))

	msg := &rdb.Message{
		Channel: channel,
		Payload: payload,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		handler.handleMessage(msg)
	}
}

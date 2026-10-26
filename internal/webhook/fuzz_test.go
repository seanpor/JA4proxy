// Package webhook provides HMAC-signed ECS payload delivery to configured webhook endpoints.
package webhook

import (
	"bytes"
	"strings"
	"testing"
)

func FuzzComputeHMAC(f *testing.F) {
	f.Add("test-secret", []byte("{\"event\":\"test\"}"))
	f.Add("", []byte{})
	f.Add("long-secret-key-that-exceeds-block-size-of-sha256-which-is-sixty-four-bytes-in-total-length-1234567890", []byte("sample payload"))

	f.Fuzz(func(t *testing.T, secret string, payload []byte) {
		sig1 := computeHMAC(secret, payload)
		sig2 := computeHMAC(secret, payload)

		if sig1 != sig2 {
			t.Fatalf("computeHMAC is not deterministic: %q != %q", sig1, sig2)
		}

		if len(sig1) != 71 || !bytes.HasPrefix([]byte(sig1), []byte("sha256=")) {
			t.Fatalf("expected 71-char 'sha256=<hex>' signature, got len %d: %q", len(sig1), sig1)
		}
	})
}

func FuzzWebhookEndpointRedaction(f *testing.F) {
	f.Add("ep-1", "https://example.com/webhook", "super-secret-key")
	f.Add("ep-2", "http://10.0.0.1:8080/hook", "")
	f.Add("ep-3", "invalid-url", "secret-token-xyz")

	f.Fuzz(func(t *testing.T, id, url, secret string) {
		ep := WebhookEndpoint{
			ID:     id,
			URL:    url,
			Secret: secret,
		}

		str := ep.String()
		gostr := ep.GoString()

		expectedSecretPart := "Secret:[REDACTED]"
		if !strings.Contains(str, expectedSecretPart) {
			t.Fatalf("String() missing redacted secret indicator: %s", str)
		}
		if !strings.Contains(gostr, expectedSecretPart) {
			t.Fatalf("GoString() missing redacted secret indicator: %s", gostr)
		}

		// The Secret must NEVER be rendered into the stringification verbatim,
		// i.e., "Secret:<secret>" must never occur.
		secretFieldPattern := "Secret:" + secret
		if secret != "" && !strings.Contains(redactedSecret, secret) && strings.Contains(str, secretFieldPattern) {
			t.Fatalf("String() leaked secret into field: %s", str)
		}
		if secret != "" && !strings.Contains(redactedSecret, secret) && strings.Contains(gostr, secretFieldPattern) {
			t.Fatalf("GoString() leaked secret into field: %s", gostr)
		}
	})
}

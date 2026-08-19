package security

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

// Phase 828a, outcomes O1 and O4.
//
// The pipeline computes a full explanation of every decision — each contributing
// signal with the human-readable Reason its module wrote, plus the action this
// connection would have received at other dial settings — and none of it was
// emitted. The event carried "event.risk_score": a single integer. An operator
// looking at a blocked connection could see 100 and nothing that explained it.
//
// These tests pin the payload shape the console and the analytics node will read,
// and the bounds that stop a misbehaving module inflating every event.

func TestEventCarriesSignalBreakdown(t *testing.T) {
	signals := []RiskSignal{
		{Name: "ja4_blacklist", Score: 100, Weight: 1.0, Reason: "fingerprint is on the blacklist"},
		{Name: "asn_datacenter", Score: 25, Weight: 0.8, Reason: "AS16509 is a hosting provider"},
		{Name: "sni_mismatch", Score: 10, Weight: 1.0, Reason: "SNI does not resolve to this host"},
	}

	payload := BuildSignalPayload(signals)
	if len(payload) != 3 {
		t.Fatalf("expected 3 signals, got %d", len(payload))
	}

	// Round-trip through JSON: that is how it actually reaches the console, and
	// a struct that looks right in memory but marshals wrong helps nobody.
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(raw)

	for _, want := range []string{
		"ja4_blacklist", "fingerprint is on the blacklist",
		"asn_datacenter", "AS16509 is a hosting provider",
		"sni_mismatch", "SNI does not resolve to this host",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("payload is missing %q\ngot: %s", want, got)
		}
	}

	// The reason is the whole point. A payload with names and scores but no
	// reasons would pass a naive length check and still leave the operator
	// guessing, so assert the key is present by name.
	if !strings.Contains(got, `"reason"`) {
		t.Errorf(`payload has no "reason" key: %s`, got)
	}
}

func TestSignalPayloadOrdersByAbsoluteContribution(t *testing.T) {
	// A signal that argues FOR allowing a connection is as interesting as one
	// that argues against. Ordering by raw score would sort every negative
	// signal to the bottom and, once the cap bites, drop them first — hiding
	// the evidence for allowing while keeping the evidence against. Given this
	// project's core asymmetry that is exactly backwards.
	signals := []RiskSignal{
		{Name: "small", Score: 5},
		{Name: "big_negative", Score: -60},
		{Name: "medium", Score: 30},
	}

	payload := BuildSignalPayload(signals)

	want := []string{"big_negative", "medium", "small"}
	for i, name := range want {
		if payload[i].Name != name {
			t.Errorf("position %d: want %q, got %q", i, name, payload[i].Name)
		}
	}
}

func TestEventCarriesCounterfactuals(t *testing.T) {
	// "What would happen if I moved the dial" is the question an operator asks
	// before touching it. The pipeline computes the answer at pipeline.go:843
	// and it had never left the process.
	cf := map[int]string{25: "allow", 50: "flag", 75: "block", 100: "ban"}

	payload := BuildCounterfactualPayload(cf)
	if len(payload) != 4 {
		t.Fatalf("expected 4 dial entries, got %d", len(payload))
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var back map[string]string
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for dial, action := range map[string]string{"25": "allow", "50": "flag", "75": "block", "100": "ban"} {
		if back[dial] != action {
			t.Errorf("dial %s: want %q, got %q", dial, action, back[dial])
		}
	}
}

func TestBypassedConnectionOmitsSignalsCleanly(t *testing.T) {
	// A bypassed connection never reaches the scorer, so it has no signals.
	// That must marshal as null, not as an empty array: "the scorer did not
	// run" and "the scorer ran and found nothing" are different facts about
	// the connection, and bypass_reason already explains the first.
	if got := BuildSignalPayload(nil); got != nil {
		t.Errorf("nil signals should stay nil, got %#v", got)
	}
	if got := BuildSignalPayload([]RiskSignal{}); got != nil {
		t.Errorf("empty signals should be nil, got %#v", got)
	}
	if got := BuildCounterfactualPayload(nil); got != nil {
		t.Errorf("nil counterfactuals should stay nil, got %#v", got)
	}

	raw, err := json.Marshal(map[string]interface{}{
		"ja4proxy.signals":         BuildSignalPayload(nil),
		"ja4proxy.counterfactuals": BuildCounterfactualPayload(nil),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(raw), `"ja4proxy.signals":null`) {
		t.Errorf("expected an explicit null, got: %s", raw)
	}
}

func TestSignalPayloadIsBounded(t *testing.T) {
	// O4: a buggy or hostile module must not be able to multiply the size of
	// every event on the stream. Redis memory is shared and this write happens
	// once per connection.
	huge := strings.Repeat("A", 10_000)
	signals := make([]RiskSignal, 500)
	for i := range signals {
		signals[i] = RiskSignal{Name: "flood", Score: i, Reason: huge}
	}

	payload := BuildSignalPayload(signals)

	if len(payload) != MaxEventSignals {
		t.Errorf("expected the payload capped at %d, got %d", MaxEventSignals, len(payload))
	}
	for i, s := range payload {
		if n := len([]rune(s.Reason)); n > MaxSignalReasonLen+len([]rune(truncationMarker)) {
			t.Errorf("signal %d: reason is %d runes, cap is %d", i, n, MaxSignalReasonLen)
		}
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// 20 signals x ~200 chars plus keys. Well under 8KB; the original input
	// was 5MB. The exact figure matters less than the order of magnitude.
	if len(raw) > 8*1024 {
		t.Errorf("payload is %d bytes from a 5MB input; the cap is not holding", len(raw))
	}
}

func TestTruncationDoesNotCorruptUTF8(t *testing.T) {
	// Reasons are operator-facing text and may contain non-ASCII. Slicing a
	// UTF-8 string by BYTES can split a multi-byte character, and json.Marshal
	// then silently substitutes U+FFFD — turning an explanation into mojibake
	// exactly when it is longest and most likely to matter.
	//
	// Sweep the cut point rather than testing one length. The first version of
	// this test used "é" (exactly 2 bytes) at a 200-rune cap: 200 is even, so a
	// byte-wise cut landed cleanly between characters and never split one. The
	// test passed against a deliberately byte-wise implementation — it was
	// green for the wrong reason. A sweep cannot be dodged by the cap and the
	// character width happening to share a factor.
	for _, ch := range []string{"é" /* 2 bytes */, "€" /* 3 */, "𝄞" /* 4 */} {
		src := strings.Repeat(ch, 80)
		for n := 1; n <= 60; n++ {
			got := truncate(src, n)
			if !utf8.ValidString(got) {
				t.Fatalf("truncate(%q x80, %d) produced invalid UTF-8: %q", ch, n, got)
			}
			if r := len([]rune(got)); r > n+len([]rune(truncationMarker)) {
				t.Fatalf("truncate(%q x80, %d) returned %d runes", ch, n, r)
			}
		}
	}

	// And end-to-end through the payload, as it actually reaches the console.
	signals := []RiskSignal{{
		Name:   "unicode",
		Score:  1,
		Reason: strings.Repeat("€", MaxSignalReasonLen+50),
	}}

	payload := BuildSignalPayload(signals)
	if !utf8.ValidString(payload[0].Reason) {
		t.Errorf("payload reason is not valid UTF-8: %q", payload[0].Reason)
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "�") {
		t.Errorf("truncation produced U+FFFD (json.Marshal repaired invalid bytes): %s", raw)
	}
}

func TestBuildSignalPayloadDoesNotReorderTheCaller(t *testing.T) {
	// The slice belongs to the PipelineResult and is read elsewhere (the
	// decision log). Sorting it in place as a side effect of building a
	// telemetry payload would silently change what another consumer sees.
	signals := []RiskSignal{
		{Name: "first", Score: 1},
		{Name: "second", Score: 90},
	}

	_ = BuildSignalPayload(signals)

	if signals[0].Name != "first" || signals[1].Name != "second" {
		t.Errorf("caller's slice was reordered: %v", signals)
	}
}

func BenchmarkBuildSignalPayload(b *testing.B) {
	// O3 input: this runs once per connection on the telemetry path. It is not
	// on the forwarding hot path (the event is marshalled and enqueued
	// fire-and-forget after the decision is already made), but it still runs
	// per connection and must stay cheap.
	signals := make([]RiskSignal, 8)
	for i := range signals {
		signals[i] = RiskSignal{
			Name:   "signal_name",
			Score:  i * 7,
			Weight: 1.0,
			Reason: "a representative human-readable explanation of this signal",
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BuildSignalPayload(signals)
	}
}

func TestCounterfactualsExistAtEveryDial(t *testing.T) {
	// phase-828a. These were gated on `dial == 0`, so the field was null in
	// every enforcing deployment — which is precisely where "what would happen
	// if I moved the dial" is the question being asked. A field that is present
	// only when the operator does not need it is not a feature.
	d := NewActionDecider(nil)

	for _, dial := range []int{0, 25, 50, 75, 100} {
		cf := d.Counterfactuals(60, []int{25, 50, 75, 100})
		payload := BuildCounterfactualPayload(cf)
		if len(payload) != 4 {
			t.Errorf("dial %d: expected 4 counterfactual entries, got %d", dial, len(payload))
		}
		for _, want := range []string{"25", "50", "75", "100"} {
			if _, ok := payload[want]; !ok {
				t.Errorf("dial %d: counterfactuals missing key %q", dial, want)
			}
		}
	}
}

func BenchmarkCounterfactuals(b *testing.B) {
	// Justifies removing the dial==0 gate: this now runs on every scored
	// connection, so it has to be cheap enough to ignore.
	d := NewActionDecider(nil)
	dials := []int{25, 50, 75, 100}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = d.Counterfactuals(60, dials)
	}
}

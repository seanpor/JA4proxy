package security

import (
	"sort"
	"strconv"
)

// Phase 828a — carry the decision's explanation into the event stream.
//
// The pipeline already computes everything an operator needs to understand a
// decision: PipelineResult.Signals holds every contributing signal, each with a
// human-readable Reason written by the module that scored it, and
// Counterfactuals holds the action this same connection would have received at
// other dial settings.
//
// None of it was emitted. cmd/ja4pd wrote "event.risk_score": one integer. The
// console showed an operator a number and left them to guess why, while the
// sentence that explained it had been computed microseconds earlier and thrown
// away.
//
// These helpers convert both into bounded, JSON-safe shapes. The bounds are not
// decoration: signal count and reason length are produced by modules, and a
// buggy or hostile module must not be able to inflate every event on the stream
// without limit. Redis memory is a shared resource and the event write is on
// the telemetry path of every single connection.

const (
	// MaxEventSignals caps how many signals ride along on one event. Real
	// decisions carry a handful; the cap exists so a misbehaving module cannot
	// multiply the size of every event in the stream.
	MaxEventSignals = 20

	// MaxSignalReasonLen caps one reason string. Reasons are written for
	// humans and are short; anything longer is a bug, and truncating it costs
	// less than letting it through.
	MaxSignalReasonLen = 200

	// truncationMarker is appended to a reason that was cut, so a reader can
	// tell "the module said this" from "the module said this and more".
	truncationMarker = "…"
)

// SignalPayload is one signal in a form safe to marshal into an event.
//
// The field names are deliberately short: this struct is serialised once per
// connection, and the names are the JSON keys the analytics node and the
// console will read.
type SignalPayload struct {
	Name   string  `json:"name"`
	Score  int     `json:"score"`
	Weight float64 `json:"weight"`
	Reason string  `json:"reason"`
}

// BuildSignalPayload converts signals into a bounded slice for event emission.
//
// Selection is by absolute contribution, highest first. Absolute matters: a
// signal scoring -40 (something actively vouching for this connection) is
// exactly as interesting to an operator as one scoring +40, and truncating by
// raw score would silently drop every negative signal first — hiding the
// evidence FOR allowing a connection while keeping the evidence against it.
// Given the project's core asymmetry, that is the wrong thing to lose.
//
// Returns nil for no signals, so a bypassed connection (which never reaches the
// scorer) marshals as JSON null rather than an empty array — "the scorer did not
// run" and "the scorer ran and found nothing" are different facts, and
// bypass_reason already explains the first.
func BuildSignalPayload(signals []RiskSignal) []SignalPayload {
	if len(signals) == 0 {
		return nil
	}

	// Copy before sorting: this runs on the caller's slice, which belongs to
	// the PipelineResult and may be read elsewhere. Reordering a caller's data
	// as a side effect of building a log payload would be a nasty surprise.
	ordered := make([]RiskSignal, len(signals))
	copy(ordered, signals)

	sort.SliceStable(ordered, func(i, j int) bool {
		return abs(ordered[i].Score) > abs(ordered[j].Score)
	})

	if len(ordered) > MaxEventSignals {
		ordered = ordered[:MaxEventSignals]
	}

	out := make([]SignalPayload, 0, len(ordered))
	for _, s := range ordered {
		out = append(out, SignalPayload{
			Name:   truncate(s.Name, MaxSignalReasonLen),
			Score:  s.Score,
			Weight: s.Weight,
			Reason: truncate(s.Reason, MaxSignalReasonLen),
		})
	}
	return out
}

// BuildCounterfactualPayload converts the {dial: action} map into a form with
// string keys, which is what JSON objects require.
//
// Returns nil when empty so the field marshals as null rather than {} — again
// distinguishing "not computed" from "computed and empty".
func BuildCounterfactualPayload(cf map[int]string) map[string]string {
	if len(cf) == 0 {
		return nil
	}
	out := make(map[string]string, len(cf))
	for dial, action := range cf {
		out[strconv.Itoa(dial)] = action
	}
	return out
}

// truncate cuts s to at most n runes, appending a marker when it cut.
//
// Rune-aware, not byte-aware: slicing a UTF-8 string by bytes can split a
// multi-byte character and produce invalid UTF-8, which json.Marshal then
// replaces with U+FFFD. Reason strings are operator-facing text and may
// legitimately contain non-ASCII.
func truncate(s string, n int) string {
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n]) + truncationMarker
}

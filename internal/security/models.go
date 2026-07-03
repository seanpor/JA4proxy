// Package security provides the risk scoring pipeline for JA4proxy.
package security

import (
	"net"
	"net/netip"
)

// RiskSignal is a single scored observation from a security module.
// It is identical in semantics to the Python RiskSignal dataclass.
type RiskSignal struct {
	// Name is the snake_case signal identifier (e.g. "ja4_whitelist").
	Name string
	// Score is the raw risk contribution (-100 to 100).
	Score int
	// Reason is a human-readable explanation.
	Reason string
	// Weight is the multiplier applied to Score before summing. Default 1.0.
	Weight float64
}

// ConnectionContext is an immutable snapshot of observable connection metadata.
// Populated before the pipeline runs; passed to every module.
type ConnectionContext struct {
	ClientIP   string
	ParsedIP   net.IP
	ClientAddr netip.Addr
	// ClientPort is the source TCP port. Zero when behind PROXY protocol
	// or when the source address is not a *net.TCPAddr.
	ClientPort           int
	JA4                  string
	JA4X                 string
	ALPN                 string
	HasValidClientCert   bool
	ClientCertificate    []byte
	SNI                  string
	TLSVersion           int
	Country              string
	CipherList           []int
	TCPJA4T              string
	TCPWindowSize        int
	TCPTTL               int
	TCPOptions           string
	ConnectionLifespanMS int
	TLSAlerts            []string

	// blocklistSignals / blocklistChecked (phase-520, JA4PROXY-2026-0094): the
	// one exception to "immutable snapshot" above. Pipeline.Process() calls
	// BlocklistManager.Check() exactly once and stashes the result here before
	// handing conn to the async worker (or straight to processInternal in Sync
	// mode) so processInternal never calls Check() a second time — a second
	// call would reintroduce the JA4PROXY-2026-0037 TOCTOU. Safe to mutate:
	// the write in Process() happens-before the read in processInternal via
	// either a direct call or the workChan send/receive.
	blocklistSignals []RiskSignal
}

// PipelineResult is the outcome of processing one connection.
type PipelineResult struct {
	Action          string
	Bypassed        bool
	BypassReason    string
	Score           int
	Signals         []RiskSignal
	Dial            int
	Counterfactuals map[int]string
}

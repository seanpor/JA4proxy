// Package logging provides ECS 8.x-compliant log formatting for JA4proxy.
package logging

import (
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// ECSFormatter formats logrus entries as ECS 8.x-compliant JSON.
// Set Mode to "legacy" to use the standard logrus JSON formatter.
// ECSFormatter implements logrus.Formatter directly via the Format method.
type ECSFormatter struct {
	// Mode controls the output format: "" or "ecs" produces ECS 8.x JSON;
	// "legacy" produces legacy JSON with timestamp/level/message fields.
	Mode string
}

// severityMap maps action names to ECS event.severity integers.
var severityMap = map[string]int{
	"allow":        1,
	"flag":         2,
	"rate_limited": 3,
	"tarpit":       4,
	"block":        5,
	"ban":          6,
}

// Format formats the log entry according to the configured Mode.
// Format implements logrus.Formatter.
func (f *ECSFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	if f.Mode == "legacy" {
		return f.doLegacy(entry)
	}
	return f.doECS(entry)
}

func (f *ECSFormatter) doLegacy(entry *logrus.Entry) ([]byte, error) {
	lf := &logrus.JSONFormatter{
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "level",
			logrus.FieldKeyMsg:   "message",
		},
	}
	return lf.Format(entry)
}

func (f *ECSFormatter) doECS(entry *logrus.Entry) ([]byte, error) {
	out := make(map[string]interface{}, 32)

	out["@timestamp"] = entry.Time.UTC().Format(time.RFC3339Nano)
	out["log.level"] = entry.Level.String()
	out["message"] = entry.Message
	out["event.kind"] = "event"
	out["event.category"] = []string{"network", "intrusion_detection"}
	out["event.type"] = []string{"connection"}
	out["network.transport"] = "tcp"
	out["network.protocol"] = "tls"
	out["service.name"] = "ja4proxy"
	out["destination.port"] = 443

	hostname, _ := os.Hostname()
	if hostname != "" {
		out["host.name"] = hostname
	}

	data := entry.Data

	if v, ok := data["host"]; ok {
		out["host.name"] = v
	}
	if v, ok := data["event_kind"]; ok {
		out["event.kind"] = v
	}
	if v, ok := data["event_action"]; ok {
		out["event.action"] = v
	} else if v, ok := data["action"]; ok {
		out["event.action"] = v
	}
	if v, ok := data["client_ip"]; ok {
		out["source.ip"] = v
	}
	if v, ok := data["src_port"]; ok {
		out["source.port"] = v
	}
	if v, ok := data["ja4"]; ok {
		out["ja4proxy.fingerprint.ja4"] = v
	}
	if v, ok := data["ja4x"]; ok {
		out["ja4proxy.fingerprint.ja4x"] = v
	}
	if v, ok := data["ja4t"]; ok {
		out["ja4proxy.fingerprint.ja4t"] = v
	}
	if v, ok := data["score"]; ok {
		out["ja4proxy.score"] = v
		out["event.risk_score"] = v
	}
	if v, ok := data["sni"]; ok {
		out["ja4proxy.sni"] = v
	}
	if v, ok := data["alpn"]; ok {
		out["ja4proxy.alpn"] = v
	}
	if v, ok := data["country"]; ok {
		out["ja4proxy.country_code"] = v
	}
	if v, ok := data["tls_version"]; ok {
		out["tls.version"] = v
	}
	if v, ok := data["tls_cipher"]; ok {
		out["tls.cipher"] = v
	}
	if v, ok := data["service_version"]; ok {
		out["service.version"] = v
	}
	if v, ok := data["dial"]; ok {
		out["ja4proxy.dial_setting"] = v
	}
	if v, ok := data["signals"]; ok {
		out["ja4proxy.signals"] = v
	}
	if v, ok := data["dial_old"]; ok {
		out["ja4proxy.dial.old_value"] = v
	}
	if v, ok := data["dial_new"]; ok {
		out["ja4proxy.dial.new_value"] = v
	}

	if a, ok := data["action"]; ok {
		if s, ok := a.(string); ok {
			if s == "allow" {
				out["event.outcome"] = "success"
			} else {
				out["event.outcome"] = "failure"
			}
			if sev, ok2 := severityMap[s]; ok2 {
				out["event.severity"] = sev
			}
			if s == "ban" {
				if ip, ok3 := data["client_ip"]; ok3 {
					ipStr, _ := ip.(string)
					out["threat.indicator.ip"] = ipStr
					if strings.Contains(ipStr, ":") {
						out["threat.indicator.type"] = "ipv6-addr"
					} else {
						out["threat.indicator.type"] = "ipv4-addr"
					}
				}
			}
		}
	}

	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// NewECSLogrusFormatter returns a logrus.Formatter backed by ECSFormatter.
// ECSFormatter now implements logrus.Formatter directly via its Format method.
func NewECSLogrusFormatter(mode string) logrus.Formatter {
	return &ECSFormatter{Mode: mode}
}

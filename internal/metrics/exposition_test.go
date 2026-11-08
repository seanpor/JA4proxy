package metrics_test

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/expfmt"
	"github.com/seanpor/ja4proxy/internal/metrics"
	"github.com/seanpor/ja4proxy/internal/tap"
)

var (
	metricNameRegex = regexp.MustCompile(`^[a-zA-Z_:][a-zA-Z0-9_:]*$`)
	ja4MetricRegex  = regexp.MustCompile(`^ja4proxy_[a-z0-9_]+$`)
	labelNameRegex  = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)
)

func TestOpenMetricsExpositionStandards(t *testing.T) {
	cases := []struct {
		name       string
		collectors []prometheus.Collector
	}{
		{
			name:       "ProxyMetrics",
			collectors: append(metrics.Collectors(), metrics.NetBoxCIDRsLoaded),
		},
		{
			name:       "TapMetrics",
			collectors: tap.Collectors(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := prometheus.NewPedanticRegistry()
			for _, c := range tc.collectors {
				if err := reg.Register(c); err != nil {
					t.Fatalf("failed to register collector %v on pedantic registry: %v", c, err)
				}
			}

			// Gather all metric families
			families, err := reg.Gather()
			if err != nil {
				t.Fatalf("pedantic registry Gather() returned error: %v", err)
			}
			if len(families) == 0 {
				t.Fatalf("no metric families gathered for %s", tc.name)
			}

			for _, fam := range families {
				famName := fam.GetName()

				// 1. Assert metric naming conventions
				if !metricNameRegex.MatchString(famName) {
					t.Errorf("metric family %q violates Prometheus metric name syntax", famName)
				}
				if !ja4MetricRegex.MatchString(famName) {
					t.Errorf("metric family %q does not match expected prefix/pattern ^ja4proxy_[a-z0-9_]+$", famName)
				}

				// 2. Assert counter naming rule (ends strictly with _total)
				famType := fam.GetType()
				if famType.String() == "COUNTER" {
					if !strings.HasSuffix(famName, "_total") {
						t.Errorf("counter metric family %q does not end with _total", famName)
					}
				}

				// 3. Assert non-empty HELP description
				if strings.TrimSpace(fam.GetHelp()) == "" {
					t.Errorf("metric family %q has empty HELP description", famName)
				}

				// 4. Assert labels on any instances
				for _, m := range fam.GetMetric() {
					for _, lbl := range m.GetLabel() {
						lblKey := lbl.GetName()
						if !labelNameRegex.MatchString(lblKey) {
							t.Errorf("metric %q has invalid label name %q (must match ^[a-z_][a-z0-9_]*$)", famName, lblKey)
						}
						if strings.HasPrefix(lblKey, "__") {
							t.Errorf("metric %q has reserved internal label %q", famName, lblKey)
						}
					}
				}
			}

			// 5. Test OpenMetrics text exposition format
			var buf bytes.Buffer
			encoder := expfmt.NewEncoder(&buf, expfmt.FmtOpenMetrics_1_0_0)
			for _, fam := range families {
				if err := encoder.Encode(fam); err != nil {
					t.Errorf("failed to encode family %s to OpenMetrics text format: %v", fam.GetName(), err)
				}
			}
			if closer, ok := encoder.(expfmt.Closer); ok {
				if err := closer.Close(); err != nil {
					t.Errorf("failed to close OpenMetrics encoder: %v", err)
				}
			}

			output := buf.String()
			if !strings.Contains(output, "# EOF") {
				t.Errorf("OpenMetrics exposition missing # EOF terminal line")
			}
		})
	}
}

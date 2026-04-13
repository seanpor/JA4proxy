package metrics

import "github.com/prometheus/client_golang/prometheus"

// NetBoxCIDRsLoaded counts successful and failed NetBox CIDR fetches.
// Registered via init() to avoid merge conflicts with other phases touching metrics.go.
// phase-94i2
var NetBoxCIDRsLoaded = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "ja4proxy_netbox_cidrs_loaded",
		Help: "NetBox CIDR fetch results (phase-94i2)",
	},
	[]string{"status"}, // ok | error
)

func init() {
	prometheus.MustRegister(NetBoxCIDRsLoaded)
}

package wizard

import (
	_ "embed"
	"fmt"
	"strings"
	"text/template"
)

//go:embed templates/proxy.yml.tmpl
var proxyYMLTemplate string

//go:embed templates/haproxy.cfg.tmpl
var haproxyCFGTemplate string

//go:embed templates/systemd.service.tmpl
var systemdServiceTemplate string

type TemplateData struct {
	BackendHost     string
	BackendPort     int
	BindIP          string
	LogLevel        string
	DialValue       int
	AllowedSNIs     []string
	UpstreamLB      bool
	TrustedCIDRs    []string
	WritePROXY      bool
	PROXYVersion    int
	TLSCerts        string
	TLSCertPath     string
	TLSKeyPath      string
	GeoIPPaths      []string
	MonitoringStack bool
	Firewall        string
	Mode            string
	Lane            int
	LaneName        string
	ProjectName     string
	Ports           map[string]int
}

func RenderProxyYML(data TemplateData) (string, error) {
	tmpl, err := template.New("proxy.yml").Funcs(templateFuncs()).Parse(proxyYMLTemplate)
	if err != nil {
		return "", fmt.Errorf("parse proxy.yml template: %w", err)
	}
	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute proxy.yml template: %w", err)
	}
	return buf.String(), nil
}

func RenderHAProxyCfg(data TemplateData) (string, error) {
	tmpl, err := template.New("haproxy.cfg").Funcs(templateFuncs()).Parse(haproxyCFGTemplate)
	if err != nil {
		return "", fmt.Errorf("parse haproxy.cfg template: %w", err)
	}
	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute haproxy.cfg template: %w", err)
	}
	return buf.String(), nil
}

func RenderSystemdService(data TemplateData) (string, error) {
	tmpl, err := template.New("systemd.service").Funcs(templateFuncs()).Parse(systemdServiceTemplate)
	if err != nil {
		return "", fmt.Errorf("parse systemd.service template: %w", err)
	}
	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute systemd.service template: %w", err)
	}
	return buf.String(), nil
}

func templateFuncs() template.FuncMap {
	return template.FuncMap{
		"join": strings.Join,
		"add": func(a, b int) int {
			return a + b
		},
	}
}

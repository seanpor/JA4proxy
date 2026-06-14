package wizard

import (
	"net"
	"os"
	"strconv"
	"strings"
)

func validPort(s string) bool {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return false
	}
	return v >= 1 && v <= 65535
}

func validBindIP(s string) bool {
	return net.ParseIP(strings.TrimSpace(s)) != nil
}

func validCertPath(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	info, err := os.Stat(s)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func validDir(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	info, err := os.Stat(s)
	if err != nil {
		return false
	}
	return info.IsDir()
}

func atoi(s string, defaultVal int) int {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return defaultVal
	}
	return v
}

func splitCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

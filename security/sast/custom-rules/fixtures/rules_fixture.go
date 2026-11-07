//go:build ignore

package testfixtures

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
)

type dummyMetric struct{}

func (m dummyMetric) Inc() {}

var metric dummyMetric

func badHTTPBodyDecode(resp *http.Response) {
	var target map[string]interface{}
	// ruleid: ja4p-unbounded-http-body-decode
	_ = json.NewDecoder(resp.Body).Decode(&target)
}

func badHTTPBodyReadAll(resp *http.Response) {
	// ruleid: ja4p-unbounded-http-body-decode
	_, _ = io.ReadAll(resp.Body)
}

func goodHTTPBodyDecode(resp *http.Response) {
	var target map[string]interface{}
	// ok: ja4p-unbounded-http-body-decode
	_ = json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&target)
}

func goodHTTPBodyReadAll(resp *http.Response) {
	// ok: ja4p-unbounded-http-body-decode
	_, _ = io.ReadAll(io.LimitReader(resp.Body, 256<<10))
}

func badKeyRead(keyPath string) ([]byte, error) {
	// ruleid: ja4p-sensitive-key-read-perm-check
	return os.ReadFile(keyPath)
}

func goodKeyRead(keyPath string) ([]byte, error) {
	info, err := os.Stat(keyPath)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, os.ErrPermission
	}
	// ok: ja4p-sensitive-key-read-perm-check
	return os.ReadFile(keyPath)
}

func badChannelDrop(ch chan int, val int) {
	// ruleid: ja4p-select-default-missing-metric
	select {
	case ch <- val:
	default:
		// silent drop
	}
}

func goodChannelDrop(ch chan int, val int) {
	// ok: ja4p-select-default-missing-metric
	select {
	case ch <- val:
	default:
		metric.Inc()
	}
}

func badRegexCompile(input string) bool {
	// ruleid: ja4p-hotpath-regexp-compile
	re := regexp.MustCompile(`^[a-z]+$`)
	return re.MatchString(input)
}

var pkgRegex = regexp.MustCompile(`^[a-z]+$`)

func goodRegexUsage(input string) bool {
	// ok: ja4p-hotpath-regexp-compile
	return pkgRegex.MatchString(input)
}

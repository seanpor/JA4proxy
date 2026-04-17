// ja4check reads a raw TLS ClientHello binary file and prints the JA4 fingerprint.
//
// Usage:
//
//	ja4check <clienthello.bin>
//
// Output: the JA4 fingerprint string on stdout, e.g. t13d030200_1301,1302_0000,0010,002b
// Used by parity tests to compare Go vs Python JA4 output.
package main

import (
	"fmt"
	"os"

	gotls "github.com/anomalyco/ja4proxy/internal/tls"
)

// osExit is overridden in tests to avoid calling os.Exit.
var osExit = os.Exit

func main() {
	result, code := mainResult(os.Args[1:])
	if code != 0 {
		fmt.Fprintln(os.Stderr, result)
		osExit(code)
		return
	}
	fmt.Println(result)
}

// mainResult returns the output string and exit code.
func mainResult(args []string) (string, int) {
	result, err := run(args)
	if err != nil {
		if _, ok := err.(*parseError); ok {
			return err.Error(), 2
		}
		return err.Error(), 1
	}
	return result, 0
}

// parseError wraps TLS parse failures so main() can distinguish exit code 2.
type parseError struct{ err error }

func (e *parseError) Error() string { return "parse error: " + e.err.Error() }

// run encapsulates the ja4check logic for testability.
func run(args []string) (string, error) {
	if len(args) < 1 {
		return "", fmt.Errorf("usage: ja4check <clienthello.bin>")
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		return "", err
	}
	info, err := gotls.ParseClientHello(data)
	if err != nil {
		return "", &parseError{err}
	}
	return gotls.ComputeJA4(info), nil
}

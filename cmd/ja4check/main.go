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

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: ja4check <clienthello.bin>")
		os.Exit(1)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	info, err := gotls.ParseClientHello(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse error: %v\n", err)
		os.Exit(2)
	}
	fmt.Println(gotls.ComputeJA4(info))
}

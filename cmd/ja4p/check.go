package main

import (
	"fmt"
	"io"
	"os"

	gotls "github.com/seanpor/ja4proxy/internal/tls"
	"github.com/spf13/cobra"
)

func buildCheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check [clienthello.bin]",
		Short: "Compute JA4 fingerprint from a raw binary file",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			f, err := os.Open(args[0])
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
				os.Exit(1)
			}
			defer f.Close()
			data, err := io.ReadAll(io.LimitReader(f, 1<<20))
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
				os.Exit(1)
			}
			info, err := gotls.ParseClientHello(data)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing ClientHello: %v\n", err)
				os.Exit(1)
			}
			fmt.Println(gotls.ComputeJA4(info))
		},
	}
}

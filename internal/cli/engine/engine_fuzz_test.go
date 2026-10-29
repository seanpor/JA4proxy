package engine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/seanpor/ja4proxy/internal/cli/engine"
	"pgregory.net/rapid"
)

// exitPanic records an intercepted osExit call.
type exitPanic struct {
	Code int
}

// FuzzCLIArgumentParsing fuzzes the Cobra CLI argument dispatcher and flags.
func FuzzCLIArgumentParsing(f *testing.F) {
	seeds := []string{
		"help",
		"--help",
		"--output json",
		"health",
		"ip lookup 127.0.0.1",
		"ip ban 192.168.1.1 --confirm",
		"ip release 192.168.1.1 --confirm",
		"dial show",
		"config show",
		"allowlist list",
		"blocklist list",
		"policy validate",
		"simulation run",
		"invalid-subcommand --unknown-flag",
		"--url http://127.0.0.1:8080 --token secret123 ip lookup 10.0.0.1",
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, argString string) {
		// Mock HTTP test server responding to any endpoint
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","records":[],"count":0}`))
		}))
		defer server.Close()

		// Intercept osExit inside engine
		origExit := engine.SetOSExit(func(code int) {
			panic(exitPanic{Code: code})
		})
		defer engine.SetOSExit(origExit)

		args := strings.Fields(argString)
		cmd := engine.BuildManagementRoot()
		cmd.SetArgs(args)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SilenceErrors = true
		cmd.SilenceUsage = true

		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(exitPanic); ok {
					// Expected exit via osExit handler
					return
				}
				t.Fatalf("unexpected panic while parsing CLI args %q: %v", argString, r)
			}
		}()

		// Execute root command
		_ = cmd.ExecuteContext(context.Background())
	})
}

// TestProperty_CLI_JSONOutputInvariant tests that when --output json is specified,
// any non-empty stdout output is strictly valid JSON.
func TestProperty_CLI_JSONOutputInvariant(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","mode":"monitor","dial":50,"records":[{"id":1,"name":"rule1"}]}`))
	}))
	defer server.Close()

	commandsToTest := []string{
		"dial get",
		"health",
		"allowlist list",
		"blocklist list",
	}

	rapid.Check(t, func(t *rapid.T) {
		subcmd := rapid.SampledFrom(commandsToTest).Draw(t, "subcmd")

		origExit := engine.SetOSExit(func(code int) {
			panic(exitPanic{Code: code})
		})
		defer engine.SetOSExit(origExit)

		var outBuf, errBuf bytes.Buffer
		cmd := engine.BuildManagementRoot()
		args := append(strings.Fields(subcmd), "--url", server.URL, "--token", "test-token", "--output", "json")
		cmd.SetArgs(args)
		cmd.SetOut(&outBuf)
		cmd.SetErr(&errBuf)
		cmd.SilenceErrors = true

		func() {
			defer func() {
				_ = recover()
			}()
			_ = cmd.ExecuteContext(context.Background())
		}()

		outputStr := strings.TrimSpace(outBuf.String())
		if outputStr != "" {
			if !json.Valid([]byte(outputStr)) {
				t.Fatalf("command %q with --output json produced invalid JSON: %s", subcmd, outputStr)
			}
		}
	})
}

// TestProperty_CLI_UnknownCommandsYieldError asserts that unknown subcommands strictly
// produce non-zero return codes or Cobra execution errors.
func TestProperty_CLI_UnknownCommandsYieldError(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		randWord := rapid.StringMatching("[a-z]{3,10}").Draw(t, "randWord")
		cmdName := fmt.Sprintf("random-cmd-%s", randWord)

		cmd := engine.BuildManagementRoot()
		cmd.SetArgs([]string{cmdName})
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SilenceErrors = true

		err := cmd.ExecuteContext(context.Background())
		if err == nil {
			t.Fatalf("expected error executing unknown command %q, got nil", cmdName)
		}
	})
}

// BenchmarkCLIParseAndExecute measures throughput of CLI argument dispatch.
func BenchmarkCLIParseAndExecute(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	origExit := engine.SetOSExit(func(code int) {})
	defer engine.SetOSExit(origExit)

	args := []string{"health", "--url", server.URL, "--token", "tok", "--output", "json"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmd := engine.BuildManagementRoot()
		cmd.SetArgs(args)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		cmd.SilenceErrors = true
		_ = cmd.ExecuteContext(context.Background())
	}
}

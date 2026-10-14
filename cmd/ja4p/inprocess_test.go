package main

import (
	"bytes"
	"testing"
)

func TestInProcessRootCmd(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)

	cmd.SetArgs([]string{"--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("help failed: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("Available Commands")) {
		t.Errorf("unexpected help output: %s", buf.String())
	}

	cmd = NewRootCmd()
	buf.Reset()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("version failed: %v", err)
	}

	cmd = NewRootCmd()
	buf.Reset()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"completion", "bash"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("completion failed: %v", err)
	}

	cmd = NewRootCmd()
	buf.Reset()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"backup", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("backup help failed: %v", err)
	}

	cmd = NewRootCmd()
	buf.Reset()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"restore", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("restore help failed: %v", err)
	}

	cmd = NewRootCmd()
	buf.Reset()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"cluster", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("cluster help failed: %v", err)
	}

	// Test validate subcommand
	cmd = NewRootCmd()
	buf.Reset()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"validate", "config/proxy.yml"})
	_ = cmd.Execute()

	// Test test ip subcommand
	cmd = NewRootCmd()
	buf.Reset()
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"test", "ip", "192.0.2.1"})
	_ = cmd.Execute()

	// Test resolvePassphrase helper
	if p, err := resolvePassphrase("", "direct-key"); err != nil || p != "direct-key" {
		t.Errorf("resolvePassphrase failed: %v, %s", err, p)
	}

	// Test sortedKeys helper
	counts := map[string]int{"b": 2, "a": 1, "c": 3}
	keys := sortedKeys(counts)
	if len(keys) != 3 || keys[0] != "a" || keys[1] != "b" || keys[2] != "c" {
		t.Errorf("sortedKeys incorrect: %v", keys)
	}
}

package commands_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/anomalyco/ja4proxy/internal/cli/commands"
)

// validMinimalPolicy is a known-good policy YAML that passes all validation rules.
const validMinimalPolicy = `meta:
  version: "1.0"
  environment: prod
  last_updated: "2026-04-01T00:00:00Z"
  last_updated_by: "ops@example.com"
dial:
  setting: 10
  changed_by: "ops@example.com"
`

// invalidSyntaxPolicy uses a tab indent which is illegal in YAML.
const invalidSyntaxPolicy = "meta:\n\tversion: '1.0'\n"

// invalidDialPolicy has a dial setting above 100.
const invalidDialPolicy = `meta:
  version: "1.0"
  environment: prod
  last_updated: "2026-04-01T00:00:00Z"
  last_updated_by: "ops@example.com"
dial:
  setting: 150
  changed_by: "ops@example.com"
`

// unknownFieldPolicy has an unrecognised top-level key.
const unknownFieldPolicy = validMinimalPolicy + "\nrogue_key:\n  value: true\n"

// invalidJA4Policy has a malformed JA4 fingerprint in the allowlist.
const invalidJA4Policy = validMinimalPolicy + `
allowlist:
  fingerprints:
    - ja4: "bad_fingerprint"
      reason: "test"
      added_by: "ops@example.com"
`

// TestPolicyValidate_ValidYAML verifies that known-good YAML passes without error.
func TestPolicyValidate_ValidYAML(t *testing.T) {
	err := commands.RunPolicyValidate(validMinimalPolicy, 0)
	if err != nil {
		t.Errorf("expected nil error for valid policy, got: %v", err)
	}
}

// TestPolicyValidate_InvalidYAML verifies that a tab-indented YAML file returns
// a PolicyValidationError.
func TestPolicyValidate_InvalidYAML(t *testing.T) {
	err := commands.RunPolicyValidate(invalidSyntaxPolicy, 0)
	if err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}

	var syntaxErr *commands.PolicySyntaxError
	if !errors.As(err, &syntaxErr) {
		t.Errorf("expected *commands.PolicySyntaxError, got %T: %v", err, err)
	}
}

// TestPolicyValidate_InvalidDial verifies that dial=150 is rejected with an
// error mentioning "dial".
func TestPolicyValidate_InvalidDial(t *testing.T) {
	err := commands.RunPolicyValidate(invalidDialPolicy, 0)
	if err == nil {
		t.Fatal("expected error for dial=150, got nil")
	}

	if !strings.Contains(strings.ToLower(err.Error()), "dial") {
		t.Errorf("error %q does not mention 'dial'", err.Error())
	}
}

// TestPolicyValidate_UnknownField verifies that unknown top-level keys are rejected.
func TestPolicyValidate_UnknownField(t *testing.T) {
	err := commands.RunPolicyValidate(unknownFieldPolicy, 0)
	if err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
}

// TestPolicyValidate_InvalidJA4 verifies that a malformed JA4 fingerprint in
// the allowlist is rejected.
func TestPolicyValidate_InvalidJA4(t *testing.T) {
	err := commands.RunPolicyValidate(invalidJA4Policy, 0)
	if err == nil {
		t.Fatal("expected error for invalid JA4 fingerprint, got nil")
	}
}

// TestPolicyValidate_ValidWithExistingDial verifies that a dial setting that
// would be a valid increment from a current_dial passes.
func TestPolicyValidate_ValidWithExistingDial(t *testing.T) {
	// dial=10, current=0 → delta=10 which should be allowed
	err := commands.RunPolicyValidate(validMinimalPolicy, 0)
	if err != nil {
		t.Errorf("expected nil for valid dial increment, got: %v", err)
	}
}

// TestPolicyValidate_TableDriven runs multiple valid/invalid cases together.
func TestPolicyValidate_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		yaml        string
		currentDial int
		wantErr     bool
	}{
		{"valid_minimal", validMinimalPolicy, 0, false},
		{"invalid_syntax", invalidSyntaxPolicy, 0, true},
		{"invalid_dial", invalidDialPolicy, 0, true},
		{"unknown_field", unknownFieldPolicy, 0, true},
		{"invalid_ja4", invalidJA4Policy, 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := commands.RunPolicyValidate(tc.yaml, tc.currentDial)
			if tc.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error, got: %v", err)
			}
		})
	}
}

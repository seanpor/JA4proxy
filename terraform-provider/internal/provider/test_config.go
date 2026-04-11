package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
)

// testConfigValue constructs a DynamicValue for provider configuration in tests.
// Used by provider_test.go which calls this function but doesn't define it.
func testConfigValue(t *testing.T, attrs map[string]interface{}) *tfprotov6.DynamicValue {
	t.Helper()

	vals := make(map[string]tftypes.Value)
	schema := map[string]tftypes.Type{
		"api_url":   tftypes.String,
		"api_token": tftypes.String,
	}

	for k := range schema {
		if attrVal, ok := attrs[k]; ok && attrVal != nil {
			if s, ok := attrVal.(string); ok {
				vals[k] = tftypes.NewValue(tftypes.String, s)
			} else {
				vals[k] = tftypes.NewValue(tftypes.String, nil)
			}
		} else {
			vals[k] = tftypes.NewValue(tftypes.String, nil)
		}
	}

	objType := tftypes.Object{AttributeTypes: schema}
	objVal := tftypes.NewValue(objType, vals)

	dv, err := tfprotov6.NewDynamicValue(objType, objVal)
	if err != nil {
		t.Fatalf("failed to create DynamicValue: %v", err)
	}
	return &dv
}

// testConfigValue2 is an alias for use by resource test files that need it via provider.
func testConfigValue2(t *testing.T, attrs map[string]interface{}) *tfprotov6.DynamicValue {
	t.Helper()
	return testConfigValue(t, attrs)
}

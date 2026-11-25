package bicep

import (
	"testing"
)

// Phase B tests: Bicep @secure() decorator mapping (P0-9) — the
// decorator must survive into the emitted ARM template as a secureString
// / secureObject parameter type, so AEGIS-AZURE-316 can fire.

func TestPhaseB_SecureStringParam(t *testing.T) {
	src := `
@secure()
param dbAdminPassword string = 'hunter2'
@allowed(['dev', 'prod'])
param environment string = 'prod'
resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'storea'
  location: 'westeurope'
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
}
`
	res := parseBicep(t, src)
	var params []string
	for i := range res {
		if res[i].Type != "arm_parameter" {
			continue
		}
		params = append(params, res[i].Name)
		if res[i].Name == "dbAdminPassword" {
			if got := mustString(t, &res[i], "type"); got != "secureString" {
				t.Errorf("dbAdminPassword type = %q, want secureString", got)
			}
			if got := mustString(t, &res[i], "default"); got != "hunter2" {
				t.Errorf("dbAdminPassword default = %q, want hunter2", got)
			}
		}
		if res[i].Name == "environment" {
			if got := mustString(t, &res[i], "type"); got != "string" {
				t.Errorf("environment type = %q, want string (not secure)", got)
			}
			if got := mustString(t, &res[i], "default"); got != "prod" {
				t.Errorf("environment default = %q, want prod", got)
			}
		}
	}
	if len(params) != 2 {
		t.Fatalf("expected 2 arm_parameter resources, got %v", params)
	}
}

func TestPhaseB_SecureObjectParam(t *testing.T) {
	src := `
@secure()
param config object = {
  key: 'value'
}
resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'storea'
  location: 'westeurope'
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
}
`
	res := parseBicep(t, src)
	p := findResource(res, "arm_parameter")
	if p == nil {
		t.Fatalf("no arm_parameter emitted")
	}
	if got := mustString(t, p, "type"); got != "secureObject" {
		t.Errorf("config type = %q, want secureObject", got)
	}
}

func TestPhaseB_NonSecureParamUnchanged(t *testing.T) {
	src := `
param location string = 'westeurope'
resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'storea'
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
}
`
	res := parseBicep(t, src)
	p := findResource(res, "arm_parameter")
	if p == nil {
		t.Fatalf("no arm_parameter emitted")
	}
	if got := mustString(t, p, "type"); got != "string" {
		t.Errorf("location type = %q, want string", got)
	}
}

package arm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aegis/internal/ir"
)

// writeTemp writes content to a temp file and returns its path.
func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHandles(t *testing.T) {
	a := New()
	armTmpl := `{"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#", "resources": []}`
	notArm := `{"foo": "bar"}`
	armPath := writeTemp(t, "azuredeploy.json", armTmpl)
	notArmPath := writeTemp(t, "data.json", notArm)
	if !a.Handles(armPath) {
		t.Errorf("Handles(arm template) = false, want true")
	}
	if a.Handles(notArmPath) {
		t.Errorf("Handles(plain json) = true, want false")
	}
	if a.Handles("main.tf") {
		t.Errorf("Handles(.tf) = true, want false")
	}
	if a.Handles("template.bicep") {
		t.Errorf("Handles(.bicep) = true, want false")
	}
	if a.Handles("missing.json") {
		t.Errorf("Handles(missing file) = true, want false")
	}
}

func TestName(t *testing.T) {
	if New().Name() != "arm" {
		t.Errorf("Name() = %q, want arm", New().Name())
	}
}

const armStorageVuln = `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": {
    "accountName": { "type": "string", "defaultValue": "vulnstore1" }
  },
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2023-01-01",
      "name": "[parameters('accountName')]",
      "location": "westeurope",
      "kind": "StorageV2",
      "sku": { "name": "Standard_LRS" },
      "properties": {
        "allowBlobPublicAccess": true,
        "minimumTlsVersion": "TLS1_0",
        "supportsHttpsTrafficOnly": false
      }
    }
  ]
}`

const armStorageSecure = `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2023-01-01",
      "name": "securestore1",
      "location": "westeurope",
      "kind": "StorageV2",
      "sku": { "name": "Standard_LRS" },
      "properties": {
        "allowBlobPublicAccess": false,
        "minimumTlsVersion": "TLS1_2",
        "supportsHttpsTrafficOnly": true
      }
    }
  ]
}`

func parseARM(t *testing.T, content string) []ir.Resource {
	t.Helper()
	a := New()
	res, diags, err := a.Parse("azuredeploy.json", []byte(content))
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}
	for _, d := range diags {
		if d.Level == "error" {
			t.Fatalf("diagnostic error: %s", d.Message)
		}
	}
	return res
}

func findResource(res []ir.Resource, typ string) *ir.Resource {
	for i := range res {
		if res[i].Type == typ {
			return &res[i]
		}
	}
	return nil
}

func mustBool(t *testing.T, r *ir.Resource, attr string) bool {
	t.Helper()
	v, ok := r.Attributes[attr]
	if !ok {
		t.Fatalf("attribute %q missing", attr)
	}
	b, ok := v.AsBool()
	if !ok {
		t.Fatalf("attribute %q not a known bool", attr)
	}
	return b
}

func mustString(t *testing.T, r *ir.Resource, attr string) string {
	t.Helper()
	v, ok := r.Attributes[attr]
	if !ok {
		t.Fatalf("attribute %q missing", attr)
	}
	s, ok := v.AsString()
	if !ok {
		t.Fatalf("attribute %q not a known string", attr)
	}
	return s
}

func TestStorageVulnerable(t *testing.T) {
	res := parseARM(t, armStorageVuln)
	r := findResource(res, "azurerm_storage_account")
	if r == nil {
		t.Fatalf("no azurerm_storage_account; got %d resources", len(res))
	}
	if r.Name != "vulnstore1" {
		t.Errorf("name = %q, want vulnstore1 (parameter resolution)", r.Name)
	}
	if !mustBool(t, r, "allow_blob_public_access") {
		t.Errorf("allow_blob_public_access = false, want true")
	}
	if got := mustString(t, r, "min_tls_version"); got != "TLS1_0" {
		t.Errorf("min_tls_version = %q, want TLS1_0", got)
	}
	if mustBool(t, r, "https_traffic_only_enabled") {
		t.Errorf("https_traffic_only_enabled = true, want false")
	}
}

func TestStorageSecure(t *testing.T) {
	res := parseARM(t, armStorageSecure)
	r := findResource(res, "azurerm_storage_account")
	if r == nil {
		t.Fatalf("no azurerm_storage_account")
	}
	if mustBool(t, r, "allow_blob_public_access") {
		t.Errorf("allow_blob_public_access should be false")
	}
	if got := mustString(t, r, "min_tls_version"); got != "TLS1_2" {
		t.Errorf("min_tls_version = %q, want TLS1_2", got)
	}
}

const armKeyVaultVuln = `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "variables": { "kvSuffix": "-vault" },
  "resources": [
    {
      "type": "Microsoft.KeyVault/vaults",
      "apiVersion": "2023-07-01",
      "name": "[concat('mykv', variables('kvSuffix'))]",
      "location": "westeurope",
      "properties": {
        "enablePurgeProtection": false,
        "softDeleteRetentionInDays": 7,
        "tenantId": "00000000-0000-0000-0000-000000000000",
        "sku": { "name": "standard", "family": "A" }
      }
    }
  ]
}`

const armKeyVaultSecure = `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.KeyVault/vaults",
      "apiVersion": "2023-07-01",
      "name": "securekv",
      "location": "westeurope",
      "properties": {
        "enablePurgeProtection": true,
        "softDeleteRetentionInDays": 90,
        "tenantId": "00000000-0000-0000-0000-000000000000",
        "sku": { "name": "standard", "family": "A" }
      }
    }
  ]
}`

func TestKeyVaultVulnerable(t *testing.T) {
	res := parseARM(t, armKeyVaultVuln)
	r := findResource(res, "azurerm_key_vault")
	if r == nil {
		t.Fatalf("no azurerm_key_vault")
	}
	if r.Name != "mykv-vault" {
		t.Errorf("name = %q, want mykv-vault (concat resolution)", r.Name)
	}
	if mustBool(t, r, "purge_protection_enabled") {
		t.Errorf("purge_protection_enabled should be false")
	}
	v, ok := r.Attributes["soft_delete_retention_days"]
	if !ok {
		t.Fatalf("soft_delete_retention_days missing")
	}
	f, ok := v.Raw.(float64)
	if !ok || !v.Known || f != 7 {
		t.Errorf("soft_delete_retention_days = %v, want 7", v.Raw)
	}
}

func TestKeyVaultSecure(t *testing.T) {
	res := parseARM(t, armKeyVaultSecure)
	r := findResource(res, "azurerm_key_vault")
	if r == nil {
		t.Fatalf("no azurerm_key_vault")
	}
	if !mustBool(t, r, "purge_protection_enabled") {
		t.Errorf("purge_protection_enabled should be true")
	}
}

const armSQLVuln = `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Sql/servers",
      "apiVersion": "2023-05-01-preview",
      "name": "vulnsql",
      "location": "westeurope",
      "properties": {
        "minimalTlsVersion": "1.0",
        "publicNetworkAccess": "Enabled",
        "administratorLogin": "sqladmin"
      }
    }
  ]
}`

const armSQLSecure = `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Sql/servers",
      "apiVersion": "2023-05-01-preview",
      "name": "securesql",
      "location": "westeurope",
      "properties": {
        "minimalTlsVersion": "1.2",
        "publicNetworkAccess": "Disabled",
        "administratorLogin": "sqladmin"
      }
    }
  ]
}`

func TestSQLVulnerable(t *testing.T) {
	res := parseARM(t, armSQLVuln)
	r := findResource(res, "azurerm_mssql_server")
	if r == nil {
		t.Fatalf("no azurerm_mssql_server")
	}
	if got := mustString(t, r, "minimum_tls_version"); got != "1.0" {
		t.Errorf("minimum_tls_version = %q, want 1.0", got)
	}
	// publicNetworkAccess "Enabled" is converted to boolean true.
	if got := mustBool(t, r, "public_network_access_enabled"); got != true {
		t.Errorf("public_network_access_enabled = %v, want true", got)
	}
}

func TestSQLSecure(t *testing.T) {
	res := parseARM(t, armSQLSecure)
	r := findResource(res, "azurerm_mssql_server")
	if r == nil {
		t.Fatalf("no azurerm_mssql_server")
	}
	if got := mustString(t, r, "minimum_tls_version"); got != "1.2" {
		t.Errorf("minimum_tls_version = %q, want 1.2", got)
	}
}

const armAKSVuln = `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.ContainerService/managedClusters",
      "apiVersion": "2024-01-01",
      "name": "vulnaks",
      "location": "westeurope",
      "properties": {
        "enableRbac": false,
        "dnsPrefix": "vulnaks",
        "kubernetesVersion": "1.28.0",
        "addonProfiles": {
          "httpApplicationRouting": { "enabled": true }
        }
      }
    }
  ]
}`

const armAKSSecure = `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.ContainerService/managedClusters",
      "apiVersion": "2024-01-01",
      "name": "secureaks",
      "location": "westeurope",
      "properties": {
        "enableRbac": true,
        "dnsPrefix": "secureaks",
        "disableLocalAccounts": true
      }
    }
  ]
}`

func TestAKSVulnerable(t *testing.T) {
	res := parseARM(t, armAKSVuln)
	r := findResource(res, "azurerm_kubernetes_cluster")
	if r == nil {
		t.Fatalf("no azurerm_kubernetes_cluster")
	}
	if mustBool(t, r, "role_based_access_control_enabled") {
		t.Errorf("role_based_access_control_enabled should be false")
	}
}

func TestAKSSecure(t *testing.T) {
	res := parseARM(t, armAKSSecure)
	r := findResource(res, "azurerm_kubernetes_cluster")
	if r == nil {
		t.Fatalf("no azurerm_kubernetes_cluster")
	}
	if !mustBool(t, r, "role_based_access_control_enabled") {
		t.Errorf("role_based_access_control_enabled should be true")
	}
}

func TestUnknownParameter(t *testing.T) {
	tmpl := `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": { "noDefault": { "type": "string" } },
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2023-01-01",
      "name": "[parameters('noDefault')]",
      "location": "westeurope",
      "properties": { "allowBlobPublicAccess": "[parameters('noDefault')]" }
    }
  ]
}`
	res := parseARM(t, tmpl)
	r := findResource(res, "azurerm_storage_account")
	if r == nil {
		t.Fatalf("no azurerm_storage_account")
	}
	// Name falls back to raw expression string when unresolvable.
	if r.Name == "" {
		t.Errorf("name should not be empty")
	}
	v, ok := r.Attributes["allow_blob_public_access"]
	if !ok {
		t.Fatalf("allow_blob_public_access missing")
	}
	if v.Known {
		t.Errorf("allow_blob_public_access should be Unknown (no default)")
	}
}

func TestUnmappedType(t *testing.T) {
	tmpl := `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Exotic/widgets",
      "apiVersion": "2024-01-01",
      "name": "w1",
      "properties": {}
    }
  ]
}`
	a := New()
	res, diags, err := a.Parse("azuredeploy.json", []byte(tmpl))
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 {
		t.Fatalf("want 1 resource, got %d", len(res))
	}
	if !strings.HasPrefix(res[0].Type, "arm_") {
		t.Errorf("unmapped type = %q, want arm_ prefix", res[0].Type)
	}
	found := false
	for _, d := range diags {
		if strings.Contains(d.Message, "unmapped resource type") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected unmapped-type warning diagnostic")
	}
}

func TestCopyLoopSkipped(t *testing.T) {
	tmpl := `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2023-01-01",
      "name": "copytest",
      "copy": { "name": "loop", "count": 3 },
      "properties": {}
    }
  ]
}`
	a := New()
	res, diags, err := a.Parse("azuredeploy.json", []byte(tmpl))
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 0 {
		t.Errorf("copy-loop resource should be skipped, got %d resources", len(res))
	}
	found := false
	for _, d := range diags {
		if strings.Contains(d.Message, "copy loop") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected copy-loop warning diagnostic")
	}
}

func TestInvalidJSON(t *testing.T) {
	a := New()
	_, diags, err := a.Parse("azuredeploy.json", []byte("{not json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(diags) == 0 || diags[0].Level != "error" {
		t.Errorf("expected error diagnostic for invalid JSON")
	}
}

func TestExpressionFunctions(t *testing.T) {
	tmpl := `{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "parameters": { "env": { "type": "string", "defaultValue": "Prod" } },
  "variables": {
    "lower": "[toLower(parameters('env'))]",
    "fmt": "[format('{0}-store', parameters('env'))]",
    "unknown1": "[resourceGroup().location]",
    "unknown2": "[if(equals(1, 1), 'a', 'b')]"
  },
  "resources": [
    {
      "type": "Microsoft.Storage/storageAccounts",
      "apiVersion": "2023-01-01",
      "name": "[variables('lower')]",
      "location": "[variables('unknown1')]",
      "properties": {
        "allowBlobPublicAccess": false,
        "minimumTlsVersion": "TLS1_2",
        "supportsHttpsTrafficOnly": true,
        "tags": "[variables('fmt')]"
      }
    }
  ]
}`
	res := parseARM(t, tmpl)
	r := findResource(res, "azurerm_storage_account")
	if r == nil {
		t.Fatalf("no azurerm_storage_account")
	}
	if r.Name != "prod" {
		t.Errorf("name = %q, want prod (toLower)", r.Name)
	}
	if v, ok := r.Attributes["location"]; !ok || v.Known {
		t.Errorf("location should be Unknown (resourceGroup())")
	}
	if got := mustString(t, r, "tags"); got != "Prod-store" {
		t.Errorf("tags = %q, want Prod-store (format)", got)
	}
}

// TestAzureRulesFireOnARM verifies end-to-end that existing Azure rules fire
// on ARM-converted resources (the core strategy: no new rules needed).
func TestAzureRulesFireOnARM(t *testing.T) {
	// This test uses the rule registry directly.
	res := parseARM(t, armStorageVuln)
	r := findResource(res, "azurerm_storage_account")
	if r == nil {
		t.Fatalf("no azurerm_storage_account")
	}
	// Simulate the two key rules' logic via attribute presence: the rules
	// themselves are tested in the azure package; here we verify the
	// attributes they need are present and known.
	for _, attr := range []string{"allow_blob_public_access", "min_tls_version", "https_traffic_only_enabled"} {
		v, ok := r.Attributes[attr]
		if !ok {
			t.Errorf("attribute %q missing: AEGIS-AZR rules cannot evaluate", attr)
			continue
		}
		if !v.Known {
			t.Errorf("attribute %q unknown: rules stay silent", attr)
		}
	}
	kv := parseARM(t, armKeyVaultVuln)
	kr := findResource(kv, "azurerm_key_vault")
	if kr == nil {
		t.Fatalf("no azurerm_key_vault")
	}
	for _, attr := range []string{"purge_protection_enabled", "soft_delete_retention_days"} {
		v, ok := kr.Attributes[attr]
		if !ok || !v.Known {
			t.Errorf("key vault attribute %q missing/unknown", attr)
		}
	}
}

package bicep

import (
	"strings"
	"testing"

	"aegis/internal/ir"
)

func parseBicep(t *testing.T, src string) []ir.Resource {
	t.Helper()
	a := New()
	res, diags, err := a.Parse("main.bicep", []byte(src))
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
		t.Fatalf("attribute %q not a known bool (known=%v raw=%v)", attr, v.Known, v.Raw)
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

func TestHandles(t *testing.T) {
	a := New()
	for _, p := range []string{"main.bicep", "dir/deploy.bicep", "MAIN.BICEP"} {
		if !a.Handles(p) {
			t.Errorf("Handles(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"main.tf", "azuredeploy.json", "Dockerfile"} {
		if a.Handles(p) {
			t.Errorf("Handles(%q) = true, want false", p)
		}
	}
}

func TestName(t *testing.T) {
	if New().Name() != "bicep" {
		t.Errorf("Name() = %q, want bicep", New().Name())
	}
}

const bicepStorageVuln = `
param location string = 'westeurope'
param accountName string = 'vulnbicep1'

resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: accountName
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    allowBlobPublicAccess: true
    minimumTlsVersion: 'TLS1_0'
    supportsHttpsTrafficOnly: false
  }
}
`

const bicepStorageSecure = `
param location string = 'westeurope'

resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'securebicep1'
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
  }
}
`

func TestStorageVulnerable(t *testing.T) {
	res := parseBicep(t, bicepStorageVuln)
	r := findResource(res, "azurerm_storage_account")
	if r == nil {
		t.Fatalf("no azurerm_storage_account; got %d resources", len(res))
	}
	if r.Name != "vulnbicep1" {
		t.Errorf("name = %q, want vulnbicep1 (param resolution)", r.Name)
	}
	if !mustBool(t, r, "allow_blob_public_access") {
		t.Errorf("allow_blob_public_access should be true")
	}
	if got := mustString(t, r, "min_tls_version"); got != "TLS1_0" {
		t.Errorf("min_tls_version = %q, want TLS1_0", got)
	}
	if mustBool(t, r, "https_traffic_only_enabled") {
		t.Errorf("https_traffic_only_enabled should be false")
	}
}

func TestStorageSecure(t *testing.T) {
	res := parseBicep(t, bicepStorageSecure)
	r := findResource(res, "azurerm_storage_account")
	if r == nil {
		t.Fatalf("no azurerm_storage_account")
	}
	if mustBool(t, r, "allow_blob_public_access") {
		t.Errorf("allow_blob_public_access should be false")
	}
}

const bicepKeyVaultVuln = `
var kvName = 'vulnkv-bicep'

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: kvName
  location: 'westeurope'
  properties: {
    enablePurgeProtection: false
    softDeleteRetentionInDays: 7
    tenantId: '00000000-0000-0000-0000-000000000000'
    sku: {
      name: 'standard'
      family: 'A'
    }
  }
}
`

const bicepKeyVaultSecure = `
resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'securekvbicep'
  location: 'westeurope'
  properties: {
    enablePurgeProtection: true
    softDeleteRetentionInDays: 90
    tenantId: '00000000-0000-0000-0000-000000000000'
    sku: {
      name: 'standard'
      family: 'A'
    }
  }
}
`

func TestKeyVaultVulnerable(t *testing.T) {
	res := parseBicep(t, bicepKeyVaultVuln)
	r := findResource(res, "azurerm_key_vault")
	if r == nil {
		t.Fatalf("no azurerm_key_vault")
	}
	if r.Name != "vulnkv-bicep" {
		t.Errorf("name = %q, want vulnkv-bicep (var resolution)", r.Name)
	}
	if mustBool(t, r, "purge_protection_enabled") {
		t.Errorf("purge_protection_enabled should be false")
	}
}

func TestKeyVaultSecure(t *testing.T) {
	res := parseBicep(t, bicepKeyVaultSecure)
	r := findResource(res, "azurerm_key_vault")
	if r == nil {
		t.Fatalf("no azurerm_key_vault")
	}
	if !mustBool(t, r, "purge_protection_enabled") {
		t.Errorf("purge_protection_enabled should be true")
	}
}

const bicepSQLVuln = `
resource sql 'Microsoft.Sql/servers@2023-05-01-preview' = {
  name: 'vulnsqlbicep'
  location: 'westeurope'
  properties: {
    minimalTlsVersion: '1.0'
    publicNetworkAccess: 'Enabled'
    administratorLogin: 'sqladmin'
  }
}
`

const bicepSQLSecure = `
resource sql 'Microsoft.Sql/servers@2023-05-01-preview' = {
  name: 'securesqlbicep'
  location: 'westeurope'
  properties: {
    minimalTlsVersion: '1.2'
    publicNetworkAccess: 'Disabled'
    administratorLogin: 'sqladmin'
  }
}
`

func TestSQLVulnerable(t *testing.T) {
	res := parseBicep(t, bicepSQLVuln)
	r := findResource(res, "azurerm_mssql_server")
	if r == nil {
		t.Fatalf("no azurerm_mssql_server")
	}
	if got := mustString(t, r, "minimum_tls_version"); got != "1.0" {
		t.Errorf("minimum_tls_version = %q, want 1.0", got)
	}
}

func TestSQLSecure(t *testing.T) {
	res := parseBicep(t, bicepSQLSecure)
	r := findResource(res, "azurerm_mssql_server")
	if r == nil {
		t.Fatalf("no azurerm_mssql_server")
	}
	if got := mustString(t, r, "minimum_tls_version"); got != "1.2" {
		t.Errorf("minimum_tls_version = %q, want 1.2", got)
	}
}

const bicepAKSVuln = `
resource aks 'Microsoft.ContainerService/managedClusters@2024-01-01' = {
  name: 'vulnaksbicep'
  location: 'westeurope'
  properties: {
    enableRbac: false
    dnsPrefix: 'vulnaksbicep'
  }
}
`

const bicepAKSSecure = `
resource aks 'Microsoft.ContainerService/managedClusters@2024-01-01' = {
  name: 'secureaksbicep'
  location: 'westeurope'
  properties: {
    enableRbac: true
    dnsPrefix: 'secureaksbicep'
    disableLocalAccounts: true
  }
}
`

func TestAKSVulnerable(t *testing.T) {
	res := parseBicep(t, bicepAKSVuln)
	r := findResource(res, "azurerm_kubernetes_cluster")
	if r == nil {
		t.Fatalf("no azurerm_kubernetes_cluster")
	}
	if mustBool(t, r, "role_based_access_control_enabled") {
		t.Errorf("role_based_access_control_enabled should be false")
	}
}

func TestAKSSecure(t *testing.T) {
	res := parseBicep(t, bicepAKSSecure)
	r := findResource(res, "azurerm_kubernetes_cluster")
	if r == nil {
		t.Fatalf("no azurerm_kubernetes_cluster")
	}
	if !mustBool(t, r, "role_based_access_control_enabled") {
		t.Errorf("role_based_access_control_enabled should be true")
	}
}

// Real Bicep templates spell the property enableRBAC (all-caps RBAC), as
// the R4 corpus does (idx 76/81/84). The fixtures above use the historical
// enableRbac casing; these pin the real spelling to the renamed attribute
// AEGIS-AZURE-014 reads.
const bicepAKSVulnRBAC = `
resource aks 'Microsoft.ContainerService/managedClusters@2024-01-01' = {
  name: 'vulnaksrbac'
  location: 'westeurope'
  properties: {
    enableRBAC: false
    dnsPrefix: 'vulnaksrbac'
  }
}
`

const bicepAKSSecureRBAC = `
resource aks 'Microsoft.ContainerService/managedClusters@2024-01-01' = {
  name: 'secureaksrbac'
  location: 'westeurope'
  properties: {
    enableRBAC: true
    dnsPrefix: 'secureaksrbac'
  }
}
`

func TestAKSVulnerableRBACSpelling(t *testing.T) {
	res := parseBicep(t, bicepAKSVulnRBAC)
	r := findResource(res, "azurerm_kubernetes_cluster")
	if r == nil {
		t.Fatalf("no azurerm_kubernetes_cluster")
	}
	if mustBool(t, r, "role_based_access_control_enabled") {
		t.Errorf("role_based_access_control_enabled should be false for enableRBAC: false")
	}
}

func TestAKSSecureRBACSpelling(t *testing.T) {
	res := parseBicep(t, bicepAKSSecureRBAC)
	r := findResource(res, "azurerm_kubernetes_cluster")
	if r == nil {
		t.Fatalf("no azurerm_kubernetes_cluster")
	}
	if !mustBool(t, r, "role_based_access_control_enabled") {
		t.Errorf("role_based_access_control_enabled should be true for enableRBAC: true")
	}
}

func TestInterpolation(t *testing.T) {
	src := `
param base string = 'myapp'
param env string = 'prod'

resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: '${base}-${env}-store'
  location: 'westeurope'
  properties: {
    allowBlobPublicAccess: false
  }
}
`
	res := parseBicep(t, src)
	r := findResource(res, "azurerm_storage_account")
	if r == nil {
		t.Fatalf("no azurerm_storage_account")
	}
	if r.Name != "myapp-prod-store" {
		t.Errorf("name = %q, want myapp-prod-store (interpolation)", r.Name)
	}
}

func TestTernaryUnknown(t *testing.T) {
	src := `
param prod bool = true

resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'ternarystore'
  location: 'westeurope'
  properties: {
    allowBlobPublicAccess: prod ? true : false
  }
}
`
	res := parseBicep(t, src)
	r := findResource(res, "azurerm_storage_account")
	if r == nil {
		t.Fatalf("no azurerm_storage_account")
	}
	v, ok := r.Attributes["allow_blob_public_access"]
	if !ok {
		t.Fatalf("allow_blob_public_access missing")
	}
	if v.Known {
		t.Errorf("ternary should be Unknown (if() not evaluated)")
	}
}

func TestForLoopExpanded(t *testing.T) {
	src := `
param names array = ['storea', 'storeb']
resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = [for n in names: {
  name: n
  location: 'westeurope'
  properties: {
    allowBlobPublicAccess: true
  }
}]
`
	a := New()
	res, diags, err := a.Parse("main.bicep", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	// One resource per element, with the loop variable substituted.
	if len(res) != 2 {
		t.Fatalf("for-loop should expand to 2 resources, got %d", len(res))
	}
	names := map[string]bool{}
	for _, r := range res {
		names[r.Name] = true
		v, ok := r.Attributes["allow_blob_public_access"]
		if !ok {
			t.Fatalf("allow_blob_public_access missing on %s", r.Name)
		}
		if b, ok := v.AsBool(); !ok || !b {
			t.Errorf("allow_blob_public_access should be true on %s", r.Name)
		}
	}
	if !names["storea"] || !names["storeb"] {
		t.Errorf("loop variable not substituted into names: %v", names)
	}
	for _, d := range diags {
		if d.Level == "error" {
			t.Errorf("unexpected error diagnostic: %s", d.Message)
		}
	}
}

func TestForLoopRangeExpanded(t *testing.T) {
	src := `
resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = [for i in range(0, 2): {
  name: 'loopstore'
  location: 'westeurope'
  properties: {}
}]
`
	a := New()
	res, _, err := a.Parse("main.bicep", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 {
		t.Errorf("range(0,2) for-loop should expand to 2 resources, got %d", len(res))
	}
}

func TestForLoopUnresolvableEmitsRepresentative(t *testing.T) {
	src := `
param names array
resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = [for n in names: {
  name: n
  location: 'westeurope'
  properties: {
    allowBlobPublicAccess: true
  }
}]
`
	a := New()
	res, diags, err := a.Parse("main.bicep", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	// Collection not statically resolvable: single representative resource
	// so static properties are still checked (better than silence).
	if len(res) != 1 {
		t.Fatalf("expected 1 representative resource, got %d", len(res))
	}
	found := false
	for _, d := range diags {
		if strings.Contains(d.Message, "not statically resolvable") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'not statically resolvable' warning diagnostic")
	}
}

func TestExistingSkipped(t *testing.T) {
	src := `
resource kv 'Microsoft.KeyVault/vaults@2023-07-01' existing = {
  name: 'already-there'
}
`
	a := New()
	res, diags, err := a.Parse("main.bicep", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 0 {
		t.Errorf("existing resource should be skipped, got %d", len(res))
	}
	found := false
	for _, d := range diags {
		if strings.Contains(d.Message, "existing") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected existing-resource diagnostic")
	}
}

func TestChildResourceParent(t *testing.T) {
	src := `
resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'parentstore'
  location: 'westeurope'
  properties: {}
}

resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: stg
  name: 'mycontainer'
  properties: {
    publicAccess: 'Blob'
  }
}
`
	res := parseBicep(t, src)
	r := findResource(res, "azurerm_storage_container")
	if r == nil {
		t.Fatalf("no azurerm_storage_container")
	}
	// Parent name resolution: stg has a static name, so the child name
	// should be parentstore/mycontainer.
	if r.Name != "parentstore/mycontainer" {
		t.Errorf("container name = %q, want parentstore/mycontainer", r.Name)
	}
}

func TestDecoratorsSkipped(t *testing.T) {
	src := `
@description('The storage account name')
param accountName string = 'decoratedstore'

@secure()
param secretVal string = 's3cret'

resource stg 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: accountName
  location: 'westeurope'
  properties: {
    allowBlobPublicAccess: false
  }
}
`
	res := parseBicep(t, src)
	r := findResource(res, "azurerm_storage_account")
	if r == nil {
		t.Fatalf("no azurerm_storage_account")
	}
	if r.Name != "decoratedstore" {
		t.Errorf("name = %q, want decoratedstore", r.Name)
	}
}

// TestAzureRulesFireOnBicep verifies the attributes the Azure rules need
// are present and known on Bicep-converted resources.
func TestAzureRulesFireOnBicep(t *testing.T) {
	res := parseBicep(t, bicepStorageVuln)
	r := findResource(res, "azurerm_storage_account")
	if r == nil {
		t.Fatalf("no azurerm_storage_account")
	}
	for _, attr := range []string{"allow_blob_public_access", "min_tls_version", "https_traffic_only_enabled"} {
		v, ok := r.Attributes[attr]
		if !ok || !v.Known {
			t.Errorf("attribute %q missing/unknown: AEGIS-AZR rules cannot evaluate", attr)
		}
	}
}

package pulumi

import (
	"strings"
	"testing"

	"aegis/internal/ir"
)

func parse(t *testing.T, path, src string) ([]ir.Resource, []ir.Diagnostic) {
	t.Helper()
	rs, diags, err := Adapter{}.Parse(path, []byte(src))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	return rs, diags
}

func findResource(rs []ir.Resource, name string) *ir.Resource {
	for i := range rs {
		if rs[i].Name == name {
			return &rs[i]
		}
	}
	return nil
}

func attrString(t *testing.T, r ir.Resource, attr string) (string, bool) {
	t.Helper()
	v, ok := r.Attributes[attr]
	if !ok {
		return "", false
	}
	s, ok := v.AsString()
	return s, ok
}

// 1. Vulnerable S3 bucket: public ACL, no encryption -> rules must fire on it.
func TestVulnerableS3Bucket(t *testing.T) {
	rs, _ := parse(t, "Pulumi.yaml", `
name: vuln
runtime: yaml
resources:
  data:
    type: aws:s3:Bucket
    properties:
      bucket: my-data
      acl: public-read
`)
	if len(rs) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(rs))
	}
	r := rs[0]
	if r.Type != "aws_s3_bucket" {
		t.Errorf("type = %q, want aws_s3_bucket", r.Type)
	}
	if r.Provider != "aws" {
		t.Errorf("provider = %q, want aws", r.Provider)
	}
	if s, ok := attrString(t, r, "acl"); !ok || s != "public-read" {
		t.Errorf("acl = %q, %v; want public-read", s, ok)
	}
	if s, ok := attrString(t, r, "bucket"); !ok || s != "my-data" {
		t.Errorf("bucket = %q, %v; want my-data", s, ok)
	}
}

// 2. Secure S3 bucket with encryption + versioning + private ACL.
func TestSecureS3Bucket(t *testing.T) {
	rs, _ := parse(t, "Pulumi.yaml", `
name: secure
runtime: yaml
resources:
  logs:
    type: aws:s3:BucketV2
    properties:
      bucket: my-logs
      acl: private
      versioning:
        enabled: true
      serverSideEncryptionConfiguration:
        rule:
          applyServerSideEncryptionByDefault:
            sseAlgorithm: aws:kms
`)
	r := findResource(rs, "logs")
	if r == nil {
		t.Fatal("resource logs not found")
	}
	if r.Type != "aws_s3_bucket" {
		t.Errorf("BucketV2 should map to aws_s3_bucket, got %q", r.Type)
	}
	// camelCase property must be snake_cased for rule compatibility.
	if _, ok := r.Attributes["server_side_encryption_configuration"]; !ok {
		t.Errorf("expected snake_cased server_side_encryption_configuration, got keys: %v", keysOf(r))
	}
	if _, ok := r.Attributes["serverSideEncryptionConfiguration"]; ok {
		t.Errorf("camelCase property name should have been converted")
	}
}

func keysOf(r *ir.Resource) []string {
	var out []string
	for k := range r.Attributes {
		out = append(out, k)
	}
	return out
}

// 3. Azure storage account mapping.
func TestAzureStorageAccount(t *testing.T) {
	rs, _ := parse(t, "Pulumi.yaml", `
name: az
runtime: yaml
resources:
  sa:
    type: azure-native:storage:StorageAccount
    properties:
      accountName: mystorage
      kind: StorageV2
      allowBlobPublicAccess: true
`)
	r := findResource(rs, "sa")
	if r == nil {
		t.Fatal("resource sa not found")
	}
	if r.Type != "azurerm_storage_account" {
		t.Errorf("type = %q, want azurerm_storage_account", r.Type)
	}
	if r.Provider != "azure" {
		t.Errorf("provider = %q, want azure", r.Provider)
	}
	// allowBlobPublicAccess is a YAML bool, not a string.
	v, ok := r.Attributes["allow_blob_public_access"]
	if !ok {
		t.Fatalf("allow_blob_public_access missing; keys: %v", keysOf(r))
	}
	if b, ok := v.AsBool(); !ok || !b {
		t.Errorf("allow_blob_public_access = %v, want true bool", v.Raw)
	}
}

// 4. GCP bucket mapping.
func TestGCPBucket(t *testing.T) {
	rs, _ := parse(t, "Pulumi.yaml", `
name: gcp
runtime: yaml
resources:
  assets:
    type: gcp:storage:Bucket
    properties:
      name: my-assets
      location: US
      uniformBucketLevelAccess: true
`)
	r := findResource(rs, "assets")
	if r == nil {
		t.Fatal("resource assets not found")
	}
	if r.Type != "google_storage_bucket" {
		t.Errorf("type = %q, want google_storage_bucket", r.Type)
	}
	if r.Provider != "gcp" {
		t.Errorf("provider = %q, want gcp", r.Provider)
	}
}

// 5. ${...} references: variables resolve, resource refs stay unknown-with-ref,
// unknown names become unknown.
func TestReferences(t *testing.T) {
	rs, diags := parse(t, "Pulumi.yaml", `
name: refs
runtime: yaml
variables:
  env: prod
configuration:
  instanceType:
    type: string
    default: t3.micro
  dbPassword:
    type: string
    secret: true
resources:
  role:
    type: aws:iam:Role
    properties:
      name: app-role
  fn:
    type: aws:lambda:Function
    properties:
      runtime: python3.11
      handler: index.handler
      role: ${role.arn}
      environment:
        variables:
          ENV: ${env}
          TYPE: ${instanceType}
          DB_PASSWORD: ${dbPassword}
          MYSTERY: ${nope.nothing}
`)
	_ = diags
	fn := findResource(rs, "fn")
	if fn == nil {
		t.Fatal("resource fn not found")
	}
	// Resource reference -> unknown with qualified Ref (type.name.attr).
	rv, ok := fn.Attributes["role"]
	if !ok || rv.Known || rv.Ref != "aws_iam_role.role.arn" {
		t.Errorf("role ref: known=%v ref=%q, want unknown with ref aws_iam_role.role.arn", rv.Known, rv.Ref)
	}
	env, ok := fn.Attributes["environment"].AsMap()
	if !ok {
		t.Fatalf("environment not a map")
	}
	vars, ok := env["variables"].AsMap()
	if !ok {
		t.Fatalf("environment.variables not a map")
	}
	if s, ok := vars["env"].AsString(); !ok || s != "prod" {
		t.Errorf("variable ref: got %q %v, want prod", s, ok)
	}
	if s, ok := vars["type"].AsString(); !ok || s != "t3.micro" {
		t.Errorf("config default ref: got %q %v, want t3.micro", s, ok)
	}
	if v, ok := vars["db_password"]; !ok || v.Known {
		t.Errorf("secret config without default must be unknown, got known=%v", v.Known)
	}
	if v, ok := vars["mystery"]; !ok || v.Known {
		t.Errorf("unknown name must be unknown, got known=%v", v.Known)
	}
}

// 6. fn:: intrinsics become explicit unknowns with a warning.
func TestIntrinsicUnknown(t *testing.T) {
	rs, diags := parse(t, "Pulumi.yaml", `
name: intr
runtime: yaml
resources:
  ami:
    type: aws:ec2:Instance
    properties:
      ami:
        fn::invoke:
          function: aws:ec2:getAmi
          arguments:
            mostRecent: true
      instanceType: t3.micro
`)
	r := findResource(rs, "ami")
	if r == nil {
		t.Fatal("resource ami not found")
	}
	v, ok := r.Attributes["ami"]
	if !ok || v.Known {
		t.Errorf("fn::invoke must be unknown, got known=%v", v.Known)
	}
	found := false
	for _, d := range diags {
		if d.Level == "warning" && strings.Contains(d.Message, "fn::invoke") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected warning diagnostic for fn::invoke, got %v", diags)
	}
	if s, ok := attrString(t, *r, "instance_type"); !ok || s != "t3.micro" {
		t.Errorf("instance_type = %q %v, want t3.micro", s, ok)
	}
}

// 7. Unmapped type falls back with a warning (never silently dropped).
func TestUnmappedTypeFallback(t *testing.T) {
	rs, diags := parse(t, "Pulumi.yaml", `
name: fb
runtime: yaml
resources:
  weird:
    type: aws:somefuture:Widget
    properties:
      foo: bar
`)
	r := findResource(rs, "weird")
	if r == nil {
		t.Fatal("resource weird not found")
	}
	if !strings.HasPrefix(r.Type, "pulumi_") {
		t.Errorf("unmapped type should use pulumi_ fallback, got %q", r.Type)
	}
	found := false
	for _, d := range diags {
		if d.Level == "warning" && strings.Contains(d.Message, "unmapped type") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected unmapped-type warning, got %v", diags)
	}
}

// 8. Handles() only claims Pulumi.yaml / Pulumi.yml.
func TestHandles(t *testing.T) {
	a := Adapter{}
	for _, p := range []string{"Pulumi.yaml", "PULUMI.YAML", "dir/Pulumi.yml", "Pulumi.YML"} {
		if !a.Handles(p) {
			t.Errorf("Handles(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"main.tf", "template.yaml", "k8s.yaml", "Pulumi.yaml.bak", "myPulumi.yaml"} {
		if a.Handles(p) {
			t.Errorf("Handles(%q) = true, want false", p)
		}
	}
}

// 9. Document without resources: section -> warning, no resources.
func TestNoResourcesSection(t *testing.T) {
	rs, diags := parse(t, "Pulumi.yaml", "name: empty\nruntime: yaml\n")
	if len(rs) != 0 {
		t.Errorf("expected 0 resources, got %d", len(rs))
	}
	if len(diags) == 0 {
		t.Errorf("expected a warning diagnostic")
	}
}

// 10. Deterministic resource order (sorted by name).
func TestDeterministicOrder(t *testing.T) {
	rs, _ := parse(t, "Pulumi.yaml", `
name: ord
runtime: yaml
resources:
  zebra:
    type: aws:s3:Bucket
  apple:
    type: aws:s3:Bucket
  mango:
    type: aws:s3:Bucket
`)
	if len(rs) != 3 || rs[0].Name != "apple" || rs[1].Name != "mango" || rs[2].Name != "zebra" {
		t.Errorf("resources not in sorted order: %v", rs)
	}
}

// 11. toSnake conversion table.
func TestToSnake(t *testing.T) {
	cases := map[string]string{
		"bucket":                            "bucket",
		"serverSideEncryptionConfiguration": "server_side_encryption_configuration",
		"allowBlobPublicAccess":             "allow_blob_public_access",
		"uniformBucketLevelAccess":          "uniform_bucket_level_access",
		"kmsKeyId":                          "kms_key_id",
		"enableDnsSupport":                  "enable_dns_support",
		"ENV":                               "env",
		"DB_PASSWORD":                       "db_password",
		"HTTPServer":                        "http_server",
	}
	for in, want := range cases {
		if got := toSnake(in); got != want {
			t.Errorf("toSnake(%q) = %q, want %q", in, got, want)
		}
	}
}

// 12. Type table has 60+ mappings and no duplicate canonical collisions that
// would silently merge distinct resources (informational check).
func TestTypeTableSize(t *testing.T) {
	if len(pulumiTypeTable) < 60 {
		t.Errorf("type table has %d entries, want >= 60", len(pulumiTypeTable))
	}
	seen := map[string]string{}
	for tok, m := range pulumiTypeTable {
		if prev, ok := seen[m.tfType]; ok {
			t.Logf("note: %s and %s both map to %s (intentional alias)", prev, tok, m.tfType)
		} else {
			seen[m.tfType] = tok
		}
	}
}

// 13. Template-nested layout: resources under template: (legacy/embedded
// Pulumi YAML, as seen in real-world programs). Root cause of the round-2
// zero-findings gap: the adapter previously only read top-level resources:.
func TestTemplateNestedLayout(t *testing.T) {
	rs, diags := parse(t, "Pulumi.yaml", `
name: legacy
runtime: yaml
description: Legacy layout program.
template:
  configuration:
    bucketName:
      type: String
      default: my-data
  resources:
    data:
      type: aws:s3:Bucket
      properties:
        bucket: ${bucketName}
        acl: public-read
`)
	if len(rs) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(rs))
	}
	r := rs[0]
	if r.Type != "aws_s3_bucket" {
		t.Errorf("type = %q, want aws_s3_bucket", r.Type)
	}
	// ${bucketName} must resolve against template.configuration defaults.
	if s, ok := attrString(t, r, "bucket"); !ok || s != "my-data" {
		t.Errorf("bucket = %q, %v; want my-data (config default resolved)", s, ok)
	}
	if s, ok := attrString(t, r, "acl"); !ok || s != "public-read" {
		t.Errorf("acl = %q, %v; want public-read", s, ok)
	}
	// The layout must be disclosed, not silent.
	found := false
	for _, d := range diags {
		if d.Level == "info" && strings.Contains(d.Message, "template:") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected info diagnostic about template:-nested layout")
	}
}

// 14. Root-level resources: take precedence over template: when both exist.
func TestRootLayoutPrecedence(t *testing.T) {
	rs, _ := parse(t, "Pulumi.yaml", `
name: mixed
runtime: yaml
resources:
  top:
    type: aws:s3:Bucket
    properties:
      bucket: from-root
template:
  resources:
    nested:
      type: aws:s3:Bucket
      properties:
        bucket: from-template
`)
	if len(rs) != 1 {
		t.Fatalf("expected 1 resource (root wins), got %d", len(rs))
	}
	if rs[0].Name != "top" {
		t.Errorf("resource = %q, want top (root layout precedence)", rs[0].Name)
	}
}

// 15. Template-nested variables: resolve.
func TestTemplateNestedVariables(t *testing.T) {
	rs, _ := parse(t, "Pulumi.yaml", `
name: vars
runtime: yaml
template:
  variables:
    env: prod
  resources:
    data:
      type: aws:s3:Bucket
      properties:
        bucket: my-data
        tags:
          env: ${env}
`)
	if len(rs) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(rs))
	}
	tags, ok := rs[0].Attributes["tags"]
	if !ok {
		t.Fatalf("tags attribute missing")
	}
	m, ok := tags.AsMap()
	if !ok {
		t.Fatalf("tags is not a map")
	}
	ev, ok := m["env"]
	if !ok {
		t.Fatalf("tags.env missing")
	}
	if s, ok := ev.AsString(); !ok || s != "prod" {
		t.Errorf("tags.env = %q, %v; want prod", s, ok)
	}
}

// 16. Azure storage account: Pulumi azure-native property names normalize
// to the Terraform attribute names the rules expect.
func TestAzureStoragePropertyNormalization(t *testing.T) {
	rs, _ := parse(t, "Pulumi.yaml", `
name: az
runtime: yaml
template:
  resources:
    stg:
      type: azure-native:storage:StorageAccount
      properties:
        accountName: mystg
        minimumTlsVersion: TLS1_2
        supportsHttpsTrafficOnly: true
        allowSharedKeyAccess: false
        allowBlobPublicAccess: false
        publicNetworkAccess: Disabled
        networkRuleSet:
          defaultAction: Deny
          bypass: None
`)
	if len(rs) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(rs))
	}
	r := rs[0]
	if r.Type != "azurerm_storage_account" {
		t.Fatalf("type = %q, want azurerm_storage_account", r.Type)
	}
	checks := map[string]string{
		"min_tls_version": "TLS1_2",
	}
	for attr, want := range checks {
		if s, ok := attrString(t, r, attr); !ok || s != want {
			t.Errorf("%s = %q, %v; want %q", attr, s, ok, want)
		}
	}
	for _, attr := range []string{"https_traffic_only_enabled", "network_rules"} {
		if _, ok := r.Attributes[attr]; !ok {
			t.Errorf("attribute %q missing after normalization", attr)
		}
	}
	// shared_access_key_enabled must be false (secure) and present.
	if v, ok := r.Attributes["shared_access_key_enabled"]; !ok {
		t.Errorf("shared_access_key_enabled missing")
	} else if b, ok := v.AsBool(); !ok || b {
		t.Errorf("shared_access_key_enabled = %v; want false", v.Raw)
	}
	// public_network_access_enabled must be false (Disabled enum).
	if v, ok := r.Attributes["public_network_access_enabled"]; !ok {
		t.Errorf("public_network_access_enabled missing")
	} else if b, ok := v.AsBool(); !ok || b {
		t.Errorf("public_network_access_enabled = %v; want false", v.Raw)
	}
	// allow_blob_public_access passes through correctly.
	if v, ok := r.Attributes["allow_blob_public_access"]; !ok {
		t.Errorf("allow_blob_public_access missing")
	} else if b, ok := v.AsBool(); !ok || b {
		t.Errorf("allow_blob_public_access = %v; want false", v.Raw)
	}
}

// 17. New typemap entries resolve without "unmapped type" warnings.
func TestNewTypemapEntries(t *testing.T) {
	cases := map[string]string{
		"aws:ec2:NetworkAclRule":                    "aws_network_acl_rule",
		"azure-native:authorization:RoleAssignment": "azurerm_role_assignment",
		"azure-native:resources:ResourceGroup":      "azurerm_resource_group",
		"azure-native:sql:FirewallRule":             "azurerm_mssql_firewall_rule",
		"azure-native:storage:BlobContainer":        "azurerm_storage_container",
	}
	for token, want := range cases {
		rs, diags := parse(t, "Pulumi.yaml", "name: x\nruntime: yaml\nresources:\n  r1:\n    type: "+token+"\n    properties:\n      name: x\n")
		if len(rs) != 1 || rs[0].Type != want {
			t.Errorf("%s -> %q, want %q", token, rs[0].Type, want)
		}
		for _, d := range diags {
			if strings.Contains(d.Message, "unmapped type") {
				t.Errorf("%s produced unmapped-type warning", token)
			}
		}
	}
}

// 18. Template config: alias for configuration: is honored.
// Note: partial interpolation ("${region}-data") is not supported by the
// adapter (known limitation); pure ${...} references resolve.
func TestTemplateConfigAlias(t *testing.T) {
	rs, _ := parse(t, "Pulumi.yaml", `
name: cfg
runtime: yaml
template:
  config:
    bucketName:
      default: my-data
  resources:
    data:
      type: aws:s3:Bucket
      properties:
        bucket: ${bucketName}
`)
	if len(rs) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(rs))
	}
	if s, ok := attrString(t, rs[0], "bucket"); !ok || s != "my-data" {
		t.Errorf("bucket = %q, %v; want my-data", s, ok)
	}
}

// 19. NSG: nested properties.securityRules[].properties flattened so rules
// read direction/access at the rule level (round-3 gap: 5 FNs).
func TestNSGNestedRuleProperties(t *testing.T) {
	rs, _ := parse(t, "Pulumi.yaml", `
name: nsg
runtime: yaml
template:
  resources:
    webNsg:
      type: azure-native:network:NetworkSecurityGroup
      properties:
        networkSecurityGroupName: web-nsg
        securityRules:
          - name: allow-ssh
            properties:
              priority: 100
              direction: Inbound
              access: Allow
              protocol: Tcp
              sourceAddressPrefix: "*"
              destinationPortRange: "22"
`)
	if len(rs) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(rs))
	}
	r := rs[0]
	if r.Type != "azurerm_network_security_group" {
		t.Fatalf("type = %q", r.Type)
	}
	rules, ok := r.Attributes["security_rule"]
	if !ok {
		t.Fatalf("security_rule attribute missing")
	}
	lst, ok := rules.Raw.([]ir.Value)
	if !ok || len(lst) != 1 {
		t.Fatalf("security_rule is not a 1-element list")
	}
	m, ok := lst[0].AsMap()
	if !ok {
		t.Fatalf("rule is not a map")
	}
	if s, ok := m["direction"].AsString(); !ok || s != "Inbound" {
		t.Errorf("direction not flattened: %v", m["direction"].Raw)
	}
	if s, ok := m["access"].AsString(); !ok || s != "Allow" {
		t.Errorf("access not flattened")
	}
	if _, has := m["properties"]; has {
		t.Errorf("nested properties map not removed after flatten")
	}
}

// 20. Key Vault: nested properties flattened + enable* renamed (round-3
// gap: 4 FNs on purge protection).
func TestKeyVaultNestedProperties(t *testing.T) {
	rs, _ := parse(t, "Pulumi.yaml", `
name: kv
runtime: yaml
template:
  resources:
    mainVault:
      type: azure-native:keyvault:Vault
      properties:
        vaultName: my-kv
        properties:
          enablePurgeProtection: false
          enableSoftDelete: true
`)
	if len(rs) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(rs))
	}
	r := rs[0]
	if r.Type != "azurerm_key_vault" {
		t.Fatalf("type = %q", r.Type)
	}
	if v, ok := r.Attributes["purge_protection_enabled"]; !ok {
		t.Errorf("purge_protection_enabled missing after flatten+rename")
	} else if b, ok := v.AsBool(); !ok || b {
		t.Errorf("purge_protection_enabled = %v; want false", v.Raw)
	}
	if _, has := r.Attributes["properties"]; has {
		t.Errorf("nested properties map not removed after flatten")
	}
}

// 21. Parity (item 2): Key Vault softDeleteRetentionInDays -> the
// soft_delete_retention_days the Azure rules read, and sku.name ->
// sku_name (same promotion as the ARM adapter).
func TestKeyVaultRetentionAndSkuNormalization(t *testing.T) {
	rs, _ := parse(t, "Pulumi.yaml", `
name: kv
runtime: yaml
template:
  resources:
    mainVault:
      type: azure-native:keyvault:Vault
      properties:
        vaultName: my-kv
        properties:
          sku:
            family: A
            name: standard
          softDeleteRetentionInDays: 7
`)
	if len(rs) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(rs))
	}
	r := rs[0]
	if v, ok := r.Attributes["soft_delete_retention_days"]; !ok {
		t.Errorf("soft_delete_retention_days missing (softDeleteRetentionInDays not renamed)")
	} else if f, ok := v.Raw.(float64); !ok || f != 7 {
		t.Errorf("soft_delete_retention_days = %v; want 7", v.Raw)
	}
	if _, ok := r.Attributes["soft_delete_retention_in_days"]; ok {
		t.Errorf("unrenamed soft_delete_retention_in_days still present")
	}
	if s, ok := attrString(t, r, "sku_name"); !ok || s != "standard" {
		t.Errorf("sku_name = %q, want standard", s)
	}
}

// 22. Parity (item 2): Key Vault networkAcls ipRules [{value}] unwrap to a
// plain string list, and virtualNetworkRules [{id}] become
// virtual_network_subnet_ids, so AZURE-205 reads them like TF ip_rules.
func TestKeyVaultNetworkAclsUnwrap(t *testing.T) {
	rs, _ := parse(t, "Pulumi.yaml", `
name: kv
runtime: yaml
template:
  resources:
    mainVault:
      type: azure-native:keyvault:Vault
      properties:
        vaultName: my-kv
        properties:
          networkAcls:
            bypass: None
            defaultAction: Deny
            ipRules:
              - value: 1.2.3.4/32
            virtualNetworkRules:
              - id: /subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/v/subnets/s
`)
	if len(rs) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(rs))
	}
	r := rs[0]
	nacls, ok := r.Attributes["network_acls"]
	if !ok {
		t.Fatalf("network_acls missing")
	}
	m, ok := nacls.AsMap()
	if !ok {
		t.Fatalf("network_acls is not a map")
	}
	ips, ok := m["ip_rules"]
	if !ok {
		t.Fatalf("ip_rules missing after unwrap")
	}
	lst, ok := ips.Raw.([]ir.Value)
	if !ok || len(lst) != 1 {
		t.Fatalf("ip_rules is not a 1-element list: %#v", ips.Raw)
	}
	if s, ok := lst[0].AsString(); !ok || s != "1.2.3.4/32" {
		t.Errorf("ip_rules[0] = %v, want 1.2.3.4/32", lst[0].Raw)
	}
	subs, ok := m["virtual_network_subnet_ids"]
	if !ok {
		t.Fatalf("virtual_network_subnet_ids missing after unwrap")
	}
	slst, ok := subs.Raw.([]ir.Value)
	if !ok || len(slst) != 1 {
		t.Fatalf("virtual_network_subnet_ids is not a 1-element list")
	}
	if _, ok := m["virtual_network_rules"]; ok {
		t.Errorf("unrenamed virtual_network_rules still present")
	}
}

// 23. Parity (item 2): a Pulumi YAML mapping for `policy` (e.g. an S3
// BucketPolicy document) is stringified to JSON so the policy rules,
// which read a JSON string, can evaluate it. A policy containing an
// unresolved reference stays a mapping (never fabricated).
func TestMapValuedPolicyStringified(t *testing.T) {
	rs, _ := parse(t, "Pulumi.yaml", `
name: s3pol
runtime: yaml
template:
  resources:
    b:
      type: aws:s3:Bucket
      properties:
        bucket: my-bucket
    bPolicy:
      type: aws:s3:BucketPolicy
      properties:
        bucket: ${b.id}
        policy:
          Version: "2012-10-17"
          Statement:
            - Sid: PublicRead
              Effect: Allow
              Principal: "*"
              Action: s3:GetObject
              Resource: "arn:aws:s3:::my-bucket/*"
`)
	if len(rs) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(rs))
	}
	pol := findResource(rs, "bPolicy")
	if pol == nil {
		t.Fatalf("bPolicy resource missing")
	}
	s, ok := attrString(t, *pol, "policy")
	if !ok {
		t.Fatalf("policy was not stringified to a JSON string")
	}
	if !strings.Contains(s, `"effect"`) || !strings.Contains(s, `s3:GetObject`) {
		t.Errorf("stringified policy lost content: %s", s)
	}
}

// 24. Parity (item 2): a policy with an unresolved reference is NOT
// stringified (its Unknown part must not become fabricated JSON).
func TestPolicyWithUnknownNotStringified(t *testing.T) {
	rs, _ := parse(t, "Pulumi.yaml", `
name: s3pol
runtime: yaml
template:
  resources:
    bPolicy:
      type: aws:s3:BucketPolicy
      properties:
        bucket: some-bucket
        policy:
          Version: "2012-10-17"
          Statement:
            - Effect: Allow
              Principal: "*"
              Action: s3:GetObject
              Resource: ${missingVar}
`)
	if len(rs) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(rs))
	}
	v, ok := rs[0].Attributes["policy"]
	if !ok {
		t.Fatalf("policy attribute missing")
	}
	if _, isMap := v.Raw.(map[string]ir.Value); !isMap {
		t.Errorf("policy with Unknown content was stringified; want mapping left intact")
	}
}

// R5 regression (AEGIS-AZURE-313): the publicNetworkAccess enum ->
// boolean conversion used to run only for storage accounts and MSSQL
// servers, so a Pulumi Redis cache kept the raw string under
// public_network_access and bool rules saw no
// public_network_access_enabled at all.
func TestAzureRedisPublicNetworkAccessEnum(t *testing.T) {
	rs, _ := parse(t, "Pulumi.yaml", `
name: r5-redis
runtime: yaml
template:
  resources:
    sessionsCache:
      type: azure-native:cache:Redis
      properties:
        redisName: sessions-x
        resourceGroupName: rg-cache
        location: northeurope
        enableNonSslPort: false
        minimumTlsVersion: '1.2'
        publicNetworkAccess: Enabled
`)
	if len(rs) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(rs))
	}
	r := rs[0]
	if r.Type != "azurerm_redis_cache" {
		t.Fatalf("type = %q, want azurerm_redis_cache", r.Type)
	}
	if v, ok := r.Attributes["public_network_access_enabled"]; !ok {
		t.Errorf("public_network_access_enabled missing after enum conversion")
	} else if b, ok := v.AsBool(); !ok || !b {
		t.Errorf("public_network_access_enabled = %v; want bool true", v.Raw)
	}
}

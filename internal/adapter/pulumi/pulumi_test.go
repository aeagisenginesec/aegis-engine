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

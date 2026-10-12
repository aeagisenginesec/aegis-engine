package terraform

import (
	"strings"
	"testing"

	"aegis/internal/adapter/terraform"
	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// test helpers
// ---------------------------------------------------------------------------

func backendRes(name string, attrs map[string]ir.Value) ir.Resource {
	return ir.Resource{
		Type: "terraform_backend", Name: name, Provider: "terraform",
		Attributes: attrs,
		Span:       ir.Span{File: "t.tf", StartLine: 1, StartCol: 1, EndLine: 5, EndCol: 1},
	}
}

func configRes(attrs map[string]ir.Value) ir.Resource {
	return ir.Resource{
		Type: "terraform_config", Name: "terraform", Provider: "terraform",
		Attributes: attrs,
		Span:       ir.Span{File: "t.tf", StartLine: 1, StartCol: 1, EndLine: 5, EndCol: 1},
	}
}

func providerRes(name string, attrs map[string]ir.Value) ir.Resource {
	return ir.Resource{
		Type: "terraform_provider", Name: name, Provider: "terraform",
		Attributes: attrs,
		Span:       ir.Span{File: "t.tf", StartLine: 1, StartCol: 1, EndLine: 5, EndCol: 1},
	}
}

func strVal(s string) ir.Value {
	return ir.Value{Raw: s, Known: true, Span: ir.Span{File: "t.tf"}}
}
func boolVal(b bool) ir.Value {
	return ir.Value{Raw: b, Known: true, Span: ir.Span{File: "t.tf"}}
}
func unknownVal() ir.Value { return ir.UnknownValue(ir.Span{File: "t.tf"}) }

func provEntry(name, version string) ir.Value {
	m := map[string]ir.Value{"name": strVal(name)}
	if version != "" {
		m["version"] = strVal(version)
	}
	return ir.Value{Raw: m, Known: true, Span: ir.Span{File: "t.tf"}}
}

func TestRulesInIDOrder(t *testing.T) {
	rules := TerraformRules()
	want := []string{
		"AEGIS-TF-001", "AEGIS-TF-002", "AEGIS-TF-003", "AEGIS-TF-004",
		"AEGIS-TF-005", "AEGIS-TF-006", "AEGIS-TF-007", "AEGIS-TF-008",
	}
	if len(rules) != len(want) {
		t.Fatalf("expected %d rules, got %d", len(want), len(rules))
	}
	seen := map[string]bool{}
	for i, r := range rules {
		if r.ID() != want[i] {
			t.Errorf("rule %d: got %s, want %s", i, r.ID(), want[i])
		}
		if seen[r.ID()] {
			t.Errorf("duplicate rule ID %s", r.ID())
		}
		seen[r.ID()] = true
		if r.Title() == "" || r.Description() == "" {
			t.Errorf("%s missing title/description", r.ID())
		}
	}
}

// ---------------------------------------------------------------------------
// TF-001: S3 backend without encryption
// ---------------------------------------------------------------------------

func Test001_FiresWhenEncryptAbsent(t *testing.T) {
	r := backendRes("s3", map[string]ir.Value{"bucket": strVal("b")})
	fs := tfBackendNoEncrypt{}.Check(r)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].RuleID != "AEGIS-TF-001" || fs[0].Severity != ir.SeverityHigh {
		t.Errorf("unexpected finding: %+v", fs[0])
	}
}

func Test001_FiresWhenEncryptFalse(t *testing.T) {
	r := backendRes("s3", map[string]ir.Value{"encrypt": boolVal(false)})
	if len(tfBackendNoEncrypt{}.Check(r)) != 1 {
		t.Error("expected finding for encrypt=false")
	}
}

func Test001_SilentWhenEncryptTrue(t *testing.T) {
	r := backendRes("s3", map[string]ir.Value{"encrypt": boolVal(true)})
	if len(tfBackendNoEncrypt{}.Check(r)) != 0 {
		t.Error("expected no finding for encrypt=true")
	}
}

func Test001_SilentWhenUnknown(t *testing.T) {
	r := backendRes("s3", map[string]ir.Value{"encrypt": unknownVal()})
	if len(tfBackendNoEncrypt{}.Check(r)) != 0 {
		t.Error("expected no finding for unknown encrypt")
	}
}

func Test001_SilentForNonS3(t *testing.T) {
	r := backendRes("gcs", map[string]ir.Value{})
	if len(tfBackendNoEncrypt{}.Check(r)) != 0 {
		t.Error("expected no finding for non-s3 backend")
	}
}

// ---------------------------------------------------------------------------
// TF-002: S3 backend without locking
// ---------------------------------------------------------------------------

func Test002_FiresWhenNoLockTable(t *testing.T) {
	r := backendRes("s3", map[string]ir.Value{"bucket": strVal("b")})
	fs := tfBackendNoLocking{}.Check(r)
	if len(fs) != 1 || fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("expected 1 high finding, got %+v", fs)
	}
}

func Test002_SilentWithLockTable(t *testing.T) {
	r := backendRes("s3", map[string]ir.Value{"dynamodb_table": strVal("locks")})
	if len(tfBackendNoLocking{}.Check(r)) != 0 {
		t.Error("expected no finding with dynamodb_table set")
	}
}

func Test002_SilentWhenUnknown(t *testing.T) {
	r := backendRes("s3", map[string]ir.Value{"dynamodb_table": unknownVal()})
	if len(tfBackendNoLocking{}.Check(r)) != 0 {
		t.Error("expected no finding for unknown table")
	}
}

// ---------------------------------------------------------------------------
// TF-003: unpinned provider version
// ---------------------------------------------------------------------------

func Test003_FiresWhenVersionAbsent(t *testing.T) {
	r := configRes(map[string]ir.Value{
		"required_providers": ir.Value{Raw: []ir.Value{provEntry("aws", "")}, Known: true},
	})
	fs := tfProviderUnpinned{}.Check(r)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if !strings.Contains(fs[0].Evidence.Attribute, "aws.version") {
		t.Errorf("evidence should name the provider: %s", fs[0].Evidence.Attribute)
	}
}

func Test003_FiresOnOpenEndedConstraint(t *testing.T) {
	r := configRes(map[string]ir.Value{
		"required_providers": ir.Value{Raw: []ir.Value{provEntry("aws", ">= 5.0")}, Known: true},
	})
	if len(tfProviderUnpinned{}.Check(r)) != 1 {
		t.Error("expected finding for >= 5.0")
	}
}

func Test003_SilentOnBoundedConstraint(t *testing.T) {
	for _, v := range []string{"~> 5.0", ">= 5.0, < 6.0", "= 5.31.0"} {
		r := configRes(map[string]ir.Value{
			"required_providers": ir.Value{Raw: []ir.Value{provEntry("aws", v)}, Known: true},
		})
		if len(tfProviderUnpinned{}.Check(r)) != 0 {
			t.Errorf("expected no finding for %q", v)
		}
	}
}

func Test003_SilentWhenBlockAbsent(t *testing.T) {
	// TF-007 owns the missing block; no double count.
	r := configRes(map[string]ir.Value{})
	if len(tfProviderUnpinned{}.Check(r)) != 0 {
		t.Error("expected no finding when required_providers absent")
	}
}

// ---------------------------------------------------------------------------
// TF-004: unpinned terraform version
// ---------------------------------------------------------------------------

func Test004_FiresWhenAbsent(t *testing.T) {
	r := configRes(map[string]ir.Value{})
	fs := tfVersionUnpinned{}.Check(r)
	if len(fs) != 1 || fs[0].Severity != ir.SeverityMedium {
		t.Fatalf("expected 1 medium finding, got %+v", fs)
	}
}

func Test004_SilentWhenPinned(t *testing.T) {
	r := configRes(map[string]ir.Value{"required_version": strVal(">= 1.5.0")})
	if len(tfVersionUnpinned{}.Check(r)) != 0 {
		t.Error("expected no finding when required_version set")
	}
}

func Test004_SilentWhenUnknown(t *testing.T) {
	r := configRes(map[string]ir.Value{"required_version": unknownVal()})
	if len(tfVersionUnpinned{}.Check(r)) != 0 {
		t.Error("expected no finding for unknown version")
	}
}

// ---------------------------------------------------------------------------
// TF-005: HTTP backend
// ---------------------------------------------------------------------------

func Test005_FiresOnHTTP(t *testing.T) {
	r := backendRes("http", map[string]ir.Value{"address": strVal("http://state.internal/tf")})
	fs := tfBackendHTTP{}.Check(r)
	if len(fs) != 1 || fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("expected 1 high finding, got %+v", fs)
	}
}

func Test005_SilentOnHTTPS(t *testing.T) {
	r := backendRes("http", map[string]ir.Value{"address": strVal("https://state.internal/tf")})
	if len(tfBackendHTTP{}.Check(r)) != 0 {
		t.Error("expected no finding for https")
	}
}

func Test005_SilentWhenUnknown(t *testing.T) {
	r := backendRes("http", map[string]ir.Value{"address": unknownVal()})
	if len(tfBackendHTTP{}.Check(r)) != 0 {
		t.Error("expected no finding for unknown address")
	}
}

// ---------------------------------------------------------------------------
// TF-006: local backend
// ---------------------------------------------------------------------------

func Test006_FiresOnLocal(t *testing.T) {
	r := backendRes("local", map[string]ir.Value{})
	fs := tfBackendLocal{}.Check(r)
	if len(fs) != 1 || fs[0].Severity != ir.SeverityMedium {
		t.Fatalf("expected 1 medium finding, got %+v", fs)
	}
}

func Test006_SilentForS3(t *testing.T) {
	r := backendRes("s3", map[string]ir.Value{})
	if len(tfBackendLocal{}.Check(r)) != 0 {
		t.Error("expected no finding for s3 backend")
	}
}

// ---------------------------------------------------------------------------
// TF-007: missing required_providers
// ---------------------------------------------------------------------------

func Test007_FiresWhenAbsent(t *testing.T) {
	r := configRes(map[string]ir.Value{})
	fs := tfNoRequiredProviders{}.Check(r)
	if len(fs) != 1 || fs[0].Severity != ir.SeverityLow {
		t.Fatalf("expected 1 low finding, got %+v", fs)
	}
}

func Test007_SilentWhenPresent(t *testing.T) {
	r := configRes(map[string]ir.Value{
		"required_providers": ir.Value{Raw: []ir.Value{provEntry("aws", "~> 5.0")}, Known: true},
	})
	if len(tfNoRequiredProviders{}.Check(r)) != 0 {
		t.Error("expected no finding when required_providers present")
	}
}

// ---------------------------------------------------------------------------
// TF-008: skip_credentials_validation
// ---------------------------------------------------------------------------

func Test008_FiresWhenTrue(t *testing.T) {
	r := providerRes("aws", map[string]ir.Value{"skip_credentials_validation": boolVal(true)})
	fs := tfSkipCredValidation{}.Check(r)
	if len(fs) != 1 || fs[0].Severity != ir.SeverityMedium {
		t.Fatalf("expected 1 medium finding, got %+v", fs)
	}
}

func Test008_SilentWhenFalseOrAbsent(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		{"skip_credentials_validation": boolVal(false)},
		{"region": strVal("us-east-1")},
	} {
		r := providerRes("aws", attrs)
		if len(tfSkipCredValidation{}.Check(r)) != 0 {
			t.Errorf("expected no finding for %v", attrs)
		}
	}
}

func Test008_SilentWhenUnknown(t *testing.T) {
	r := providerRes("aws", map[string]ir.Value{"skip_credentials_validation": unknownVal()})
	if len(tfSkipCredValidation{}.Check(r)) != 0 {
		t.Error("expected no finding for unknown value")
	}
}

// ---------------------------------------------------------------------------
// adapter end-to-end: terraform/provider blocks become resources
// ---------------------------------------------------------------------------

func TestAdapter_EmitsTerraformResources(t *testing.T) {
	src := `terraform {
  required_version = ">= 1.5.0"
  backend "s3" {
    bucket = "my-state"
  }
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 4.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  skip_credentials_validation = true
}

resource "aws_s3_bucket" "b" {
  bucket = "b"
}
`
	mod, _, err := terraform.Adapter{}.ParseModule("t.tf", []byte(src))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	byType := map[string][]ir.Resource{}
	for _, r := range mod.Resources {
		byType[r.Type] = append(byType[r.Type], r)
	}
	if len(byType["terraform_config"]) != 1 {
		t.Fatalf("expected 1 terraform_config, got %d", len(byType["terraform_config"]))
	}
	if len(byType["terraform_backend"]) != 1 || byType["terraform_backend"][0].Name != "s3" {
		t.Fatalf("expected 1 s3 terraform_backend, got %+v", byType["terraform_backend"])
	}
	if len(byType["terraform_provider"]) != 1 || byType["terraform_provider"][0].Name != "aws" {
		t.Fatalf("expected 1 aws terraform_provider, got %+v", byType["terraform_provider"])
	}
	if len(byType["aws_s3_bucket"]) != 1 {
		t.Fatalf("expected 1 aws_s3_bucket, got %d", len(byType["aws_s3_bucket"]))
	}
	// required_version present -> TF-004 silent; version ">= 4.0" -> TF-003 fires
	cfg := byType["terraform_config"][0]
	if len(tfVersionUnpinned{}.Check(cfg)) != 0 {
		t.Error("TF-004 should be silent with required_version set")
	}
	if len(tfProviderUnpinned{}.Check(cfg)) != 1 {
		t.Error("TF-003 should fire for >= 4.0")
	}
	if len(tfNoRequiredProviders{}.Check(cfg)) != 0 {
		t.Error("TF-007 should be silent with required_providers present")
	}
	// backend without encrypt/dynamodb_table -> TF-001 + TF-002 fire
	be := byType["terraform_backend"][0]
	if len(tfBackendNoEncrypt{}.Check(be)) != 1 {
		t.Error("TF-001 should fire (encrypt absent)")
	}
	if len(tfBackendNoLocking{}.Check(be)) != 1 {
		t.Error("TF-002 should fire (dynamodb_table absent)")
	}
	// provider with skip_credentials_validation=true -> TF-008 fires
	p := byType["terraform_provider"][0]
	if len(tfSkipCredValidation{}.Check(p)) != 1 {
		t.Error("TF-008 should fire")
	}
}

func TestAdapter_NoTerraformBlockNoSynthetic(t *testing.T) {
	src := `resource "aws_s3_bucket" "b" {
  bucket = "b"
}
`
	mod, _, err := terraform.Adapter{}.ParseModule("t.tf", []byte(src))
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	for _, r := range mod.Resources {
		if strings.HasPrefix(r.Type, "terraform_") {
			t.Errorf("unexpected synthetic resource %s without terraform block", r.Address())
		}
	}
}

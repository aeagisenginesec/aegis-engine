package aws

import (
	"testing"

	"aegis/internal/ir"
)

// AEGIS-AWS-009: EBS volume without encryption.

func TestEBSUnencrypted_AbsentFires(t *testing.T) {
	v := res("aws_ebs_volume", "data", nil)
	f := runRule(ebsUnencrypted{}, v)
	if len(f) != 1 || f[0].Severity != "medium" {
		t.Fatalf("expected 1 medium finding, got %+v", f)
	}
	if f[0].Evidence.Attribute != "encrypted" {
		t.Fatalf("wrong evidence attribute: %s", f[0].Evidence.Attribute)
	}
}

func TestEBSUnencrypted_FalseFires(t *testing.T) {
	v := res("aws_ebs_volume", "data", map[string]ir.Value{"encrypted": kv(false, 3)})
	if f := runRule(ebsUnencrypted{}, v); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestEBSUnencrypted_TrueOK(t *testing.T) {
	v := res("aws_ebs_volume", "data", map[string]ir.Value{"encrypted": kv(true, 3)})
	if f := runRule(ebsUnencrypted{}, v); len(f) != 0 {
		t.Fatalf("encrypted volume must not fire, got %d", len(f))
	}
}

func TestEBSUnencrypted_UnknownNoFinding(t *testing.T) {
	v := res("aws_ebs_volume", "data", map[string]ir.Value{"encrypted": ku(3)})
	if f := runRule(ebsUnencrypted{}, v); len(f) != 0 {
		t.Fatalf("unknown encrypted must not fire, got %d", len(f))
	}
}

// AEGIS-AWS-010: CloudTrail without log file validation.

func TestCloudTrailNoValidation_AbsentFires(t *testing.T) {
	tr := res("aws_cloudtrail", "main", nil)
	f := runRule(cloudtrailNoValidation{}, tr)
	if len(f) != 1 || f[0].Severity != "medium" {
		t.Fatalf("expected 1 medium finding, got %+v", f)
	}
	if f[0].Evidence.Attribute != "enable_log_file_validation" {
		t.Fatalf("wrong evidence attribute: %s", f[0].Evidence.Attribute)
	}
}

func TestCloudTrailNoValidation_FalseFires(t *testing.T) {
	tr := res("aws_cloudtrail", "main", map[string]ir.Value{"enable_log_file_validation": kv(false, 3)})
	if f := runRule(cloudtrailNoValidation{}, tr); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestCloudTrailNoValidation_TrueOK(t *testing.T) {
	tr := res("aws_cloudtrail", "main", map[string]ir.Value{"enable_log_file_validation": kv(true, 3)})
	if f := runRule(cloudtrailNoValidation{}, tr); len(f) != 0 {
		t.Fatalf("validated trail must not fire, got %d", len(f))
	}
}

func TestCloudTrailNoValidation_UnknownNoFinding(t *testing.T) {
	tr := res("aws_cloudtrail", "main", map[string]ir.Value{"enable_log_file_validation": ku(3)})
	if f := runRule(cloudtrailNoValidation{}, tr); len(f) != 0 {
		t.Fatalf("unknown value must not fire, got %d", len(f))
	}
}

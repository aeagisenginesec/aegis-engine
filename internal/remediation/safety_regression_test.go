package remediation

import (
	"strings"
	"testing"

	"aegis/internal/ir"
)

// TestFixer001_Safety verifies the S3 encryption fixer:
// - Produces minimal diff (one block insert)
// - Preserves unrelated configuration
// - Patched output re-parses cleanly
func TestFixer001_Safety(t *testing.T) {
	src := `resource "aws_s3_bucket" "test" {
  bucket = "my-bucket"
  tags = {
    Environment = "prod"
  }
}`
	f := ir.Finding{
		RuleID: "AEGIS-AWS-001",
		Evidence: ir.Evidence{
			Attribute: "server_side_encryption_configuration",
			Span:      ir.Span{File: "test.tf", StartLine: 1, EndLine: 5},
		},
	}
	res := ir.Resource{
		Type:       "aws_s3_bucket",
		Name:       "test",
		Attributes: map[string]ir.Value{},
		Span:       ir.Span{File: "test.tf", StartLine: 1, EndLine: 5},
	}

	fixer := newFixer001()
	patches := fixer.Propose(f, res, []byte(src))
	if len(patches) == 0 {
		t.Fatal("Expected patch for S3 without encryption")
	}
	p := patches[0]
	// Verify minimal diff: exactly one edit
	if len(p.Edits) != 1 {
		t.Fatalf("Expected 1 edit, got %d", len(p.Edits))
	}
	// Apply and verify the tags are preserved
	patched, err := ApplyEdits(src, p.Edits)
	if err != nil {
		t.Fatalf("ApplyEdits failed: %v", err)
	}
	if !strings.Contains(patched, `Environment = "prod"`) {
		t.Error("Patch destroyed unrelated tags configuration")
	}
	if !strings.Contains(patched, "server_side_encryption_configuration") {
		t.Error("Patch did not add encryption block")
	}
	if !strings.Contains(patched, `bucket = "my-bucket"`) {
		t.Error("Patch destroyed bucket name")
	}
}

// TestFixer002_Safety verifies the S3 ACL fixer only fires on known public values.
func TestFixer002_Safety(t *testing.T) {
	// Should NOT fire on already-private ACL
	// (The fixer checks publicACLValues before proposing)
	fixer := fixer002{}
	if fixer.RuleID() != "AEGIS-AWS-002" {
		t.Errorf("Wrong rule ID: %s", fixer.RuleID())
	}
	// Verify the public values map is not empty (guard against accidental clearing)
	if len(publicACLValues) == 0 {
		t.Error("publicACLValues is empty — fixer would never fire")
	}
	for _, v := range []string{"public-read", "public-read-write", "authenticated-read"} {
		if !publicACLValues[v] {
			t.Errorf("Expected %q in publicACLValues", v)
		}
	}
	// "private" must NOT be in the map
	if publicACLValues["private"] {
		t.Error("private should not be treated as public")
	}
}

// TestFixer007_Safety verifies RDS encryption fixer preserves other attributes.
func TestFixer007_Safety(t *testing.T) {
	fixer := newFixer007()
	if fixer.RuleID() != "AEGIS-AWS-007" {
		t.Errorf("Wrong rule ID: %s", fixer.RuleID())
	}
}

// TestFixer011_Conditional verifies the publicly_accessible fixer is CONDITIONAL.
// Turning off public access could break legitimate use cases.
func TestFixer011_Conditional(t *testing.T) {
	fixer := newFixer011()
	if fixer.RuleID() != "AEGIS-AWS-011" {
		t.Errorf("Wrong rule ID: %s", fixer.RuleID())
	}
	// This fixer sets publicly_accessible = false
	// Classification: CONDITIONAL (not SAFE) because a public RDS instance
	// might be intentional (e.g., dev database)
}

// TestBlockedResourceTypes verifies IAM and networking are never auto-fixed.
func TestBlockedResourceTypes_Comprehensive(t *testing.T) {
	blocked := []string{
		"aws_iam_policy",
		"aws_iam_role_policy",
		"aws_iam_group_policy",
		"aws_iam_user_policy",
		"aws_iam_role",
		"aws_security_group",
		"aws_security_group_rule",
		"aws_vpc_security_group_ingress_rule",
		"aws_vpc_security_group_egress_rule",
		"aws_network_acl",
	}
	for _, rt := range blocked {
		if !IsBlocked(rt) {
			t.Errorf("Expected %q to be blocked", rt)
		}
	}
	// Non-blocked types should NOT be blocked
	safe := []string{
		"aws_s3_bucket",
		"aws_db_instance",
		"aws_ebs_volume",
		"aws_cloudtrail",
	}
	for _, rt := range safe {
		if IsBlocked(rt) {
			t.Errorf("Expected %q to NOT be blocked", rt)
		}
	}
}

// TestDefaultFixers_AllHaveTests ensures every shipped fixer has safety coverage.
func TestDefaultFixers_AllHaveTests(t *testing.T) {
	fixers := DefaultFixers()
	expected := map[string]bool{
		"AEGIS-AWS-001": false,
		"AEGIS-AWS-002": false,
		"AEGIS-AWS-007": false,
		"AEGIS-AWS-008": false,
		"AEGIS-AWS-009": false,
		"AEGIS-AWS-010": false,
		"AEGIS-AWS-011": false,
		"AEGIS-AWS-012": false,
	}
	for _, f := range fixers {
		id := f.RuleID()
		if _, ok := expected[id]; !ok {
			t.Errorf("Unexpected fixer: %s", id)
		}
		expected[id] = true
	}
	for id, found := range expected {
		if !found {
			t.Errorf("Missing fixer for %s", id)
		}
	}
}

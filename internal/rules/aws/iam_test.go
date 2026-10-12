package aws

import (
	"testing"

	"aegis/internal/ir"
)

// AEGIS-AWS-006: IAM policy allows all actions on all resources.

func TestIAMAdmin_StarStarFires(t *testing.T) {
	p := res("aws_iam_policy", "admin", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`, 3),
	})
	f := runRule(iamAdminPolicy{}, p)
	if len(f) != 1 || f[0].Severity != "critical" {
		t.Fatalf("expected 1 critical finding, got %+v", f)
	}
	if f[0].Evidence.Attribute != "policy" {
		t.Fatalf("wrong evidence attribute: %s", f[0].Evidence.Attribute)
	}
}

func TestIAMAdmin_ListFormFires(t *testing.T) {
	p := res("aws_iam_policy", "admin", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":["*"],"Resource":["arn:aws:s3:::b/*","*"]}]}`, 3),
	})
	if f := runRule(iamAdminPolicy{}, p); len(f) != 1 {
		t.Fatalf("expected 1 finding for list form, got %d", len(f))
	}
}

func TestIAMAdmin_ScopedOK(t *testing.T) {
	p := res("aws_iam_policy", "ro", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"*"}]}`, 3),
	})
	if f := runRule(iamAdminPolicy{}, p); len(f) != 0 {
		t.Fatalf("scoped actions must not fire, got %d", len(f))
	}
	p2 := res("aws_iam_policy", "ro2", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::b/*"}]}`, 3),
	})
	if f := runRule(iamAdminPolicy{}, p2); len(f) != 0 {
		t.Fatalf("scoped resources must not fire, got %d", len(f))
	}
}

func TestIAMAdmin_DenyStarOK(t *testing.T) {
	p := res("aws_iam_policy", "deny", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`, 3),
	})
	if f := runRule(iamAdminPolicy{}, p); len(f) != 0 {
		t.Fatalf("Deny *:* must not fire, got %d", len(f))
	}
}

func TestIAMAdmin_UnknownNoFinding(t *testing.T) {
	p := res("aws_iam_policy", "x", map[string]ir.Value{"policy": ku(3)})
	if f := runRule(iamAdminPolicy{}, p); len(f) != 0 {
		t.Fatalf("unknown policy must not fire, got %d", len(f))
	}
}

func TestIAMAdmin_MalformedNoFinding(t *testing.T) {
	p := res("aws_iam_policy", "x", map[string]ir.Value{"policy": ks(`{oops`, 3)})
	if f := runRule(iamAdminPolicy{}, p); len(f) != 0 {
		t.Fatalf("malformed policy must not fire, got %d", len(f))
	}
}

func TestIAMAdmin_RolePolicyApplies(t *testing.T) {
	p := res("aws_iam_role_policy", "rp", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`, 3),
	})
	if f := runRule(iamAdminPolicy{}, p); len(f) != 1 {
		t.Fatalf("aws_iam_role_policy should be inspected, got %d", len(f))
	}
}

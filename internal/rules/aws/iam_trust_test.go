package aws

import (
	"reflect"
	"testing"

	"aegis/internal/ir"
)

// policyDoc wraps statements in a minimal IAM policy document.
func policyDoc(stmt string) string {
	return `{"Version":"2012-10-17","Statement":[` + stmt + `]}`
}

func roleWithTrust(trustJSON string, line int) ir.Resource {
	return res("aws_iam_role", "open", map[string]ir.Value{
		"assume_role_policy": ks(trustJSON, line),
	})
}

func TestRoleOpenTrust_Positive(t *testing.T) {
	doc := policyDoc(`{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}`)
	out := (iamRoleOpenTrust{}).CheckAll([]ir.Resource{roleWithTrust(doc, 5)})
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	f := out[0]
	if f.RuleID != "AEGIS-AWS-101" || f.Severity != ir.SeverityCritical {
		t.Fatalf("wrong rule/severity: %+v", f)
	}
	if f.Resource != "aws_iam_role.open" {
		t.Fatalf("wrong resource: %s", f.Resource)
	}
	if len(f.Path) != 1 || f.Path[0].Resource != "aws_iam_role.open" {
		t.Fatalf("expected single-step path on the role: %+v", f.Path)
	}
	if f.Evidence.Attribute != "assume_role_policy" {
		t.Fatalf("wrong evidence attribute: %s", f.Evidence.Attribute)
	}
}

func TestRoleOpenTrust_AWSStarPrincipal(t *testing.T) {
	doc := policyDoc(`{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}`)
	out := (iamRoleOpenTrust{}).CheckAll([]ir.Resource{roleWithTrust(doc, 5)})
	if len(out) != 1 {
		t.Fatalf("expected 1 finding for AWS:*, got %d", len(out))
	}
}

func TestRoleOpenTrust_AWSStarListPrincipal(t *testing.T) {
	doc := policyDoc(`{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::123:root","*"]},"Action":"sts:AssumeRole"}`)
	out := (iamRoleOpenTrust{}).CheckAll([]ir.Resource{roleWithTrust(doc, 5)})
	if len(out) != 1 {
		t.Fatalf("expected 1 finding for AWS list with *, got %d", len(out))
	}
}

func TestRoleOpenTrust_Negative(t *testing.T) {
	docs := []string{
		policyDoc(`{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}`),
		policyDoc(`{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123:role/specific"},"Action":"sts:AssumeRole"}`),
		policyDoc(`{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole"}`),
		// Wildcard scoped by a Condition: cannot prove it is open.
		policyDoc(`{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-abc"}}}`),
	}
	for i, doc := range docs {
		out := (iamRoleOpenTrust{}).CheckAll([]ir.Resource{roleWithTrust(doc, 5)})
		if len(out) != 0 {
			t.Fatalf("case %d: expected no finding, got %+v", i, out)
		}
	}
}

func TestRoleOpenTrust_MalformedAndUnknown(t *testing.T) {
	bad := res("aws_iam_role", "bad", map[string]ir.Value{
		"assume_role_policy": ks(`{not json`, 3),
	})
	unk := res("aws_iam_role", "unk", map[string]ir.Value{
		"assume_role_policy": ku(4),
	})
	absent := res("aws_iam_role", "absent", map[string]ir.Value{})
	out := (iamRoleOpenTrust{}).CheckAll([]ir.Resource{bad, unk, absent})
	if len(out) != 0 {
		t.Fatalf("malformed/unknown/absent must not fire: %+v", out)
	}
}

func TestRoleOpenTrust_Determinism(t *testing.T) {
	doc := policyDoc(`{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}`)
	in := []ir.Resource{
		roleWithTrust(doc, 5),
		res("aws_iam_role", "aaa", map[string]ir.Value{"assume_role_policy": ks(doc, 9)}),
	}
	a := (iamRoleOpenTrust{}).CheckAll(in)
	b := (iamRoleOpenTrust{}).CheckAll(in)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("non-deterministic output:\n%+v\n%+v", a, b)
	}
	if len(a) != 2 || a[0].Resource != "aws_iam_role.aaa" {
		t.Fatalf("expected address-sorted findings: %+v", a)
	}
}

func managedPolicyWithDoc(doc string, line int) ir.Resource {
	return res("aws_iam_policy", "admin", map[string]ir.Value{
		"policy": ks(doc, line),
	})
}

func TestAdminManagedPolicy_Positive(t *testing.T) {
	doc := policyDoc(`{"Effect":"Allow","Action":"*","Resource":"*"}`)
	out := (iamAdminManagedPolicy{}).CheckAll([]ir.Resource{managedPolicyWithDoc(doc, 6)})
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	f := out[0]
	if f.RuleID != "AEGIS-AWS-102" || f.Severity != ir.SeverityHigh {
		t.Fatalf("wrong rule/severity: %+v", f)
	}
	if len(f.Path) != 1 || f.Path[0].Resource != "aws_iam_policy.admin" {
		t.Fatalf("expected single-step path on the policy: %+v", f.Path)
	}
}

func TestAdminManagedPolicy_IamStar(t *testing.T) {
	docs := []string{
		policyDoc(`{"Effect":"Allow","Action":"iam:*","Resource":"*"}`),
		policyDoc(`{"Effect":"Allow","Action":["ec2:Describe*","iam:*"],"Resource":"*"}`),
	}
	for i, doc := range docs {
		out := (iamAdminManagedPolicy{}).CheckAll([]ir.Resource{managedPolicyWithDoc(doc, 6)})
		if len(out) != 1 {
			t.Fatalf("case %d: expected 1 finding for iam:*, got %d", i, len(out))
		}
	}
}

func TestAdminManagedPolicy_Negative(t *testing.T) {
	docs := []string{
		policyDoc(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}`),
		policyDoc(`{"Effect":"Allow","Action":"*","Resource":"arn:aws:s3:::b/*"}`),
		policyDoc(`{"Effect":"Allow","NotAction":"*","Resource":"*"}`),
		policyDoc(`{"Effect":"Deny","Action":"*","Resource":"*"}`),
	}
	for i, doc := range docs {
		out := (iamAdminManagedPolicy{}).CheckAll([]ir.Resource{managedPolicyWithDoc(doc, 6)})
		if len(out) != 0 {
			t.Fatalf("case %d: expected no finding, got %+v", i, out)
		}
	}
}

func TestAdminManagedPolicy_MalformedAndUnknown(t *testing.T) {
	bad := managedPolicyWithDoc(`[broken`, 3)
	unk := res("aws_iam_policy", "unk", map[string]ir.Value{"policy": ku(4)})
	out := (iamAdminManagedPolicy{}).CheckAll([]ir.Resource{bad, unk})
	if len(out) != 0 {
		t.Fatalf("malformed/unknown must not fire: %+v", out)
	}
}

func TestCrossResourceRules_SatisfyInterface(t *testing.T) {
	// Compile-time assertions live in the rule files; this exercises the
	// engine's CrossResourceRule branch for the new rules.
	for _, rule := range []ir.Rule{
		iamRoleOpenTrust{}, iamAdminManagedPolicy{}, rdsPublicPath{}, s3ExfiltrationPath{},
	} {
		if _, ok := rule.(ir.CrossResourceRule); !ok {
			t.Fatalf("%s does not implement CrossResourceRule", rule.ID())
		}
		if rule.ID() == "" || rule.Title() == "" || rule.Description() == "" {
			t.Fatalf("%T has empty metadata", rule)
		}
	}
}

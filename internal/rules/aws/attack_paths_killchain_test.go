package aws

import (
	"testing"

	"aegis/internal/ir"
)

func apStrVal(s string) ir.Value {
	return ir.Value{Raw: s, Known: true, Span: ir.Span{File: "main.tf", StartLine: 1}}
}

func apRefVal(ref string) ir.Value {
	return ir.Value{Raw: ref, Known: true, Ref: ref, Span: ir.Span{File: "main.tf", StartLine: 1}}
}

func apResource(typ, name string, attrs map[string]ir.Value) ir.Resource {
	if attrs == nil {
		attrs = map[string]ir.Value{}
	}
	return ir.Resource{Type: typ, Name: name, Attributes: attrs,
		Span: ir.Span{File: "main.tf", StartLine: 1}}
}

// apIngressBlock builds a nested ingress block like the real IR.
func apIngressBlock(cidr string) ir.Value {
	return ir.Value{
		Raw: []ir.Value{
			{Raw: map[string]ir.Value{"cidr_blocks": apStrVal(cidr)}, Known: true},
		},
		Known: true, Span: ir.Span{File: "main.tf", StartLine: 1},
	}
}

// Full kill-chain: open SG shared by EC2 and RDS.
func TestKillChain629(t *testing.T) {
	resources := []ir.Resource{
		apResource("aws_security_group", "web", map[string]ir.Value{
			"ingress": apIngressBlock("0.0.0.0/0"),
		}),
		apResource("aws_instance", "web", map[string]ir.Value{
			"vpc_security_group_ids": apRefVal("aws_security_group.web.id"),
		}),
		apResource("aws_db_instance", "prod", map[string]ir.Value{
			"vpc_security_group_ids": apRefVal("aws_security_group.web.id"),
		}),
	}
	findings := (killChain{}).CheckAll(resources)
	if len(findings) == 0 {
		t.Fatal("AEGIS-AWS-629: expected kill chain finding")
	}
	f := findings[0]
	if f.RuleID != "AEGIS-AWS-629" {
		t.Errorf("rule ID = %s", f.RuleID)
	}
	if len(f.Path) < 3 {
		t.Errorf("expected 3+ path steps, got %d", len(f.Path))
	}
	// Every step must have a resource and detail (evidence-backed).
	for _, s := range f.Path {
		if s.Resource == "" || s.Detail == "" {
			t.Errorf("path step missing resource/detail: %+v", s)
		}
	}
}

// No chain when nothing is exposed. Strengthened 2026-10-12: the original
// computed hasConcreteEntry and discarded it with `_ =`, asserting nothing.
// A fully private setup may still emit uncertain (medium) chains, but a
// concrete high/critical chain must never appear.
func TestKillChain629NoExposure(t *testing.T) {
	resources := []ir.Resource{
		apResource("aws_security_group", "web", map[string]ir.Value{
			"ingress": apIngressBlock("10.0.0.0/8"),
		}),
		apResource("aws_db_instance", "prod", map[string]ir.Value{
			"vpc_security_group_ids": apRefVal("aws_security_group.web.id"),
		}),
	}
	findings := (killChain{}).CheckAll(resources)
	for _, f := range findings {
		if f.RuleID == "AEGIS-AWS-629" && (f.Severity == ir.SeverityHigh || f.Severity == ir.SeverityCritical) {
			t.Errorf("AEGIS-AWS-629: unexpected %s finding with no internet entry: %+v", f.Severity, f)
		}
	}
}

// TestKillChain629_NoDataStoreQuiet: negative for AEGIS-AWS-629 — with no
// data store in the resource set, no internet-to-data chain can exist.
func TestKillChain629_NoDataStoreQuiet(t *testing.T) {
	resources := []ir.Resource{
		apResource("aws_security_group", "web", map[string]ir.Value{
			"ingress": apIngressBlock("0.0.0.0/0"),
		}),
		apResource("aws_instance", "web", map[string]ir.Value{
			"vpc_security_group_ids": apRefVal("aws_security_group.web.id"),
		}),
	}
	findings := (killChain{}).CheckAll(resources)
	if len(findings) != 0 {
		t.Fatalf("AEGIS-AWS-629: expected 0 findings with no data store, got %d", len(findings))
	}
}

// IAM privilege chain: Lambda with admin policy.
func TestIAMPrivilegeChain630(t *testing.T) {
	resources := []ir.Resource{
		apResource("aws_iam_role", "app", nil),
		apResource("aws_iam_policy", "admin", map[string]ir.Value{
			"policy": apStrVal(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`),
		}),
		apResource("aws_iam_role_policy_attachment", "aa", map[string]ir.Value{
			"role":       apRefVal("aws_iam_role.app.name"),
			"policy_arn": apRefVal("aws_iam_policy.admin.arn"),
		}),
		apResource("aws_lambda_function", "api", map[string]ir.Value{
			"role": apRefVal("aws_iam_role.app.arn"),
		}),
	}
	findings := (iamPrivilegeChain{}).CheckAll(resources)
	if len(findings) == 0 {
		t.Fatal("AEGIS-AWS-630: expected IAM privilege chain finding")
	}
	f := findings[0]
	if f.RuleID != "AEGIS-AWS-630" {
		t.Errorf("rule ID = %s", f.RuleID)
	}
	if len(f.Path) != 3 {
		t.Errorf("expected 3 path steps (role→policy→workload), got %d", len(f.Path))
	}
}

// No IAM chain when policy is least-privilege.
func TestIAMPrivilegeChain630Clean(t *testing.T) {
	resources := []ir.Resource{
		apResource("aws_iam_role", "app", nil),
		apResource("aws_iam_policy", "scoped", map[string]ir.Value{
			"policy": apStrVal(`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::app/*"}]}`),
		}),
		apResource("aws_iam_role_policy_attachment", "aa", map[string]ir.Value{
			"role":       apRefVal("aws_iam_role.app.name"),
			"policy_arn": apRefVal("aws_iam_policy.scoped.arn"),
		}),
		apResource("aws_lambda_function", "api", map[string]ir.Value{
			"role": apRefVal("aws_iam_role.app.arn"),
		}),
	}
	findings := (iamPrivilegeChain{}).CheckAll(resources)
	if len(findings) != 0 {
		t.Errorf("expected no findings for least-privilege policy, got %d", len(findings))
	}
}

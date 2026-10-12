package aws

import (
	"testing"

	"aegis/internal/adapter/terraform"
	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-AWS-501: privilege escalation (create policy + attach policy)
// ---------------------------------------------------------------------------

func Test501_CreateAndAttachFires(t *testing.T) {
	p := res("aws_iam_policy", "esc", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":["iam:CreatePolicy","iam:AttachRolePolicy"],"Resource":"*"}]}`, 3),
	})
	f := runRule(iamPrivilegeEscalation{}, p)
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-501" {
		t.Fatalf("expected 1 finding for 501, got %+v", f)
	}
	if f[0].Severity != ir.SeverityCritical {
		t.Fatalf("501 must be critical, got %s", f[0].Severity)
	}
	if f[0].Evidence.Attribute != "policy" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("501 finding must carry policy evidence, got %+v", f[0].Evidence)
	}
}

func Test501_SplitStatementsFires(t *testing.T) {
	// Authoring and attachment in separate statements still escalates.
	p := res("aws_iam_policy", "esc", map[string]ir.Value{
		"policy": ks(`{"Statement":[
			{"Effect":"Allow","Action":"iam:PutRolePolicy","Resource":"*"},
			{"Effect":"Allow","Action":"iam:AttachUserPolicy","Resource":"*"}]}`, 3),
	})
	if f := runRule(iamPrivilegeEscalation{}, p); len(f) != 1 {
		t.Fatalf("expected 501 to fire across statements, got %d", len(f))
	}
}

func Test501_WildcardActionsFire(t *testing.T) {
	p := res("aws_iam_role_policy", "esc", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":["iam:Create*","iam:Attach*"],"Resource":"*"}]}`, 3),
	})
	if f := runRule(iamPrivilegeEscalation{}, p); len(f) != 1 {
		t.Fatalf("expected 501 to fire on iam:Create*+iam:Attach*, got %d", len(f))
	}
}

func Test501_OnlyOneSideSilent(t *testing.T) {
	p := res("aws_iam_policy", "half", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":"iam:CreatePolicy","Resource":"*"}]}`, 3),
	})
	if f := runRule(iamPrivilegeEscalation{}, p); len(f) != 0 {
		t.Fatalf("501 must not fire with only authoring, got %d", len(f))
	}
}

func Test501_LeastPrivilegeSilent(t *testing.T) {
	p := res("aws_iam_policy", "safe", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::app/*"}]}`, 3),
	})
	if f := runRule(iamPrivilegeEscalation{}, p); len(f) != 0 {
		t.Fatalf("501 must not fire on least-privilege, got %d", len(f))
	}
}

func Test501_UnparseableSilent(t *testing.T) {
	p := res("aws_iam_policy", "bad", map[string]ir.Value{
		"policy": ks(`{not valid json`, 3),
	})
	if f := runRule(iamPrivilegeEscalation{}, p); len(f) != 0 {
		t.Fatalf("501 must not fire on unparseable policy, got %d", len(f))
	}
}

func Test501_UnknownSilent(t *testing.T) {
	p := res("aws_iam_policy", "unk", map[string]ir.Value{"policy": ku(3)})
	if f := runRule(iamPrivilegeEscalation{}, p); len(f) != 0 {
		t.Fatalf("501 must not fire on unknown policy, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-502: iam:PassRole on * + compute launch primitive
// ---------------------------------------------------------------------------

func Test502_PassRoleStarPlusRunInstancesFires(t *testing.T) {
	p := res("aws_iam_policy", "esc", map[string]ir.Value{
		"policy": ks(`{"Statement":[
			{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"},
			{"Effect":"Allow","Action":"ec2:RunInstances","Resource":"*"}]}`, 3),
	})
	f := runRule(iamPassRoleEscalation{}, p)
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-502" {
		t.Fatalf("expected 1 finding for 502, got %+v", f)
	}
	if f[0].Severity != ir.SeverityCritical {
		t.Fatalf("502 must be critical, got %s", f[0].Severity)
	}
}

func Test502_PassRoleStarPlusLambdaFires(t *testing.T) {
	p := res("aws_iam_user_policy", "esc", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":["iam:PassRole","lambda:CreateFunction"],"Resource":"*"}]}`, 3),
	})
	if f := runRule(iamPassRoleEscalation{}, p); len(f) != 1 {
		t.Fatalf("expected 502 to fire on PassRole+lambda:CreateFunction, got %d", len(f))
	}
}

func Test502_PassRoleScopedSilent(t *testing.T) {
	// PassRole scoped to a single role ARN is not the 502 pattern.
	p := res("aws_iam_policy", "scoped", map[string]ir.Value{
		"policy": ks(`{"Statement":[
			{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::123456789012:role/app"},
			{"Effect":"Allow","Action":"ec2:RunInstances","Resource":"*"}]}`, 3),
	})
	if f := runRule(iamPassRoleEscalation{}, p); len(f) != 0 {
		t.Fatalf("502 must not fire when PassRole is scoped, got %d", len(f))
	}
}

func Test502_PassRoleAloneSilent(t *testing.T) {
	p := res("aws_iam_policy", "half", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}]}`, 3),
	})
	if f := runRule(iamPassRoleEscalation{}, p); len(f) != 0 {
		t.Fatalf("502 must not fire without a launch primitive, got %d", len(f))
	}
}

func Test502_UnparseableSilent(t *testing.T) {
	p := res("aws_iam_policy", "bad", map[string]ir.Value{"policy": ks(`[`, 3)})
	if f := runRule(iamPassRoleEscalation{}, p); len(f) != 0 {
		t.Fatalf("502 must not fire on unparseable policy, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-503: data exfiltration pairs
// ---------------------------------------------------------------------------

func Test503_S3ExfilPairFires(t *testing.T) {
	p := res("aws_iam_policy", "exfil", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"*"}]}`, 3),
	})
	f := runRule(iamDataExfiltration{}, p)
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-503" {
		t.Fatalf("expected 1 finding for 503, got %+v", f)
	}
	if f[0].Severity != ir.SeverityHigh {
		t.Fatalf("503 must be high, got %s", f[0].Severity)
	}
}

func Test503_SnapshotShareFires(t *testing.T) {
	p := res("aws_iam_policy", "exfil", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":["rds:CreateDBSnapshot","rds:ModifyDBSnapshotAttribute"],"Resource":"*"}]}`, 3),
	})
	if f := runRule(iamDataExfiltration{}, p); len(f) != 1 {
		t.Fatalf("expected 503 to fire on RDS snapshot share pair, got %d", len(f))
	}
	p2 := res("aws_iam_policy", "exfil2", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":["ec2:CreateSnapshot","ec2:ModifySnapshotAttribute"],"Resource":"*"}]}`, 3),
	})
	if f := runRule(iamDataExfiltration{}, p2); len(f) != 1 {
		t.Fatalf("expected 503 to fire on EBS snapshot share pair, got %d", len(f))
	}
}

func Test503_ScopedS3Silent(t *testing.T) {
	// Same pair scoped to one bucket is normal backup behavior.
	p := res("aws_iam_policy", "scoped", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::app/*"}]}`, 3),
	})
	if f := runRule(iamDataExfiltration{}, p); len(f) != 0 {
		t.Fatalf("503 must not fire when S3 pair is resource-scoped, got %d", len(f))
	}
}

func Test503_HalfPairSilent(t *testing.T) {
	p := res("aws_iam_policy", "half", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`, 3),
	})
	if f := runRule(iamDataExfiltration{}, p); len(f) != 0 {
		t.Fatalf("503 must not fire on a half pair, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-504: IAM permissions management on *
// ---------------------------------------------------------------------------

func Test504_IamWriteOnStarFires(t *testing.T) {
	p := res("aws_iam_policy", "mgmt", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":"iam:PutRolePolicy","Resource":"*"}]}`, 3),
	})
	f := runRule(iamPermissionsMgmt{}, p)
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-504" {
		t.Fatalf("expected 1 finding for 504, got %+v", f)
	}
	if f[0].Severity != ir.SeverityHigh {
		t.Fatalf("504 must be high, got %s", f[0].Severity)
	}
}

func Test504_IamStarFires(t *testing.T) {
	p := res("aws_iam_policy", "mgmt", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}`, 3),
	})
	if f := runRule(iamPermissionsMgmt{}, p); len(f) != 1 {
		t.Fatalf("expected 504 to fire on iam:*, got %d", len(f))
	}
}

func Test504_ReadOnlySilent(t *testing.T) {
	p := res("aws_iam_policy", "ro", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":["iam:GetRole","iam:ListUsers","iam:GenerateCredentialReport"],"Resource":"*"}]}`, 3),
	})
	if f := runRule(iamPermissionsMgmt{}, p); len(f) != 0 {
		t.Fatalf("504 must not fire on read-only IAM actions, got %d", len(f))
	}
}

func Test504_ScopedSilent(t *testing.T) {
	p := res("aws_iam_policy", "scoped", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":"iam:PutRolePolicy","Resource":"arn:aws:iam::123456789012:role/app"}]}`, 3),
	})
	if f := runRule(iamPermissionsMgmt{}, p); len(f) != 0 {
		t.Fatalf("504 must not fire when scoped to a role, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-505: write actions on *
// ---------------------------------------------------------------------------

func Test505_WriteOnStarFires(t *testing.T) {
	p := res("aws_iam_policy", "w", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}`, 3),
	})
	f := runRule(iamWriteNoConstraints{}, p)
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-505" {
		t.Fatalf("expected 1 finding for 505, got %+v", f)
	}
	if f[0].Severity != ir.SeverityHigh {
		t.Fatalf("505 must be high, got %s", f[0].Severity)
	}
}

func Test505_ServiceWildcardFires(t *testing.T) {
	// ec2:* includes every write verb, so it fires 505 on "*".
	p := res("aws_iam_policy", "w", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"}]}`, 3),
	})
	if f := runRule(iamWriteNoConstraints{}, p); len(f) != 1 {
		t.Fatalf("expected 505 to fire on ec2:* on *, got %d", len(f))
	}
}

func Test505_BlanketStarDeferred(t *testing.T) {
	// Action "*" on "*" is AEGIS-AWS-006's case; 505 must stay silent.
	p := res("aws_iam_policy", "admin", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`, 3),
	})
	if f := runRule(iamWriteNoConstraints{}, p); len(f) != 0 {
		t.Fatalf("505 must defer blanket *:* to rule 006, got %d", len(f))
	}
}

func Test505_ReadOnlySilent(t *testing.T) {
	p := res("aws_iam_policy", "ro", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":"*"}]}`, 3),
	})
	if f := runRule(iamWriteNoConstraints{}, p); len(f) != 0 {
		t.Fatalf("505 must not fire on read-only actions, got %d", len(f))
	}
}

func Test505_ScopedWriteSilent(t *testing.T) {
	p := res("aws_iam_policy", "scoped", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"arn:aws:s3:::app/*"}]}`, 3),
	})
	if f := runRule(iamWriteNoConstraints{}, p); len(f) != 0 {
		t.Fatalf("505 must not fire on scoped writes, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// Shared contract checks
// ---------------------------------------------------------------------------

func Test501_505_AppliesTo(t *testing.T) {
	for _, rule := range IAMPrivilegeRules() {
		for _, typ := range []string{"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy"} {
			if !rule.AppliesTo(typ) {
				t.Fatalf("%s must apply to %s", rule.ID(), typ)
			}
		}
		if rule.AppliesTo("aws_s3_bucket") {
			t.Fatalf("%s must not apply to aws_s3_bucket", rule.ID())
		}
	}
}

func Test501_505_IDsInOrder(t *testing.T) {
	rules := IAMPrivilegeRules()
	want := []string{"AEGIS-AWS-501", "AEGIS-AWS-502", "AEGIS-AWS-503", "AEGIS-AWS-504", "AEGIS-AWS-505"}
	if len(rules) != len(want) {
		t.Fatalf("expected %d rules, got %d", len(want), len(rules))
	}
	for i, r := range rules {
		if r.ID() != want[i] {
			t.Fatalf("rule %d: expected %s, got %s", i, want[i], r.ID())
		}
	}
}

func Test501_505_Severities(t *testing.T) {
	want := map[string]ir.Severity{
		"AEGIS-AWS-501": ir.SeverityCritical,
		"AEGIS-AWS-502": ir.SeverityCritical,
		"AEGIS-AWS-503": ir.SeverityHigh,
		"AEGIS-AWS-504": ir.SeverityHigh,
		"AEGIS-AWS-505": ir.SeverityHigh,
	}
	for _, r := range IAMPrivilegeRules() {
		if r.Severity() != want[r.ID()] {
			t.Fatalf("%s: expected severity %s, got %s", r.ID(), want[r.ID()], r.Severity())
		}
	}
}

func Test501_505_DenyOnlySilent(t *testing.T) {
	p := res("aws_iam_policy", "deny", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Deny","Action":["iam:CreatePolicy","iam:AttachRolePolicy"],"Resource":"*"}]}`, 3),
	})
	for _, r := range IAMPrivilegeRules() {
		if f := runRule(r, p); len(f) != 0 {
			t.Fatalf("%s must not fire on Deny statements, got %d", r.ID(), len(f))
		}
	}
}

func Test501_505_NotActionSilent(t *testing.T) {
	// NotAction semantics need the full action space: cannot decide -> silent.
	p := res("aws_iam_policy", "na", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","NotAction":"iam:Get*","Resource":"*"}]}`, 3),
	})
	for _, r := range IAMPrivilegeRules() {
		if f := runRule(r, p); len(f) != 0 {
			t.Fatalf("%s must not fire on NotAction statements, got %d", r.ID(), len(f))
		}
	}
}

// ---------------------------------------------------------------------------
// Regression: held-out iam-escalation corpus uses single-line object
// constructors without commas ({ Effect = "Allow" Action = ... }), which the
// strict HCL parser rejects. The adapter's lenient recovery must restore the
// policy so 502 fires end-to-end.
// ---------------------------------------------------------------------------

func Test502_EndToEndMissingCommaHCL(t *testing.T) {
	src := `resource "aws_iam_policy" "v" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow" Action = "iam:PassRole" Resource = "*" },
      { Effect = "Allow" Action = "ec2:RunInstances" Resource = "*" }
    ]
  })
}
`
	mod, _, err := (terraform.Adapter{}).ParseModule("t.tf", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(mod.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(mod.Resources))
	}
	f := (iamPassRoleEscalation{}).Check(mod.Resources[0])
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-502" {
		t.Fatalf("expected 502 to fire end-to-end, got %+v", f)
	}
}

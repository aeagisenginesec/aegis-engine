package aws

import (
	"testing"

	"aegis/internal/ir"
)

// testRes builds a minimal resource for rule tests.
func fgRes(typ, name string, attrs map[string]ir.Value) ir.Resource {
	return ir.Resource{
		Type:       typ,
		Name:       name,
		Provider:   "aws",
		Attributes: attrs,
		Span:       ir.Span{File: "test.tf", StartLine: 1, StartCol: 1, EndLine: 5, EndCol: 1},
	}
}

func fgStr(s string) ir.Value {
	return ir.Value{Raw: s, Known: true, Span: ir.Span{File: "test.tf"}}
}

func fgBool(b bool) ir.Value {
	return ir.Value{Raw: b, Known: true, Span: ir.Span{File: "test.tf"}}
}

func fgUnknown() ir.Value {
	return ir.Value{Known: false, Span: ir.Span{File: "test.tf"}}
}

func fgBlock(m map[string]ir.Value) ir.Value {
	return ir.Value{Raw: []ir.Value{{Raw: m, Known: true}}, Known: true}
}

func fgList(items ...ir.Value) ir.Value {
	return ir.Value{Raw: items, Known: true}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-540: RDS IAM auth (mysql/postgres scoped)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// AEGIS-AWS-541: Launch configuration IMDSv1
// ---------------------------------------------------------------------------

func Test541_AbsentMetadataOptions(t *testing.T) {
	r := fgRes("aws_launch_configuration", "lc", map[string]ir.Value{})
	if got := (launchConfigNoIMDSv2{}).Check(r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
}

func Test541_OptionalTokens(t *testing.T) {
	r := fgRes("aws_launch_configuration", "lc", map[string]ir.Value{
		"metadata_options": fgBlock(map[string]ir.Value{"http_tokens": fgStr("optional")}),
	})
	got := (launchConfigNoIMDSv2{}).Check(r)
	if len(got) != 1 || got[0].Evidence.Actual != "optional" {
		t.Fatalf("expected 1 finding with actual=optional, got %+v", got)
	}
}

func Test541_RequiredSilent(t *testing.T) {
	r := fgRes("aws_launch_configuration", "lc", map[string]ir.Value{
		"metadata_options": fgBlock(map[string]ir.Value{"http_tokens": fgStr("required")}),
	})
	if got := (launchConfigNoIMDSv2{}).Check(r); len(got) != 0 {
		t.Fatalf("expected silent, got %d", len(got))
	}
}

func Test541_UnknownBlockSilent(t *testing.T) {
	r := fgRes("aws_launch_configuration", "lc", map[string]ir.Value{
		"metadata_options": fgUnknown(),
	})
	if got := (launchConfigNoIMDSv2{}).Check(r); len(got) != 0 {
		t.Fatalf("expected silent for unknown block, got %d", len(got))
	}
}

func Test541_WrongResourceType(t *testing.T) {
	if (launchConfigNoIMDSv2{}).AppliesTo("aws_instance") {
		t.Fatal("541 must not apply to aws_instance (204 covers it)")
	}
	if !(launchConfigNoIMDSv2{}).AppliesTo("aws_launch_configuration") {
		t.Fatal("541 must apply to aws_launch_configuration")
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-542: Lambda without VPC
// ---------------------------------------------------------------------------

func Test542_NoVPCConfig(t *testing.T) {
	r := fgRes("aws_lambda_function", "fn", map[string]ir.Value{})
	if got := (lambdaNoVPC{}).Check(r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
}

func Test542_WithVPCConfigSilent(t *testing.T) {
	r := fgRes("aws_lambda_function", "fn", map[string]ir.Value{
		"vpc_config": fgBlock(map[string]ir.Value{
			"subnet_ids":         fgList(fgStr("subnet-1")),
			"security_group_ids": fgList(fgStr("sg-1")),
		}),
	})
	if got := (lambdaNoVPC{}).Check(r); len(got) != 0 {
		t.Fatalf("expected silent, got %d", len(got))
	}
}

func Test542_UnknownVPCSilent(t *testing.T) {
	r := fgRes("aws_lambda_function", "fn", map[string]ir.Value{
		"vpc_config": fgUnknown(),
	})
	if got := (lambdaNoVPC{}).Check(r); len(got) != 0 {
		t.Fatalf("expected silent for unknown vpc_config, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-543: RDS without log exports
// ---------------------------------------------------------------------------

func Test543_AbsentFires(t *testing.T) {
	r := fgRes("aws_db_instance", "db", map[string]ir.Value{})
	got := (rdsNoLogExports{}).Check(r)
	if len(got) != 1 || got[0].Severity != ir.SeverityLow {
		t.Fatalf("expected 1 low finding, got %+v", got)
	}
}

func Test543_EmptyListFires(t *testing.T) {
	r := fgRes("aws_db_instance", "db", map[string]ir.Value{
		"enabled_cloudwatch_logs_exports": fgList(),
	})
	if got := (rdsNoLogExports{}).Check(r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
}

func Test543_WithExportsSilent(t *testing.T) {
	r := fgRes("aws_db_instance", "db", map[string]ir.Value{
		"enabled_cloudwatch_logs_exports": fgList(fgStr("error")),
	})
	if got := (rdsNoLogExports{}).Check(r); len(got) != 0 {
		t.Fatalf("expected silent, got %d", len(got))
	}
}

func Test543_UnknownSilent(t *testing.T) {
	r := fgRes("aws_db_instance", "db", map[string]ir.Value{
		"enabled_cloudwatch_logs_exports": fgUnknown(),
	})
	if got := (rdsNoLogExports{}).Check(r); len(got) != 0 {
		t.Fatalf("expected silent for unknown, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-544: RDS without auto minor upgrades
// ---------------------------------------------------------------------------

func Test544_AbsentQuiet(t *testing.T) {
	// Absent: the AWS API + provider default is TRUE, so absent means
	// upgrades ARE applied. Only explicit false fires.
	r := fgRes("aws_db_instance", "db", map[string]ir.Value{})
	if got := (rdsNoAutoMinorUpgrade{}).Check(r); len(got) != 0 {
		t.Fatalf("expected silent on absent (default true), got %+v", got)
	}
}

func Test544_ExplicitFalse(t *testing.T) {
	r := fgRes("aws_db_instance", "db", map[string]ir.Value{
		"auto_minor_version_upgrade": fgBool(false),
	})
	got := (rdsNoAutoMinorUpgrade{}).Check(r)
	if len(got) != 1 || got[0].Evidence.Actual != "false" {
		t.Fatalf("expected 1 finding with actual=false, got %+v", got)
	}
}

func Test544_EnabledSilent(t *testing.T) {
	r := fgRes("aws_db_instance", "db", map[string]ir.Value{
		"auto_minor_version_upgrade": fgBool(true),
	})
	if got := (rdsNoAutoMinorUpgrade{}).Check(r); len(got) != 0 {
		t.Fatalf("expected silent, got %d", len(got))
	}
}

func Test544_UnknownSilent(t *testing.T) {
	r := fgRes("aws_db_instance", "db", map[string]ir.Value{
		"auto_minor_version_upgrade": fgUnknown(),
	})
	if got := (rdsNoAutoMinorUpgrade{}).Check(r); len(got) != 0 {
		t.Fatalf("expected silent for unknown, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// Pack wiring
// ---------------------------------------------------------------------------

func TestFinalGapRules_InIDOrder(t *testing.T) {
	rules := FinalGapRules()
	want := []string{
		"AEGIS-AWS-541", "AEGIS-AWS-542",
		"AEGIS-AWS-543", "AEGIS-AWS-544",
	}
	if len(rules) != len(want) {
		t.Fatalf("expected %d rules, got %d", len(want), len(rules))
	}
	for i, r := range rules {
		if r.ID() != want[i] {
			t.Fatalf("rule %d: expected %s, got %s", i, want[i], r.ID())
		}
	}
}

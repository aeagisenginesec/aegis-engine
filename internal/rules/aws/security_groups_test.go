package aws

import (
	"testing"

	"aegis/internal/ir"
)

// AEGIS-AWS-004: Security group ingress open to the world.

func TestSGIngress_OpenCIDRFires(t *testing.T) {
	sg := res("aws_security_group", "web", map[string]ir.Value{
		"ingress": blks(3, blk("cidr_blocks", strList(4, "0.0.0.0/0"), "from_port", kv(false, 4))),
	})
	f := runRule(sgOpenIngress{}, sg)
	if len(f) != 1 || f[0].Severity != "high" {
		t.Fatalf("expected 1 high finding, got %+v", f)
	}
	if f[0].Evidence.Attribute != "ingress.cidr_blocks" || f[0].Evidence.Actual != "0.0.0.0/0" {
		t.Fatalf("wrong evidence: %+v", f[0].Evidence)
	}
}

func TestSGIngress_RestrictedOK(t *testing.T) {
	sg := res("aws_security_group", "web", map[string]ir.Value{
		"ingress": blks(3, blk("cidr_blocks", strList(4, "10.0.0.0/8"))),
	})
	if f := runRule(sgOpenIngress{}, sg); len(f) != 0 {
		t.Fatalf("restricted CIDR must not fire, got %d", len(f))
	}
}

func TestSGIngress_NoIngressBlocksOK(t *testing.T) {
	sg := res("aws_security_group", "web", nil)
	if f := runRule(sgOpenIngress{}, sg); len(f) != 0 {
		t.Fatalf("no ingress blocks must not fire, got %d", len(f))
	}
}

func TestSGIngress_UnknownCIDRsNoFinding(t *testing.T) {
	sg := res("aws_security_group", "web", map[string]ir.Value{
		"ingress": blks(3, blk("cidr_blocks", ku(4))),
	})
	if f := runRule(sgOpenIngress{}, sg); len(f) != 0 {
		t.Fatalf("unknown cidr_blocks must not fire, got %d", len(f))
	}
}

func TestSGIngress_StandaloneRuleFires(t *testing.T) {
	r := res("aws_security_group_rule", "ssh", map[string]ir.Value{
		"type":        ks("ingress", 2),
		"cidr_blocks": strList(3, "0.0.0.0/0"),
	})
	if f := runRule(sgOpenIngress{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestSGIngress_StandaloneRuleWrongTypeNoFinding(t *testing.T) {
	r := res("aws_security_group_rule", "out", map[string]ir.Value{
		"type":        ks("egress", 2),
		"cidr_blocks": strList(3, "0.0.0.0/0"),
	})
	if f := runRule(sgOpenIngress{}, r); len(f) != 0 {
		t.Fatalf("egress-type rule must not fire ingress rule, got %d", len(f))
	}
}

func TestSGIngress_VPCRuleFires(t *testing.T) {
	r := res("aws_vpc_security_group_ingress_rule", "http", map[string]ir.Value{
		"cidr_ipv4": ks("0.0.0.0/0", 2),
	})
	f := runRule(sgOpenIngress{}, r)
	if len(f) != 1 || f[0].Evidence.Attribute != "cidr_ipv4" {
		t.Fatalf("expected 1 finding on cidr_ipv4, got %+v", f)
	}
}

func TestSGIngress_VPCRuleUnknownNoFinding(t *testing.T) {
	r := res("aws_vpc_security_group_ingress_rule", "http", map[string]ir.Value{
		"cidr_ipv4": ku(2),
	})
	if f := runRule(sgOpenIngress{}, r); len(f) != 0 {
		t.Fatalf("unknown cidr_ipv4 must not fire, got %d", len(f))
	}
}

// AEGIS-AWS-005: Security group egress open to the world.

func TestSGEgress_OpenCIDRFires(t *testing.T) {
	sg := res("aws_security_group", "web", map[string]ir.Value{
		"egress": blks(3, blk("cidr_blocks", strList(4, "0.0.0.0/0"))),
	})
	f := runRule(sgOpenEgress{}, sg)
	if len(f) != 1 || f[0].Severity != "medium" {
		t.Fatalf("expected 1 medium finding, got %+v", f)
	}
	if f[0].Evidence.Attribute != "egress.cidr_blocks" {
		t.Fatalf("wrong evidence attribute: %s", f[0].Evidence.Attribute)
	}
}

func TestSGEgress_IngressNotFlagged(t *testing.T) {
	sg := res("aws_security_group", "web", map[string]ir.Value{
		"ingress": blks(3, blk("cidr_blocks", strList(4, "0.0.0.0/0"))),
	})
	if f := runRule(sgOpenEgress{}, sg); len(f) != 0 {
		t.Fatalf("ingress block must not fire egress rule, got %d", len(f))
	}
}

func TestSGEgress_StandaloneEgressRuleFires(t *testing.T) {
	r := res("aws_security_group_rule", "out", map[string]ir.Value{
		"type":        ks("egress", 2),
		"cidr_blocks": strList(3, "0.0.0.0/0"),
	})
	if f := runRule(sgOpenEgress{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

// CheckAll-level tests: inline-group egress findings require attachment
// evidence; standalone groups carry no traffic and stay quiet.

func TestSGEgress_CheckAllStandaloneQuiet(t *testing.T) {
	sg := res("aws_security_group", "web", map[string]ir.Value{
		"egress": blks(3, blk("cidr_blocks", strList(4, "0.0.0.0/0"))),
	})
	if f := (sgOpenEgress{}).CheckAll([]ir.Resource{sg}); len(f) != 0 {
		t.Fatalf("standalone SG must stay quiet for 005, got %+v", f)
	}
}

func TestSGEgress_CheckAllAttachedFires(t *testing.T) {
	sg := res("aws_security_group", "web", map[string]ir.Value{
		"egress": blks(3, blk("cidr_blocks", strList(4, "0.0.0.0/0"))),
	})
	inst := res("aws_instance", "web", map[string]ir.Value{
		"vpc_security_group_ids": {Raw: []ir.Value{
			{Known: false, Ref: "aws_security_group.web.id", Span: spanAt(5)},
		}, Known: false, Span: spanAt(5)},
	})
	f := (sgOpenEgress{}).CheckAll([]ir.Resource{sg, inst})
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-005" {
		t.Fatalf("attached SG must fire 005, got %+v", f)
	}
}

func TestSGEgress_CheckAllSGToSGRefNotAttachment(t *testing.T) {
	sg := res("aws_security_group", "db", map[string]ir.Value{
		"egress": blks(3, blk("cidr_blocks", strList(4, "0.0.0.0/0"))),
	})
	other := res("aws_security_group", "app", map[string]ir.Value{
		"ingress": blks(3, blk("cidr_blocks", strList(4, "10.0.0.0/8"))),
	})
	// An SG-to-SG reference lives in a rule resource, not a workload.
	rule := res("aws_security_group_rule", "app2db", map[string]ir.Value{
		"type":                     ks("ingress", 2),
		"security_group_id":        {Known: false, Ref: "aws_security_group.app.id", Span: spanAt(2)},
		"source_security_group_id": {Known: false, Ref: "aws_security_group.db.id", Span: spanAt(2)},
		"cidr_blocks":              strList(3, "10.0.0.0/8"),
	})
	_ = other
	if f := (sgOpenEgress{}).CheckAll([]ir.Resource{sg, other, rule}); len(f) != 0 {
		t.Fatalf("SG-to-SG reference must not count as attachment, got %+v", f)
	}
}

func TestSGEgress_CheckAllStandaloneRuleFires(t *testing.T) {
	r := res("aws_security_group_rule", "out", map[string]ir.Value{
		"type":        ks("egress", 2),
		"cidr_blocks": strList(3, "0.0.0.0/0"),
	})
	if f := (sgOpenEgress{}).CheckAll([]ir.Resource{r}); len(f) != 1 {
		t.Fatalf("standalone egress-rule resource must fire 005, got %+v", f)
	}
}

func TestSGEgress_UnknownNoFinding(t *testing.T) {
	sg := res("aws_security_group", "web", map[string]ir.Value{
		"egress": blks(3, blk("cidr_blocks", ku(4))),
	})
	if f := runRule(sgOpenEgress{}, sg); len(f) != 0 {
		t.Fatalf("unknown egress cidr_blocks must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-858: Security group exposes database port to the internet
// ---------------------------------------------------------------------------

// knum builds a known numeric value (HCL numbers arrive as float64).
func knum(f float64, line int) ir.Value {
	return ir.Value{Raw: f, Known: true, Span: spanAt(line)}
}

func TestSGDBPort_InlinePostgresFires(t *testing.T) {
	sg := res("aws_security_group", "db", map[string]ir.Value{
		"ingress": blks(3, blk(
			"from_port", knum(5432, 4),
			"to_port", knum(5432, 4),
			"protocol", ks("tcp", 4),
			"cidr_blocks", strList(4, "0.0.0.0/0"),
		)),
	})
	f := runRule(sgDatabasePort{}, sg)
	if len(f) != 1 || f[0].RuleID != "AEGIS-AWS-858" {
		t.Fatalf("expected 1 AEGIS-AWS-858 finding, got %+v", f)
	}
	if f[0].Evidence.Actual != "0.0.0.0/0 to port 5432" {
		t.Fatalf("wrong evidence actual: %q", f[0].Evidence.Actual)
	}
}

func TestSGDBPort_InlineWebPortNoFinding(t *testing.T) {
	sg := res("aws_security_group", "web", map[string]ir.Value{
		"ingress": blks(3, blk(
			"from_port", knum(443, 4),
			"to_port", knum(443, 4),
			"protocol", ks("tcp", 4),
			"cidr_blocks", strList(4, "0.0.0.0/0"),
		)),
	})
	if f := runRule(sgDatabasePort{}, sg); len(f) != 0 {
		t.Fatalf("world-open 443 is not a database port, got %d findings", len(f))
	}
}

func TestSGDBPort_InlineRangeCoveringDBFires(t *testing.T) {
	sg := res("aws_security_group", "db", map[string]ir.Value{
		"ingress": blks(3, blk(
			"from_port", knum(5000, 4),
			"to_port", knum(6000, 4),
			"protocol", ks("tcp", 4),
			"cidr_blocks", strList(4, "0.0.0.0/0"),
		)),
	})
	if f := runRule(sgDatabasePort{}, sg); len(f) != 1 {
		t.Fatalf("range 5000-6000 covers 5432, expected 1 finding, got %d", len(f))
	}
}

func TestSGDBPort_InlineRestrictedCIDRNoFinding(t *testing.T) {
	sg := res("aws_security_group", "db", map[string]ir.Value{
		"ingress": blks(3, blk(
			"from_port", knum(5432, 4),
			"to_port", knum(5432, 4),
			"protocol", ks("tcp", 4),
			"cidr_blocks", strList(4, "10.0.0.0/8"),
		)),
	})
	if f := runRule(sgDatabasePort{}, sg); len(f) != 0 {
		t.Fatalf("5432 from a restricted CIDR must not fire, got %d", len(f))
	}
}

func TestSGDBPort_InlineAllProtocolFires(t *testing.T) {
	sg := res("aws_security_group", "all", map[string]ir.Value{
		"ingress": blks(3, blk(
			"from_port", knum(0, 4),
			"to_port", knum(0, 4),
			"protocol", ks("-1", 4),
			"cidr_blocks", strList(4, "0.0.0.0/0"),
		)),
	})
	f := runRule(sgDatabasePort{}, sg)
	if len(f) != 1 {
		t.Fatalf("protocol -1 to the world exposes DB ports, expected 1, got %d", len(f))
	}
	if f[0].Evidence.Actual != "0.0.0.0/0 to all ports" {
		t.Fatalf("wrong evidence actual: %q", f[0].Evidence.Actual)
	}
}

func TestSGDBPort_InlineIPv6Fires(t *testing.T) {
	sg := res("aws_security_group", "db", map[string]ir.Value{
		"ingress": blks(3, blk(
			"from_port", knum(3306, 4),
			"to_port", knum(3306, 4),
			"protocol", ks("tcp", 4),
			"ipv6_cidr_blocks", strList(4, "::/0"),
		)),
	})
	f := runRule(sgDatabasePort{}, sg)
	if len(f) != 1 || f[0].Evidence.Attribute != "ingress.ipv6_cidr_blocks" {
		t.Fatalf("expected 1 finding on ingress.ipv6_cidr_blocks, got %+v", f)
	}
}

func TestSGDBPort_InlineUnknownPortsNoFinding(t *testing.T) {
	sg := res("aws_security_group", "db", map[string]ir.Value{
		"ingress": blks(3, blk(
			"from_port", ku(4),
			"to_port", ku(4),
			"protocol", ks("tcp", 4),
			"cidr_blocks", strList(4, "0.0.0.0/0"),
		)),
	})
	if f := runRule(sgDatabasePort{}, sg); len(f) != 0 {
		t.Fatalf("unresolved ports must not fire, got %d", len(f))
	}
}

func TestSGDBPort_StandaloneRuleFires(t *testing.T) {
	r := res("aws_security_group_rule", "redis", map[string]ir.Value{
		"type":        ks("ingress", 2),
		"protocol":    ks("tcp", 2),
		"from_port":   knum(6379, 2),
		"to_port":     knum(6379, 2),
		"cidr_blocks": strList(3, "0.0.0.0/0"),
	})
	if f := runRule(sgDatabasePort{}, r); len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
}

func TestSGDBPort_StandaloneRuleEgressNoFinding(t *testing.T) {
	r := res("aws_security_group_rule", "out", map[string]ir.Value{
		"type":        ks("egress", 2),
		"protocol":    ks("tcp", 2),
		"from_port":   knum(5432, 2),
		"to_port":     knum(5432, 2),
		"cidr_blocks": strList(3, "0.0.0.0/0"),
	})
	if f := runRule(sgDatabasePort{}, r); len(f) != 0 {
		t.Fatalf("egress-type rule must not fire the ingress DB rule, got %d", len(f))
	}
}

func TestSGDBPort_VPCRuleFires(t *testing.T) {
	r := res("aws_vpc_security_group_ingress_rule", "mongo", map[string]ir.Value{
		"cidr_ipv6":   ks("::/0", 2),
		"ip_protocol": ks("tcp", 2),
		"from_port":   knum(27017, 2),
		"to_port":     knum(27017, 2),
	})
	f := runRule(sgDatabasePort{}, r)
	if len(f) != 1 || f[0].Evidence.Attribute != "cidr_ipv6" {
		t.Fatalf("expected 1 finding on cidr_ipv6, got %+v", f)
	}
}

func TestSGDBPort_VPCRuleAllProtocolFires(t *testing.T) {
	r := res("aws_vpc_security_group_ingress_rule", "all", map[string]ir.Value{
		"cidr_ipv4":   ks("0.0.0.0/0", 2),
		"ip_protocol": ks("-1", 2),
	})
	if f := runRule(sgDatabasePort{}, r); len(f) != 1 {
		t.Fatalf("ip_protocol -1 without ports exposes DB ports, expected 1, got %d", len(f))
	}
}

func TestSGDBPort_VPCRuleNonDBPortNoFinding(t *testing.T) {
	r := res("aws_vpc_security_group_ingress_rule", "ssh", map[string]ir.Value{
		"cidr_ipv4":   ks("0.0.0.0/0", 2),
		"ip_protocol": ks("tcp", 2),
		"from_port":   knum(22, 2),
		"to_port":     knum(22, 2),
	})
	if f := runRule(sgDatabasePort{}, r); len(f) != 0 {
		t.Fatalf("world-open 22 is not a database port, got %d", len(f))
	}
}

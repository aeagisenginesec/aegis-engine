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
		"type":                   ks("ingress", 2),
		"security_group_id":      {Known: false, Ref: "aws_security_group.app.id", Span: spanAt(2)},
		"source_security_group_id": {Known: false, Ref: "aws_security_group.db.id", Span: spanAt(2)},
		"cidr_blocks":            strList(3, "10.0.0.0/8"),
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

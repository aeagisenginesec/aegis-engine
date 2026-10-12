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

func TestSGEgress_UnknownNoFinding(t *testing.T) {
	sg := res("aws_security_group", "web", map[string]ir.Value{
		"egress": blks(3, blk("cidr_blocks", ku(4))),
	})
	if f := runRule(sgOpenEgress{}, sg); len(f) != 0 {
		t.Fatalf("unknown egress cidr_blocks must not fire, got %d", len(f))
	}
}

package alibaba

import (
	"testing"

	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-ALI-007: RAM policy grants wildcard actions
// ---------------------------------------------------------------------------

func TestALI007_WildcardFires(t *testing.T) {
	doc := `{"Version":"1","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`
	r := res("alicloud_ram_policy", "p", map[string]ir.Value{"policy_document": ks(doc, 3)})
	f := mustFinding(t, runRule(ramPolicyWildcard{}, r), "AEGIS-ALI-007")
	if f.Severity != ir.SeverityCritical {
		t.Fatalf("wrong severity: %s", f.Severity)
	}
}

func TestALI007_WildcardListFires(t *testing.T) {
	doc := `{
  "Version": "1",
  "Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": "*"}]
}`
	r := res("alicloud_ram_policy", "p", map[string]ir.Value{"policy_document": ks(doc, 3)})
	mustFinding(t, runRule(ramPolicyWildcard{}, r), "AEGIS-ALI-007")
}

func TestALI007_ScopedQuiet(t *testing.T) {
	doc := `{"Version":"1","Statement":[{"Effect":"Allow","Action":["oss:GetObject","oss:ListObjects"],"Resource":"acs:oss:*:*:bkt/*"}]}`
	r := res("alicloud_ram_policy", "p", map[string]ir.Value{"policy_document": ks(doc, 3)})
	mustQuiet(t, runRule(ramPolicyWildcard{}, r))
}

func TestALI007_AbsentQuiet(t *testing.T) {
	mustQuiet(t, runRule(ramPolicyWildcard{}, res("alicloud_ram_policy", "p", nil)))
}

// ---------------------------------------------------------------------------
// AEGIS-ALI-008: ECS disk without encryption
// ---------------------------------------------------------------------------

func TestALI008_DiskAbsentFires(t *testing.T) {
	r := res("alicloud_ecs_disk", "d", nil)
	f := mustFinding(t, runRule(ecsDiskUnencrypted{}, r), "AEGIS-ALI-008")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity: %s", f.Severity)
	}
}

func TestALI008_DiskEncryptedQuiet(t *testing.T) {
	r := res("alicloud_ecs_disk", "d", map[string]ir.Value{"encrypted": kv(true, 3)})
	mustQuiet(t, runRule(ecsDiskUnencrypted{}, r))
}

func TestALI008_InstanceDataDiskUnencryptedFires(t *testing.T) {
	r := res("alicloud_instance", "i", map[string]ir.Value{
		"data_disks": blks(3, blk("encrypted", kv(false, 4))),
	})
	fs := runRule(ecsDiskUnencrypted{}, r)
	if len(fs) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(fs))
	}
	if fs[0].RuleID != "AEGIS-ALI-008" {
		t.Fatalf("wrong rule ID: %s", fs[0].RuleID)
	}
}

func TestALI008_InstanceDataDiskEncryptedQuiet(t *testing.T) {
	r := res("alicloud_instance", "i", map[string]ir.Value{
		"data_disks": blks(3, blk("encrypted", kv(true, 4))),
	})
	mustQuiet(t, runRule(ecsDiskUnencrypted{}, r))
}

// ---------------------------------------------------------------------------
// AEGIS-ALI-009: ECS security group rule open to the world
// ---------------------------------------------------------------------------

func openIngressRule(cidr string) map[string]ir.Value {
	return map[string]ir.Value{
		"type":    ks("ingress", 2),
		"policy":  ks("accept", 3),
		"cidr_ip": ks(cidr, 4),
	}
}

func TestALI009_OpenIngressFires(t *testing.T) {
	r := res("alicloud_security_group_rule", "open", openIngressRule("0.0.0.0/0"))
	f := mustFinding(t, runRule(sgOpenIngress{}, r), "AEGIS-ALI-009")
	if f.Severity != ir.SeverityCritical {
		t.Fatalf("wrong severity: %s", f.Severity)
	}
}

func TestALI009_RestrictedQuiet(t *testing.T) {
	r := res("alicloud_security_group_rule", "ok", openIngressRule("10.0.0.0/8"))
	mustQuiet(t, runRule(sgOpenIngress{}, r))
}

func TestALI009_EgressQuiet(t *testing.T) {
	attrs := openIngressRule("0.0.0.0/0")
	attrs["type"] = ks("egress", 2)
	r := res("alicloud_security_group_rule", "eg", attrs)
	mustQuiet(t, runRule(sgOpenIngress{}, r))
}

func TestALI009_DropQuiet(t *testing.T) {
	attrs := openIngressRule("0.0.0.0/0")
	attrs["policy"] = ks("drop", 3)
	r := res("alicloud_security_group_rule", "dr", attrs)
	mustQuiet(t, runRule(sgOpenIngress{}, r))
}

// Regression test for the 2026-10-14 sampling audit: a present-but-
// unresolved policy must NOT fire — the pack's unknown-value contract
// says unresolved values yield no finding (the rule might be "drop").
func TestALI009_UnknownPolicyQuiet(t *testing.T) {
	attrs := openIngressRule("0.0.0.0/0")
	attrs["policy"] = ku(3)
	r := res("alicloud_security_group_rule", "unk", attrs)
	mustQuiet(t, runRule(sgOpenIngress{}, r))
}

// Absent policy keeps firing: the provider default is accept.
func TestALI009_AbsentPolicyFires(t *testing.T) {
	attrs := map[string]ir.Value{
		"type":    ks("ingress", 2),
		"cidr_ip": ks("0.0.0.0/0", 4),
	}
	r := res("alicloud_security_group_rule", "nopolicy", attrs)
	mustFinding(t, runRule(sgOpenIngress{}, r), "AEGIS-ALI-009")
}

// ---------------------------------------------------------------------------
// AEGIS-ALI-010: RDS instance without transparent data encryption
// ---------------------------------------------------------------------------

func TestALI010_AbsentFires(t *testing.T) {
	r := res("alicloud_db_instance", "db", nil)
	f := mustFinding(t, runRule(rdsNoTDE{}, r), "AEGIS-ALI-010")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity: %s", f.Severity)
	}
}

func TestALI010_EnabledQuiet(t *testing.T) {
	r := res("alicloud_db_instance", "db", map[string]ir.Value{"tde_status": ks("Enabled", 3)})
	mustQuiet(t, runRule(rdsNoTDE{}, r))
}

func TestALI010_UnknownQuiet(t *testing.T) {
	r := res("alicloud_db_instance", "db", map[string]ir.Value{"tde_status": ku(3)})
	mustQuiet(t, runRule(rdsNoTDE{}, r))
}

// ---------------------------------------------------------------------------
// AEGIS-ALI-011: ALB load balancer without access logging
// ---------------------------------------------------------------------------

func TestALI011_AbsentFires(t *testing.T) {
	mustFinding(t, runRule(albNoAccessLog{}, res("alicloud_alb_load_balancer", "lb", nil)), "AEGIS-ALI-011")
}

func TestALI011_ConfigQuiet(t *testing.T) {
	r := res("alicloud_alb_load_balancer", "lb", map[string]ir.Value{
		"access_log_config": blks(3, blk("log_project", ks("p", 4), "log_store", ks("s", 5))),
	})
	mustQuiet(t, runRule(albNoAccessLog{}, r))
}

// ---------------------------------------------------------------------------
// AEGIS-ALI-012: ActionTrail trail without full event capture
// ---------------------------------------------------------------------------

func TestALI012_AbsentFires(t *testing.T) {
	mustFinding(t, runRule(actionTrailNarrow{}, res("alicloud_actiontrail_trail", "t", nil)), "AEGIS-ALI-012")
}

func TestALI012_WriteOnlyFires(t *testing.T) {
	r := res("alicloud_actiontrail_trail", "t", map[string]ir.Value{"event_rw": ks("Write", 3)})
	mustFinding(t, runRule(actionTrailNarrow{}, r), "AEGIS-ALI-012")
}

func TestALI012_AllQuiet(t *testing.T) {
	r := res("alicloud_actiontrail_trail", "t", map[string]ir.Value{"event_rw": ks("All", 3)})
	mustQuiet(t, runRule(actionTrailNarrow{}, r))
}

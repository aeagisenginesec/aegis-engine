package aws

import (
	"testing"

	"aegis/internal/ir"
)

func esRes(attrs map[string]ir.Value) ir.Resource {
	return res("aws_elasticsearch_domain", "d", attrs)
}

func osRes(attrs map[string]ir.Value) ir.Resource {
	return res("aws_opensearch_domain", "d", attrs)
}

func wantOne(t *testing.T, rule ir.Rule, r ir.Resource, id string) {
	t.Helper()
	got := runRule(rule, r)
	if len(got) != 1 {
		t.Fatalf("%s: want 1 finding, got %d", id, len(got))
	}
	if got[0].RuleID != id {
		t.Fatalf("%s: wrong rule ID %s", id, got[0].RuleID)
	}
	if got[0].Resource == "" || got[0].Evidence.Attribute == "" {
		t.Fatalf("%s: finding missing resource/attribute", id)
	}
}

func wantZero(t *testing.T, rule ir.Rule, r ir.Resource, id string) {
	t.Helper()
	if got := runRule(rule, r); len(got) != 0 {
		t.Fatalf("%s: want 0 findings, got %d", id, len(got))
	}
}

// AEGIS-AWS-637: HTTPS enforcement
func Test637_AbsentFires(t *testing.T) {
	wantOne(t, esNoEnforceHTTPS{}, esRes(nil), "AEGIS-AWS-637")
}

func Test637_EnforcedQuiet(t *testing.T) {
	r := esRes(map[string]ir.Value{
		"domain_endpoint_options": blks(2, blk("enforce_https", kv(true, 3))),
	})
	wantZero(t, esNoEnforceHTTPS{}, r, "AEGIS-AWS-637")
}

func Test637_OpensearchFires(t *testing.T) {
	wantOne(t, esNoEnforceHTTPS{}, osRes(nil), "AEGIS-AWS-637")
}

// AEGIS-AWS-638: dedicated master
func Test638_FalseFires(t *testing.T) {
	r := esRes(map[string]ir.Value{
		"cluster_config": blks(2, blk("dedicated_master_enabled", kv(false, 3))),
	})
	wantOne(t, esNoDedicatedMaster{}, r, "AEGIS-AWS-638")
}

func Test638_AbsentFires(t *testing.T) {
	wantOne(t, esNoDedicatedMaster{}, esRes(nil), "AEGIS-AWS-638")
}

func Test638_EnabledQuiet(t *testing.T) {
	r := esRes(map[string]ir.Value{
		"cluster_config": blks(2, blk("dedicated_master_enabled", kv(true, 3))),
	})
	wantZero(t, esNoDedicatedMaster{}, r, "AEGIS-AWS-638")
}

// AEGIS-AWS-639: zone awareness
func Test639_AbsentFires(t *testing.T) {
	wantOne(t, esNoZoneAwareness{}, esRes(nil), "AEGIS-AWS-639")
}

func Test639_EnabledQuiet(t *testing.T) {
	r := esRes(map[string]ir.Value{
		"cluster_config": blks(2, blk("zone_awareness_enabled", kv(true, 3))),
	})
	wantZero(t, esNoZoneAwareness{}, r, "AEGIS-AWS-639")
}

func Test639_UnknownQuiet(t *testing.T) {
	r := esRes(map[string]ir.Value{
		"cluster_config": blks(2, blk("zone_awareness_enabled", ku(3))),
	})
	wantZero(t, esNoZoneAwareness{}, r, "AEGIS-AWS-639")
}

// AEGIS-AWS-640: internal user database (opensearch only)
func Test640_AbsentFires(t *testing.T) {
	wantOne(t, opensearchNoInternalUser{}, osRes(nil), "AEGIS-AWS-640")
}

func Test640_EnabledQuiet(t *testing.T) {
	r := osRes(map[string]ir.Value{
		"advanced_security_options": blks(2, blk("internal_user_database_enabled", kv(true, 3))),
	})
	wantZero(t, opensearchNoInternalUser{}, r, "AEGIS-AWS-640")
}

func Test640_WrongTypeQuiet(t *testing.T) {
	// Rule applies to opensearch only; runRule gates on AppliesTo.
	if got := runRule(opensearchNoInternalUser{}, esRes(nil)); len(got) != 0 {
		t.Fatalf("want 0 findings for elasticsearch type, got %d", len(got))
	}
}

// AEGIS-AWS-641: snapshot options
func Test641_AbsentFires(t *testing.T) {
	wantOne(t, esNoSnapshotOptions{}, esRes(nil), "AEGIS-AWS-641")
}

func Test641_PresentQuiet(t *testing.T) {
	r := esRes(map[string]ir.Value{
		"snapshot_options": blks(2, blk("automated_snapshot_start_hour", ks("3", 3))),
	})
	wantZero(t, esNoSnapshotOptions{}, r, "AEGIS-AWS-641")
}

// AEGIS-AWS-642: slow logs
func Test642_AbsentFires(t *testing.T) {
	wantOne(t, esNoSlowLogs{}, esRes(nil), "AEGIS-AWS-642")
}

func Test642_SlowLogsQuiet(t *testing.T) {
	r := esRes(map[string]ir.Value{
		"log_publishing_options": blks(2, blk("log_type", ks("SEARCH_SLOW_LOGS", 3))),
	})
	wantZero(t, esNoSlowLogs{}, r, "AEGIS-AWS-642")
}

func Test642_AuditOnlyFires(t *testing.T) {
	r := esRes(map[string]ir.Value{
		"log_publishing_options": blks(2, blk("log_type", ks("AUDIT_LOGS", 3))),
	})
	wantOne(t, esNoSlowLogs{}, r, "AEGIS-AWS-642")
}

// AEGIS-AWS-643: EOL engine version
func Test643_OldVersionFires(t *testing.T) {
	r := esRes(map[string]ir.Value{"elasticsearch_version": ks("2.3", 2)})
	wantOne(t, searchOldEngineVersion{}, r, "AEGIS-AWS-643")
}

func Test643_ModernQuiet(t *testing.T) {
	r := esRes(map[string]ir.Value{"elasticsearch_version": ks("7.10", 2)})
	wantZero(t, searchOldEngineVersion{}, r, "AEGIS-AWS-643")
}

func Test643_AbsentQuiet(t *testing.T) {
	wantZero(t, searchOldEngineVersion{}, esRes(nil), "AEGIS-AWS-643")
}

// AEGIS-AWS-644: elasticsearch without advanced security
func Test644_AbsentFires(t *testing.T) {
	wantOne(t, esNoAdvancedSecurity{}, esRes(nil), "AEGIS-AWS-644")
}

func Test644_EnabledQuiet(t *testing.T) {
	r := esRes(map[string]ir.Value{
		"advanced_security_options": blks(2, blk("enabled", kv(true, 3))),
	})
	wantZero(t, esNoAdvancedSecurity{}, r, "AEGIS-AWS-644")
}

func TestSearch2RulesInIDOrder(t *testing.T) {
	rules := Search2Rules()
	if len(rules) != 8 {
		t.Fatalf("expected 8 rules, got %d", len(rules))
	}
	if rules[0].ID() != "AEGIS-AWS-637" || rules[7].ID() != "AEGIS-AWS-644" {
		t.Fatalf("ID order broken: %s .. %s", rules[0].ID(), rules[7].ID())
	}
}

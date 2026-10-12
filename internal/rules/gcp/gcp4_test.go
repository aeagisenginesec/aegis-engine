package gcp

import (
	"testing"

	"aegis/internal/ir"
)

// sqlWithFlags builds a google_sql_database_instance with the given
// database_flags blocks.
func sqlWithFlags(flags ...map[string]ir.Value) ir.Resource {
	return res("google_sql_database_instance", "db", map[string]ir.Value{
		"settings": blks(3, blk("database_flags", blks(4, flags...))),
	})
}

// --- 101: log_checkpoints ---
func TestGCP101_NoFlagFires(t *testing.T) {
	mustFinding(t, runRule(sqlNoLogCheckpoints{}, sqlWithFlags()), "AEGIS-GCP-101")
}
func TestGCP101_FlagOnQuiet(t *testing.T) {
	r := sqlWithFlags(blk("name", ks("log_checkpoints", 5), "value", ks("on", 5)))
	if len(runRule(sqlNoLogCheckpoints{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}
func TestGCP101_FlagOffFires(t *testing.T) {
	r := sqlWithFlags(blk("name", ks("log_checkpoints", 5), "value", ks("off", 5)))
	mustFinding(t, runRule(sqlNoLogCheckpoints{}, r), "AEGIS-GCP-101")
}

// --- 102: log_connections ---
func TestGCP102_NoFlagFires(t *testing.T) {
	mustFinding(t, runRule(sqlNoLogConnections{}, sqlWithFlags()), "AEGIS-GCP-102")
}
func TestGCP102_FlagOnQuiet(t *testing.T) {
	r := sqlWithFlags(blk("name", ks("log_connections", 5), "value", ks("ON", 5)))
	if len(runRule(sqlNoLogConnections{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 103: log_disconnections ---
func TestGCP103_NoFlagFires(t *testing.T) {
	mustFinding(t, runRule(sqlNoLogDisconnectionsPg{}, sqlWithFlags()), "AEGIS-GCP-103")
}
func TestGCP103_FlagOnQuiet(t *testing.T) {
	r := sqlWithFlags(blk("name", ks("log_disconnections", 5), "value", ks("on", 5)))
	if len(runRule(sqlNoLogDisconnectionsPg{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 104: log_lock_waits ---
func TestGCP104_NoFlagFires(t *testing.T) {
	mustFinding(t, runRule(sqlNoLogLockWaits{}, sqlWithFlags()), "AEGIS-GCP-104")
}
func TestGCP104_FlagOnQuiet(t *testing.T) {
	r := sqlWithFlags(blk("name", ks("log_lock_waits", 5), "value", ks("on", 5)))
	if len(runRule(sqlNoLogLockWaits{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 105: log_duration ---
func TestGCP105_NoFlagFires(t *testing.T) {
	mustFinding(t, runRule(sqlNoLogDuration{}, sqlWithFlags()), "AEGIS-GCP-105")
}
func TestGCP105_FlagOnQuiet(t *testing.T) {
	r := sqlWithFlags(blk("name", ks("log_duration", 5), "value", ks("on", 5)))
	if len(runRule(sqlNoLogDuration{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 106: pgAudit ---
func TestGCP106_NoAuditFires(t *testing.T) {
	mustFinding(t, runRule(sqlNoPgAudit{}, sqlWithFlags()), "AEGIS-GCP-106")
}
func TestGCP106_PgAuditQuiet(t *testing.T) {
	r := sqlWithFlags(
		blk("name", ks("pgaudit.log", 5), "value", ks("READ,WRITE", 5)),
		blk("name", ks("shared_preload_libraries", 5), "value", ks("pgaudit", 5)),
	)
	if len(runRule(sqlNoPgAudit{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}
func TestGCP106_ReadOnlyFires(t *testing.T) {
	r := sqlWithFlags(blk("name", ks("pgaudit.log", 5), "value", ks("READ", 5)))
	mustFinding(t, runRule(sqlNoPgAudit{}, r), "AEGIS-GCP-106")
}
func TestGCP106_UnknownValueQuiet(t *testing.T) {
	r := sqlWithFlags(blk("name", ks("pgaudit.log", 5), "value", ku(5)))
	if len(runRule(sqlNoPgAudit{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown value")
	}
}

// --- 107: log_min_messages ---
func TestGCP107_NoFlagFires(t *testing.T) {
	mustFinding(t, runRule(sqlLogMinMessages{}, sqlWithFlags()), "AEGIS-GCP-107")
}
func TestGCP107_WarningQuiet(t *testing.T) {
	r := sqlWithFlags(blk("name", ks("log_min_messages", 5), "value", ks("WARNING", 5)))
	if len(runRule(sqlLogMinMessages{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}
func TestGCP107_InfoFires(t *testing.T) {
	r := sqlWithFlags(blk("name", ks("log_min_messages", 5), "value", ks("INFO", 5)))
	mustFinding(t, runRule(sqlLogMinMessages{}, r), "AEGIS-GCP-107")
}

// --- 108: metadata server ---
func TestGCP108_NoWIConfigFires(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{})
	mustFinding(t, runRule(gkeNoMetadataServer{}, r), "AEGIS-GCP-108")
}
func TestGCP108_WIConfigQuiet(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{
		"workload_identity_config": blks(3, blk("workload_pool", ks("p.svc.id.goog", 4))),
	})
	if len(runRule(gkeNoMetadataServer{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}
func TestGCP108_MetadataModeQuiet(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{
		"node_config": blks(3, blk(
			"workload_metadata_config", blks(4, blk("mode", ks("GKE_METADATA", 5))),
		)),
	})
	if len(runRule(gkeNoMetadataServer{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 109: binary authorization ---
func TestGCP109_AbsentFires(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{})
	mustFinding(t, runRule(gkeBinaryAuthDisabled{}, r), "AEGIS-GCP-109")
}
func TestGCP109_EnabledQuiet(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{
		"binary_authorization": blks(3, blk("enabled", kv(true, 4))),
	})
	if len(runRule(gkeBinaryAuthDisabled{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}
func TestGCP109_EvalModeQuiet(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{
		"binary_authorization": blks(3, blk("evaluation_mode", ks("PROJECT_SINGLETON_POLICY_ENFORCE", 4))),
	})
	if len(runRule(gkeBinaryAuthDisabled{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}
func TestGCP109_DisabledFires(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{
		"binary_authorization": blks(3, blk("enabled", kv(false, 4))),
	})
	mustFinding(t, runRule(gkeBinaryAuthDisabled{}, r), "AEGIS-GCP-109")
}

// --- 110: legacy ABAC ---
func TestGCP110_EnabledFires(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{"enable_legacy_abac": kv(true, 3)})
	mustFinding(t, runRule(gkeLegacyABACGap{}, r), "AEGIS-GCP-110")
}
func TestGCP110_DisabledQuiet(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{"enable_legacy_abac": kv(false, 3)})
	if len(runRule(gkeLegacyABACGap{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}
func TestGCP110_AbsentQuiet(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{})
	if len(runRule(gkeLegacyABACGap{}, r)) != 0 {
		t.Fatal("expected 0 findings (default false)")
	}
}

// --- 111: network policy ---
func TestGCP111_AbsentFires(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{})
	mustFinding(t, runRule(gkeNoNetworkPolicyGap{}, r), "AEGIS-GCP-111")
}
func TestGCP111_EnabledQuiet(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{
		"network_policy": blks(3, blk("enabled", kv(true, 4))),
	})
	if len(runRule(gkeNoNetworkPolicyGap{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}
func TestGCP111_DisabledFires(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{
		"network_policy": blks(3, blk("enabled", kv(false, 4))),
	})
	mustFinding(t, runRule(gkeNoNetworkPolicyGap{}, r), "AEGIS-GCP-111")
}

// --- 112: private cluster ---
func TestGCP112_AbsentFires(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{})
	mustFinding(t, runRule(gkeNoPrivateClusterGap{}, r), "AEGIS-GCP-112")
}
func TestGCP112_PrivateNodesQuiet(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{
		"private_cluster_config": blks(3, blk("enable_private_nodes", kv(true, 4))),
	})
	if len(runRule(gkeNoPrivateClusterGap{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 113: control plane public ---
func TestGCP113_WorldCIDRFires(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{
		"master_authorized_networks_config": blks(3, blk(
			"cidr_blocks", blks(4, blk("cidr_block", ks("0.0.0.0/0", 5))),
		)),
	})
	mustFinding(t, runRule(gkePublicControlPlane{}, r), "AEGIS-GCP-113")
}
func TestGCP113_NoConfigFires(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{})
	mustFinding(t, runRule(gkePublicControlPlane{}, r), "AEGIS-GCP-113")
}
func TestGCP113_PrivateEndpointQuiet(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{
		"private_cluster_config": blks(3, blk("enable_private_endpoint", kv(true, 4))),
	})
	if len(runRule(gkePublicControlPlane{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}
func TestGCP113_RestrictedCIDRQuiet(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{
		"master_authorized_networks_config": blks(3, blk(
			"cidr_blocks", blks(4, blk("cidr_block", ks("10.0.0.0/8", 5))),
		)),
	})
	if len(runRule(gkePublicControlPlane{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 114: release channel ---
func TestGCP114_AbsentFires(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{})
	mustFinding(t, runRule(gkeNoReleaseChannel{}, r), "AEGIS-GCP-114")
}
func TestGCP114_ChannelSetQuiet(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{
		"release_channel": blks(3, blk("channel", ks("REGULAR", 4))),
	})
	if len(runRule(gkeNoReleaseChannel{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 115: Stackdriver logging ---
func TestGCP115_NoneFires(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{"logging_service": ks("none", 3)})
	mustFinding(t, runRule(gkeNoStackdriverLogging{}, r), "AEGIS-GCP-115")
}
func TestGCP115_AbsentQuiet(t *testing.T) {
	r := res("google_container_cluster", "c", map[string]ir.Value{})
	if len(runRule(gkeNoStackdriverLogging{}, r)) != 0 {
		t.Fatal("expected 0 findings (default logs)")
	}
}
func TestGCP115_DefaultQuiet(t *testing.T) {
	r := res("google_container_cluster", "c",
		map[string]ir.Value{"logging_service": ks("logging.googleapis.com", 3)})
	if len(runRule(gkeNoStackdriverLogging{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 116/117: node pool management ---
func TestGCP116_NoManagementFires(t *testing.T) {
	r := res("google_container_node_pool", "p", map[string]ir.Value{})
	mustFinding(t, runRule(nodePoolNoAutoRepair{}, r), "AEGIS-GCP-116")
}
func TestGCP116_AutoRepairQuiet(t *testing.T) {
	r := res("google_container_node_pool", "p", map[string]ir.Value{
		"management": blks(3, blk("auto_repair", kv(true, 4))),
	})
	if len(runRule(nodePoolNoAutoRepair{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}
func TestGCP116_DisabledFires(t *testing.T) {
	r := res("google_container_node_pool", "p", map[string]ir.Value{
		"management": blks(3, blk("auto_repair", kv(false, 4))),
	})
	mustFinding(t, runRule(nodePoolNoAutoRepair{}, r), "AEGIS-GCP-116")
}
func TestGCP117_NoManagementFires(t *testing.T) {
	r := res("google_container_node_pool", "p", map[string]ir.Value{})
	mustFinding(t, runRule(nodePoolNoAutoUpgrade{}, r), "AEGIS-GCP-117")
}
func TestGCP117_AutoUpgradeQuiet(t *testing.T) {
	r := res("google_container_node_pool", "p", map[string]ir.Value{
		"management": blks(3, blk("auto_upgrade", kv(true, 4))),
	})
	if len(runRule(nodePoolNoAutoUpgrade{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 118: IP forwarding ---
func TestGCP118_EnabledFires(t *testing.T) {
	r := res("google_compute_instance", "i", map[string]ir.Value{"can_ip_forward": kv(true, 3)})
	mustFinding(t, runRule(instanceIPForwarding{}, r), "AEGIS-GCP-118")
}
func TestGCP118_DisabledQuiet(t *testing.T) {
	r := res("google_compute_instance", "i", map[string]ir.Value{"can_ip_forward": kv(false, 3)})
	if len(runRule(instanceIPForwarding{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 119: serial port ---
func TestGCP119_SerialPortMapBoolFires(t *testing.T) {
	r := res("google_compute_instance", "i", map[string]ir.Value{
		"metadata": ir.Value{
			Raw:   map[string]ir.Value{"serial-port-enable": kv(true, 4)},
			Known: true, Span: spanAt(3),
		},
	})
	mustFinding(t, runRule(instanceSerialPortAccess{}, r), "AEGIS-GCP-119")
}
func TestGCP119_SerialPortStringFires(t *testing.T) {
	r := res("google_compute_instance", "i", map[string]ir.Value{
		"metadata": blks(3, blk("serial-port-enable", ks("TRUE", 4))),
	})
	mustFinding(t, runRule(instanceSerialPortAccess{}, r), "AEGIS-GCP-119")
}
func TestGCP119_NoMetadataQuiet(t *testing.T) {
	r := res("google_compute_instance", "i", map[string]ir.Value{})
	if len(runRule(instanceSerialPortAccess{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 120: subnetwork flow logs ---
func TestGCP120_NoLogConfigFires(t *testing.T) {
	r := res("google_compute_subnetwork", "s", map[string]ir.Value{})
	mustFinding(t, runRule(subnetworkNoFlowLogs{}, r), "AEGIS-GCP-120")
}
func TestGCP120_LogConfigQuiet(t *testing.T) {
	r := res("google_compute_subnetwork", "s", map[string]ir.Value{"log_config": blks(3, blk())})
	if len(runRule(subnetworkNoFlowLogs{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 121: uniform bucket-level access ---
func TestGCP121_AbsentFires(t *testing.T) {
	r := res("google_storage_bucket", "b", map[string]ir.Value{})
	mustFinding(t, runRule(bucketNoUniformAccessGap{}, r), "AEGIS-GCP-121")
}
func TestGCP121_EnabledQuiet(t *testing.T) {
	r := res("google_storage_bucket", "b", map[string]ir.Value{"uniform_bucket_level_access": kv(true, 3)})
	if len(runRule(bucketNoUniformAccessGap{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

// --- 122: public access prevention ---
func TestGCP122_AbsentFires(t *testing.T) {
	r := res("google_storage_bucket", "b", map[string]ir.Value{})
	mustFinding(t, runRule(bucketPAPNotEnforced{}, r), "AEGIS-GCP-122")
}
func TestGCP122_EnforcedQuiet(t *testing.T) {
	r := res("google_storage_bucket", "b",
		map[string]ir.Value{"public_access_prevention": ks("enforced", 3)})
	if len(runRule(bucketPAPNotEnforced{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}
func TestGCP122_InheritedFires(t *testing.T) {
	r := res("google_storage_bucket", "b",
		map[string]ir.Value{"public_access_prevention": ks("inherited", 3)})
	mustFinding(t, runRule(bucketPAPNotEnforced{}, r), "AEGIS-GCP-122")
}

// Verify all 22 new rules are registered in ID order
func TestGCP4_AllRegistered(t *testing.T) {
	rules := GCP4Rules()
	if len(rules) != 22 {
		t.Fatalf("expected 22 rules, got %d", len(rules))
	}
	for i, r := range rules {
		want := 101 + i
		var got int
		_, err := scanID(r.ID(), &got)
		if err != nil || got != want {
			t.Fatalf("rule %d: want AEGIS-GCP-%03d, got %s", i, want, r.ID())
		}
		if r.Title() == "" || r.Description() == "" {
			t.Fatalf("rule %s missing title/description", r.ID())
		}
		if r.Severity() != ir.SeverityLow && r.Severity() != ir.SeverityMedium &&
			r.Severity() != ir.SeverityHigh && r.Severity() != ir.SeverityCritical {
			t.Fatalf("rule %s has invalid severity", r.ID())
		}
	}
}

// Verify unknown values never produce findings across the new rules
func TestGCP4_UnknownNoFindings(t *testing.T) {
	unknownCluster := res("google_container_cluster", "c", map[string]ir.Value{
		"workload_identity_config": ku(3),
		"binary_authorization":     ku(3),
		"enable_legacy_abac":       ku(3),
		"network_policy":           ku(3),
		"private_cluster_config":   ku(3),
		"release_channel":          ku(3),
		"logging_service":          ku(3),
	})
	unknownPool := res("google_container_node_pool", "p", map[string]ir.Value{
		"management": ku(3),
	})
	unknownInst := res("google_compute_instance", "i", map[string]ir.Value{
		"can_ip_forward": ku(3),
		"metadata":       ku(3),
	})
	unknownSubnet := res("google_compute_subnetwork", "s", map[string]ir.Value{"log_config": ku(3)})
	unknownBucket := res("google_storage_bucket", "b", map[string]ir.Value{
		"uniform_bucket_level_access": ku(3),
		"public_access_prevention":    ku(3),
	})
	unknownSQL := res("google_sql_database_instance", "db", map[string]ir.Value{
		"settings": blks(3, blk("database_flags", blks(4,
			blk("name", ks("log_checkpoints", 5), "value", ku(5)),
			blk("name", ks("pgaudit.log", 5), "value", ku(5)),
		))),
	})
	cases := []struct {
		rule ir.Rule
		res  ir.Resource
	}{
		{sqlNoLogCheckpoints{}, unknownSQL},
		{sqlNoPgAudit{}, unknownSQL},
		{gkeNoMetadataServer{}, unknownCluster},
		{gkeBinaryAuthDisabled{}, unknownCluster},
		{gkeLegacyABACGap{}, unknownCluster},
		{gkeNoNetworkPolicyGap{}, unknownCluster},
		{gkeNoPrivateClusterGap{}, unknownCluster},
		{gkePublicControlPlane{}, unknownCluster},
		{gkeNoReleaseChannel{}, unknownCluster},
		{gkeNoStackdriverLogging{}, unknownCluster},
		{nodePoolNoAutoRepair{}, unknownPool},
		{nodePoolNoAutoUpgrade{}, unknownPool},
		{instanceIPForwarding{}, unknownInst},
		{instanceSerialPortAccess{}, unknownInst},
		{subnetworkNoFlowLogs{}, unknownSubnet},
		{bucketNoUniformAccessGap{}, unknownBucket},
		{bucketPAPNotEnforced{}, unknownBucket},
	}
	for _, c := range cases {
		if len(runRule(c.rule, c.res)) != 0 {
			t.Fatalf("rule %s: expected 0 findings for unknown", c.rule.ID())
		}
	}
}

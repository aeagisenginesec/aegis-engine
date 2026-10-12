package aws

import (
	"testing"

	"aegis/internal/ir"
)

func TestAuroraPerfInsightsNoCMK(t *testing.T) {
	fire := res("aws_rds_cluster", "db", map[string]ir.Value{
		"performance_insights_enabled": kv(true, 2),
	})
	quiet := res("aws_rds_cluster", "db", map[string]ir.Value{
		"performance_insights_enabled": kv(true, 2),
		"performance_insights_kms_key_id": ks("arn:aws:kms:eu-west-1:123:key/abc", 3),
	})
	disabled := res("aws_rds_cluster", "db", map[string]ir.Value{
		"performance_insights_enabled": kv(false, 2),
	})
	if got := runRule(auroraPerfInsightsNoCMK{}, fire); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	for _, r := range []ir.Resource{quiet, disabled} {
		if got := runRule(auroraPerfInsightsNoCMK{}, r); len(got) != 0 {
			t.Fatalf("expected quiet, got %d", len(got))
		}
	}
}

func TestDBInstanceNoEnhancedMon(t *testing.T) {
	absent := res("aws_db_instance", "db", map[string]ir.Value{})
	explicit := res("aws_db_instance", "db", map[string]ir.Value{
		"monitoring_interval": num(0, 2),
	})
	quiet := res("aws_db_instance", "db", map[string]ir.Value{
		"monitoring_interval": num(30, 2),
	})
	for _, r := range []ir.Resource{absent, explicit} {
		if got := runRule(dbInstanceNoEnhancedMon{}, r); len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(got))
		}
	}
	if got := runRule(dbInstanceNoEnhancedMon{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}

func TestDBInstanceNoCopyTagsSnapshot(t *testing.T) {
	absent := res("aws_db_instance", "db", map[string]ir.Value{})
	explicit := res("aws_db_instance", "db", map[string]ir.Value{
		"copy_tags_to_snapshot": kv(false, 2),
	})
	quiet := res("aws_db_instance", "db", map[string]ir.Value{
		"copy_tags_to_snapshot": kv(true, 2),
	})
	for _, r := range []ir.Resource{absent, explicit} {
		if got := runRule(dbInstanceNoCopyTagsSnapshot{}, r); len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(got))
		}
	}
	if got := runRule(dbInstanceNoCopyTagsSnapshot{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}

func TestAuroraSkipFinalSnapshot(t *testing.T) {
	fire := res("aws_rds_cluster", "db", map[string]ir.Value{
		"skip_final_snapshot": kv(true, 2),
	})
	quiet := res("aws_rds_cluster", "db", map[string]ir.Value{
		"skip_final_snapshot": kv(false, 2),
	})
	if got := runRule(auroraSkipFinalSnapshot{}, fire); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got := runRule(auroraSkipFinalSnapshot{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}

func TestAuroraNoAutomatedBackup(t *testing.T) {
	absent := res("aws_rds_cluster", "db", map[string]ir.Value{})
	explicit := res("aws_rds_cluster", "db", map[string]ir.Value{
		"backup_retention_period": num(0, 2),
	})
	quiet := res("aws_rds_cluster", "db", map[string]ir.Value{
		"backup_retention_period": num(7, 2),
	})
	for _, r := range []ir.Resource{absent, explicit} {
		if got := runRule(auroraNoAutomatedBackup{}, r); len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(got))
		}
	}
	if got := runRule(auroraNoAutomatedBackup{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}

func TestDBClusterSnapshotShared(t *testing.T) {
	fire := res("aws_db_cluster_snapshot", "snap", map[string]ir.Value{
		"shared_accounts": strList(2, "123456789012"),
	})
	quietEmpty := res("aws_db_cluster_snapshot", "snap", map[string]ir.Value{
		"shared_accounts": strList(2),
	})
	quietAbsent := res("aws_db_cluster_snapshot", "snap", map[string]ir.Value{})
	if got := runRule(dbClusterSnapshotShared{}, fire); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	for _, r := range []ir.Resource{quietEmpty, quietAbsent} {
		if got := runRule(dbClusterSnapshotShared{}, r); len(got) != 0 {
			t.Fatalf("expected quiet, got %d", len(got))
		}
	}
}

func TestDBInstanceDefaultOptionGroup(t *testing.T) {
	absent := res("aws_db_instance", "db", map[string]ir.Value{})
	def := res("aws_db_instance", "db", map[string]ir.Value{
		"option_group_name": ks("default:mysql-8-0", 2),
	})
	quiet := res("aws_db_instance", "db", map[string]ir.Value{
		"option_group_name": ks("custom-audit-group", 2),
	})
	for _, r := range []ir.Resource{absent, def} {
		if got := runRule(dbInstanceDefaultOptionGroup{}, r); len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(got))
		}
	}
	if got := runRule(dbInstanceDefaultOptionGroup{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}

func TestDBSubnetGroupSingleSubnet(t *testing.T) {
	fire := res("aws_db_subnet_group", "sg", map[string]ir.Value{
		"subnet_ids": strList(2, "subnet-1"),
	})
	quiet := res("aws_db_subnet_group", "sg", map[string]ir.Value{
		"subnet_ids": strList(2, "subnet-1", "subnet-2"),
	})
	unk := res("aws_db_subnet_group", "sg", map[string]ir.Value{
		"subnet_ids": ku(2),
	})
	if got := runRule(dbSubnetGroupSingleSubnet{}, fire); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	for _, r := range []ir.Resource{quiet, unk} {
		if got := runRule(dbSubnetGroupSingleSubnet{}, r); len(got) != 0 {
			t.Fatalf("expected quiet, got %d", len(got))
		}
	}
}

func TestAuroraDefaultParamGroup(t *testing.T) {
	absent := res("aws_rds_cluster", "db", map[string]ir.Value{})
	def := res("aws_rds_cluster", "db", map[string]ir.Value{
		"db_cluster_parameter_group_name": ks("default.aurora-mysql8.0", 2),
	})
	quiet := res("aws_rds_cluster", "db", map[string]ir.Value{
		"db_cluster_parameter_group_name": ks("hardened-aurora", 2),
	})
	for _, r := range []ir.Resource{absent, def} {
		if got := runRule(auroraDefaultParamGroup{}, r); len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(got))
		}
	}
	if got := runRule(auroraDefaultParamGroup{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}

func TestDBParamGroupNoForceSSL(t *testing.T) {
	fire := res("aws_db_parameter_group", "pg", map[string]ir.Value{
		"parameter": blks(2,
			blk("name", ks("rds.force_ssl", 3), "value", ks("0", 3))),
	})
	quiet := res("aws_db_parameter_group", "pg", map[string]ir.Value{
		"parameter": blks(2,
			blk("name", ks("rds.force_ssl", 3), "value", ks("1", 3))),
	})
	other := res("aws_db_parameter_group", "pg", map[string]ir.Value{
		"parameter": blks(2,
			blk("name", ks("max_connections", 3), "value", ks("100", 3))),
	})
	if got := runRule(dbParamGroupNoForceSSL{}, fire); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	for _, r := range []ir.Resource{quiet, other} {
		if got := runRule(dbParamGroupNoForceSSL{}, r); len(got) != 0 {
			t.Fatalf("expected quiet, got %d", len(got))
		}
	}
}

func TestDBInstancePasswordNoRotation(t *testing.T) {
	fire := res("aws_db_instance", "db", map[string]ir.Value{
		"password": ks("s3cr3t-static", 2),
	})
	quiet := res("aws_db_instance", "db", map[string]ir.Value{
		"password":                   ks("s3cr3t-static", 2),
		"manage_master_user_password": kv(true, 3),
	})
	noPw := res("aws_db_instance", "db", map[string]ir.Value{})
	got := runRule(dbInstancePasswordNoRotation{}, fire)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].Evidence.Actual != "[REDACTED] (plaintext password in config, no rotation)" {
		t.Fatalf("password leaked in evidence: %q", got[0].Evidence.Actual)
	}
	for _, r := range []ir.Resource{quiet, noPw} {
		if got := runRule(dbInstancePasswordNoRotation{}, r); len(got) != 0 {
			t.Fatalf("expected quiet, got %d", len(got))
		}
	}
}

func TestRedshiftNoVersionUpgrade(t *testing.T) {
	fire := res("aws_redshift_cluster", "rs", map[string]ir.Value{
		"allow_version_upgrade": kv(false, 2),
	})
	quiet := res("aws_redshift_cluster", "rs", map[string]ir.Value{
		"allow_version_upgrade": kv(true, 2),
	})
	if got := runRule(redshiftNoVersionUpgrade{}, fire); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got := runRule(redshiftNoVersionUpgrade{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}

func TestRedshiftShortSnapshotRet(t *testing.T) {
	fire := res("aws_redshift_cluster", "rs", map[string]ir.Value{
		"automated_snapshot_retention_period": num(1, 2),
	})
	quiet := res("aws_redshift_cluster", "rs", map[string]ir.Value{
		"automated_snapshot_retention_period": num(30, 2),
	})
	unk := res("aws_redshift_cluster", "rs", map[string]ir.Value{
		"automated_snapshot_retention_period": ku(2),
	})
	if got := runRule(redshiftShortSnapshotRet{}, fire); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	for _, r := range []ir.Resource{quiet, unk} {
		if got := runRule(redshiftShortSnapshotRet{}, r); len(got) != 0 {
			t.Fatalf("expected quiet, got %d", len(got))
		}
	}
}

func TestRedshiftNoCopyTagsSnapshot(t *testing.T) {
	absent := res("aws_redshift_cluster", "rs", map[string]ir.Value{})
	quiet := res("aws_redshift_cluster", "rs", map[string]ir.Value{
		"copy_tags_to_snapshot": kv(true, 2),
	})
	if got := runRule(redshiftNoCopyTagsSnapshot{}, absent); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got := runRule(redshiftNoCopyTagsSnapshot{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}

func TestElasticacheNoSnapRetention(t *testing.T) {
	absent := res("aws_elasticache_cluster", "ec", map[string]ir.Value{})
	explicit := res("aws_elasticache_cluster", "ec", map[string]ir.Value{
		"snapshot_retention_limit": num(0, 2),
	})
	quiet := res("aws_elasticache_cluster", "ec", map[string]ir.Value{
		"snapshot_retention_limit": num(5, 2),
	})
	for _, r := range []ir.Resource{absent, explicit} {
		if got := runRule(elasticacheNoSnapRetention{}, r); len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(got))
		}
	}
	if got := runRule(elasticacheNoSnapRetention{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}

func TestElasticacheNoAtRestEncryption(t *testing.T) {
	absent := res("aws_elasticache_replication_group", "rg", map[string]ir.Value{})
	explicit := res("aws_elasticache_replication_group", "rg", map[string]ir.Value{
		"at_rest_encryption_enabled": kv(false, 2),
	})
	quiet := res("aws_elasticache_replication_group", "rg", map[string]ir.Value{
		"at_rest_encryption_enabled": kv(true, 2),
	})
	for _, r := range []ir.Resource{absent, explicit} {
		if got := runRule(elasticacheNoAtRestEncryption{}, r); len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(got))
		}
	}
	if got := runRule(elasticacheNoAtRestEncryption{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}

func TestElasticacheNoAutoFailover(t *testing.T) {
	absent := res("aws_elasticache_replication_group", "rg", map[string]ir.Value{})
	explicit := res("aws_elasticache_replication_group", "rg", map[string]ir.Value{
		"automatic_failover_enabled": kv(false, 2),
	})
	quiet := res("aws_elasticache_replication_group", "rg", map[string]ir.Value{
		"automatic_failover_enabled": kv(true, 2),
	})
	for _, r := range []ir.Resource{absent, explicit} {
		if got := runRule(elasticacheNoAutoFailover{}, r); len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(got))
		}
	}
	if got := runRule(elasticacheNoAutoFailover{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}

func TestElasticacheRGNoSnapRetention(t *testing.T) {
	absent := res("aws_elasticache_replication_group", "rg", map[string]ir.Value{})
	quiet := res("aws_elasticache_replication_group", "rg", map[string]ir.Value{
		"snapshot_retention_limit": num(7, 2),
	})
	if got := runRule(elasticacheRGNoSnapRetention{}, absent); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got := runRule(elasticacheRGNoSnapRetention{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}

func TestDBInstanceNoPerfInsights(t *testing.T) {
	absent := res("aws_db_instance", "db", map[string]ir.Value{})
	explicit := res("aws_db_instance", "db", map[string]ir.Value{
		"performance_insights_enabled": kv(false, 2),
	})
	quiet := res("aws_db_instance", "db", map[string]ir.Value{
		"performance_insights_enabled": kv(true, 2),
	})
	for _, r := range []ir.Resource{absent, explicit} {
		if got := runRule(dbInstanceNoPerfInsights{}, r); len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(got))
		}
	}
	if got := runRule(dbInstanceNoPerfInsights{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}

func TestNeptuneNoDeletionProtection(t *testing.T) {
	absent := res("aws_neptune_cluster", "np", map[string]ir.Value{})
	explicit := res("aws_neptune_cluster", "np", map[string]ir.Value{
		"deletion_protection": kv(false, 2),
	})
	quiet := res("aws_neptune_cluster", "np", map[string]ir.Value{
		"deletion_protection": kv(true, 2),
	})
	for _, r := range []ir.Resource{absent, explicit} {
		if got := runRule(neptuneNoDeletionProtection{}, r); len(got) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(got))
		}
	}
	if got := runRule(neptuneNoDeletionProtection{}, quiet); len(got) != 0 {
		t.Fatalf("expected quiet, got %d", len(got))
	}
}

// TestDatabasesDeepRuleIDs asserts the 700-719 ID range is fully covered.
func TestDatabasesDeepRuleIDs(t *testing.T) {
	rules := DatabasesDeepRules()
	if len(rules) != 20 {
		t.Fatalf("expected 20 rules, got %d", len(rules))
	}
	for i, r := range rules {
		want := "AEGIS-AWS-" + itoa(700+i)
		if r.ID() != want {
			t.Fatalf("rule %d has ID %q, want %q", i, r.ID(), want)
		}
		if r.Title() == "" || r.Description() == "" {
			t.Fatalf("rule %s has empty metadata", r.ID())
		}
	}
}

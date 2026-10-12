package aws

import (
	"testing"

	"aegis/internal/ir"
)

// --- AEGIS-AWS-311: RDS without IAM database authentication ---

func Test311_AbsentFires(t *testing.T) {
	fs := runRule(rdsNoIAMAuth{}, res("aws_db_instance", "db", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityMedium || fs[0].Evidence.Attribute != "iam_database_authentication_enabled" {
		t.Fatalf("wrong finding: %+v", fs[0])
	}
}

func Test311_FalseFires(t *testing.T) {
	fs := runRule(rdsNoIAMAuth{}, res("aws_db_instance", "db",
		map[string]ir.Value{"iam_database_authentication_enabled": kv(false, 3)}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test311_TrueQuiet(t *testing.T) {
	fs := runRule(rdsNoIAMAuth{}, res("aws_db_instance", "db",
		map[string]ir.Value{"iam_database_authentication_enabled": kv(true, 3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test311_UnknownQuiet(t *testing.T) {
	fs := runRule(rdsNoIAMAuth{}, res("aws_db_instance", "db",
		map[string]ir.Value{"iam_database_authentication_enabled": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- AEGIS-AWS-312: DynamoDB table without point-in-time recovery ---

func Test312_AbsentBlockFires(t *testing.T) {
	fs := runRule(dynamoNoPITR{}, res("aws_dynamodb_table", "t", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityMedium {
		t.Fatalf("want medium severity, got %s", fs[0].Severity)
	}
}

func Test312_DisabledFires(t *testing.T) {
	fs := runRule(dynamoNoPITR{}, res("aws_dynamodb_table", "t",
		map[string]ir.Value{"point_in_time_recovery": blks(4, blk("enabled", kv(false, 5)))}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test312_EnabledQuiet(t *testing.T) {
	fs := runRule(dynamoNoPITR{}, res("aws_dynamodb_table", "t",
		map[string]ir.Value{"point_in_time_recovery": blks(4, blk("enabled", kv(true, 5)))}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test312_UnknownBlockQuiet(t *testing.T) {
	fs := runRule(dynamoNoPITR{}, res("aws_dynamodb_table", "t",
		map[string]ir.Value{"point_in_time_recovery": ku(4)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- AEGIS-AWS-313: DynamoDB table without customer-managed encryption ---

func Test313_AbsentBlockFires(t *testing.T) {
	fs := runRule(dynamoNoCMK{}, res("aws_dynamodb_table", "t", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("want high severity, got %s", fs[0].Severity)
	}
}

func Test313_DisabledFires(t *testing.T) {
	fs := runRule(dynamoNoCMK{}, res("aws_dynamodb_table", "t",
		map[string]ir.Value{"server_side_encryption": blks(4, blk("enabled", kv(false, 5)))}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test313_EnabledQuiet(t *testing.T) {
	fs := runRule(dynamoNoCMK{}, res("aws_dynamodb_table", "t",
		map[string]ir.Value{"server_side_encryption": blks(4, blk("enabled", kv(true, 5)))}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test313_UnknownBlockQuiet(t *testing.T) {
	fs := runRule(dynamoNoCMK{}, res("aws_dynamodb_table", "t",
		map[string]ir.Value{"server_side_encryption": ku(4)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- AEGIS-AWS-314: Redshift cluster unencrypted ---

func Test314_AbsentFires(t *testing.T) {
	fs := runRule(redshiftUnencrypted{}, res("aws_redshift_cluster", "rs", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test314_FalseFires(t *testing.T) {
	fs := runRule(redshiftUnencrypted{}, res("aws_redshift_cluster", "rs",
		map[string]ir.Value{"encrypted": kv(false, 3)}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test314_TrueQuiet(t *testing.T) {
	fs := runRule(redshiftUnencrypted{}, res("aws_redshift_cluster", "rs",
		map[string]ir.Value{"encrypted": kv(true, 3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test314_UnknownQuiet(t *testing.T) {
	fs := runRule(redshiftUnencrypted{}, res("aws_redshift_cluster", "rs",
		map[string]ir.Value{"encrypted": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- AEGIS-AWS-315: Redshift cluster publicly accessible ---

func Test315_TrueFires(t *testing.T) {
	fs := runRule(redshiftPublic{}, res("aws_redshift_cluster", "rs",
		map[string]ir.Value{"publicly_accessible": kv(true, 4)}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("want high severity, got %s", fs[0].Severity)
	}
}

func Test315_AbsentQuiet(t *testing.T) {
	fs := runRule(redshiftPublic{}, res("aws_redshift_cluster", "rs", map[string]ir.Value{}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test315_FalseQuiet(t *testing.T) {
	fs := runRule(redshiftPublic{}, res("aws_redshift_cluster", "rs",
		map[string]ir.Value{"publicly_accessible": kv(false, 4)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test315_UnknownQuiet(t *testing.T) {
	fs := runRule(redshiftPublic{}, res("aws_redshift_cluster", "rs",
		map[string]ir.Value{"publicly_accessible": ku(4)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- AEGIS-AWS-316: Redshift cluster without audit logging ---

func Test316_AbsentBlockFires(t *testing.T) {
	fs := runRule(redshiftNoAuditLog{}, res("aws_redshift_cluster", "rs", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityMedium {
		t.Fatalf("want medium severity, got %s", fs[0].Severity)
	}
}

func Test316_BlockPresentQuiet(t *testing.T) {
	fs := runRule(redshiftNoAuditLog{}, res("aws_redshift_cluster", "rs",
		map[string]ir.Value{"logging": blks(4, blk("bucket_name", ks("logs", 5)))}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test316_UnknownBlockQuiet(t *testing.T) {
	fs := runRule(redshiftNoAuditLog{}, res("aws_redshift_cluster", "rs",
		map[string]ir.Value{"logging": ku(4)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- AEGIS-AWS-317: EFS file system unencrypted ---

func Test317_AbsentFires(t *testing.T) {
	fs := runRule(efsUnencrypted{}, res("aws_efs_file_system", "fs", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test317_FalseFires(t *testing.T) {
	fs := runRule(efsUnencrypted{}, res("aws_efs_file_system", "fs",
		map[string]ir.Value{"encrypted": kv(false, 3)}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test317_TrueQuiet(t *testing.T) {
	fs := runRule(efsUnencrypted{}, res("aws_efs_file_system", "fs",
		map[string]ir.Value{"encrypted": kv(true, 3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test317_UnknownQuiet(t *testing.T) {
	fs := runRule(efsUnencrypted{}, res("aws_efs_file_system", "fs",
		map[string]ir.Value{"encrypted": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- AEGIS-AWS-318: OpenSearch domain without node-to-node encryption ---

func Test318_AbsentBlockFires(t *testing.T) {
	for _, typ := range []string{"aws_opensearch_domain", "aws_elasticsearch_domain"} {
		fs := runRule(opensearchNoNodeToNode{}, res(typ, "dom", map[string]ir.Value{}))
		if len(fs) != 1 {
			t.Fatalf("%s: got %d findings, want 1", typ, len(fs))
		}
		if fs[0].Severity != ir.SeverityHigh {
			t.Fatalf("%s: want high severity, got %s", typ, fs[0].Severity)
		}
	}
}

func Test318_DisabledFires(t *testing.T) {
	fs := runRule(opensearchNoNodeToNode{}, res("aws_opensearch_domain", "dom",
		map[string]ir.Value{"node_to_node_encryption": blks(4, blk("enabled", kv(false, 5)))}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test318_EnabledQuiet(t *testing.T) {
	fs := runRule(opensearchNoNodeToNode{}, res("aws_opensearch_domain", "dom",
		map[string]ir.Value{"node_to_node_encryption": blks(4, blk("enabled", kv(true, 5)))}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test318_UnknownBlockQuiet(t *testing.T) {
	fs := runRule(opensearchNoNodeToNode{}, res("aws_opensearch_domain", "dom",
		map[string]ir.Value{"node_to_node_encryption": ku(4)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- AEGIS-AWS-319: OpenSearch domain without encryption at rest ---

func Test319_AbsentBlockFires(t *testing.T) {
	for _, typ := range []string{"aws_opensearch_domain", "aws_elasticsearch_domain"} {
		fs := runRule(opensearchNoEncryptAtRest{}, res(typ, "dom", map[string]ir.Value{}))
		if len(fs) != 1 {
			t.Fatalf("%s: got %d findings, want 1", typ, len(fs))
		}
	}
}

func Test319_DisabledFires(t *testing.T) {
	fs := runRule(opensearchNoEncryptAtRest{}, res("aws_elasticsearch_domain", "dom",
		map[string]ir.Value{"encrypt_at_rest": blks(4, blk("enabled", kv(false, 5)))}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test319_EnabledQuiet(t *testing.T) {
	fs := runRule(opensearchNoEncryptAtRest{}, res("aws_opensearch_domain", "dom",
		map[string]ir.Value{"encrypt_at_rest": blks(4, blk("enabled", kv(true, 5)))}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test319_UnknownBlockQuiet(t *testing.T) {
	fs := runRule(opensearchNoEncryptAtRest{}, res("aws_opensearch_domain", "dom",
		map[string]ir.Value{"encrypt_at_rest": ku(4)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- AEGIS-AWS-320: ElastiCache replication group without transit encryption ---

func Test320_AbsentFires(t *testing.T) {
	fs := runRule(elasticacheNoTransitEnc{}, res("aws_elasticache_replication_group", "rg", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test320_FalseFires(t *testing.T) {
	fs := runRule(elasticacheNoTransitEnc{}, res("aws_elasticache_replication_group", "rg",
		map[string]ir.Value{"transit_encryption_enabled": kv(false, 3)}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test320_TrueQuiet(t *testing.T) {
	fs := runRule(elasticacheNoTransitEnc{}, res("aws_elasticache_replication_group", "rg",
		map[string]ir.Value{"transit_encryption_enabled": kv(true, 3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test320_UnknownQuiet(t *testing.T) {
	fs := runRule(elasticacheNoTransitEnc{}, res("aws_elasticache_replication_group", "rg",
		map[string]ir.Value{"transit_encryption_enabled": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- AEGIS-AWS-321: ElastiCache replication group without at-rest encryption ---

func Test321_AbsentFires(t *testing.T) {
	fs := runRule(elasticacheNoAtRestEnc{}, res("aws_elasticache_replication_group", "rg", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test321_FalseFires(t *testing.T) {
	fs := runRule(elasticacheNoAtRestEnc{}, res("aws_elasticache_replication_group", "rg",
		map[string]ir.Value{"at_rest_encryption_enabled": kv(false, 3)}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test321_TrueQuiet(t *testing.T) {
	fs := runRule(elasticacheNoAtRestEnc{}, res("aws_elasticache_replication_group", "rg",
		map[string]ir.Value{"at_rest_encryption_enabled": kv(true, 3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test321_UnknownQuiet(t *testing.T) {
	fs := runRule(elasticacheNoAtRestEnc{}, res("aws_elasticache_replication_group", "rg",
		map[string]ir.Value{"at_rest_encryption_enabled": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- AEGIS-AWS-322: Aurora cluster without backup retention ---

func Test322_AbsentFires(t *testing.T) {
	fs := runRule(auroraNoBackup{}, res("aws_rds_cluster", "c", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test322_ZeroFires(t *testing.T) {
	fs := runRule(auroraNoBackup{}, res("aws_rds_cluster", "c",
		map[string]ir.Value{"backup_retention_period": kn(0, 3)}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test322_PositiveQuiet(t *testing.T) {
	fs := runRule(auroraNoBackup{}, res("aws_rds_cluster", "c",
		map[string]ir.Value{"backup_retention_period": kn(7, 3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test322_UnknownQuiet(t *testing.T) {
	fs := runRule(auroraNoBackup{}, res("aws_rds_cluster", "c",
		map[string]ir.Value{"backup_retention_period": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- StorageRules registration order ---

func TestStorageRules_IDOrder(t *testing.T) {
	rules := StorageRules()
	want := []string{
		"AEGIS-AWS-311", "AEGIS-AWS-312", "AEGIS-AWS-313", "AEGIS-AWS-314",
		"AEGIS-AWS-315", "AEGIS-AWS-316", "AEGIS-AWS-317", "AEGIS-AWS-318",
		"AEGIS-AWS-319", "AEGIS-AWS-320", "AEGIS-AWS-321", "AEGIS-AWS-322",
	}
	if len(rules) != len(want) {
		t.Fatalf("got %d rules, want %d", len(rules), len(want))
	}
	for i, w := range want {
		if rules[i].ID() != w {
			t.Fatalf("rule %d: got %s, want %s", i, rules[i].ID(), w)
		}
	}
}

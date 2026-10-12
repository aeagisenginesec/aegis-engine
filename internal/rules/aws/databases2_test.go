package aws

import (
	"testing"

	"aegis/internal/ir"
)

func TestDatabases2Rules_IDOrder(t *testing.T) {
	rules := Databases2Rules()
	want := []string{
		"AEGIS-AWS-351", "AEGIS-AWS-352", "AEGIS-AWS-353", "AEGIS-AWS-354",
		"AEGIS-AWS-355", "AEGIS-AWS-356", "AEGIS-AWS-357", "AEGIS-AWS-358",
		"AEGIS-AWS-359", "AEGIS-AWS-360",
	}
	if len(rules) != len(want) {
		t.Fatalf("expected %d rules, got %d", len(want), len(rules))
	}
	for i, w := range want {
		if rules[i].ID() != w {
			t.Fatalf("rule %d: want ID %s, got %s", i, w, rules[i].ID())
		}
	}
}

func Test351_DocDBUnencryptedFires(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		{},
		{"storage_encrypted": kv(false, 3)},
	} {
		fs := runRule(docdbUnencrypted{}, res("aws_docdb_cluster", "main", attrs))
		if len(fs) != 1 {
			t.Fatalf("got %d findings, want 1", len(fs))
		}
		if fs[0].Severity != ir.SeverityHigh {
			t.Fatalf("want high severity, got %s", fs[0].Severity)
		}
	}
}

func Test351_DocDBEncryptedQuiet(t *testing.T) {
	fs := runRule(docdbUnencrypted{}, res("aws_docdb_cluster", "main",
		map[string]ir.Value{"storage_encrypted": kv(true, 3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test351_DocDBUnknownQuiet(t *testing.T) {
	fs := runRule(docdbUnencrypted{}, res("aws_docdb_cluster", "main",
		map[string]ir.Value{"storage_encrypted": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test352_NeptuneUnencryptedFires(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		{},
		{"storage_encrypted": kv(false, 3)},
	} {
		fs := runRule(neptuneUnencrypted{}, res("aws_neptune_cluster", "main", attrs))
		if len(fs) != 1 {
			t.Fatalf("got %d findings, want 1", len(fs))
		}
		if fs[0].Severity != ir.SeverityHigh {
			t.Fatalf("want high severity, got %s", fs[0].Severity)
		}
	}
}

func Test352_NeptuneEncryptedQuiet(t *testing.T) {
	fs := runRule(neptuneUnencrypted{}, res("aws_neptune_cluster", "main",
		map[string]ir.Value{"storage_encrypted": kv(true, 3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test352_NeptuneUnknownQuiet(t *testing.T) {
	fs := runRule(neptuneUnencrypted{}, res("aws_neptune_cluster", "main",
		map[string]ir.Value{"storage_encrypted": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test353_DocDBNoBackupFires(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		{},
		{"backup_retention_period": kn(0, 3)},
	} {
		fs := runRule(docdbNoBackup{}, res("aws_docdb_cluster", "main", attrs))
		if len(fs) != 1 {
			t.Fatalf("got %d findings, want 1", len(fs))
		}
		if fs[0].Severity != ir.SeverityMedium {
			t.Fatalf("want medium severity, got %s", fs[0].Severity)
		}
	}
}

func Test353_DocDBBackupQuiet(t *testing.T) {
	fs := runRule(docdbNoBackup{}, res("aws_docdb_cluster", "main",
		map[string]ir.Value{"backup_retention_period": kn(7, 3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test353_DocDBBackupUnknownQuiet(t *testing.T) {
	fs := runRule(docdbNoBackup{}, res("aws_docdb_cluster", "main",
		map[string]ir.Value{"backup_retention_period": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test354_MemoryDBNoTLSFires(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		{},
		{"tls_enabled": kv(false, 3)},
	} {
		fs := runRule(memorydbNoTLS{}, res("aws_memorydb_cluster", "main", attrs))
		if len(fs) != 1 {
			t.Fatalf("got %d findings, want 1", len(fs))
		}
		if fs[0].Severity != ir.SeverityHigh {
			t.Fatalf("want high severity, got %s", fs[0].Severity)
		}
	}
}

func Test354_MemoryDBTLSQuiet(t *testing.T) {
	fs := runRule(memorydbNoTLS{}, res("aws_memorydb_cluster", "main",
		map[string]ir.Value{"tls_enabled": kv(true, 3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test354_MemoryDBTLSUnknownQuiet(t *testing.T) {
	fs := runRule(memorydbNoTLS{}, res("aws_memorydb_cluster", "main",
		map[string]ir.Value{"tls_enabled": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test355_DAXNoEncryptionFires(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		{},
		{"server_side_encryption": blks(3, blk("enabled", kv(false, 4)))},
	} {
		fs := runRule(daxNoEncryption{}, res("aws_dax_cluster", "main", attrs))
		if len(fs) != 1 {
			t.Fatalf("got %d findings, want 1", len(fs))
		}
		if fs[0].Severity != ir.SeverityMedium {
			t.Fatalf("want medium severity, got %s", fs[0].Severity)
		}
	}
}

func Test355_DAXEncryptedQuiet(t *testing.T) {
	fs := runRule(daxNoEncryption{}, res("aws_dax_cluster", "main", map[string]ir.Value{
		"server_side_encryption": blks(3, blk("enabled", kv(true, 4))),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test355_DAXUnknownQuiet(t *testing.T) {
	fs := runRule(daxNoEncryption{}, res("aws_dax_cluster", "main", map[string]ir.Value{
		"server_side_encryption": blks(3, blk("enabled", ku(4))),
	}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test356_DMSPublicFires(t *testing.T) {
	fs := runRule(dmsPublic{}, res("aws_dms_replication_instance", "main",
		map[string]ir.Value{"publicly_accessible": kv(true, 3)}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Fatalf("want high severity, got %s", fs[0].Severity)
	}
}

func Test356_DMSPrivateQuiet(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		{},
		{"publicly_accessible": kv(false, 3)},
	} {
		fs := runRule(dmsPublic{}, res("aws_dms_replication_instance", "main", attrs))
		if len(fs) != 0 {
			t.Fatalf("got %d findings, want 0", len(fs))
		}
	}
}

func Test356_DMSPublicUnknownQuiet(t *testing.T) {
	fs := runRule(dmsPublic{}, res("aws_dms_replication_instance", "main",
		map[string]ir.Value{"publicly_accessible": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test357_DMSNoSSLFires(t *testing.T) {
	for _, mode := range []string{"none", "NONE", "None"} {
		fs := runRule(dmsNoSSL{}, res("aws_dms_endpoint", "src",
			map[string]ir.Value{"ssl_mode": ks(mode, 3)}))
		if len(fs) != 1 {
			t.Fatalf("mode=%q: got %d findings, want 1", mode, len(fs))
		}
		if fs[0].Severity != ir.SeverityHigh {
			t.Fatalf("want high severity, got %s", fs[0].Severity)
		}
	}
}

func Test357_DMSSLQuiet(t *testing.T) {
	// Note: absent ssl_mode now FIRES (provider default "none") — see
	// Test357_AbsentFires.
	for _, attrs := range []map[string]ir.Value{
		{"ssl_mode": ks("require", 3)},
		{"ssl_mode": ks("verify-full", 3)},
	} {
		fs := runRule(dmsNoSSL{}, res("aws_dms_endpoint", "src", attrs))
		if len(fs) != 0 {
			t.Fatalf("got %d findings, want 0", len(fs))
		}
	}
}

func Test357_DMSNoSSLUnknownQuiet(t *testing.T) {
	fs := runRule(dmsNoSSL{}, res("aws_dms_endpoint", "src",
		map[string]ir.Value{"ssl_mode": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test358_AuroraNoDelProtectionFires(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		{},
		{"deletion_protection": kv(false, 3)},
	} {
		fs := runRule(auroraNoDelProtection{}, res("aws_rds_cluster", "main", attrs))
		if len(fs) != 1 {
			t.Fatalf("got %d findings, want 1", len(fs))
		}
		if fs[0].Severity != ir.SeverityMedium {
			t.Fatalf("want medium severity, got %s", fs[0].Severity)
		}
	}
}

func Test358_AuroraDelProtectionQuiet(t *testing.T) {
	fs := runRule(auroraNoDelProtection{}, res("aws_rds_cluster", "main",
		map[string]ir.Value{"deletion_protection": kv(true, 3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test358_AuroraDelProtectionUnknownQuiet(t *testing.T) {
	fs := runRule(auroraNoDelProtection{}, res("aws_rds_cluster", "main",
		map[string]ir.Value{"deletion_protection": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test359_AuroraUnencryptedFires(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		{},
		{"storage_encrypted": kv(false, 3)},
	} {
		fs := runRule(auroraUnencrypted{}, res("aws_rds_cluster", "main", attrs))
		if len(fs) != 1 {
			t.Fatalf("got %d findings, want 1", len(fs))
		}
		if fs[0].Severity != ir.SeverityHigh {
			t.Fatalf("want high severity, got %s", fs[0].Severity)
		}
	}
}

func Test359_AuroraEncryptedQuiet(t *testing.T) {
	fs := runRule(auroraUnencrypted{}, res("aws_rds_cluster", "main",
		map[string]ir.Value{"storage_encrypted": kv(true, 3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test359_AuroraEncryptedUnknownQuiet(t *testing.T) {
	fs := runRule(auroraUnencrypted{}, res("aws_rds_cluster", "main",
		map[string]ir.Value{"storage_encrypted": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test360_AuroraNoIAMAuthFires(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		{},
		{"iam_database_authentication_enabled": kv(false, 3)},
	} {
		fs := runRule(auroraNoIAMAuth{}, res("aws_rds_cluster", "main", attrs))
		if len(fs) != 1 {
			t.Fatalf("got %d findings, want 1", len(fs))
		}
		if fs[0].Severity != ir.SeverityMedium {
			t.Fatalf("want medium severity, got %s", fs[0].Severity)
		}
	}
}

func Test360_AuroraIAMAuthQuiet(t *testing.T) {
	fs := runRule(auroraNoIAMAuth{}, res("aws_rds_cluster", "main",
		map[string]ir.Value{"iam_database_authentication_enabled": kv(true, 3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test360_AuroraIAMAuthUnknownQuiet(t *testing.T) {
	fs := runRule(auroraNoIAMAuth{}, res("aws_rds_cluster", "main",
		map[string]ir.Value{"iam_database_authentication_enabled": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test357_AbsentFires(t *testing.T) {
	// Absent ssl_mode: the AWS API default is "none" (plaintext).
	r := res("aws_dms_endpoint", "ep", map[string]ir.Value{})
	if fs := runRule(dmsNoSSL{}, r); len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

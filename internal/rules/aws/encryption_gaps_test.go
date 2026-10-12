package aws

import (
	"testing"

	"aegis/internal/ir"
)

func TestEncryptionGapRules_IDOrder(t *testing.T) {
	rules := EncryptionGapRules()
	want := []string{
		"AEGIS-AWS-514", "AEGIS-AWS-515", "AEGIS-AWS-516", "AEGIS-AWS-517",
		"AEGIS-AWS-518", "AEGIS-AWS-519", "AEGIS-AWS-520",
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

// --- 514: ElastiCache without auth token ---

func Test514_NoAuthTokenFires(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		{"transit_encryption_enabled": kv(true, 3)},
		{
			"transit_encryption_enabled": kv(true, 3),
			"auth_token":                 ks("", 4),
		},
	} {
		fs := runRule(elasticacheNoAuthToken{}, res("aws_elasticache_replication_group", "main", attrs))
		if len(fs) != 1 {
			t.Fatalf("got %d findings, want 1", len(fs))
		}
		if fs[0].Severity != ir.SeverityHigh {
			t.Fatalf("want high severity, got %s", fs[0].Severity)
		}
		if fs[0].Evidence.Attribute != "auth_token" {
			t.Fatalf("want auth_token evidence, got %s", fs[0].Evidence.Attribute)
		}
	}
}

func Test514_AuthTokenSetQuiet(t *testing.T) {
	fs := runRule(elasticacheNoAuthToken{}, res("aws_elasticache_replication_group", "main",
		map[string]ir.Value{
			"transit_encryption_enabled": kv(true, 3),
			"auth_token":                 ks("s3cr3t-token", 4),
		}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test514_TransitOffOrUnknownQuiet(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		{"transit_encryption_enabled": kv(false, 3)},
		{},
		{"transit_encryption_enabled": ku(3)},
		{"transit_encryption_enabled": kv(true, 3), "auth_token": ku(4)},
	} {
		fs := runRule(elasticacheNoAuthToken{}, res("aws_elasticache_replication_group", "main", attrs))
		if len(fs) != 0 {
			t.Fatalf("attrs %v: got %d findings, want 0", attrs, len(fs))
		}
	}
}

// --- 515: ECR without KMS ---

func Test515_NoEncryptionBlockFires(t *testing.T) {
	fs := runRule(ecrNoKMS{}, res("aws_ecr_repository", "main", map[string]ir.Value{}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityMedium {
		t.Fatalf("want medium severity, got %s", fs[0].Severity)
	}
}

func Test515_AES256Fires(t *testing.T) {
	fs := runRule(ecrNoKMS{}, res("aws_ecr_repository", "main",
		map[string]ir.Value{
			"encryption_configuration": blks(3, blk("encryption_type", ks("AES256", 4))),
		}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test515_KMSQuiet(t *testing.T) {
	for _, typ := range []string{"KMS", "kms"} {
		fs := runRule(ecrNoKMS{}, res("aws_ecr_repository", "main",
			map[string]ir.Value{
				"encryption_configuration": blks(3, blk("encryption_type", ks(typ, 4))),
			}))
		if len(fs) != 0 {
			t.Fatalf("type %s: got %d findings, want 0", typ, len(fs))
		}
	}
}

func Test515_UnknownQuiet(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		{"encryption_configuration": ku(3)},
		{"encryption_configuration": blks(3, blk("encryption_type", ku(4)))},
	} {
		fs := runRule(ecrNoKMS{}, res("aws_ecr_repository", "main", attrs))
		if len(fs) != 0 {
			t.Fatalf("got %d findings, want 0", len(fs))
		}
	}
}

// --- 516: EMR in-transit encryption ---

func emrConfig(transit, atRest bool) map[string]ir.Value {
	return map[string]ir.Value{
		"configuration": ks(
			`{"EncryptionConfiguration":{"EnableInTransitEncryption":`+boolStr(transit)+
				`,"EnableAtRestEncryption":`+boolStr(atRest)+`}}`, 3),
	}
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func Test516_NoTransitFires(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		emrConfig(false, true),
		{"configuration": ks(`{"EncryptionConfiguration":{"EnableAtRestEncryption":true}}`, 3)},
	} {
		fs := runRule(emrNoTransitEncryption{}, res("aws_emr_security_configuration", "main", attrs))
		if len(fs) != 1 {
			t.Fatalf("got %d findings, want 1", len(fs))
		}
		if fs[0].Severity != ir.SeverityMedium {
			t.Fatalf("want medium severity, got %s", fs[0].Severity)
		}
	}
}

func Test516_TransitEnabledQuiet(t *testing.T) {
	fs := runRule(emrNoTransitEncryption{}, res("aws_emr_security_configuration", "main", emrConfig(true, true)))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test516_BadConfigQuiet(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		{},
		{"configuration": ku(3)},
		{"configuration": ks("not-json{{{", 3)},
		{"configuration": ks(`{"SomethingElse":{}}`, 3)},
	} {
		fs := runRule(emrNoTransitEncryption{}, res("aws_emr_security_configuration", "main", attrs))
		if len(fs) != 0 {
			t.Fatalf("got %d findings, want 0", len(fs))
		}
	}
}

// --- 517: EMR at-rest encryption ---

func Test517_NoAtRestFires(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		emrConfig(true, false),
		{"configuration": ks(`{"EncryptionConfiguration":{"EnableInTransitEncryption":true}}`, 3)},
	} {
		fs := runRule(emrNoLocalDiskEncryption{}, res("aws_emr_security_configuration", "main", attrs))
		if len(fs) != 1 {
			t.Fatalf("got %d findings, want 1", len(fs))
		}
		if fs[0].Severity != ir.SeverityMedium {
			t.Fatalf("want medium severity, got %s", fs[0].Severity)
		}
	}
}

func Test517_AtRestEnabledQuiet(t *testing.T) {
	fs := runRule(emrNoLocalDiskEncryption{}, res("aws_emr_security_configuration", "main", emrConfig(true, true)))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test517_BadConfigQuiet(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		{},
		{"configuration": ku(3)},
		{"configuration": ks("not-json{{{", 3)},
		{"configuration": ks(`{"SomethingElse":{}}`, 3)},
	} {
		fs := runRule(emrNoLocalDiskEncryption{}, res("aws_emr_security_configuration", "main", attrs))
		if len(fs) != 0 {
			t.Fatalf("got %d findings, want 0", len(fs))
		}
	}
}

// --- 518: DAX without TLS ---

func Test518_NoTLSFires(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		{},
		{"cluster_endpoint_encryption_type": ks("NONE", 3)},
	} {
		fs := runRule(daxNoTLS{}, res("aws_dax_cluster", "main", attrs))
		if len(fs) != 1 {
			t.Fatalf("got %d findings, want 1", len(fs))
		}
		if fs[0].Severity != ir.SeverityMedium {
			t.Fatalf("want medium severity, got %s", fs[0].Severity)
		}
	}
}

func Test518_TLSQuiet(t *testing.T) {
	for _, typ := range []string{"TLS", "tls"} {
		fs := runRule(daxNoTLS{}, res("aws_dax_cluster", "main",
			map[string]ir.Value{"cluster_endpoint_encryption_type": ks(typ, 3)}))
		if len(fs) != 0 {
			t.Fatalf("type %s: got %d findings, want 0", typ, len(fs))
		}
	}
}

func Test518_UnknownQuiet(t *testing.T) {
	fs := runRule(daxNoTLS{}, res("aws_dax_cluster", "main",
		map[string]ir.Value{"cluster_endpoint_encryption_type": ku(3)}))
	if len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 519: Search domain outdated TLS ---

func Test519_OldTLSFires(t *testing.T) {
	for _, typ := range []string{"aws_elasticsearch_domain", "aws_opensearch_domain"} {
		fs := runRule(searchOutdatedTLS{}, res(typ, "main",
			map[string]ir.Value{
				"domain_endpoint_options": blks(3, blk("tls_security_policy", ks("Policy-Min-TLS-1-0-2019-07", 4))),
			}))
		if len(fs) != 1 {
			t.Fatalf("type %s: got %d findings, want 1", typ, len(fs))
		}
		if fs[0].Severity != ir.SeverityMedium {
			t.Fatalf("want medium severity, got %s", fs[0].Severity)
		}
	}
}

func Test519_ModernTLSQuiet(t *testing.T) {
	for _, pol := range []string{"Policy-Min-TLS-1-2-2019-07", "Policy-Min-TLS-1-2-PFS-2023-10"} {
		fs := runRule(searchOutdatedTLS{}, res("aws_elasticsearch_domain", "main",
			map[string]ir.Value{
				"domain_endpoint_options": blks(3, blk("tls_security_policy", ks(pol, 4))),
			}))
		if len(fs) != 0 {
			t.Fatalf("policy %s: got %d findings, want 0", pol, len(fs))
		}
	}
}

func Test519_MissingOrUnknownQuiet(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		{},
		{"domain_endpoint_options": ku(3)},
		{"domain_endpoint_options": blks(3, blk("tls_security_policy", ku(4)))},
		{"domain_endpoint_options": blks(3, blk("enforce_https", kv(true, 4)))},
		{"domain_endpoint_options": blks(3, blk("tls_security_policy", ks("Some-Future-Policy", 4)))},
	} {
		fs := runRule(searchOutdatedTLS{}, res("aws_elasticsearch_domain", "main", attrs))
		if len(fs) != 0 {
			t.Fatalf("got %d findings, want 0", len(fs))
		}
	}
}

// --- 520: Transfer Server outdated policy ---

func Test520_OldPolicyFires(t *testing.T) {
	fs := runRule(transferOldSecurityPolicy{}, res("aws_transfer_server", "main",
		map[string]ir.Value{"security_policy_name": ks("TransferSecurityPolicy-2018-11", 3)}))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityMedium {
		t.Fatalf("want medium severity, got %s", fs[0].Severity)
	}
}

func Test520_ModernPolicyQuiet(t *testing.T) {
	for _, pol := range []string{
		"TransferSecurityPolicy-2020-06",
		"TransferSecurityPolicy-2022-03",
		"TransferSecurityPolicy-2024-01",
	} {
		fs := runRule(transferOldSecurityPolicy{}, res("aws_transfer_server", "main",
			map[string]ir.Value{"security_policy_name": ks(pol, 3)}))
		if len(fs) != 0 {
			t.Fatalf("policy %s: got %d findings, want 0", pol, len(fs))
		}
	}
}

func Test520_MissingOrUnknownQuiet(t *testing.T) {
	for _, attrs := range []map[string]ir.Value{
		{},
		{"security_policy_name": ku(3)},
		{"security_policy_name": ks("TransferSecurityPolicy-2099-99", 3)},
	} {
		fs := runRule(transferOldSecurityPolicy{}, res("aws_transfer_server", "main", attrs))
		if len(fs) != 0 {
			t.Fatalf("got %d findings, want 0", len(fs))
		}
	}
}

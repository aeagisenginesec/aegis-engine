package aws

// Rule IDs covered in this file: AEGIS-AWS-361, AEGIS-AWS-363, AEGIS-AWS-364, AEGIS-AWS-366, AEGIS-AWS-368, AEGIS-AWS-369

import (
	"fmt"
	"testing"

	"aegis/internal/ir"
)

func TestAnalyticsRulesIDOrder(t *testing.T) {
	rules := AnalyticsRules()
	if len(rules) != 10 {
		t.Fatalf("expected 10 analytics rules, got %d", len(rules))
	}
	for i, r := range rules {
		want := fmt.Sprintf("AEGIS-AWS-%d", 361+i)
		if r.ID() != want {
			t.Errorf("rule %d: want ID %s, got %s", i, want, r.ID())
		}
	}
}

// --- 361: EMR security configuration ---

func Test361_DisabledFires(t *testing.T) {
	cfg := res("aws_emr_security_configuration", "c", map[string]ir.Value{
		"configuration": ks(`{"EncryptionConfiguration":{"EnableAtRestEncryption":false}}`, 3),
	})
	fs := runRule(emrNoAtRestEncryption{}, cfg)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityHigh {
		t.Errorf("want high severity, got %s", fs[0].Severity)
	}
}

func Test361_EnabledQuiet(t *testing.T) {
	cfg := res("aws_emr_security_configuration", "c", map[string]ir.Value{
		"configuration": ks(`{"EncryptionConfiguration":{"EnableAtRestEncryption":true}}`, 3),
	})
	if fs := runRule(emrNoAtRestEncryption{}, cfg); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test361_UnknownQuiet(t *testing.T) {
	cfg := res("aws_emr_security_configuration", "c", map[string]ir.Value{
		"configuration": ku(3),
	})
	if fs := runRule(emrNoAtRestEncryption{}, cfg); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test361_BadJSONQuiet(t *testing.T) {
	cfg := res("aws_emr_security_configuration", "c", map[string]ir.Value{
		"configuration": ks(`{not json`, 3),
	})
	if fs := runRule(emrNoAtRestEncryption{}, cfg); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 362: EMR visible to all users ---

func Test362_TrueFires(t *testing.T) {
	c := res("aws_emr_cluster", "c", map[string]ir.Value{"visible_to_all_users": kv(true, 3)})
	fs := runRule(emrVisibleToAllUsers{}, c)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	if fs[0].Severity != ir.SeverityMedium {
		t.Errorf("want medium severity, got %s", fs[0].Severity)
	}
}

func Test362_FalseQuiet(t *testing.T) {
	c := res("aws_emr_cluster", "c", map[string]ir.Value{"visible_to_all_users": kv(false, 3)})
	if fs := runRule(emrVisibleToAllUsers{}, c); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test362_UnknownQuiet(t *testing.T) {
	c := res("aws_emr_cluster", "c", map[string]ir.Value{"visible_to_all_users": ku(3)})
	if fs := runRule(emrVisibleToAllUsers{}, c); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 363: Athena workgroup ---

func athenaRes(encOpt string, optKnown bool) ir.Resource {
	var enc map[string]ir.Value
	if optKnown {
		enc = blk("encryption_option", ks(encOpt, 6))
	} else {
		enc = blk("encryption_option", ku(6))
	}
	return res("aws_athena_workgroup", "w", map[string]ir.Value{
		"configuration": blks(3,
			blk("result_configuration", blks(4,
				blk("encryption_configuration", blks(5, enc)))),
		),
	})
}

func Test363_NoneFires(t *testing.T) {
	fs := runRule(athenaNoResultEncryption{}, athenaRes("NONE", true))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test363_SSEKMSQuiet(t *testing.T) {
	if fs := runRule(athenaNoResultEncryption{}, athenaRes("SSE_KMS", true)); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test363_UnknownQuiet(t *testing.T) {
	if fs := runRule(athenaNoResultEncryption{}, athenaRes("", false)); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test363_AbsentChainFires(t *testing.T) {
	w := res("aws_athena_workgroup", "w", map[string]ir.Value{})
	fs := runRule(athenaNoResultEncryption{}, w)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

// --- 364: Glue data catalog ---

func glueRes(mode string, modeKnown bool) ir.Resource {
	var rest map[string]ir.Value
	if modeKnown {
		rest = blk("catalog_encryption_mode", ks(mode, 6))
	} else {
		rest = blk("catalog_encryption_mode", ku(6))
	}
	return res("aws_glue_data_catalog_encryption_settings", "s", map[string]ir.Value{
		"data_catalog_encryption_settings": blks(3,
			blk("encryption_at_rest", blks(5, rest))),
	})
}

func Test364_NonKMSFires(t *testing.T) {
	fs := runRule(glueCatalogNoSSEKMS{}, glueRes("SSE-S3", true))
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test364_SSEKMSQuiet(t *testing.T) {
	if fs := runRule(glueCatalogNoSSEKMS{}, glueRes("SSE-KMS", true)); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test364_UnknownQuiet(t *testing.T) {
	if fs := runRule(glueCatalogNoSSEKMS{}, glueRes("", false)); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test364_AbsentBlockFires(t *testing.T) {
	s := res("aws_glue_data_catalog_encryption_settings", "s", map[string]ir.Value{})
	fs := runRule(glueCatalogNoSSEKMS{}, s)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

// --- 365: Firehose ---

func Test365_AbsentFires(t *testing.T) {
	s := res("aws_kinesis_firehose_delivery_stream", "s", map[string]ir.Value{})
	fs := runRule(firehoseNoEncryption{}, s)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test365_DisabledFires(t *testing.T) {
	s := res("aws_kinesis_firehose_delivery_stream", "s", map[string]ir.Value{
		"server_side_encryption": blks(3, blk("enabled", kv(false, 4))),
	})
	fs := runRule(firehoseNoEncryption{}, s)
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
}

func Test365_EnabledQuiet(t *testing.T) {
	s := res("aws_kinesis_firehose_delivery_stream", "s", map[string]ir.Value{
		"server_side_encryption": blks(3, blk("enabled", kv(true, 4))),
	})
	if fs := runRule(firehoseNoEncryption{}, s); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

func Test365_UnknownQuiet(t *testing.T) {
	s := res("aws_kinesis_firehose_delivery_stream", "s", map[string]ir.Value{
		"server_side_encryption": blks(3, blk("enabled", ku(4))),
	})
	if fs := runRule(firehoseNoEncryption{}, s); len(fs) != 0 {
		t.Fatalf("got %d findings, want 0", len(fs))
	}
}

// --- 366-370: KMS-absent rules ---

func kmsRuleCases() []struct {
	name string
	rule ir.Rule
	typ  string
	attr string
	sev  ir.Severity
} {
	return []struct {
		name string
		rule ir.Rule
		typ  string
		attr string
		sev  ir.Severity
	}{
		{"366", sagemakerNotebookNoKMS{}, "aws_sagemaker_notebook_instance", "kms_key_id", ir.SeverityHigh},
		{"367", sagemakerEndpointNoKMS{}, "aws_sagemaker_endpoint_configuration", "kms_key_arn", ir.SeverityMedium},
		{"368", fsxWindowsNoKMS{}, "aws_fsx_windows_file_system", "kms_key_id", ir.SeverityHigh},
		{"369", fsxLustreNoKMS{}, "aws_fsx_lustre_file_system", "kms_key_id", ir.SeverityHigh},
		{"370", sagemakerDomainNoKMS{}, "aws_sagemaker_domain", "kms_key_id", ir.SeverityMedium},
	}
}

func TestKMSAbsentFires(t *testing.T) {
	for _, c := range kmsRuleCases() {
		r := res(c.typ, "x", map[string]ir.Value{})
		fs := runRule(c.rule, r)
		if len(fs) != 1 {
			t.Errorf("%s: absent key: got %d findings, want 1", c.name, len(fs))
			continue
		}
		if fs[0].Severity != c.sev {
			t.Errorf("%s: want severity %s, got %s", c.name, c.sev, fs[0].Severity)
		}
		if fs[0].Evidence.Attribute != c.attr {
			t.Errorf("%s: want attribute %s, got %s", c.name, c.attr, fs[0].Evidence.Attribute)
		}
	}
}

func TestKMSPresentQuiet(t *testing.T) {
	for _, c := range kmsRuleCases() {
		r := res(c.typ, "x", map[string]ir.Value{
			c.attr: ks("arn:aws:kms:us-east-1:123456789012:key/abcd", 3),
		})
		if fs := runRule(c.rule, r); len(fs) != 0 {
			t.Errorf("%s: present key: got %d findings, want 0", c.name, len(fs))
		}
	}
}

func TestKMSUnknownQuiet(t *testing.T) {
	for _, c := range kmsRuleCases() {
		r := res(c.typ, "x", map[string]ir.Value{c.attr: ku(3)})
		if fs := runRule(c.rule, r); len(fs) != 0 {
			t.Errorf("%s: unknown key: got %d findings, want 0", c.name, len(fs))
		}
	}
}

func TestKMSEmptyFires(t *testing.T) {
	for _, c := range kmsRuleCases() {
		r := res(c.typ, "x", map[string]ir.Value{c.attr: ks("  ", 3)})
		fs := runRule(c.rule, r)
		if len(fs) != 1 {
			t.Errorf("%s: empty key: got %d findings, want 1", c.name, len(fs))
		}
	}
}

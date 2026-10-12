package aws

import (
	"testing"

	"aegis/internal/ir"
)

func Test443_EnforcedQuiet(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`
	if !policyEnforcesSecureTransport(doc) {
		t.Fatal("should detect SecureTransport deny")
	}
}

func Test443_NoDenyFires(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}`
	if policyEnforcesSecureTransport(doc) {
		t.Fatal("allow-only policy must not count as enforcement")
	}
}

func Test443_MalformedQuiet(t *testing.T) {
	if policyEnforcesSecureTransport("{not json") {
		t.Fatal("malformed JSON must not count")
	}
}

func Test443_BoolFalseVariant(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Deny","Condition":{"Bool":{"aws:SecureTransport":false}}}]}`
	if !policyEnforcesSecureTransport(doc) {
		t.Fatal("bool false variant should count")
	}
}

func Test443_CheckAllFires(t *testing.T) {
	bkt := res("aws_s3_bucket", "data", map[string]ir.Value{})
	pol := res("aws_s3_bucket_policy", "data", map[string]ir.Value{
		"bucket": ks("data", 2),
		"policy": ks(`{"Statement":[]}`, 3),
	})
	out := (s3NoSecureTransport{}).CheckAll([]ir.Resource{bkt, pol})
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
}

func Test443_CheckAllQuietWhenEnforced(t *testing.T) {
	bkt := res("aws_s3_bucket", "data", map[string]ir.Value{})
	pol := res("aws_s3_bucket_policy", "data", map[string]ir.Value{
		"bucket": ks("data", 2),
		"policy": ks(`{"Statement":[{"Effect":"Deny","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`, 3),
	})
	out := (s3NoSecureTransport{}).CheckAll([]ir.Resource{bkt, pol})
	if len(out) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(out))
	}
}

func Test444_PublicIPFires(t *testing.T) {
	r := res("aws_instance", "web", map[string]ir.Value{"associate_public_ip_address": kv(true, 3)})
	if len(runRule(ec2PublicIP{}, r)) != 1 {
		t.Fatal("expected 1 finding")
	}
}

func Test444_PrivateQuiet(t *testing.T) {
	r := res("aws_instance", "web", map[string]ir.Value{"associate_public_ip_address": kv(false, 3)})
	if len(runRule(ec2PublicIP{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func Test444_UnknownQuiet(t *testing.T) {
	r := res("aws_instance", "web", map[string]ir.Value{"associate_public_ip_address": ku(3)})
	if len(runRule(ec2PublicIP{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func Test445_NoLoggingFires(t *testing.T) {
	r := res("aws_s3_bucket", "data", map[string]ir.Value{})
	if len(runRule(s3NoAccessLogging{}, r)) != 1 {
		t.Fatal("expected 1 finding")
	}
}

func Test445_LoggingQuiet(t *testing.T) {
	r := res("aws_s3_bucket", "data", map[string]ir.Value{
		"logging": blks(3, blk("target_bucket", ks("logs", 4))),
	})
	if len(runRule(s3NoAccessLogging{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func Test446_NoMultiAZFires(t *testing.T) {
	r := res("aws_db_instance", "main", map[string]ir.Value{})
	if len(runRule(rdsNoMultiAZ{}, r)) != 1 {
		t.Fatal("expected 1 finding for absent multi_az")
	}
}

func Test446_MultiAZQuiet(t *testing.T) {
	r := res("aws_db_instance", "main", map[string]ir.Value{"multi_az": kv(true, 3)})
	if len(runRule(rdsNoMultiAZ{}, r)) != 0 {
		t.Fatal("expected 0 findings")
	}
}

func Test446_UnknownQuiet(t *testing.T) {
	r := res("aws_db_instance", "main", map[string]ir.Value{"multi_az": ku(3)})
	if len(runRule(rdsNoMultiAZ{}, r)) != 0 {
		t.Fatal("expected 0 findings for unknown")
	}
}

func TestCheckovParityRules_IDOrder(t *testing.T) {
	rules := CheckovParityRules()
	want := []string{"AEGIS-AWS-443", "AEGIS-AWS-444", "AEGIS-AWS-445", "AEGIS-AWS-446"}
	if len(rules) != len(want) {
		t.Fatalf("want %d rules, got %d", len(want), len(rules))
	}
	for i, w := range want {
		if rules[i].ID() != w {
			t.Fatalf("want %s at %d, got %s", w, i, rules[i].ID())
		}
	}
}

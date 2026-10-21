package aws

import (
	"testing"

	"aegis/internal/ir"
)

func sseInline(algo, key string) ir.Value {
	def := map[string]ir.Value{"sse_algorithm": ks(algo, 6)}
	if key != "" {
		def["kms_master_key_id"] = ks(key, 6)
	}
	return blks(3, blk("rule", blks(4, map[string]ir.Value{
		"apply_server_side_encryption_by_default": blks(5, def),
	})))
}

func sseStandalone(bucket, algo, key string) ir.Resource {
	def := map[string]ir.Value{"sse_algorithm": ks(algo, 6)}
	if key != "" {
		def["kms_master_key_id"] = ks(key, 6)
	}
	return res("aws_s3_bucket_server_side_encryption_configuration", bucket, map[string]ir.Value{
		"bucket": ks(bucket, 2),
		"rule": blks(3, map[string]ir.Value{
			"apply_server_side_encryption_by_default": blks(4, def),
		}),
	})
}

// --- AEGIS-AWS-852: S3 CMK ---

func Test852_InlineAES256Fires(t *testing.T) {
	bkt := res("aws_s3_bucket", "data", map[string]ir.Value{
		"server_side_encryption_configuration": sseInline("AES256", ""),
	})
	if f := runCross(s3NoCMK{}, bkt); len(f) != 1 || f[0].RuleID != "AEGIS-AWS-852" {
		t.Errorf("expected 852 on AES256 bucket, got %+v", f)
	}
}

func Test852_InlineKMSWithCMKQuiet(t *testing.T) {
	bkt := res("aws_s3_bucket", "data", map[string]ir.Value{
		"server_side_encryption_configuration": sseInline("aws:kms", "arn:aws:kms:us-east-1:123456789012:key/abc-123"),
	})
	if f := runCross(s3NoCMK{}, bkt); len(f) != 0 {
		t.Errorf("expected quiet on aws:kms + CMK, got %+v", f)
	}
}

func Test852_InlineKMSNoKeyFires(t *testing.T) {
	bkt := res("aws_s3_bucket", "data", map[string]ir.Value{
		"server_side_encryption_configuration": sseInline("aws:kms", ""),
	})
	if f := runCross(s3NoCMK{}, bkt); len(f) != 1 {
		t.Errorf("expected 852 on aws:kms without key, got %+v", f)
	}
}

func Test852_InlineKMSAWSManagedKeyFires(t *testing.T) {
	for _, key := range []string{
		"arn:aws:kms:us-east-1:123456789012:key/aws/s3",
		"alias/aws/s3",
		"aws/s3",
	} {
		bkt := res("aws_s3_bucket", "data", map[string]ir.Value{
			"server_side_encryption_configuration": sseInline("aws:kms", key),
		})
		if f := runCross(s3NoCMK{}, bkt); len(f) != 1 {
			t.Errorf("key %q: expected 852 (AWS-managed aws/s3 key), got %+v", key, f)
		}
	}
}

func Test852_UnencryptedQuiet(t *testing.T) {
	// No SSE at all: 001's job, not 852's.
	bkt := res("aws_s3_bucket", "data", nil)
	if f := runCross(s3NoCMK{}, bkt); len(f) != 0 {
		t.Errorf("expected quiet on unencrypted bucket, got %+v", f)
	}
}

func Test852_StandaloneAES256Fires(t *testing.T) {
	bkt := res("aws_s3_bucket", "data", nil)
	cfg := sseStandalone("data", "AES256", "")
	if f := runCross(s3NoCMK{}, bkt, cfg); len(f) != 1 || f[0].Resource != "aws_s3_bucket.data" {
		t.Errorf("expected 852 on bucket via standalone AES256 config, got %+v", f)
	}
}

func Test852_StandaloneKMSWithCMKQuiet(t *testing.T) {
	bkt := res("aws_s3_bucket", "data", nil)
	cfg := sseStandalone("data", "aws:kms", "arn:aws:kms:us-east-1:123456789012:key/abc-123")
	if f := runCross(s3NoCMK{}, bkt, cfg); len(f) != 0 {
		t.Errorf("expected quiet on standalone aws:kms + CMK, got %+v", f)
	}
}

// --- AEGIS-AWS-853: DocumentDB CMK ---

func Test853_AWSManagedFires(t *testing.T) {
	r := res("aws_docdb_cluster", "db", map[string]ir.Value{
		"storage_encrypted": kv(true, 3),
	})
	if f := runRule(docdbNoCMK{}, r); len(f) != 1 || f[0].RuleID != "AEGIS-AWS-853" {
		t.Errorf("expected 853 on encrypted DocDB without kms_key_id, got %+v", f)
	}
}

func Test853_CMKQuiet(t *testing.T) {
	r := res("aws_docdb_cluster", "db", map[string]ir.Value{
		"storage_encrypted": kv(true, 3),
		"kms_key_id":        ks("arn:aws:kms:us-east-1:123456789012:key/abc-123", 3),
	})
	if f := runRule(docdbNoCMK{}, r); len(f) != 0 {
		t.Errorf("expected quiet on DocDB with CMK, got %+v", f)
	}
}

func Test853_UnencryptedQuiet(t *testing.T) {
	// Unencrypted: 351's job, not 853's.
	r := res("aws_docdb_cluster", "db", map[string]ir.Value{
		"storage_encrypted": kv(false, 3),
	})
	if f := runRule(docdbNoCMK{}, r); len(f) != 0 {
		t.Errorf("expected quiet on unencrypted DocDB, got %+v", f)
	}
}

// --- AEGIS-AWS-854: Neptune CMK ---

func Test854_AWSManagedFires(t *testing.T) {
	r := res("aws_neptune_cluster", "db", map[string]ir.Value{
		"storage_encrypted": kv(true, 3),
	})
	if f := runRule(neptuneNoCMK{}, r); len(f) != 1 || f[0].RuleID != "AEGIS-AWS-854" {
		t.Errorf("expected 854 on encrypted Neptune without kms_key_id, got %+v", f)
	}
}

func Test854_CMKQuiet(t *testing.T) {
	r := res("aws_neptune_cluster", "db", map[string]ir.Value{
		"storage_encrypted": kv(true, 3),
		"kms_key_id":        ks("arn:aws:kms:us-east-1:123456789012:key/abc-123", 3),
	})
	if f := runRule(neptuneNoCMK{}, r); len(f) != 0 {
		t.Errorf("expected quiet on Neptune with CMK, got %+v", f)
	}
}

func Test854_UnencryptedQuiet(t *testing.T) {
	r := res("aws_neptune_cluster", "db", map[string]ir.Value{
		"storage_encrypted": kv(false, 3),
	})
	if f := runRule(neptuneNoCMK{}, r); len(f) != 0 {
		t.Errorf("expected quiet on unencrypted Neptune, got %+v", f)
	}
}

// --- AEGIS-AWS-855: EBS volume CMK ---

func Test855_AWSManagedFires(t *testing.T) {
	r := res("aws_ebs_volume", "v", map[string]ir.Value{
		"encrypted": kv(true, 3),
	})
	if f := runRule(ebsVolumeNoCMK{}, r); len(f) != 1 || f[0].RuleID != "AEGIS-AWS-855" {
		t.Errorf("expected 855 on encrypted EBS volume without kms_key_id, got %+v", f)
	}
}

func Test855_CMKQuiet(t *testing.T) {
	r := res("aws_ebs_volume", "v", map[string]ir.Value{
		"encrypted":  kv(true, 3),
		"kms_key_id": ks("arn:aws:kms:us-east-1:123456789012:key/abc-123", 3),
	})
	if f := runRule(ebsVolumeNoCMK{}, r); len(f) != 0 {
		t.Errorf("expected quiet on EBS volume with CMK, got %+v", f)
	}
}

func Test855_UnencryptedQuiet(t *testing.T) {
	// Unencrypted: 009's job, not 855's.
	r := res("aws_ebs_volume", "v", map[string]ir.Value{
		"encrypted": kv(false, 3),
	})
	if f := runRule(ebsVolumeNoCMK{}, r); len(f) != 0 {
		t.Errorf("expected quiet on unencrypted EBS volume, got %+v", f)
	}
}

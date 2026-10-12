package aws

import (
	"testing"

	"aegis/internal/ir"
)

// AEGIS-AWS-001: S3 bucket without server-side encryption.

func TestS3Encryption_AbsentBlockFires(t *testing.T) {
	bkt := res("aws_s3_bucket", "data", nil)
	f := runRule(s3Encryption{}, bkt)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].RuleID != "AEGIS-AWS-001" || f[0].Severity != "high" {
		t.Fatalf("wrong finding: %+v", f[0])
	}
	if f[0].Resource != "aws_s3_bucket.data" {
		t.Fatalf("wrong resource: %s", f[0].Resource)
	}
	if f[0].Evidence.Attribute != "server_side_encryption_configuration" {
		t.Fatalf("wrong evidence attribute: %s", f[0].Evidence.Attribute)
	}
	if f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatal("evidence must carry actual and expected")
	}
	if f[0].Evidence.Span.File == "" {
		t.Fatal("evidence must carry a span")
	}
}

func TestS3Encryption_EmptyBlockFires(t *testing.T) {
	bkt := res("aws_s3_bucket", "data", map[string]ir.Value{
		"server_side_encryption_configuration": blks(3, blk()),
	})
	if f := runRule(s3Encryption{}, bkt); len(f) != 1 {
		t.Fatalf("expected 1 finding for empty SSE block, got %d", len(f))
	}
}

func TestS3Encryption_ConfiguredOK(t *testing.T) {
	bkt := res("aws_s3_bucket", "data", map[string]ir.Value{
		"server_side_encryption_configuration": blks(3, blk("rule", blks(4, map[string]ir.Value{
			"apply_server_side_encryption_by_default": blks(5, map[string]ir.Value{"sse_algorithm": ks("AES256", 6)}),
		}))),
	})
	if f := runRule(s3Encryption{}, bkt); len(f) != 0 {
		t.Fatalf("expected no findings for encrypted bucket, got %d: %+v", len(f), f)
	}
}

func TestS3Encryption_UnknownBlockNoFinding(t *testing.T) {
	bkt := res("aws_s3_bucket", "data", map[string]ir.Value{
		"server_side_encryption_configuration": ku(3),
	})
	if f := runRule(s3Encryption{}, bkt); len(f) != 0 {
		t.Fatalf("unknown SSE block must not fire, got %d", len(f))
	}
}

func TestS3Encryption_UnknownAlgorithmNoFinding(t *testing.T) {
	bkt := res("aws_s3_bucket", "data", map[string]ir.Value{
		"server_side_encryption_configuration": blks(3, blk("rule", blks(4, map[string]ir.Value{
			"apply_server_side_encryption_by_default": blks(5, map[string]ir.Value{"sse_algorithm": ku(6)}),
		}))),
	})
	if f := runRule(s3Encryption{}, bkt); len(f) != 0 {
		t.Fatalf("unknown sse_algorithm must not fire, got %d", len(f))
	}
}

func TestS3Encryption_StandaloneResourceNoFinding(t *testing.T) {
	r := res("aws_s3_bucket_server_side_encryption_configuration", "data", map[string]ir.Value{
		"bucket": ks("data", 2),
	})
	if f := runRule(s3Encryption{}, r); len(f) != 0 {
		t.Fatalf("standalone SSE resource must not fire, got %d", len(f))
	}
}

// AEGIS-AWS-002: S3 bucket with public ACL.

func TestS3PublicACL_Fires(t *testing.T) {
	for _, acl := range []string{"public-read", "public-read-write", "authenticated-read"} {
		bkt := res("aws_s3_bucket", "data", map[string]ir.Value{"acl": ks(acl, 3)})
		f := runRule(s3PublicACL{}, bkt)
		if len(f) != 1 {
			t.Fatalf("acl=%q: expected 1 finding, got %d", acl, len(f))
		}
		if f[0].Severity != "high" || f[0].Evidence.Attribute != "acl" || f[0].Evidence.Actual != acl {
			t.Fatalf("acl=%q: wrong finding: %+v", acl, f[0])
		}
	}
}

func TestS3PublicACL_PrivateOK(t *testing.T) {
	bkt := res("aws_s3_bucket", "data", map[string]ir.Value{"acl": ks("private", 3)})
	if f := runRule(s3PublicACL{}, bkt); len(f) != 0 {
		t.Fatalf("private acl must not fire, got %d", len(f))
	}
}

func TestS3PublicACL_AbsentOK(t *testing.T) {
	bkt := res("aws_s3_bucket", "data", nil)
	if f := runRule(s3PublicACL{}, bkt); len(f) != 0 {
		t.Fatalf("absent acl (default private) must not fire, got %d", len(f))
	}
}

func TestS3PublicACL_UnknownNoFinding(t *testing.T) {
	bkt := res("aws_s3_bucket", "data", map[string]ir.Value{"acl": ku(3)})
	if f := runRule(s3PublicACL{}, bkt); len(f) != 0 {
		t.Fatalf("unknown acl must not fire, got %d", len(f))
	}
}

// AEGIS-AWS-003: S3 bucket policy allows public principal.

func TestS3PublicPolicy_StarPrincipalFires(t *testing.T) {
	pol := res("aws_s3_bucket_policy", "data", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]}`, 3),
	})
	f := runRule(s3PublicPolicy{}, pol)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != "critical" || f[0].Evidence.Attribute != "policy" {
		t.Fatalf("wrong finding: %+v", f[0])
	}
}

func TestS3PublicPolicy_MapPrincipalFires(t *testing.T) {
	pol := res("aws_s3_bucket_policy", "data", map[string]ir.Value{
		"policy": ks(`{"Statement":{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:*","Resource":"*"}}`, 3),
	})
	if f := runRule(s3PublicPolicy{}, pol); len(f) != 1 {
		t.Fatalf("expected 1 finding for {AWS:*}, got %d", len(f))
	}
}

func TestS3PublicPolicy_DenyOK(t *testing.T) {
	pol := res("aws_s3_bucket_policy", "data", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Deny","Principal":"*","Action":"*","Resource":"*"}]}`, 3),
	})
	if f := runRule(s3PublicPolicy{}, pol); len(f) != 0 {
		t.Fatalf("explicit Deny must not fire, got %d", len(f))
	}
}

func TestS3PublicPolicy_ScopedPrincipalOK(t *testing.T) {
	pol := res("aws_s3_bucket_policy", "data", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123:root"},"Action":"s3:GetObject","Resource":"*"}]}`, 3),
	})
	if f := runRule(s3PublicPolicy{}, pol); len(f) != 0 {
		t.Fatalf("scoped principal must not fire, got %d", len(f))
	}
}

func TestS3PublicPolicy_UnknownNoFinding(t *testing.T) {
	pol := res("aws_s3_bucket_policy", "data", map[string]ir.Value{"policy": ku(3)})
	if f := runRule(s3PublicPolicy{}, pol); len(f) != 0 {
		t.Fatalf("unknown policy must not fire, got %d", len(f))
	}
}

func TestS3PublicPolicy_MalformedNoFinding(t *testing.T) {
	pol := res("aws_s3_bucket_policy", "data", map[string]ir.Value{"policy": ks(`{not json`, 3)})
	if f := runRule(s3PublicPolicy{}, pol); len(f) != 0 {
		t.Fatalf("malformed policy must not fire, got %d", len(f))
	}
}

// AEGIS-AWS-012: S3 bucket without versioning.

func TestS3Versioning_AbsentFires(t *testing.T) {
	bkt := res("aws_s3_bucket", "data", nil)
	f := runRule(s3Versioning{}, bkt)
	if len(f) != 1 || f[0].Severity != "medium" {
		t.Fatalf("expected 1 medium finding, got %+v", f)
	}
	if f[0].Evidence.Attribute != "versioning" {
		t.Fatalf("wrong evidence attribute: %s", f[0].Evidence.Attribute)
	}
}

func TestS3Versioning_DisabledFires(t *testing.T) {
	bkt := res("aws_s3_bucket", "data", map[string]ir.Value{
		"versioning": blks(3, blk("enabled", kv(false, 4))),
	})
	if f := runRule(s3Versioning{}, bkt); len(f) != 1 {
		t.Fatalf("expected 1 finding for disabled versioning, got %d", len(f))
	}
}

func TestS3Versioning_EnabledOK(t *testing.T) {
	bkt := res("aws_s3_bucket", "data", map[string]ir.Value{
		"versioning": blks(3, blk("enabled", kv(true, 4))),
	})
	if f := runRule(s3Versioning{}, bkt); len(f) != 0 {
		t.Fatalf("enabled versioning must not fire, got %d", len(f))
	}
}

func TestS3Versioning_UnknownNoFinding(t *testing.T) {
	bkt := res("aws_s3_bucket", "data", map[string]ir.Value{
		"versioning": blks(3, blk("enabled", ku(4))),
	})
	if f := runRule(s3Versioning{}, bkt); len(f) != 0 {
		t.Fatalf("unknown enabled must not fire, got %d", len(f))
	}
	bkt2 := res("aws_s3_bucket", "data", map[string]ir.Value{"versioning": ku(3)})
	if f := runRule(s3Versioning{}, bkt2); len(f) != 0 {
		t.Fatalf("unknown versioning block must not fire, got %d", len(f))
	}
}

func TestS3PublicACL_BucketACLResourceFires(t *testing.T) {
	// Modern aws_s3_bucket_acl resource with a public canned ACL.
	acl := res("aws_s3_bucket_acl", "assets", map[string]ir.Value{"acl": ks("public-read", 3)})
	if !(s3PublicACL{}).AppliesTo("aws_s3_bucket_acl") {
		t.Fatal("002 must apply to aws_s3_bucket_acl")
	}
	f := runRule(s3PublicACL{}, acl)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding on aws_s3_bucket_acl, got %d", len(f))
	}
}

func TestS3PublicACL_BucketACLResourcePrivateOK(t *testing.T) {
	acl := res("aws_s3_bucket_acl", "assets", map[string]ir.Value{"acl": ks("private", 3)})
	f := runRule(s3PublicACL{}, acl)
	if len(f) != 0 {
		t.Fatalf("expected 0 findings for private ACL, got %d", len(f))
	}
}

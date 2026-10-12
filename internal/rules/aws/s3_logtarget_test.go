package aws

import (
	"testing"

	"aegis/internal/ir"
)

// Log-delivery buckets (target_bucket of an aws_s3_bucket_logging resource)
// are logging infrastructure, not data buckets: the S3 hardening rules must
// not flag them for missing encryption, versioning, public-access block,
// TLS enforcement, access logging, or lifecycle configuration.
//
// Regression: held-out clean projects pair a hardened bucket with a bare
// log-delivery bucket; flagging the latter produced false positives.

func logTargetFixture() []ir.Resource {
	data := res("aws_s3_bucket", "data", map[string]ir.Value{})
	logs := res("aws_s3_bucket", "logs", map[string]ir.Value{})
	logging := res("aws_s3_bucket_logging", "data", map[string]ir.Value{
		"bucket":        {Ref: "aws_s3_bucket.data.id", Span: spanAt(2)},
		"target_bucket": {Ref: "aws_s3_bucket.logs.id", Span: spanAt(3)},
	})
	return []ir.Resource{data, logs, logging}
}

func TestLogTarget_001_Silent(t *testing.T) {
	rs := logTargetFixture()
	out := (s3Encryption{}).CheckAll(rs)
	for _, f := range out {
		if f.Resource == "aws_s3_bucket.logs" {
			t.Fatalf("001 must not fire on log-delivery bucket, got %+v", f)
		}
	}
	// Sanity: a bare bucket with no logging relationship still fires.
	bare := res("aws_s3_bucket", "bare", map[string]ir.Value{})
	if out := (s3Encryption{}).CheckAll([]ir.Resource{bare}); len(out) != 1 {
		t.Fatalf("001 must fire on ordinary bare bucket, got %d", len(out))
	}
}

func TestLogTarget_012_Silent(t *testing.T) {
	rs := logTargetFixture()
	out := (s3Versioning{}).CheckAll(rs)
	for _, f := range out {
		if f.Resource == "aws_s3_bucket.logs" {
			t.Fatalf("012 must not fire on log-delivery bucket, got %+v", f)
		}
	}
	bare := res("aws_s3_bucket", "bare", map[string]ir.Value{})
	if out := (s3Versioning{}).CheckAll([]ir.Resource{bare}); len(out) != 1 {
		t.Fatalf("012 must fire on ordinary bare bucket, got %d", len(out))
	}
}

func TestLogTarget_206_Silent(t *testing.T) {
	rs := logTargetFixture()
	out := (s3NoPublicAccessBlock{}).CheckAll(rs)
	for _, f := range out {
		if f.Resource == "aws_s3_bucket.logs" {
			t.Fatalf("206 must not fire on log-delivery bucket, got %+v", f)
		}
	}
	bare := res("aws_s3_bucket", "bare", map[string]ir.Value{})
	if out := (s3NoPublicAccessBlock{}).CheckAll([]ir.Resource{bare}); len(out) != 1 {
		t.Fatalf("206 must fire on ordinary bare bucket, got %d", len(out))
	}
}

func TestLogTarget_443_Silent(t *testing.T) {
	rs := logTargetFixture()
	out := (s3NoSecureTransport{}).CheckAll(rs)
	for _, f := range out {
		if f.Resource == "aws_s3_bucket.logs" {
			t.Fatalf("443 must not fire on log-delivery bucket, got %+v", f)
		}
	}
	bare := res("aws_s3_bucket", "bare", map[string]ir.Value{})
	if out := (s3NoSecureTransport{}).CheckAll([]ir.Resource{bare}); len(out) != 1 {
		t.Fatalf("443 must fire on ordinary bare bucket, got %d", len(out))
	}
}

func TestLogTarget_445_Silent(t *testing.T) {
	rs := logTargetFixture()
	out := (s3NoAccessLogging{}).CheckAll(rs)
	for _, f := range out {
		if f.Resource == "aws_s3_bucket.logs" {
			t.Fatalf("445 must not fire on log-delivery bucket, got %+v", f)
		}
	}
}

func TestLogTarget_601_Silent(t *testing.T) {
	rs := logTargetFixture()
	out := (s3NoLifecycle{}).CheckAll(rs)
	for _, f := range out {
		if f.Resource == "aws_s3_bucket.logs" {
			t.Fatalf("601 must not fire on log-delivery bucket, got %+v", f)
		}
	}
	bare := res("aws_s3_bucket", "bare", map[string]ir.Value{})
	if out := (s3NoLifecycle{}).CheckAll([]ir.Resource{bare}); len(out) != 1 {
		t.Fatalf("601 must fire on ordinary bare bucket, got %d", len(out))
	}
}

// Unresolvable target links must not exempt anything (fail-safe).
func TestLogTarget_UnresolvableTargetNoExemption(t *testing.T) {
	bare := res("aws_s3_bucket", "bare", map[string]ir.Value{})
	logging := res("aws_s3_bucket_logging", "x", map[string]ir.Value{
		"bucket":        {Ref: "aws_s3_bucket.data.id", Span: spanAt(2)},
		"target_bucket": ku(3), // unknown: cannot prove it targets the bucket
	})
	if out := (s3Encryption{}).CheckAll([]ir.Resource{bare, logging}); len(out) != 1 {
		t.Fatalf("001 must still fire when target is unresolvable, got %d", len(out))
	}
}

// Cross-file contamination regression: two independent projects (different
// directories) define aws_s3_bucket.logs. A logging config in project B that
// targets B's bucket must NOT suppress findings on project A's bucket.
// Reported by the blind evaluation as a scale anomaly: 10 findings
// deterministically vanished at full-corpus scale.
func resInFile(typ, name, file string, attrs map[string]ir.Value) ir.Resource {
	r := res(typ, name, attrs)
	r.Span.File = file
	return r
}

func TestLogTarget_CrossFileNoContamination(t *testing.T) {
	// Project A: bare bucket, no logging relationship.
	aBucket := resInFile("aws_s3_bucket", "logs", "/a/main.tf", map[string]ir.Value{})
	// Project B: hardened bucket + logging config targeting B's bucket.
	bBucket := resInFile("aws_s3_bucket", "logs", "/b/main.tf", map[string]ir.Value{})
	bLogging := resInFile("aws_s3_bucket_logging", "b", "/b/main.tf", map[string]ir.Value{
		"bucket":        {Ref: "aws_s3_bucket.assets.id", Span: ir.Span{File: "/b/main.tf"}},
		"target_bucket": {Ref: "aws_s3_bucket.logs.id", Span: ir.Span{File: "/b/main.tf"}},
	})
	rs := []ir.Resource{aBucket, bBucket, bLogging}

	// Project A's bucket must still fire on all five hardening rules.
	for id, rule := range map[string]ir.CrossResourceRule{
		"AEGIS-AWS-001": s3Encryption{},
		"AEGIS-AWS-012": s3Versioning{},
		"AEGIS-AWS-206": s3NoPublicAccessBlock{},
		"AEGIS-AWS-445": s3NoAccessLogging{},
		"AEGIS-AWS-601": s3NoLifecycle{},
	} {
		fired := false
		for _, f := range rule.CheckAll(rs) {
			if f.Evidence.Span.File == "/a/main.tf" {
				fired = true
			}
		}
		if !fired {
			t.Fatalf("%s must fire on project A's bucket despite project B's log target", id)
		}
	}
	// Project B's bucket (a genuine log target) must stay silent on 001.
	for _, f := range (s3Encryption{}).CheckAll(rs) {
		if f.Evidence.Span.File == "/b/main.tf" {
			t.Fatalf("001 must not fire on project B's log-delivery bucket, got %+v", f)
		}
	}
}

// Same-directory cross-file refs must keep working: bucket in a.tf, logging
// config in b.tf, same directory.
func TestLogTarget_SameDirCrossFileStillCorrelates(t *testing.T) {
	bucket := resInFile("aws_s3_bucket", "logs", "/proj/main.tf", map[string]ir.Value{})
	logging := resInFile("aws_s3_bucket_logging", "l", "/proj/other.tf", map[string]ir.Value{
		"bucket":        {Ref: "aws_s3_bucket.data.id", Span: ir.Span{File: "/proj/other.tf"}},
		"target_bucket": {Ref: "aws_s3_bucket.logs.id", Span: ir.Span{File: "/proj/other.tf"}},
	})
	rs := []ir.Resource{bucket, logging}
	for _, f := range (s3Encryption{}).CheckAll(rs) {
		if f.Evidence.Span.File == "/proj/main.tf" {
			t.Fatalf("001 must not fire: same-directory log target exempts the bucket, got %+v", f)
		}
	}
}

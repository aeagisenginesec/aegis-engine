package aws

import (
	"reflect"
	"testing"

	"aegis/internal/ir"
)

// --- shared fixtures -------------------------------------------------

func openSGFixture() ir.Resource {
	return res("aws_security_group", "web", map[string]ir.Value{
		"ingress": blks(3, blk(
			"from_port", ks("443", 4),
			"to_port", ks("443", 4),
			"protocol", ks("tcp", 4),
			"cidr_blocks", strList(4, "0.0.0.0/0"),
		)),
	})
}

func closedSGFixture() ir.Resource {
	return res("aws_security_group", "db", map[string]ir.Value{
		"ingress": blks(3, blk(
			"cidr_blocks", strList(4, "10.0.0.0/8"),
		)),
	})
}

func rdsFixture(name string, public ir.Value) ir.Resource {
	return res("aws_db_instance", name, map[string]ir.Value{
		"publicly_accessible": public,
	})
}

func bucketFixture(name string) ir.Resource {
	return res("aws_s3_bucket", name, map[string]ir.Value{})
}

func bucketRef(line int, ref string) ir.Value {
	return ir.Value{Known: false, Span: spanAt(line), Ref: ref}
}

func bucketPolicyFixture(name, bucketRefPath, doc string, line int) ir.Resource {
	attrs := map[string]ir.Value{"bucket": bucketRef(line, bucketRefPath)}
	if doc != "" {
		attrs["policy"] = ks(doc, line+1)
	} else {
		attrs["policy"] = ku(line + 1)
	}
	return res("aws_s3_bucket_policy", name, attrs)
}

func publicReadPolicyDoc() string {
	return `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::assets/*"}]}`
}

// --- AEGIS-AWS-103 ----------------------------------------------------

func TestRDSPath_Positive(t *testing.T) {
	sg := openSGFixture()
	rds := rdsFixture("main", kv(true, 10))
	out := findRDSPaths([]ir.Resource{sg, rds},
		func(string) bool { return true },
		func(ir.Resource) *ir.Resource { return &sg },
	)
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	f := out[0]
	if f.RuleID != "AEGIS-AWS-103" || f.Severity != ir.SeverityHigh {
		t.Fatalf("wrong rule/severity: %+v", f)
	}
	if f.Resource != "aws_db_instance.main" {
		t.Fatalf("wrong resource: %s", f.Resource)
	}
	want := []string{"internet", "aws_security_group.web", "aws_db_instance.main"}
	if len(f.Path) != len(want) {
		t.Fatalf("expected %d path steps, got %+v", len(want), f.Path)
	}
	for i, w := range want {
		if f.Path[i].Resource != w {
			t.Fatalf("step %d: want %s, got %s", i, w, f.Path[i].Resource)
		}
		if f.Path[i].Detail == "" {
			t.Fatalf("step %d has empty detail", i)
		}
	}
}

func TestRDSPath_Negative(t *testing.T) {
	sg := openSGFixture()
	cases := []struct {
		name string
		rds  ir.Resource
		expo bool
	}{
		{"not public", rdsFixture("a", kv(false, 10)), true},
		{"unknown flag", rdsFixture("b", ku(10)), true},
		{"absent flag", res("aws_db_instance", "c", map[string]ir.Value{}), true},
		{"not exposed", rdsFixture("d", kv(true, 10)), false},
	}
	for _, c := range cases {
		out := findRDSPaths([]ir.Resource{sg, c.rds},
			func(string) bool { return c.expo },
			func(ir.Resource) *ir.Resource { return &sg },
		)
		if len(out) != 0 {
			t.Fatalf("%s: expected no finding, got %+v", c.name, out)
		}
	}
}

// TestRDSPath103_PrivateRDSQuiet: explicit rule-ID-tagged negative for
// AEGIS-AWS-103 — a non-public RDS instance produces no exposure path.
func TestRDSPath103_PrivateRDSQuiet(t *testing.T) {
	sg := openSGFixture()
	rds := rdsFixture("main", kv(false, 10))
	out := findRDSPaths([]ir.Resource{sg, rds},
		func(string) bool { return true },
		func(ir.Resource) *ir.Resource { return &sg },
	)
	if len(out) != 0 {
		t.Fatalf("AEGIS-AWS-103: expected no finding for publicly_accessible=false, got %+v", out)
	}
}

func TestRDSPath_NoSGIdentified(t *testing.T) {
	rds := rdsFixture("main", kv(true, 10))
	out := findRDSPaths([]ir.Resource{rds},
		func(string) bool { return true },
		func(ir.Resource) *ir.Resource { return nil },
	)
	// A path must never name a hop it cannot prove: with no attached open
	// SG identified, 103 stays silent (rule 011 still reports the public
	// flag on its own).
	if len(out) != 0 {
		t.Fatalf("expected no 103 finding without an attached open SG, got %d", len(out))
	}
}

func TestRDSPath_Determinism(t *testing.T) {
	sg := openSGFixture()
	rds := rdsFixture("main", kv(true, 10))
	run := func() []ir.Finding {
		return findRDSPaths([]ir.Resource{rds, sg},
			func(string) bool { return true },
			func(ir.Resource) *ir.Resource { return &sg },
		)
	}
	if !reflect.DeepEqual(run(), run()) {
		t.Fatal("non-deterministic output")
	}
}

func TestOpenSGs(t *testing.T) {
	open := openSGFixture()
	closed := closedSGFixture()
	// Standalone ingress rule attached to the closed SG via reference.
	rule := res("aws_security_group_rule", "open", map[string]ir.Value{
		"type":              ks("ingress", 20),
		"cidr_blocks":       strList(21, "0.0.0.0/0"),
		"security_group_id": bucketRef(22, "aws_security_group.db.id"),
	})
	// Egress-only world rule must not mark anything open for ingress.
	egress := res("aws_security_group_rule", "eg", map[string]ir.Value{
		"type":              ks("egress", 30),
		"cidr_blocks":       strList(31, "0.0.0.0/0"),
		"security_group_id": bucketRef(32, "aws_security_group.web.id"),
	})
	got := openSGs([]ir.Resource{closed, open, rule, egress})
	if len(got) != 2 {
		t.Fatalf("expected 2 open SGs, got %v", addrs(got))
	}
	if got[0].Address() != "aws_security_group.db" || got[1].Address() != "aws_security_group.web" {
		t.Fatalf("expected address-sorted open SGs, got %v", addrs(got))
	}
}

func addrs(rs []ir.Resource) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.Address()
	}
	return out
}

func TestCollectRefAddrs(t *testing.T) {
	r := res("aws_db_instance", "main", map[string]ir.Value{
		"vpc_security_group_ids": ir.Value{Known: false, Span: spanAt(7), Raw: []ir.Value{
			bucketRef(7, "aws_security_group.db.id"),
			bucketRef(7, "aws_security_group.web.id"),
		}},
	})
	got := collectRefAddrs(r)
	want := []string{"aws_security_group.db", "aws_security_group.web"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("want %v, got %v", want, got)
	}
}

// --- AEGIS-AWS-104 ----------------------------------------------------

func TestS3Exfiltration_PolicyPath(t *testing.T) {
	b := bucketFixture("assets")
	p := bucketPolicyFixture("assets", "aws_s3_bucket.assets.id", publicReadPolicyDoc(), 10)
	out := (s3ExfiltrationPath{}).CheckAll([]ir.Resource{b, p})
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	f := out[0]
	if f.RuleID != "AEGIS-AWS-104" || f.Severity != ir.SeverityCritical {
		t.Fatalf("wrong rule/severity: %+v", f)
	}
	if f.Resource != "aws_s3_bucket.assets" {
		t.Fatalf("wrong resource: %s", f.Resource)
	}
	want := []string{"internet", "aws_s3_bucket_policy.assets", "aws_s3_bucket.assets"}
	if len(f.Path) != len(want) {
		t.Fatalf("expected %d path steps, got %+v", len(want), f.Path)
	}
	for i, w := range want {
		if f.Path[i].Resource != w {
			t.Fatalf("step %d: want %s, got %s", i, w, f.Path[i].Resource)
		}
	}
	if f.Evidence.Attribute != "policy" {
		t.Fatalf("policy grant should be the evidence, got %s", f.Evidence.Attribute)
	}
}

func TestS3Exfiltration_ACLPath(t *testing.T) {
	b := bucketFixture("assets")
	a := res("aws_s3_bucket_acl", "assets", map[string]ir.Value{
		"bucket": bucketRef(12, "aws_s3_bucket.assets.id"),
		"acl":    ks("public-read", 13),
	})
	out := (s3ExfiltrationPath{}).CheckAll([]ir.Resource{b, a})
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	if out[0].Path[1].Resource != "aws_s3_bucket_acl.assets" {
		t.Fatalf("wrong path: %+v", out[0].Path)
	}
}

func TestS3Exfiltration_InlineACL(t *testing.T) {
	b := res("aws_s3_bucket", "legacy", map[string]ir.Value{
		"acl": ks("public-read-write", 5),
	})
	out := (s3ExfiltrationPath{}).CheckAll([]ir.Resource{b})
	if len(out) != 1 {
		t.Fatalf("expected 1 finding for inline public ACL, got %d", len(out))
	}
	if len(out[0].Path) != 3 || out[0].Path[0].Resource != "internet" {
		t.Fatalf("expected 3-step path: %+v", out[0].Path)
	}
}

func TestS3Exfiltration_Negative(t *testing.T) {
	privDoc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123:root"},"Action":"s3:GetObject","Resource":"*"}]}`
	b := bucketFixture("assets")
	cases := []struct {
		name string
		rs   []ir.Resource
	}{
		{"no policy or acl", []ir.Resource{b}},
		{"private acl", []ir.Resource{b, res("aws_s3_bucket_acl", "a", map[string]ir.Value{
			"bucket": bucketRef(3, "aws_s3_bucket.assets.id"), "acl": ks("private", 4)})}},
		{"scoped principal", []ir.Resource{b, bucketPolicyFixture("p", "aws_s3_bucket.assets.id", privDoc, 10)}},
		{"malformed policy", []ir.Resource{b, bucketPolicyFixture("p", "aws_s3_bucket.assets.id", `{broken`, 10)}},
		{"unknown policy", []ir.Resource{b, bucketPolicyFixture("p", "aws_s3_bucket.assets.id", "", 10)}},
		{"dangling ref", []ir.Resource{b, bucketPolicyFixture("p", "aws_s3_bucket.ghost.id", publicReadPolicyDoc(), 10)}},
		{"deny only", []ir.Resource{b, bucketPolicyFixture("p", "aws_s3_bucket.assets.id",
			`{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*"}]}`, 10)}},
	}
	for _, c := range cases {
		out := (s3ExfiltrationPath{}).CheckAll(c.rs)
		if len(out) != 0 {
			t.Fatalf("%s: expected no finding, got %+v", c.name, out)
		}
	}
}

func TestS3Exfiltration_OneFindingPerBucket(t *testing.T) {
	b := bucketFixture("assets")
	p := bucketPolicyFixture("pol", "aws_s3_bucket.assets.id", publicReadPolicyDoc(), 10)
	a := res("aws_s3_bucket_acl", "acl", map[string]ir.Value{
		"bucket": bucketRef(20, "aws_s3_bucket.assets.id"),
		"acl":    ks("public-read", 21),
	})
	out := (s3ExfiltrationPath{}).CheckAll([]ir.Resource{b, p, a})
	if len(out) != 1 {
		t.Fatalf("expected exactly 1 finding per bucket, got %d", len(out))
	}
	if out[0].Evidence.Attribute != "policy" {
		t.Fatalf("policy grant should win over ACL, got %s", out[0].Evidence.Attribute)
	}
}

func TestS3Exfiltration_Determinism(t *testing.T) {
	b := bucketFixture("assets")
	p := bucketPolicyFixture("pol", "aws_s3_bucket.assets.id", publicReadPolicyDoc(), 10)
	run := func() []ir.Finding {
		return (s3ExfiltrationPath{}).CheckAll([]ir.Resource{p, b})
	}
	a, b2 := run(), run()
	if !reflect.DeepEqual(a, b2) {
		t.Fatal("non-deterministic output")
	}
}

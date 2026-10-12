package remediation

import (
	"strings"
	"testing"

	"aegis/internal/ir"
)

func spanOf(file string, sl, el int) ir.Span {
	return ir.Span{File: file, StartLine: sl, StartCol: 1, EndLine: el, EndCol: 1}
}

func boolAttr(file string, line int, v bool) ir.Value {
	return ir.Value{Raw: v, Known: true, Span: spanOf(file, line, line)}
}

func findingFor(ruleID, resource, attr, file string, sl, el int) ir.Finding {
	return ir.Finding{
		RuleID:   ruleID,
		Resource: resource,
		Evidence: ir.Evidence{Attribute: attr, Span: spanOf(file, sl, el)},
	}
}

func applySingle(t *testing.T, p Patch, src string) string {
	t.Helper()
	out, err := ApplyEdits(src, p.Edits)
	if err != nil {
		t.Fatalf("ApplyEdits failed: %v", err)
	}
	return out
}

// --- 007: RDS storage_encrypted ---

func TestFixer007Positive(t *testing.T) {
	src := "resource \"aws_db_instance\" \"main\" {\n  storage_encrypted = false\n}\n"
	res := ir.Resource{
		Type: "aws_db_instance", Name: "main",
		Attributes: map[string]ir.Value{"storage_encrypted": boolAttr("db.tf", 2, false)},
		Span:       spanOf("db.tf", 1, 3),
	}
	f := findingFor("AEGIS-AWS-007", "aws_db_instance.main", "storage_encrypted", "db.tf", 2, 2)
	patches := newFixer007().Propose(f, res, []byte(src))
	if len(patches) != 1 {
		t.Fatalf("want 1 patch, got %d", len(patches))
	}
	out := applySingle(t, patches[0], src)
	if !strings.Contains(out, "storage_encrypted = true") {
		t.Errorf("patched content missing fix:\n%s", out)
	}
	if strings.Contains(out, "false") {
		t.Errorf("patched content still has false:\n%s", out)
	}
	if patches[0].Diff == "" {
		t.Error("diff should be non-empty")
	}
}

func TestFixer007AbsentInserts(t *testing.T) {
	src := "resource \"aws_db_instance\" \"main\" {\n  engine = \"mysql\"\n}\n"
	res := ir.Resource{
		Type: "aws_db_instance", Name: "main",
		Attributes: map[string]ir.Value{},
		Span:       spanOf("db.tf", 1, 3),
	}
	f := findingFor("AEGIS-AWS-007", "aws_db_instance.main", "storage_encrypted", "db.tf", 1, 3)
	patches := newFixer007().Propose(f, res, []byte(src))
	if len(patches) != 1 {
		t.Fatalf("want 1 patch, got %d", len(patches))
	}
	out := applySingle(t, patches[0], src)
	if !strings.Contains(out, "storage_encrypted = true") {
		t.Errorf("patched content missing inserted attribute:\n%s", out)
	}
	if !strings.HasSuffix(strings.TrimSpace(out), "}") {
		t.Errorf("closing brace lost:\n%s", out)
	}
}

func TestFixer007Negative(t *testing.T) {
	src := "resource \"aws_s3_bucket\" \"b\" {\n  storage_encrypted = false\n}\n"
	res := ir.Resource{
		Type: "aws_s3_bucket", Name: "b",
		Attributes: map[string]ir.Value{"storage_encrypted": boolAttr("s.tf", 2, false)},
		Span:       spanOf("s.tf", 1, 3),
	}
	f := findingFor("AEGIS-AWS-007", "aws_s3_bucket.b", "storage_encrypted", "s.tf", 2, 2)
	if patches := newFixer007().Propose(f, res, []byte(src)); len(patches) != 0 {
		t.Errorf("wrong resource type should yield no patch, got %d", len(patches))
	}
	// Already true: no-op.
	res2 := ir.Resource{
		Type: "aws_db_instance", Name: "main",
		Attributes: map[string]ir.Value{"storage_encrypted": boolAttr("db.tf", 2, true)},
		Span:       spanOf("db.tf", 1, 3),
	}
	f2 := findingFor("AEGIS-AWS-007", "aws_db_instance.main", "storage_encrypted", "db.tf", 2, 2)
	if patches := newFixer007().Propose(f2, res2, []byte(src)); len(patches) != 0 {
		t.Errorf("already-fixed should yield no patch, got %d", len(patches))
	}
}

// --- 008 / 009 / 010 / 011 ---

func boolFixerCase(t *testing.T, fx Fixer, resType, attr, file string, want string) {
	t.Helper()
	// Build the "bad" value: if want=="true", current is false and vice versa.
	badStr := "false"
	bad := false
	if want == "false" {
		badStr = "true"
		bad = true
	}
	src := "resource \"" + resType + "\" \"x\" {\n  " + attr + " = " + badStr + "\n}\n"
	res := ir.Resource{
		Type: resType, Name: "x",
		Attributes: map[string]ir.Value{attr: boolAttr(file, 2, bad)},
		Span:       spanOf(file, 1, 3),
	}
	f := findingFor(fx.RuleID(), resType+".x", attr, file, 2, 2)
	patches := fx.Propose(f, res, []byte(src))
	if len(patches) != 1 {
		t.Fatalf("%s: want 1 patch, got %d", fx.RuleID(), len(patches))
	}
	out := applySingle(t, patches[0], src)
	if !strings.Contains(out, attr+" = "+want) {
		t.Errorf("%s: patched content missing %s = %s:\n%s", fx.RuleID(), attr, want, out)
	}
}

func TestFixer008(t *testing.T) {
	boolFixerCase(t, newFixer008(), "aws_db_instance", "deletion_protection", "db.tf", "true")
}

func TestFixer009(t *testing.T) {
	boolFixerCase(t, newFixer009(), "aws_ebs_volume", "encrypted", "ebs.tf", "true")
}

func TestFixer010(t *testing.T) {
	boolFixerCase(t, newFixer010(), "aws_cloudtrail", "enable_log_file_validation", "ct.tf", "true")
}

func TestFixer011(t *testing.T) {
	boolFixerCase(t, newFixer011(), "aws_db_instance", "publicly_accessible", "db.tf", "false")
	// Absent publicly_accessible never fires the rule: no patch on absence.
	src := "resource \"aws_db_instance\" \"x\" {\n  engine = \"mysql\"\n}\n"
	res := ir.Resource{Type: "aws_db_instance", Name: "x",
		Attributes: map[string]ir.Value{}, Span: spanOf("db.tf", 1, 3)}
	f := findingFor("AEGIS-AWS-011", "aws_db_instance.x", "publicly_accessible", "db.tf", 1, 3)
	if patches := newFixer011().Propose(f, res, []byte(src)); len(patches) != 0 {
		t.Errorf("absent attribute should yield no patch for 011, got %d", len(patches))
	}
}

// --- 001: S3 SSE block insertion ---

func TestFixer001Positive(t *testing.T) {
	src := "resource \"aws_s3_bucket\" \"assets\" {\n  bucket = \"x\"\n}\n"
	res := ir.Resource{Type: "aws_s3_bucket", Name: "assets",
		Attributes: map[string]ir.Value{}, Span: spanOf("s3.tf", 1, 3)}
	f := findingFor("AEGIS-AWS-001", "aws_s3_bucket.assets", "server_side_encryption_configuration", "s3.tf", 1, 3)
	patches := newFixer001().Propose(f, res, []byte(src))
	if len(patches) != 1 {
		t.Fatalf("want 1 patch, got %d", len(patches))
	}
	out := applySingle(t, patches[0], src)
	for _, want := range []string{
		"server_side_encryption_configuration {",
		"sse_algorithm = \"AES256\"",
		"bucket = \"x\"",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("patched content missing %q:\n%s", want, out)
		}
	}
	if patches[0].Diff == "" {
		t.Error("diff should be non-empty")
	}
}

func TestFixer001Negative(t *testing.T) {
	src := "resource \"aws_s3_bucket\" \"assets\" {\n  bucket = \"x\"\n}\n"
	// Block already present: no duplicate insertion.
	res := ir.Resource{Type: "aws_s3_bucket", Name: "assets",
		Attributes: map[string]ir.Value{
			"server_side_encryption_configuration": {Raw: []ir.Value{}, Known: true, Span: spanOf("s3.tf", 2, 2)},
		},
		Span: spanOf("s3.tf", 1, 3)}
	f := findingFor("AEGIS-AWS-001", "aws_s3_bucket.assets", "server_side_encryption_configuration", "s3.tf", 1, 3)
	if patches := newFixer001().Propose(f, res, []byte(src)); len(patches) != 0 {
		t.Errorf("existing block should yield no patch, got %d", len(patches))
	}
	// Wrong type.
	res2 := ir.Resource{Type: "aws_db_instance", Name: "d", Span: spanOf("s3.tf", 1, 3)}
	if patches := newFixer001().Propose(f, res2, []byte(src)); len(patches) != 0 {
		t.Errorf("wrong type should yield no patch, got %d", len(patches))
	}
}

// --- 012: versioning block ---

func TestFixer012Positive(t *testing.T) {
	src := "resource \"aws_s3_bucket\" \"assets\" {\n  bucket = \"x\"\n}\n"
	res := ir.Resource{Type: "aws_s3_bucket", Name: "assets",
		Attributes: map[string]ir.Value{}, Span: spanOf("s3.tf", 1, 3)}
	f := findingFor("AEGIS-AWS-012", "aws_s3_bucket.assets", "versioning", "s3.tf", 1, 3)
	patches := newFixer012().Propose(f, res, []byte(src))
	if len(patches) != 1 {
		t.Fatalf("want 1 patch, got %d", len(patches))
	}
	out := applySingle(t, patches[0], src)
	if !strings.Contains(out, "versioning {") || !strings.Contains(out, "enabled = true") {
		t.Errorf("patched content missing versioning block:\n%s", out)
	}
}

// --- 002: ACL to private ---

func TestFixer002Positive(t *testing.T) {
	for _, resType := range []string{"aws_s3_bucket_acl", "aws_s3_bucket"} {
		src := "resource \"" + resType + "\" \"a\" {\n  acl = \"public-read\"\n}\n"
		res := ir.Resource{Type: resType, Name: "a",
			Attributes: map[string]ir.Value{
				"acl": {Raw: "public-read", Known: true, Span: spanOf("a.tf", 2, 2)},
			},
			Span: spanOf("a.tf", 1, 3)}
		f := findingFor("AEGIS-AWS-002", resType+".a", "acl", "a.tf", 2, 2)
		patches := fixer002{}.Propose(f, res, []byte(src))
		if len(patches) != 1 {
			t.Fatalf("%s: want 1 patch, got %d", resType, len(patches))
		}
		out := applySingle(t, patches[0], src)
		if !strings.Contains(out, `acl = "private"`) {
			t.Errorf("%s: patched content missing private ACL:\n%s", resType, out)
		}
	}
}

func TestFixer002Negative(t *testing.T) {
	src := "resource \"aws_s3_bucket_acl\" \"a\" {\n  acl = \"private\"\n}\n"
	res := ir.Resource{Type: "aws_s3_bucket_acl", Name: "a",
		Attributes: map[string]ir.Value{
			"acl": {Raw: "private", Known: true, Span: spanOf("a.tf", 2, 2)},
		},
		Span: spanOf("a.tf", 1, 3)}
	f := findingFor("AEGIS-AWS-002", "aws_s3_bucket_acl.a", "acl", "a.tf", 2, 2)
	if patches := (fixer002{}).Propose(f, res, []byte(src)); len(patches) != 0 {
		t.Errorf("non-public ACL should yield no patch, got %d", len(patches))
	}
	// Unknown ACL value: no patch.
	res2 := ir.Resource{Type: "aws_s3_bucket_acl", Name: "a",
		Attributes: map[string]ir.Value{"acl": ir.UnknownValue(spanOf("a.tf", 2, 2))},
		Span:       spanOf("a.tf", 1, 3)}
	if patches := (fixer002{}).Propose(f, res2, []byte(src)); len(patches) != 0 {
		t.Errorf("unknown ACL should yield no patch, got %d", len(patches))
	}
	// Wrong resource type.
	res3 := ir.Resource{Type: "aws_iam_role", Name: "r", Span: spanOf("a.tf", 1, 3)}
	if patches := (fixer002{}).Propose(f, res3, []byte(src)); len(patches) != 0 {
		t.Errorf("wrong type should yield no patch, got %d", len(patches))
	}
}

// --- attrEdit span mismatch: never corrupt ---

func TestAttrEditSpanMismatch(t *testing.T) {
	// Evidence span points at a line that does not assign the attribute.
	src := "resource \"aws_db_instance\" \"main\" {\n  engine = \"mysql\"\n}\n"
	res := ir.Resource{Type: "aws_db_instance", Name: "main",
		Attributes: map[string]ir.Value{"storage_encrypted": boolAttr("db.tf", 9, false)},
		Span:       spanOf("db.tf", 1, 3)}
	f := findingFor("AEGIS-AWS-007", "aws_db_instance.main", "storage_encrypted", "db.tf", 9, 9)
	if patches := newFixer007().Propose(f, res, []byte(src)); len(patches) != 0 {
		t.Errorf("span mismatch should yield no patch, got %d", len(patches))
	}
}

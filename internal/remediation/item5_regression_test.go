package remediation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aegis/internal/ir"
)

// Item 5 regression tests: reference-rewriting refusal, comment
// preservation, multiline refusal, duplicate-insert refusal, and
// duplicate-address file-aware matching/validation.

func resolvedBoolAttr(file string, line int, v bool) ir.Value {
	return ir.Value{Raw: v, Known: true, Span: spanOf(file, line, line)}
}

func TestFixer007RefusesVariableReference(t *testing.T) {
	// Semantics resolves var.encrypt (default false) to Known=false, but
	// the source line is a reference. Rewriting it to a literal would
	// sever the variable binding; the fixer must refuse.
	src := "resource \"aws_db_instance\" \"main\" {\n  storage_encrypted = var.encrypt\n}\n"
	res := ir.Resource{
		Type: "aws_db_instance", Name: "main",
		Attributes: map[string]ir.Value{"storage_encrypted": resolvedBoolAttr("db.tf", 2, false)},
		Span:       spanOf("db.tf", 1, 3),
	}
	f := findingFor("AEGIS-AWS-007", "aws_db_instance.main", "storage_encrypted", "db.tf", 2, 2)
	if patches := newFixer007().Propose(f, res, []byte(src)); len(patches) != 0 {
		t.Errorf("variable reference must yield no patch, got %+v", patches)
	}
}

func TestFixer009RefusesLocalAndCallReferences(t *testing.T) {
	for _, rhs := range []string{"local.enc", "tobool(var.enc)", "var.enc ? true : false", "merge({}, {}).enc"} {
		src := "resource \"aws_ebs_volume\" \"v\" {\n  encrypted = " + rhs + "\n}\n"
		res := ir.Resource{
			Type: "aws_ebs_volume", Name: "v",
			Attributes: map[string]ir.Value{"encrypted": resolvedBoolAttr("v.tf", 2, false)},
			Span:       spanOf("v.tf", 1, 3),
		}
		f := findingFor("AEGIS-AWS-009", "aws_ebs_volume.v", "encrypted", "v.tf", 2, 2)
		if patches := newFixer009().Propose(f, res, []byte(src)); len(patches) != 0 {
			t.Errorf("rhs %q must yield no patch, got %+v", rhs, patches)
		}
	}
}

func TestFixer002RefusesVariableACL(t *testing.T) {
	src := "resource \"aws_s3_bucket_acl\" \"a\" {\n  acl = var.acl\n}\n"
	res := ir.Resource{
		Type: "aws_s3_bucket_acl", Name: "a",
		Attributes: map[string]ir.Value{"acl": {Raw: "public-read", Known: true, Span: spanOf("a.tf", 2, 2)}},
		Span:       spanOf("a.tf", 1, 3),
	}
	f := findingFor("AEGIS-AWS-002", "aws_s3_bucket_acl.a", "acl", "a.tf", 2, 2)
	if patches := (fixer002{}).Propose(f, res, []byte(src)); len(patches) != 0 {
		t.Errorf("variable ACL must yield no patch, got %+v", patches)
	}
}

func TestFixer007PreservesTrailingComment(t *testing.T) {
	src := "resource \"aws_db_instance\" \"main\" {\n  storage_encrypted = false # keep false for teardown\n}\n"
	res := ir.Resource{
		Type: "aws_db_instance", Name: "main",
		Attributes: map[string]ir.Value{"storage_encrypted": resolvedBoolAttr("db.tf", 2, false)},
		Span:       spanOf("db.tf", 1, 3),
	}
	f := findingFor("AEGIS-AWS-007", "aws_db_instance.main", "storage_encrypted", "db.tf", 2, 2)
	patches := newFixer007().Propose(f, res, []byte(src))
	if len(patches) != 1 {
		t.Fatalf("want 1 patch, got %d", len(patches))
	}
	out := applySingle(t, patches[0], src)
	if !strings.Contains(out, "storage_encrypted = true # keep false for teardown") {
		t.Errorf("trailing comment lost:\n%s", out)
	}
	// // comments are preserved too.
	src2 := "resource \"aws_db_instance\" \"main\" {\n  storage_encrypted = false // demo only\n}\n"
	patches2 := newFixer007().Propose(f, res, []byte(src2))
	if len(patches2) != 1 {
		t.Fatalf("want 1 patch for // comment, got %d", len(patches2))
	}
	if out2 := applySingle(t, patches2[0], src2); !strings.Contains(out2, "// demo only") {
		t.Errorf("// comment lost:\n%s", out2)
	}
}

func TestFixer007PreservesCRLF(t *testing.T) {
	src := "resource \"aws_db_instance\" \"main\" {\r\n  storage_encrypted = false\r\n}\r\n"
	res := ir.Resource{
		Type: "aws_db_instance", Name: "main",
		Attributes: map[string]ir.Value{"storage_encrypted": resolvedBoolAttr("db.tf", 2, false)},
		Span:       spanOf("db.tf", 1, 3),
	}
	f := findingFor("AEGIS-AWS-007", "aws_db_instance.main", "storage_encrypted", "db.tf", 2, 2)
	patches := newFixer007().Propose(f, res, []byte(src))
	if len(patches) != 1 {
		t.Fatalf("want 1 patch, got %d", len(patches))
	}
	out := applySingle(t, patches[0], src)
	if !strings.Contains(out, "storage_encrypted = true\r\n") {
		t.Errorf("fixed line must keep CRLF:\n%q", out)
	}
	if strings.Count(out, "\r\n") != 3 {
		t.Errorf("all lines must stay CRLF:\n%q", out)
	}
}

func TestBlockFixerPreservesCRLF(t *testing.T) {
	src := "resource \"aws_s3_bucket\" \"b\" {\r\n  bucket = \"x\"\r\n}\r\n"
	res := ir.Resource{
		Type: "aws_s3_bucket", Name: "b",
		Attributes: map[string]ir.Value{},
		Span:       spanOf("b.tf", 1, 3),
	}
	f := findingFor("AEGIS-AWS-001", "aws_s3_bucket.b", "server_side_encryption_configuration", "b.tf", 1, 3)
	patches := newFixer001().Propose(f, res, []byte(src))
	if len(patches) != 1 {
		t.Fatalf("want 1 patch, got %d", len(patches))
	}
	out := applySingle(t, patches[0], src)
	if strings.Contains(out, "\n  server_side") && !strings.Contains(out, "\r\n  server_side") {
		t.Errorf("inserted block must use CRLF:\n%q", out)
	}
	for _, line := range strings.Split(strings.TrimSuffix(out, "\r\n"), "\r\n") {
		if strings.HasSuffix(line, "\r") || strings.Contains(line, "\n") {
			t.Errorf("mixed line ending in %q (full %q)", line, out)
		}
	}
}

func TestFixer007RefusesMultilineSpan(t *testing.T) {
	src := "resource \"aws_db_instance\" \"main\" {\n  storage_encrypted =\n    false\n}\n"
	res := ir.Resource{
		Type: "aws_db_instance", Name: "main",
		Attributes: map[string]ir.Value{"storage_encrypted": resolvedBoolAttr("db.tf", 2, false)},
		Span:       spanOf("db.tf", 1, 4),
	}
	// Span covers lines 2-3 (multi-line value).
	f := findingFor("AEGIS-AWS-007", "aws_db_instance.main", "storage_encrypted", "db.tf", 2, 3)
	if patches := newFixer007().Propose(f, res, []byte(src)); len(patches) != 0 {
		t.Errorf("multi-line span must yield no patch, got %+v", patches)
	}
}

func TestBoolFixerUnknownAttrNeverDuplicates(t *testing.T) {
	// Attribute present but unresolved: the fixer must not insert a
	// second attribute line next to the existing one.
	src := "resource \"aws_db_instance\" \"main\" {\n  storage_encrypted = var.encrypt\n}\n"
	res := ir.Resource{
		Type: "aws_db_instance", Name: "main",
		Attributes: map[string]ir.Value{"storage_encrypted": ir.UnknownValue(spanOf("db.tf", 2, 2))},
		Span:       spanOf("db.tf", 1, 3),
	}
	f := findingFor("AEGIS-AWS-007", "aws_db_instance.main", "storage_encrypted", "db.tf", 2, 2)
	if patches := newFixer007().Propose(f, res, []byte(src)); len(patches) != 0 {
		t.Errorf("unknown attribute must yield no patch, got %+v", patches)
	}
}

func TestProposeAllDuplicateAddressFileAware(t *testing.T) {
	aSrc := "resource \"aws_s3_bucket\" \"dup\" {\n  bucket = \"a\"\n}\n"
	bSrc := "resource \"aws_s3_bucket\" \"dup\" {\n  bucket = \"b\"\n}\n"
	files := map[string][]byte{"a.tf": []byte(aSrc), "b.tf": []byte(bSrc)}
	readFile := func(path string) ([]byte, error) { return files[path], nil }
	resA := ir.Resource{Type: "aws_s3_bucket", Name: "dup", Attributes: map[string]ir.Value{}, Span: spanOf("a.tf", 1, 3)}
	resB := ir.Resource{Type: "aws_s3_bucket", Name: "dup", Attributes: map[string]ir.Value{}, Span: spanOf("b.tf", 1, 3)}
	findings := []ir.Finding{
		findingFor("AEGIS-AWS-001", "aws_s3_bucket.dup", "server_side_encryption_configuration", "a.tf", 1, 3),
		findingFor("AEGIS-AWS-001", "aws_s3_bucket.dup", "server_side_encryption_configuration", "b.tf", 1, 3),
	}
	patches := ProposeAll(findings, []ir.Resource{resA, resB}, readFile)
	if len(patches) != 2 {
		t.Fatalf("want 2 patches (one per file), got %d: %+v", len(patches), patches)
	}
	seen := map[string]bool{}
	for _, p := range patches {
		if len(p.Edits) != 1 {
			t.Fatalf("want 1 edit per patch, got %+v", p.Edits)
		}
		seen[p.Edits[0].File] = true
		// The b.tf patch must insert before b.tf's own closing brace,
		// not a.tf's: both are line 3 here by construction, but the
		// file attribution is what the old first-by-address code got
		// wrong (both patches targeted a.tf).
	}
	if !seen["a.tf"] || !seen["b.tf"] {
		t.Errorf("patches must target both files, got %v", seen)
	}
}

func TestValidatePatchDuplicateAddressPerFile(t *testing.T) {
	dir := writeTarget(t, map[string]string{
		"a.tf": "resource \"aws_s3_bucket\" \"dup\" {\n  bucket = \"a\"\n}\n",
		"b.tf": "resource \"aws_s3_bucket\" \"dup\" {\n  bucket = \"b\"\n}\n",
	})
	// Fake scan models the real one: findings are per-file, paths are
	// rooted at the scanned dir (tmp for the after-scan).
	scan := func(d string) (ir.ScanResult, []ir.Resource, error) {
		var findings []ir.Finding
		var resources []ir.Resource
		for _, name := range []string{"a.tf", "b.tf"} {
			content, _ := os.ReadFile(filepath.Join(d, name))
			resources = append(resources, ir.Resource{
				Type: "aws_s3_bucket", Name: "dup",
				Span: spanOf(filepath.Join(d, name), 1, 3),
			})
			if !strings.Contains(string(content), "server_side_encryption") {
				findings = append(findings, findingFor(
					"AEGIS-AWS-001", "aws_s3_bucket.dup",
					"server_side_encryption_configuration", filepath.Join(d, name), 1, 3))
			}
		}
		return ir.ScanResult{Findings: findings}, resources, nil
	}
	p := Patch{
		RuleID:   "AEGIS-AWS-001",
		Resource: "aws_s3_bucket.dup",
		Edits: []Edit{{
			File:      filepath.Join(dir, "a.tf"),
			StartLine: 3, EndLine: 3,
			NewText: "  server_side_encryption_configuration {}\n}",
		}},
	}
	v, err := ValidatePatch(dir, p, scan)
	if err != nil {
		t.Fatal(err)
	}
	if v.ResourceMissing {
		t.Error("ResourceMissing must be false: a.tf's resource still parses")
	}
	if !v.Fixed {
		t.Error("Fixed must be true: the a.tf finding is gone; the b.tf twin is a separate patch's job")
	}
}

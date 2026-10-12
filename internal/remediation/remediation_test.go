package remediation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aegis/internal/ir"
)

// --- ApplyEdits ---

func TestApplyEditsSingle(t *testing.T) {
	out, err := ApplyEdits("a\nb\nc\n", []Edit{{File: "f", StartLine: 2, EndLine: 2, NewText: "B"}})
	if err != nil {
		t.Fatal(err)
	}
	if out != "a\nB\nc\n" {
		t.Errorf("got %q", out)
	}
}

func TestApplyEditsMultiLine(t *testing.T) {
	out, err := ApplyEdits("a\nb\nc\nd\n", []Edit{
		{File: "f", StartLine: 4, EndLine: 4, NewText: "D1\nD2"},
		{File: "f", StartLine: 1, EndLine: 2, NewText: "AB"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out != "AB\nc\nD1\nD2\n" {
		t.Errorf("got %q", out)
	}
}

func TestApplyEditsOverlapRejected(t *testing.T) {
	_, err := ApplyEdits("a\nb\nc\nd\n", []Edit{
		{File: "f", StartLine: 2, EndLine: 3, NewText: "x"},
		{File: "f", StartLine: 3, EndLine: 4, NewText: "y"},
	})
	if err == nil {
		t.Error("overlapping edits should be rejected")
	}
	_, err = ApplyEdits("a\nb\n", []Edit{
		{File: "f", StartLine: 1, EndLine: 1, NewText: "x"},
		{File: "f", StartLine: 1, EndLine: 1, NewText: "y"},
	})
	if err == nil {
		t.Error("duplicate edits should be rejected")
	}
}

func TestApplyEditsOutOfRange(t *testing.T) {
	for _, e := range []Edit{
		{File: "f", StartLine: 0, EndLine: 1, NewText: "x"},
		{File: "f", StartLine: 5, EndLine: 5, NewText: "x"},
		{File: "f", StartLine: 2, EndLine: 1, NewText: "x"},
	} {
		if _, err := ApplyEdits("a\nb\n", []Edit{e}); err == nil {
			t.Errorf("edit %+v should be rejected", e)
		}
	}
}

func TestApplyEditsNoTrailingNewline(t *testing.T) {
	out, err := ApplyEdits("a\nb", []Edit{{File: "f", StartLine: 2, EndLine: 2, NewText: "B"}})
	if err != nil {
		t.Fatal(err)
	}
	if out != "a\nB" {
		t.Errorf("got %q", out)
	}
}

// --- ProposeAll ---

func TestProposeAllDeterminismAndCoverage(t *testing.T) {
	src := "resource \"aws_db_instance\" \"main\" {\n  storage_encrypted = false\n}\n" +
		"resource \"aws_security_group\" \"web\" {\n}\n"
	_ = src
	files := map[string][]byte{
		"db.tf": []byte("resource \"aws_db_instance\" \"main\" {\n  storage_encrypted = false\n}\n"),
		"sg.tf": []byte("resource \"aws_security_group\" \"web\" {\n}\n"),
	}
	resources := []ir.Resource{
		{Type: "aws_db_instance", Name: "main",
			Attributes: map[string]ir.Value{"storage_encrypted": boolAttr("db.tf", 2, false)},
			Span:       spanOf("db.tf", 1, 3)},
		{Type: "aws_security_group", Name: "web", Span: spanOf("sg.tf", 1, 2)},
	}
	findings := []ir.Finding{
		// No fixer: open ingress needs human judgment.
		findingFor("AEGIS-AWS-004", "aws_security_group.web", "ingress", "sg.tf", 1, 2),
		// Attack path: no auto-fix.
		findingFor("AEGIS-AWS-103", "aws_db_instance.main", "publicly_accessible", "db.tf", 1, 3),
		// Fixable.
		findingFor("AEGIS-AWS-007", "aws_db_instance.main", "storage_encrypted", "db.tf", 2, 2),
		// Unknown resource: skipped.
		findingFor("AEGIS-AWS-007", "aws_db_instance.ghost", "storage_encrypted", "db.tf", 2, 2),
	}
	readFile := func(path string) ([]byte, error) { return files[path], nil }
	run := func() []Patch { return ProposeAll(findings, resources, readFile) }
	p1, p2 := run(), run()
	if len(p1) != 1 || len(p2) != 1 {
		t.Fatalf("want exactly 1 patch, got %d / %d", len(p1), len(p2))
	}
	if p1[0].RuleID != "AEGIS-AWS-007" || p1[0].Resource != "aws_db_instance.main" {
		t.Errorf("unexpected patch: %+v", p1[0])
	}
	if p1[0].Diff != p2[0].Diff {
		t.Error("ProposeAll is not deterministic")
	}
	if !strings.Contains(p1[0].Diff, "@@") || !strings.Contains(p1[0].Diff, "storage_encrypted") {
		t.Errorf("diff looks wrong:\n%s", p1[0].Diff)
	}
}

func TestDefaultFixersSorted(t *testing.T) {
	fixers := DefaultFixers()
	if len(fixers) != 8 {
		t.Fatalf("want 8 fixers, got %d", len(fixers))
	}
	for i := 1; i < len(fixers); i++ {
		if fixers[i-1].RuleID() >= fixers[i].RuleID() {
			t.Errorf("fixers not sorted: %s before %s", fixers[i-1].RuleID(), fixers[i].RuleID())
		}
	}
}

// --- ValidatePatch ---

func writeTarget(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		full := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A .git dir must be skipped by the copy, not scanned/copied.
	if err := os.MkdirAll(filepath.Join(dir, ".git", "objects"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "objects", "x"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestValidatePatchFixed(t *testing.T) {
	dir := writeTarget(t, map[string]string{
		"db.tf": "resource \"aws_db_instance\" \"main\" {\n  storage_encrypted = false\n}\n",
	})
	before := ir.ScanResult{Target: dir, Resources: 1, Findings: []ir.Finding{
		findingFor("AEGIS-AWS-007", "aws_db_instance.main", "storage_encrypted", filepath.Join(dir, "db.tf"), 2, 2),
	}}
	after := ir.ScanResult{Target: dir, Resources: 1, Findings: nil}
	dbRes := []ir.Resource{{Type: "aws_db_instance", Name: "main"}}
	scan := func(d string) (ir.ScanResult, []ir.Resource, error) {
		if d == dir {
			return before, dbRes, nil
		}
		return after, dbRes, nil
	}
	p := Patch{
		RuleID:   "AEGIS-AWS-007",
		Resource: "aws_db_instance.main",
		Edits: []Edit{{
			File:      filepath.Join(dir, "db.tf"),
			StartLine: 2, EndLine: 2,
			NewText: "  storage_encrypted = true",
		}},
	}
	v, err := ValidatePatch(dir, p, scan)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Fixed {
		t.Error("Fixed should be true")
	}
	if len(v.NewFindings) != 0 {
		t.Errorf("unexpected new findings: %+v", v.NewFindings)
	}
	// Original tree untouched.
	orig, _ := os.ReadFile(filepath.Join(dir, "db.tf"))
	if strings.Contains(string(orig), "true") {
		t.Error("original file was modified")
	}
}

func TestValidatePatchNewFindings(t *testing.T) {
	dir := writeTarget(t, map[string]string{
		"db.tf": "resource \"aws_db_instance\" \"main\" {\n  storage_encrypted = false\n}\n",
	})
	before := ir.ScanResult{Findings: []ir.Finding{
		findingFor("AEGIS-AWS-007", "aws_db_instance.main", "storage_encrypted", filepath.Join(dir, "db.tf"), 2, 2),
	}}
	introduced := findingFor("AEGIS-AWS-011", "aws_db_instance.main", "publicly_accessible", filepath.Join(dir, "db.tf"), 2, 2)
	after := ir.ScanResult{Findings: []ir.Finding{introduced}}
	dbRes := []ir.Resource{{Type: "aws_db_instance", Name: "main"}}
	scan := func(d string) (ir.ScanResult, []ir.Resource, error) {
		if d == dir {
			return before, dbRes, nil
		}
		return after, dbRes, nil
	}
	p := Patch{
		RuleID:   "AEGIS-AWS-007",
		Resource: "aws_db_instance.main",
		Edits: []Edit{{
			File:      filepath.Join(dir, "db.tf"),
			StartLine: 2, EndLine: 2,
			NewText: "  storage_encrypted = true",
		}},
	}
	v, err := ValidatePatch(dir, p, scan)
	if err != nil {
		t.Fatal(err)
	}
	if !v.Fixed {
		t.Error("Fixed should be true: the 007 target finding is gone")
	}
	if len(v.NewFindings) != 1 || v.NewFindings[0].RuleID != "AEGIS-AWS-011" {
		t.Errorf("want the introduced 011 finding, got %+v", v.NewFindings)
	}
	// Re-run with the 007 finding still present after, to isolate the
	// Fixed=false branch.
	after2 := ir.ScanResult{Findings: []ir.Finding{
		findingFor("AEGIS-AWS-007", "aws_db_instance.main", "storage_encrypted", filepath.Join(dir, "db.tf"), 2, 2),
		introduced,
	}}
	scan2 := func(d string) (ir.ScanResult, []ir.Resource, error) {
		if d == dir {
			return before, dbRes, nil
		}
		return after2, dbRes, nil
	}
	v2, err := ValidatePatch(dir, p, scan2)
	if err != nil {
		t.Fatal(err)
	}
	if v2.Fixed {
		t.Error("Fixed should be false when the target finding persists")
	}
	if len(v2.NewFindings) != 1 || v2.NewFindings[0].RuleID != "AEGIS-AWS-011" {
		t.Errorf("want the introduced 011 finding, got %+v", v2.NewFindings)
	}
}

func TestValidatePatchOutsideTargetRejected(t *testing.T) {
	dir := writeTarget(t, map[string]string{"db.tf": "x\n"})
	p := Patch{
		RuleID:   "AEGIS-AWS-007",
		Resource: "aws_db_instance.main",
		Edits:    []Edit{{File: "/etc/passwd", StartLine: 1, EndLine: 1, NewText: "x"}},
	}
	scan := func(d string) (ir.ScanResult, []ir.Resource, error) { return ir.ScanResult{}, nil, nil }
	if _, err := ValidatePatch(dir, p, scan); err == nil {
		t.Error("patch escaping the target dir should be rejected")
	}
}

func TestValidatePatchScanError(t *testing.T) {
	dir := writeTarget(t, map[string]string{"db.tf": "x\n"})
	p := Patch{RuleID: "AEGIS-AWS-007", Resource: "r",
		Edits: []Edit{{File: filepath.Join(dir, "db.tf"), StartLine: 1, EndLine: 1, NewText: "y"}}}
	scan := func(d string) (ir.ScanResult, []ir.Resource, error) {
		return ir.ScanResult{}, nil, os.ErrClosed
	}
	if _, err := ValidatePatch(dir, p, scan); err == nil {
		t.Error("before-scan failure should propagate")
	}
}

func TestValidatePatchCorruptPatchRejected(t *testing.T) {
	dir := writeTarget(t, map[string]string{
		"db.tf": "resource \"aws_db_instance\" \"main\" {\n  storage_encrypted = false\n}\n",
	})
	before := ir.ScanResult{Findings: []ir.Finding{
		findingFor("AEGIS-AWS-007", "aws_db_instance.main", "storage_encrypted", filepath.Join(dir, "db.tf"), 2, 2),
	}}
	dbRes := []ir.Resource{{Type: "aws_db_instance", Name: "main"}}
	// After a corrupting patch the resource no longer parses: the finding
	// is gone but so is the resource. That must never read as "fixed".
	after := ir.ScanResult{Findings: nil}
	scan := func(d string) (ir.ScanResult, []ir.Resource, error) {
		if d == dir {
			return before, dbRes, nil
		}
		return after, nil, nil // resource vanished
	}
	p := Patch{
		RuleID:   "AEGIS-AWS-007",
		Resource: "aws_db_instance.main",
		Edits: []Edit{{
			File:      filepath.Join(dir, "db.tf"),
			StartLine: 1, EndLine: 3,
			NewText: "{{{ not hcl at all }}}",
		}},
	}
	v, err := ValidatePatch(dir, p, scan)
	if err != nil {
		t.Fatal(err)
	}
	if v.Fixed {
		t.Error("corrupting patch must not validate as fixed")
	}
	if !v.ResourceMissing {
		t.Error("ResourceMissing should be set when the target resource no longer parses")
	}
}

func TestValidatePatchNewErrorDiagnosticsRejected(t *testing.T) {
	dir := writeTarget(t, map[string]string{
		"db.tf": "resource \"aws_db_instance\" \"main\" {\n  storage_encrypted = false\n}\n",
	})
	before := ir.ScanResult{Findings: []ir.Finding{
		findingFor("AEGIS-AWS-007", "aws_db_instance.main", "storage_encrypted", filepath.Join(dir, "db.tf"), 2, 2),
	}}
	dbRes := []ir.Resource{{Type: "aws_db_instance", Name: "main"}}
	after := ir.ScanResult{
		Findings:    nil,
		Diagnostics: []ir.Diagnostic{{Level: "error", Message: "parse boom"}},
	}
	scan := func(d string) (ir.ScanResult, []ir.Resource, error) {
		if d == dir {
			return before, dbRes, nil
		}
		return after, dbRes, nil
	}
	p := Patch{
		RuleID:   "AEGIS-AWS-007",
		Resource: "aws_db_instance.main",
		Edits: []Edit{{
			File:      filepath.Join(dir, "db.tf"),
			StartLine: 2, EndLine: 2,
			NewText: "  storage_encrypted = true",
		}},
	}
	v, err := ValidatePatch(dir, p, scan)
	if err != nil {
		t.Fatal(err)
	}
	if v.Fixed {
		t.Error("patch introducing new error diagnostics must not validate as fixed")
	}
}

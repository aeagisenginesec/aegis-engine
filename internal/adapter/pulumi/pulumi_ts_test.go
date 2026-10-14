package pulumi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aegis/internal/ir"
)

// writeTSProgram creates a temp dir holding a Pulumi TypeScript program:
// Pulumi.yaml + package.json + index.ts.
func writeTSProgram(t *testing.T, pulumiYAML string, extra map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"Pulumi.yaml":  pulumiYAML,
		"package.json": `{"name":"ts-prog","dependencies":{"@pulumi/aws":"^6.0.0"}}` + "\n",
		"index.ts":     "import * as aws from \"@pulumi/aws\";\nconst b = new aws.s3.Bucket(\"b\", {acl: \"public-read\"});\n",
	}
	for name, body := range extra {
		files[name] = body
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func parseFile(t *testing.T, path string) ([]ir.Resource, []ir.Diagnostic) {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return parse(t, path, string(src))
}

// hasNotAnalyzedWarning reports whether diags carry the honest TS/JS warning.
func hasNotAnalyzedWarning(diags []ir.Diagnostic) bool {
	for _, d := range diags {
		if d.Level == "warning" && strings.Contains(d.Message, "not analyzed") {
			return true
		}
	}
	return false
}

// 1. A declared Node.js program warns instead of scanning silently clean.
func TestTSProgramWarns(t *testing.T) {
	dir := writeTSProgram(t, "name: ts-prog\nruntime: nodejs\ndescription: TS program\n", nil)
	rs, diags := parseFile(t, filepath.Join(dir, "Pulumi.yaml"))
	if len(rs) != 0 {
		t.Fatalf("TS program must yield no resources, got %d", len(rs))
	}
	if !hasNotAnalyzedWarning(diags) {
		t.Fatalf("expected 'not analyzed' warning, got %+v", diags)
	}
	var msg string
	for _, d := range diags {
		if strings.Contains(d.Message, "not analyzed") {
			msg = d.Message
		}
	}
	if !strings.Contains(msg, "TypeScript/JavaScript") {
		t.Errorf("warning must name the language, got %q", msg)
	}
	if !strings.Contains(msg, "index.ts") {
		t.Errorf("warning must list the unparsed entrypoint, got %q", msg)
	}
	// The generic "no resources" warning must not also fire: the honest
	// warning replaces it.
	for _, d := range diags {
		if strings.Contains(d.Message, "no resources: section") {
			t.Errorf("redundant 'no resources' warning alongside honest warning: %q", d.Message)
		}
	}
}

// 2. Fallback detection: no runtime field, but package.json + .ts entrypoints.
func TestTSProgramWarnsWithoutRuntime(t *testing.T) {
	dir := writeTSProgram(t, "name: ts-prog\ndescription: no runtime field\n", nil)
	rs, diags := parseFile(t, filepath.Join(dir, "Pulumi.yaml"))
	if len(rs) != 0 {
		t.Fatalf("expected no resources, got %d", len(rs))
	}
	if !hasNotAnalyzedWarning(diags) {
		t.Fatalf("expected 'not analyzed' warning via entrypoint detection, got %+v", diags)
	}
}

// 3. A declarative YAML program never warns.
func TestYAMLProgramNoWarning(t *testing.T) {
	rs, diags := parse(t, "Pulumi.yaml", `
name: yaml-prog
runtime: yaml
resources:
  data:
    type: aws:s3:Bucket
    properties:
      bucket: my-data
`)
	if len(rs) != 1 {
		t.Fatalf("YAML program must parse, got %d resources", len(rs))
	}
	if hasNotAnalyzedWarning(diags) {
		t.Fatalf("YAML program must not warn, got %+v", diags)
	}
}

// 4. Other language runtimes are out of this check's scope: no warning.
func TestPythonProgramNoWarning(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"Pulumi.yaml":     "name: py-prog\nruntime: python\ndescription: Python program\n",
		"requirements.txt": "pulumi>=3.0.0\n",
		"__main__.py":     "import pulumi_aws as aws\nb = aws.s3.Bucket('b')\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rs, diags := parseFile(t, filepath.Join(dir, "Pulumi.yaml"))
	if len(rs) != 0 {
		t.Fatalf("expected no resources, got %d", len(rs))
	}
	if hasNotAnalyzedWarning(diags) {
		t.Fatalf("Python program must not warn under this check's scope, got %+v", diags)
	}
}

// 5. Mixed dir: runtime: yaml is authoritative even with .ts files present.
func TestMixedDirYAMLNoWarning(t *testing.T) {
	dir := writeTSProgram(t, "name: mixed\nruntime: yaml\nresources:\n  data:\n    type: aws:s3:Bucket\n    properties:\n      bucket: my-data\n", nil)
	rs, diags := parseFile(t, filepath.Join(dir, "Pulumi.yaml"))
	if len(rs) != 1 {
		t.Fatalf("YAML program must parse despite sibling .ts files, got %d", len(rs))
	}
	if hasNotAnalyzedWarning(diags) {
		t.Fatalf("runtime: yaml must not warn despite sibling .ts files, got %+v", diags)
	}
}

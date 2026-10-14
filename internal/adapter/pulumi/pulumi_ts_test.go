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

// 4. A declared Python program warns instead of scanning silently.
func TestPythonProgramWarns(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"Pulumi.yaml":      "name: py-prog\nruntime: python\ndescription: Python program\n",
		"requirements.txt": "pulumi>=3.0.0\n",
		"__main__.py":      "import pulumi_aws as aws\nb = aws.s3.Bucket('b')\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rs, diags := parseFile(t, filepath.Join(dir, "Pulumi.yaml"))
	if len(rs) != 0 {
		t.Fatalf("Python program must yield no resources, got %d", len(rs))
	}
	if !hasNotAnalyzedWarning(diags) {
		t.Fatalf("expected 'not analyzed' warning for Python, got %+v", diags)
	}
	for _, d := range diags {
		if strings.Contains(d.Message, "not analyzed") {
			if !strings.Contains(d.Message, "Python") {
				t.Errorf("warning must name the language, got %q", d.Message)
			}
			if !strings.Contains(d.Message, "__main__.py") {
				t.Errorf("warning must list the unparsed entrypoint, got %q", d.Message)
			}
		}
		if strings.Contains(d.Message, "no resources: section") {
			t.Errorf("redundant 'no resources' warning alongside honest warning: %q", d.Message)
		}
	}
}

// 4b. Fallback detection: no runtime field, but requirements.txt + .py entrypoint.
func TestPythonProgramWarnsWithoutRuntime(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"Pulumi.yaml":      "name: py-prog\ndescription: no runtime field\n",
		"requirements.txt": "pulumi>=3.0.0\n",
		"__main__.py":      "import pulumi_aws as aws\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rs, diags := parseFile(t, filepath.Join(dir, "Pulumi.yaml"))
	if len(rs) != 0 {
		t.Fatalf("expected no resources, got %d", len(rs))
	}
	if !hasNotAnalyzedWarning(diags) {
		t.Fatalf("expected 'not analyzed' warning via Python markers, got %+v", diags)
	}
}

// 4c. A declared Go program warns.
func TestGoProgramWarns(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"Pulumi.yaml": "name: go-prog\nruntime: go\ndescription: Go program\n",
		"go.mod":      "module example.com/go-prog\n\ngo 1.25\n",
		"main.go":     "package main\n\nfunc main() {}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rs, diags := parseFile(t, filepath.Join(dir, "Pulumi.yaml"))
	if len(rs) != 0 {
		t.Fatalf("Go program must yield no resources, got %d", len(rs))
	}
	if !hasNotAnalyzedWarning(diags) {
		t.Fatalf("expected 'not analyzed' warning for Go, got %+v", diags)
	}
	for _, d := range diags {
		if strings.Contains(d.Message, "not analyzed") && !strings.Contains(d.Message, "Go") {
			t.Errorf("warning must name the language, got %q", d.Message)
		}
	}
}

// 4d. A declared .NET program warns.
func TestDotnetProgramWarns(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"Pulumi.yaml": "name: dotnet-prog\nruntime: dotnet\ndescription: .NET program\n",
		"MyStack.csproj": "<Project Sdk=\"Pulumi/Pulumi.CSharp.Sdk\">\n</Project>\n",
		"MyStack.cs":  "using Pulumi;\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rs, diags := parseFile(t, filepath.Join(dir, "Pulumi.yaml"))
	if len(rs) != 0 {
		t.Fatalf(".NET program must yield no resources, got %d", len(rs))
	}
	if !hasNotAnalyzedWarning(diags) {
		t.Fatalf("expected 'not analyzed' warning for .NET, got %+v", diags)
	}
	for _, d := range diags {
		if strings.Contains(d.Message, "not analyzed") && !strings.Contains(d.Message, ".NET") {
			t.Errorf("warning must name the language, got %q", d.Message)
		}
	}
}

// 4e. A declared Java program warns.
func TestJavaProgramWarns(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"Pulumi.yaml": "name: java-prog\nruntime: java\ndescription: Java program\n",
		"pom.xml":     "<project></project>\n",
		"App.java":    "public class App {}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rs, diags := parseFile(t, filepath.Join(dir, "Pulumi.yaml"))
	if len(rs) != 0 {
		t.Fatalf("Java program must yield no resources, got %d", len(rs))
	}
	if !hasNotAnalyzedWarning(diags) {
		t.Fatalf("expected 'not analyzed' warning for Java, got %+v", diags)
	}
}

// 4f. Negative: Pulumi.yaml with no runtime, no markers, no resources —
// no honest warning (the generic "no resources" warning still fires).
func TestPulumiNoMarkersNoWarning(t *testing.T) {
	dir := t.TempDir()
	yamlPath := filepath.Join(dir, "Pulumi.yaml")
	if err := os.WriteFile(yamlPath, []byte("name: bare\ndescription: nothing here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, diags := parseFile(t, yamlPath)
	if hasNotAnalyzedWarning(diags) {
		t.Fatalf("bare Pulumi.yaml must not get the honest warning, got %+v", diags)
	}
	found := false
	for _, d := range diags {
		if strings.Contains(d.Message, "no resources: section") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected the generic 'no resources' warning, got %+v", diags)
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

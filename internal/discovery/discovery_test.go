package discovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsExcludedGlobs(t *testing.T) {
	SetExcludePatterns([]string{"vendor/**", "*.tfvars", "docs/*.md"})
	defer SetExcludePatterns(nil)
	cases := map[string]bool{
		"/repo/vendor/lib/vuln.tf": true,
		"/repo/vendor/vuln.tf":     true,
		"vendor/vuln.tf":           true,
		"/repo/vars.tfvars":        true,
		"vars.tfvars":              true,
		"/repo/docs/readme.md":     true,
		"/repo/main.tf":            false,
		"/repo/docs/sub/deep.md":   false, // docs/*.md is single-level
		"/repo/src/vendor/x.tf":    true,  // vendor/** matches at any depth (gitignore-style)
	}
	for path, want := range cases {
		if got := IsExcluded(path); got != want {
			t.Errorf("IsExcluded(%q) = %v, want %v", path, got, want)
		}
	}
	// **/ prefix makes vendor match at any depth.
	SetExcludePatterns([]string{"**/vendor/**"})
	defer SetExcludePatterns(nil)
	if !IsExcluded("/repo/src/vendor/x.tf") {
		t.Errorf("**/vendor/** should match at any depth")
	}
}

func TestIsExcludedEmpty(t *testing.T) {
	SetExcludePatterns(nil)
	if IsExcluded("/repo/vendor/x.tf") {
		t.Errorf("no patterns: nothing should be excluded")
	}
}

func TestGlobToRegex(t *testing.T) {
	cases := map[string]struct {
		pat     string
		match   []string
		nomatch []string
	}{
		"star": {
			pat:     "*.tf",
			match:   []string{"main.tf", "a.tf"},
			nomatch: []string{"dir/main.tf", "main.tfvars"},
		},
		"doublestar": {
			pat:     "vendor/**",
			match:   []string{"vendor/a.tf", "vendor/a/b.tf"},
			nomatch: []string{"src/vendor/a.tf", "vendor"},
		},
		"question": {
			pat:     "main.t?",
			match:   []string{"main.tf"},
			nomatch: []string{"main.tfvars", "main.t"},
		},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			for _, s := range c.match {
				if !matchGlob(c.pat, s) {
					t.Errorf("matchGlob(%q, %q) = false, want true", c.pat, s)
				}
			}
			for _, s := range c.nomatch {
				if matchGlob(c.pat, s) {
					t.Errorf("matchGlob(%q, %q) = true, want false", c.pat, s)
				}
			}
		})
	}
}

func TestOutputFileNamesSkippedBelowRoot(t *testing.T) {
	dir := t.TempDir()
	// A vulnerable .tf file plus the tool's own output names (one empty,
	// one with garbage content) and a legitimately named JSON manifest.
	tf := "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"x\"\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(tf), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"out.json", "out.sarif", "out.html", "aegis.json", "aegis.sarif", "sbom.spdx.json", "sbom.cyclonedx.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte{}, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "template.json"), []byte(`{"AWSTemplateFormatVersion": "2010-09-09"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	files, _, err := DiscoverWithReport(dir)
	if err != nil {
		t.Fatalf("DiscoverWithReport: %v", err)
	}
	seen := map[string]bool{}
	for _, f := range files {
		seen[filepath.Base(f.Path)] = true
	}
	for _, name := range []string{"out.json", "out.sarif", "out.html", "aegis.json", "aegis.sarif", "sbom.spdx.json", "sbom.cyclonedx.json"} {
		if seen[name] {
			t.Errorf("output file %s should be skipped, got files %v", name, files)
		}
	}
	if !seen["main.tf"] || !seen["template.json"] {
		t.Errorf("expected main.tf and template.json to be discovered, got %v", files)
	}
}

func TestOutputFileNameAsExplicitRootStillScanned(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out.json")
	if err := os.WriteFile(out, []byte(`{"AWSTemplateFormatVersion": "2010-09-09"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	files, _, err := DiscoverWithReport(out)
	if err != nil {
		t.Fatalf("DiscoverWithReport: %v", err)
	}
	if len(files) != 1 || files[0].Path != out {
		t.Errorf("explicitly named out.json should still be scanned, got %v", files)
	}
}

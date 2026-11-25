package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sbomFixture is a small project exercising every inventory source:
// a provider requirement, a registry module, a git module, a Dockerfile
// base image, and a Compose service image.
const sbomFixtureTF = `terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.0"
}

module "consul" {
  source = "git::https://example.com/consul.git?ref=v1.2.3"
}

resource "aws_s3_bucket" "b" {
  bucket = "sbom-test"
}
`

const sbomFixtureDockerfile = "FROM ubuntu:22.04\nRUN echo hi\n"

const sbomFixtureCompose = "services:\n  web:\n    image: nginx:1.25\n"

func writeSBOMFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"main.tf":     sbomFixtureTF,
		"Dockerfile":  sbomFixtureDockerfile,
		"compose.yml": sbomFixtureCompose,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func runSBOMScan(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func readSBOMJSON(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read SBOM %s: %v", path, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("SBOM %s is not valid JSON: %v", path, err)
	}
	return doc
}

func TestScanSBOMSPDX(t *testing.T) {
	dir := writeSBOMFixture(t)
	out := filepath.Join(dir, "sbom.spdx.json")
	code, _, stderr := runSBOMScan(t, "scan", dir, "--format=json", "--sbom", "spdx-json", "--sbom-out", out)
	// The fixture has findings (unencrypted bucket), so the scan exits 1;
	// the SBOM must still be written.
	if code != 1 {
		t.Fatalf("scan exit code = %d, want 1 (findings present)", code)
	}
	if !strings.Contains(stderr, "wrote SBOM (5 packages)") {
		t.Errorf("stderr = %q, want SBOM note with 5 packages", stderr)
	}
	doc := readSBOMJSON(t, out)
	if doc["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("spdxVersion = %v", doc["spdxVersion"])
	}
	pkgs, _ := doc["packages"].([]any)
	if len(pkgs) != 5 {
		t.Fatalf("packages = %d, want 5", len(pkgs))
	}
	names := map[string]bool{}
	for _, p := range pkgs {
		names[p.(map[string]any)["name"].(string)] = true
	}
	for _, want := range []string{"hashicorp/aws", "vpc", "consul", "ubuntu", "nginx"} {
		if !names[want] {
			t.Errorf("SPDX packages missing %q (got %v)", want, names)
		}
	}
	// The SBOM file itself must not be re-discovered as a manifest on a
	// second scan of the same directory.
	code2, _, _ := runSBOMScan(t, "scan", dir, "--format=json", "--sbom-out", filepath.Join(dir, "sbom2.spdx.json"))
	if code2 != 1 {
		t.Fatalf("second scan exit code = %d, want 1", code2)
	}
}

func TestScanSBOMCycloneDX(t *testing.T) {
	dir := writeSBOMFixture(t)
	out := filepath.Join(dir, "sbom.cyclonedx.json")
	code, _, stderr := runSBOMScan(t, "scan", dir, "--format=text", "--sbom", "cyclonedx-json", "--sbom-out", out)
	if code != 1 {
		t.Fatalf("scan exit code = %d, want 1 (findings present)", code)
	}
	if !strings.Contains(stderr, "wrote SBOM (5 packages)") {
		t.Errorf("stderr = %q, want SBOM note with 5 packages", stderr)
	}
	doc := readSBOMJSON(t, out)
	if doc["bomFormat"] != "CycloneDX" || doc["specVersion"] != "1.6" {
		t.Errorf("bomFormat/specVersion = %v/%v, want CycloneDX/1.6", doc["bomFormat"], doc["specVersion"])
	}
	comps, _ := doc["components"].([]any)
	if len(comps) != 5 {
		t.Fatalf("components = %d, want 5", len(comps))
	}
}

// Empty project: a valid, empty SBOM document, not an error.
func TestScanSBOMEmptyProject(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte("resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"x\"\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "sbom.spdx.json")
	code, _, stderr := runSBOMScan(t, "scan", dir, "--format=json", "--sbom", "spdx-json", "--sbom-out", out)
	if code != 1 {
		t.Fatalf("scan exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr, "wrote SBOM (0 packages)") {
		t.Errorf("stderr = %q, want SBOM note with 0 packages", stderr)
	}
	doc := readSBOMJSON(t, out)
	if pkgs := doc["packages"].([]any); len(pkgs) != 0 {
		t.Errorf("packages = %d, want 0", len(pkgs))
	}
}

// Malformed Terraform: the scan completes (parse failure is a
// diagnostic, not a crash), and the SBOM still renders — empty, from
// whatever parsed — instead of crashing.
func TestScanSBOMMalformedInput(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte("resource \"aws_s3_bucket\" \"b\" {\n  bucket = \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "sbom.spdx.json")
	code, _, stderr := runSBOMScan(t, "scan", dir, "--format=json", "--sbom", "spdx-json", "--sbom-out", out)
	if code != 0 {
		t.Fatalf("scan exit code = %d, want 0 (no findings; parse failure is a diagnostic)", code)
	}
	if !strings.Contains(stderr, "wrote SBOM (0 packages)") {
		t.Errorf("stderr = %q, want SBOM note with 0 packages", stderr)
	}
	doc := readSBOMJSON(t, out)
	if pkgs := doc["packages"].([]any); len(pkgs) != 0 {
		t.Errorf("packages = %d, want 0", len(pkgs))
	}
}

func TestScanSBOMBadFormat(t *testing.T) {
	dir := writeSBOMFixture(t)
	code, _, stderr := runSBOMScan(t, "scan", dir, "--sbom", "spdx-xml")
	if code != 2 {
		t.Fatalf("scan exit code = %d, want 2 for unknown --sbom value", code)
	}
	if !strings.Contains(stderr, "unknown --sbom") {
		t.Errorf("stderr = %q, want unknown --sbom error", stderr)
	}
}

func TestScanSBOMUnwritableOut(t *testing.T) {
	dir := writeSBOMFixture(t)
	code, _, stderr := runSBOMScan(t, "scan", dir, "--sbom", "spdx-json", "--sbom-out", filepath.Join(dir, "no-such-dir", "sbom.spdx.json"))
	if code != 2 {
		t.Fatalf("scan exit code = %d, want 2 for unwritable --sbom-out", code)
	}
	if !strings.Contains(stderr, "sbom:") {
		t.Errorf("stderr = %q, want sbom write error", stderr)
	}
}

func TestWriteSBOMDefaults(t *testing.T) {
	// Default filenames resolve without an explicit --sbom-out.
	// The two successful calls create files in the test working
	// directory; remove them even on failure.
	t.Cleanup(func() {
		os.Remove("sbom.spdx.json")
		os.Remove("sbom.cyclonedx.json")
	})
	if p, err := writeSBOM("spdx-json", "", "t", nil); err != nil || p != "sbom.spdx.json" {
		t.Errorf("writeSBOM spdx default = (%q, %v), want (sbom.spdx.json, nil)", p, err)
	}
	if p, err := writeSBOM("cyclonedx-json", "", "t", nil); err != nil || p != "sbom.cyclonedx.json" {
		t.Errorf("writeSBOM cyclonedx default = (%q, %v), want (sbom.cyclonedx.json, nil)", p, err)
	}
	if _, err := writeSBOM("spdx-xml", "", "t", nil); err == nil {
		t.Error("writeSBOM unknown format: want error, got nil")
	}
}

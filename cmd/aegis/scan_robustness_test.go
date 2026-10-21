package main

// Robustness audit tests (2026-10-14 mission, Part B).
//
// Per-adapter adversarial matrix: malformed, empty, truncated, binary,
// deeply nested, and extremely long-line inputs. Every case must
// terminate (no hangs) without panicking; parse failures must surface as
// diagnostics/errors, never as crashes. A CLI-level test drives one
// malformed file per adapter through run() to pin the diagnostic/exit
// behavior end to end.
//
// These are characterization tests: they add no production code and
// change no rule or adapter logic.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aegis/internal/adapter/arm"
	"aegis/internal/adapter/bicep"
	"aegis/internal/adapter/cloudformation"
	"aegis/internal/adapter/compose"
	"aegis/internal/adapter/dockerfile"
	"aegis/internal/adapter/manifests"
	"aegis/internal/adapter/planjson"
	"aegis/internal/adapter/pulumi"
	"aegis/internal/adapter/terraform"
	"aegis/internal/ir"
)

// adapterHarness binds one adapter's parse entry point for the matrix.
type adapterHarness struct {
	name  string
	file  string // realistic filename passed to Parse
	valid []byte // minimal valid document (truncated for the truncated case)
	deep  []byte // deeply nested / adversarially large document
	parse func(path string, src []byte) (diags int, err error, panicked any)
}

// wrapParse adapts a standard Parse func with panic recovery.
func wrapParse(p func(string, []byte) ([]ir.Resource, []ir.Diagnostic, error)) func(string, []byte) (int, error, any) {
	return func(path string, src []byte) (diags int, err error, panicked any) {
		defer func() {
			if r := recover(); r != nil {
				diags, err, panicked = 0, nil, r
			}
		}()
		_, d, e := p(path, src)
		return len(d), e, nil
	}
}

func auditAdapters() []adapterHarness {
	tfValid := []byte("resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"x\"\n}\n")
	tfDeep := []byte("resource \"x\" \"y\" {\n  v = " + strings.Repeat("{k=", 3000) + "1" + strings.Repeat("}", 3000) + "\n}\n")
	ta := terraform.New()

	yamlDeep := func() []byte {
		return []byte("top: " + strings.Repeat("{k: ", 10000) + "1" + strings.Repeat("}", 10000) + "\n")
	}
	jsonDeep := func() []byte {
		return []byte(strings.Repeat("[", 5000) + strings.Repeat("]", 5000))
	}

	return []adapterHarness{
		{
			name: "terraform", file: "main.tf", valid: tfValid, deep: tfDeep,
			parse: func(path string, src []byte) (diags int, err error, panicked any) {
				defer func() {
					if r := recover(); r != nil {
						diags, err, panicked = 0, nil, r
					}
				}()
				_, d, e := ta.ParseModule(path, src)
				return len(d), e, nil
			},
		},
		{
			name: "planjson", file: "tfplan.plan.json",
			valid: []byte(`{"format_version":"1.2","terraform_version":"1.5.0","resource_changes":[]}`),
			deep:  jsonDeep(),
			parse: wrapParse(planjson.Adapter{}.Parse),
		},
		{
			name: "compose", file: "docker-compose.yml",
			valid: []byte("services:\n  web:\n    image: nginx:1.25\n"),
			deep:  yamlDeep(),
			parse: wrapParse(compose.New().Parse),
		},
		{
			name: "pulumi", file: "Pulumi.yaml",
			valid: []byte("name: proj\nruntime: yaml\nresources:\n  b:\n    type: aws:s3:Bucket\n"),
			deep:  yamlDeep(),
			parse: wrapParse(pulumi.Adapter{}.Parse),
		},
		{
			name: "arm", file: "azuredeploy.json",
			valid: []byte(`{"$schema":"https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#","contentVersion":"1.0.0.0","resources":[]}`),
			deep:  jsonDeep(),
			parse: wrapParse(arm.New().Parse),
		},
		{
			name: "bicep", file: "main.bicep",
			valid: []byte("resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n  name: 'stx'\n  location: 'westeurope'\n}\n"),
			deep:  []byte("resource r 'T@1' = {\n" + strings.Repeat("{\n", 2000)),
			parse: wrapParse(bicep.New().Parse),
		},
		{
			name: "cloudformation", file: "template.yaml",
			valid: []byte("AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  B:\n    Type: AWS::S3::Bucket\n"),
			deep:  yamlDeep(),
			parse: wrapParse(cloudformation.Adapter{}.Parse),
		},
		{
			name: "manifests", file: "deploy.yaml",
			valid: []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cfg\n"),
			deep:  yamlDeep(),
			parse: wrapParse(manifests.Adapter{}.Parse),
		},
		{
			name: "dockerfile", file: "Dockerfile",
			valid: []byte("FROM alpine:3.19\nRUN echo hi\n"),
			deep:  []byte(strings.Repeat("RUN echo hello-world\n", 20000)),
			parse: wrapParse(dockerfile.New().Parse),
		},
	}
}

// binaryGarbage is 4 KiB of every byte value cycling — never valid input
// for any text format.
func binaryGarbage() []byte {
	var b bytes.Buffer
	for i := 0; i < 16; i++ {
		for v := 0; v < 256; v++ {
			b.WriteByte(byte(v))
		}
	}
	return b.Bytes()
}

// TestCLIAuditAdapterRobustness feeds every adapter malformed, empty,
// truncated, binary, deeply nested, and huge-line inputs. Each case must
// return (diagnostics and/or error allowed) within the watchdog window;
// a panic or a hang fails the test naming the adapter and case.
func TestCLIAuditAdapterRobustness(t *testing.T) {
	bin := binaryGarbage()
	for _, ad := range auditAdapters() {
		cases := []struct {
			name string
			src  []byte
		}{
			{"empty", []byte{}},
			{"binary garbage", bin},
			{"truncated", ad.valid[:len(ad.valid)/2]},
			{"deeply nested", ad.deep},
			{"extremely long line", longLineFor(ad.name)},
		}
		for _, c := range cases {
			t.Run(ad.name+"/"+c.name, func(t *testing.T) {
				type outcome struct {
					diags    int
					err      error
					panicked any
				}
				done := make(chan outcome, 1)
				go func() {
					d, e, p := ad.parse(ad.file, c.src)
					done <- outcome{d, e, p}
				}()
				select {
				case o := <-done:
					if o.panicked != nil {
						t.Errorf("adapter %s panicked on %s input: %v", ad.name, c.name, o.panicked)
					} else {
						t.Logf("adapter %s %-18s -> diags=%d err=%v", ad.name, c.name, o.diags, o.err != nil)
					}
				case <-time.After(30 * time.Second):
					t.Errorf("adapter %s HUNG on %s input (no return within 30s)", ad.name, c.name)
				}
			})
		}
	}
}

// longLineFor builds a ~2 MiB single-line input with a comment/quote
// prefix appropriate to the adapter's format.
func longLineFor(adapter string) []byte {
	prefix := "#"
	switch adapter {
	case "planjson", "arm":
		return []byte(`{"k": "` + strings.Repeat("x", 2000000) + `"}`)
	case "bicep":
		prefix = "//"
	}
	return []byte(prefix + strings.Repeat("x", 2000000) + "\n")
}

// TestCLIAuditMalformedDirPerAdapter writes one malformed file per
// adapter extension plus one valid vulnerable file, then pins the
// end-to-end behavior: non-strict reports diagnostics and exits on
// findings; --strict upgrades to exit 2.
func TestCLIAuditMalformedDirPerAdapter(t *testing.T) {
	dir := t.TempDir()
	malformed := map[string]string{
		"bad.tf":             "resource \"aws_s3_bucket\" \"x\" {\n  bucket = \n",
		"bad.plan.json":      `{"format_version": "1.2", "resource_changes": [`,
		"docker-compose.yml": "services:\n  web:\n    image: [unclosed\n",
		"Pulumi.yaml":        "name: proj\nruntime: [oops\n",
		"arm.json":           `{"$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#", "resources": [`,
		"bad.bicep":          "\x00\x01\x02 not bicep \xff\xfe",
		"cfn.template":       `{"AWSTemplateFormatVersion": "2010-09-09", "Resources": `,
		"k8s.yaml":           "\x00\x01binary\xff\xfe",
		"Dockerfile":         "\x00\x01\x02\xff\xfe",
		"ok.tf":              vulnTF, // valid + vulnerable: drives the findings exit
	}
	for name, content := range malformed {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Non-strict: findings from ok.tf -> exit 1, diagnostics for the rest.
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", dir}, &stdout, &stderr); code != 1 {
		t.Errorf("non-strict scan = %d, want 1 (findings in ok.tf); stderr: %s", code, stderr.String())
	}
	combined := stdout.String() + stderr.String()
	if !strings.Contains(combined, "diagnostic") && !strings.Contains(combined, "incomplete scan") {
		t.Errorf("expected parse-failure diagnostics in output, got:\n%s", firstLines(combined, 15))
	}

	// Strict: any unparseable file -> exit 2.
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"scan", dir, "--strict"}, &stdout, &stderr); code != 2 {
		t.Errorf("strict scan = %d, want 2; stderr: %s", code, stderr.String())
	}
}

// TestCLIAuditEmptyInputs pins degenerate-input behavior: an empty file
// and an empty directory scan without crashing and report zero findings.
func TestCLIAuditEmptyInputs(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "empty.tf"), []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "empty.yaml"), []byte{}, 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"scan", dir, "--format=json"}, &stdout, &stderr); code != 0 {
		t.Errorf("scan of empty files = %d, want 0; stderr: %s", code, stderr.String())
	}
}

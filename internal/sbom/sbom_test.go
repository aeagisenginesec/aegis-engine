package sbom

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"aegis/internal/adapter/terraform"
	"aegis/internal/ir"
)

var fixedTime = time.Date(2026, 11, 25, 18, 0, 0, 0, time.UTC)

func testModule() terraform.Module {
	return terraform.Module{
		Path: "main.tf",
		ProviderReqs: []terraform.ProviderReq{
			{Name: "aws", Source: "hashicorp/aws", Version: "~> 5.0", Span: ir.Span{File: "main.tf", StartLine: 3}},
			{Name: "random", Source: "hashicorp/random", Version: "", Span: ir.Span{File: "main.tf", StartLine: 4}},
			// Local name only: no source declared.
			{Name: "custom", Source: "", Version: "", Span: ir.Span{File: "main.tf", StartLine: 5}},
		},
		ModuleCalls: []terraform.ModuleCall{
			{
				Name:   "vpc",
				Source: "terraform-aws-modules/vpc/aws",
				Inputs: map[string]ir.Value{"version": {Raw: "5.1.0", Known: true}},
				Span:   ir.Span{File: "main.tf", StartLine: 10},
			},
			{
				Name:   "consul",
				Source: "git::https://example.com/consul.git?ref=v1.2.3",
				Inputs: map[string]ir.Value{},
				Span:   ir.Span{File: "main.tf", StartLine: 20},
			},
			{
				Name:   "dynamic",
				Source: "", // source = var.module_source: not static, skipped
				Inputs: map[string]ir.Value{},
				Span:   ir.Span{File: "main.tf", StartLine: 30},
			},
		},
	}
}

func testResources() []ir.Resource {
	span := func(line int) ir.Span { return ir.Span{File: "Dockerfile", StartLine: line} }
	return []ir.Resource{
		{
			Type: "docker_stage", Name: "base", Provider: "docker",
			Attributes: map[string]ir.Value{
				"base_image": {Raw: "ubuntu:22.04", Known: true, Span: span(1)},
				"base_tag":   {Raw: "22.04", Known: true, Span: span(1)},
			},
			Span: span(1),
		},
		{
			Type: "docker_stage", Name: "final", Provider: "docker",
			Attributes: map[string]ir.Value{
				// Same image, second stage: dedup must collapse it.
				"base_image": {Raw: "ubuntu:22.04", Known: true, Span: span(5)},
				"base_tag":   {Raw: "22.04", Known: true, Span: span(5)},
			},
			Span: span(5),
		},
		{
			Type: "compose_service", Name: "web", Provider: "compose",
			Attributes: map[string]ir.Value{
				"image": {Raw: "nginx:1.25", Known: true, Span: ir.Span{File: "compose.yml", StartLine: 4}},
			},
			Span: ir.Span{File: "compose.yml", StartLine: 3},
		},
		{
			Type: "compose_service", Name: "db", Provider: "compose",
			Attributes: map[string]ir.Value{
				// Untagged image: implicit :latest, version stays empty.
				"image": {Raw: "postgres", Known: true, Span: ir.Span{File: "compose.yml", StartLine: 9}},
			},
			Span: ir.Span{File: "compose.yml", StartLine: 8},
		},
		{
			Type: "compose_service", Name: "cache", Provider: "compose",
			Attributes: map[string]ir.Value{
				// Digest-pinned image: no tag, digest kept in Source.
				"image": {Raw: "redis@sha256:deadbeef", Known: true, Span: ir.Span{File: "compose.yml", StartLine: 14}},
			},
			Span: ir.Span{File: "compose.yml", StartLine: 13},
		},
		{
			Type: "compose_service", Name: "noimage", Provider: "compose",
			Attributes: map[string]ir.Value{
				// build: only, no image key: contributes nothing.
			},
			Span: ir.Span{File: "compose.yml", StartLine: 18},
		},
		{
			Type: "aws_s3_bucket", Name: "b", Provider: "aws",
			Attributes: map[string]ir.Value{},
		},
	}
}

func TestCollect(t *testing.T) {
	deps := Collect([]terraform.Module{testModule()}, testResources())
	want := []ir.Dependency{
		{Kind: "container-image", Name: "nginx", Version: "1.25", Source: "nginx:1.25", File: "compose.yml", Line: 4},
		{Kind: "container-image", Name: "postgres", Version: "", Source: "postgres", File: "compose.yml", Line: 9},
		{Kind: "container-image", Name: "redis", Version: "", Source: "redis@sha256:deadbeef", File: "compose.yml", Line: 14},
		{Kind: "container-image", Name: "ubuntu", Version: "22.04", Source: "ubuntu:22.04", File: "Dockerfile", Line: 1},
		{Kind: "terraform-module", Name: "consul", Version: "v1.2.3", Source: "git::https://example.com/consul.git?ref=v1.2.3", File: "main.tf", Line: 20},
		{Kind: "terraform-module", Name: "vpc", Version: "5.1.0", Source: "terraform-aws-modules/vpc/aws", File: "main.tf", Line: 10},
		{Kind: "terraform-provider", Name: "custom", Version: "", Source: "", File: "main.tf", Line: 5},
		{Kind: "terraform-provider", Name: "hashicorp/aws", Version: "~> 5.0", Source: "hashicorp/aws", File: "main.tf", Line: 3},
		{Kind: "terraform-provider", Name: "hashicorp/random", Version: "", Source: "hashicorp/random", File: "main.tf", Line: 4},
	}
	if len(deps) != len(want) {
		t.Fatalf("got %d dependencies, want %d:\n%+v", len(deps), len(want), deps)
	}
	for i := range want {
		if deps[i] != want[i] {
			t.Errorf("deps[%d] = %+v, want %+v", i, deps[i], want[i])
		}
	}
}

// Negative evidence: no modules, no resources, and nil inputs all yield
// an empty (non-nil) inventory, never a panic or a nil slice.
func TestCollectEmpty(t *testing.T) {
	for _, tc := range []struct {
		name string
		mods []terraform.Module
		res  []ir.Resource
	}{
		{"nil inputs", nil, nil},
		{"empty inputs", []terraform.Module{}, []ir.Resource{}},
		{"module with nothing", []terraform.Module{{Path: "empty.tf"}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deps := Collect(tc.mods, tc.res)
			if deps == nil {
				t.Fatal("Collect returned nil; want empty non-nil slice")
			}
			if len(deps) != 0 {
				t.Fatalf("got %d dependencies, want 0: %+v", len(deps), deps)
			}
		})
	}
}

// Malformed inputs must not crash Collect: unknown values, non-string
// attributes, blank refs, and garbage sources are skipped, not fatal.
func TestCollectMalformed(t *testing.T) {
	mods := []terraform.Module{{
		Path: "bad.tf",
		ProviderReqs: []terraform.ProviderReq{
			{Name: "aws", Source: "hashicorp/aws", Version: "~> 5.0", Span: ir.Span{File: "bad.tf", StartLine: 1}},
		},
		ModuleCalls: []terraform.ModuleCall{
			// version input is a non-string (e.g. a number): ignored.
			{Name: "weird", Source: "terraform-aws-modules/weird/aws",
				Inputs: map[string]ir.Value{"version": {Raw: 42, Known: true}},
				Span:   ir.Span{File: "bad.tf", StartLine: 2}},
			// version input is an unknown value: ignored.
			{Name: "unk", Source: "terraform-aws-modules/unk/aws",
				Inputs: map[string]ir.Value{"version": {Raw: "1.0", Known: false}},
				Span:   ir.Span{File: "bad.tf", StartLine: 3}},
		},
	}}
	res := []ir.Resource{
		{Type: "docker_stage", Name: "s", Provider: "docker", Attributes: map[string]ir.Value{
			"base_image": {Raw: "   ", Known: true, Span: ir.Span{File: "Dockerfile", StartLine: 1}},
		}},
		{Type: "docker_stage", Name: "s2", Provider: "docker", Attributes: map[string]ir.Value{
			"base_image": {Raw: 42, Known: true, Span: ir.Span{File: "Dockerfile", StartLine: 2}},
		}},
		{Type: "docker_stage", Name: "s3", Provider: "docker", Attributes: map[string]ir.Value{
			"base_image": {Raw: "alpine:3.19", Known: false, Span: ir.Span{File: "Dockerfile", StartLine: 3}},
		}},
		{Type: "compose_service", Name: "x", Provider: "compose", Attributes: map[string]ir.Value{
			"image": {Raw: "localhost:5000/my-app:2.0", Known: true, Span: ir.Span{File: "compose.yml", StartLine: 1}},
		}},
	}
	deps := Collect(mods, res)
	byName := map[string]ir.Dependency{}
	for _, d := range deps {
		byName[d.Name] = d
	}
	if len(deps) != 4 {
		t.Fatalf("got %d dependencies, want 4: %+v", len(deps), deps)
	}
	if d := byName["weird"]; d.Version != "" {
		t.Errorf("non-string version input leaked: %+v", d)
	}
	if d := byName["unk"]; d.Version != "" {
		t.Errorf("unknown version input leaked: %+v", d)
	}
	// Registry port (localhost:5000) must not be mistaken for a tag.
	if d := byName["localhost:5000/my-app"]; d.Version != "2.0" {
		t.Errorf("registry-port image parsed wrong: %+v", d)
	}
	if _, ok := byName["alpine"]; ok {
		t.Error("unknown base_image value should be skipped")
	}
}

func TestDocName(t *testing.T) {
	if got := docName("my-infra"); got != "my-infra" {
		t.Errorf("docName(my-infra) = %q", got)
	}
	if got := docName("/tmp/sbom-demo"); got != "sbom-demo" {
		t.Errorf("docName(/tmp/sbom-demo) = %q", got)
	}
	if got := docName(""); got != "project" {
		t.Errorf("docName(\"\") = %q", got)
	}
	// "." resolves to the current directory's base name, never ".".
	if got := docName("."); got == "." || got == "" {
		t.Errorf("docName(.) = %q", got)
	}
}

func TestSplitImageRef(t *testing.T) {
	cases := []struct{ ref, name, tag string }{
		{"ubuntu:22.04", "ubuntu", "22.04"},
		{"ubuntu", "ubuntu", ""},
		{"docker.io/library/nginx:1.25", "docker.io/library/nginx", "1.25"},
		{"localhost:5000/my-app:2.0", "localhost:5000/my-app", "2.0"},
		{"localhost:5000/my-app", "localhost:5000/my-app", ""},
		{"redis@sha256:deadbeef", "redis", ""},
		{"my-app:1.0@sha256:deadbeef", "my-app", "1.0"},
		{"", "", ""},
	}
	for _, c := range cases {
		if name, tag := splitImageRef(c.ref); name != c.name || tag != c.tag {
			t.Errorf("splitImageRef(%q) = (%q, %q), want (%q, %q)", c.ref, name, tag, c.name, c.tag)
		}
	}
}

func TestGitRef(t *testing.T) {
	cases := []struct{ src, ref string }{
		{"git::https://example.com/r.git?ref=v1.2.3", "v1.2.3"},
		{"git::https://example.com/r.git//sub?ref=main&depth=1", "main"},
		{"git::https://example.com/r.git", ""},
		{"terraform-aws-modules/vpc/aws", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := gitRef(c.src); got != c.ref {
			t.Errorf("gitRef(%q) = %q, want %q", c.src, got, c.ref)
		}
	}
}

func TestGitURL(t *testing.T) {
	cases := []struct{ src, url string }{
		{"git::https://example.com/r.git?ref=v1", "https://example.com/r.git"},
		{"git::https://example.com/r.git//sub?ref=v1", "https://example.com/r.git"},
		{"https://example.com/r.git", "https://example.com/r.git"},
		{"terraform-aws-modules/vpc/aws", ""},
		{"git::git@github.com:org/r.git", ""},
	}
	for _, c := range cases {
		if got := gitURL(c.src); got != c.url {
			t.Errorf("gitURL(%q) = %q, want %q", c.src, got, c.url)
		}
	}
}

func TestIsRegistryModule(t *testing.T) {
	if !isRegistryModule("terraform-aws-modules/vpc/aws") {
		t.Error("registry module not recognized")
	}
	for _, src := range []string{"", "git::https://example.com/r.git", "./local", "a/b", "a/b/c/d", "hashicorp/aws.git"} {
		if isRegistryModule(src) {
			t.Errorf("isRegistryModule(%q) = true, want false", src)
		}
	}
}

// --- SPDX ---

func TestWriteSPDX(t *testing.T) {
	deps := Collect([]terraform.Module{testModule()}, testResources())
	var buf bytes.Buffer
	if err := WriteSPDX(&buf, "my-infra", deps, fixedTime); err != nil {
		t.Fatalf("WriteSPDX: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SPDX output is not valid JSON: %v", err)
	}
	if doc["spdxVersion"] != "SPDX-2.3" {
		t.Errorf("spdxVersion = %v, want SPDX-2.3", doc["spdxVersion"])
	}
	if doc["dataLicense"] != "CC0-1.0" {
		t.Errorf("dataLicense = %v, want CC0-1.0", doc["dataLicense"])
	}
	if doc["SPDXID"] != "SPDXRef-DOCUMENT" {
		t.Errorf("SPDXID = %v", doc["SPDXID"])
	}
	if doc["name"] != "my-infra-sbom" {
		t.Errorf("name = %v, want my-infra-sbom", doc["name"])
	}
	ci, ok := doc["creationInfo"].(map[string]any)
	if !ok {
		t.Fatal("creationInfo missing")
	}
	if ci["created"] != "2026-11-25T18:00:00Z" {
		t.Errorf("created = %v", ci["created"])
	}
	creators, _ := ci["creators"].([]any)
	if len(creators) != 1 || !strings.HasPrefix(creators[0].(string), "Tool: aegis-") {
		t.Errorf("creators = %v, want one Tool: aegis-<version>", creators)
	}
	pkgs, ok := doc["packages"].([]any)
	if !ok || len(pkgs) != len(deps) {
		t.Fatalf("packages = %d, want %d", len(pkgs), len(deps))
	}
	// First package (sorted first: nginx) carries its purl and version.
	p0 := pkgs[0].(map[string]any)
	if p0["name"] != "nginx" || p0["versionInfo"] != "1.25" {
		t.Errorf("first package = %v %v, want nginx 1.25", p0["name"], p0["versionInfo"])
	}
	refs, _ := p0["externalRefs"].([]any)
	if len(refs) != 1 || refs[0].(map[string]any)["referenceLocator"] != "pkg:oci/nginx@1.25" {
		t.Errorf("nginx externalRefs = %v, want purl pkg:oci/nginx@1.25", refs)
	}
	rels, ok := doc["relationships"].([]any)
	if !ok || len(rels) != len(deps) {
		t.Fatalf("relationships = %d, want %d", len(rels), len(deps))
	}
	for _, r := range rels {
		rel := r.(map[string]any)
		if rel["spdxElementId"] != "SPDXRef-DOCUMENT" || rel["relationshipType"] != "DESCRIBES" {
			t.Errorf("bad relationship: %v", rel)
		}
	}
}

// Empty inventory still yields a valid SPDX document: zero packages,
// zero relationships, all required document fields present.
func TestWriteSPDXEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSPDX(&buf, "empty", nil, fixedTime); err != nil {
		t.Fatalf("WriteSPDX: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("SPDX output is not valid JSON: %v", err)
	}
	for _, k := range []string{"spdxVersion", "dataLicense", "SPDXID", "name", "documentNamespace", "creationInfo", "packages", "relationships"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("empty SPDX document missing %q", k)
		}
	}
	if pkgs := doc["packages"].([]any); len(pkgs) != 0 {
		t.Errorf("packages = %d, want 0", len(pkgs))
	}
}

// --- CycloneDX ---

func TestWriteCycloneDX(t *testing.T) {
	deps := Collect([]terraform.Module{testModule()}, testResources())
	var buf bytes.Buffer
	if err := WriteCycloneDX(&buf, "my-infra", deps, fixedTime); err != nil {
		t.Fatalf("WriteCycloneDX: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("CycloneDX output is not valid JSON: %v", err)
	}
	if doc["bomFormat"] != "CycloneDX" {
		t.Errorf("bomFormat = %v", doc["bomFormat"])
	}
	if doc["specVersion"] != "1.6" {
		t.Errorf("specVersion = %v, want 1.6", doc["specVersion"])
	}
	if doc["version"] != float64(1) {
		t.Errorf("version = %v, want 1", doc["version"])
	}
	sn, _ := doc["serialNumber"].(string)
	if !strings.HasPrefix(sn, "urn:uuid:") {
		t.Errorf("serialNumber = %v, want urn:uuid:...", sn)
	}
	md, ok := doc["metadata"].(map[string]any)
	if !ok {
		t.Fatal("metadata missing")
	}
	if md["timestamp"] != "2026-11-25T18:00:00Z" {
		t.Errorf("timestamp = %v", md["timestamp"])
	}
	tools, _ := md["tools"].([]any)
	if len(tools) != 1 || tools[0].(map[string]any)["name"] != "aegis" {
		t.Errorf("tools = %v, want one aegis tool", tools)
	}
	root, _ := md["component"].(map[string]any)
	if root["type"] != "application" || root["name"] != "my-infra" {
		t.Errorf("root component = %v, want application my-infra", root)
	}
	comps, ok := doc["components"].([]any)
	if !ok || len(comps) != len(deps) {
		t.Fatalf("components = %d, want %d", len(comps), len(deps))
	}
	// Container images are type "container", Terraform entries "library".
	types := map[string]string{}
	for _, c := range comps {
		cm := c.(map[string]any)
		types[cm["name"].(string)] = cm["type"].(string)
	}
	if types["nginx"] != "container" || types["hashicorp/aws"] != "library" {
		t.Errorf("component types = %v", types)
	}
	// The dependency graph links the root to every component.
	ds, ok := doc["dependencies"].([]any)
	if !ok || len(ds) != 1 {
		t.Fatalf("dependencies = %v, want one root entry", doc["dependencies"])
	}
	rootDep := ds[0].(map[string]any)
	if rootDep["ref"] != root["bom-ref"] {
		t.Errorf("root dep ref = %v, want %v", rootDep["ref"], root["bom-ref"])
	}
	depends, _ := rootDep["dependsOn"].([]any)
	if len(depends) != len(deps) {
		t.Errorf("dependsOn = %d entries, want %d", len(depends), len(deps))
	}
}

// Empty inventory still yields a valid CycloneDX document.
func TestWriteCycloneDXEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCycloneDX(&buf, "empty", nil, fixedTime); err != nil {
		t.Fatalf("WriteCycloneDX: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("CycloneDX output is not valid JSON: %v", err)
	}
	for _, k := range []string{"bomFormat", "specVersion", "serialNumber", "version", "metadata", "components", "dependencies"} {
		if _, ok := doc[k]; !ok {
			t.Errorf("empty CycloneDX document missing %q", k)
		}
	}
	if comps := doc["components"].([]any); len(comps) != 0 {
		t.Errorf("components = %d, want 0", len(comps))
	}
	ds := doc["dependencies"].([]any)
	if len(ds) != 1 {
		t.Fatalf("dependencies = %d, want 1 root entry", len(ds))
	}
	if _, has := ds[0].(map[string]any)["dependsOn"]; has {
		t.Error("empty root entry must not carry dependsOn")
	}
}

// A failing writer surfaces the error instead of a partial document.
func TestWritersPropagateErrors(t *testing.T) {
	deps := Collect([]terraform.Module{testModule()}, testResources())
	fw := &failWriter{}
	if err := WriteSPDX(fw, "x", deps, fixedTime); err == nil {
		t.Error("WriteSPDX with failing writer: want error, got nil")
	}
	fw = &failWriter{}
	if err := WriteCycloneDX(fw, "x", deps, fixedTime); err == nil {
		t.Error("WriteCycloneDX with failing writer: want error, got nil")
	}
}

type failWriter struct{}

func (*failWriter) Write(p []byte) (int, error) { return 0, errWriteFail }

type errString string

func (e errString) Error() string { return string(e) }

const errWriteFail = errString("write failed")

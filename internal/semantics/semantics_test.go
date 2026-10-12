package semantics_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"aegis/internal/adapter/terraform"
	"aegis/internal/ir"
	"aegis/internal/semantics"
)

func mustParseModule(t *testing.T, path, src string) terraform.Module {
	t.Helper()
	mod, diags, err := (&terraform.Adapter{}).ParseModule(path, []byte(src))
	if err != nil {
		t.Fatalf("ParseModule error: %v", err)
	}
	for _, d := range diags {
		if d.Level == "error" {
			t.Fatalf("parse diagnostic: %s", d.Message)
		}
	}
	return mod
}

func mustResolveOne(t *testing.T, src string) ir.Resource {
	t.Helper()
	mod := mustParseModule(t, "main.tf", src)
	scope := semantics.MergeModules([]terraform.Module{mod})
	out := scope.ResolveResources(mod.Resources)
	// Skip synthetic terraform_* resources (variable/locals/data/output
	// blocks emitted for secret-detection rules); tests target real resources.
	var real []ir.Resource
	for _, r := range out {
		if r.Provider != "terraform" {
			real = append(real, r)
		}
	}
	if len(real) != 1 {
		t.Fatalf("expected 1 real resource, got %d", len(real))
	}
	return real[0]
}

func attrStr(t *testing.T, r ir.Resource, name string) (string, bool) {
	t.Helper()
	v, ok := r.Attr(name)
	if !ok {
		t.Fatalf("resource %s has no attribute %q", r.Address(), name)
	}
	s, known := v.AsString()
	return s, known
}

func TestVarDefaultResolves(t *testing.T) {
	r := mustResolveOne(t, `
variable "region" { default = "us-east-1" }
resource "aws_s3_bucket" "data" { bucket = var.region }
`)
	got, known := attrStr(t, r, "bucket")
	if !known || got != "us-east-1" {
		t.Fatalf("bucket = %q known=%v, want %q known=true", got, known, "us-east-1")
	}
}

func TestVarWithoutDefaultStaysUnknown(t *testing.T) {
	r := mustResolveOne(t, `
variable "region" {}
resource "aws_s3_bucket" "data" { bucket = var.region }
`)
	v, _ := r.Attr("bucket")
	if v.Known {
		t.Fatal("bucket should stay unknown")
	}
	if !v.IsRef() || v.Ref != "var.region" {
		t.Fatalf("bucket ref = %q, want %q", v.Ref, "var.region")
	}
}

func TestUndeclaredVarStaysUnknown(t *testing.T) {
	r := mustResolveOne(t, `
resource "aws_s3_bucket" "data" { bucket = var.nope }
`)
	v, _ := r.Attr("bucket")
	if v.Known || v.Ref != "var.nope" {
		t.Fatalf("got known=%v ref=%q, want unknown ref var.nope", v.Known, v.Ref)
	}
}

func TestLocalChainResolves(t *testing.T) {
	r := mustResolveOne(t, `
variable "x" { default = "v" }
locals { b = var.x }
locals { a = local.b }
resource "aws_s3_bucket" "d" { bucket = local.a }
`)
	got, known := attrStr(t, r, "bucket")
	if !known || got != "v" {
		t.Fatalf("bucket = %q known=%v, want %q", got, known, "v")
	}
}

func TestVarDefaultReferencingLocal(t *testing.T) {
	r := mustResolveOne(t, `
locals { y = "deep" }
variable "x" { default = local.y }
resource "aws_s3_bucket" "d" { bucket = var.x }
`)
	got, known := attrStr(t, r, "bucket")
	if !known || got != "deep" {
		t.Fatalf("bucket = %q known=%v, want %q", got, known, "deep")
	}
}

func TestLocalCycleTerminatesUnknown(t *testing.T) {
	for _, src := range []string{
		`locals { a = local.b }
		  locals { b = local.a }
		  resource "aws_s3_bucket" "d" { bucket = local.a }`,
		`locals { a = local.a }
		  resource "aws_s3_bucket" "d" { bucket = local.a }`,
	} {
		r := mustResolveOne(t, src)
		v, _ := r.Attr("bucket")
		if v.Known {
			t.Fatalf("cyclic local should stay unknown (src: %q)", src)
		}
		if !v.IsRef() {
			t.Fatalf("cyclic local should keep its ref (src: %q)", src)
		}
	}
}

func TestNonLocalRefsKeptForM3(t *testing.T) {
	mod := mustParseModule(t, "main.tf", `
resource "aws_s3_bucket" "d" {
  bucket = data.aws_ami.ubuntu.id
  tags   = local.tags
}
resource "aws_security_group" "w" {
  name = each.key
}
`)
	scope := semantics.MergeModules([]terraform.Module{mod})
	out := scope.ResolveResources(mod.Resources)
	if len(out) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(out))
	}
	r := out[0]
	v, _ := r.Attr("bucket")
	if v.Known || v.Ref != "data.aws_ami.ubuntu.id" {
		t.Fatalf("data ref: known=%v ref=%q", v.Known, v.Ref)
	}
	v, _ = r.Attr("tags")
	if v.Known || v.Ref != "local.tags" {
		t.Fatalf("undeclared local ref: known=%v ref=%q", v.Known, v.Ref)
	}
}

func TestUnknownRefInsideContainersResolvesRest(t *testing.T) {
	span := ir.Span{File: "t.tf", StartLine: 1, StartCol: 1, EndLine: 1, EndCol: 2}
	res := ir.Resource{
		Type: "aws_x", Name: "y",
		Attributes: map[string]ir.Value{
			"list": {Raw: []ir.Value{
				{Known: false, Span: span, Ref: "var.missing"},
				{Raw: "static", Known: true, Span: span},
			}, Known: true, Span: span},
			"obj": {Raw: map[string]ir.Value{
				"a": {Known: false, Span: span, Ref: "var.missing"},
				"b": {Raw: "bval", Known: true, Span: span},
			}, Known: true, Span: span},
		},
	}
	scope := semantics.Scope{Variables: map[string]ir.Value{}, Locals: map[string]ir.Value{}}
	out := scope.ResolveResources([]ir.Resource{res})[0]

	list, ok := out.Attributes["list"].AsList()
	if !ok || len(list) != 2 {
		t.Fatalf("list not preserved: %+v", out.Attributes["list"])
	}
	if list[0].Known || list[0].Ref != "var.missing" {
		t.Fatalf("list[0] should keep ref, got %+v", list[0])
	}
	if s, known := list[1].AsString(); !known || s != "static" {
		t.Fatalf("list[1] = %q known=%v", s, known)
	}
	obj, ok := out.Attributes["obj"].AsMap()
	if !ok {
		t.Fatalf("obj not a map: %+v", out.Attributes["obj"])
	}
	if obj["a"].Known || obj["a"].Ref != "var.missing" {
		t.Fatalf("obj.a should keep ref, got %+v", obj["a"])
	}
	if s, known := obj["b"].AsString(); !known || s != "bval" {
		t.Fatalf("obj.b = %q known=%v", s, known)
	}
}

func TestMergeModulesLaterFileWins(t *testing.T) {
	a := mustParseModule(t, "a.tf", `variable "x" { default = "from-a" }`)
	b := mustParseModule(t, "b.tf", `variable "x" { default = "from-b" }`)
	scope := semantics.MergeModules([]terraform.Module{a, b})
	got, ok := scope.Variables["x"].AsString()
	if !ok || got != "from-b" {
		t.Fatalf("x = %q known=%v, want from-b", got, ok)
	}
	// Deterministic regardless of input order.
	scope2 := semantics.MergeModules([]terraform.Module{b, a})
	got2, _ := scope2.Variables["x"].AsString()
	if got2 != got {
		t.Fatalf("non-deterministic merge: %q vs %q", got, got2)
	}
}

func TestResolveIsDeterministic(t *testing.T) {
	mod := mustParseModule(t, "main.tf", `
variable "region" { default = "us-east-1" }
variable "open" {}
locals {
  tags = var.region
  cyc  = local.cyc
}
resource "aws_s3_bucket" "data" {
  bucket = var.region
  acl    = var.open
  tags   = local.tags
}
resource "aws_s3_bucket" "other" { bucket = local.cyc }
`)
	scope := semantics.MergeModules([]terraform.Module{mod})
	first := scope.ResolveResources(mod.Resources)
	second := scope.ResolveResources(mod.Resources)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("ResolveResources is not deterministic")
	}
}

// --- module expansion ---

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func parseDir(t *testing.T, dir string) []terraform.Module {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var mods []terraform.Module
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".tf" {
			continue
		}
		p := filepath.Join(dir, e.Name())
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		mod, _, err := (&terraform.Adapter{}).ParseModule(p, src)
		if err != nil {
			t.Fatal(err)
		}
		mods = append(mods, mod)
	}
	return mods
}

func TestModuleExpansionBindsInputs(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.tf"), `
variable "cidr" { default = "10.0.0.0/16" }
module "vpc" {
  source     = "./modules/vpc"
  cidr_block = var.cidr
}
`)
	writeFile(t, filepath.Join(root, "modules/vpc/main.tf"), `
variable "cidr_block" { default = "0.0.0.0/0" }
resource "aws_vpc" "main" { cidr_block = var.cidr_block }
`)
	mods := parseDir(t, root)
	res, diags := semantics.ExpandModules(root, mods, &terraform.Adapter{}, 0)
	for _, d := range diags {
		if d.Level == "error" {
			t.Fatalf("diagnostic: %s", d.Message)
		}
	}
	// Skip synthetic terraform_* resources emitted for secret detection.
	var real []ir.Resource
	for _, r := range res {
		if r.Provider != "terraform" {
			real = append(real, r)
		}
	}
	if len(real) != 1 {
		t.Fatalf("expected 1 expanded resource, got %d", len(real))
	}
	if real[0].Name != "module.vpc.main" {
		t.Fatalf("name = %q, want module.vpc.main", real[0].Name)
	}
	got, known := attrStr(t, real[0], "cidr_block")
	if !known || got != "10.0.0.0/16" {
		t.Fatalf("cidr_block = %q known=%v, want input-bound 10.0.0.0/16", got, known)
	}
}

func TestModuleDefaultUsedWhenNoInput(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.tf"), `
module "vpc" { source = "./modules/vpc" }
`)
	writeFile(t, filepath.Join(root, "modules/vpc/main.tf"), `
variable "cidr_block" { default = "10.1.0.0/16" }
resource "aws_vpc" "main" { cidr_block = var.cidr_block }
`)
	mods := parseDir(t, root)
	res, _ := semantics.ExpandModules(root, mods, &terraform.Adapter{}, 0)
	var real []ir.Resource
	for _, r := range res {
		if r.Provider != "terraform" {
			real = append(real, r)
		}
	}
	if len(real) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(real))
	}
	got, known := attrStr(t, real[0], "cidr_block")
	if !known || got != "10.1.0.0/16" {
		t.Fatalf("cidr_block = %q known=%v, want declared default", got, known)
	}
}

func TestRemoteModuleSkippedWithDiagnostic(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.tf"), `
module "consul" {
  source  = "hashicorp/consul/aws"
  version = "0.1.0"
}
`)
	mods := parseDir(t, root)
	res, diags := semantics.ExpandModules(root, mods, &terraform.Adapter{}, 0)
	if len(res) != 0 {
		t.Fatalf("expected 0 resources, got %d", len(res))
	}
	found := false
	for _, d := range diags {
		if strings.Contains(d.Message, "remote") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a remote-source diagnostic, got %+v", diags)
	}
}

func TestNestedModulesRespectMaxDepth(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.tf"), `module "l1" { source = "./l1" }`)
	writeFile(t, filepath.Join(root, "l1/main.tf"), `
resource "aws_x" "one" { v = "1" }
module "l2" { source = "./l2" }
`)
	writeFile(t, filepath.Join(root, "l1/l2/main.tf"), `
resource "aws_x" "two" { v = "2" }
module "l3" { source = "./l3" }
`)
	writeFile(t, filepath.Join(root, "l1/l2/l3/main.tf"), `
resource "aws_x" "three" { v = "3" }
`)
	mods := parseDir(t, root)
	res, _ := semantics.ExpandModules(root, mods, &terraform.Adapter{}, 2)
	names := map[string]bool{}
	for _, r := range res {
		names[r.Name] = true
	}
	if !names["module.l1.one"] || !names["module.l1.module.l2.two"] {
		t.Fatalf("depth 1-2 resources missing: %v", names)
	}
	if names["module.l1.module.l2.module.l3.three"] {
		t.Fatalf("depth-3 resource should have been skipped: %v", names)
	}
}

func TestModuleCycleTerminates(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.tf"), `module "a" { source = "./a" }`)
	writeFile(t, filepath.Join(root, "a/main.tf"), `
resource "aws_x" "in_a" { v = "x" }
module "back" { source = ".." }
`)
	mods := parseDir(t, root)
	res, diags := semantics.ExpandModules(root, mods, &terraform.Adapter{}, 4)
	if len(res) != 1 || res[0].Name != "module.a.in_a" {
		t.Fatalf("expected the one cyclic resource, got %+v", res)
	}
	found := false
	for _, d := range diags {
		if strings.Contains(d.Message, "cycle") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a cycle diagnostic, got %+v", diags)
	}
}

func TestExpandModulesDeterministic(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "main.tf"), `
module "b" { source = "./mods/b" }
module "a" { source = "./mods/a" }
`)
	writeFile(t, filepath.Join(root, "mods/a/main.tf"), `resource "aws_x" "ra" { v = "a" }`)
	writeFile(t, filepath.Join(root, "mods/b/main.tf"), `resource "aws_x" "rb" { v = "b" }`)
	mods := parseDir(t, root)
	r1, d1 := semantics.ExpandModules(root, mods, &terraform.Adapter{}, 0)
	r2, d2 := semantics.ExpandModules(root, mods, &terraform.Adapter{}, 0)
	if !reflect.DeepEqual(r1, r2) || !reflect.DeepEqual(d1, d2) {
		t.Fatal("ExpandModules is not deterministic")
	}
	if len(r1) != 2 || r1[0].Name != "module.a.ra" || r1[1].Name != "module.b.rb" {
		t.Fatalf("unexpected order/names: %+v", r1)
	}
}

package terraform

import (
	"fmt"
	"strings"
	"testing"

	"aegis/internal/ir"
)

var _ ir.Adapter = Adapter{}
var _ ir.Adapter = New()

func TestName(t *testing.T) {
	if got := (Adapter{}).Name(); got != "terraform" {
		t.Fatalf("Name() = %q, want terraform", got)
	}
	if got := New().Name(); got != "terraform" {
		t.Fatalf("New().Name() = %q, want terraform", got)
	}
}

func TestHandles(t *testing.T) {
	a := Adapter{}
	cases := []struct {
		path string
		want bool
	}{
		{"main.tf", true},
		{"a/b/c.tf", true},
		{"MAIN.TF", true},
		{"./relative.tf", true},
		{"vars.tfvars", false}, // M1: tfvars explicitly excluded
		{"terraform.tfvars", false},
		{"VARS.TFVARS", false},
		{"notes.txt", false},
		{"main.tf.json", false},
		{"tf", false},
		{"", false},
	}
	for _, c := range cases {
		if got := a.Handles(c.path); got != c.want {
			t.Errorf("Handles(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

const simpleHCL = `resource "aws_s3_bucket" "app_data" {
  bucket = "my-bucket"
  acl = "private"
  versioning = true
  retention_days = 30
  price = 3.14
  tags = {
    Name = "app"
    Env = "prod"
  }
  allowed_ips = ["10.0.0.0/8", "192.168.0.0/16"]
}
`

func mustParse(t *testing.T, path, src string) ([]ir.Resource, []ir.Diagnostic) {
	t.Helper()
	res, diags, err := (Adapter{}).Parse(path, []byte(src))
	if err != nil {
		t.Fatalf("Parse returned hard error: %v", err)
	}
	return res, diags
}

func TestParseSimpleResource(t *testing.T) {
	res, diags := mustParse(t, "main.tf", simpleHCL)
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	if len(res) != 1 {
		t.Fatalf("got %d resources, want 1", len(res))
	}
	r := res[0]
	if r.Type != "aws_s3_bucket" || r.Name != "app_data" {
		t.Errorf("identity = %s %s, want aws_s3_bucket app_data", r.Type, r.Name)
	}
	if r.Provider != "aws" {
		t.Errorf("Provider = %q, want aws", r.Provider)
	}
	if r.Address() != "aws_s3_bucket.app_data" {
		t.Errorf("Address() = %q", r.Address())
	}
	// Block span: line 1 -> line 12.
	if r.Span.StartLine != 1 || r.Span.EndLine != 12 {
		t.Errorf("block span lines = %d-%d, want 1-12", r.Span.StartLine, r.Span.EndLine)
	}
	if r.Span.File != "main.tf" {
		t.Errorf("span file = %q", r.Span.File)
	}

	strAttr := func(name, want string) {
		t.Helper()
		v, ok := r.Attr(name)
		if !ok {
			t.Fatalf("missing attribute %q", name)
		}
		s, ok := v.AsString()
		if !ok || s != want {
			t.Errorf("%s = (%v,%v), want (%q,true)", name, v.Raw, ok, want)
		}
	}
	strAttr("bucket", "my-bucket")
	strAttr("acl", "private")

	if b, ok := attr(t, r, "versioning").AsBool(); !ok || !b {
		t.Errorf("versioning = %v, want (true,true)", r.Attributes["versioning"])
	}
	if f, ok := asFloat(r, "retention_days"); !ok || f != 30 {
		t.Errorf("retention_days = %v, want 30", r.Attributes["retention_days"].Raw)
	}
	if f, ok := asFloat(r, "price"); !ok || f != 3.14 {
		t.Errorf("price = %v, want 3.14", r.Attributes["price"].Raw)
	}

	tags, ok := attr(t, r, "tags").AsMap()
	if !ok {
		t.Fatalf("tags not a known map: %+v", r.Attributes["tags"])
	}
	if s, ok := tags["Name"].AsString(); !ok || s != "app" {
		t.Errorf("tags.Name = %v", tags["Name"].Raw)
	}
	if s, ok := tags["Env"].AsString(); !ok || s != "prod" {
		t.Errorf("tags.Env = %v", tags["Env"])
	}

	ips, ok := attr(t, r, "allowed_ips").AsList()
	if !ok || len(ips) != 2 {
		t.Fatalf("allowed_ips not a known 2-list: %+v", r.Attributes["allowed_ips"])
	}
	if s, _ := ips[0].AsString(); s != "10.0.0.0/8" {
		t.Errorf("allowed_ips[0] = %q", s)
	}

	// Attribute span: `bucket` value starts line 2, col 12.
	bv := attr(t, r, "bucket")
	if bv.Span.StartLine != 2 || bv.Span.StartCol != 12 {
		t.Errorf("bucket span = %v, want line 2 col 12", bv.Span)
	}
}

// attr fetches a required attribute or fails the test.
func attr(t *testing.T, r ir.Resource, name string) ir.Value {
	t.Helper()
	v, ok := r.Attr(name)
	if !ok {
		t.Fatalf("missing attribute %q", name)
	}
	return v
}

func asFloat(r ir.Resource, name string) (float64, bool) {
	v, ok := r.Attr(name)
	if !ok || !v.Known {
		return 0, false
	}
	f, ok := v.Raw.(float64)
	return f, ok
}

const sgHCL = `resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port = 80
    to_port = 80
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port = 443
    to_port = 443
    protocol = "tcp"
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
  }
}
`

func TestParseNestedBlocks(t *testing.T) {
	res, _ := mustParse(t, "sg.tf", sgHCL)
	if len(res) != 1 {
		t.Fatalf("got %d resources, want 1", len(res))
	}
	r := res[0]

	ing, ok := attr(t, r, "ingress").AsList()
	if !ok || len(ing) != 2 {
		t.Fatalf("ingress: got %+v, want 2-element known list", r.Attributes["ingress"])
	}
	first, ok := ing[0].AsMap()
	if !ok {
		t.Fatalf("ingress[0] not a map: %+v", ing[0].Raw)
	}
	if f, ok := first["from_port"].Raw.(float64); !ok || f != 80 || !first["from_port"].Known {
		t.Errorf("ingress[0].from_port = %+v", first["from_port"])
	}
	if s, ok := first["protocol"].AsString(); !ok || s != "tcp" {
		t.Errorf("ingress[0].protocol = %+v", first["protocol"])
	}
	blocks, ok := first["cidr_blocks"].AsList()
	if !ok || len(blocks) != 1 {
		t.Fatalf("ingress[0].cidr_blocks = %+v", first["cidr_blocks"])
	}
	second, _ := ing[1].AsMap()
	if f, _ := second["from_port"].Raw.(float64); f != 443 {
		t.Errorf("ingress[1].from_port = %v, want 443", second["from_port"].Raw)
	}

	eg, ok := attr(t, r, "egress").AsList()
	if !ok || len(eg) != 1 {
		t.Fatalf("egress: got %+v, want 1-element known list", r.Attributes["egress"])
	}
	// Nested block spans are recorded.
	if ing[0].Span.StartLine == 0 || ing[1].Span.StartLine <= ing[0].Span.StartLine {
		t.Errorf("nested block spans not ordered: %+v %+v", ing[0].Span, ing[1].Span)
	}
}

const unknownHCL = `resource "aws_instance" "app" {
  ami = data.aws_ami.ubuntu.id
  instance_type = var.instance_type
  subnet_id = each.key
  idx = count.index
  nm = local.name
  payload = jsonencode({ a = "b" })
  flag = var.enabled ? "yes" : "no"
  mixed = ["a", var.x]
  sum = 1 + 2
  static_list = ["a", "b"]
  static_num = -5
  static_str = "plain"
}
`

func TestParseUnknownValues(t *testing.T) {
	res, diags := mustParse(t, "u.tf", unknownHCL)
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	if len(res) != 1 {
		t.Fatalf("got %d resources, want 1", len(res))
	}
	r := res[0]
	for _, name := range []string{"ami", "instance_type", "subnet_id", "idx", "nm", "flag", "mixed", "sum"} {
		v, ok := r.Attr(name)
		if !ok {
			t.Fatalf("missing attribute %q", name)
		}
		if v.Known {
			t.Errorf("%s should be Unknown, got %+v", name, v.Raw)
		}
	}
	// M3: jsonencode() over static args evaluates to a known JSON string.
	if s, ok := attr(t, r, "payload").AsString(); !ok || s != `{"a":"b"}` {
		t.Errorf("payload should be known JSON {\"a\":\"b\"}: %+v", r.Attributes["payload"])
	}
	// Static values stay known.
	if l, ok := attr(t, r, "static_list").AsList(); !ok || len(l) != 2 {
		t.Errorf("static_list should be known 2-list: %+v", r.Attributes["static_list"])
	}
	if f, ok := asFloat(r, "static_num"); !ok || f != -5 {
		t.Errorf("static_num should be known -5: %+v", r.Attributes["static_num"])
	}
	if s, ok := attr(t, r, "static_str").AsString(); !ok || s != "plain" {
		t.Errorf("static_str should be known: %+v", r.Attributes["static_str"])
	}
}

func TestParseSyntaxError(t *testing.T) {
	// Balanced braces but an invalid expression: a syntax error is still a
	// diagnostic, not a hard error. (Truncated/unbalanced input is rejected
	// by PreValidate instead — see TestParseTruncatedBlockIsHardError.)
	broken := "resource \"aws_s3_bucket\" \"broken\" {\n  bucket =\n}\n"
	res, diags, err := (Adapter{}).Parse("broken.tf", []byte(broken))
	if err != nil {
		t.Fatalf("syntax error should be a diagnostic, not a hard error: %v", err)
	}
	found := false
	for _, d := range diags {
		if d.Level == "error" {
			found = true
			if d.Span.File != "broken.tf" || d.Span.StartLine == 0 {
				t.Errorf("error diagnostic has bad span: %+v", d.Span)
			}
		}
	}
	if !found {
		t.Fatalf("expected at least one error diagnostic, got %+v", diags)
	}
	_ = res // partial resources may or may not be present; diagnostics are the contract
}

func TestParseEmpty(t *testing.T) {
	for _, src := range []string{"", "\n", "# just a comment\n", "  \n\t\n"} {
		res, diags, err := (Adapter{}).Parse("empty.tf", []byte(src))
		if err != nil {
			t.Fatalf("empty input: hard error %v", err)
		}
		if len(res) != 0 || len(diags) != 0 {
			t.Fatalf("empty input: got %d resources, %d diagnostics", len(res), len(diags))
		}
	}
}

const mixedBlocksHCL = `variable "foo" {
  default = "bar"
}

data "aws_ami" "ubuntu" {
  most_recent = true
}

output "id" {
  value = "x"
}

terraform {
  required_version = ">= 1.0"
}

provider "aws" {
  region = "eu-west-1"
}

locals {
  name = "x"
}

module "vpc" {
  source = "./vpc"
}

resource "aws_s3_bucket" "only" {
  bucket = "b"
}

resource "lonely" {
  x = 1
}
`

func TestNonResourceBlocksIgnored(t *testing.T) {
	res, diags := mustParse(t, "mixed.tf", mixedBlocksHCL)
	// Synthetic resources are now intentionally emitted for supply-chain
	// and terraform-security rules. Parse returns mod.Resources:
	// terraform_data (data blocks), terraform_config, terraform_provider.
	// variable/locals/output pseudo-resources live in
	// Module.SyntheticResources (see TestSyntheticResourcesSplit).
	// Only the module call and malformed resource are skipped.
	if len(res) != 4 {
		t.Fatalf("got %d resources, want 4 (1 real + 3 synthetic)", len(res))
	}
	found := map[string]bool{}
	for _, r := range res {
		found[r.Type+"."+r.Name] = true
	}
	for _, want := range []string{
		"aws_s3_bucket.only",
		"terraform_data.aws_ami.ubuntu",
		"terraform_config.terraform",
		"terraform_provider.aws",
	} {
		if !found[want] {
			t.Errorf("missing expected resource %q (got %v)", want, found)
		}
	}
	// Malformed resource label count -> warning diagnostic, skipped.
	foundWarn := false
	for _, d := range diags {
		if d.Level == "warning" {
			foundWarn = true
		}
		if d.Level == "error" {
			t.Errorf("unexpected error diagnostic: %+v", d)
		}
	}
	if !foundWarn {
		t.Errorf("expected a warning for the 1-label resource block, got %+v", diags)
	}
}

func TestParseHeredocAndNestedObject(t *testing.T) {
	src := "resource \"aws_iam_policy\" \"p\" {\n  policy = <<EOT\n{\n  \"Version\": \"2012-10-17\"\n}\nEOT\n  config = {\n    nested = {\n      deep = true\n    }\n  }\n}\n"
	res, _ := mustParse(t, "h.tf", src)
	if len(res) != 1 {
		t.Fatalf("got %d resources", len(res))
	}
	pol, ok := attr(t, res[0], "policy").AsString()
	if !ok || !strings.Contains(pol, "Version") {
		t.Errorf("heredoc should be a known string: %+v", res[0].Attributes["policy"])
	}
	cfg, ok := attr(t, res[0], "config").AsMap()
	if !ok {
		t.Fatalf("config not a known map")
	}
	nested, ok := cfg["nested"].AsMap()
	if !ok {
		t.Fatalf("config.nested not a known map")
	}
	if b, ok := nested["deep"].AsBool(); !ok || !b {
		t.Errorf("config.nested.deep = %+v", nested["deep"])
	}
}

func TestProviderInference(t *testing.T) {
	cases := map[string]string{
		"aws_s3_bucket":           "aws",
		"azurerm_resource_group":  "azurerm",
		"google_compute_instance": "google",
		"kubernetes_deployment":   "kubernetes",
		"random_pet":              "random",
		"terraform_data":          "terraform",
	}
	for typ, want := range cases {
		if got := providerOf(typ); got != want {
			t.Errorf("providerOf(%q) = %q, want %q", typ, got, want)
		}
	}
}

// TestNoPanicOnHostileInput feeds pathological inputs; the contract is
// "never crash the scanner" — every case must return without panicking.
func TestNoPanicOnHostileInput(t *testing.T) {
	inputs := []string{
		"resource",
		"resource \"\" \"\" {}",
		"resource \"a\" \"b\" { x = }",
		"resource \"a\" \"b\" { x = [1, }",
		"resource \"a\" \"b\" { x = { a = } }",
		"resource \"a\" \"b\" { x = <<EOT\nunterminated",
		"resource \"a\" \"b\" { dynamic \"x\" { for_each = var.y content { z = 1 } } }",
		"\x00\x01\x02",
		"resource \"a\" \"b\" {\n" + strings.Repeat("x", 100000) + "\n}",
		"resource \"a\" \"b\" { x = \"${var.a}${var.b}${var.c}\" }",
		"resource \"a\" \"b\" { x = - -5 }",
		"resource \"a\" \"b\" { x = !true }",
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Parse panicked on hostile input: %v", r)
		}
	}()
	for i, in := range inputs {
		_, _, _ = (Adapter{}).Parse("hostile.tf", []byte(in))
		_ = i
	}
}

func TestParseCompositeRefPreservation(t *testing.T) {
	const src = `resource "aws_security_group" "web" {
  ingress {
    cidr_blocks = [var.cidr, "10.0.0.0/8"]
  }
  tags = { Env = var.env, Team = "core" }
  mixed_bad = ["a", var.x, jsonencode({b = "c"})]
}
`
	res, _ := mustParse(t, "c.tf", src)
	r := res[0]

	// List with a ref element: Unknown container, ref preserved inside.
	ing, ok := attr(t, r, "ingress").AsList()
	if !ok || len(ing) != 1 {
		t.Fatalf("ingress: %+v", r.Attributes["ingress"])
	}
	blk, ok := ing[0].AsMap()
	if !ok {
		t.Fatalf("ingress[0] not a map")
	}
	if _, ok := blk["cidr_blocks"].AsList(); ok {
		t.Fatalf("cidr_blocks should be Unknown (has ref child), got known list")
	}
	raw, _ := blk["cidr_blocks"].Raw.([]ir.Value)
	if len(raw) != 2 {
		t.Fatalf("cidr_blocks raw len = %d, want 2", len(raw))
	}
	if raw[0].Ref != "var.cidr" {
		t.Errorf("cidr_blocks[0].Ref = %q, want var.cidr", raw[0].Ref)
	}
	if s, _ := raw[1].AsString(); s != "10.0.0.0/8" {
		t.Errorf("cidr_blocks[1] = %q", s)
	}

	// Object with ref values: same treatment.
	tagsRaw, _ := r.Attributes["tags"].Raw.(map[string]ir.Value)
	if tagsRaw["Env"].Ref != "var.env" {
		t.Errorf("tags.Env.Ref = %q, want var.env", tagsRaw["Env"].Ref)
	}
	if s, _ := tagsRaw["Team"].AsString(); s != "core" {
		t.Errorf("tags.Team = %q", s)
	}
	if r.Attributes["tags"].Known {
		t.Errorf("tags should be Unknown (has ref child)")
	}

	// Composite containing a non-ref, non-static element: plain Unknown.
	mb := r.Attributes["mixed_bad"]
	if mb.Known || mb.Raw != nil {
		t.Errorf("mixed_bad should be plain Unknown, got %+v", mb)
	}
}

func TestParseModuleProviderReqs(t *testing.T) {
	src := `
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source = "hashicorp/random"
    }
    dynamic = {
      source  = "hashicorp/dynamic"
      version = var.provider_version
    }
  }
}

resource "aws_s3_bucket" "b" {
  bucket = "x"
}
`
	mod, diags, err := (Adapter{}).ParseModule("versions.tf", []byte(src))
	if err != nil {
		t.Fatalf("ParseModule: %v", err)
	}
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	if len(mod.ProviderReqs) != 3 {
		t.Fatalf("got %d provider reqs, want 3: %+v", len(mod.ProviderReqs), mod.ProviderReqs)
	}
	// Sorted by name: aws, dynamic, random.
	if mod.ProviderReqs[0].Name != "aws" || mod.ProviderReqs[1].Name != "dynamic" || mod.ProviderReqs[2].Name != "random" {
		t.Errorf("reqs not sorted by name: %+v", mod.ProviderReqs)
	}
	aws := mod.ProviderReqs[0]
	if aws.Source != "hashicorp/aws" || aws.Version != "~> 5.0" {
		t.Errorf("aws req wrong: %+v", aws)
	}
	if aws.Span.File != "versions.tf" || aws.Span.StartLine == 0 {
		t.Errorf("aws req missing span: %+v", aws.Span)
	}
	random := mod.ProviderReqs[2]
	if random.Source != "hashicorp/random" || random.Version != "" {
		t.Errorf("random req wrong (absent version -> empty): %+v", random)
	}
	dynamic := mod.ProviderReqs[1]
	if dynamic.Source != "hashicorp/dynamic" || dynamic.Version != "" {
		t.Errorf("dynamic req wrong (unknown version -> empty): %+v", dynamic)
	}
	// Resources still parsed alongside: the S3 bucket plus the synthetic
	// terraform_config resource for the terraform block.
	if len(mod.Resources) != 2 {
		t.Errorf("got %d resources, want 2", len(mod.Resources))
	}
}

func TestParseModuleNoTerraformBlock(t *testing.T) {
	mod, _, err := (Adapter{}).ParseModule("main.tf", []byte(`resource "aws_s3_bucket" "b" { bucket = "x" }`))
	if err != nil {
		t.Fatalf("ParseModule: %v", err)
	}
	if len(mod.ProviderReqs) != 0 {
		t.Errorf("expected no provider reqs, got %+v", mod.ProviderReqs)
	}
}

func TestDynamicBlockPreserved(t *testing.T) {
	src := `resource "aws_security_group" "web" {
  dynamic "ingress" {
    for_each = var.ports
    content {
      from_port = ingress.value
    }
  }
}
`
	mod, _, err := Adapter{}.ParseModule("t.tf", []byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mod.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(mod.Resources))
	}
	r := mod.Resources[0]
	dyn, ok := r.Attributes["dynamic"].AsList()
	if !ok || len(dyn) != 1 {
		t.Fatalf("expected dynamic block preserved, got %+v", r.Attributes["dynamic"])
	}
	m, ok := dyn[0].Raw.(map[string]ir.Value)
	if !ok {
		t.Fatalf("dynamic element not a map: %+v", dyn[0].Raw)
	}
	label, ok := m["__label"].AsString()
	if !ok || label != "ingress" {
		t.Fatalf("expected __label=ingress, got %+v", m["__label"])
	}
	// No adapter-level warning: the semantics expansion pass owns the
	// "cannot expand" diagnostic. Verify none is emitted here.
	_, diags, err := Adapter{}.ParseModule("t.tf", []byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, d := range diags {
		if strings.Contains(d.Message, "dynamic") {
			t.Fatalf("unexpected dynamic diagnostic at adapter level: %+v", d)
		}
	}
}

func TestUnknownCountWarns(t *testing.T) {
	src := `resource "aws_instance" "web" {
  count         = var.instance_count
  ami           = "ami-123"
  instance_type = "t3.micro"
}
`
	_, diags, err := Adapter{}.ParseModule("t.tf", []byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, d := range diags {
		if d.Level == "warning" && d.Span.StartLine == 2 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a warning diagnostic for unknown count, got %+v", diags)
	}
}

func TestStaticCountNoWarning(t *testing.T) {
	src := `resource "aws_instance" "web" {
  count         = 2
  ami           = "ami-123"
  instance_type = "t3.micro"
}
`
	_, diags, err := Adapter{}.ParseModule("t.tf", []byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(diags) != 0 {
		t.Fatalf("static count must not warn, got %+v", diags)
	}
}

// TestLenientMissingCommaRecovery: single-line object constructors without
// comma separators (e.g. { Effect = "Allow" Action = "s3:GetObject" }) are
// recovered by inserting commas at the parser-reported positions. Without
// recovery, the parser silently drops the remaining items, mangling
// jsonencode() policy documents.
func TestLenientMissingCommaRecovery(t *testing.T) {
	src := `resource "aws_iam_policy" "v" {
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow" Action = "iam:PassRole" Resource = "*" },
      { Effect = "Allow" Action = "ec2:RunInstances" Resource = "*" }
    ]
  })
}
`
	mod, diags, err := Adapter{}.ParseModule("t.tf", []byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(diags) != 0 {
		t.Fatalf("recovered parse must be clean, got %+v", diags)
	}
	if len(mod.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(mod.Resources))
	}
	v := mod.Resources[0].Attributes["policy"]
	s, ok := v.Raw.(string)
	if !ok || !v.Known {
		t.Fatalf("policy must be a known string, got known=%v type=%T", v.Known, v.Raw)
	}
	for _, want := range []string{"iam:PassRole", "ec2:RunInstances"} {
		if !strings.Contains(s, want) {
			t.Errorf("recovered policy missing %q: %s", want, s)
		}
	}
}

// TestLenientSameLineRecovery: multiple attributes on one line inside a
// block body (single-line blocks and multi-attribute lines in multi-line
// blocks) are recovered by inserting newlines at the parser-reported
// positions. Without recovery the parser keeps only the first attribute
// per line, so rules would see e.g. an S3 bucket with no acl or an RDS
// instance with no storage_encrypted.
func TestLenientSameLineRecovery(t *testing.T) {
	cases := []struct {
		name  string
		src   string
		check func(t *testing.T, mod Module)
	}{
		{
			name: "single-line resource block",
			src: `resource "aws_s3_bucket" "pub" { bucket = "c1" acl = "public-read" }
`,
			check: func(t *testing.T, mod Module) {
				if len(mod.Resources) != 1 {
					t.Fatalf("expected 1 resource, got %d", len(mod.Resources))
				}
				acl, ok := mod.Resources[0].Attributes["acl"].AsString()
				if !ok || acl != "public-read" {
					t.Errorf("acl = %q, want public-read", acl)
				}
			},
		},
		{
			name: "single-line block with three attributes",
			src: `resource "aws_ebs_volume" "enc" { availability_zone = "us-east-1a" size = 10 encrypted = true }
`,
			check: func(t *testing.T, mod Module) {
				enc, ok := mod.Resources[0].Attributes["encrypted"].AsBool()
				if !ok || !enc {
					t.Errorf("encrypted = %v (known=%v), want true", enc, ok)
				}
				size, ok := mod.Resources[0].Attributes["size"].AsString()
				_ = size
				if v, ok2 := mod.Resources[0].Attributes["size"]; !ok2 || !v.Known {
					t.Errorf("size missing or unknown")
				}
			},
		},
		{
			name: "multi-attribute lines in a multi-line block",
			src: `resource "aws_db_instance" "privdb" {
  engine = "postgres" instance_class = "db.t3.micro"
  publicly_accessible = false storage_encrypted = true deletion_protection = true
}
`,
			check: func(t *testing.T, mod Module) {
				for attr, want := range map[string]bool{
					"storage_encrypted": true, "deletion_protection": true,
				} {
					got, ok := mod.Resources[0].Attributes[attr].AsBool()
					if !ok || got != want {
						t.Errorf("%s = %v (known=%v), want %v", attr, got, ok, want)
					}
				}
				pub, ok := mod.Resources[0].Attributes["publicly_accessible"].AsBool()
				if !ok || pub {
					t.Errorf("publicly_accessible = %v, want false", pub)
				}
			},
		},
		{
			name: "single-line nested block",
			src: `resource "google_compute_firewall" "openfw" {
  name = "fw1" network = "default"
  allow { protocol = "tcp" ports = ["22"] }
  source_ranges = ["0.0.0.0/0"]
}
`,
			check: func(t *testing.T, mod Module) {
				allow, ok := mod.Resources[0].Attributes["allow"].AsList()
				if !ok || len(allow) != 1 {
					t.Fatalf("allow block missing: %v", mod.Resources[0].Attributes["allow"])
				}
				m, _ := allow[0].AsMap()
				ports, ok := m["ports"].AsList()
				if !ok || len(ports) != 1 {
					t.Errorf("ports missing from nested single-line block: %+v", m)
				}
				network, ok := mod.Resources[0].Attributes["network"].AsString()
				if !ok || network != "default" {
					t.Errorf("network = %q, want default", network)
				}
			},
		},
		{
			name: "same-line body plus comma-less jsonencode object",
			src: `resource "aws_iam_policy" "admin" {
  policy = jsonencode({ Statement = [{ Effect = "Allow" Action = "*" Resource = "*" }] })
}
`,
			check: func(t *testing.T, mod Module) {
				pol, ok := mod.Resources[0].Attributes["policy"].AsString()
				if !ok {
					t.Fatalf("policy not a known string")
				}
				for _, want := range []string{`"Action":"*"`, `"Resource":"*"`} {
					if !strings.Contains(pol, want) {
						t.Errorf("policy missing %s: %s", want, pol)
					}
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mod, diags, err := Adapter{}.ParseModule("t.tf", []byte(tc.src))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(diags) != 0 {
				t.Fatalf("recovered parse must be clean, got %+v", diags)
			}
			tc.check(t, mod)
		})
	}
}

// TestLenientSingleVsMultiLineEquivalence: the same resource written
// single-line and multi-line must yield identical attribute sets.
func TestLenientSingleVsMultiLineEquivalence(t *testing.T) {
	single := `resource "azurerm_storage_account" "s" { name = "st" resource_group_name = "rg" location = "westeurope" account_tier = "Standard" account_replication_type = "GRS" allow_blob_public_access = false min_tls_version = "TLS1_2" }
`
	multi := `resource "azurerm_storage_account" "s" {
  name = "st"
  resource_group_name = "rg"
  location = "westeurope"
  account_tier = "Standard"
  account_replication_type = "GRS"
  allow_blob_public_access = false
  min_tls_version = "TLS1_2"
}
`
	a, _, err := Adapter{}.ParseModule("a.tf", []byte(single))
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := Adapter{}.ParseModule("b.tf", []byte(multi))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Resources) != 1 || len(b.Resources) != 1 {
		t.Fatalf("expected 1 resource each, got %d / %d", len(a.Resources), len(b.Resources))
	}
	if len(a.Resources[0].Attributes) != len(b.Resources[0].Attributes) {
		t.Fatalf("attribute count differs: single-line %d vs multi-line %d",
			len(a.Resources[0].Attributes), len(b.Resources[0].Attributes))
	}
	for k, va := range a.Resources[0].Attributes {
		vb, ok := b.Resources[0].Attributes[k]
		if !ok {
			t.Errorf("multi-line form missing attribute %q", k)
			continue
		}
		if va.Known != vb.Known || fmt.Sprint(va.Raw) != fmt.Sprint(vb.Raw) {
			t.Errorf("attribute %q differs: single-line %#v vs multi-line %#v", k, va.Raw, vb.Raw)
		}
	}
}

// TestLenientSameLineBraceInString: a '{' inside a string literal on the
// block's line must not be mistaken for the block's opening brace.
func TestLenientSameLineBraceInString(t *testing.T) {
	src := `resource "a" "b" { x = "{" y = 2 }
`
	mod, diags, err := Adapter{}.ParseModule("t.tf", []byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(diags) != 0 {
		t.Fatalf("recovered parse must be clean, got %+v", diags)
	}
	if len(mod.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(mod.Resources))
	}
	x, ok := mod.Resources[0].Attributes["x"].AsString()
	if !ok || x != "{" {
		t.Errorf("x = %q, want \"{\"", x)
	}
	if y, ok := mod.Resources[0].Attributes["y"]; !ok || !y.Known {
		t.Errorf("y missing after recovery")
	}
}

// TestPureFunctionEvaluation: jsonencode/merge/concat over static
// arguments evaluate to known values; calls over references or
// non-whitelisted functions stay Unknown (never guessed).
func TestPureFunctionEvaluation(t *testing.T) {
	src := `resource "aws_iam_policy" "admin" {
  policy = jsonencode(merge(
    { Version = "2012-10-17" },
    { Statement = [{ Effect = "Allow" Action = concat(["*"], []) Resource = "*" }] }
  ))
}
resource "aws_iam_policy" "readonly" {
  policy = jsonencode({
    Statement = [{ Effect = "Allow" Action = concat(["s3:GetObject"], ["s3:ListBucket"]) Resource = "arn:aws:s3:::c2/*" }]
  })
}
resource "aws_s3_bucket" "merged" {
  tags = merge({ Env = "prod" }, { Owner = "team" })
}
resource "aws_s3_bucket" "concatlist" {
  tags = concat(["a"], ["b"])
}
resource "aws_s3_bucket" "dynamic" {
  tags = merge({ Env = "prod" }, var.extra)
}
resource "aws_s3_bucket" "impure" {
  tags = uuid()
}
`
	mod, diags, err := Adapter{}.ParseModule("t.tf", []byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(diags) != 0 {
		t.Fatalf("parse must be clean, got %+v", diags)
	}
	res := map[string]ir.Resource{}
	for _, r := range mod.Resources {
		res[r.Address()] = r
	}
	admin, ok := res["aws_iam_policy.admin"].Attributes["policy"].AsString()
	if !ok {
		t.Fatalf("admin policy not a known string")
	}
	if !strings.Contains(admin, `"Action":["*"]`) || !strings.Contains(admin, `"Resource":"*"`) {
		t.Errorf("jsonencode(merge(...)) policy lost admin statement: %s", admin)
	}
	if !strings.Contains(admin, `"Version":"2012-10-17"`) {
		t.Errorf("jsonencode(merge(...)) policy lost Version: %s", admin)
	}
	ro, ok := res["aws_iam_policy.readonly"].Attributes["policy"].AsString()
	if !ok {
		t.Fatalf("readonly policy not a known string")
	}
	if !strings.Contains(ro, "s3:GetObject") || !strings.Contains(ro, "s3:ListBucket") {
		t.Errorf("concat() inside jsonencode lost actions: %s", ro)
	}
	merged, ok := res["aws_s3_bucket.merged"].Attributes["tags"].AsMap()
	if !ok || len(merged) != 2 {
		t.Errorf("merge() tags = %+v, want 2 entries", merged)
	}
	conc, ok := res["aws_s3_bucket.concatlist"].Attributes["tags"].AsList()
	if !ok || len(conc) != 2 {
		t.Errorf("concat() tags = %+v, want 2 elements", conc)
	}
	if v := res["aws_s3_bucket.dynamic"].Attributes["tags"]; v.Known {
		t.Errorf("merge() over a reference must stay Unknown, got %#v", v.Raw)
	}
	if v := res["aws_s3_bucket.impure"].Attributes["tags"]; v.Known {
		t.Errorf("non-whitelisted call must stay Unknown, got %#v", v.Raw)
	}
}

func TestLenientUnrecoverableUnchanged(t *testing.T) {
	src := `resource "aws_instance" "web" {
  ami = "ami-123"
  instance_type =
}
`
	_, diags, err := Adapter{}.ParseModule("t.tf", []byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(diags) == 0 {
		t.Fatal("expected diagnostics for genuinely broken HCL")
	}
}

// TestLenientCleanUntouched: valid files are not modified by the recovery.
func TestLenientCleanUntouched(t *testing.T) {
	src := `resource "aws_s3_bucket" "b" {
  bucket = "mybucket"
}
`
	mod, diags, err := Adapter{}.ParseModule("t.tf", []byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(diags) != 0 {
		t.Fatalf("valid file must have no diagnostics, got %+v", diags)
	}
	if len(mod.Resources) != 1 || mod.Resources[0].Address() != "aws_s3_bucket.b" {
		t.Fatalf("unexpected resources: %+v", mod.Resources)
	}
}

package planjson

import (
	"strings"
	"testing"
)

const fixturePlan = `{
  "format_version": "1.2",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_s3_bucket.data",
          "type": "aws_s3_bucket",
          "name": "data",
          "values": {
            "bucket": "my-bucket",
            "acl": "private",
            "versioning": {"enabled": true},
            "tags": {"Name": "data", "env": "prod"}
          },
          "sensitive_values": {}
        },
        {
          "address": "aws_db_instance.main",
          "type": "aws_db_instance",
          "name": "main",
          "values": {"username": "admin", "password": "s3cret-hunter2", "port": 5432},
          "sensitive_values": {"password": true}
        },
        {
          "address": "aws_security_group.web",
          "type": "aws_security_group",
          "name": "web",
          "values": {
            "ingress": [
              {"cidr_blocks": ["0.0.0.0/0"], "from_port": 443}
            ]
          },
          "sensitive_values": {
            "ingress": [{"cidr_blocks": [true]}]
          }
        }
      ],
      "child_modules": [
        {
          "address": "module.vpc",
          "resources": [
            {
              "address": "module.vpc.aws_subnet.a",
              "type": "aws_subnet",
              "name": "a",
              "values": {
                "cidr_block": "10.0.1.0/24",
                "availability_zone": null,
                "tags": {"Name": "a"}
              },
              "sensitive_values": {}
            }
          ],
          "child_modules": []
        }
      ]
    }
  }
}`

func TestHandles(t *testing.T) {
	var a Adapter
	cases := map[string]bool{
		"plan.plan.json":    true,
		"dir/out.PLAN.JSON": true,
		"plan.json":         false,
		"plan.json.bak":     false,
		"main.tf":           false,
		"myplan.jsonx":      false,
		"":                  false,
	}
	for path, want := range cases {
		if got := a.Handles(path); got != want {
			t.Errorf("Handles(%q) = %v, want %v", path, got, want)
		}
	}
	if got := a.Name(); got != "terraform-plan" {
		t.Errorf("Name() = %q, want terraform-plan", got)
	}
}

func TestParseFixture(t *testing.T) {
	var a Adapter
	const path = "test.plan.json"
	res, diags, err := a.Parse(path, []byte(fixturePlan))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if len(diags) != 0 {
		t.Fatalf("expected no diagnostics, got %v", diags)
	}
	if len(res) != 4 {
		t.Fatalf("expected 4 resources, got %d", len(res))
	}
	byAddr := map[string]int{}
	for i, r := range res {
		byAddr[r.Type+"."+r.Name] = i
		if r.Span.File != path {
			t.Errorf("resource %d span file = %q, want %q", i, r.Span.File, path)
		}
		if r.Provider == "" {
			t.Errorf("resource %d has empty provider", i)
		}
	}

	// Root resource: Name is the short name, Address() equals plan address.
	s3 := res[byAddr["aws_s3_bucket.data"]]
	if s3.Name != "data" {
		t.Errorf("s3 Name = %q, want data", s3.Name)
	}
	if got := s3.Address(); got != "aws_s3_bucket.data" {
		t.Errorf("s3 Address() = %q, want aws_s3_bucket.data", got)
	}
	if s3.Provider != "aws" {
		t.Errorf("s3 Provider = %q, want aws", s3.Provider)
	}
	if v, ok := s3.Attr("acl"); !ok {
		t.Error("s3 missing acl attribute")
	} else if s, known := v.AsString(); !known || s != "private" {
		t.Errorf("s3 acl = %q known=%v, want private/true", s, known)
	}
	if v, ok := s3.Attr("versioning"); !ok {
		t.Error("s3 missing versioning attribute")
	} else if m, known := v.AsMap(); !known || m["enabled"].Raw != true {
		t.Errorf("s3 versioning not decoded as nested map: %+v", v)
	}

	// Sensitive value redacted: unknown AND no secret bytes retained.
	db := res[byAddr["aws_db_instance.main"]]
	pw, ok := db.Attr("password")
	if !ok {
		t.Fatal("db missing password attribute")
	}
	if pw.Known {
		t.Error("sensitive password must be Unknown")
	}
	if pw.Raw != nil {
		t.Errorf("sensitive password Raw must be nil, got %v", pw.Raw)
	}
	if u, ok := db.Attr("username"); !ok {
		t.Error("db missing username")
	} else if s, known := u.AsString(); !known || s != "admin" {
		t.Errorf("db username = %q known=%v", s, known)
	}
	if p, ok := db.Attr("port"); !ok {
		t.Error("db missing port")
	} else if f, known := p.Raw.(float64); !known || f != 5432 {
		t.Errorf("db port = %v known=%v, want 5432/true", p.Raw, known)
	}

	// Child-module resource: module-qualified Name keeps Address() unique.
	sub := res[byAddr["aws_subnet.module.vpc.a"]]
	if sub.Name != "module.vpc.a" {
		t.Errorf("subnet Name = %q, want module.vpc.a", sub.Name)
	}
	if got := sub.Address(); got != "aws_subnet.module.vpc.a" {
		t.Errorf("subnet Address() = %q", got)
	}
	if v, ok := sub.Attr("cidr_block"); !ok {
		t.Error("subnet missing cidr_block")
	} else if s, known := v.AsString(); !known || s != "10.0.1.0/24" {
		t.Errorf("subnet cidr_block = %q known=%v", s, known)
	}
	// JSON null (unknown at apply time) -> Unknown.
	if v, ok := sub.Attr("availability_zone"); !ok {
		t.Error("subnet missing availability_zone")
	} else if v.Known {
		t.Error("null availability_zone must be Unknown")
	}

	// Sensitivity inside a list, positional recursion.
	sg := res[byAddr["aws_security_group.web"]]
	ing, ok := sg.Attr("ingress")
	if !ok {
		t.Fatal("sg missing ingress")
	}
	lst, known := ing.AsList()
	if !known || len(lst) != 1 {
		t.Fatalf("sg ingress not a 1-element known list: %+v", ing)
	}
	m, known := lst[0].AsMap()
	if !known {
		t.Fatal("sg ingress[0] not a known map")
	}
	if cb, ok := m["cidr_blocks"]; !ok {
		t.Error("sg ingress[0] missing cidr_blocks")
	} else if cl, known := cb.AsList(); !known || len(cl) != 1 || cl[0].Known {
		t.Errorf("sensitive cidr_blocks[0] must be Unknown, got %+v", cb)
	} else if cl[0].Raw != nil {
		t.Errorf("sensitive cidr_blocks[0] Raw must be nil, got %v", cl[0].Raw)
	}
	if fp, ok := m["from_port"]; !ok {
		t.Error("sg ingress[0] missing from_port")
	} else if f, known := fp.Raw.(float64); !known || f != 443 {
		t.Errorf("sg from_port = %v known=%v, want 443/true", fp.Raw, known)
	}
}

func TestParseMalformed(t *testing.T) {
	var a Adapter
	for _, src := range []string{"", "{not json", "[1,2"} {
		if _, _, err := a.Parse("x.plan.json", []byte(src)); err == nil {
			t.Errorf("Parse(%q) expected hard error, got nil", src)
		}
	}
}

func TestParseNoPlannedValues(t *testing.T) {
	var a Adapter
	res, diags, err := a.Parse("x.plan.json", []byte(`{"format_version":"1.0"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 0 {
		t.Errorf("expected 0 resources, got %d", len(res))
	}
	if len(diags) != 1 || diags[0].Level != "warning" {
		t.Errorf("expected one warning diagnostic, got %+v", diags)
	}
}

func TestParseSkipsBadResource(t *testing.T) {
	var a Adapter
	src := `{"planned_values":{"root_module":{"resources":[
		{"address":"","type":"","name":"ghost","values":{}},
		{"address":"aws_s3_bucket.ok","type":"aws_s3_bucket","name":"ok","values":{"acl":"private"}}
	]}}}`
	res, diags, err := a.Parse("x.plan.json", []byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 1 || res[0].Name != "ok" {
		t.Errorf("expected only the good resource, got %+v", res)
	}
	if len(diags) != 1 || diags[0].Level != "warning" ||
		!strings.Contains(diags[0].Message, "ghost") {
		t.Errorf("expected warning mentioning ghost, got %+v", diags)
	}
}

func TestParseEmptyValues(t *testing.T) {
	var a Adapter
	src := `{"planned_values":{"root_module":{"resources":[
		{"address":"aws_s3_bucket.e","type":"aws_s3_bucket","name":"e"}
	]}}}`
	res, _, err := a.Parse("x.plan.json", []byte(src))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(res) != 1 || len(res[0].Attributes) != 0 {
		t.Errorf("expected one resource with empty attributes, got %+v", res)
	}
}

// No-panic sweep over hostile shapes.
func TestParseHostile(t *testing.T) {
	var a Adapter
	srcs := []string{
		`{"planned_values":{"root_module":{"resources":[{"address":123,"type":[],"name":{},"values":[]}]}}}`,
		`{"planned_values":{"root_module":{"resources":null,"child_modules":[{}]}}}`,
		`{"planned_values":{"root_module":{"child_modules":[{"address":"module.a","child_modules":[{"resources":[{"address":"module.a.module.b.aws_x.y","type":"aws_x","name":"y","values":{"a":{"b":{"c":[1,{"d":null}]}}}}]}]}]}}}`,
		`{"planned_values": {"root_module": {"resources": [{"address": "x", "type": "y", "name": "z", "values": {"s": {"t": {"u": {"v": {"w": 1}}}}}, "sensitive_values": {"s": true}}]}}}`,
	}
	for i, src := range srcs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("src %d panicked: %v", i, r)
				}
			}()
			_, _, _ = a.Parse("x.plan.json", []byte(src))
		}()
	}
}

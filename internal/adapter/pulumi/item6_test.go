package pulumi

import (
	"strings"
	"testing"
)

// Item 6: a self-referential YAML anchor (&a [*a]) used to recurse
// value() until the goroutine stack overflowed. Must yield Unknown +
// diagnostic, with the resource still present.
func TestItem6AliasCycle(t *testing.T) {
	src := `name: test
runtime: yaml
resources:
  bucket:
    type: aws:s3:Bucket
    properties:
      bucket: &a [*a]
`
	res, diags, err := Adapter{}.Parse("Pulumi.yaml", []byte(src))
	if err != nil {
		t.Fatalf("Parse returned hard error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(res))
	}
	found := false
	for _, d := range diags {
		if strings.Contains(d.Message, "alias cycle") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected alias-cycle diagnostic, got %v", diags)
	}
}

// Item 6: a variable reference cycle (a: ${b}, b: ${a}) used to recurse
// value -> scalar -> resolveRef until stack overflow. Must yield Unknown
// + diagnostic, never a crash.
func TestItem6VarCycle(t *testing.T) {
	src := `name: test
runtime: yaml
variables:
  a: ${b}
  b: ${a}
resources:
  bucket:
    type: aws:s3:Bucket
    properties:
      bucket: ${a}
`
	res, diags, err := Adapter{}.Parse("Pulumi.yaml", []byte(src))
	if err != nil {
		t.Fatalf("Parse returned hard error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(res))
	}
	found := false
	for _, d := range diags {
		if strings.Contains(d.Message, "reference cycle") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected reference-cycle diagnostic, got %v", diags)
	}
}

// Item 6: a non-cyclic variable chain must still resolve (guards must not
// turn every ${...} into Unknown).
func TestItem6VarChainResolves(t *testing.T) {
	src := `name: test
runtime: yaml
variables:
  a: hello
  b: ${a}
resources:
  bucket:
    type: aws:s3:Bucket
    properties:
      bucket: ${b}
`
	res, _, err := Adapter{}.Parse("Pulumi.yaml", []byte(src))
	if err != nil {
		t.Fatalf("Parse returned hard error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(res))
	}
	v, ok := res[0].Attributes["bucket"]
	if !ok || !v.Known || v.Raw != "hello" {
		t.Fatalf("expected bucket=hello known, got %+v (present=%v)", v, ok)
	}
}

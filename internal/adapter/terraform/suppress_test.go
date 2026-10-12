package terraform

import (
	"reflect"
	"testing"
)

func TestParseSuppressComment(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{`# aegis:skip=AEGIS-AWS-001`, []string{"AEGIS-AWS-001"}},
		{`  # aegis:skip=AEGIS-AWS-001`, []string{"AEGIS-AWS-001"}},
		{`// aegis:skip=AEGIS-AWS-001`, []string{"AEGIS-AWS-001"}},
		{`# aegis:skip=AEGIS-AWS-001,AEGIS-AWS-012`, []string{"AEGIS-AWS-001", "AEGIS-AWS-012"}},
		{`# aegis:skip=AEGIS-AWS-001, AEGIS-AWS-012`, []string{"AEGIS-AWS-001", "AEGIS-AWS-012"}},
		{`# aegis:skip=all`, []string{"all"}},
		{`# some other comment`, nil},
		{`# aegis:skip=`, nil},
		{`resource "aws_s3_bucket" "a" { # aegis:skip=AEGIS-AWS-001`, []string{"AEGIS-AWS-001"}},
		{``, nil},
	}
	for _, tc := range cases {
		if got := parseSuppressComment(tc.line); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("line %q: got %v, want %v", tc.line, got, tc.want)
		}
	}
}

func TestSuppressRulesForBlock(t *testing.T) {
	comments := map[int][]string{
		10: {"AEGIS-AWS-001"},
		20: {"AEGIS-AWS-012", "AEGIS-AWS-013"},
	}
	// Line above.
	if got := suppressRulesForBlock(comments, 11); !reflect.DeepEqual(got, []string{"AEGIS-AWS-001"}) {
		t.Errorf("above: got %v", got)
	}
	// Same line.
	if got := suppressRulesForBlock(comments, 20); !reflect.DeepEqual(got, []string{"AEGIS-AWS-012", "AEGIS-AWS-013"}) {
		t.Errorf("same: got %v", got)
	}
	// No comment.
	if got := suppressRulesForBlock(comments, 30); len(got) != 0 {
		t.Errorf("none: got %v", got)
	}
	// Line 0 guard (startLine-1 = 0, no comments there).
	if got := suppressRulesForBlock(comments, 1); len(got) != 0 {
		t.Errorf("line1: got %v", got)
	}
}

func TestParseModule_InlineSuppressions(t *testing.T) {
	src := `# aegis:skip=AEGIS-AWS-001
resource "aws_s3_bucket" "above" {
  bucket = "above"
}

resource "aws_s3_bucket" "same" { # aegis:skip=AEGIS-AWS-012
  bucket = "same"
}

# aegis:skip=AEGIS-AWS-001,AEGIS-AWS-012
resource "aws_s3_bucket" "multi" {
  bucket = "multi"
}

# aegis:skip=all
resource "aws_s3_bucket" "everything" {
  bucket = "everything"
}

resource "aws_s3_bucket" "plain" {
  bucket = "plain"
}

// aegis:skip=AEGIS-AWS-003
resource "aws_s3_bucket" "slashes" {
  bucket = "slashes"
}
`
	mod, _, err := Adapter{}.ParseModule("test.tf", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := map[string][]string{}
	for _, r := range mod.Resources {
		got[r.Name] = r.SuppressedRules
	}
	want := map[string][]string{
		"above":      {"AEGIS-AWS-001"},
		"same":       {"AEGIS-AWS-012"},
		"multi":      {"AEGIS-AWS-001", "AEGIS-AWS-012"},
		"everything": {"all"},
		"plain":      nil,
		"slashes":    {"AEGIS-AWS-003"},
	}
	for name, w := range want {
		if !reflect.DeepEqual(got[name], w) {
			t.Errorf("resource %q: got %v, want %v", name, got[name], w)
		}
	}
}

func TestParseModule_SuppressionDoesNotLeak(t *testing.T) {
	// A comment two lines above must NOT attach.
	src := `# aegis:skip=AEGIS-AWS-001

resource "aws_s3_bucket" "far" {
  bucket = "far"
}
`
	mod, _, err := Adapter{}.ParseModule("test.tf", []byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(mod.Resources) != 1 {
		t.Fatalf("got %d resources", len(mod.Resources))
	}
	if len(mod.Resources[0].SuppressedRules) != 0 {
		t.Errorf("leaked suppression: %v", mod.Resources[0].SuppressedRules)
	}
}

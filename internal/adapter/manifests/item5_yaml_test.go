package manifests

import (
	"strings"
	"testing"
	"time"

	"aegis/internal/ir"
)

// Item 5: YAML duplicate-key / alias safety (CVE-class DoS in the old
// Decode(&any) path: quadratic error list, OOM-kill on 30 KiB input).

func TestParseDuplicateKeysFailFast(t *testing.T) {
	src := "x: &a [1,2,3]\n" + strings.Repeat("y: *a\n", 5000)
	start := time.Now()
	rs, diags := mustParse(t, "x.yaml", src)
	if time.Since(start) > 10*time.Second {
		t.Errorf("duplicate-key input took too long: %v", time.Since(start))
	}
	if len(rs) != 0 {
		t.Fatalf("expected no resources, got %d", len(rs))
	}
	if len(diags) != 1 || diags[0].Level != "error" {
		t.Fatalf("expected one error diagnostic, got %+v", diags)
	}
	if len(diags[0].Message) > 4096 {
		t.Errorf("diagnostic message not bounded: %d bytes", len(diags[0].Message))
	}
	if !strings.Contains(diags[0].Message, "already defined") {
		t.Errorf("expected duplicate-key diagnostic, got %q", diags[0].Message)
	}
}

func TestParseAnchorsAndMergeKeys(t *testing.T) {
	src := `
apiVersion: v1
kind: ConfigMap
metadata:
  name: m
data:
  base: &base
    a: "1"
    b: "2"
  merged:
    <<: *base
    b: "override"
  aliased: *base
`
	rs, diags := mustParse(t, "x.yaml", src)
	if len(diags) != 0 {
		t.Fatalf("unexpected diagnostics: %+v", diags)
	}
	if len(rs) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(rs))
	}
	data, ok := rs[0].Attributes["data"]
	if !ok {
		t.Fatalf("no data attribute: %+v", rs[0].Attributes)
	}
	merged := data.Raw.(map[string]ir.Value)["merged"].Raw.(map[string]ir.Value)
	if merged["a"].Raw != "1" || merged["b"].Raw != "override" {
		t.Errorf("merge key not honored: %#v", merged)
	}
}

func TestParseCyclicAliasRejected(t *testing.T) {
	src := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: m\ndata: &a\n  self: *a\n"
	rs, diags := mustParse(t, "x.yaml", src)
	if len(rs) != 0 {
		t.Fatalf("expected no resources for cyclic alias, got %d", len(rs))
	}
	if len(diags) != 1 || diags[0].Level != "error" {
		t.Fatalf("expected one error diagnostic, got %+v", diags)
	}
	if !strings.Contains(diags[0].Message, "cyclic") {
		t.Errorf("expected cyclic-alias diagnostic, got %q", diags[0].Message)
	}
}

func TestParseBillionLaughsBounded(t *testing.T) {
	// Classic exponential-expansion shape: each level doubles the
	// previous. The node budget must abort this fast with a clear
	// error instead of expanding 2^25 nodes.
	var sb strings.Builder
	sb.WriteString("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: m\ndata:\n")
	sb.WriteString("  a0: &a0 [\"x\"]\n")
	for i := 1; i <= 25; i++ {
		sb.WriteString("  a" + itoa(i) + ": &a" + itoa(i) + " [*a" + itoa(i-1) + ", *a" + itoa(i-1) + "]\n")
	}
	start := time.Now()
	rs, diags := mustParse(t, "x.yaml", sb.String())
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("billion-laughs input took too long: %v", elapsed)
	}
	if len(rs) != 0 {
		t.Fatalf("expected no resources for budget-exceeded input, got %d", len(rs))
	}
	if len(diags) != 1 || diags[0].Level != "error" {
		t.Fatalf("expected one error diagnostic, got %+v", diags)
	}
	if !strings.Contains(diags[0].Message, "budget") {
		t.Errorf("expected node-budget diagnostic, got %q", diags[0].Message)
	}
	if len(diags[0].Message) > 4096 {
		t.Errorf("unbounded diagnostic: %d bytes", len(diags[0].Message))
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}

package custom

import (
	"os"
	"path/filepath"
	"testing"

	"aegis/internal/ir"
	"aegis/internal/rules"
)

// Helpers to build IR values.
func kv(v any) ir.Value { return ir.Value{Raw: v, Known: true} }
func ku() ir.Value      { return ir.Value{Known: false} }
func res(typ, name string, attrs map[string]ir.Value) ir.Resource {
	return ir.Resource{
		Type: typ, Name: name, Provider: "aws",
		Attributes: attrs,
		Span:       ir.Span{File: "t.tf", StartLine: 1, StartCol: 1, EndLine: 1, EndCol: 10},
	}
}
func tags(m map[string]string) ir.Value {
	mm := map[string]ir.Value{}
	for k, v := range m {
		mm[k] = kv(v)
	}
	return ir.Value{Raw: mm, Known: true}
}
func blks(maps ...map[string]ir.Value) ir.Value {
	var out []ir.Value
	for _, m := range maps {
		out = append(out, ir.Value{Raw: m, Known: true})
	}
	return ir.Value{Raw: out, Known: true}
}

// compileRule builds a rule from an inline YAML doc for tests.
func compileRule(t *testing.T, doc string) *Rule {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "r.yaml"), []byte(doc), 0600); err != nil {
		t.Fatal(err)
	}
	rs, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir: %v", err)
	}
	if len(rs) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rs))
	}
	r, ok := rs[0].(*Rule)
	if !ok {
		t.Fatalf("not a *Rule: %T", rs[0])
	}
	return r
}

func check(t *testing.T, r *Rule, res ir.Resource) []ir.Finding {
	t.Helper()
	if !r.AppliesTo(res.Type) {
		t.Fatalf("rule does not apply to %s", res.Type)
	}
	return r.Check(res)
}

// --- Operators ---

func TestAbsent_FiresWhenMissing(t *testing.T) {
	r := compileRule(t, `rules:
- id: C1
  title: t
  severity: high
  resource_types: [aws_s3_bucket]
  conditions: [{attribute: tags.Team, operator: absent}]`)
	if got := check(t, r, res("aws_s3_bucket", "b", nil)); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
}

func TestAbsent_QuietWhenPresent(t *testing.T) {
	r := compileRule(t, `rules:
- id: C1
  title: t
  severity: high
  resource_types: [aws_s3_bucket]
  conditions: [{attribute: tags.Team, operator: absent}]`)
	got := check(t, r, res("aws_s3_bucket", "b", map[string]ir.Value{"tags": tags(map[string]string{"Team": "x"})}))
	if len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
}

func TestPresent_FiresWhenSet(t *testing.T) {
	r := compileRule(t, `rules:
- id: C1
  title: t
  severity: medium
  resource_types: [aws_instance]
  conditions: [{attribute: user_data, operator: present}]`)
	if got := check(t, r, res("aws_instance", "i", map[string]ir.Value{"user_data": kv("x")})); len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
}

func TestPresent_QuietWhenMissing(t *testing.T) {
	r := compileRule(t, `rules:
- id: C1
  title: t
  severity: medium
  resource_types: [aws_instance]
  conditions: [{attribute: user_data, operator: present}]`)
	if got := check(t, r, res("aws_instance", "i", nil)); len(got) != 0 {
		t.Fatalf("expected 0, got %d", len(got))
	}
}

func TestEquals_FiresAndQuiets(t *testing.T) {
	r := compileRule(t, `rules:
- id: C1
  title: t
  severity: critical
  resource_types: [aws_s3_bucket]
  conditions: [{attribute: acl, operator: equals, value: public-read}]`)
	if got := check(t, r, res("aws_s3_bucket", "b", map[string]ir.Value{"acl": kv("public-read")})); len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	if got := check(t, r, res("aws_s3_bucket", "b", map[string]ir.Value{"acl": kv("private")})); len(got) != 0 {
		t.Fatalf("expected 0, got %d", len(got))
	}
}

func TestNotEquals(t *testing.T) {
	r := compileRule(t, `rules:
- id: C1
  title: t
  severity: low
  resource_types: [aws_s3_bucket]
  conditions: [{attribute: acl, operator: not_equals, value: private}]`)
	if got := check(t, r, res("aws_s3_bucket", "b", map[string]ir.Value{"acl": kv("public-read")})); len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	if got := check(t, r, res("aws_s3_bucket", "b", map[string]ir.Value{"acl": kv("private")})); len(got) != 0 {
		t.Fatalf("expected 0, got %d", len(got))
	}
}

func TestContains_StringAndList(t *testing.T) {
	r := compileRule(t, `rules:
- id: C1
  title: t
  severity: high
  resource_types: [aws_iam_policy]
  conditions: [{attribute: policy, operator: contains, value: '"*"' }]`)
	if got := check(t, r, res("aws_iam_policy", "p", map[string]ir.Value{"policy": kv(`{"Action":"*"}`)})); len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	if got := check(t, r, res("aws_iam_policy", "p", map[string]ir.Value{"policy": kv(`{"Action":"s3:Get"}`)})); len(got) != 0 {
		t.Fatalf("expected 0, got %d", len(got))
	}
	// list form
	r2 := compileRule(t, `rules:
- id: C2
  title: t
  severity: high
  resource_types: [aws_security_group]
  conditions: [{attribute: cidr_blocks, operator: contains, value: 0.0.0.0/0}]`)
	lst := ir.Value{Raw: []ir.Value{kv("10.0.0.0/8"), kv("0.0.0.0/0")}, Known: true}
	if got := r2.Check(res("aws_security_group", "s", map[string]ir.Value{"cidr_blocks": lst})); len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
}

func TestRegex(t *testing.T) {
	r := compileRule(t, `rules:
- id: C1
  title: t
  severity: low
  resource_types: [aws_instance]
  conditions: [{attribute: instance_type, operator: regex, value: "^t3\\."}]`)
	if got := check(t, r, res("aws_instance", "i", map[string]ir.Value{"instance_type": kv("t3.micro")})); len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	if got := check(t, r, res("aws_instance", "i", map[string]ir.Value{"instance_type": kv("m5.large")})); len(got) != 0 {
		t.Fatalf("expected 0, got %d", len(got))
	}
}

func TestGTLT(t *testing.T) {
	r := compileRule(t, `rules:
- id: C1
  title: t
  severity: medium
  resource_types: [aws_db_instance]
  conditions: [{attribute: backup_retention_period, operator: lt, value: 7}]`)
	if got := check(t, r, res("aws_db_instance", "d", map[string]ir.Value{"backup_retention_period": kv(float64(0))})); len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	if got := check(t, r, res("aws_db_instance", "d", map[string]ir.Value{"backup_retention_period": kv(float64(30))})); len(got) != 0 {
		t.Fatalf("expected 0, got %d", len(got))
	}
	// gt with int value in YAML
	r2 := compileRule(t, `rules:
- id: C2
  title: t
  severity: medium
  resource_types: [aws_db_instance]
  conditions: [{attribute: backup_retention_period, operator: gt, value: 35}]`)
	if got := r2.Check(res("aws_db_instance", "d", map[string]ir.Value{"backup_retention_period": kv(float64(40))})); len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
}

// --- Nested attributes ---

func TestNested_MapPath(t *testing.T) {
	r := compileRule(t, `rules:
- id: C1
  title: t
  severity: high
  resource_types: [aws_s3_bucket]
  conditions: [{attribute: tags.Team, operator: absent}]`)
	// present -> quiet
	got := check(t, r, res("aws_s3_bucket", "b", map[string]ir.Value{"tags": tags(map[string]string{"Team": "sec"})}))
	if len(got) != 0 {
		t.Fatalf("expected 0, got %d", len(got))
	}
	// map present but key missing -> fires
	got = check(t, r, res("aws_s3_bucket", "b", map[string]ir.Value{"tags": tags(map[string]string{"Env": "prod"})}))
	if len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
}

func TestNested_BlockPath(t *testing.T) {
	r := compileRule(t, `rules:
- id: C1
  title: t
  severity: medium
  resource_types: [aws_s3_bucket]
  conditions: [{attribute: versioning.enabled, operator: equals, value: true}]`)
	on := res("aws_s3_bucket", "b", map[string]ir.Value{
		"versioning": blks(map[string]ir.Value{"enabled": kv(true)}),
	})
	if got := check(t, r, on); len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	off := res("aws_s3_bucket", "b", map[string]ir.Value{
		"versioning": blks(map[string]ir.Value{"enabled": kv(false)}),
	})
	if got := check(t, r, off); len(got) != 0 {
		t.Fatalf("expected 0, got %d", len(got))
	}
}

// --- Combinators ---

func TestMatchAll_RequiresEveryCondition(t *testing.T) {
	r := compileRule(t, `rules:
- id: C1
  title: t
  severity: high
  resource_types: [aws_db_instance]
  match: all
  conditions:
    - attribute: storage_encrypted
      operator: equals
      value: false
    - attribute: publicly_accessible
      operator: equals
      value: true`)
	both := res("aws_db_instance", "d", map[string]ir.Value{
		"storage_encrypted": kv(false), "publicly_accessible": kv(true)})
	if got := check(t, r, both); len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	one := res("aws_db_instance", "d", map[string]ir.Value{
		"storage_encrypted": kv(false), "publicly_accessible": kv(false)})
	if got := check(t, r, one); len(got) != 0 {
		t.Fatalf("expected 0, got %d", len(got))
	}
}

func TestMatchAny_FiresOnOne(t *testing.T) {
	r := compileRule(t, `rules:
- id: C1
  title: t
  severity: high
  resource_types: [aws_db_instance]
  match: any
  conditions:
    - attribute: storage_encrypted
      operator: equals
      value: false
    - attribute: publicly_accessible
      operator: equals
      value: true`)
	one := res("aws_db_instance", "d", map[string]ir.Value{
		"storage_encrypted": kv(true), "publicly_accessible": kv(true)})
	if got := check(t, r, one); len(got) != 1 {
		t.Fatalf("expected 1, got %d", len(got))
	}
	neither := res("aws_db_instance", "d", map[string]ir.Value{
		"storage_encrypted": kv(true), "publicly_accessible": kv(false)})
	if got := check(t, r, neither); len(got) != 0 {
		t.Fatalf("expected 0, got %d", len(got))
	}
}

func TestMatchDefaultIsAll(t *testing.T) {
	r := compileRule(t, `rules:
- id: C1
  title: t
  severity: high
  resource_types: [aws_db_instance]
  conditions:
    - attribute: a
      operator: equals
      value: 1
    - attribute: b
      operator: equals
      value: 2`)
	one := res("aws_db_instance", "d", map[string]ir.Value{"a": kv(float64(1)), "b": kv(float64(9))})
	if got := check(t, r, one); len(got) != 0 {
		t.Fatalf("expected 0 (default all), got %d", len(got))
	}
}

// --- Unknown values stay silent ---

func TestUnknown_Silent(t *testing.T) {
	for _, doc := range []string{
		`rules:
- id: C1
  title: t
  severity: high
  resource_types: [aws_s3_bucket]
  conditions: [{attribute: acl, operator: equals, value: public-read}]`,
		`rules:
- id: C1
  title: t
  severity: high
  resource_types: [aws_s3_bucket]
  conditions: [{attribute: acl, operator: not_equals, value: private}]`,
		`rules:
- id: C1
  title: t
  severity: high
  resource_types: [aws_s3_bucket]
  conditions: [{attribute: acl, operator: present}]`,
		`rules:
- id: C1
  title: t
  severity: high
  resource_types: [aws_s3_bucket]
  conditions: [{attribute: acl, operator: contains, value: public}]`,
		`rules:
- id: C1
  title: t
  severity: high
  resource_types: [aws_s3_bucket]
  conditions: [{attribute: acl, operator: regex, value: "^public"}]`,
		`rules:
- id: C1
  title: t
  severity: medium
  resource_types: [aws_db_instance]
  conditions: [{attribute: backup_retention_period, operator: lt, value: 7}]`,
	} {
		r := compileRule(t, doc)
		got := r.Check(res("aws_s3_bucket", "b", map[string]ir.Value{
			"acl": ku(), "backup_retention_period": ku(),
		}))
		if len(got) != 0 {
			t.Fatalf("operator in %q: expected silence on unknown, got %d", doc[:60], len(got))
		}
	}
}

func TestUnknownNested_Silent(t *testing.T) {
	r := compileRule(t, `rules:
- id: C1
  title: t
  severity: high
  resource_types: [aws_s3_bucket]
  conditions: [{attribute: tags.Team, operator: equals, value: sec}]`)
	got := check(t, r, res("aws_s3_bucket", "b", map[string]ir.Value{"tags": ku()}))
	if len(got) != 0 {
		t.Fatalf("expected 0, got %d", len(got))
	}
}

// --- Loader validation ---

func writeDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func expectLoadError(t *testing.T, dir, substr string) {
	t.Helper()
	_, err := LoadDir(dir)
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", substr)
	}
	if !contains(err.Error(), substr) {
		t.Fatalf("expected error containing %q, got %q", substr, err.Error())
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

func TestInvalidYAML(t *testing.T) {
	dir := writeDir(t, map[string]string{"bad.yaml": "rules:\n  - id: [\n"})
	expectLoadError(t, dir, "invalid YAML")
}

func TestUnknownField_Rejected(t *testing.T) {
	dir := writeDir(t, map[string]string{"r.yaml": `rules:
- id: C1
  title: t
  severity: high
  resource_types: [aws_s3_bucket]
  bogus_field: 1
  conditions: [{attribute: a, operator: absent}]`})
	expectLoadError(t, dir, "bogus_field")
}

func TestBadSeverity(t *testing.T) {
	dir := writeDir(t, map[string]string{"r.yaml": `rules:
- id: C1
  title: t
  severity: catastrophic
  resource_types: [aws_s3_bucket]
  conditions: [{attribute: a, operator: absent}]`})
	expectLoadError(t, dir, "invalid severity")
}

func TestBadOperator(t *testing.T) {
	dir := writeDir(t, map[string]string{"r.yaml": `rules:
- id: C1
  title: t
  severity: high
  resource_types: [aws_s3_bucket]
  conditions: [{attribute: a, operator: maybe}]`})
	expectLoadError(t, dir, "invalid operator")
}

func TestMissingValue(t *testing.T) {
	dir := writeDir(t, map[string]string{"r.yaml": `rules:
- id: C1
  title: t
  severity: high
  resource_types: [aws_s3_bucket]
  conditions: [{attribute: a, operator: equals}]`})
	expectLoadError(t, dir, "requires a value")
}

func TestBadRegex(t *testing.T) {
	dir := writeDir(t, map[string]string{"r.yaml": `rules:
- id: C1
  title: t
  severity: high
  resource_types: [aws_s3_bucket]
  conditions: [{attribute: a, operator: regex, value: "([a-z"}]`})
	expectLoadError(t, dir, "invalid regex")
}

func TestNonNumericGT(t *testing.T) {
	dir := writeDir(t, map[string]string{"r.yaml": `rules:
- id: C1
  title: t
  severity: high
  resource_types: [aws_s3_bucket]
  conditions: [{attribute: a, operator: gt, value: many}]`})
	expectLoadError(t, dir, "numeric value")
}

func TestNoConditions(t *testing.T) {
	dir := writeDir(t, map[string]string{"r.yaml": `rules:
- id: C1
  title: t
  severity: high
  resource_types: [aws_s3_bucket]`})
	expectLoadError(t, dir, "at least one condition")
}

func TestNoResourceTypes(t *testing.T) {
	dir := writeDir(t, map[string]string{"r.yaml": `rules:
- id: C1
  title: t
  severity: high
  conditions: [{attribute: a, operator: absent}]`})
	expectLoadError(t, dir, "resource_type")
}

func TestMissingTitle(t *testing.T) {
	dir := writeDir(t, map[string]string{"r.yaml": `rules:
- id: C1
  severity: high
  resource_types: [aws_s3_bucket]
  conditions: [{attribute: a, operator: absent}]`})
	expectLoadError(t, dir, "title is required")
}

func TestDuplicateID_SameFile(t *testing.T) {
	dir := writeDir(t, map[string]string{"r.yaml": `rules:
- id: C1
  title: t
  severity: high
  resource_types: [aws_s3_bucket]
  conditions: [{attribute: a, operator: absent}]
- id: C1
  title: t2
  severity: low
  resource_types: [aws_s3_bucket]
  conditions: [{attribute: b, operator: absent}]`})
	expectLoadError(t, dir, "duplicate rule id")
}

func TestDuplicateID_AcrossFiles(t *testing.T) {
	dir := writeDir(t, map[string]string{
		"a.yaml": "rules:\n- id: C1\n  title: t\n  severity: high\n  resource_types: [aws_s3_bucket]\n  conditions: [{attribute: a, operator: absent}]\n",
		"b.yaml": "rules:\n- id: C1\n  title: t\n  severity: low\n  resource_types: [aws_s3_bucket]\n  conditions: [{attribute: b, operator: absent}]\n",
	})
	expectLoadError(t, dir, "duplicate rule id")
}

func TestEmptyDir(t *testing.T) {
	expectLoadError(t, t.TempDir(), "no .yaml/.yml files")
}

func TestMissingDir(t *testing.T) {
	expectLoadError(t, filepath.Join(t.TempDir(), "nope"), "cannot read directory")
}

func TestNoRulesKey(t *testing.T) {
	dir := writeDir(t, map[string]string{"r.yaml": "rules: []\n"})
	expectLoadError(t, dir, "defines no rules")
}

// --- Engine end-to-end ---

func TestEndToEnd_ViaRegistry(t *testing.T) {
	dir := writeDir(t, map[string]string{"r.yaml": `rules:
- id: CUSTOM-001
  title: "Team tag required"
  description: "d"
  severity: high
  resource_types: [aws_s3_bucket]
  conditions: [{attribute: tags.Team, operator: absent}]`})
	crules, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	reg := rules.NewRegistry()
	for _, r := range crules {
		reg.Register(r)
	}
	resources := []ir.Resource{
		res("aws_s3_bucket", "tagged", map[string]ir.Value{"tags": tags(map[string]string{"Team": "sec"})}),
		res("aws_s3_bucket", "untagged", nil),
		res("aws_instance", "i", nil), // wrong type: must not apply
	}
	findings := reg.Run(resources)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.RuleID != "CUSTOM-001" || f.Resource != "aws_s3_bucket.untagged" {
		t.Fatalf("unexpected finding: %+v", f)
	}
	if f.Severity != ir.SeverityHigh || f.Title == "" || f.Description == "" {
		t.Fatalf("incomplete finding metadata: %+v", f)
	}
	if f.Evidence.Attribute != "tags.Team" || f.Evidence.Actual != "absent" {
		t.Fatalf("bad evidence: %+v", f.Evidence)
	}
}

func TestEndToEnd_DeterministicOrder(t *testing.T) {
	dir := writeDir(t, map[string]string{
		"b.yaml": "rules:\n- id: CUSTOM-002\n  title: t\n  severity: low\n  resource_types: [aws_s3_bucket]\n  conditions: [{attribute: x, operator: absent}]\n",
		"a.yaml": "rules:\n- id: CUSTOM-001\n  title: t\n  severity: high\n  resource_types: [aws_s3_bucket]\n  conditions: [{attribute: x, operator: absent}]\n",
	})
	crules, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if crules[0].ID() != "CUSTOM-001" || crules[1].ID() != "CUSTOM-002" {
		t.Fatalf("rules not sorted by ID: %s, %s", crules[0].ID(), crules[1].ID())
	}
}

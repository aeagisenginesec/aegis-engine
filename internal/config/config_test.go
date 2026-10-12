package config

import (
	"os"
	"path/filepath"
	"testing"

	"aegis/internal/ir"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "aegis.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func mkFinding(ruleID string, sev ir.Severity) ir.Finding {
	return ir.Finding{RuleID: ruleID, Severity: sev, Title: "t"}
}

func TestSeverityOverride(t *testing.T) {
	p := writeConfig(t, "severity_overrides:\n  AEGIS-AWS-001: low\n  AEGIS-AWS-004: critical\n")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	out, diags := c.Apply([]ir.Finding{
		mkFinding("AEGIS-AWS-001", ir.SeverityHigh),
		mkFinding("AEGIS-AWS-004", ir.SeverityMedium),
		mkFinding("AEGIS-AWS-002", ir.SeverityHigh),
	})
	if len(diags) != 0 {
		t.Errorf("unexpected diags: %v", diags)
	}
	got := map[string]ir.Severity{}
	for _, f := range out {
		got[f.RuleID] = f.Severity
	}
	if got["AEGIS-AWS-001"] != ir.SeverityLow {
		t.Errorf("001 not downgraded: %v", got["AEGIS-AWS-001"])
	}
	if got["AEGIS-AWS-004"] != ir.SeverityCritical {
		t.Errorf("004 not escalated: %v", got["AEGIS-AWS-004"])
	}
	if got["AEGIS-AWS-002"] != ir.SeverityHigh {
		t.Errorf("002 should be untouched: %v", got["AEGIS-AWS-002"])
	}
}

func TestExcludeRules(t *testing.T) {
	p := writeConfig(t, "exclude_rules:\n  - AEGIS-AWS-001\n")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := c.Apply([]ir.Finding{
		mkFinding("AEGIS-AWS-001", ir.SeverityHigh),
		mkFinding("AEGIS-AWS-002", ir.SeverityHigh),
	})
	if len(out) != 1 || out[0].RuleID != "AEGIS-AWS-002" {
		t.Errorf("exclude_rules did not drop 001: %v", out)
	}
}

func TestInvalidSeverityWarns(t *testing.T) {
	p := writeConfig(t, "severity_overrides:\n  AEGIS-AWS-001: bogus\n")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	out, diags := c.Apply([]ir.Finding{mkFinding("AEGIS-AWS-001", ir.SeverityHigh)})
	if len(out) != 1 || out[0].Severity != ir.SeverityHigh {
		t.Errorf("invalid severity must leave the finding untouched")
	}
	if len(diags) == 0 {
		t.Errorf("expected a warning diagnostic for invalid severity")
	}
}

func TestUnmatchedOverrideWarns(t *testing.T) {
	p := writeConfig(t, "severity_overrides:\n  AEGIS-AWS-999: low\n")
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	_, diags := c.Apply([]ir.Finding{mkFinding("AEGIS-AWS-001", ir.SeverityHigh)})
	if len(diags) == 0 {
		t.Errorf("expected a warning for an override that matched nothing")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.yaml")); err == nil {
		t.Errorf("expected error for missing file")
	}
}

func TestNilConfigApply(t *testing.T) {
	var c *Config
	in := []ir.Finding{mkFinding("A", ir.SeverityHigh)}
	out, diags := c.Apply(in)
	if len(out) != 1 || len(diags) != 0 {
		t.Errorf("nil config must pass findings through untouched")
	}
}

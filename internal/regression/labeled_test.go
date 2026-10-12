// Package regression holds golden-file tests that pin the full scan
// pipeline's output. This file adds paired vulnerable/secure fixtures for
// the top-20 Critical/High AWS rules: the target rule must fire on the
// vulnerable fixture, and the secure fixture must produce zero medium+
// findings. Fixtures live in testdata/<rule-id>/{vulnerable,secure}.tf with
// the scanner's actual medium+ rule IDs recorded in expected.json.
package regression

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"aegis/internal/adapter/terraform"
	"aegis/internal/ir"
	"aegis/internal/rules"
	"aegis/internal/semantics"
)

// labeledRules are the top-20 Critical/High AWS rule IDs (9 critical, then
// the 11 lowest-numbered high), each with a paired fixture directory.
var labeledRules = []string{
	"AEGIS-AWS-003", "AEGIS-AWS-006", "AEGIS-AWS-101", "AEGIS-AWS-104",
	"AEGIS-AWS-202", "AEGIS-AWS-501", "AEGIS-AWS-502", "AEGIS-AWS-534",
	"AEGIS-AWS-629", "AEGIS-AWS-001", "AEGIS-AWS-002", "AEGIS-AWS-004",
	"AEGIS-AWS-007", "AEGIS-AWS-011", "AEGIS-AWS-102", "AEGIS-AWS-103",
	"AEGIS-AWS-105", "AEGIS-AWS-201", "AEGIS-AWS-203", "AEGIS-AWS-204",
}

type labeledExpected struct {
	Vulnerable struct {
		Findings []string `json:"findings"`
	} `json:"vulnerable"`
	Secure struct {
		Findings []string `json:"findings"`
	} `json:"secure"`
}

// mediumPlus mirrors the corpus FP definition: a secure fixture must not
// produce critical, high, or medium findings. Low/info hygiene rules are
// out of scope for this gate.
func mediumPlus(s ir.Severity) bool {
	return s == ir.SeverityCritical || s == ir.SeverityHigh || s == ir.SeverityMedium
}

func scanLabeledFixture(t *testing.T, ruleID, side string) []ir.Finding {
	t.Helper()
	path := filepath.Join("testdata", ruleID, side+".tf")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s/%s: reading fixture: %v", ruleID, side, err)
	}
	mod, diags, err := terraform.New().ParseModule(side+".tf", src)
	if err != nil {
		t.Fatalf("%s/%s: parse hard error: %v", ruleID, side, err)
	}
	for _, d := range diags {
		if d.Level == "error" {
			t.Fatalf("%s/%s: parse error diagnostic: %s", ruleID, side, d.Message)
		}
	}
	resources := append([]ir.Resource{}, mod.Resources...)
	resources = append(resources, mod.SyntheticResources...)
	scope := semantics.MergeModules([]terraform.Module{mod})
	resources = scope.ResolveResources(resources)
	findings := rules.DefaultRegistry().Run(resources)
	if findings == nil {
		findings = []ir.Finding{}
	}
	return findings
}

func findingRuleIDs(fs []ir.Finding, onlyMediumPlus bool) []string {
	seen := map[string]bool{}
	for _, f := range fs {
		if onlyMediumPlus && !mediumPlus(f.Severity) {
			continue
		}
		seen[f.RuleID] = true
	}
	var out []string
	for id := range seen {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func TestLabeledPairs(t *testing.T) {
	for _, ruleID := range labeledRules {
		ruleID := ruleID
		t.Run(ruleID, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", ruleID, "expected.json"))
			if err != nil {
				t.Fatalf("expected.json missing for %s", ruleID)
			}
			var want labeledExpected
			if err := json.Unmarshal(raw, &want); err != nil {
				t.Fatalf("%s: bad expected.json: %v", ruleID, err)
			}

			// Vulnerable side: the target rule must fire, and every
			// recorded medium+ finding must still fire (subset check:
			// new rules may legitimately appear without breaking this).
			vuln := scanLabeledFixture(t, ruleID, "vulnerable")
			gotV := findingRuleIDs(vuln, true)
			gotSet := map[string]bool{}
			for _, id := range gotV {
				gotSet[id] = true
			}
			if !gotSet[ruleID] {
				t.Errorf("vulnerable fixture: target rule %s did not fire (got %v)", ruleID, gotV)
			}
			for _, id := range want.Vulnerable.Findings {
				if !gotSet[id] {
					t.Errorf("vulnerable fixture: expected finding %s missing (got %v)", id, gotV)
				}
			}

			// Secure side: zero medium+ findings, exactly as recorded.
			sec := scanLabeledFixture(t, ruleID, "secure")
			gotS := findingRuleIDs(sec, true)
			if len(gotS) != 0 {
				t.Errorf("secure fixture: expected zero medium+ findings, got %v", gotS)
			}
			if len(want.Secure.Findings) != 0 {
				t.Errorf("expected.json for %s records secure findings %v; harden the fixture instead",
					ruleID, want.Secure.Findings)
			}

			// Sanity: the pair must actually discriminate — the target
			// rule fires on vulnerable and not on secure.
			_ = strings.Join(gotS, ",")
		})
	}
}

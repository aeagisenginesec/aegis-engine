// Package config loads the optional aegis.yaml project configuration.
//
// Supported keys:
//
//	severity_overrides:
//	  AEGIS-AWS-001: low        # downgrade a noisy rule
//	  AEGIS-AWS-004: critical   # escalate what matters to you
//	exclude_rules:
//	  - AEGIS-AWS-558           # drop a rule entirely for this project
//
// Severity overrides apply at report time: the finding keeps its rule ID,
// evidence, and remediation, but the reported severity changes. This
// affects --fail-on thresholds, text/JSON/SARIF output, and the exit code.
// Unknown rule IDs and invalid severities are reported as warnings, never
// hard errors, so a stale config cannot break a scan.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"aegis/internal/ir"
)

// Config is the decoded aegis.yaml.
type Config struct {
	SeverityOverrides map[string]string `yaml:"severity_overrides"`
	ExcludeRules      []string          `yaml:"exclude_rules"`
}

// Load reads and parses the config file at path.
func Load(path string) (*Config, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(src, &c); err != nil {
		return nil, fmt.Errorf("config: invalid YAML: %w", err)
	}
	if c.SeverityOverrides == nil {
		c.SeverityOverrides = map[string]string{}
	}
	return &c, nil
}

var validSeverities = map[string]ir.Severity{
	"info":     ir.SeverityInfo,
	"low":      ir.SeverityLow,
	"medium":   ir.SeverityMedium,
	"high":     ir.SeverityHigh,
	"critical": ir.SeverityCritical,
}

// excludedSet builds the exclude_rules lookup.
func (c *Config) excludedSet() map[string]bool {
	out := make(map[string]bool, len(c.ExcludeRules))
	for _, id := range c.ExcludeRules {
		out[strings.TrimSpace(id)] = true
	}
	return out
}

// Apply rewrites finding severities per severity_overrides and drops
// findings for exclude_rules. It returns the rewritten findings and any
// warnings (unknown rule IDs, invalid severity values).
func (c *Config) Apply(findings []ir.Finding) ([]ir.Finding, []ir.Diagnostic) {
	if c == nil {
		return findings, nil
	}
	excluded := c.excludedSet()
	// Normalize override keys/values once; warn on problems.
	overrides := make(map[string]ir.Severity, len(c.SeverityOverrides))
	var diags []ir.Diagnostic
	for id, sev := range c.SeverityOverrides {
		id = strings.TrimSpace(id)
		s, ok := validSeverities[strings.ToLower(strings.TrimSpace(sev))]
		if !ok {
			diags = append(diags, ir.Diagnostic{
				Level:   "warning",
				Message: fmt.Sprintf("config: invalid severity %q for rule %s; ignored (want info|low|medium|high|critical)", sev, id),
			})
			continue
		}
		overrides[id] = s
	}
	seen := map[string]bool{}
	out := findings[:0]
	for _, f := range findings {
		if excluded[f.RuleID] {
			continue
		}
		if s, ok := overrides[f.RuleID]; ok {
			seen[f.RuleID] = true
			f.Severity = s
		}
		out = append(out, f)
	}
	// Warn about overrides that matched no finding: usually a typo'd rule ID
	// or a rule that simply didn't fire on this codebase.
	for id := range overrides {
		if !seen[id] {
			diags = append(diags, ir.Diagnostic{
				Level:   "warning",
				Message: fmt.Sprintf("config: severity override for %s matched no findings; check the rule ID", id),
			})
		}
	}
	return out, diags
}

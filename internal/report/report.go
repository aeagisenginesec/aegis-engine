// Package report renders ir.ScanResult in the formats Aegis supports.
//
// All writers redact secret-looking evidence values before emitting them:
// any evidence attribute whose key contains password, secret, token or key
// (case-insensitive) has its Actual value replaced with [REDACTED].
// Reports must never leak credentials, even when a rule legitimately
// inspects a sensitive attribute.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"aegis/internal/ir"
	"aegis/internal/version"
)

// Version is stamped into every report envelope.
const Version = version.Version

// redactedValue is the placeholder written for secret-looking values.
const redactedValue = "[REDACTED]"

// secretKey reports whether an attribute key looks secret-bearing.
func secretKey(key string) bool {
	k := strings.ToLower(key)
	for _, sub := range []string{"password", "passwd", "secret", "token", "apikey", "api_key", "key"} {
		if strings.Contains(k, sub) {
			return true
		}
	}
	return false
}

// redactFindings returns a copy of fs with secret-looking evidence redacted.
func redactFindings(fs []ir.Finding) []ir.Finding {
	out := make([]ir.Finding, 0, len(fs))
	for _, f := range fs {
		if secretKey(f.Evidence.Attribute) {
			f.Evidence.Actual = redactedValue
		}
		out = append(out, f)
	}
	return out
}

// jsonEnvelope is the versioned JSON report format.
type jsonEnvelope struct {
	Version      string               `json:"aegis_version"`
	Target       string               `json:"target"`
	Resources    int                  `json:"resources_scanned"`
	Findings     []ir.Finding         `json:"findings"`
	Diagnostics  []ir.Diagnostic      `json:"diagnostics"`
	Completeness ir.ScanCompleteness  `json:"scan_completeness"`
}

// WriteJSON writes the versioned JSON envelope.
func WriteJSON(w io.Writer, res ir.ScanResult) error {
	diags := res.Diagnostics
	if diags == nil {
		diags = []ir.Diagnostic{}
	}
	env := jsonEnvelope{
		Version:      Version,
		Target:       res.Target,
		Resources:    res.Resources,
		Findings:     redactFindings(res.Findings),
		Diagnostics:  diags,
		Completeness: res.Completeness,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(env)
}

// sarif types — minimal valid SARIF 2.1.0 shape.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription sarifMessage      `json:"shortDescription"`
	Help             sarifMessage      `json:"help,omitempty"`
	HelpURI          string            `json:"helpUri,omitempty"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

// sarifLevel maps Aegis severity to SARIF level.
func sarifLevel(s ir.Severity) string {
	switch s {
	case ir.SeverityCritical, ir.SeverityHigh:
		return "error"
	case ir.SeverityMedium:
		return "warning"
	default: // low, info, and anything unknown
		return "note"
	}
}

// WriteAttackPathsJSON writes only findings that carry attack paths,
// as a focused JSON document for kill-chain consumers.
func WriteAttackPathsJSON(w io.Writer, res ir.ScanResult) error {
	findings := filterPathFindings(res.Findings)
	env := jsonEnvelope{
		Version:     Version,
		Target:      res.Target,
		Resources:   res.Resources,
		Findings:    redactFindings(findings),
		Diagnostics: res.Diagnostics,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(env)
}

// WriteAttackPathsText renders only findings with attack paths as ASCII
// kill-chain diagrams.
func WriteAttackPathsText(w io.Writer, res ir.ScanResult) error {
	findings := filterPathFindings(res.Findings)
	fmt.Fprintf(w, "aegis attack paths: %s\n", res.Target)
	fmt.Fprintf(w, "chains: %d\n\n", len(findings))
	for _, f := range findings {
		sev := strings.ToUpper(string(f.Severity))
		fmt.Fprintf(w, "%s %s — %s\n", sev, f.RuleID, f.Title)
		fmt.Fprintf(w, "%s\n", renderPathASCII(f))
		fmt.Fprintf(w, "---\n\n")
	}
	if len(findings) == 0 {
		fmt.Fprintf(w, "No complete attack chains found.\n")
	}
	return nil
}

// filterPathFindings keeps only findings with a non-empty Path.
func filterPathFindings(fs []ir.Finding) []ir.Finding {
	var out []ir.Finding
	for _, f := range fs {
		if len(f.Path) > 0 {
			out = append(out, f)
		}
	}
	return out
}

// renderPathASCII draws a finding's Path as an ASCII chain diagram.
func renderPathASCII(f ir.Finding) string {
	var sb strings.Builder
	sb.WriteString("INTERNET\n")
	for _, step := range f.Path {
		sb.WriteString("  │\n  ▼\n")
		fmt.Fprintf(&sb, "  %s\n", step.Resource)
		fmt.Fprintf(&sb, "    %s\n", step.Detail)
		if step.Span.File != "" {
			fmt.Fprintf(&sb, "    @ %s:%d\n", step.Span.File, step.Span.StartLine)
		}
	}
	return sb.String()
}

// WriteSARIF writes a valid SARIF 2.1.0 log. Rules are derived from the
// findings' rule IDs (deduplicated); every result carries ruleId, level,
// message and a physical location with region.
func WriteSARIF(w io.Writer, res ir.ScanResult) error {
	findings := redactFindings(res.Findings)

	seen := map[string]bool{}
	var rules []sarifRule
	var results []sarifResult
	for _, f := range findings {
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			helpText := f.Description
			if f.Remediation != "" {
				helpText += "\n\nHow to fix:\n" + f.Remediation
			}
			helpURI := ""
			if len(f.References) > 0 {
				helpURI = f.References[0]
			}
			rules = append(rules, sarifRule{
				ID:               f.RuleID,
				Name:             f.Title,
				ShortDescription: sarifMessage{Text: f.Title},
				Help:             sarifMessage{Text: helpText},
				HelpURI:          helpURI,
				Properties:       map[string]string{"severity": string(f.Severity)},
			})
		}
		span := f.Evidence.Span
		results = append(results, sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: fmt.Sprintf("%s (%s)", f.Title, f.Resource)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: span.File},
					Region: sarifRegion{
						StartLine:   span.StartLine,
						StartColumn: span.StartCol,
						EndLine:     span.EndLine,
						EndColumn:   span.EndCol,
					},
				},
			}},
		})
	}
	if rules == nil {
		rules = []sarifRule{}
	}
	if results == nil {
		results = []sarifResult{}
	}
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "aegis",
				Version:        Version,
				InformationURI: "https://github.com/aegis/engine",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// WriteText writes the human-readable report. One finding per entry:
//
//	SEVERITY rule-id file:line — title
//	  evidence: attribute = "actual" (expected "expected") in resource.address
//
// followed by a summary line and any diagnostics.
func WriteText(w io.Writer, res ir.ScanResult) error {
	findings := redactFindings(res.Findings)
	fmt.Fprintf(w, "aegis scan: %s\n", res.Target)
	fmt.Fprintf(w, "resources: %d, findings: %d\n", res.Resources, len(findings))
	// Scan-completeness: distinguish "zero findings" from "incomplete scan"
	c := res.Completeness
	if c.FilesDiscovered > 0 {
		fmt.Fprintf(w, "files: %d discovered, %d parsed",
			c.FilesDiscovered, c.FilesParsed)
		if c.FilesSkipped > 0 {
			fmt.Fprintf(w, ", %d skipped", c.FilesSkipped)
		}
		if c.FilesFailed > 0 {
			fmt.Fprintf(w, ", %d FAILED", c.FilesFailed)
		}
		fmt.Fprintf(w, "\n")
		if !c.Complete() {
			fmt.Fprintf(w, "WARNING: incomplete scan — %d file(s) could not be parsed. "+
				"\"0 findings\" does not mean \"clean\".\n", c.FilesFailed)
			for _, f := range c.Files {
				if f.Status == "failed" {
					fmt.Fprintf(w, "  failed: %s (%s)\n", f.Path, f.Reason)
				}
			}
		}
	}
	for _, f := range findings {
		sev := strings.ToUpper(string(f.Severity))
		fmt.Fprintf(w, "%s %s %s:%d — %s\n",
			sev, f.RuleID, f.Evidence.Span.File, f.Evidence.Span.StartLine, f.Title)
		ev := f.Evidence
		fmt.Fprintf(w, "  evidence: %s = %q (expected %q) in %s\n",
			ev.Attribute, ev.Actual, ev.Expected, f.Resource)
		if len(f.Compliance) > 0 {
			fmt.Fprintf(w, "  compliance:")
			for _, c := range f.Compliance {
				fmt.Fprintf(w, " %s:%s", c.Framework, c.Control)
			}
			fmt.Fprintf(w, "\n")
		}
		if len(f.Path) > 0 {
			fmt.Fprintf(w, "  attack path:\n")
			for _, step := range f.Path {
				fmt.Fprintf(w, "    → %s — %s\n", step.Resource, step.Detail)
			}
		}
		if f.Remediation != "" {
			fmt.Fprintf(w, "  fix:\n")
			for _, line := range strings.Split(f.Remediation, "\n") {
				fmt.Fprintf(w, "    %s\n", line)
			}
		}
		if len(f.References) > 0 {
			fmt.Fprintf(w, "  learn more:\n")
			for _, ref := range f.References {
				fmt.Fprintf(w, "    %s\n", ref)
			}
		}
	}
	if len(res.Diagnostics) > 0 {
		fmt.Fprintf(w, "diagnostics: %d\n", len(res.Diagnostics))
		for _, d := range res.Diagnostics {
			fmt.Fprintf(w, "  [%s] %s:%d — %s\n", d.Level, d.Span.File, d.Span.StartLine, d.Message)
		}
	}
	return nil
}

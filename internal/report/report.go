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

// jsonSummary is the at-a-glance rollup every JSON report carries.
type jsonSummary struct {
	Resources       int `json:"resources"`
	FilesDiscovered int `json:"files_discovered"`
	FilesParsed     int `json:"files_parsed"`
	FilesSkipped    int `json:"files_skipped"`
	Findings        int `json:"findings"`
	Critical        int `json:"critical"`
	High            int `json:"high"`
	Medium          int `json:"medium"`
	Low             int `json:"low"`
}

// summarize rolls findings and completeness into a jsonSummary.
func summarize(res ir.ScanResult) jsonSummary {
	s := jsonSummary{
		Resources:       res.Resources,
		FilesDiscovered: res.Completeness.FilesDiscovered,
		FilesParsed:     res.Completeness.FilesParsed,
		FilesSkipped:    res.Completeness.FilesSkipped,
		Findings:        len(res.Findings),
	}
	for _, f := range res.Findings {
		switch f.Severity {
		case ir.SeverityCritical:
			s.Critical++
		case ir.SeverityHigh:
			s.High++
		case ir.SeverityMedium:
			s.Medium++
		case ir.SeverityLow:
			s.Low++
		}
	}
	return s
}

// jsonFinding is the flattened, human-scannable JSON finding shape.
// Location is hoisted to top-level file/line instead of a nested span,
// and evidence is a single readable string.
type jsonFinding struct {
	RuleID      string             `json:"rule_id"`
	Severity    string             `json:"severity"`
	Title       string             `json:"title"`
	Description string             `json:"description"`
	Resource    string             `json:"resource"`
	File        string             `json:"file"`
	Line        int                `json:"line"`
	Evidence    string             `json:"evidence"`
	Expected    string             `json:"expected,omitempty"`
	Remediation string             `json:"remediation,omitempty"`
	References  []string           `json:"references,omitempty"`
	Compliance  []ir.ComplianceRef `json:"compliance,omitempty"`
	Path        []ir.PathStep      `json:"path,omitempty"`
}

// flattenFinding converts an ir.Finding to the flat JSON shape.
// Callers must pass findings through redactFindings first.
func flattenFinding(f ir.Finding) jsonFinding {
	ev := f.Evidence.Actual
	if f.Evidence.Attribute != "" {
		ev = f.Evidence.Attribute + " = " + ev
	}
	return jsonFinding{
		RuleID:      f.RuleID,
		Severity:    string(f.Severity),
		Title:       f.Title,
		Description: f.Description,
		Resource:    f.Resource,
		File:        f.Evidence.Span.File,
		Line:        f.Evidence.Span.StartLine,
		Evidence:    ev,
		Expected:    f.Evidence.Expected,
		Remediation: f.Remediation,
		References:  f.References,
		Compliance:  f.Compliance,
		Path:        f.Path,
	}
}

// flattenFindings converts a redacted finding list to the flat JSON shape.
func flattenFindings(fs []ir.Finding) []jsonFinding {
	out := make([]jsonFinding, 0, len(fs))
	for _, f := range fs {
		out = append(out, flattenFinding(f))
	}
	return out
}

// jsonEnvelope is the versioned JSON report format.
type jsonEnvelope struct {
	Version           string                `json:"aegis_version"`
	Target            string                `json:"target"`
	Summary           jsonSummary           `json:"summary"`
	Findings          []jsonFinding         `json:"findings"`
	Diagnostics       []ir.Diagnostic       `json:"diagnostics"`
	Completeness      ir.ScanCompleteness   `json:"scan_completeness"`
	ComplianceSummary *ir.ComplianceSummary `json:"compliance_summary,omitempty"`
}

// WriteJSON writes the versioned JSON envelope.
func WriteJSON(w io.Writer, res ir.ScanResult) error {
	diags := res.Diagnostics
	if diags == nil {
		diags = []ir.Diagnostic{}
	}
	redacted := redactFindings(res.Findings)
	env := jsonEnvelope{
		Version:           Version,
		Target:            res.Target,
		Summary:           summarize(res),
		Findings:          flattenFindings(redacted),
		Diagnostics:       diags,
		Completeness:      res.Completeness,
		ComplianceSummary: res.ComplianceSummary,
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
	redacted := redactFindings(findings)
	filtered := res
	filtered.Findings = redacted
	env := jsonEnvelope{
		Version:     Version,
		Target:      res.Target,
		Summary:     summarize(filtered),
		Findings:    flattenFindings(redacted),
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

// TextOptions controls WriteText rendering.
type TextOptions struct {
	// Color enables ANSI colors for severity. The CLI enables it when
	// stdout is a terminal (see --color); it stays off when piped so
	// redirected output remains plain text.
	Color bool
}

// ansi wraps s in an ANSI color sequence when color is enabled.
func ansi(color bool, code, s string) string {
	if !color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// severityColor returns the ANSI code for a severity level.
func severityColor(sev ir.Severity) string {
	switch sev {
	case ir.SeverityCritical:
		return "1;91" // bold bright red
	case ir.SeverityHigh:
		return "38;5;208" // orange (256-color)
	case ir.SeverityMedium:
		return "33" // yellow
	case ir.SeverityLow:
		return "32" // green
	default:
		return "0"
	}
}

// WriteText writes the human-readable report. One finding per entry:
//
//	SEVERITY rule-id file:line — title
//	  evidence: attribute = "actual" (expected "expected") in resource.address
//
// followed by a summary line and any diagnostics.
func WriteText(w io.Writer, res ir.ScanResult) error {
	return WriteTextWithOptions(w, res, TextOptions{})
}

// WriteTextWithOptions writes the human-readable report. Findings are
// grouped severity-first (critical, high, medium, low), each rendered as
// a card separated from the next by a blank line. When opts.Color is set,
// severity headers, rollup counts and rule IDs are ANSI-colored.
func WriteTextWithOptions(w io.Writer, res ir.ScanResult, opts TextOptions) error {
	findings := redactFindings(res.Findings)
	s := summarize(res)

	fmt.Fprintf(w, "Aegis %s - scan: %s\n", Version, res.Target)
	fmt.Fprintf(w, "================================================================\n")
	c := res.Completeness
	if c.FilesDiscovered > 0 {
		fmt.Fprintf(w, "  files:     %d discovered, %d parsed",
			c.FilesDiscovered, c.FilesParsed)
		if c.FilesSkipped > 0 {
			fmt.Fprintf(w, ", %d skipped", c.FilesSkipped)
		}
		if c.FilesFailed > 0 {
			fmt.Fprintf(w, ", %d FAILED", c.FilesFailed)
		}
		fmt.Fprintf(w, "\n")
	}
	fmt.Fprintf(w, "  resources: %d\n", res.Resources)
	fmt.Fprintf(w, "  findings:  %d  (%s %d, %s %d, %s %d, %s %d)\n",
		s.Findings,
		ansi(opts.Color, severityColor(ir.SeverityCritical), "critical"), s.Critical,
		ansi(opts.Color, severityColor(ir.SeverityHigh), "high"), s.High,
		ansi(opts.Color, severityColor(ir.SeverityMedium), "medium"), s.Medium,
		ansi(opts.Color, severityColor(ir.SeverityLow), "low"), s.Low)
	fmt.Fprintf(w, "================================================================\n")
	if !c.Complete() && c.FilesDiscovered > 0 {
		fmt.Fprintf(w, "WARNING: incomplete scan - %d file(s) could not be parsed. "+
			"\"0 findings\" does not mean \"clean\".\n", c.FilesFailed)
		for _, f := range c.Files {
			if f.Status == "failed" {
				fmt.Fprintf(w, "  failed: %s (%s)\n", f.Path, f.Reason)
			}
		}
	}

	// Group findings by severity, most severe first.
	ordered := []ir.Severity{
		ir.SeverityCritical, ir.SeverityHigh, ir.SeverityMedium, ir.SeverityLow,
	}
	seen := map[ir.Severity]bool{}
	var rest []ir.Finding
	groups := map[ir.Severity][]ir.Finding{}
	for _, f := range findings {
		known := false
		for _, sev := range ordered {
			if f.Severity == sev {
				known = true
				break
			}
		}
		if known {
			groups[f.Severity] = append(groups[f.Severity], f)
			seen[f.Severity] = true
		} else {
			rest = append(rest, f)
		}
	}
	for _, sev := range ordered {
		fs := groups[sev]
		if len(fs) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n%s\n", ansi(opts.Color, severityColor(sev),
			fmt.Sprintf("%s (%d)", strings.ToUpper(string(sev)), len(fs))))
		fmt.Fprintf(w, "----------------------------------------------------------------\n")
		for _, f := range fs {
			writeTextFinding(w, f, opts)
		}
	}
	if len(rest) > 0 {
		fmt.Fprintf(w, "\n%s\n", ansi(opts.Color, "1", fmt.Sprintf("OTHER (%d)", len(rest))))
		fmt.Fprintf(w, "----------------------------------------------------------------\n")
		for _, f := range rest {
			writeTextFinding(w, f, opts)
		}
	}
	if len(res.Diagnostics) > 0 {
		fmt.Fprintf(w, "\ndiagnostics: %d\n", len(res.Diagnostics))
		for _, d := range res.Diagnostics {
			fmt.Fprintf(w, "  [%s] %s:%d - %s\n", d.Level, d.Span.File, d.Span.StartLine, d.Message)
		}
	}
	if cs := res.ComplianceSummary; cs != nil {
		fmt.Fprintf(w, "\ncompliance %s: %d/%d controls passing", cs.Framework, cs.ControlsPassing, cs.ControlsTotal)
		if cs.ControlsFailing > 0 {
			fmt.Fprintf(w, " - FAILING: %s", strings.Join(cs.FailedControls, ", "))
		}
		fmt.Fprintf(w, "\n")
	}
	return nil
}

// writeTextFinding renders one finding as a compact card, followed by a
// blank line so cards never run together.
func writeTextFinding(w io.Writer, f ir.Finding, opts TextOptions) {
	ev := f.Evidence
	loc := ev.Span.File
	if ev.Span.StartLine > 0 {
		loc = fmt.Sprintf("%s:%d", loc, ev.Span.StartLine)
	}
	fmt.Fprintf(w, "  %s  %s\n", ansi(opts.Color, "1", f.RuleID), f.Title)
	fmt.Fprintf(w, "    %s  %s\n", loc, f.Resource)
	evidence := ev.Actual
	if ev.Attribute != "" {
		evidence = ev.Attribute + " = " + evidence
	}
	if ev.Expected != "" {
		evidence += fmt.Sprintf("  (expected: %s)", ev.Expected)
	}
	fmt.Fprintf(w, "    evidence: %s\n", evidence)
	if len(f.Compliance) > 0 {
		fmt.Fprintf(w, "    compliance:")
		for _, cc := range f.Compliance {
			fmt.Fprintf(w, " %s:%s", cc.Framework, cc.Control)
		}
		fmt.Fprintf(w, "\n")
	}
	if len(f.Path) > 0 {
		fmt.Fprintf(w, "    attack path:\n")
		for _, step := range f.Path {
			fmt.Fprintf(w, "      -> %s - %s\n", step.Resource, step.Detail)
		}
	}
	if f.Remediation != "" {
		lines := strings.Split(strings.TrimSpace(f.Remediation), "\n")
		fmt.Fprintf(w, "    fix: %s\n", strings.TrimSpace(lines[0]))
		for _, line := range lines[1:] {
			fmt.Fprintf(w, "         %s\n", strings.TrimRight(line, " \t"))
		}
	}
	if len(f.References) > 0 {
		for _, ref := range f.References {
			fmt.Fprintf(w, "    see: %s\n", ref)
		}
	}
	fmt.Fprintf(w, "\n")
}

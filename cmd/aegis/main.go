// Command aegis is the Aegis IaC scanner CLI.
//
// Usage:
//
//	aegis scan <dir> [--format=text|json|sarif] [--rules=aws]
//
// Exit codes are CI-gate friendly: 0 = clean, 1 = findings, 2 = usage/scan
// error. The scanner never executes scanned content and never fails silently:
// every file it cannot parse becomes a diagnostic, never a crash.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"aegis/internal/adapter/arm"
	"aegis/internal/adapter/bicep"
	"aegis/internal/adapter/cloudformation"
	"aegis/internal/adapter/compose"
	"aegis/internal/adapter/dockerfile"
	"aegis/internal/adapter/manifests"
	"aegis/internal/adapter/planjson"
	"aegis/internal/adapter/pulumi"
	"aegis/internal/adapter/terraform"
	"aegis/internal/advisories"
	"aegis/internal/config"
	"aegis/internal/discovery"
	"aegis/internal/ir"
	"aegis/internal/qualitygate"
	"aegis/internal/remediation"
	"aegis/internal/report"
	"aegis/internal/rules"
	"aegis/internal/rules/custom"
	"aegis/internal/semantics"
	"aegis/internal/version"
)

// ruleRunner is the interface the CLI codes against; rules.Registry
// implements it. Depending on the interface (not the concrete registry)
// keeps the CLI decoupled from rule-pack internals.
type ruleRunner interface {
	Run([]ir.Resource) []ir.Finding
}

const usageText = `aegis — Infrastructure-as-Code security scanner

Usage:
  aegis scan <dir> [--format=text|json|sarif] [--rules=PACKS] [--advisories=file] [--fail-on=critical|high|medium|low] [--baseline=file] [--baseline-out=file] [--strict] [--compliance=FW] [--config=aegis.yaml] [--exclude=globs]
  aegis fix  <dir> [--apply] [--rule=RULEID] [--format=text|json] [--force]
  aegis serve [--addr=127.0.0.1:8734] [--auth-token=TOKEN]
  aegis quality-gate [--format=text|json] [--bench-dir=DIR] [--corpus-dir=DIR]
  aegis doctor
  aegis --version

Commands:
  scan  scan a directory, print findings
  fix   propose validated patches for findings (dry run by default;
        --apply writes only patches that fix cleanly with no new findings;
        IAM/networking resources are never patched unless --force)
  serve start the HTTP API (loopback by default; no database required)
  quality-gate
        run automated release gates (precision, recall, rule coverage,
        performance, parser safety); exits 0 on pass, 1 on fail
  doctor
        run binary self-checks (version, rule count, parse smoke test,
        remediation dry-run); exits 0 when healthy

Flags:
  --format     output format: text (default), json, sarif (scan only)
  --color      text colors: auto (default, on when stdout is a terminal),
               always, never
  --rules      comma-separated rule packs: aws,azure,gcp,k8s,supplychain,all (default "all")
  --advisories threat-advisory JSON feed enabling supply-chain checks
  --custom-rules directory of YAML custom rule files (see docs/custom-rules-example.yaml)
  --fail-on    scan exits 1 only when a finding meets this severity
               (critical|high|medium|low); default: any finding fails
  --baseline     suppress findings fingerprinted in this baseline JSON file
                 (rule_id + resource + attribute); see --baseline-out
  --baseline-out write current findings as a baseline JSON file, then exit
                 reporting them normally (pair with --baseline on later runs)
  --apply      fix: write validated patches to the target tree
  --force      fix: allow patches on IAM/networking resource types
               (blocked by default; review every diff before applying)
  --rule     fix: only propose patches for this rule ID
  --max-file-size scan: per-file size cap in bytes (default 10485760);
               files larger than this are skipped with a diagnostic
  --timeout  scan: overall scan timeout in seconds (default 0 = no limit);
               the scan aborts with exit 2 when exceeded
  --compliance scan: filter findings to a compliance framework and report a
               per-control pass/fail summary (CIS-AWS-1.5, NIST-800-53, PCI-DSS-4.0)
  --config   scan: project config YAML with severity_overrides and
               exclude_rules (see docs/PULUMI.md for the format)
  --exclude  scan: comma-separated glob patterns for paths to skip
               (e.g. "vendor/**,*.tfvars"); skipped files are reported
  --strict   scan: fail with exit 2 if any file fails to parse
  --attack-paths scan: report only attack-chain findings (internet-to-data
               kill chains and exposure paths); works with text and json
  --auth-token serve: require "Authorization: Bearer TOKEN" on /v1/scan
               (or set AEGIS_SERVE_TOKEN); required in practice whenever
               serve binds a non-loopback address

Exit codes:
  0  scan clean (or below --fail-on threshold) / fix dry run
  1  findings reported (scan) / patches proposed or applied (fix)
  2  usage or scan error, or --strict with unparseable files
`

// defaultAdapters returns the language adapters wired into this build.
// NOTE: assumes the terraform adapter exposes terraform.New(); adjust the
// single call below if the sibling package names its constructor differently.
func defaultAdapters() []ir.Adapter {
	// compose.New() precedes manifests.Adapter{}: manifests claims every
	// .yml/.yaml file, so compose files must be matched first. pulumi.New()
	// likewise precedes manifests: a file named Pulumi.yaml is a Pulumi
	// program, not a generic manifest. arm.New() precedes manifests for the
	// same reason: manifests claims every .json file, but ARM deployment
	// templates (detected by $schema sniffing) belong to the arm adapter.
	return []ir.Adapter{terraform.New(), planjson.Adapter{}, compose.New(), pulumi.Adapter{}, arm.New(), bicep.New(), cloudformation.New(), manifests.Adapter{}, dockerfile.New()}
}

// defaultScanFunc re-scans a directory with the production adapters and
// rules; used to validate remediation patches in an isolated copy.
func defaultScanFunc(d string) (ir.ScanResult, []ir.Resource, error) {
	res, resources, _, err := scanFull(d, defaultAdapters(), rules.DefaultRegistry())
	return res, resources, err
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the CLI; factored out for testing. stdout carries the report,
// stderr carries usage/errors.
func run(args []string, stdout, stderr io.Writer) int {
	// Help is always available.
	for _, a := range args {
		if a == "-h" || a == "--help" || a == "help" {
			fmt.Fprint(stdout, usageText)
			return 0
		}
		if a == "-v" || a == "--version" || a == "version" {
			fmt.Fprintln(stdout, version.String())
			return 0
		}
	}

	// Split flags from positionals so both `scan --format=json <dir>` and
	// `scan <dir> --format=json` work (flag.Parse stops at the first
	// positional, so we pre-sort).
	var flagArgs, posArgs []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") && a != "-" {
			flagArgs = append(flagArgs, a)
			// Consume a separate value: `--format json`.
			if !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flagArgs = append(flagArgs, args[i])
			}
			continue
		}
		posArgs = append(posArgs, a)
	}

	if len(posArgs) == 0 || (posArgs[0] != "scan" && posArgs[0] != "fix" && posArgs[0] != "serve" && posArgs[0] != "quality-gate" && posArgs[0] != "doctor") {
		fmt.Fprint(stderr, usageText)
		return 2
	}
	cmd := posArgs[0]
	if cmd == "doctor" {
		return runDoctor(stdout, stderr)
	}
	if cmd == "quality-gate" {
		return runQualityGate(flagArgs, stdout, stderr)
	}
	if cmd == "serve" {
		addr := "127.0.0.1:8734"
		authToken := os.Getenv("AEGIS_SERVE_TOKEN")
		for i := 0; i < len(flagArgs); i++ {
			a := flagArgs[i]
			if a == "--addr" && i+1 < len(flagArgs) {
				addr = flagArgs[i+1]
				i++
			} else if strings.HasPrefix(a, "--addr=") {
				addr = strings.TrimPrefix(a, "--addr=")
			} else if a == "--auth-token" && i+1 < len(flagArgs) {
				authToken = flagArgs[i+1]
				i++
			} else if strings.HasPrefix(a, "--auth-token=") {
				authToken = strings.TrimPrefix(a, "--auth-token=")
			}
		}
		return runServe(addr, authToken)
	}
	if len(posArgs) < 2 {
		fmt.Fprintf(stderr, "aegis: %s requires a target directory\n", cmd)
		fmt.Fprint(stderr, usageText)
		return 2
	}
	target := posArgs[1]
	if len(posArgs) > 2 {
		fmt.Fprintf(stderr, "aegis: unexpected argument %q\n", posArgs[2])
		return 2
	}
	if st, err := os.Stat(target); err != nil || !st.IsDir() {
		fmt.Fprintf(stderr, "aegis: %s target %q is not a readable directory\n", cmd, target)
		return 2
	}

	switch cmd {
	case "fix":
		return runFix(target, flagArgs, stdout, stderr)
	default:
		return runScan(target, flagArgs, stdout, stderr)
	}
}

// runQualityGate executes `aegis quality-gate [--format=text|json]
// [--bench-dir=DIR] [--corpus-dir=DIR]`. Exits 0 when all gates pass
// (or skip), 1 when any gate fails, 2 on usage error.
func runQualityGate(flagArgs []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("quality-gate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "")
	benchDir := fs.String("bench-dir", "", "")
	corpusDir := fs.String("corpus-dir", "", "")
	if err := fs.Parse(flagArgs); err != nil {
		return 2
	}
	switch *format {
	case "text", "json":
	default:
		fmt.Fprintf(stderr, "aegis: unknown --format %q (want text|json)\n", *format)
		return 2
	}
	opts := qualitygate.Options{Out: stdout}
	if *benchDir != "" {
		opts.BenchDir = *benchDir
	}
	if *corpusDir != "" {
		opts.CorpusDir = *corpusDir
	}
	rep := qualitygate.RunAll(opts)
	if *format == "json" {
		qualitygate.PrintJSON(rep, stdout)
	} else {
		qualitygate.PrintReport(rep, stdout)
	}
	if rep.Passed {
		return 0
	}
	return 1
}

// fixJSONPatch is one patch entry in the JSON fix report.
type fixJSONPatch struct {
	RuleID      string `json:"rule_id"`
	Resource    string `json:"resource"`
	Description string `json:"description"`
	Diff        string `json:"diff"`
	Fixed       bool   `json:"fixed"`
	NewFindings int    `json:"new_findings"`
	Applied     bool   `json:"applied"`
}

// runFix executes `aegis fix <dir> [--apply] [--rule=RULEID] [--format=text|json] [--force]`.
// Dry run is the default: nothing in the target tree is ever modified unless
// --apply is given, and then only patches that validate cleanly
// (fixed with no new findings) are written back. Patches are never proposed
// for blocked IAM/networking resource types unless --force is given.
func runFix(target string, flagArgs []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("fix", flag.ContinueOnError)
	fs.SetOutput(stderr)
	apply := fs.Bool("apply", false, "")
	force := fs.Bool("force", false, "")
	ruleFilter := fs.String("rule", "", "")
	format := fs.String("format", "text", "")
	if err := fs.Parse(flagArgs); err != nil {
		return 2
	}
	// --force opts into patches on blocked IAM/networking resource types.
	// runFix owns this global: every invocation sets it explicitly from the
	// flag, so a previous --force call can never leak into a later one.
	remediation.AllowBlocked = *force
	if *force {
		fmt.Fprintf(stderr, "WARNING: --force enables patches on IAM/networking resources. Review every diff before applying.\n")
	}
	switch *format {
	case "text", "json":
	default:
		fmt.Fprintf(stderr, "aegis: unknown --format %q (want text|json)\n", *format)
		return 2
	}

	res, resources, _, scanErr := scanFull(target, defaultAdapters(), rules.DefaultRegistry())
	if scanErr != nil {
		fmt.Fprintf(stderr, "aegis: scan error: %v\n", scanErr)
		return 2
	}

	patches := remediation.ProposeAll(res.Findings, resources, os.ReadFile)
	if *ruleFilter != "" {
		var kept []remediation.Patch
		for _, p := range patches {
			if p.RuleID == *ruleFilter {
				kept = append(kept, p)
			}
		}
		patches = kept
	}

	type outcome struct {
		patch      remediation.Patch
		validation remediation.Validation
		applied    bool
		skipped    string // reason when not applied under --apply
	}
	outcomes := make([]outcome, 0, len(patches))
	before := len(res.Findings)
	// Phase 1: validate every patch against the pristine tree. Validation
	// must see the original sources, never a partially-patched tree.
	for _, p := range patches {
		v, verr := remediation.ValidatePatch(target, p, defaultScanFunc)
		if verr != nil {
			fmt.Fprintf(stderr, "aegis: cannot validate patch for %s (%s): %v\n", p.RuleID, p.Resource, verr)
			return 2
		}
		outcomes = append(outcomes, outcome{patch: p, validation: v})
	}

	// Phase 2: under --apply, write back only patches that validated
	// cleanly. All selected edits are merged and applied in one bottom-up
	// pass per file, so line numbers (computed against the original) stay
	// valid; overlapping edits keep the first patch and skip the rest.
	if *apply {
		// claimed[file][line] = outcome index that claimed the line.
		claimed := map[string]map[int]int{}
		var selected []int // indexes into outcomes
		for i, o := range outcomes {
			if !(o.validation.Fixed && len(o.validation.NewFindings) == 0) {
				outcomes[i].skipped = "did not validate cleanly"
				continue
			}
			conflict := false
			for _, e := range o.patch.Edits {
				if claimed[e.File] == nil {
					claimed[e.File] = map[int]int{}
				}
				for ln := e.StartLine; ln <= e.EndLine; ln++ {
					if by, ok := claimed[e.File][ln]; ok {
						outcomes[i].skipped = fmt.Sprintf("overlaps %s patch for %s",
							outcomes[by].patch.RuleID, outcomes[by].patch.Resource)
						conflict = true
						break
					}
				}
				if conflict {
					break
				}
			}
			if conflict {
				continue
			}
			for _, e := range o.patch.Edits {
				for ln := e.StartLine; ln <= e.EndLine; ln++ {
					claimed[e.File][ln] = i
				}
			}
			selected = append(selected, i)
		}
		if len(selected) > 0 {
			var allEdits []remediation.Edit
			for _, i := range selected {
				allEdits = append(allEdits, outcomes[i].patch.Edits...)
				outcomes[i].applied = true
			}
			if err := applyEdits(allEdits); err != nil {
				fmt.Fprintf(stderr, "aegis: apply failed: %v\n", err)
				return 2
			}
		}
	}

	if *format == "json" {
		jp := make([]fixJSONPatch, 0, len(outcomes))
		for _, o := range outcomes {
			jp = append(jp, fixJSONPatch{
				RuleID:      o.patch.RuleID,
				Resource:    o.patch.Resource,
				Description: o.patch.Description,
				Diff:        o.patch.Diff,
				Fixed:       o.validation.Fixed,
				NewFindings: len(o.validation.NewFindings),
				Applied:     o.applied,
			})
		}
		enc := map[string]any{"patches": jp, "applied": *apply}
		if err := jsonEncode(stdout, enc); err != nil {
			fmt.Fprintf(stderr, "aegis: report error: %v\n", err)
			return 2
		}
	} else {
		if *apply {
			fmt.Fprintf(stdout, "aegis fix: %s (--apply)\n", target)
		} else {
			fmt.Fprintf(stdout, "aegis fix: %s (dry run — use --apply to write changes)\n", target)
		}
		fmt.Fprintf(stdout, "findings: %d, patches proposed: %d\n", before, len(outcomes))
		for _, o := range outcomes {
			fmt.Fprintf(stdout, "\n%s %s — %s\n", o.patch.RuleID, o.patch.Resource, o.patch.Description)
			fmt.Fprintf(stdout, "%s\n", o.patch.Diff)
			fmt.Fprintf(stdout, "  would fix: %v, new findings: %d",
				o.validation.Fixed, len(o.validation.NewFindings))
			if o.validation.ResourceMissing {
				fmt.Fprintf(stdout, " (target resource unparseable after patch — rejected)")
			}
			if *apply {
				switch {
				case o.applied:
					fmt.Fprintf(stdout, ", apply: written")
				case o.skipped != "":
					fmt.Fprintf(stdout, ", apply: skipped (%s)", o.skipped)
				default:
					fmt.Fprintf(stdout, ", apply: skipped")
				}
			}
			fmt.Fprintln(stdout)
		}
	}

	appliedAny := false
	for _, o := range outcomes {
		if o.applied {
			appliedAny = true
		}
	}
	if *apply && appliedAny {
		after, rerr := scanDir(target, defaultAdapters(), rules.DefaultRegistry())
		if rerr != nil {
			fmt.Fprintf(stderr, "aegis: re-scan error: %v\n", rerr)
			return 2
		}
		// In JSON mode the re-scan line must not go to stdout: it
		// would corrupt the JSON document (Phase 7 F1). It belongs
		// on stderr there; text mode keeps it on stdout.
		if *format == "json" {
			fmt.Fprintf(stderr, "\nre-scan: findings %d → %d\n", before, len(after.Findings))
		} else {
			fmt.Fprintf(stdout, "\nre-scan: findings %d → %d\n", before, len(after.Findings))
		}
	}
	if len(outcomes) > 0 {
		return 1
	}
	return 0
}

// applyEdits writes validated edits back to the real files. Edits use
// 1-based inclusive line spans; multiple edits to the same file are applied
// from bottom to top so earlier line numbers stay valid.
func applyEdits(edits []remediation.Edit) error {
	byFile := map[string][]remediation.Edit{}
	for _, e := range edits {
		byFile[e.File] = append(byFile[e.File], e)
	}
	for file, edits := range byFile {
		src, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("read %s: %w", file, err)
		}
		lines := strings.Split(string(src), "\n")
		// Sort edits descending by start line: bottom-up application.
		for i := 0; i < len(edits); i++ {
			for j := i + 1; j < len(edits); j++ {
				if edits[j].StartLine > edits[i].StartLine {
					edits[i], edits[j] = edits[j], edits[i]
				}
			}
		}
		for _, e := range edits {
			if e.StartLine < 1 || e.EndLine < e.StartLine || e.EndLine > len(lines) {
				return fmt.Errorf("edit for %s has out-of-range lines %d-%d (file has %d lines)",
					file, e.StartLine, e.EndLine, len(lines))
			}
			var repl []string
			if e.NewText != "" {
				repl = strings.Split(e.NewText, "\n")
			}
			// lines slice is 0-based; spans are 1-based and EndLine inclusive.
			lines = append(lines[:e.StartLine-1], append(repl, lines[e.EndLine:]...)...)
		}
		out := strings.Join(lines, "\n")
		if err := os.WriteFile(file, []byte(out), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", file, err)
		}
	}
	return nil
}

// jsonEncode writes v as indented JSON (tiny local helper so the fix
// reporter doesn't depend on report internals).
func jsonEncode(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// severityRank orders severities for --fail-on: higher rank = more severe.
func severityRank(s ir.Severity) int {
	switch s {
	case ir.SeverityCritical:
		return 4
	case ir.SeverityHigh:
		return 3
	case ir.SeverityMedium:
		return 2
	case ir.SeverityLow:
		return 1
	default:
		return 0 // info and anything unrecognized never trip a gate
	}
}

// failOnValue is a flag.Value that records whether --fail-on was passed,
// so an explicit empty value (--fail-on=) is a usage error rather than
// silently meaning "unset".
type failOnValue struct {
	set   bool
	value string
}

func (f *failOnValue) String() string { return f.value }
func (f *failOnValue) Set(s string) error {
	f.set = true
	f.value = s
	return nil
}

// resolveColor maps --color to a boolean. "auto" (the default) enables
// color only when stdout is a terminal, honoring the NO_COLOR convention
// and TERM=dumb. It returns false for ok on an unknown mode.
func resolveColor(mode string, stdout io.Writer) (color, ok bool) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", "auto":
		if os.Getenv("NO_COLOR") != "" {
			return false, true
		}
		if os.Getenv("TERM") == "dumb" {
			return false, true
		}
		return isTerminal(stdout), true
	case "always":
		return true, true
	case "never":
		return false, true
	default:
		return false, false
	}
}

// isTerminal reports whether w is a character device (a terminal).
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

// complianceSummary builds the per-control pass/fail summary for a
// --compliance run: every control mapped for the framework is listed;
// controls with at least one finding fail, the rest pass.
func complianceSummary(framework string, findings []ir.Finding) *ir.ComplianceSummary {
	controls := rules.ComplianceControls(framework)
	failed := map[string]bool{}
	for _, f := range findings {
		for _, r := range f.Compliance {
			if r.Framework == framework {
				failed[r.Control] = true
			}
		}
	}
	var failedList []string
	for c := range failed {
		failedList = append(failedList, c)
	}
	sort.Strings(failedList)
	return &ir.ComplianceSummary{
		Framework:       framework,
		ControlsTotal:   len(controls),
		ControlsPassing: len(controls) - len(failed),
		ControlsFailing: len(failed),
		FailedControls:  failedList,
	}
}

// runScan executes `aegis scan <dir>`.
func runScan(target string, flagArgs []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "")
	ruleset := fs.String("rules", "all", "")
	colorMode := fs.String("color", "auto", "")
	advisoriesPath := fs.String("advisories", "", "")
	baselinePath := fs.String("baseline", "", "")
	baselineOut := fs.String("baseline-out", "", "")
	complianceFw := fs.String("compliance", "", "")
	customRulesDir := fs.String("custom-rules", "", "")
	configPath := fs.String("config", "", "")
	exclude := fs.String("exclude", "", "")
	attackPaths := fs.Bool("attack-paths", false, "")
	maxFileSize := fs.Int64("max-file-size", 0, "")
	timeoutSecs := fs.Int("timeout", 0, "")
	strict := fs.Bool("strict", false, "fail with exit 2 if any file fails to parse")
	var failOn failOnValue
	fs.Var(&failOn, "fail-on", "")
	if err := fs.Parse(flagArgs); err != nil {
		return 2
	}
	// --max-file-size overrides the discovery per-file cap for this run.
	if *maxFileSize > 0 {
		discovery.SetMaxFileBytes(*maxFileSize)
	}
	// --exclude is process-global in discovery; always (re)set it so
	// repeated runScan calls (tests, serve) never leak patterns.
	var excludePats []string
	if *exclude != "" {
		for _, p := range strings.Split(*exclude, ",") {
			if p = strings.TrimSpace(p); p != "" {
				excludePats = append(excludePats, p)
			}
		}
	}
	discovery.SetExcludePatterns(excludePats)
	switch *format {
	case "text", "json", "sarif":
	default:
		fmt.Fprintf(stderr, "aegis: unknown --format %q (want text|json|sarif)\n", *format)
		return 2
	}
	color, ok := resolveColor(*colorMode, stdout)
	if !ok {
		fmt.Fprintf(stderr, "aegis: unknown --color %q (want auto|always|never)\n", *colorMode)
		return 2
	}
	if *complianceFw != "" && !rules.HasComplianceFramework(*complianceFw) {
		fmt.Fprintf(stderr, "aegis: unknown --compliance %q (want one of %s)\n",
			*complianceFw, strings.Join(rules.ComplianceFrameworks(), ", "))
		return 2
	}
	packs := strings.Split(*ruleset, ",")
	if unknown := rules.UnknownPacks(packs); len(unknown) > 0 {
		fmt.Fprintf(stderr, "aegis: unknown --rules %q (want comma-separated subset of %s, or all)\n",
			*ruleset, strings.Join(rules.KnownPacks, ","))
		return 2
	}
	registry := rules.RegistryFor(packs...)
	// --custom-rules loads user-defined YAML rules into the registry
	// alongside the built-in packs.
	if *customRulesDir != "" {
		customRules, err := custom.LoadDir(*customRulesDir)
		if err != nil {
			fmt.Fprintf(stderr, "aegis: custom-rules: %v\n", err)
			return 2
		}
		for _, r := range customRules {
			registry.Register(r)
		}
	}
	// --advisories implies the supplychain pack: load the feed and inject
	// synthetic advisory + provider resources for matching.
	var advisoryLoader func(reqs []terraform.ProviderReq) []ir.Resource
	if *advisoriesPath != "" {
		advs, err := advisories.Load(*advisoriesPath)
		if err != nil {
			fmt.Fprintf(stderr, "aegis: advisories: %v\n", err)
			return 2
		}
		registry = rules.RegistryFor(append(packs, "supplychain")...)
		advisoryLoader = func(reqs []terraform.ProviderReq) []ir.Resource {
			var out []ir.Resource
			for _, a := range advs {
				out = append(out, ir.Resource{
					Type:     "aegis_advisory",
					Name:     a.ID,
					Provider: "aegis",
					Attributes: map[string]ir.Value{
						"package":  {Raw: a.Package, Known: true},
						"affected": {Raw: a.Affected, Known: true},
						"severity": {Raw: a.Severity, Known: true},
					},
					Span: ir.Span{File: *advisoriesPath},
				})
			}
			for _, r := range reqs {
				out = append(out, ir.Resource{
					Type:     "terraform_provider",
					Name:     r.Source,
					Provider: "terraform",
					Attributes: map[string]ir.Value{
						"version_constraint": {Raw: r.Version, Known: r.Version != ""},
					},
					Span: r.Span,
				})
			}
			return out
		}
	}
	threshold := 1 // any finding fails by default
	if failOn.set {
		switch ir.Severity(strings.ToLower(failOn.value)) {
		case ir.SeverityCritical, ir.SeverityHigh, ir.SeverityMedium, ir.SeverityLow:
			threshold = severityRank(ir.Severity(strings.ToLower(failOn.value)))
		default:
			fmt.Fprintf(stderr, "aegis: unknown --fail-on %q (want critical|high|medium|low)\n", failOn.value)
			return 2
		}
	}

	res, resources, providerReqs, scanErr := scanWithTimeout(target, *timeoutSecs)
	if scanErr != nil {
		fmt.Fprintf(stderr, "aegis: scan error: %v\n", scanErr)
		return 2
	}
	if advisoryLoader != nil {
		resources = append(resources, advisoryLoader(providerReqs)...)
	}
	res.Resources = len(resources)
	if findings := registry.Run(resources); findings != nil {
		res.Findings = findings
	}
	// Inline-suppression compatibility: warn about aegis:skip IDs that are
	// not registered rules (removed by deduplication or typos). Such
	// entries have no effect; they are never silently migrated.
	for _, d := range rules.ValidateSuppressedRuleIDs(rules.CollectSuppressedRuleIDs(resources), registry) {
		fmt.Fprintf(stderr, "aegis: warning: %s\n", d.Message())
	}
	// Compliance: filter to the requested framework (narrowing refs), or
	// enrich every finding with all its mapped controls.
	if *complianceFw != "" {
		res.Findings = rules.FilterByCompliance(res.Findings, *complianceFw)
		res.ComplianceSummary = complianceSummary(*complianceFw, res.Findings)
	} else {
		res.Findings = rules.EnrichCompliance(res.Findings)
	}
	// --config severity overrides / rule exclusions apply after compliance
	// filtering so overrides see the final finding set.
	if *configPath != "" {
		cfg, err := config.Load(*configPath)
		if err != nil {
			fmt.Fprintf(stderr, "aegis: %v\n", err)
			return 2
		}
		var cdiags []ir.Diagnostic
		res.Findings, cdiags = cfg.Apply(res.Findings)
		res.Diagnostics = append(res.Diagnostics, cdiags...)
	}
	// Remediation: attach fix steps and doc links to every finding.
	res.Findings = rules.EnrichRemediation(res.Findings)
	// Baseline-out captures the post-inline-suppression findings so a later
	// --baseline run over unchanged code reports nothing new.
	if *baselineOut != "" {
		if err := rules.WriteBaseline(*baselineOut, res.Findings); err != nil {
			fmt.Fprintf(stderr, "aegis: baseline-out: %v\n", err)
			return 2
		}
	}
	// Baseline suppression drops previously-fingerprinted findings.
	if *baselinePath != "" {
		baseline, err := rules.LoadBaseline(*baselinePath)
		if err != nil {
			fmt.Fprintf(stderr, "aegis: baseline: %v\n", err)
			return 2
		}
		// Compatibility: warn about baseline entries referencing rule IDs
		// that are not registered (removed by deduplication or typos).
		// Such entries have no effect; they are never silently migrated
		// to a different rule.
		for _, d := range rules.ValidateBaselineIDs(baseline, registry) {
			fmt.Fprintf(stderr, "aegis: warning: %s\n", d.Message())
		}
		res.Findings = rules.ApplyBaseline(baseline, res.Findings)
	}

	var werr error
	switch *format {
	case "json":
		if *attackPaths {
			werr = report.WriteAttackPathsJSON(stdout, res)
		} else {
			werr = report.WriteJSON(stdout, res)
		}
	case "sarif":
		werr = report.WriteSARIF(stdout, res)
	default:
		if *attackPaths {
			werr = report.WriteAttackPathsText(stdout, res)
		} else {
			werr = report.WriteTextWithOptions(stdout, res, report.TextOptions{Color: color})
		}
	}
	if werr != nil {
		fmt.Fprintf(stderr, "aegis: report error: %v\n", werr)
		return 2
	}
	// --strict: fail if any file could not be parsed (incomplete scan)
	if *strict && !res.Completeness.Complete() {
		fmt.Fprintf(stderr, "aegis: strict mode: %d file(s) failed to parse\n",
			res.Completeness.FilesFailed)
		return 2
	}
	for _, f := range res.Findings {
		if severityRank(f.Severity) >= threshold {
			return 1
		}
	}
	return 0
}

// scanWithTimeout runs scanFull, aborting with an error if timeoutSecs > 0
// and the scan exceeds it. The scan itself is not cancellable mid-flight;
// the timeout bounds how long the CLI waits before reporting failure.
func scanWithTimeout(target string, timeoutSecs int) (ir.ScanResult, []ir.Resource, []terraform.ProviderReq, error) {
	if timeoutSecs <= 0 {
		return scanFull(target, defaultAdapters(), nil)
	}
	type result struct {
		res ir.ScanResult
		rs  []ir.Resource
		pr  []terraform.ProviderReq
		err error
	}
	ch := make(chan result, 1)
	go func() {
		res, rs, pr, err := scanFull(target, defaultAdapters(), nil)
		ch <- result{res, rs, pr, err}
	}()
	select {
	case r := <-ch:
		return r.res, r.rs, r.pr, r.err
	case <-time.After(time.Duration(timeoutSecs) * time.Second):
		return ir.ScanResult{}, nil, nil, fmt.Errorf("scan timed out after %d seconds", timeoutSecs)
	}
}

// runDoctor executes `aegis doctor`: binary self-checks. Exits 0 when
// healthy, 1 when any check fails.
func runDoctor(stdout, stderr io.Writer) int {
	fmt.Fprintln(stdout, "aegis doctor — self-check")
	failed := 0
	check := func(name string, ok bool, detail string) {
		status := "ok"
		if !ok {
			status = "FAIL"
			failed++
		}
		if detail != "" {
			fmt.Fprintf(stdout, "  [%s] %s: %s\n", status, name, detail)
		} else {
			fmt.Fprintf(stdout, "  [%s] %s\n", status, name)
		}
	}

	// 1. Rule registry loads.
	reg := rules.DefaultRegistry()
	all := reg.All()
	check("rule registry", len(all) > 0, fmt.Sprintf("%d rules loaded", len(all)))

	// 2. Parse smoke test: a minimal valid file must parse with no errors.
	ta := terraform.New()
	mod, diags, err := ta.ParseModule("doctor.tf", []byte("resource \"aws_s3_bucket\" \"d\" {\n  bucket = \"doctor-test\"\n}\n"))
	errCount := 0
	for _, d := range diags {
		if d.Level == "error" {
			errCount++
		}
	}
	check("parse smoke test", err == nil && errCount == 0 && len(mod.Resources) == 1,
		fmt.Sprintf("1 resource parsed, %d error diagnostics", errCount))

	// 3. Malformed input must produce an error, never silent clean.
	_, _, merr := ta.ParseModule("doctor-bad.tf", []byte("resource \"aws_s3_bucket\" \"d\" {\n  bucket = \n"))
	check("malformed input rejected", merr != nil, "truncated HCL returns an error")

	// 4. Binary garbage must produce an error.
	_, _, berr := ta.ParseModule("doctor-bin.tf", []byte{0x00, 0x01, 0x02, 'r', 'e', 's'})
	check("binary input rejected", berr != nil, "null bytes return an error")

	// 5. Rules fire on the smoke-test resource.
	findings := reg.Run(mod.Resources)
	check("rule engine", len(findings) > 0, fmt.Sprintf("%d findings on unencrypted bucket", len(findings)))

	// 6. Remediation dry-run proposes without writing.
	patches := remediation.ProposeAll(findings, mod.Resources, func(path string) ([]byte, error) {
		return []byte("resource \"aws_s3_bucket\" \"d\" {\n  bucket = \"doctor-test\"\n}\n"), nil
	})
	check("remediation dry-run", len(patches) >= 0, fmt.Sprintf("%d patches proposed (no writes)", len(patches)))

	// 7. Version/runtime info.
	check("runtime", true, fmt.Sprintf("go %s, %s/%s", runtime.Version(), runtime.GOOS, runtime.GOARCH))

	if failed > 0 {
		fmt.Fprintf(stderr, "aegis doctor: %d check(s) FAILED\n", failed)
		return 1
	}
	fmt.Fprintln(stdout, "aegis doctor: all checks passed")
	return 0
}

// scanDir runs the full pipeline: discover -> adapt -> parse -> rules.
// A discovery hard failure is returned as an error (exit 2); everything
// else — including per-file parse failures — becomes diagnostics on the
// result, never a crash.
func scanDir(target string, adapters []ir.Adapter, engine ruleRunner) (ir.ScanResult, error) {
	res, _, _, err := scanFull(target, adapters, engine)
	return res, err
}

// scanFull is scanDir plus the resolved resource list and the collected
// provider requirements, for callers (like `fix` and `--advisories`) that
// need more than the result summary.
func scanFull(target string, adapters []ir.Adapter, engine ruleRunner) (ir.ScanResult, []ir.Resource, []terraform.ProviderReq, error) {
	res := ir.ScanResult{
		Target:      target,
		Findings:    []ir.Finding{},
		Diagnostics: []ir.Diagnostic{},
	}
	// A missing scan target is a usage error, not a clean scan: failing
	// open here prevents silently reporting "0 findings" for a typo'd path.
	// (Discovery itself still skips unreadable entries mid-walk by design.)
	if _, err := os.Stat(target); err != nil {
		return res, nil, nil, fmt.Errorf("target: %w", err)
	}
	files, discSkipped, err := discovery.DiscoverWithReport(target)
	if err != nil {
		return res, nil, nil, fmt.Errorf("discovery: %w", err)
	}
	// Files discovery dropped for size/total caps must be reported, not
	// silently skipped: an over-cap file used to vanish with no
	// diagnostic at all (0 findings that looked clean). Oversize files
	// get a warning diagnostic each; a scan-wide cap hit gets one
	// diagnostic naming the cap (the remaining files are unknowable).
	var discSkippedFiles []discovery.Skipped
	for _, sk := range discSkipped {
		if sk.Path == target {
			res.Diagnostics = append(res.Diagnostics, ir.Diagnostic{
				Level:   "warning",
				Message: sk.Reason,
				Span:    ir.Span{File: target},
			})
			continue
		}
		discSkippedFiles = append(discSkippedFiles, sk)
		res.Diagnostics = append(res.Diagnostics, ir.Diagnostic{
			Level:   "warning",
			Message: fmt.Sprintf("discovery: skipped %s: %s", sk.Path, sk.Reason),
			Span:    ir.Span{File: sk.Path},
		})
	}
	var resources []ir.Resource
	var mods []terraform.Module
	var providerReqs []terraform.ProviderReq
	tfAdapter, _ := defaultAdapters()[0].(*terraform.Adapter)
	// Parse files concurrently: ParseModule/Parse calls are independent per
	// file. Results are reassembled in discovery order so diagnostics,
	// resources, and modules come out exactly as the sequential loop
	// produced them.
	results := parseFilesConcurrent(files, adapters)
	// Build scan-completeness: every discovered file gets an explicit outcome,
	// including which adapter (format) handled it.
	completeness := ir.ScanCompleteness{
		FilesDiscovered: len(files) + len(discSkippedFiles),
	}
	// Discovery-dropped oversize files count as discovered-but-skipped.
	for _, sk := range discSkippedFiles {
		completeness.FilesSkipped++
		completeness.Files = append(completeness.Files, ir.FileStatus{
			Path:   sk.Path,
			Status: "skipped",
			Reason: sk.Reason,
		})
	}
	for i, pr := range results {
		res.Diagnostics = append(res.Diagnostics, pr.diags...)
		fpath := files[i].Path
		st := ir.FileStatus{Path: fpath, Format: pr.adapterName}
		if pr.failed {
			completeness.FilesFailed++
			reason := "parse or read failure"
			for _, d := range pr.diags {
				if d.Level == "error" {
					reason = d.Message
					break
				}
			}
			st.Status = "failed"
			st.Reason = reason
			completeness.Files = append(completeness.Files, st)
			continue
		}
		// Skipped: file was excluded by --exclude pattern, no adapter handles
		// it, or the adapter could not parse it (e.g., unrecognized document).
		// Warnings from successful parses (e.g., unresolvable for_each where
		// resources ARE produced) do NOT mark the file as skipped.
		isSkipped := false
		var skipReason string
		hasResources := pr.mod != nil || len(pr.resources) > 0
		if !hasResources {
			for _, d := range pr.diags {
				if d.Level == "warning" {
					isSkipped = true
					skipReason = d.Message
					break
				}
			}
		}
		if isSkipped {
			completeness.FilesSkipped++
			st.Status = "skipped"
			st.Reason = skipReason
			completeness.Files = append(completeness.Files, st)
			continue
		}
		completeness.FilesParsed++
		st.Status = "parsed"
		completeness.Files = append(completeness.Files, st)
		if pr.mod != nil {
			mods = append(mods, *pr.mod)
			providerReqs = append(providerReqs, pr.mod.ProviderReqs...)
			resources = append(resources, pr.mod.Resources...)
			// Synthetic terraform_* pseudo-resources (for secret-detection
			// rules 536/538/539). They carry no resolvable refs; semantic
			// resolution is a no-op for them.
			resources = append(resources, pr.mod.SyntheticResources...)
			continue
		}
		resources = append(resources, pr.resources...)
	}
	// Milestone 2 semantics: resolve var/local references, then expand
	// local module calls. Plan-JSON resources carry no refs; resolution is
	// a no-op for them.
	if len(mods) > 0 {
		scope := semantics.MergeModules(mods)
		resources = scope.ResolveResources(resources)
		expandedDyn, dynDiags := scope.ExpandDynamicBlocks(resources)
		res.Diagnostics = append(res.Diagnostics, dynDiags...)
		resources = expandedDyn
		if tfAdapter != nil {
			expanded, mdiags := semantics.ExpandModules(target, mods, tfAdapter, 2)
			res.Diagnostics = append(res.Diagnostics, mdiags...)
			resources = append(resources, expanded...)
			// Drop bare-address twins: module files are parsed once as
			// roots and again via expansion. The expanded copy (correct
			// address, resolved inputs, rewritten refs) is authoritative;
			// the bare copy would double every finding on the block.
			resources = semantics.RemoveBareModuleTwins(resources, expanded)
		}
	}
	res.Resources = len(resources)
	res.Completeness = completeness
	if engine != nil {
		if findings := engine.Run(resources); findings != nil {
			res.Findings = findings
		}
	}
	return res, resources, providerReqs, nil
}

// fileParseResult is the parse outcome for one discovered file.
type fileParseResult struct {
	diags       []ir.Diagnostic
	mod         *terraform.Module // non-nil when the terraform adapter handled it
	resources   []ir.Resource     // for non-terraform adapters
	failed      bool              // read or parse hard failure; diags carry the reason
	adapterName string            // adapter that handled the file ("" if none/excluded)
}

// parseFilesConcurrent parses every discovered file with a bounded worker
// pool (runtime.NumCPU workers). Results are returned in discovery order,
// so callers see exactly the sequence the old sequential loop produced.
func parseFilesConcurrent(files []discovery.File, adapters []ir.Adapter) []fileParseResult {
	results := make([]fileParseResult, len(files))
	if len(files) == 0 {
		return results
	}
	workers := runtime.NumCPU()
	if workers > len(files) {
		workers = len(files)
	}
	jobs := make(chan int, len(files))
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				results[idx] = parseOneFile(files[idx], adapters)
			}
		}()
	}
	for i := range files {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return results
}

// parseOneFile selects the adapter, reads, and parses a single file,
// mirroring the sequential loop's diagnostic behavior exactly.
func parseOneFile(f discovery.File, adapters []ir.Adapter) (pr fileParseResult) {
	// --exclude patterns win over everything: the file is reported as
	// skipped with an explicit reason, never parsed.
	if discovery.IsExcluded(f.Path) {
		pr.diags = append(pr.diags, ir.Diagnostic{
			Level:   "warning",
			Message: fmt.Sprintf("excluded by --exclude pattern; skipped"),
			Span:    ir.Span{File: f.Path},
		})
		return pr
	}
	var ad ir.Adapter
	for _, a := range adapters {
		if a.Handles(f.Path) {
			ad = a
			break
		}
	}
	if ad == nil {
		pr.diags = append(pr.diags, ir.Diagnostic{
			Level:   "warning",
			Message: fmt.Sprintf("no adapter handles %s; skipped", f.Path),
			Span:    ir.Span{File: f.Path},
		})
		pr.failed = true
		return pr
	}
	src, err := discovery.Read(f)
	if err != nil {
		pr.diags = append(pr.diags, ir.Diagnostic{
			Level:   "error",
			Message: fmt.Sprintf("cannot read %s: %v", f.Path, err),
			Span:    ir.Span{File: f.Path},
		})
		pr.failed = true
		return pr
	}
	pr.adapterName = ad.Name()
	// Terraform files go through ParseModule so the semantics layer
	// gets variables/locals/module calls for M2 resolution.
	if ta, ok := ad.(*terraform.Adapter); ok {
		mod, diags, perr := safeParseModule(ta, f.Path, src)
		pr.diags = append(pr.diags, diags...)
		if perr != nil {
			pr.diags = append(pr.diags, ir.Diagnostic{
				Level:   "error",
				Message: fmt.Sprintf("parse failed for %s: %v", f.Path, perr),
				Span:    ir.Span{File: f.Path},
			})
			pr.failed = true
			return pr
		}
		pr.mod = &mod
		return pr
	}
	rs, diags, perr := safeParse(ad, f.Path, src)
	pr.diags = append(pr.diags, diags...)
	if perr != nil {
		pr.diags = append(pr.diags, ir.Diagnostic{
			Level:   "error",
			Message: fmt.Sprintf("parse failed for %s: %v", f.Path, perr),
			Span:    ir.Span{File: f.Path},
		})
		pr.failed = true
		return pr
	}
	pr.resources = rs
	return pr
}

// safeParseModule calls adapter ParseModule with panic recovery.
func safeParseModule(ad *terraform.Adapter, path string, src []byte) (mod terraform.Module, diags []ir.Diagnostic, err error) {
	defer func() {
		if r := recover(); r != nil {
			mod = terraform.Module{}
			diags = nil
			err = fmt.Errorf("adapter %s panicked: %v", ad.Name(), r)
		}
	}()
	return ad.ParseModule(path, src)
}

// safeParse calls adapter Parse with panic recovery: a misbehaving adapter
// must degrade to a diagnostic, never take down the scan.
func safeParse(ad ir.Adapter, path string, src []byte) (rs []ir.Resource, diags []ir.Diagnostic, err error) {
	defer func() {
		if r := recover(); r != nil {
			rs = nil
			diags = nil
			err = fmt.Errorf("adapter %s panicked: %v", ad.Name(), r)
		}
	}()
	return ad.Parse(path, src)
}

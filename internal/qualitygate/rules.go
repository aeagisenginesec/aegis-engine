package qualitygate

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"aegis/internal/ir"
	"aegis/internal/rules"
	packalibaba "aegis/internal/rules/alibaba"
	packaws "aegis/internal/rules/aws"
	packazure "aegis/internal/rules/azure"
	packcompose "aegis/internal/rules/compose"
	packdocker "aegis/internal/rules/docker"
	packgcp "aegis/internal/rules/gcp"
	packk8s "aegis/internal/rules/k8s"
	packoci "aegis/internal/rules/oci"
	packsupplychain "aegis/internal/rules/supplychain"
	packterraform "aegis/internal/rules/terraform"
)

// ruleEvidence records what test code proves about one rule: whether some
// test constructs a violating fixture and asserts the rule fires (positive),
// and whether some test constructs a secure fixture and asserts the rule
// stays quiet (negative). A rule counts as tested only when BOTH hold.
type ruleEvidence struct {
	pos, neg           bool
	posTests, negTests []string
}

// idPattern matches rule ID literals such as "AEGIS-AWS-103".
var idPattern = regexp.MustCompile(`^AEGIS-[A-Z0-9]+-[0-9]+$`)

// idSearchPattern finds rule IDs embedded in longer strings (assertion
// messages); idPattern requires the whole literal to be an ID.
var idSearchPattern = regexp.MustCompile(`AEGIS-[A-Z0-9]+-[0-9]+`)

// runRuleCoverageGate verifies that every critical/high-severity rule in the
// default registry has real detection-test evidence: at least one test that
// proves the rule fires on a violating fixture AND at least one test that
// proves it stays quiet on a secure fixture.
//
// The analysis is evidence-based, not mention-based: a bare string mention
// of a rule ID (in a comment, a table, or a meta test like TestRulesInIDOrder)
// counts for nothing. Evidence is attributed per test function via:
//   - instantiated rule types (runRule(SomeRule{}, ...), (SomeRule{}).CheckAll(...))
//     resolved through the pack's type->ID map built from ID() methods;
//   - explicit rule ID arguments to mustFinding/mustFire/expectFinding(s);
//   - quoted rule ID literals asserted against (f.RuleID != "AEGIS-...");
//   - assertion shape: len(findings)!=0 + fail => negative, len(findings)==0
//   - fail => positive, mustFinding => positive, mustQuiet => negative;
//   - pack-wide shared negatives: a test that runs every pack rule over a
//     real fixture and fails on ANY finding (e.g. k8s TestCompliantContainerQuiet
//     via runAll, supplychain TestFixedVersionSilent via runSC) counts as
//     negative evidence for every rule of that pack.
//
// Deliberate exclusions (documented, never silent):
//   - TestUnknownNeverFires_* / *UnknownNoFindings: all-unknown-attribute
//     fixtures are not secure fixtures, so they are weak shared evidence
//     and do not count.
//   - A test function that computes a value and discards it (`_ = x`) with no
//     fail-call asserts nothing and contributes no evidence.
func runRuleCoverageGate(o Options) GateResult {
	tested, total, missingPos, missingNeg := computeRuleCoverage(o)
	passed := len(missingPos) == 0 && len(missingNeg) == 0

	details := fmt.Sprintf("%d/%d critical/high rules have pos+neg evidence", tested, total)
	if !passed {
		if len(missingPos) > 0 {
			details += "; missing positive: " + joinCapped(missingPos, 10)
		}
		if len(missingNeg) > 0 {
			details += "; missing negative: " + joinCapped(missingNeg, 10)
		}
	}
	return GateResult{
		Name:      "rule-coverage",
		Passed:    passed,
		Metric:    fmt.Sprintf("%d/%d with pos+neg evidence", tested, total),
		Threshold: "100% of critical/high rules with pos+neg test evidence",
		Details:   details,
	}
}

// computeRuleCoverage runs the evidence analysis and returns the honest
// counts plus the full deficient ID lists (uncapped, for debugging).
func computeRuleCoverage(o Options) (tested, total int, missingPos, missingNeg []string) {
	registry := rules.DefaultRegistry()
	all := registry.All()

	var critHigh []ir.Rule
	for _, r := range all {
		if r.Severity() == ir.SeverityCritical || r.Severity() == ir.SeverityHigh {
			critHigh = append(critHigh, r)
		}
	}

	typeIDs := buildTypeIDMap(o.ModuleRoot)
	packIDs := buildPackIDMap()
	runners := findPackRunners(o.ModuleRoot)

	evidence := map[string]*ruleEvidence{}
	getEv := func(id string) *ruleEvidence {
		e, ok := evidence[id]
		if !ok {
			e = &ruleEvidence{}
			evidence[id] = e
		}
		return e
	}

	// Group test files by directory: table constructors (kmsRuleCases,
	// publicNetCases, ...) may live in a different _test.go file than the
	// tests that range over them.
	byDir := map[string][]string{}
	walkErr := filepath.Walk(o.ModuleRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		dir := filepath.Dir(path)
		byDir[dir] = append(byDir[dir], path)
		return nil
	})
	if walkErr == nil {
		for dir, paths := range byDir {
			idx := &testDirIndex{
				typeMap:    typeIDs[dir],
				tableTypes: map[string]map[string]bool{},
				tableIDs:   map[string]map[string]bool{},
				helpers:    map[string]string{},
				runners:    runners[dir],
				packSet:    packIDs[filepath.Base(dir)],
			}
			if idx.typeMap == nil {
				idx.typeMap = map[string]string{}
			}
			analyzeTestDir(paths, idx, getEv)
		}
	}

	for _, r := range critHigh {
		e := evidence[r.ID()]
		if e == nil || !e.pos {
			missingPos = append(missingPos, r.ID())
		}
		if e == nil || !e.neg {
			missingNeg = append(missingNeg, r.ID())
		}
	}
	deficient := map[string]bool{}
	for _, id := range missingPos {
		deficient[id] = true
	}
	for _, id := range missingNeg {
		deficient[id] = true
	}
	sort.Strings(missingPos)
	sort.Strings(missingNeg)
	return len(critHigh) - len(deficient), len(critHigh), missingPos, missingNeg
}

func joinCapped(ids []string, cap int) string {
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	shown := sorted
	suffix := ""
	if len(sorted) > cap {
		shown = sorted[:cap]
		suffix = fmt.Sprintf(" (+%d more)", len(sorted)-cap)
	}
	return strings.Join(shown, ", ") + suffix
}

// buildTypeIDMap scans non-test Go sources for `func (T) ID() string` methods
// returning a string literal, producing dir -> type name -> rule ID.
func buildTypeIDMap(moduleRoot string) map[string]map[string]string {
	out := map[string]map[string]string{}
	_ = filepath.Walk(moduleRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil
		}
		dir := filepath.Dir(path)
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Name.Name != "ID" || fd.Recv == nil || len(fd.Recv.List) != 1 || fd.Body == nil {
				continue
			}
			var tname string
			switch t := fd.Recv.List[0].Type.(type) {
			case *ast.Ident:
				tname = t.Name
			case *ast.StarExpr:
				if id, ok := t.X.(*ast.Ident); ok {
					tname = id.Name
				}
			}
			if tname == "" {
				continue
			}
			id := ""
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if rs, ok := n.(*ast.ReturnStmt); ok && len(rs.Results) == 1 {
					if bl, ok := rs.Results[0].(*ast.BasicLit); ok && bl.Kind == token.STRING {
						if s, err := strconv.Unquote(bl.Value); err == nil && idPattern.MatchString(s) {
							id = s
						}
					}
				}
				return id == ""
			})
			if id != "" {
				if out[dir] == nil {
					out[dir] = map[string]string{}
				}
				out[dir][tname] = id
			}
		}
		return nil
	})
	return out
}

// buildPackIDMap returns pack directory base name -> set of rule IDs offered
// by that pack, used to attribute pack-wide shared negative tests.
func buildPackIDMap() map[string]map[string]bool {
	packs := map[string][]ir.Rule{
		"alibaba":     packalibaba.Rules(),
		"aws":         packaws.Rules(),
		"azure":       packazure.Rules(),
		"compose":     packcompose.Rules(),
		"docker":      packdocker.Rules(),
		"gcp":         packgcp.Rules(),
		"k8s":         packk8s.Rules(),
		"oci":         packoci.Rules(),
		"supplychain": packsupplychain.Rules(),
		"terraform":   packterraform.Rules(),
	}
	out := map[string]map[string]bool{}
	for pack, rs := range packs {
		set := map[string]bool{}
		for _, r := range rs {
			set[r.ID()] = true
		}
		out[pack] = set
	}
	return out
}

// findPackRunners returns the set of test-helper function names (per package
// dir) whose body iterates over the pack's Rules() — e.g. k8s runAll,
// supplychain runSC. Calling such a helper executes every pack rule.
func findPackRunners(moduleRoot string) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	_ = filepath.Walk(moduleRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil
		}
		dir := filepath.Dir(path)
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil || strings.HasPrefix(fd.Name.Name, "Test") {
				continue
			}
			rangesRules := false
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if rs, ok := n.(*ast.RangeStmt); ok {
					if call, ok := rs.X.(*ast.CallExpr); ok && isRulesCall(call) {
						rangesRules = true
						return false
					}
				}
				return !rangesRules
			})
			if rangesRules {
				if out[dir] == nil {
					out[dir] = map[string]bool{}
				}
				out[dir][fd.Name.Name] = true
			}
		}
		return nil
	})
	return out
}

func isRulesCall(c *ast.CallExpr) bool {
	switch fn := c.Fun.(type) {
	case *ast.Ident:
		return fn.Name == "Rules"
	case *ast.SelectorExpr:
		return fn.Sel.Name == "Rules"
	}
	return false
}

// testDirIndex holds package-wide pre-pass data for one test directory:
// rule types and rule IDs in tables returned by table-constructor functions
// (kmsRuleCases, publicNetCases, ...), keyed by function name.
type testDirIndex struct {
	typeMap    map[string]string          // rule type name -> rule ID
	tableTypes map[string]map[string]bool // func name -> rule types in returned tables
	tableIDs   map[string]map[string]bool // func name -> rule IDs in returned tables
	helpers    map[string]string          // test helper name -> rule type it wraps
	runners    map[string]bool            // pack-runner helper names
	packSet    map[string]bool            // rule IDs offered by the pack
}

// analyzeTestDir indexes all _test.go files in one directory, then analyzes
// every Test function in them.
func analyzeTestDir(paths []string, idx *testDirIndex, getEv func(string) *ruleEvidence) {
	type namedFile struct {
		path string
		f    *ast.File
	}
	var files []namedFile
	for _, path := range paths {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			continue
		}
		files = append(files, namedFile{path, f})
	}
	// Pre-pass: table constructors. A func qualifies when a return statement
	// yields composite literals of known rule types or rule ID literals
	// (the table entries).
	for _, nf := range files {
		for _, decl := range nf.f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			types := map[string]bool{}
			ids := map[string]bool{}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				rs, ok := n.(*ast.ReturnStmt)
				if !ok {
					return true
				}
				for _, r := range rs.Results {
					for _, t := range collectRuleTypes(r, idx.typeMap) {
						types[t] = true
					}
					ast.Inspect(r, func(m ast.Node) bool {
						if s, ok := strLitOf(m); ok {
							ids[s] = true
						}
						return true
					})
				}
				return true
			})
			if len(types) > 0 {
				idx.tableTypes[fd.Name.Name] = types
			}
			if len(ids) > 0 {
				idx.tableIDs[fd.Name.Name] = ids
			}
			// Thin wrappers: `func run105(rs ...ir.Resource) []ir.Finding {
			// return (multiHopPath{}).CheckAll(rs) }` — calls to the
			// helper are calls to the rule.
			if t := helperRuleType(fd, idx.typeMap); t != "" {
				idx.helpers[fd.Name.Name] = t
			}
		}
	}
	for _, nf := range files {
		for _, decl := range nf.f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !strings.HasPrefix(fn.Name.Name, "Test") || fn.Body == nil {
				continue
			}
			newFuncAnalyzer(idx, fn.Name.Name, getEv).analyze(fn)
		}
	}
}

// helperRuleType resolves thin test helpers that wrap exactly one rule,
// e.g. `func run105(rs ...ir.Resource) []ir.Finding {
// return (multiHopPath{}).CheckAll(rs) }`.
func helperRuleType(fd *ast.FuncDecl, typeMap map[string]string) string {
	if fd.Body == nil || len(fd.Body.List) != 1 {
		return ""
	}
	rs, ok := fd.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(rs.Results) != 1 {
		return ""
	}
	call, ok := rs.Results[0].(*ast.CallExpr)
	if !ok {
		return ""
	}
	if se, ok := call.Fun.(*ast.SelectorExpr); ok {
		if cl := unwrapComposite(se.X); cl != nil {
			if t := compositeTypeName(cl); typeMap[t] != "" {
				return t
			}
		}
	}
	return ""
}

// collectRuleTypes returns the names of known rule types instantiated as
// composite literals anywhere under e.
func collectRuleTypes(e ast.Expr, typeMap map[string]string) []string {
	var out []string
	seen := map[string]bool{}
	ast.Inspect(e, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		if t := compositeTypeName(cl); t != "" && typeMap[t] != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
		return true
	})
	return out
}

// funcAnalyzer attributes detection evidence for a single test function.
type funcAnalyzer struct {
	idx        *testDirIndex
	name       string
	getEv      func(string) *ruleEvidence
	varTypes   map[string]string          // var -> rule type name (direct)
	varIDs     map[string]string          // var -> rule ID (e.g. fs := fired["AEGIS-K8S-001"])
	assigns    map[string]*ast.CallExpr   // var -> RHS call for x := f(...)
	strVars    map[string]string          // var -> rule ID literal (id := "AEGIS-...")
	tableVars  map[string]map[string]bool // var -> rule types (inline table literal)
	runnerVars map[string]bool            // var assigned from a pack-runner call
	loopTypes  map[string]map[string]bool // table loop var -> rule types
	loopIDs    map[string]map[string]bool // table loop var -> rule IDs
	posIDs     map[string]bool
	negIDs     map[string]bool
}

func newFuncAnalyzer(idx *testDirIndex, name string, getEv func(string) *ruleEvidence) *funcAnalyzer {
	return &funcAnalyzer{
		idx: idx, name: name, getEv: getEv,
		varTypes: map[string]string{}, varIDs: map[string]string{},
		assigns: map[string]*ast.CallExpr{},
		strVars: map[string]string{}, tableVars: map[string]map[string]bool{},
		runnerVars: map[string]bool{},
		loopTypes:  map[string]map[string]bool{}, loopIDs: map[string]map[string]bool{},
		posIDs: map[string]bool{}, negIDs: map[string]bool{},
	}
}

func (a *funcAnalyzer) addPos(ids ...string) {
	for _, id := range ids {
		if id != "" {
			a.posIDs[id] = true
		}
	}
}

func (a *funcAnalyzer) addNeg(ids ...string) {
	for _, id := range ids {
		if id != "" {
			a.negIDs[id] = true
		}
	}
}

// unwrapComposite strips parentheses: (T{}) parses as ParenExpr.
func unwrapComposite(e ast.Expr) *ast.CompositeLit {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			break
		}
		e = p.X
	}
	cl, _ := e.(*ast.CompositeLit)
	return cl
}

// ruleTypeOfCall extracts the rule type name from calls that instantiate a
// rule: runRule(T{}, ...), runCross(T{}, ...), (T{}).CheckAll(...),
// expectFinding(t, T{}, r, n), etc. Only composites whose type is a known
// rule type count, so fixtures like ir.Value{...} never attribute.
func (a *funcAnalyzer) ruleTypeOfCall(c *ast.CallExpr) string {
	if se, ok := c.Fun.(*ast.SelectorExpr); ok {
		if cl := unwrapComposite(se.X); cl != nil {
			if t := compositeTypeName(cl); a.idx.typeMap[t] != "" {
				return t
			}
		}
	}
	if id, ok := c.Fun.(*ast.Ident); ok {
		if t := a.idx.helpers[id.Name]; t != "" {
			return t
		}
	}
	for _, arg := range c.Args {
		if cl := unwrapComposite(arg); cl != nil {
			if t := compositeTypeName(cl); a.idx.typeMap[t] != "" {
				return t
			}
		}
	}
	return ""
}

// attrib resolves an expression to rule IDs via variable->type mappings,
// recorded call assignments, inline rule instantiation, table loop
// variables, or quoted ID indexes like fired["AEGIS-..."].
func (a *funcAnalyzer) attrib(e ast.Expr) []string {
	return a.attribSeen(e, map[string]bool{})
}

func (a *funcAnalyzer) attribSeen(e ast.Expr, seen map[string]bool) []string {
	switch x := e.(type) {
	case *ast.Ident:
		if seen[x.Name] {
			return nil // assignment cycle (e.g. fs = append(fs, ...))
		}
		seen[x.Name] = true
		if id, ok := a.varIDs[x.Name]; ok {
			return []string{id}
		}
		if t, ok := a.varTypes[x.Name]; ok {
			if id := a.idx.typeMap[t]; id != "" {
				return []string{id}
			}
		}
		if call, ok := a.assigns[x.Name]; ok {
			// x := runRule(<ruleexpr>, ...)
			if idx := ruleArgIndex(call); idx >= 0 && idx < len(call.Args) {
				if ids := a.attribSeen(call.Args[idx], seen); len(ids) > 0 {
					return ids
				}
			}
			// x := (T{}).CheckAll(...)
			if t := a.ruleTypeOfCall(call); t != "" {
				if id := a.idx.typeMap[t]; id != "" {
					return []string{id}
				}
			}
		}
	case *ast.CallExpr:
		if t := a.ruleTypeOfCall(x); t != "" {
			if id := a.idx.typeMap[t]; id != "" {
				return []string{id}
			}
		}
	case *ast.CompositeLit:
		// expectFinding(t, someRule{}, ...) — rule passed directly.
		if t := compositeTypeName(x); a.idx.typeMap[t] != "" {
			return []string{a.idx.typeMap[t]}
		}
	case *ast.IndexExpr:
		if s, ok := strLitOf(x.Index); ok {
			return []string{s}
		}
	case *ast.SelectorExpr:
		// c.rule / c.id where c is a table-driven loop variable.
		if id, ok := x.X.(*ast.Ident); ok {
			var out []string
			seen := map[string]bool{}
			for t := range a.loopTypes[id.Name] {
				if rid := a.idx.typeMap[t]; rid != "" && !seen[rid] {
					seen[rid] = true
					out = append(out, rid)
				}
			}
			for rid := range a.loopIDs[id.Name] {
				if !seen[rid] {
					seen[rid] = true
					out = append(out, rid)
				}
			}
			return out
		}
	}
	return nil
}

// ruleArgIndex returns the argument position holding the rule under test:
// arg 0 for runRule/runCross-style helpers, arg 1 for (t, rule, ...)-style
// helpers like expectFinding/expectFindings/mustFire-adjacent forms.
func ruleArgIndex(c *ast.CallExpr) int {
	if id, ok := c.Fun.(*ast.Ident); ok {
		switch id.Name {
		case "expectFinding", "expectFindings":
			return 1
		}
	}
	if se, ok := c.Fun.(*ast.SelectorExpr); ok {
		if _, ok := se.X.(*ast.CompositeLit); ok {
			return -1 // rule is the receiver, handled via ruleTypeOfCall
		}
	}
	return 0
}

// resolveRuleIDs resolves a rule-ID argument: quoted literal, ID variable
// (id := "AEGIS-..."), table loop field (c.id), or falls back to nil.
func (a *funcAnalyzer) resolveRuleIDs(e ast.Expr) []string {
	if s, ok := strLitOf(e); ok {
		return []string{s}
	}
	if id, ok := e.(*ast.Ident); ok {
		if rid, ok := a.strVars[id.Name]; ok {
			return []string{rid}
		}
	}
	return a.attrib(e)
}

// ifLiterals collects rule ID literals appearing anywhere in an if statement
// (condition or body), e.g. in assertion messages. IDs embedded in longer
// message strings count (substring search).
func ifLiterals(s *ast.IfStmt) []string {
	var ids []string
	seen := map[string]bool{}
	ast.Inspect(s, func(n ast.Node) bool {
		bl, ok := n.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			return true
		}
		v, err := strconv.Unquote(bl.Value)
		if err != nil {
			return true
		}
		for _, m := range idSearchPattern.FindAllString(v, -1) {
			if !seen[m] {
				seen[m] = true
				ids = append(ids, m)
			}
		}
		return true
	})
	return ids
}

func strLitOf(n ast.Node) (string, bool) {
	bl, ok := n.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(bl.Value)
	if err != nil || !idPattern.MatchString(s) {
		return "", false
	}
	return s, true
}

func intLitOf(e ast.Expr) (int, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.INT {
		return 0, false
	}
	n, err := strconv.Atoi(bl.Value)
	return n, err == nil
}

func isLenCall(e ast.Expr) (*ast.CallExpr, bool) {
	c, ok := e.(*ast.CallExpr)
	if !ok {
		return nil, false
	}
	id, ok := c.Fun.(*ast.Ident)
	if !ok || id.Name != "len" || len(c.Args) != 1 {
		return nil, false
	}
	return c, true
}

func isFailCall(c *ast.CallExpr) bool {
	se, ok := c.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	recv, ok := se.X.(*ast.Ident)
	if !ok || recv.Name != "t" {
		return false
	}
	switch se.Sel.Name {
	case "Fatal", "Fatalf", "Error", "Errorf", "Fail", "FailNow":
		return true
	}
	return false
}

func bodyHasFail(b *ast.BlockStmt) bool {
	found := false
	ast.Inspect(b, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok && isFailCall(c) {
			found = true
			return false
		}
		return !found
	})
	return found
}

func callName(c *ast.CallExpr) string {
	switch fn := c.Fun.(type) {
	case *ast.Ident:
		return fn.Name
	case *ast.SelectorExpr:
		return fn.Sel.Name
	}
	return ""
}

// loopVarName returns the iteration variable name for
// `for _, v := range ...` / `for v := range ...` ("" if blank/missing).
func loopVarName(s *ast.RangeStmt) string {
	if s.Tok != token.DEFINE {
		return ""
	}
	if id, ok := s.Value.(*ast.Ident); ok && id.Name != "_" {
		return id.Name
	}
	if s.Value == nil {
		if id, ok := s.Key.(*ast.Ident); ok && id.Name != "_" {
			return id.Name
		}
	}
	return ""
}

// condEvidence classifies an if-condition guarding a fail call, returning
// attributed rule IDs with polarity (+1 positive, -1 negative).
func (a *funcAnalyzer) condEvidence(e ast.Expr) (map[string]int, bool) {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return a.condEvidence(x.X)
	case *ast.BinaryExpr:
		if x.Op == token.LOR || x.Op == token.LAND {
			l, lok := a.condEvidence(x.X)
			r, rok := a.condEvidence(x.Y)
			if !lok && !rok {
				return nil, false
			}
			out := map[string]int{}
			for id, p := range l {
				out[id] = p
			}
			for id, p := range r {
				if x.Op == token.LOR {
					out[id] = p
				} else if lp, ok := out[id]; ok && lp == p {
					out[id] = p // AND: keep only agreed attributions
				}
			}
			if len(out) == 0 {
				return nil, false
			}
			return out, true
		}
		if lc, ok := isLenCall(x.X); ok {
			ids := a.attrib(lc.Args[0])
			if len(ids) == 0 {
				return nil, false
			}
			out := map[string]int{}
			switch x.Op {
			case token.NEQ:
				if n, ok := intLitOf(x.Y); ok {
					pol := 1
					if n == 0 {
						pol = -1 // len!=0 + fail => asserts quiet
					}
					for _, id := range ids {
						out[id] = pol
					}
					return out, true
				}
			case token.EQL:
				if n, ok := intLitOf(x.Y); ok {
					pol := -1
					if n == 0 {
						pol = 1 // len==0 + fail => asserts firing
					}
					for _, id := range ids {
						out[id] = pol
					}
					return out, true
				}
			case token.LSS, token.LEQ:
				for _, id := range ids { // len<1 + fail => asserts firing
					out[id] = 1
				}
				return out, true
			case token.GTR, token.GEQ:
				for _, id := range ids { // len>0 + fail => asserts quiet
					out[id] = -1
				}
				return out, true
			}
			return nil, false
		}
		// f.RuleID != "AEGIS-..." (+ fail) => asserts the finding IS this rule.
		if x.Op == token.NEQ || x.Op == token.EQL {
			if id, ok := ruleIDComparison(x); ok {
				if x.Op == token.NEQ {
					return map[string]int{id: 1}, true
				}
				return map[string]int{id: -1}, true
			}
		}
	}
	return nil, false
}

func (a *funcAnalyzer) analyze(fn *ast.FuncDecl) {
	name := fn.Name.Name
	// All-unknown-attribute fixtures are not secure fixtures: pack-wide
	// unknown tests are deliberately weak shared evidence and must not
	// count toward coverage.
	if strings.Contains(name, "UnknownNeverFires") || strings.Contains(name, "UnknownNoFindings") {
		return
	}

	// Pre-pass: assignments. Covers plain statements and if-statement
	// initializers (`if fs := runRule(T{}, r); len(fs) != 0 { ... }`).
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range as.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || i >= len(as.Rhs) {
				continue
			}
			switch rhs := as.Rhs[i].(type) {
			case *ast.BasicLit:
				if s, ok := strLitOf(rhs); ok {
					a.strVars[id.Name] = s
				}
			case *ast.CallExpr:
				a.assigns[id.Name] = rhs
				if t := a.ruleTypeOfCall(rhs); t != "" {
					a.varTypes[id.Name] = t
					continue
				}
				if fn, ok := rhs.Fun.(*ast.Ident); ok && a.idx.runners[fn.Name] {
					a.runnerVars[id.Name] = true
				}
			case *ast.CompositeLit:
				if types := collectRuleTypes(rhs, a.idx.typeMap); len(types) > 0 {
					set := map[string]bool{}
					for _, t := range types {
						set[t] = true
					}
					a.tableVars[id.Name] = set
				}
			case *ast.IndexExpr:
				// fs := fired["AEGIS-K8S-001"] — findings sliced by rule ID.
				if s, ok := strLitOf(rhs.Index); ok {
					a.varIDs[id.Name] = s
				}
			}
		}
		return true
	})

	ast.Inspect(fn.Body, a.visit)

	for id := range a.posIDs {
		e := a.getEv(id)
		e.pos = true
		e.posTests = append(e.posTests, a.name)
	}
	for id := range a.negIDs {
		e := a.getEv(id)
		e.neg = true
		e.negTests = append(e.negTests, a.name)
	}
}

// tableKeysForRange resolves the rule types and rule IDs iterated by a
// range statement: a table-constructor call, a table variable, or an inline
// table literal.
func (a *funcAnalyzer) tableKeysForRange(x ast.Expr) (types, ids map[string]bool) {
	types = map[string]bool{}
	ids = map[string]bool{}
	collect := func(e ast.Expr) {
		for _, t := range collectRuleTypes(e, a.idx.typeMap) {
			types[t] = true
		}
		ast.Inspect(e, func(n ast.Node) bool {
			if s, ok := strLitOf(n); ok {
				ids[s] = true
			}
			return true
		})
	}
	switch t := x.(type) {
	case *ast.CallExpr:
		if id, ok := t.Fun.(*ast.Ident); ok {
			for ty := range a.idx.tableTypes[id.Name] {
				types[ty] = true
			}
			for rid := range a.idx.tableIDs[id.Name] {
				ids[rid] = true
			}
		}
	case *ast.Ident:
		for ty := range a.tableVars[t.Name] {
			types[ty] = true
		}
	case *ast.CompositeLit:
		collect(t)
	}
	if len(types) == 0 && len(ids) == 0 {
		return nil, nil
	}
	return types, ids
}

func (a *funcAnalyzer) visit(n ast.Node) bool {
	switch s := n.(type) {
	case *ast.CallExpr:
		a.handleCall(s)
	case *ast.IfStmt:
		if !bodyHasFail(s.Body) {
			return true
		}
		// Overlay if-init assignments (`if f := runRule(T{}, r); len(f) != 0`):
		// the same variable name is often reused across sequential guards
		// for different rules, so resolve against this if's own initializer.
		type saved struct {
			vt   string
			hasV bool
			as   *ast.CallExpr
			hasA bool
		}
		savedMap := map[string]saved{}
		if initAssign, ok := s.Init.(*ast.AssignStmt); ok {
			for i, lhs := range initAssign.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || i >= len(initAssign.Rhs) {
					continue
				}
				call, ok := initAssign.Rhs[i].(*ast.CallExpr)
				if !ok {
					continue
				}
				sv := saved{}
				sv.vt, sv.hasV = a.varTypes[id.Name]
				sv.as, sv.hasA = a.assigns[id.Name]
				savedMap[id.Name] = sv
				a.assigns[id.Name] = call
				if t := a.ruleTypeOfCall(call); t != "" {
					a.varTypes[id.Name] = t
				} else {
					delete(a.varTypes, id.Name)
				}
			}
		}
		if ev, ok := a.condEvidence(s.Cond); ok {
			for id, pol := range ev {
				if pol > 0 {
					a.addPos(id)
				} else {
					a.addNeg(id)
				}
			}
		} else {
			// Fallback: the test author named the rule in the assertion
			// (usually the failure message). A fail-on-true guard naming a
			// rule is a negative assertion ("this must not happen").
			a.addNeg(ifLiterals(s)...)
		}
		for name, sv := range savedMap {
			if sv.hasV {
				a.varTypes[name] = sv.vt
			} else {
				delete(a.varTypes, name)
			}
			if sv.hasA {
				a.assigns[name] = sv.as
			} else {
				delete(a.assigns, name)
			}
		}
		return true
	case *ast.RangeStmt:
		// Shared negative: `for k, v := range <runnerVar> { t.Error... }`
		// fails on ANY finding, so every pack rule stayed quiet on a real
		// fixture.
		if id, ok := s.X.(*ast.Ident); ok && a.runnerVars[id.Name] && bodyHasFail(s.Body) {
			for rid := range a.idx.packSet {
				a.addNeg(rid)
			}
			return true
		}
		// Table-driven tests: `for _, c := range table()` — the loop body
		// asserts per table entry, so evidence attributes to every rule in
		// the table.
		if types, ids := a.tableKeysForRange(s.X); types != nil || ids != nil {
			if lv := loopVarName(s); lv != "" {
				savedT, hadT := a.loopTypes[lv]
				savedI, hadI := a.loopIDs[lv]
				if types != nil {
					a.loopTypes[lv] = types
				}
				if ids != nil {
					a.loopIDs[lv] = ids
				}
				ast.Inspect(s.Body, a.visit)
				if hadT {
					a.loopTypes[lv] = savedT
				} else {
					delete(a.loopTypes, lv)
				}
				if hadI {
					a.loopIDs[lv] = savedI
				} else {
					delete(a.loopIDs, lv)
				}
				return false
			}
		}
	}
	return true
}

func (a *funcAnalyzer) handleCall(s *ast.CallExpr) {
	switch callName(s) {
	case "mustFinding":
		if len(s.Args) >= 3 {
			ids := a.resolveRuleIDs(s.Args[2])
			if len(ids) == 0 {
				ids = a.attrib(s.Args[1])
			}
			a.addPos(ids...)
		}
	case "mustFire":
		// mustFire(t, src, ruleID, n): n>0 => positive, n==0 => negative.
		if len(s.Args) >= 4 {
			ids := a.resolveRuleIDs(s.Args[2])
			if n, ok := intLitOf(s.Args[3]); ok {
				if n > 0 {
					a.addPos(ids...)
				} else {
					a.addNeg(ids...)
				}
			}
		}
	case "expectFinding":
		// expectFinding(t, rule, r, want)
		if len(s.Args) >= 4 {
			if n, ok := intLitOf(s.Args[3]); ok {
				ids := a.attrib(s.Args[1])
				if n > 0 {
					a.addPos(ids...)
				} else {
					a.addNeg(ids...)
				}
			}
		}
	case "expectFindings":
		// expectFindings(t, rule, resources, want, ruleID)
		if len(s.Args) >= 5 {
			ids := a.resolveRuleIDs(s.Args[4])
			if n, ok := intLitOf(s.Args[3]); ok {
				if n > 0 {
					a.addPos(ids...)
				} else {
					a.addNeg(ids...)
				}
			}
		}
	case "mustQuiet":
		if len(s.Args) >= 2 {
			a.addNeg(a.attrib(s.Args[1])...)
		}
	}
	// wantOne(t, rule, r, id) / wantZero(t, rule, r, id) families
	// (incl. wantOneLambda/wantZeroLambda): positive/negative by prefix.
	if name := callName(s); strings.HasPrefix(name, "wantOne") {
		if len(s.Args) >= 1 {
			a.addPos(a.resolveRuleIDs(s.Args[len(s.Args)-1])...)
		}
	} else if strings.HasPrefix(name, "wantZero") {
		if len(s.Args) >= 1 {
			a.addNeg(a.resolveRuleIDs(s.Args[len(s.Args)-1])...)
		}
	}
}

// ruleIDComparison matches `f.RuleID != "AEGIS-..."` / `f.RuleID == "AEGIS-..."`
// and returns the rule ID.
func ruleIDComparison(be *ast.BinaryExpr) (string, bool) {
	check := func(a, b ast.Expr) (string, bool) {
		se, ok := a.(*ast.SelectorExpr)
		if !ok || se.Sel.Name != "RuleID" {
			return "", false
		}
		bl, ok := b.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(bl.Value)
		if err != nil || !idPattern.MatchString(s) {
			return "", false
		}
		return s, true
	}
	if id, ok := check(be.X, be.Y); ok {
		return id, true
	}
	return check(be.Y, be.X)
}

// compositeTypeName renders the type name of a composite literal
// (e.g. `tgwPermissivePropagation{}` or `&noProbe{}`).
func compositeTypeName(cl *ast.CompositeLit) string {
	switch t := cl.Type.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return id.Name
		}
	case *ast.SelectorExpr:
		return t.Sel.Name
	}
	return ""
}

// Command matrix regenerates benchmark/parity/support-matrix.json.
//
// It computes the per-adapter × per-rule applicability matrix without
// running a scan: each adapter's canonical IR type set is derived from its
// type-mapping table (parsed statically from the adapter source with
// go/parser, so the generator never drifts from the code), and each rule's
// AppliesTo predicate is evaluated live against that set via the real rule
// registry. terraform/planjson pass provider-native types straight through,
// so every rule is statically applicable to them (documented
// over-approximation, matching the original matrix).
//
// Usage:
//
//	go run ./benchmark/parity/cmd/matrix [-root <repo-root>] [-out <path>]
//
// Defaults: -root is the current working directory, -out is
// benchmark/parity/support-matrix.json under -root.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"aegis/internal/rules"
)

// adapters in canonical (alphabetical) order, matching support-matrix.json.
var adapterOrder = []string{
	"arm", "bicep", "cloudformation", "compose", "dockerfile",
	"manifests", "planjson", "pulumi", "terraform",
}

// wildcardAdapters pass provider-native types through untouched, so every
// rule is statically applicable to them.
var wildcardAdapters = map[string]bool{"terraform": true, "planjson": true}

// k8sKinds is the representative workload/RBAC kind list used to expand the
// manifests adapter's open-ended "k8s_<Kind>" type space. K8s rules apply by
// k8s_ prefix, so adapter membership is independent of the exact list; the
// list only bounds matched_types. (Derived from the kinds the k8s rules
// reason about: podSpecs workloads + RBAC + ConfigMap/Ingress/Service.)
var k8sKinds = []string{
	"ClusterRole", "ClusterRoleBinding", "ConfigMap", "Deployment",
	"Ingress", "Pod", "Role", "RoleBinding", "Service",
}

// stringMapValues parses the named map[string]string (or compatible)
// variable from a Go source file and returns its values.
func stringMapValues(path, varName string) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, err
	}
	var vals []string
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range vs.Names {
			if name.Name != varName || i >= len(vs.Values) {
				continue
			}
			lit, ok := vs.Values[i].(*ast.CompositeLit)
			if !ok {
				continue
			}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				vals = append(vals, compositeFirstString(kv.Value))
			}
		}
		return true
	})
	if vals == nil {
		return nil, fmt.Errorf("%s: variable %q not found", path, varName)
	}
	return vals, nil
}

// compositeFirstString extracts the string from either a plain "v" value or
// a {"v", ...} positional struct literal (pulumi's typeMapping).
func compositeFirstString(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.BasicLit:
		return strings.Trim(v.Value, `"`)
	case *ast.CompositeLit:
		if len(v.Elts) > 0 {
			return compositeFirstString(v.Elts[0])
		}
	}
	return ""
}

type matrixRule struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Adapters    []string `json:"adapters"`
	MatchedType []string `json:"matched_types"`
}

type matrix struct {
	Adapters    []string     `json:"adapters"`
	GeneratedBy string       `json:"generated_by"`
	Method      string       `json:"method"`
	RuleCount   int          `json:"rule_count"`
	Rules       []matrixRule `json:"rules"`
}

func main() {
	root := flag.String("root", ".", "repository root")
	out := flag.String("out", "", "output path (default <root>/benchmark/parity/support-matrix.json)")
	flag.Parse()
	if *out == "" {
		*out = filepath.Join(*root, "benchmark", "parity", "support-matrix.json")
	}
	ad := func(p string) string { return filepath.Join(*root, "internal", "adapter", p) }

	cfnVals, err := stringMapValues(filepath.Join(ad("cloudformation"), "typemap.go"), "cfnToTF")
	must(err)
	armVals, err := stringMapValues(filepath.Join(ad("arm"), "typemap.go"), "armTypeTable")
	must(err)
	pulumiVals, err := stringMapValues(filepath.Join(ad("pulumi"), "typemap.go"), "pulumiTypeTable")
	must(err)

	// Adapter -> canonical IR types it can emit. bicep reuses the ARM type
	// table (parity by construction: bicep.go delegates to arm.BuildResources).
	typeSets := map[string][]string{
		"arm":            dedup(armVals),
		"bicep":          dedup(armVals),
		"cloudformation": dedup(cfnVals),
		"compose":        {"compose_service"},
		"dockerfile":     {"docker_stage"},
		"pulumi":         dedup(pulumiVals),
	}
	var k8sTypes []string
	for _, k := range k8sKinds {
		k8sTypes = append(k8sTypes, "k8s_"+k)
	}
	typeSets["manifests"] = k8sTypes

	reg := rules.RegistryFor("all")
	all := reg.All()
	sort.Slice(all, func(i, j int) bool { return all[i].ID() < all[j].ID() })

	m := matrix{
		Adapters:    adapterOrder,
		GeneratedBy: "benchmark/parity/cmd/matrix",
		Method:      "static AppliesTo analysis against adapter typemap type lists; see file header | terraform/planjson adapters pass through native provider types, so all rules are applicable to them.",
		RuleCount:   len(all),
	}
	for _, r := range all {
		mr := matrixRule{ID: r.ID(), Severity: string(r.Severity())}
		matchedSet := map[string]bool{}
		for _, a := range adapterOrder {
			if wildcardAdapters[a] {
				mr.Adapters = append(mr.Adapters, a)
				continue
			}
			hit := false
			for _, t := range typeSets[a] {
				if r.AppliesTo(t) {
					matchedSet[t] = true
					hit = true
				}
			}
			if hit {
				mr.Adapters = append(mr.Adapters, a)
			}
		}
		for t := range matchedSet {
			mr.MatchedType = append(mr.MatchedType, t)
		}
		sort.Strings(mr.MatchedType)
		if mr.MatchedType == nil {
			mr.MatchedType = []string{}
		}
		m.Rules = append(m.Rules, mr)
	}

	// Match the committed file's formatting: 1-space indent.
	raw, err := json.MarshalIndent(m, "", " ")
	must(err)
	raw = append(raw, '\n')
	must(os.WriteFile(*out, raw, 0644))
	fmt.Printf("wrote %s (%d rules)\n", *out, len(all))
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "matrix:", err)
		os.Exit(1)
	}
}

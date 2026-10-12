// Graph traversal safety: cycles must terminate, 10k-node graphs must
// terminate, nothing may panic, and no rule may emit duplicate findings
// for the same underlying issue.
//
// The traversal surface under test: graph.Build, Graph.PubliclyExposed,
// attackpath.Builder (BuildKillChains, IAMChains), every AWS
// CrossResourceRule via CheckAll, and the full engine Registry.Run
// (concurrent rules + deterministic sort).
package graph_test

import (
	"fmt"
	"testing"
	"time"

	"aegis/internal/attackpath"
	"aegis/internal/graph"
	"aegis/internal/ir"
	"aegis/internal/rules"
	awsrules "aegis/internal/rules/aws"
)

func safetySpan(line int) ir.Span {
	return ir.Span{File: "safety.tf", StartLine: line, StartCol: 1, EndLine: line, EndCol: 20}
}

// cyclicResources builds A -> B -> C -> A reference cycles plus an open
// security group, so every traversal below has a real cycle to survive.
func cyclicResources() []ir.Resource {
	ref := func(target string, line int) ir.Value {
		return ir.Value{Known: false, Ref: target, Span: safetySpan(line)}
	}
	mk := func(name, peer string, line int) ir.Resource {
		return ir.Resource{
			Type: "aws_instance", Name: name, Provider: "aws",
			Attributes: map[string]ir.Value{"peer": ref(peer, line)},
			Span:       safetySpan(line),
		}
	}
	return []ir.Resource{
		mk("a", "aws_instance.b.id", 1),
		mk("b", "aws_instance.c.id", 5),
		mk("c", "aws_instance.a.id", 9),
		{
			Type: "aws_security_group", Name: "open", Provider: "aws",
			Attributes: map[string]ir.Value{
				"ingress": {Known: true, Span: safetySpan(13), Raw: []ir.Value{
					{Known: true, Span: safetySpan(14), Raw: map[string]ir.Value{
						"cidr_blocks": {Known: true, Span: safetySpan(15), Raw: []ir.Value{
							{Known: true, Raw: "0.0.0.0/0", Span: safetySpan(15)},
						}},
					}},
				}},
			},
			Span: safetySpan(13),
		},
	}
}

// chainResources builds n aws_instance nodes in a reference chain
// (n0 -> n1 -> ...), plus one open SG, one DB, and one LB so the
// attack-path builder has entry/workload/data hops to chew on.
func chainResources(n int) []ir.Resource {
	out := make([]ir.Resource, 0, n+3)
	for i := 0; i < n; i++ {
		attrs := map[string]ir.Value{}
		if i+1 < n {
			attrs["peer"] = ir.Value{
				Known: false,
				Ref:   fmt.Sprintf("aws_instance.n%04d.id", i+1),
				Span:  safetySpan(i + 1),
			}
		}
		out = append(out, ir.Resource{
			Type: "aws_instance", Name: fmt.Sprintf("n%04d", i), Provider: "aws",
			Attributes: attrs, Span: safetySpan(i + 1),
		})
	}
	out = append(out,
		ir.Resource{
			Type: "aws_security_group", Name: "open", Provider: "aws",
			Attributes: map[string]ir.Value{
				"ingress": {Known: true, Span: safetySpan(n + 1), Raw: []ir.Value{
					{Known: true, Span: safetySpan(n + 2), Raw: map[string]ir.Value{
						"cidr_blocks": {Known: true, Span: safetySpan(n + 2), Raw: []ir.Value{
							{Known: true, Raw: "0.0.0.0/0", Span: safetySpan(n + 2)},
						}},
					}},
				}},
			},
			Span: safetySpan(n + 1),
		},
		ir.Resource{
			Type: "aws_db_instance", Name: "data", Provider: "aws",
			Attributes: map[string]ir.Value{
				"vpc_security_group_ids": {Known: false, Ref: "aws_security_group.open.id", Span: safetySpan(n + 3)},
			},
			Span: safetySpan(n + 3),
		},
	)
	return out
}

// runTraversal exercises the whole traversal surface and returns every
// finding produced. It must terminate and must not panic.
func runTraversal(resources []ir.Resource) []ir.Finding {
	g := graph.Build(resources)
	for _, addr := range g.Nodes() {
		_ = g.PubliclyExposed(addr)
		_ = g.OutEdges(addr)
		_ = g.InEdges(addr)
	}
	b := attackpath.NewBuilder(resources)
	_ = b.BuildKillChains()
	_ = b.IAMChains()

	var findings []ir.Finding
	for _, rule := range awsrules.Rules() {
		if cr, ok := rule.(ir.CrossResourceRule); ok {
			findings = append(findings, cr.CheckAll(resources)...)
		}
	}
	reg := rules.RegistryFor("aegis-aws")
	findings = append(findings, reg.Run(resources)...)
	return findings
}

// withWatchdog runs fn and fails the test if it does not finish within
// limit. A hung traversal fails loudly instead of hanging the suite.
func withWatchdog(t *testing.T, limit time.Duration, name string, fn func() []ir.Finding) []ir.Finding {
	t.Helper()
	done := make(chan []ir.Finding, 1)
	go func() {
		done <- fn()
	}()
	select {
	case out := <-done:
		return out
	case <-time.After(limit):
		t.Fatalf("%s: traversal did not terminate within %s", name, limit)
		return nil
	}
}

func assertNoDuplicateFindings(t *testing.T, findings []ir.Finding) {
	t.Helper()
	seen := map[string]int{}
	for _, f := range findings {
		key := f.RuleID + "\x00" + f.Resource + "\x00" + f.Evidence.Attribute +
			"\x00" + f.Evidence.Actual + "\x00" + f.Evidence.Span.String()
		seen[key]++
		if seen[key] > 1 {
			t.Errorf("duplicate finding: rule %s resource %s attribute %q actual %q (x%d)",
				f.RuleID, f.Resource, f.Evidence.Attribute, f.Evidence.Actual, seen[key])
		}
	}
}

func TestGraphCycleTerminates(t *testing.T) {
	rs := cyclicResources()
	g := graph.Build(rs)
	// Sanity: the cycle really is in the graph.
	for from, to := range map[string]string{
		"aws_instance.a": "aws_instance.b",
		"aws_instance.b": "aws_instance.c",
		"aws_instance.c": "aws_instance.a",
	} {
		if !g.HasEdge(from, to) {
			t.Fatalf("expected cycle edge %s -> %s", from, to)
		}
	}
	findings := withWatchdog(t, 30*time.Second, "cyclic graph", func() []ir.Finding {
		return runTraversal(rs)
	})
	assertNoDuplicateFindings(t, findings)
}

func TestGraphTenKNodesTerminates(t *testing.T) {
	rs := chainResources(10000)
	if len(rs) < 10000 {
		t.Fatalf("expected >= 10000 resources, got %d", len(rs))
	}
	start := time.Now()
	findings := withWatchdog(t, 30*time.Second, "10k-node graph", func() []ir.Finding {
		return runTraversal(rs)
	})
	t.Logf("10k-node traversal: %d findings in %s", len(findings), time.Since(start).Round(time.Millisecond))
	assertNoDuplicateFindings(t, findings)
}

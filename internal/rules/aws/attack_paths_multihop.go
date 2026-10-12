package aws

import (
	"sort"
	"strings"

	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-AWS-105: Multi-hop network attack path to database
//
// Extends the single-hop paths of AEGIS-AWS-103 with transitive traversal:
//   - SG chains:    internet -> SG-A (world-open) -> SG-B (allows SG-A) -> RDS
//   - EC2 stepping: internet -> SG (world-open) -> EC2 -> RDS (shared SG)
//
// Only the SHORTEST path per (internet, RDS) is emitted, only when it
// requires 3+ edges (4+ nodes). Shorter paths are covered by AEGIS-AWS-103.
// BFS depth is capped at 4 edges to bound explosion. All iteration is
// deterministic: nodes and neighbors are sorted.
// ---------------------------------------------------------------------------

type multiHopPath struct{}

func (multiHopPath) ID() string { return "AEGIS-AWS-105" }
func (multiHopPath) Title() string {
	return "Multi-hop network attack path to database"
}
func (multiHopPath) Description() string {
	return "A database is reachable from the internet through a chain of " +
		"hops — e.g. a world-open security group leading to a second " +
		"security group, or a compromised EC2 stepping stone sharing the " +
		"database's security group. No single hop looks critical alone."
}
func (multiHopPath) Severity() ir.Severity { return ir.SeverityHigh }

func (multiHopPath) AppliesTo(resType string) bool {
	return resType == "aws_db_instance"
}

// Check cannot correlate on one resource; CheckAll performs the analysis.
func (multiHopPath) Check(ir.Resource) []ir.Finding { return nil }

func (multiHopPath) CheckAll(resources []ir.Resource) []ir.Finding {
	g := buildAttackGraph(resources)
	sorted := append([]ir.Resource(nil), resources...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Address() < sorted[j].Address()
	})
	var out []ir.Finding
	for _, r := range sorted {
		if r.Type != "aws_db_instance" {
			continue
		}
		path := shortestAttackPath(g, "internet", r.Address(), 4)
		if len(path) < 4 {
			// 0 = unreachable, 3 = internet->SG->RDS (covered by 103).
			// Only multi-hop paths (4+ nodes) belong to 105.
			continue
		}
		out = append(out, multiHopFinding(r, path, resources))
	}
	return out
}

var _ ir.CrossResourceRule = multiHopPath{}

// attackGraph is an adjacency list over "internet", SG, EC2, and RDS nodes.
type attackGraph struct {
	adj map[string][]string // node -> sorted unique neighbors
	res map[string]ir.Resource
}

// buildAttackGraph constructs the network-reachability graph:
//   - internet -> SG            when SG has world ingress
//   - SG-A -> SG-B             when SG-B's ingress references SG-A
//   - SG -> EC2                when EC2 attaches SG
//   - SG -> RDS                when RDS attaches SG
//   - EC2 -> RDS               when EC2 and RDS share an SG
func buildAttackGraph(resources []ir.Resource) *attackGraph {
	g := &attackGraph{adj: map[string][]string{}, res: map[string]ir.Resource{}}
	byAddr := map[string]ir.Resource{}
	for _, r := range resources {
		byAddr[r.Address()] = r
		g.res[r.Address()] = r
	}
	addEdge := func(from, to string) {
		if from == to {
			return
		}
		g.adj[from] = append(g.adj[from], to)
	}

	var sgs, ec2s, rdss []ir.Resource
	for _, r := range resources {
		switch r.Type {
		case "aws_security_group":
			sgs = append(sgs, r)
		case "aws_instance":
			ec2s = append(ec2s, r)
		case "aws_db_instance":
			rdss = append(rdss, r)
		}
	}

	// internet -> world-open SGs
	openSet := map[string]bool{}
	for _, sg := range openSGs(resources) {
		openSet[sg.Address()] = true
		addEdge("internet", sg.Address())
	}

	// SG attachment sets
	sgOfEC2 := map[string][]string{} // ec2 addr -> sorted SG addrs
	for _, e := range ec2s {
		sgOfEC2[e.Address()] = attachedSGs(e, byAddr)
	}
	sgOfRDS := map[string][]string{}
	for _, d := range rdss {
		sgOfRDS[d.Address()] = attachedSGs(d, byAddr)
	}

	// SG-A -> SG-B when SG-B's ingress references SG-A
	for _, sgB := range sgs {
		for _, sgAAddr := range sgIngressSources(sgB, byAddr) {
			if _, ok := byAddr[sgAAddr]; ok {
				addEdge(sgAAddr, sgB.Address())
			}
		}
	}

	// SG -> EC2, SG -> RDS via attachment
	for _, e := range ec2s {
		for _, sg := range sgOfEC2[e.Address()] {
			addEdge(sg, e.Address())
		}
	}
	for _, d := range rdss {
		for _, sg := range sgOfRDS[d.Address()] {
			addEdge(sg, d.Address())
		}
	}

	// EC2 -> RDS when they share an SG (stepping stone), or when RDS's SG
	// allows ingress from EC2's SG (lateral movement).
	for _, e := range ec2s {
		eSGs := map[string]bool{}
		for _, s := range sgOfEC2[e.Address()] {
			eSGs[s] = true
		}
		for _, d := range rdss {
			shared := false
			for _, s := range sgOfRDS[d.Address()] {
				if eSGs[s] {
					shared = true
					break
				}
			}
			if shared {
				addEdge(e.Address(), d.Address())
				continue
			}
			// RDS's SG allows from one of EC2's SGs.
			for _, rdsSG := range sgOfRDS[d.Address()] {
				allowed := false
				for _, src := range sgIngressSources(byAddr[rdsSG], byAddr) {
					if eSGs[src] {
						allowed = true
						break
					}
				}
				if allowed {
					addEdge(e.Address(), d.Address())
					break
				}
			}
		}
	}

	// Sort + dedupe neighbors for determinism.
	for from, tos := range g.adj {
		sort.Strings(tos)
		g.adj[from] = dedupeStrings(tos)
	}
	_ = openSet
	return g
}

// attachedSGs returns the sorted addresses of security groups attached to
// an EC2 instance or RDS via vpc_security_group_ids / security_groups.
// Only references resolving to known aws_security_group resources count.
func attachedSGs(r ir.Resource, byAddr map[string]ir.Resource) []string {
	seen := map[string]bool{}
	for _, attr := range []string{"vpc_security_group_ids", "security_groups"} {
		v, ok := r.Attributes[attr]
		if !ok {
			continue
		}
		for _, ref := range collectRefAddrs(ir.Resource{Attributes: map[string]ir.Value{"x": v}}) {
			if tgt, ok := byAddr[ref]; ok && tgt.Type == "aws_security_group" {
				seen[ref] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// sgIngressSources returns the addresses of security groups referenced by
// SG ingress rules via source_security_group_id (or security_groups).
// Only known aws_security_group targets count; unknown values are skipped.
func sgIngressSources(sg ir.Resource, byAddr map[string]ir.Resource) []string {
	seen := map[string]bool{}
	blks, _, present, known := getBlocks(sg, "ingress")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		for _, attr := range []string{"source_security_group_id", "security_groups"} {
			v, ok := b[attr]
			if !ok {
				continue
			}
			for _, ref := range collectRefAddrs(ir.Resource{Attributes: map[string]ir.Value{"x": v}}) {
				if tgt, ok := byAddr[ref]; ok && tgt.Type == "aws_security_group" {
					seen[ref] = true
				}
			}
		}
	}
	// Standalone rule resources pointing at this SG.
	for _, r := range byAddr {
		if r.Type != "aws_security_group_rule" && r.Type != "aws_vpc_security_group_ingress_rule" {
			continue
		}
		if t, _, p, k := getString(r, "type"); p && k && t == "egress" {
			continue
		}
		parent, ok := refTargetAddr(r, "security_group_id")
		if !ok || parent != sg.Address() {
			continue
		}
		for _, attr := range []string{"source_security_group_id"} {
			v, ok := r.Attributes[attr]
			if !ok {
				continue
			}
			for _, ref := range collectRefAddrs(ir.Resource{Attributes: map[string]ir.Value{"x": v}}) {
				if tgt, ok := byAddr[ref]; ok && tgt.Type == "aws_security_group" {
					seen[ref] = true
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// shortestAttackPath runs BFS from source, capped at maxDepth edges,
// returning the shortest node path to target (nil if unreachable within
// the cap). Neighbors are visited in sorted order: the first path found
// to a node is the deterministic shortest.
func shortestAttackPath(g *attackGraph, source, target string, maxDepth int) []string {
	if source == target {
		return []string{source}
	}
	prev := map[string]string{source: ""}
	depth := map[string]int{source: 0}
	queue := []string{source}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur == target {
			break
		}
		if depth[cur] >= maxDepth {
			continue
		}
		for _, nxt := range g.adj[cur] {
			if _, seen := prev[nxt]; seen {
				continue
			}
			prev[nxt] = cur
			depth[nxt] = depth[cur] + 1
			queue = append(queue, nxt)
		}
	}
	if _, ok := prev[target]; !ok {
		return nil
	}
	var path []string
	for n := target; n != ""; n = prev[n] {
		path = append([]string{n}, path...)
	}
	return path
}

// multiHopFinding builds the AEGIS-AWS-105 finding with per-hop evidence.
func multiHopFinding(rds ir.Resource, path []string, resources []ir.Resource) ir.Finding {
	byAddr := map[string]ir.Resource{}
	for _, r := range resources {
		byAddr[r.Address()] = r
	}
	steps := make([]ir.PathStep, 0, len(path))
	for i, node := range path {
		var detail string
		var span ir.Span
		switch {
		case node == "internet":
			detail = "public internet can reach the VPC via 0.0.0.0/0 ingress"
			if len(path) > 1 {
				if sg, ok := byAddr[path[1]]; ok {
					span = sg.Span
				}
			}
		case strings.HasPrefix(node, "aws_security_group."):
			if i == 0 {
				detail = "entry security group"
			} else {
				prev := path[i-1]
				if prev == "internet" {
					detail = "security group allows ingress from 0.0.0.0/0"
				} else {
					detail = "security group allows ingress from " + prev
				}
			}
			if sg, ok := byAddr[node]; ok {
				span = sg.Span
			}
		case strings.HasPrefix(node, "aws_instance."):
			detail = "EC2 instance reachable as a stepping stone"
			if inst, ok := byAddr[node]; ok {
				span = inst.Span
			}
		default:
			detail = "database reachable through the path"
			span = rds.Span
		}
		steps = append(steps, ir.PathStep{Resource: node, Detail: detail, Span: span})
	}
	return ir.Finding{
		RuleID:      "AEGIS-AWS-105",
		Title:       (multiHopPath{}).Title(),
		Description: (multiHopPath{}).Description(),
		Severity:    ir.SeverityHigh,
		Resource:    rds.Address(),
		Evidence: ir.Evidence{
			Attribute: "vpc_security_group_ids",
			Span:      rds.Span,
			Actual:    "reachable from the internet via " + strings.Join(path, " -> "),
			Expected:  "no world-reachable multi-hop path to the database",
		},
		Path: steps,
	}
}

func dedupeStrings(in []string) []string {
	out := in[:0]
	var prev string
	for i, s := range in {
		if i == 0 || s != prev {
			out = append(out, s)
		}
		prev = s
	}
	return out
}

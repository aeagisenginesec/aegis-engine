// Package graph builds a typed resource-reference graph over IR resources.
//
// Nodes are resources keyed by Address() ("type.name"). Edges are derived
// from unresolved reference values (ir.Value.Ref): a ref whose head names
// another known node becomes an edge. Refs to variables, locals, data
// sources, count/each/self, modules, or nonexistent resources never create
// edges — invalid paths are rejected, never invented.
//
// All iteration is deterministic: nodes and edges are sorted, map traversal
// is key-ordered, and duplicate addresses keep the first resource seen.
package graph

import (
	"sort"
	"strings"

	"aegis/internal/ir"
)

// Edge is a reference from one resource to another.
type Edge struct {
	From string // "type.name"
	To   string // "type.name"
	Via  string // the reference string that created the edge
}

// Graph is an immutable-after-Build resource reference graph.
type Graph struct {
	resources map[string]ir.Resource
	out       map[string][]Edge
	in        map[string][]Edge
	nodes     []string
}

// refSkipPrefixes are reference roots that never become graph edges:
// they name configuration values, not resources.
var refSkipPrefixes = []string{
	"var.", "local.", "data.", "each.", "count.", "self.",
	"module.", "terraform.", "path.",
}

// Build constructs the graph from resources. It never panics on any input.
func Build(resources []ir.Resource) *Graph {
	g := &Graph{
		resources: make(map[string]ir.Resource, len(resources)),
		out:       make(map[string][]Edge),
		in:        make(map[string][]Edge),
	}
	for _, r := range resources {
		addr := r.Address()
		if _, dup := g.resources[addr]; !dup {
			g.resources[addr] = r
		}
	}
	for addr := range g.resources {
		g.nodes = append(g.nodes, addr)
	}
	sort.Strings(g.nodes)

	for _, addr := range g.nodes {
		r := g.resources[addr]
		for _, key := range sortedKeysOf(r.Attributes) {
			g.walkValue(addr, r.Attributes[key])
		}
	}
	for addr, edges := range g.out {
		g.out[addr] = sortDedupeOut(edges)
	}
	for addr, edges := range g.in {
		g.in[addr] = sortDedupeIn(edges)
	}
	return g
}

// Nodes returns all resource addresses, sorted.
func (g *Graph) Nodes() []string {
	out := make([]string, len(g.nodes))
	copy(out, g.nodes)
	return out
}

// OutEdges returns edges from addr, sorted by To then Via.
func (g *Graph) OutEdges(addr string) []Edge {
	return append([]Edge(nil), g.out[addr]...)
}

// InEdges returns edges into addr, sorted by From then Via.
func (g *Graph) InEdges(addr string) []Edge {
	return append([]Edge(nil), g.in[addr]...)
}

// Resource returns the resource for addr.
func (g *Graph) Resource(addr string) (ir.Resource, bool) {
	r, ok := g.resources[addr]
	return r, ok
}

// HasEdge reports whether a reference edge exists from -> to.
func (g *Graph) HasEdge(from, to string) bool {
	for _, e := range g.out[from] {
		if e.To == to {
			return true
		}
	}
	return false
}

// walkValue recurses through attribute containers, adding an edge for every
// reference value it finds.
func (g *Graph) walkValue(from string, v ir.Value) {
	if v.IsRef() {
		g.addEdgeFromRef(from, v.Ref)
		return
	}
	if l, ok := v.AsList(); ok {
		for _, e := range l {
			g.walkValue(from, e)
		}
		return
	}
	if m, ok := v.AsMap(); ok {
		for _, k := range sortedKeysOf(m) {
			g.walkValue(from, m[k])
		}
	}
}

// addEdgeFromRef creates From->head for a dotted ref like
// "aws_s3_bucket.assets.arn". Refs to unknown nodes, self-refs, and
// non-resource roots are silently skipped.
func (g *Graph) addEdgeFromRef(from, ref string) {
	for _, p := range refSkipPrefixes {
		if strings.HasPrefix(ref, p) {
			return
		}
	}
	parts := strings.Split(ref, ".")
	if len(parts) < 2 {
		return
	}
	head := parts[0] + "." + stripIndexSuffix(parts[1])
	if head == from {
		return
	}
	if _, ok := g.resources[head]; !ok {
		return
	}
	e := Edge{From: from, To: head, Via: ref}
	g.out[from] = append(g.out[from], e)
	g.in[head] = append(g.in[head], e)
}

// stripIndexSuffix drops a trailing ["k"]/[n] index step from a path segment.
func stripIndexSuffix(seg string) string {
	if i := strings.Index(seg, "["); i >= 0 {
		return seg[:i]
	}
	return seg
}

// sortDedupeOut sorts by To, then Via, and drops duplicate triples.
func sortDedupeOut(edges []Edge) []Edge {
	cp := append([]Edge(nil), edges...)
	sort.Slice(cp, func(i, j int) bool {
		if cp[i].To != cp[j].To {
			return cp[i].To < cp[j].To
		}
		if cp[i].Via != cp[j].Via {
			return cp[i].Via < cp[j].Via
		}
		return cp[i].From < cp[j].From
	})
	return dedupe(cp)
}

// sortDedupeIn sorts by From, then Via, and drops duplicate triples.
func sortDedupeIn(edges []Edge) []Edge {
	cp := append([]Edge(nil), edges...)
	sort.Slice(cp, func(i, j int) bool {
		if cp[i].From != cp[j].From {
			return cp[i].From < cp[j].From
		}
		if cp[i].Via != cp[j].Via {
			return cp[i].Via < cp[j].Via
		}
		return cp[i].To < cp[j].To
	})
	return dedupe(cp)
}

func dedupe(edges []Edge) []Edge {
	out := edges[:0]
	var prev Edge
	for i, e := range edges {
		if i == 0 || e != prev {
			out = append(out, e)
		}
		prev = e
	}
	return out
}

func sortedKeysOf[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ---------------------------------------------------------------------------
// Exposure analysis
// ---------------------------------------------------------------------------

// PubliclyExposed reports whether the resource accepts traffic from the
// internet. Unknown or missing data always yields false — the analysis
// never fails open.
func (g *Graph) PubliclyExposed(addr string) bool {
	r, ok := g.resources[addr]
	if !ok {
		return false
	}
	switch r.Type {
	case "aws_security_group":
		return sgIngressOpen(r)
	case "aws_security_group_rule", "aws_vpc_security_group_ingress_rule":
		return ruleIngressOpen(r)
	case "aws_vpc_security_group_egress_rule":
		// An egress rule never constitutes inbound exposure by itself.
		return false
	}
	// An explicitly public database is exposed regardless of its SGs.
	if r.Type == "aws_db_instance" {
		if v, ok := r.Attr("publicly_accessible"); ok {
			if b, ok := v.AsBool(); ok && b {
				return true
			}
		}
	}
	// Otherwise: exposed iff an attached security group is exposed.
	for _, attrName := range []string{"vpc_security_group_ids", "security_groups"} {
		if v, ok := r.Attr(attrName); ok && g.sgAttrExposed(v) {
			return true
		}
	}
	return false
}

// sgIngressOpen reports whether any ingress block of a security group opens
// to the world.
func sgIngressOpen(r ir.Resource) bool {
	v, ok := r.Attr("ingress")
	if !ok {
		return false
	}
	blocks, ok := v.AsList()
	if !ok {
		return false
	}
	for _, b := range blocks {
		m, ok := b.AsMap()
		if !ok {
			continue
		}
		if cidrListOpen(m["cidr_blocks"]) || cidrListOpen(m["ipv6_cidr_blocks"]) {
			return true
		}
	}
	return false
}

// ruleIngressOpen reports whether a standalone ingress rule opens to the
// world. A known egress type, or any unknown/missing data, yields false.
func ruleIngressOpen(r ir.Resource) bool {
	if v, ok := r.Attr("type"); ok {
		if s, ok := v.AsString(); ok && s == "egress" {
			return false
		}
	}
	attrs := []string{"cidr_blocks", "ipv6_cidr_blocks"}
	for _, name := range attrs {
		if cidrListOpen(r.Attributes[name]) {
			return true
		}
	}
	// New-style VPC rule resources use singular cidr_ipv4 / cidr_ipv6.
	for _, name := range []string{"cidr_ipv4", "cidr_ipv6"} {
		if v, ok := r.Attr(name); ok && isOpenCIDR(v) {
			return true
		}
	}
	return false
}

// sgAttrExposed reports whether any security group referenced (by ref) in
// the attribute value is publicly exposed.
func (g *Graph) sgAttrExposed(v ir.Value) bool {
	if v.IsRef() {
		return g.sgRefExposed(v.Ref)
	}
	if l, ok := v.AsList(); ok {
		for _, e := range l {
			if g.sgAttrExposed(e) {
				return true
			}
		}
	}
	if m, ok := v.AsMap(); ok {
		for _, k := range sortedKeysOf(m) {
			if g.sgAttrExposed(m[k]) {
				return true
			}
		}
	}
	return false
}

// sgRefExposed resolves a ref head to a security group node and checks it.
func (g *Graph) sgRefExposed(ref string) bool {
	parts := strings.Split(ref, ".")
	if len(parts) < 2 {
		return false
	}
	head := parts[0] + "." + stripIndexSuffix(parts[1])
	if parts[0] != "aws_security_group" {
		return false
	}
	if _, ok := g.resources[head]; !ok {
		return false
	}
	return g.PubliclyExposed(head)
}

// cidrListOpen reports whether a known list value contains an open CIDR.
func cidrListOpen(v ir.Value) bool {
	l, ok := v.AsList()
	if !ok {
		return false
	}
	for _, e := range l {
		if isOpenCIDR(e) {
			return true
		}
	}
	return false
}

// isOpenCIDR reports whether a known string value is an internet-wide CIDR.
func isOpenCIDR(v ir.Value) bool {
	s, ok := v.AsString()
	if !ok {
		return false
	}
	s = strings.TrimSpace(s)
	return s == "0.0.0.0/0" || s == "::/0"
}

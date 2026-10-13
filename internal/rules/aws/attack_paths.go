package aws

import (
	"sort"
	"strings"

	"aegis/internal/graph"
	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-AWS-103: Public RDS exposure path
// ---------------------------------------------------------------------------

type rdsPublicPath struct{}

func (rdsPublicPath) ID() string { return "AEGIS-AWS-103" }
func (rdsPublicPath) Title() string {
	return "Public RDS exposure path"
}
func (rdsPublicPath) Description() string {
	return "An RDS instance is publicly accessible AND reachable from the " +
		"internet through an open security group: a complete network path " +
		"exists from the internet to the database."
}
func (rdsPublicPath) Severity() ir.Severity { return ir.SeverityHigh }

func (rdsPublicPath) AppliesTo(resType string) bool {
	return resType == "aws_db_instance"
}

// Check cannot correlate on one resource; CheckAll performs the analysis.
func (rdsPublicPath) Check(ir.Resource) []ir.Finding { return nil }

func (rdsPublicPath) CheckAll(resources []ir.Resource) []ir.Finding {
	g := graph.Build(resources)
	// Hoisted out of the per-RDS closure: the open-SG set does not depend
	// on the RDS, so recomputing it per public RDS was O(n) per RDS.
	open := openSGs(resources)
	return findRDSPaths(resources,
		func(addr string) bool { return g.PubliclyExposed(addr) },
		func(rds ir.Resource) *ir.Resource { return pickPathSG(rds, g, open) },
	)
}

var _ ir.CrossResourceRule = rdsPublicPath{}

// findRDSPaths is the testable core of AEGIS-AWS-103: for every publicly
// accessible RDS instance that the reachability function marks exposed,
// emit one correlated finding with an internet -> SG -> RDS path.
func findRDSPaths(resources []ir.Resource, exposed func(string) bool, sgFor func(ir.Resource) *ir.Resource) []ir.Finding {
	sorted := append([]ir.Resource(nil), resources...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Address() < sorted[j].Address()
	})
	var out []ir.Finding
	for _, r := range sorted {
		if r.Type != "aws_db_instance" {
			continue
		}
		pub, pubSpan, present, known := getBool(r, "publicly_accessible")
		if !present || !known || !pub {
			continue // absent/false/unresolved: no public flag, no path
		}
		if !exposed(r.Address()) {
			continue // not reachable from the internet per the graph
		}
		sg := sgFor(r)
		if sg == nil {
			// No open SG attached to this RDS could be identified.
			// A path must never name a hop it cannot prove: rule 011
			// still reports publicly_accessible=true on its own.
			continue
		}
		steps := []ir.PathStep{
			{Resource: "internet", Detail: "public internet can reach the VPC via 0.0.0.0/0 ingress", Span: sg.Span},
			{Resource: sg.Address(), Detail: "security group allows ingress from 0.0.0.0/0", Span: sg.Span},
			{Resource: r.Address(), Detail: "RDS instance is publicly accessible", Span: r.Span},
		}
		out = append(out, ir.Finding{
			RuleID:      "AEGIS-AWS-103",
			Title:       (rdsPublicPath{}).Title(),
			Description: (rdsPublicPath{}).Description(),
			Severity:    ir.SeverityHigh,
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: "publicly_accessible",
				Span:      evidenceSpan(pubSpan, r.Span),
				Actual:    "true, and the instance is reachable from the internet",
				Expected:  "publicly_accessible = false or no world-ingress path",
			},
			Path: steps,
		})
	}
	return out
}

// pickPathSG returns the open security group attached to the RDS, or nil.
// Only an SG the RDS actually references (via vpc_security_group_ids or a
// graph edge) may appear in its attack path — never "the first open SG
// anywhere". A nil graph is treated as having no edges.
func pickPathSG(rds ir.Resource, g *graph.Graph, open []ir.Resource) *ir.Resource {
	refs := map[string]bool{}
	for _, a := range collectRefAddrs(rds) {
		refs[a] = true
	}
	// Graph edges run RDS -> SG (the ref lives in the RDS resource).
	if g != nil {
		for _, e := range g.OutEdges(rds.Address()) {
			if res, ok := g.Resource(e.To); ok && res.Type == "aws_security_group" {
				refs[res.Address()] = true
			}
		}
	}
	byAddr := map[string]ir.Resource{}
	for _, s := range open {
		byAddr[s.Address()] = s
	}
	// open is address-sorted; first attached open SG wins (deterministic).
	for _, s := range open {
		if refs[s.Address()] {
			c := s
			return &c
		}
	}
	return nil
}

// openSGs returns every security group with world ingress, address-sorted:
// inline ingress blocks on aws_security_group, plus standalone
// aws_security_group_rule (type=ingress) and
// aws_vpc_security_group_ingress_rule resources mapped to their parent SG
// via the security_group_id reference.
func openSGs(resources []ir.Resource) []ir.Resource {
	byAddr := map[string]ir.Resource{}
	for _, r := range resources {
		byAddr[r.Address()] = r
	}
	open := map[string]ir.Resource{}
	markOpen := func(addr string) {
		if r, ok := byAddr[addr]; ok && r.Type == "aws_security_group" {
			open[addr] = r
		}
	}
	for _, r := range resources {
		switch r.Type {
		case "aws_security_group":
			if sgHasWorldIngress(r) {
				open[r.Address()] = r
			}
		case "aws_security_group_rule":
			t, _, present, known := getString(r, "type")
			if !present || !known || t != "ingress" {
				continue
			}
			if ruleHasWorldCIDRs(r, "cidr_blocks") {
				if addr, ok := refTargetAddr(r, "security_group_id"); ok {
					markOpen(addr)
				}
			}
		case "aws_vpc_security_group_ingress_rule":
			if ruleHasWorldCIDRs(r, "cidr_ipv4") {
				if addr, ok := refTargetAddr(r, "security_group_id"); ok {
					markOpen(addr)
				}
			}
		}
	}
	out := make([]ir.Resource, 0, len(open))
	for _, r := range open {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Address() < out[j].Address() })
	return out
}

// sgHasWorldIngress reports whether an aws_security_group has any ingress
// block with 0.0.0.0/0 in cidr_blocks. Unresolved blocks are skipped.
func sgHasWorldIngress(r ir.Resource) bool {
	blks, _, present, known := getBlocks(r, "ingress")
	if !present || !known {
		return false
	}
	for _, b := range blks {
		cidrs, allKnown := blockStrings(b, "cidr_blocks")
		if !allKnown {
			continue
		}
		if findStringFold(cidrs, worldCIDR) {
			return true
		}
	}
	return false
}

// ruleHasWorldCIDRs checks a single-rule resource's CIDR attribute (string
// or list) for 0.0.0.0/0. Unknown or misshapen values yield false.
func ruleHasWorldCIDRs(r ir.Resource, attr string) bool {
	v, ok := r.Attributes[attr]
	if !ok || !v.Known {
		return false
	}
	if s, ok := v.AsString(); ok {
		return findStringFold([]string{s}, worldCIDR)
	}
	l, ok := v.AsList()
	if !ok {
		return false
	}
	for _, item := range l {
		s, ok := item.AsString()
		if !ok || !findStringFold([]string{s}, worldCIDR) {
			return false
		}
	}
	return len(l) > 0
}

// refTargetAddr resolves a reference attribute to a "type.name" address by
// stripping the trailing attribute segment: "aws_security_group.db.id" ->
// "aws_security_group.db". A known plain string is returned as-is (the
// caller decides how to match it).
func refTargetAddr(r ir.Resource, attr string) (string, bool) {
	v, ok := r.Attributes[attr]
	if !ok {
		return "", false
	}
	if v.IsRef() {
		parts := strings.Split(v.Ref, ".")
		// Find the resource-type segment (handles module-qualified refs).
		for i, p := range parts {
			if strings.HasPrefix(p, "aws_") && i+1 < len(parts) {
				return p + "." + parts[i+1], true
			}
		}
		return "", false
	}
	if s, ok := v.AsString(); ok {
		return s, true
	}
	return "", false
}

// collectRefAddrs walks a resource's attributes collecting every
// "type.name" address reachable through reference values.
func collectRefAddrs(r ir.Resource) []string {
	seen := map[string]bool{}
	var walk func(v ir.Value)
	walk = func(v ir.Value) {
		if v.IsRef() {
			if addr, ok := refAddrOf(v.Ref); ok {
				seen[addr] = true
			}
			return
		}
		// Descend into containers even when unknown: the M2 semantics
		// layer preserves references inside unknown containers.
		switch t := v.Raw.(type) {
		case []ir.Value:
			for _, item := range t {
				walk(item)
			}
		case map[string]ir.Value:
			for _, item := range t {
				walk(item)
			}
		}
	}
	for _, v := range r.Attributes {
		walk(v)
	}
	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// refAddrOf reduces a dotted reference to its "type.name" address.
// Handles module-prefixed names: "aws_s3_bucket.module.m.data.id"
// -> "aws_s3_bucket.module.m.data".
func refAddrOf(ref string) (string, bool) {
	parts := strings.Split(ref, ".")
	for i, p := range parts {
		if strings.HasPrefix(p, "aws_") && i+1 < len(parts) {
			// Collect the full resource name, including module prefixes.
			// Format: type.(module.<name>.)*name.attr
			addr := p
			j := i + 1
			for j < len(parts) {
				if parts[j] == "module" && j+1 < len(parts) {
					addr += "." + parts[j] + "." + parts[j+1]
					j += 2
				} else {
					addr += "." + parts[j]
					j++
					break
				}
			}
			return addr, true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-104: Public S3 exfiltration path
// ---------------------------------------------------------------------------

type s3ExfiltrationPath struct{}

func (s3ExfiltrationPath) ID() string { return "AEGIS-AWS-104" }
func (s3ExfiltrationPath) Title() string {
	return "Public S3 exfiltration path"
}
func (s3ExfiltrationPath) Description() string {
	return "An S3 bucket is readable by the public internet through a bucket " +
		"policy granting s3:GetObject to everyone, or a public ACL: a " +
		"complete path exists from the internet to the bucket's data."
}
func (s3ExfiltrationPath) Severity() ir.Severity { return ir.SeverityCritical }

func (s3ExfiltrationPath) AppliesTo(resType string) bool {
	return resType == "aws_s3_bucket"
}

// Check cannot correlate on one resource; CheckAll performs the analysis.
func (s3ExfiltrationPath) Check(ir.Resource) []ir.Finding { return nil }

func (s3ExfiltrationPath) CheckAll(resources []ir.Resource) []ir.Finding {
	sorted := append([]ir.Resource(nil), resources...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Address() < sorted[j].Address()
	})
	// Index policies and ACLs by the bucket address they target.
	policies := map[string][]ir.Resource{}
	acls := map[string][]ir.Resource{}
	for _, r := range sorted {
		switch r.Type {
		case "aws_s3_bucket_policy":
			if addr, ok := policyBucketAddr(r, sorted); ok {
				policies[addr] = append(policies[addr], r)
			}
		case "aws_s3_bucket_acl":
			if addr, ok := policyBucketAddr(r, sorted); ok {
				acls[addr] = append(acls[addr], r)
			}
		}
	}
	var out []ir.Finding
	for _, b := range sorted {
		if b.Type != "aws_s3_bucket" {
			continue
		}
		if f := checkBucketExfiltration(b, policies[scopeKey(b)], acls[scopeKey(b)]); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

var _ ir.CrossResourceRule = s3ExfiltrationPath{}

// policyBucketAddr resolves which bucket a policy/ACL resource targets via
// its `bucket` attribute: a reference ("aws_s3_bucket.assets.id") or a
// known name matched against the bucket set. A CloudFormation !Ref to a
// resource logical ID ("cfn.resource.X") matches by the bucket's Name
// (its CFN logical ID), mirroring linkedBucketAddr in helpers.go.
// Unresolvable -> false.
func policyBucketAddr(r ir.Resource, buckets []ir.Resource) (string, bool) {
	v, ok := r.Attributes["bucket"]
	if !ok {
		return "", false
	}
	if v.IsRef() {
		// CloudFormation !Ref to a resource logical ID: "cfn.resource.X".
		// Match by the bucket's Name (its CFN logical ID) in scope.
		if strings.HasPrefix(v.Ref, "cfn.resource.") {
			lid := strings.TrimPrefix(v.Ref, "cfn.resource.")
			for _, b := range buckets {
				if b.Type != "aws_s3_bucket" || !sameScope(r, b) {
					continue
				}
				if b.Name == lid {
					return scopeKey(b), true
				}
			}
			return "", false
		}
		addr, ok := refAddrOf(v.Ref)
		if !ok {
			return "", false
		}
		for _, b := range buckets {
			if b.Address() == addr && sameScope(r, b) {
				return scopeKey(b), true
			}
		}
		return "", false
	}
	name, ok := v.AsString()
	if !ok {
		return "", false // unknown or misshapen: cannot attribute
	}
	name = strings.TrimSpace(name)
	for _, b := range buckets {
		if b.Type != "aws_s3_bucket" {
			continue
		}
		if !sameScope(r, b) {
			continue
		}
		if b.Name == name {
			return scopeKey(b), true
		}
		if bn, _, _, known := getString(b, "bucket"); known && strings.TrimSpace(bn) == name {
			return scopeKey(b), true
		}
	}
	return "", false
}

// checkBucketExfiltration emits at most one finding per bucket, preferring
// the bucket-policy grant over the ACL grant. Unknown/malformed policy
// documents and non-public ACLs yield nothing.
func checkBucketExfiltration(b ir.Resource, policies, acls []ir.Resource) *ir.Finding {
	for _, p := range policies {
		doc, span, present, known := getString(p, "policy")
		if !present || !known {
			continue // cannot decide for this policy
		}
		if policyGrantsPublicRead(doc) {
			grantSpan := evidenceSpan(span, p.Span)
			return &ir.Finding{
				RuleID:      "AEGIS-AWS-104",
				Title:       (s3ExfiltrationPath{}).Title(),
				Description: (s3ExfiltrationPath{}).Description(),
				Severity:    ir.SeverityCritical,
				Resource:    b.Address(),
				Evidence: ir.Evidence{
					Attribute: "policy",
					Span:      grantSpan,
					Actual:    "bucket policy allows s3:GetObject for Principal \"*\"",
					Expected:  "no public s3:GetObject grant in the bucket policy",
				},
				Path: []ir.PathStep{
					{Resource: "internet", Detail: "anonymous requests from the public internet", Span: grantSpan},
					{Resource: p.Address(), Detail: "bucket policy grants s3:GetObject to everyone", Span: grantSpan},
					{Resource: b.Address(), Detail: "bucket data is readable under the public grant", Span: b.Span},
				},
			}
		}
	}
	for _, a := range acls {
		acl, span, present, known := getString(a, "acl")
		if !present || !known {
			continue
		}
		if isPublicACL(acl) {
			grantSpan := evidenceSpan(span, a.Span)
			return &ir.Finding{
				RuleID:      "AEGIS-AWS-104",
				Title:       (s3ExfiltrationPath{}).Title(),
				Description: (s3ExfiltrationPath{}).Description(),
				Severity:    ir.SeverityCritical,
				Resource:    b.Address(),
				Evidence: ir.Evidence{
					Attribute: "acl",
					Span:      grantSpan,
					Actual:    "bucket ACL is " + strings.TrimSpace(acl),
					Expected:  "private ACL with public access blocked",
				},
				Path: []ir.PathStep{
					{Resource: "internet", Detail: "anonymous requests from the public internet", Span: grantSpan},
					{Resource: a.Address(), Detail: "bucket ACL grants public read", Span: grantSpan},
					{Resource: b.Address(), Detail: "bucket data is readable under the public ACL", Span: b.Span},
				},
			}
		}
	}
	// Legacy inline ACL on the bucket itself.
	if acl, span, present, known := getString(b, "acl"); present && known && isPublicACL(acl) {
		grantSpan := evidenceSpan(span, b.Span)
		return &ir.Finding{
			RuleID:      "AEGIS-AWS-104",
			Title:       (s3ExfiltrationPath{}).Title(),
			Description: (s3ExfiltrationPath{}).Description(),
			Severity:    ir.SeverityCritical,
			Resource:    b.Address(),
			Evidence: ir.Evidence{
				Attribute: "acl",
				Span:      grantSpan,
				Actual:    "bucket ACL is " + strings.TrimSpace(acl),
				Expected:  "private ACL with public access blocked",
			},
			Path: []ir.PathStep{
				{Resource: "internet", Detail: "anonymous requests from the public internet", Span: grantSpan},
				{Resource: b.Address(), Detail: "bucket ACL grants public read", Span: b.Span},
				{Resource: b.Address(), Detail: "bucket data is readable under the public ACL", Span: b.Span},
			},
		}
	}
	return nil
}

// policyGrantsPublicRead reports whether any Allow statement grants
// s3:GetObject (or s3:*) to Principal "*". Malformed JSON or unexpected
// shapes yield false (cannot decide -> no finding).
// policyGrantsPublicRead reports whether a policy document grants
// s3:GetObject (or s3:*) to everyone. Statement keys are matched
// case-insensitively: some adapters snake_case document keys
// (Statement -> statement, Effect -> effect), and the public-read
// conclusion must not depend on the producer's casing (same rationale
// as policyAllowsPublicPrincipal in s3.go).
func policyGrantsPublicRead(doc string) bool {
	for _, s := range policyStatements(doc) {
		eff, _ := lookupMapFold(s, "Effect").(string)
		if eff != "Allow" {
			continue
		}
		if lookupMapFold(s, "NotPrincipal") != nil {
			continue
		}
		if !principalAllowsAnyone(lookupMapFold(s, "Principal")) {
			continue
		}
		if actionMatches(lookupMapFold(s, "Action"), "s3:GetObject", "s3:*") {
			return true
		}
	}
	return false
}

// actionMatches reports whether v (string or list) contains any of the
// target actions (case-insensitive, trimmed).
func actionMatches(v any, targets ...string) bool {
	match := func(s string) bool {
		s = strings.TrimSpace(s)
		for _, t := range targets {
			if strings.EqualFold(s, t) {
				return true
			}
		}
		return false
	}
	switch t := v.(type) {
	case string:
		return match(t)
	case []any:
		for _, item := range t {
			if s, ok := item.(string); ok && match(s) {
				return true
			}
		}
	}
	return false
}

// isPublicACL reports whether an ACL value grants public read.
func isPublicACL(acl string) bool {
	switch strings.ToLower(strings.TrimSpace(acl)) {
	case "public-read", "public-read-write":
		return true
	}
	return false
}

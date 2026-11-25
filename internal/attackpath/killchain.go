package attackpath

import (
	"sort"
	"strings"

	"aegis/internal/ir"
)

// IAMChains returns the IAM privilege chains found by the builder.
// Exported for rule use; each chain traces role → policy → workload.
func (b *Builder) IAMChains() []IAMChain {
	return b.findIAMChains()
}

// uncertainEntryHop builds the placeholder hop for a workload with no
// proven internet entry point. The chain is still reported, but the entry
// is explicitly uncertain — never an invented concrete entry.
func uncertainEntryHop(wl Hop) Hop {
	entryHop := Hop{
		Resource:   "internet",
		Kind:       KindEntry,
		Detail:     "no internet entry point proven for this workload",
		Evidence:   ir.Evidence{Attribute: "entry", Span: wl.Evidence.Span},
		Confidence: ConfidenceLow,
	}
	MarkUncertain(&entryHop, "UNCERTAIN: no public ALB or world-open SG reaches "+wl.Resource)
	return entryHop
}

// iamLinkHops builds the identity hops for one IAM reachability link:
// role → policy → permission edge. The permission-edge hop names the
// grant and the target it reaches, with the policy statement as evidence,
// so a reader can tell an IAM edge from a network edge. When the grant
// comes from managed_policy_arns on the role itself (policy address ==
// role address), there is no separate policy resource: the role hop and
// the edge hop merge into one hop that names both the assumption and the
// managed grant, so the role never appears twice in a row.
func iamLinkHops(link IAMReachLink, b *Builder) []Hop {
	var hops []Hop
	role, ok := b.byAddr[link.Role]
	roleSpan := ir.Span{}
	if ok {
		roleSpan = role.Span
	}
	if link.Policy == link.Role {
		detail := "IAM role assumed by workload"
		if link.OpenTrust {
			detail = "IAM role assumable by any AWS principal (open trust policy)"
		}
		detail += "; attaches AWS-managed AdministratorAccess, granting " +
			strings.Join(link.Actions, ", ") + " on " + link.Target +
			" — no network path needed"
		return []Hop{{
			Resource:   link.Role,
			Kind:       KindIdentity,
			Detail:     detail,
			Evidence:   link.Evidence,
			Confidence: ConfidenceHigh,
		}}
	}
	roleDetail := "IAM role assumed by workload"
	if link.OpenTrust {
		roleDetail = "IAM role assumable by any AWS principal (open trust policy)"
	}
	hops = append(hops, Hop{
		Resource:   link.Role,
		Kind:       KindIdentity,
		Detail:     roleDetail,
		Evidence:   ir.Evidence{Attribute: "role", Span: roleSpan, Actual: link.Role},
		Confidence: ConfidenceHigh,
	})
	edgeDetail := "IAM reachability: " + link.Role + " grants " +
		strings.Join(link.Actions, ", ") + " on " + link.Target +
		" (Resource " + link.Resource + ") — no network path needed"
	hops = append(hops, Hop{
		Resource:   link.Policy,
		Kind:       KindIdentity,
		Detail:     "IAM policy grants: " + strings.Join(link.Actions, ", "),
		Evidence:   link.Evidence,
		Confidence: ConfidenceHigh,
	})
	hops = append(hops, Hop{
		Resource:   link.Policy,
		Kind:       KindIdentity,
		Detail:     edgeDetail,
		Evidence:   link.Evidence,
		Confidence: ConfidenceHigh,
	})
	return hops
}

// BuildKillChains assembles complete attack chains:
//
//	INTERNET → [entry: ALB or world-open SG] → [workload: EC2/Lambda/ECS]
//	         → [identity: IAM role chain, if present] → [data: RDS/S3/DynamoDB]
//
// plus IAM-permission chains (v2.4.0): a workload reaches a data store
// through an over-broad IAM grant even with no network edge, and an
// open-trust role reaches a data store directly from the internet:
//
//	INTERNET → [entry] → [workload] → [IAM role → policy → permission edge] → [data]
//	INTERNET → [open-trust role → policy → permission edge] → [data]
//
// Every hop cites evidence. Hops that cannot be proven are marked
// UNCERTAIN, never invented. Chains are deduplicated and sorted
// deterministically.
func (b *Builder) BuildKillChains() []Chain {
	var chains []Chain

	entries := append(b.findPublicALBs(), b.findOpenSGs()...)
	workloads := b.findWorkloads()
	dataStores := b.findDataStores()
	iamChains := b.findIAMChains()
	reachLinks := b.findIAMReachLinks()

	// Index IAM chains by workload for quick lookup.
	iamByWorkload := make(map[string][]IAMChain)
	for _, ic := range iamChains {
		iamByWorkload[ic.Workload.Resource] = append(iamByWorkload[ic.Workload.Resource], ic)
	}

	// Index IAM reachability links by workload -> target, and collect
	// open-trust (role-only) links separately.
	wlLinks := make(map[string]map[string][]IAMReachLink)
	var openTrustLinks []IAMReachLink
	for _, link := range reachLinks {
		if link.OpenTrust {
			openTrustLinks = append(openTrustLinks, link)
			continue
		}
		if wlLinks[link.Workload] == nil {
			wlLinks[link.Workload] = make(map[string][]IAMReachLink)
		}
		wlLinks[link.Workload][link.Target] = append(wlLinks[link.Workload][link.Target], link)
	}

	// Precompute every resource's SG attachment set once. The correlation
	// loops below previously re-parsed securityGroupsOf per
	// (data, workload, entry) triple — O(d*w*e) redundant parses of the
	// same attributes. sgSets makes each lookup O(1).
	sgSets := make(map[string]map[string]bool, len(b.byAddr))
	for addr, r := range b.byAddr {
		sgSets[addr] = securityGroupsOf(r)
	}

	// entriesReaching depends only on the workload, not the data store:
	// memoize it per workload instead of recomputing it for every
	// (data, workload) pair.
	entryCache := make(map[string][]Hop)

	// For each data store, find reachable workloads via graph edges,
	// then find entry points that reach those workloads.
	workloadHops := make(map[string]Hop, len(workloads))
	for _, wl := range workloads {
		workloadHops[wl.Resource] = wl
	}
	for _, data := range dataStores {
		reaching := b.workloadsReaching(data.Resource, workloads, sgSets)
		netSet := make(map[string]bool, len(reaching))
		for _, wl := range reaching {
			netSet[wl.Resource] = true
		}
		// IAM-only workloads: reachable through an over-broad grant
		// with no network edge. They join the same per-workload loop
		// but take the IAM branch below, so network chains keep their
		// exact existing shape.
		for wlAddr, targets := range wlLinks {
			if _, ok := targets[data.Resource]; !ok {
				continue
			}
			if netSet[wlAddr] {
				continue
			}
			if wl, ok := workloadHops[wlAddr]; ok {
				reaching = append(reaching, wl)
			}
		}
		sort.Slice(reaching, func(i, j int) bool {
			return reaching[i].Resource < reaching[j].Resource
		})
		for _, wl := range reaching {
			entriesReaching, ok := entryCache[wl.Resource]
			if !ok {
				entriesReaching = b.entriesReaching(wl.Resource, entries, sgSets)
				entryCache[wl.Resource] = entriesReaching
			}
			if netSet[wl.Resource] {
				for _, entry := range entriesReaching {
					hops := []Hop{entry, wl}
					// Attach IAM privilege hops if this workload has them.
					for _, ic := range iamByWorkload[wl.Resource] {
						hops = append(hops, ic.Role, ic.Policy)
					}
					hops = append(hops, data)
					chains = append(chains, NewChain(hops))
				}
				// Workload → data without a proven entry: still a lateral
				// movement chain, but the entry is uncertain.
				if len(entriesReaching) == 0 {
					hops := []Hop{uncertainEntryHop(wl), wl}
					for _, ic := range iamByWorkload[wl.Resource] {
						hops = append(hops, ic.Role, ic.Policy)
					}
					hops = append(hops, data)
					chains = append(chains, NewChain(hops))
				}
				continue
			}
			// IAM-only reachability: one chain per granting link, with
			// an explicit permission-edge hop naming the grant and its
			// target. A workload with no proven entry still gets the
			// uncertain-entry hop, exactly like a network chain.
			for _, link := range wlLinks[wl.Resource][data.Resource] {
				linkHops := iamLinkHops(link, b)
				if len(entriesReaching) == 0 {
					hops := []Hop{uncertainEntryHop(wl), wl}
					hops = append(hops, linkHops...)
					hops = append(hops, data)
					chains = append(chains, NewChain(hops))
					continue
				}
				for _, entry := range entriesReaching {
					hops := []Hop{entry, wl}
					hops = append(hops, linkHops...)
					hops = append(hops, data)
					chains = append(chains, NewChain(hops))
				}
			}
		}
	}

	// Open-trust chains: a role anyone can assume whose policy grants
	// data-plane actions on an in-scope data store is reachable directly
	// from the internet — no workload compromise is needed. The entry hop
	// is the open trust policy itself, cited as evidence.
	for _, link := range openTrustLinks {
		dataRes, ok := b.byAddr[link.Target]
		if !ok {
			continue
		}
		label, ok := dataTypes[dataRes.Type]
		if !ok {
			label = "data store"
		}
		entryHop := Hop{
			Resource:   "internet",
			Kind:       KindEntry,
			Detail:     "any AWS principal can assume " + link.Role + " via an open trust policy (Principal \"*\")",
			Evidence:   link.TrustEvidence,
			Confidence: ConfidenceHigh,
		}
		dataHop := Hop{
			Resource:   link.Target,
			Kind:       KindData,
			Detail:     label + " — sensitive data objective",
			Evidence:   ir.Evidence{Attribute: "resource", Span: dataRes.Span, Actual: link.Target},
			Confidence: ConfidenceHigh,
		}
		hops := []Hop{entryHop}
		hops = append(hops, iamLinkHops(link, b)...)
		hops = append(hops, dataHop)
		chains = append(chains, NewChain(hops))
	}

	return dedupeChains(chains)
}

// workloadsReaching returns workload hops that have a graph path to the
// data store address (direct reference edge or shared security group).
// sgSets is the precomputed per-resource SG attachment index: every lookup
// is O(1) instead of re-parsing the resource's attributes per pair.
func (b *Builder) workloadsReaching(dataAddr string, workloads []Hop, sgSets map[string]map[string]bool) []Hop {
	var out []Hop
	if _, ok := b.byAddr[dataAddr]; !ok {
		return nil
	}
	dataSGs := sgSets[dataAddr]
	for _, wl := range workloads {
		// Direct graph edge: workload references data or vice versa.
		if b.graph.HasEdge(wl.Resource, dataAddr) || b.graph.HasEdge(dataAddr, wl.Resource) {
			out = append(out, wl)
			continue
		}
		// Shared security group: same SG attached to both.
		for sg := range sgSets[wl.Resource] {
			if dataSGs[sg] {
				out = append(out, wl)
				break
			}
		}
	}
	return out
}

// entriesReaching returns entry hops that reach the workload.
// sgSets is the precomputed per-resource SG attachment index; the
// workload's SG set is resolved once, not once per entry.
func (b *Builder) entriesReaching(workloadAddr string, entries []Hop, sgSets map[string]map[string]bool) []Hop {
	var out []Hop
	wlSGs := sgSets[workloadAddr]
	for _, e := range entries {
		if e.Resource == "internet" {
			continue
		}
		// Entry SG attached to the workload, or ALB targeting it.
		if b.graph.HasEdge(e.Resource, workloadAddr) || b.graph.HasEdge(workloadAddr, e.Resource) {
			out = append(out, e)
			continue
		}
		if e.Kind == KindNetwork && wlSGs[e.Resource] {
			out = append(out, e)
		}
	}
	return out
}

// securityGroupsOf extracts SG addresses attached to a resource via
// vpc_security_group_ids, security_groups, or security_group attributes.
func securityGroupsOf(r ir.Resource) map[string]bool {
	out := map[string]bool{}
	for _, attr := range []string{"vpc_security_group_ids", "security_groups", "security_group", "security_group_ids"} {
		v, ok := r.Attributes[attr]
		if !ok {
			continue
		}
		// NOTE: do not skip unknown values here. A list containing
		// references is marked Known=false, but the Ref fields still
		// name the target resources — that is usable evidence.
		// Use a direct type assertion: AsList() requires Known.
		if l, ok := v.Raw.([]ir.Value); ok {
			for _, item := range l {
				if item.Ref != "" {
					if addr := refToAddr(item.Ref, "aws_security_group"); addr != "" {
						out[addr] = true
					}
					continue
				}
				if s, ok := item.Raw.(string); ok {
					if addr := refToAddr(s, "aws_security_group"); addr != "" {
						out[addr] = true
					}
				}
			}
			continue
		}
		// Extract aws_security_group.NAME references from the raw text
		// (string-shaped attributes).
		raw := rawString(v)
		for _, part := range strings.FieldsFunc(raw, func(c rune) bool {
			return c == ' ' || c == ',' || c == '[' || c == ']' || c == '"' || c == '\n'
		}) {
			if addr := refToAddr(part, "aws_security_group"); addr != "" {
				out[addr] = true
			}
		}
	}
	return out
}

// dedupeChains removes duplicate chains (same hop sequence).
func dedupeChains(chains []Chain) []Chain {
	seen := map[string]bool{}
	var out []Chain
	for _, c := range chains {
		var key strings.Builder
		for _, h := range c.Hops {
			key.WriteString(h.Resource)
			key.WriteString("|")
			key.WriteString(h.Kind)
			key.WriteString(";")
		}
		k := key.String()
		if !seen[k] {
			seen[k] = true
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].Hops) != len(out[j].Hops) {
			return len(out[i].Hops) > len(out[j].Hops)
		}
		return chainKey(out[i]) < chainKey(out[j])
	})
	return out
}

func chainKey(c Chain) string {
	var sb strings.Builder
	for _, h := range c.Hops {
		sb.WriteString(h.Resource)
	}
	return sb.String()
}

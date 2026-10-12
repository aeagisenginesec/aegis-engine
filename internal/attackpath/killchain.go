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

// BuildKillChains assembles complete attack chains:
//
//	INTERNET → [entry: ALB or world-open SG] → [workload: EC2/Lambda/ECS]
//	         → [identity: IAM role chain, if present] → [data: RDS/S3/DynamoDB]
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

	// Index IAM chains by workload for quick lookup.
	iamByWorkload := make(map[string][]IAMChain)
	for _, ic := range iamChains {
		iamByWorkload[ic.Workload.Resource] = append(iamByWorkload[ic.Workload.Resource], ic)
	}

	// For each data store, find reachable workloads via graph edges,
	// then find entry points that reach those workloads.
	for _, data := range dataStores {
		reaching := b.workloadsReaching(data.Resource, workloads)
		for _, wl := range reaching {
			entriesReaching := b.entriesReaching(wl.Resource, entries)
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
				entryHop := Hop{
					Resource:   "internet",
					Kind:       KindEntry,
					Detail:     "no internet entry point proven for this workload",
					Evidence:   ir.Evidence{Attribute: "entry", Span: wl.Evidence.Span},
					Confidence: ConfidenceLow,
				}
				MarkUncertain(&entryHop, "UNCERTAIN: no public ALB or world-open SG reaches "+wl.Resource)
				hops := []Hop{entryHop, wl}
				for _, ic := range iamByWorkload[wl.Resource] {
					hops = append(hops, ic.Role, ic.Policy)
				}
				hops = append(hops, data)
				chains = append(chains, NewChain(hops))
			}
		}
	}

	return dedupeChains(chains)
}

// workloadsReaching returns workload hops that have a graph path to the
// data store address (direct reference edge or shared security group).
func (b *Builder) workloadsReaching(dataAddr string, workloads []Hop) []Hop {
	var out []Hop
	data, ok := b.byAddr[dataAddr]
	if !ok {
		return nil
	}
	dataSGs := securityGroupsOf(data)
	for _, wl := range workloads {
		// Direct graph edge: workload references data or vice versa.
		if b.graph.HasEdge(wl.Resource, dataAddr) || b.graph.HasEdge(dataAddr, wl.Resource) {
			out = append(out, wl)
			continue
		}
		// Shared security group: same SG attached to both.
		wlr, ok := b.byAddr[wl.Resource]
		if !ok {
			continue
		}
		for sg := range securityGroupsOf(wlr) {
			if dataSGs[sg] {
				out = append(out, wl)
				break
			}
		}
	}
	return out
}

// entriesReaching returns entry hops that reach the workload.
func (b *Builder) entriesReaching(workloadAddr string, entries []Hop) []Hop {
	var out []Hop
	for _, e := range entries {
		if e.Resource == "internet" {
			continue
		}
		// Entry SG attached to the workload, or ALB targeting it.
		if b.graph.HasEdge(e.Resource, workloadAddr) || b.graph.HasEdge(workloadAddr, e.Resource) {
			out = append(out, e)
			continue
		}
		if e.Kind == KindNetwork {
			wlr, ok := b.byAddr[workloadAddr]
			if !ok {
				continue
			}
			for sg := range securityGroupsOf(wlr) {
				if sg == e.Resource {
					out = append(out, e)
					break
				}
			}
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

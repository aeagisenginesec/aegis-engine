package aws

import (
	"aegis/internal/ir"
)

const worldCIDR = "0.0.0.0/0"

// ---------------------------------------------------------------------------
// AEGIS-AWS-004: Security group ingress open to the world
// ---------------------------------------------------------------------------

type sgOpenIngress struct{}

func (sgOpenIngress) ID() string    { return "AEGIS-AWS-004" }
func (sgOpenIngress) Title() string { return "Security group ingress open to the world" }
func (sgOpenIngress) Description() string {
	return "Ingress rules allowing 0.0.0.0/0 expose the workload to the " +
		"entire internet. Restrict source CIDRs to known ranges."
}
func (sgOpenIngress) Severity() ir.Severity { return ir.SeverityHigh }

func (sgOpenIngress) AppliesTo(resType string) bool {
	return resType == "aws_security_group" ||
		resType == "aws_security_group_rule" ||
		resType == "aws_vpc_security_group_ingress_rule"
}

func (sgOpenIngress) Check(r ir.Resource) []ir.Finding {
	switch r.Type {
	case "aws_security_group":
		return checkSGBlocks(r, "ingress", sgOpenIngress{})
	case "aws_security_group_rule":
		// Direction comes from the explicit type attribute; without it
		// (or when unresolved) we cannot attribute the rule. The
		// provider requires type, so absent is malformed input anyway.
		t, _, present, known := getString(r, "type")
		if !present || !known || t != "ingress" {
			return nil
		}
		return checkRuleCIDRs(r, "cidr_blocks", sgOpenIngress{})
	case "aws_vpc_security_group_ingress_rule":
		return checkRuleCIDRs(r, "cidr_ipv4", sgOpenIngress{})
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-005: Security group egress open to the world
// ---------------------------------------------------------------------------

type sgOpenEgress struct{}

func (sgOpenEgress) ID() string    { return "AEGIS-AWS-005" }
func (sgOpenEgress) Title() string { return "Security group egress open to the world" }
func (sgOpenEgress) Description() string {
	return "Egress rules allowing 0.0.0.0/0 permit unrestricted outbound " +
		"traffic, aiding data exfiltration. Restrict destinations to required ranges. " +
		"Unrestricted egress is the AWS default and by itself is not a " +
		"misconfiguration, so this rule fires only on evidence the group " +
		"carries live traffic: the group is attached to a workload " +
		"resource in the same module, or the finding comes from a " +
		"standalone egress-rule resource that explicitly targets the " +
		"group. A standalone security group with no attachments carries " +
		"no traffic and is not flagged."
}
func (sgOpenEgress) Severity() ir.Severity { return ir.SeverityMedium }

func (sgOpenEgress) AppliesTo(resType string) bool {
	return resType == "aws_security_group" ||
		resType == "aws_security_group_rule" ||
		resType == "aws_vpc_security_group_egress_rule"
}

// CheckAll gates inline-group findings on attachment evidence (see
// Description): a standalone group with no workload attached carries no
// traffic. Standalone egress-rule resources fire ungated — the rule
// resource itself is the attachment evidence.
func (sgOpenEgress) CheckAll(resources []ir.Resource) []ir.Finding {
	attached := attachedSecurityGroups(resources)
	var out []ir.Finding
	for _, r := range resources {
		switch r.Type {
		case "aws_security_group":
			if !attached[scopeKey(r)] {
				continue
			}
			out = append(out, sgOpenEgress{}.Check(r)...)
		case "aws_security_group_rule", "aws_vpc_security_group_egress_rule":
			out = append(out, sgOpenEgress{}.Check(r)...)
		}
	}
	return out
}

var _ ir.CrossResourceRule = sgOpenEgress{}

func (sgOpenEgress) Check(r ir.Resource) []ir.Finding {
	switch r.Type {
	case "aws_security_group":
		return checkSGBlocks(r, "egress", sgOpenEgress{})
	case "aws_security_group_rule":
		t, _, present, known := getString(r, "type")
		if present && !known {
			return nil
		}
		if !present || t != "egress" {
			return nil // absent type is not evidence of an egress rule
		}
		return checkRuleCIDRs(r, "cidr_blocks", sgOpenEgress{})
	case "aws_vpc_security_group_egress_rule":
		return checkRuleCIDRs(r, "cidr_ipv4", sgOpenEgress{})
	}
	return nil
}

// attachedSecurityGroups returns the scopeKeys of aws_security_group
// resources referenced by a workload resource in the same scope (same
// directory). References are Refs to the group (e.g. an instance's
// vpc_security_group_ids = [aws_security_group.web.id]) or, for
// EC2-Classic style attachments, a security_groups list naming the
// group. Resources that merely define rules on a group
// (aws_security_group, aws_security_group_rule,
// aws_vpc_security_group_*_rule) are not workloads: an SG-to-SG
// reference is not an attachment.
func attachedSecurityGroups(resources []ir.Resource) map[string]bool {
	byAddr := map[string][]ir.Resource{}
	for _, r := range resources {
		if r.Type == "aws_security_group" {
			byAddr[r.Address()] = append(byAddr[r.Address()], r)
		}
	}
	attached := map[string]bool{}
	var walk func(name string, v ir.Value, owner ir.Resource)
	walk = func(name string, v ir.Value, owner ir.Resource) {
		if v.IsRef() {
			if addr, ok := refAddrOf(v.Ref); ok {
				for _, sg := range byAddr[addr] {
					if sameScope(owner, sg) {
						attached[scopeKey(sg)] = true
					}
				}
			}
		}
		// EC2-Classic: security_groups = ["group-name"].
		if name == "security_groups" {
			if list, ok := v.AsList(); ok {
				for _, item := range list {
					if s, ok := item.AsString(); ok {
						for _, r := range resources {
							if r.Type != "aws_security_group" || !sameScope(owner, r) {
								continue
							}
							if n, _, _, known := getString(r, "name"); known && n == s {
								attached[scopeKey(r)] = true
							}
						}
					}
				}
			}
		}
		switch raw := v.Raw.(type) {
		case map[string]ir.Value:
			for k, c := range raw {
				walk(k, c, owner)
			}
		case []ir.Value:
			for _, c := range raw {
				walk(name, c, owner)
			}
		}
	}
	for _, r := range resources {
		switch r.Type {
		case "aws_security_group", "aws_security_group_rule",
			"aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule":
			continue
		}
		for name, attr := range r.Attributes {
			walk(name, attr, r)
		}
	}
	return attached
}
func checkSGBlocks(r ir.Resource, blockName string, rule ir.Rule) []ir.Finding {
	blks, _, present, known := getBlocks(r, blockName)
	if !present || !known {
		return nil
	}
	var out []ir.Finding
	for _, b := range blks {
		cidrs, allKnown := blockStrings(b, "cidr_blocks")
		if !allKnown {
			continue // cannot decide for this block
		}
		if findStringFold(cidrs, worldCIDR) {
			out = append(out, ir.Finding{
				RuleID:      rule.ID(),
				Title:       rule.Title(),
				Description: rule.Description(),
				Severity:    rule.Severity(),
				Resource:    r.Address(),
				Evidence: ir.Evidence{
					Attribute: blockName + ".cidr_blocks",
					Span:      evidenceSpan(blockSpan(b, "cidr_blocks"), r.Span),
					Actual:    worldCIDR,
					Expected:  "restricted source CIDR ranges",
				},
			})
		}
	}
	return out
}

// checkRuleCIDRs handles single-rule resources where the CIDR attribute may
// be a string (cidr_ipv4) or a list (cidr_blocks).
func checkRuleCIDRs(r ir.Resource, attr string, rule ir.Rule) []ir.Finding {
	v, ok := r.Attributes[attr]
	if !ok {
		return nil
	}
	if !v.Known {
		return nil
	}
	var cidrs []string
	if s, ok := v.AsString(); ok {
		cidrs = []string{s}
	} else if l, ok := v.AsList(); ok {
		for _, item := range l {
			s, ok := item.AsString()
			if !ok {
				return nil // unexpected shape: cannot decide
			}
			cidrs = append(cidrs, s)
		}
	} else {
		return nil // unexpected shape: cannot decide
	}
	if findStringFold(cidrs, worldCIDR) {
		return []ir.Finding{{
			RuleID:      rule.ID(),
			Title:       rule.Title(),
			Description: rule.Description(),
			Severity:    rule.Severity(),
			Resource:    r.Address(),
			Evidence: ir.Evidence{
				Attribute: attr,
				Span:      evidenceSpan(v.Span, r.Span),
				Actual:    worldCIDR,
				Expected:  "restricted CIDR ranges",
			},
		}}
	}
	return nil
}

// blockSpan returns the span of a named value inside a block, or zero Span.
func blockSpan(b map[string]ir.Value, name string) ir.Span {
	if v, ok := b[name]; ok {
		return v.Span
	}
	return ir.Span{}
}

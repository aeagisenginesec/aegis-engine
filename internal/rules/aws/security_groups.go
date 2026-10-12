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
		"traffic, aiding data exfiltration. Restrict destinations to required ranges."
}
func (sgOpenEgress) Severity() ir.Severity { return ir.SeverityMedium }

func (sgOpenEgress) AppliesTo(resType string) bool {
	return resType == "aws_security_group" ||
		resType == "aws_security_group_rule" ||
		resType == "aws_vpc_security_group_egress_rule"
}

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

// checkSGBlocks scans ingress/egress blocks of an aws_security_group for
// 0.0.0.0/0 in cidr_blocks. Unresolved blocks or CIDR lists yield no finding.
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

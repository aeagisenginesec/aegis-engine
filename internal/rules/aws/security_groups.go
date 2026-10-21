package aws

import (
	"fmt"
	"strings"

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

// ---------------------------------------------------------------------------
// AEGIS-AWS-858: Security group exposes database port to the internet
// ---------------------------------------------------------------------------

type sgDatabasePort struct{}

func (sgDatabasePort) ID() string { return "AEGIS-AWS-858" }
func (sgDatabasePort) Title() string {
	return "Security group exposes database port to the internet"
}
func (sgDatabasePort) Description() string {
	return "Ingress allowing 0.0.0.0/0 or ::/0 to a database port " +
		"(PostgreSQL 5432, MySQL/MariaDB 3306, SQL Server 1433, Redis 6379, " +
		"MongoDB 27017, Oracle 1521, Elasticsearch 9200, CouchDB 5984) " +
		"exposes the database to internet-wide scanning and credential " +
		"attacks. Restrict source CIDRs to application tiers or bastions, " +
		"or use private connectivity. (AEGIS-AWS-004 reports the world-open " +
		"ingress itself; this rule fires additionally when the open range " +
		"covers a database port.)"
}
func (sgDatabasePort) Severity() ir.Severity { return ir.SeverityHigh }

func (sgDatabasePort) AppliesTo(resType string) bool {
	return resType == "aws_security_group" ||
		resType == "aws_security_group_rule" ||
		resType == "aws_vpc_security_group_ingress_rule"
}

func (s sgDatabasePort) Check(r ir.Resource) []ir.Finding {
	switch r.Type {
	case "aws_security_group":
		blks, _, present, known := getBlocks(r, "ingress")
		if !present || !known {
			return nil
		}
		var out []ir.Finding
		for _, b := range blks {
			cidr, attr, ok := worldCIDRInBlock(b)
			if !ok {
				continue
			}
			proto, _, pPresent, pKnown := blockString(b, "protocol")
			if pPresent && !pKnown {
				continue // unresolved protocol: cannot decide
			}
			from, _, fPresent, fKnown := blockNumber(b, "from_port")
			to, _, tPresent, tKnown := blockNumber(b, "to_port")
			port, allPorts, exposed := dbPortExposure(proto, from, to,
				fPresent && tPresent && fKnown && tKnown)
			if !exposed {
				continue
			}
			out = append(out, s.finding(r, "ingress."+attr,
				evidenceSpan(blockSpan(b, "cidr_blocks"), r.Span), cidr, port, allPorts))
		}
		return out
	case "aws_security_group_rule":
		// Mirrors AEGIS-AWS-004: direction comes from the explicit type
		// attribute; absent or unresolved type cannot be attributed.
		t, _, present, known := getString(r, "type")
		if !present || !known || t != "ingress" {
			return nil
		}
		return s.checkStandalone(r, "protocol")
	case "aws_vpc_security_group_ingress_rule":
		return s.checkStandalone(r, "ip_protocol")
	}
	return nil
}

// checkStandalone evaluates the single-rule resource forms: the world-open
// CIDR arrives as cidr_blocks/ipv6_cidr_blocks lists or a cidr_ipv4/
// cidr_ipv6 string; the protocol attribute is protoAttr ("protocol" for
// aws_security_group_rule, "ip_protocol" for the VPC rule resource).
func (s sgDatabasePort) checkStandalone(r ir.Resource, protoAttr string) []ir.Finding {
	cidr, attr, span, ok := resourceWorldCIDR(r)
	if !ok {
		return nil
	}
	proto, _, pPresent, pKnown := getString(r, protoAttr)
	if pPresent && !pKnown {
		return nil // unresolved protocol: cannot decide
	}
	from, _, fPresent, fKnown := getNumber(r, "from_port")
	to, _, tPresent, tKnown := getNumber(r, "to_port")
	port, allPorts, exposed := dbPortExposure(proto, from, to,
		fPresent && tPresent && fKnown && tKnown)
	if !exposed {
		return nil
	}
	return []ir.Finding{s.finding(r, attr, evidenceSpan(span, r.Span), cidr, port, allPorts)}
}

func (s sgDatabasePort) finding(r ir.Resource, attr string, span ir.Span, cidr string, port int, allPorts bool) ir.Finding {
	title := fmt.Sprintf("Security group exposes database port %d to the internet", port)
	actual := fmt.Sprintf("%s to port %d", cidr, port)
	if allPorts {
		title += " (all ports open)"
		actual = cidr + " to all ports"
	}
	return ir.Finding{
		RuleID:      s.ID(),
		Title:       title,
		Description: s.Description(),
		Severity:    s.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: attr,
			Span:      span,
			Actual:    actual,
			Expected:  "database ports reachable only from restricted source CIDRs",
		},
	}
}

// databasePorts lists the database ports AEGIS-AWS-858 watches, ascending
// so the port named for a covering range is deterministic.
var databasePorts = []int{1433, 1521, 3306, 5432, 5984, 6379, 9200, 27017}

const worldCIDRv6 = "::/0"

// dbPortExposure decides whether an ingress with protocol proto and port
// range [from, to] covers a database port. portsKnown=false means a bound
// was absent or unresolved (undecidable: no exposure claim). Protocols
// "-1"/"all" cover every port regardless of the range. Named protocols
// other than tcp/udp (and their numeric forms 6/17) carry no ports.
func dbPortExposure(proto string, from, to float64, portsKnown bool) (port int, allPorts bool, exposed bool) {
	switch strings.ToLower(strings.TrimSpace(proto)) {
	case "-1", "all":
		return 5432, true, true // all ports: name PostgreSQL as representative
	case "", "tcp", "udp", "6", "17":
		// port-bearing: decide from the range below
	default:
		return 0, false, false
	}
	if !portsKnown {
		return 0, false, false
	}
	for _, p := range databasePorts {
		if float64(p) >= from && float64(p) <= to {
			return p, false, true
		}
	}
	return 0, false, false
}

// worldCIDRInBlock reports whether an inline SG block opens to 0.0.0.0/0
// (cidr_blocks) or ::/0 (ipv6_cidr_blocks), returning the matched CIDR and
// the attribute name it came from. An unresolved list is undecidable.
func worldCIDRInBlock(b map[string]ir.Value) (string, string, bool) {
	v4, ok := blockStrings(b, "cidr_blocks")
	if !ok {
		return "", "", false
	}
	if findStringFold(v4, worldCIDR) {
		return worldCIDR, "cidr_blocks", true
	}
	v6, ok := blockStrings(b, "ipv6_cidr_blocks")
	if !ok {
		return "", "", false
	}
	if findStringFold(v6, worldCIDRv6) {
		return worldCIDRv6, "ipv6_cidr_blocks", true
	}
	return "", "", false
}

// resourceWorldCIDR reports whether a standalone rule resource opens to
// 0.0.0.0/0 or ::/0 via any of its CIDR attributes (list or string form),
// returning the matched CIDR, attribute name, and value span.
func resourceWorldCIDR(r ir.Resource) (string, string, ir.Span, bool) {
	for _, attr := range []string{"cidr_blocks", "ipv6_cidr_blocks"} {
		v, ok := r.Attributes[attr]
		if !ok || !v.Known {
			continue
		}
		l, ok := v.AsList()
		if !ok {
			continue
		}
		var ss []string
		valid := true
		for _, item := range l {
			s, ok := item.AsString()
			if !ok {
				valid = false
				break
			}
			ss = append(ss, s)
		}
		if !valid {
			continue
		}
		if findStringFold(ss, worldCIDR) {
			return worldCIDR, attr, v.Span, true
		}
		if findStringFold(ss, worldCIDRv6) {
			return worldCIDRv6, attr, v.Span, true
		}
	}
	for _, attr := range []string{"cidr_ipv4", "cidr_ipv6"} {
		if s, span, present, known := getString(r, attr); present && known {
			if strings.EqualFold(strings.TrimSpace(s), worldCIDR) {
				return worldCIDR, attr, span, true
			}
			if strings.TrimSpace(s) == worldCIDRv6 {
				return worldCIDRv6, attr, span, true
			}
		}
	}
	return "", "", ir.Span{}, false
}

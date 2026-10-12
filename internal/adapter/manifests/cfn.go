package manifests

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"aegis/internal/ir"
)

// cfnTypeTable normalizes CloudFormation resource types to the canonical
// AWS type names consumed by the AWS rule pack. This is the full table
// implemented by this adapter.
var cfnTypeTable = map[string]string{
	"AWS::S3::Bucket":                "aws_s3_bucket",
	"AWS::S3::BucketPolicy":          "aws_s3_bucket_policy",
	"AWS::EC2::SecurityGroup":        "aws_security_group",
	"AWS::EC2::SecurityGroupIngress": "aws_security_group_rule",
	"AWS::RDS::DBInstance":           "aws_db_instance",
	"AWS::EBS::Volume":               "aws_ebs_volume",
	"AWS::IAM::Role":                 "aws_iam_role",
	"AWS::IAM::Policy":               "aws_iam_policy",
	"AWS::CloudTrail::Trail":         "aws_cloudtrail",
}

// normalizeType maps a CloudFormation type to canonical form. Types outside
// the table become cfn_<lowercased, :: -> _>, e.g. AWS::EC2::Instance ->
// cfn_aws_ec2_instance.
func normalizeType(t string) string {
	if n, ok := cfnTypeTable[t]; ok {
		return n
	}
	return "cfn_" + strings.ToLower(strings.ReplaceAll(t, "::", "_"))
}

// cfnCtx carries template-wide state for intrinsic resolution.
type cfnCtx struct {
	p      *parser
	span   ir.Span
	params map[string]ir.Value // parameter name -> default (unknown when none)
	types  map[string]string   // logical ID -> normalized type
}

// cfnResources converts a CloudFormation template document to resources.
// Parameters are collected first so Ref resolution sees them; resources are
// emitted in sorted logical-ID order for determinism.
func (p *parser) cfnResources(m map[string]any, span ir.Span) []ir.Resource {
	ctx := &cfnCtx{p: p, span: span, params: map[string]ir.Value{}, types: map[string]string{}}
	if pm, ok := asStringMap(m["Parameters"]); ok {
		for name, pv := range pm {
			def := ir.UnknownValue(span)
			if pdm, ok := asStringMap(pv); ok {
				if d, ok := pdm["Default"]; ok {
					if sv, ok := staticScalar(d); ok {
						def = ir.Value{Raw: sv, Known: true, Span: span}
					}
				}
			}
			ctx.params[name] = def
		}
	}
	rm, ok := asStringMap(m["Resources"])
	if !ok {
		return nil
	}
	for id, rv := range rm {
		rdm, ok := asStringMap(rv)
		if !ok {
			continue
		}
		cfnType, _ := rdm["Type"].(string)
		ctx.types[id] = normalizeType(cfnType)
	}
	ids := make([]string, 0, len(rm))
	for id := range rm {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var out []ir.Resource
	for _, id := range ids {
		rdm, ok := asStringMap(rm[id])
		if !ok {
			p.diags = append(p.diags, ir.Diagnostic{
				Level:   "warning",
				Message: fmt.Sprintf("manifests: resource %q is not a mapping; skipped", id),
				Span:    span,
			})
			continue
		}
		ntype := ctx.types[id]
		var props map[string]any
		if pr, ok := rdm["Properties"]; ok {
			props, _ = asStringMap(pr)
		}
		if props == nil {
			props = map[string]any{}
		}
		out = append(out, ir.Resource{
			Type:       ntype,
			Name:       id,
			Provider:   "aws",
			Attributes: ctx.mapResource(ntype, props),
			Span:       span,
		})
	}
	return out
}

// staticScalar converts a parameter default to a Go scalar. Anything else
// (lists, maps, intrinsics) is not a static default.
func staticScalar(v any) (any, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		return t, true
	case float64:
		return t, true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	}
	return nil, false
}

// value resolves a property value, handling Ref and Fn::GetAtt intrinsics.
// Any other Fn::* becomes an explicit Unknown — intrinsics are never
// evaluated. Intrinsics nested inside lists and maps resolve recursively.
func (c *cfnCtx) value(v any) ir.Value {
	span := c.span
	if m, ok := asStringMap(v); ok && len(m) == 1 {
		for k, val := range m {
			switch {
			case k == "Ref":
				s, _ := val.(string)
				if s == "" {
					return ir.UnknownValue(span)
				}
				if def, ok := c.params[s]; ok {
					return def // parameter default (possibly unknown)
				}
				if t, ok := c.types[s]; ok {
					return ir.Value{Known: false, Span: span, Ref: t + "." + s}
				}
				return ir.UnknownValue(span)
			case k == "Fn::GetAtt":
				target := ""
				switch t := val.(type) {
				case string:
					target = t
					if i := strings.Index(t, "."); i >= 0 {
						target = t[:i]
					}
				case []any:
					if len(t) > 0 {
						target, _ = t[0].(string)
					}
				}
				if target != "" {
					if t, ok := c.types[target]; ok {
						return ir.Value{Known: false, Span: span, Ref: t + "." + target}
					}
				}
				return ir.UnknownValue(span)
			case strings.HasPrefix(k, "Fn::"):
				return ir.UnknownValue(span)
			}
		}
	}
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]ir.Value, len(t))
		for k, e := range t {
			out[k] = c.value(e)
		}
		return ir.Value{Raw: out, Known: true, Span: span}
	case map[any]any:
		out := make(map[string]ir.Value, len(t))
		for k, e := range t {
			ks, ok := k.(string)
			if !ok {
				continue
			}
			out[ks] = c.value(e)
		}
		return ir.Value{Raw: out, Known: true, Span: span}
	case []any:
		out := make([]ir.Value, 0, len(t))
		for _, e := range t {
			out = append(out, c.value(e))
		}
		return ir.Value{Raw: out, Known: true, Span: span}
	default:
		return c.p.value(v, span)
	}
}

// mapResource maps CloudFormation properties for known types to the
// canonical attribute shapes the AWS rule pack expects. Unmapped
// properties pass through verbatim with snake_case keys.
func (c *cfnCtx) mapResource(ntype string, props map[string]any) map[string]ir.Value {
	attrs := make(map[string]ir.Value, len(props))
	switch ntype {
	case "aws_s3_bucket":
		for k, v := range props {
			switch k {
			case "AccessControl":
				if s, ok := v.(string); ok {
					attrs["acl"] = c.p.strValue(aclName(s), c.span)
				} else {
					attrs["acl"] = c.value(v)
				}
			case "BucketEncryption":
				// Present means encryption is configured; the rule pack
				// treats a present-but-opaque block as "cannot decide".
				attrs["server_side_encryption_configuration"] = ir.Value{Raw: "cfn", Known: true, Span: c.span}
			case "VersioningConfiguration":
				enabled := false
				if vm, ok := asStringMap(v); ok {
					if st, ok := vm["Status"].(string); ok && st == "Enabled" {
						enabled = true
					}
				}
				attrs["versioning"] = ir.Value{Raw: map[string]ir.Value{
					"enabled": {Raw: enabled, Known: true, Span: c.span},
				}, Known: true, Span: c.span}
			case "PublicAccessBlockConfiguration":
				attrs["__cfn_public_access_block"] = ir.Value{Raw: true, Known: true, Span: c.span}
			case "LoggingConfiguration":
				// Map to the Terraform-style `logging` block so the access
				// logging rule (445) can evaluate CloudFormation buckets.
				if vm, ok := asStringMap(v); ok {
					if dest, ok := vm["DestinationBucketName"].(string); ok && dest != "" {
						attrs["logging"] = ir.Value{Raw: []ir.Value{
							{Raw: map[string]ir.Value{
								"target_bucket": {Raw: dest, Known: true, Span: c.span},
							}, Known: true, Span: c.span},
						}, Known: true, Span: c.span}
					}
				}
			default:
				attrs[snake(k)] = c.value(v)
			}
		}
	case "aws_s3_bucket_policy":
		for k, v := range props {
			switch k {
			case "PolicyDocument":
				if s, ok := c.jsonString(v); ok {
					attrs["policy"] = c.p.strValue(s, c.span)
				} else {
					attrs["policy"] = ir.UnknownValue(c.span)
				}
			case "Bucket":
				attrs["bucket"] = c.value(v)
			default:
				attrs[snake(k)] = c.value(v)
			}
		}
	case "aws_security_group":
		for k, v := range props {
			switch k {
			case "GroupDescription":
				attrs["description"] = c.value(v)
			case "SecurityGroupIngress":
				attrs["ingress"] = c.ingressRules(v)
			case "SecurityGroupEgress":
				attrs["egress"] = c.ingressRules(v)
			default:
				attrs[snake(k)] = c.value(v)
			}
		}
	case "aws_security_group_rule":
		// Standalone CFN ingress rules are always ingress direction.
		attrs["type"] = c.p.strValue("ingress", c.span)
		for k, v := range props {
			switch k {
			case "IpProtocol":
				attrs["protocol"] = c.value(v)
			case "FromPort":
				attrs["from_port"] = c.value(v)
			case "ToPort":
				attrs["to_port"] = c.value(v)
			case "CidrIp", "CidrIpv6":
				attrs["cidr_blocks"] = appendCIDR(attrs["cidr_blocks"], c.value(v), c.span)
			case "GroupId":
				attrs["security_group_id"] = c.value(v)
			default:
				attrs[snake(k)] = c.value(v)
			}
		}
	case "aws_db_instance":
		for k, v := range props {
			switch k {
			case "StorageEncrypted":
				attrs["storage_encrypted"] = c.value(v)
			case "DeletionProtection":
				attrs["deletion_protection"] = c.value(v)
			case "PubliclyAccessible":
				attrs["publicly_accessible"] = c.value(v)
			default:
				attrs[snake(k)] = c.value(v)
			}
		}
	case "aws_iam_role":
		for k, v := range props {
			switch k {
			case "AssumeRolePolicyDocument":
				if s, ok := c.jsonString(v); ok {
					attrs["assume_role_policy"] = c.p.strValue(s, c.span)
				} else {
					attrs["assume_role_policy"] = ir.UnknownValue(c.span)
				}
			default:
				attrs[snake(k)] = c.value(v)
			}
		}
	case "aws_iam_policy":
		for k, v := range props {
			switch k {
			case "PolicyDocument":
				if s, ok := c.jsonString(v); ok {
					attrs["policy"] = c.p.strValue(s, c.span)
				} else {
					attrs["policy"] = ir.UnknownValue(c.span)
				}
			default:
				attrs[snake(k)] = c.value(v)
			}
		}
	case "aws_cloudtrail":
		for k, v := range props {
			switch k {
			case "EnableLogFileValidation":
				attrs["enable_log_file_validation"] = c.value(v)
			default:
				attrs[snake(k)] = c.value(v)
			}
		}
	default:
		for k, v := range props {
			attrs[snake(k)] = c.value(v)
		}
	}
	return attrs
}

// aclName maps CFN canned ACL names to the S3 ACL strings the rule pack
// expects. Unknown values pass through verbatim.
func aclName(s string) string {
	switch s {
	case "Private":
		return "private"
	case "PublicRead":
		return "public-read"
	case "PublicReadWrite":
		return "public-read-write"
	}
	return s
}

// ingressRules converts CFN SecurityGroupIngress/Egress lists to the
// canonical ingress/egress block shape: []Value of maps with protocol,
// from_port, to_port, and cidr_blocks.
func (c *cfnCtx) ingressRules(v any) ir.Value {
	list, ok := v.([]any)
	if !ok {
		return ir.UnknownValue(c.span)
	}
	out := make([]ir.Value, 0, len(list))
	for _, item := range list {
		m, ok := asStringMap(item)
		if !ok {
			continue
		}
		em := map[string]ir.Value{}
		if p, ok := m["IpProtocol"]; ok {
			em["protocol"] = c.value(p)
		}
		if p, ok := m["FromPort"]; ok {
			em["from_port"] = c.value(p)
		}
		if p, ok := m["ToPort"]; ok {
			em["to_port"] = c.value(p)
		}
		var cidrs []ir.Value
		if x, ok := m["CidrIp"]; ok {
			cidrs = append(cidrs, c.value(x))
		}
		if x, ok := m["CidrIpv6"]; ok {
			cidrs = append(cidrs, c.value(x))
		}
		if len(cidrs) > 0 {
			em["cidr_blocks"] = ir.Value{Raw: cidrs, Known: true, Span: c.span}
		}
		out = append(out, ir.Value{Raw: em, Known: true, Span: c.span})
	}
	return ir.Value{Raw: out, Known: true, Span: c.span}
}

// appendCIDR appends one CIDR value to a cidr_blocks list under
// construction.
func appendCIDR(prev ir.Value, v ir.Value, span ir.Span) ir.Value {
	var out []ir.Value
	if l, ok := prev.AsList(); ok {
		out = append(out, l...)
	}
	out = append(out, v)
	return ir.Value{Raw: out, Known: true, Span: span}
}

// jsonString renders a property object (policy documents) as a JSON string
// after intrinsic resolution. Anything unresolvable makes the whole
// document Unknown rather than a half-rendered lie.
func (c *cfnCtx) jsonString(v any) (string, bool) {
	gv, ok := valueToGo(c.value(v))
	if !ok {
		return "", false
	}
	b, err := json.Marshal(gv)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// valueToGo converts a known ir.Value back to Go natives for JSON
// rendering. Unknown values (including Refs) fail the conversion.
func valueToGo(v ir.Value) (any, bool) {
	if !v.Known {
		return nil, false
	}
	switch t := v.Raw.(type) {
	case string, bool, float64:
		return t, true
	case []ir.Value:
		out := make([]any, 0, len(t))
		for _, e := range t {
			gv, ok := valueToGo(e)
			if !ok {
				return nil, false
			}
			out = append(out, gv)
		}
		return out, true
	case map[string]ir.Value:
		out := make(map[string]any, len(t))
		for k, e := range t {
			gv, ok := valueToGo(e)
			if !ok {
				return nil, false
			}
			out[k] = gv
		}
		return out, true
	}
	return nil, false
}

// snake converts CamelCase to snake_case for verbatim property passthrough.
// Runs of capitals are treated as one word: DBInstanceClass ->
// db_instance_class, CidrIp -> cidr_ip.
func snake(s string) string {
	var b strings.Builder
	runes := []rune(s)
	for i, r := range runes {
		if unicode.IsUpper(r) {
			if i > 0 {
				prev := runes[i-1]
				nextIsLower := i+1 < len(runes) && unicode.IsLower(runes[i+1])
				if unicode.IsLower(prev) || unicode.IsDigit(prev) ||
					(!unicode.IsLower(prev) && nextIsLower) {
					b.WriteByte('_')
				}
			}
			b.WriteRune(unicode.ToLower(r))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

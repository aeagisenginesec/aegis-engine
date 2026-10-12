package attackpath

import (
	"sort"
	"strings"

	"aegis/internal/graph"
	"aegis/internal/ir"
)

// Builder constructs evidence-backed attack chains from IR resources.
// It uses the resource graph for reference edges and inspects attributes
// directly for exposure signals (0.0.0.0/0, public flags, etc.).
type Builder struct {
	resources []ir.Resource
	byAddr    map[string]ir.Resource
	graph     *graph.Graph
}

// NewBuilder creates a chain builder over the given resources.
func NewBuilder(resources []ir.Resource) *Builder {
	byAddr := make(map[string]ir.Resource, len(resources))
	for _, r := range resources {
		if _, dup := byAddr[r.Address()]; !dup {
			byAddr[r.Address()] = r
		}
	}
	return &Builder{
		resources: resources,
		byAddr:    byAddr,
		graph:     graph.Build(resources),
	}
}

// rawString safely extracts a string from an ir.Value's Raw (any).
// Returns "" for non-string or unknown values.
func rawString(v ir.Value) string {
	if !v.Known {
		return ""
	}
	if s, ok := v.Raw.(string); ok {
		return s
	}
	return ""
}

// getString returns the attribute value and whether it's present.
// Unlike ir.Value.AsString, this works for references too: a ref value
// carries the reference string in Ref even when Known=false.
func getString(r ir.Resource, name string) (ir.Value, bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return ir.Value{}, false
	}
	return v, true
}

// rawOrRef returns the usable string: Ref if set, else the raw string.
func rawOrRef(v ir.Value) string {
	if v.Ref != "" {
		return v.Ref
	}
	return rawString(v)
}

// getBool returns (value, span, present, known).
func getBool(r ir.Resource, name string) (bool, ir.Span, bool, bool) {
	v, ok := r.Attributes[name]
	if !ok {
		return false, ir.Span{}, false, false
	}
	if !v.Known {
		return false, v.Span, true, false
	}
	raw := strings.ToLower(strings.TrimSpace(rawString(v)))
	raw = strings.Trim(raw, `"`)
	return raw == "true", v.Span, true, true
}

// isWorldOpenCIDR reports whether a CIDR value is the open internet.
func isWorldOpenCIDR(raw string) bool {
	raw = strings.Trim(strings.TrimSpace(raw), `"`)
	return raw == "0.0.0.0/0" || raw == "::/0"
}

// ---------------------------------------------------------------------------
// Entry point detection
// ---------------------------------------------------------------------------

// findOpenSGs returns security groups with world-open ingress, each as a
// network hop with evidence.
func (b *Builder) findOpenSGs() []Hop {
	var out []Hop
	sorted := b.sortedResources()
	for _, r := range sorted {
		if r.Type != "aws_security_group" && r.Type != "aws_vpc_security_group_ingress_rule" {
			continue
		}
		hop := b.sgOpenHop(r)
		if hop != nil {
			out = append(out, *hop)
		}
	}
	return out
}

// sgOpenHop checks a single SG for world-open ingress by inspecting
// nested ingress blocks (the IR nests them, not flattened attributes).
func (b *Builder) sgOpenHop(r ir.Resource) *Hop {
	// Standalone rule resources.
	if r.Type == "aws_security_group_rule" || r.Type == "aws_vpc_security_group_ingress_rule" {
		cidrAttr := "cidr_blocks"
		if r.Type == "aws_vpc_security_group_ingress_rule" {
			cidrAttr = "cidr_ipv4"
		}
		if v, ok := r.Attributes[cidrAttr]; ok && v.Known {
			if s, ok := v.AsString(); ok && isWorldOpenCIDR(s) {
				return &Hop{
					Resource: r.Address(),
					Kind:     KindNetwork,
					Detail:   "security group rule allows ingress from 0.0.0.0/0",
					Evidence: ir.Evidence{Attribute: cidrAttr, Span: v.Span,
						Actual: strings.Trim(s, `"`), Expected: "restricted CIDR"},
					Confidence: HopConfidence(v),
				}
			}
		}
		return nil
	}
	// Inline ingress blocks on aws_security_group.
	v, ok := r.Attributes["ingress"]
	if !ok {
		return nil
	}
	if !v.Known {
		h := Hop{
			Resource:   r.Address(),
			Kind:       KindNetwork,
			Detail:     "security group ingress blocks are not statically known",
			Evidence:   ir.Evidence{Attribute: "ingress", Span: v.Span},
			Confidence: ConfidenceLow,
		}
		MarkUncertain(&h, UncertainCondition)
		return &h
	}
	for _, blk := range asBlockList(v) {
		cidrV, ok := blk["cidr_blocks"]
		if !ok {
			continue
		}
		if !cidrV.Known {
			h := Hop{
				Resource:   r.Address(),
				Kind:       KindNetwork,
				Detail:     "security group ingress CIDR is not statically known",
				Evidence:   ir.Evidence{Attribute: "cidr_blocks", Span: cidrV.Span, Actual: rawString(cidrV)},
				Confidence: ConfidenceLow,
			}
			MarkUncertain(&h, ClassifyUncertainty(cidrV))
			return &h
		}
		for _, cidr := range asStringList(cidrV) {
			if isWorldOpenCIDR(cidr) {
				return &Hop{
					Resource: r.Address(),
					Kind:     KindNetwork,
					Detail:   "security group allows ingress from 0.0.0.0/0 (public internet)",
					Evidence: ir.Evidence{
						Attribute: "ingress.cidr_blocks",
						Span:      cidrV.Span,
						Actual:    strings.Trim(cidr, `"`),
						Expected:  "restricted CIDR",
					},
					Confidence: HopConfidence(cidrV),
				}
			}
		}
	}
	return nil
}

// asBlockList converts an ir.Value holding nested blocks to a slice of
// attribute maps. Handles both single-map and list-of-map shapes.
func asBlockList(v ir.Value) []map[string]ir.Value {
	if m, ok := v.AsMap(); ok {
		return []map[string]ir.Value{m}
	}
	l, ok := v.AsList()
	if !ok {
		return nil
	}
	var out []map[string]ir.Value
	for _, item := range l {
		if m, ok := item.AsMap(); ok {
			out = append(out, m)
		}
	}
	return out
}

// asStringList extracts strings from an ir.Value list.
func asStringList(v ir.Value) []string {
	l, ok := v.AsList()
	if !ok {
		if s, ok := v.AsString(); ok {
			return []string{s}
		}
		return nil
	}
	var out []string
	for _, item := range l {
		if s, ok := item.AsString(); ok {
			out = append(out, s)
		}
	}
	return out
}

// findPublicALBs returns internet-facing load balancers as entry hops.
func (b *Builder) findPublicALBs() []Hop {
	var out []Hop
	for _, r := range b.sortedResources() {
		if r.Type != "aws_lb" && r.Type != "aws_alb" {
			continue
		}
		internal, _, present, known := getBool(r, "internal")
		if present && known && internal {
			continue // internal LB: not an internet entry point
		}
		v, ok := getString(r, "internal")
		conf := ConfidenceHigh
		ev := ir.Evidence{Attribute: "internal", Span: r.Span, Actual: "false (default)", Expected: "true"}
		if ok {
			ev = ir.Evidence{Attribute: "internal", Span: v.Span, Actual: rawString(v), Expected: "true"}
			conf = HopConfidence(v)
		} else if present && !known {
			conf = ConfidenceLow
		}
		out = append(out, Hop{
			Resource:   r.Address(),
			Kind:       KindEntry,
			Detail:     "internet-facing load balancer (public entry point)",
			Evidence:   ev,
			Confidence: conf,
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// Workload detection
// ---------------------------------------------------------------------------

var workloadTypes = map[string]string{
	"aws_instance":                  "EC2 instance",
	"aws_lambda_function":           "Lambda function",
	"aws_ecs_service":               "ECS service",
	"aws_eks_cluster":               "EKS cluster",
	"aws_batch_compute_environment": "Batch compute environment",
}

// findWorkloads returns compute resources as workload hops.
func (b *Builder) findWorkloads() []Hop {
	var out []Hop
	for _, r := range b.sortedResources() {
		label, ok := workloadTypes[r.Type]
		if !ok {
			continue
		}
		out = append(out, Hop{
			Resource: r.Address(),
			Kind:     KindWorkload,
			Detail:   label + " — reachable compute, potential stepping stone",
			Evidence: ir.Evidence{
				Attribute: "resource",
				Span:      r.Span,
				Actual:    r.Address(),
			},
			Confidence: ConfidenceHigh,
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// Data store detection
// ---------------------------------------------------------------------------

var dataTypes = map[string]string{
	"aws_db_instance":         "RDS database",
	"aws_rds_cluster":         "Aurora cluster",
	"aws_dynamodb_table":      "DynamoDB table",
	"aws_s3_bucket":           "S3 bucket",
	"aws_elasticache_cluster": "ElastiCache cluster",
	"aws_redshift_cluster":    "Redshift cluster",
}

// findDataStores returns data resources as objective hops.
func (b *Builder) findDataStores() []Hop {
	var out []Hop
	for _, r := range b.sortedResources() {
		label, ok := dataTypes[r.Type]
		if !ok {
			continue
		}
		out = append(out, Hop{
			Resource: r.Address(),
			Kind:     KindData,
			Detail:   label + " — sensitive data objective",
			Evidence: ir.Evidence{
				Attribute: "resource",
				Span:      r.Span,
				Actual:    r.Address(),
			},
			Confidence: ConfidenceHigh,
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// IAM chain detection
// ---------------------------------------------------------------------------

// IAMChain describes a role → policy → workload privilege path.
type IAMChain struct {
	Role     Hop
	Policy   Hop
	Workload Hop
	Actions  []string // privileged actions granted
}

// findIAMChains traces aws_iam_role → aws_iam_policy (via
// aws_iam_role_policy_attachment or inline) → aws_instance /
// aws_lambda_function (via iam_instance_profile / role).
func (b *Builder) findIAMChains() []IAMChain {
	var out []IAMChain

	// Map role address -> attached policy addresses.
	rolePolicies := make(map[string][]string)
	for _, r := range b.resources {
		if r.Type == "aws_iam_role_policy_attachment" {
			roleV, ok1 := getString(r, "role")
			polV, ok2 := getString(r, "policy_arn")
			if ok1 && ok2 {
				roleAddr := refToAddr(rawOrRef(roleV), "aws_iam_role")
				polAddr := refToAddr(rawOrRef(polV), "aws_iam_policy")
				if roleAddr != "" && polAddr != "" {
					rolePolicies[roleAddr] = append(rolePolicies[roleAddr], polAddr)
				}
			}
		}
	}

	// Map workload -> role.
	workloadRoles := make(map[string]string)
	for _, r := range b.resources {
		switch r.Type {
		case "aws_instance":
			if v, ok := getString(r, "iam_instance_profile"); ok {
				// Instance profile -> role is a second hop; record profile as proxy.
				workloadRoles[r.Address()] = "profile:" + rawOrRef(v)
			}
		case "aws_lambda_function":
			if v, ok := getString(r, "role"); ok {
				if addr := refToAddr(rawOrRef(v), "aws_iam_role"); addr != "" {
					workloadRoles[r.Address()] = addr
				} else if u := ClassifyUncertainty(v); u != "" {
					workloadRoles[r.Address()] = "uncertain:" + u
				}
			}
		}
	}

	for workload, roleRef := range workloadRoles {
		if strings.HasPrefix(roleRef, "uncertain:") {
			continue // handled as uncertainty, not a chain
		}
		roleAddr := strings.TrimPrefix(roleRef, "profile:")
		// For instance profiles, resolve profile -> role via graph.
		if strings.HasPrefix(roleRef, "profile:") {
			roleAddr = b.resolveInstanceProfileRole(roleRef[len("profile:"):])
			if roleAddr == "" {
				continue
			}
		}
		policies := rolePolicies[roleAddr]
		for _, polAddr := range policies {
			actions := b.policyActions(polAddr)
			if len(actions) == 0 {
				continue
			}
			role, ok1 := b.byAddr[roleAddr]
			pol, ok2 := b.byAddr[polAddr]
			wl, ok3 := b.byAddr[workload]
			if !ok1 || !ok2 || !ok3 {
				continue
			}
			out = append(out, IAMChain{
				Role: Hop{
					Resource:   roleAddr,
					Kind:       KindIdentity,
					Detail:     "IAM role assumed by workload",
					Evidence:   ir.Evidence{Attribute: "role", Span: role.Span, Actual: roleAddr},
					Confidence: ConfidenceHigh,
				},
				Policy: Hop{
					Resource:   polAddr,
					Kind:       KindIdentity,
					Detail:     "IAM policy grants: " + strings.Join(actions, ", "),
					Evidence:   ir.Evidence{Attribute: "policy", Span: pol.Span, Actual: strings.Join(actions, ",")},
					Confidence: ConfidenceHigh,
				},
				Workload: Hop{
					Resource:   workload,
					Kind:       KindWorkload,
					Detail:     "workload assumes role with privileged actions",
					Evidence:   ir.Evidence{Attribute: "role", Span: wl.Span, Actual: roleAddr},
					Confidence: ConfidenceHigh,
				},
				Actions: actions,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Workload.Resource != out[j].Workload.Resource {
			return out[i].Workload.Resource < out[j].Workload.Resource
		}
		return out[i].Policy.Resource < out[j].Policy.Resource
	})
	return out
}

// refToAddr converts a Terraform reference like "aws_iam_role.foo.arn"
// to "aws_iam_role.foo" when the head matches wantType.
func refToAddr(raw, wantType string) string {
	raw = strings.TrimSpace(raw)
	parts := strings.Split(raw, ".")
	if len(parts) >= 2 && parts[0] == wantType {
		return parts[0] + "." + parts[1]
	}
	return ""
}

// resolveInstanceProfileRole follows aws_iam_instance_profile -> aws_iam_role.
func (b *Builder) resolveInstanceProfileRole(profileRef string) string {
	profAddr := refToAddr(profileRef, "aws_iam_instance_profile")
	if profAddr == "" {
		// Might be a plain name; search profiles by name.
		for _, r := range b.resources {
			if r.Type == "aws_iam_instance_profile" && r.Name == strings.Trim(profileRef, `"`) {
				profAddr = r.Address()
				break
			}
		}
	}
	if profAddr == "" {
		return ""
	}
	prof, ok := b.byAddr[profAddr]
	if !ok {
		return ""
	}
	if v, ok := getString(prof, "role"); ok {
		if addr := refToAddr(rawOrRef(v), "aws_iam_role"); addr != "" {
			return addr
		}
		// Role referenced by name.
		name := strings.Trim(rawString(v), `"`)
		for _, r := range b.resources {
			if r.Type == "aws_iam_role" && r.Name == name {
				return r.Address()
			}
		}
	}
	return ""
}

// policyActions extracts Allow actions from an aws_iam_policy document.
// Returns nil if the policy cannot be parsed (never invents actions).
func (b *Builder) policyActions(polAddr string) []string {
	pol, ok := b.byAddr[polAddr]
	if !ok {
		return nil
	}
	v, ok := getString(pol, "policy")
	if !ok {
		return nil
	}
	raw := rawString(v)
	// Look for wildcard or sensitive actions in the JSON document.
	// This is a heuristic scan, not a full IAM parser: it only reports
	// actions literally present in the document text.
	var actions []string
	upper := strings.ToUpper(raw)
	sensitive := []string{
		`"*"`, `"S3:*"`, `"EC2:*"`, `"IAM:*"`, `"RDS:*"`,
		`"DYNAMODB:*"`, `"SECRETSMANAGER:*"`, `"KMS:*"`,
		`"STS:ASSUMEROLE"`, `"IAM:PASSROLE"`,
	}
	seen := map[string]bool{}
	for _, s := range sensitive {
		if strings.Contains(upper, s) && !seen[s] {
			seen[s] = true
			actions = append(actions, strings.Trim(s, `"`))
		}
	}
	sort.Strings(actions)
	return actions
}

// sortedResources returns resources in deterministic address order.
func (b *Builder) sortedResources() []ir.Resource {
	sorted := append([]ir.Resource(nil), b.resources...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Address() < sorted[j].Address()
	})
	return sorted
}

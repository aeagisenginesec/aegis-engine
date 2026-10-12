package aws

import (
	"sort"

	"aegis/internal/attackpath"
	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// AEGIS-AWS-629: Full kill chain — internet to data store
//
// Emits one finding per complete attack chain: internet entry point
// (public ALB or world-open security group) → workload (EC2, Lambda, ECS)
// → sensitive data (RDS, S3, DynamoDB), with IAM privilege hops when a
// workload assumes a role with sensitive actions.
//
// Every hop cites concrete evidence (resource + attribute + file:line).
// Hops that cannot be proven are marked UNCERTAIN, never invented.
// ---------------------------------------------------------------------------

type killChain struct{}

func (killChain) ID() string { return "AEGIS-AWS-629" }
func (killChain) Title() string {
	return "Full kill chain: internet to data store"
}
func (killChain) Description() string {
	return "A complete, evidence-backed attack path exists from the internet " +
		"through a workload to a sensitive data store. Each hop cites the " +
		"Terraform resource and attribute that enables it. Uncertain hops " +
		"are explicitly marked, never invented."
}
func (killChain) Severity() ir.Severity { return ir.SeverityCritical }

func (killChain) AppliesTo(resType string) bool {
	// Cross-resource rule: CheckAll does the work.
	return false
}

func (killChain) Check(ir.Resource) []ir.Finding { return nil }

func (killChain) CheckAll(resources []ir.Resource) []ir.Finding {
	b := attackpath.NewBuilder(resources)
	chains := b.BuildKillChains()
	// Only report chains that reach a data objective with at least
	// entry → workload → data (3 hops), or any chain with an IAM hop.
	var out []ir.Finding
	for _, c := range chains {
		if len(c.Hops) < 3 {
			continue
		}
		hasData := false
		hasIAM := false
		for _, h := range c.Hops {
			if h.Kind == attackpath.KindData {
				hasData = true
			}
			if h.Kind == attackpath.KindIdentity {
				hasIAM = true
			}
		}
		if !hasData {
			continue
		}
		sev := ir.SeverityHigh
		if hasIAM {
			sev = ir.SeverityCritical
		}
		// Downgrade chains with uncertain entry points: without a proven
		// internet entry, the chain is speculative and should not be High.
		if c.Uncertain {
			sev = ir.SeverityMedium
		}
		steps := c.ToPathSteps()
		evidence := ir.Evidence{
			Attribute: "attack_chain",
			Span:      c.Hops[len(c.Hops)-1].Evidence.Span,
			Actual:    attackpath.RenderSummary(c),
			Expected:  "no complete internet-to-data path",
		}
		out = append(out, ir.Finding{
			RuleID:      "AEGIS-AWS-629",
			Title:       (killChain{}).Title(),
			Description: (killChain{}).Description() + " Confidence: " + c.Confidence + ".",
			Severity:    sev,
			Resource:    c.Hops[len(c.Hops)-1].Resource,
			Evidence:    evidence,
			Path:        steps,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Resource < out[j].Resource
	})
	return out
}

var _ ir.CrossResourceRule = killChain{}

// ---------------------------------------------------------------------------
// AEGIS-AWS-630: IAM privilege escalation chain
//
// Traces aws_iam_role → aws_iam_policy → workload (EC2/Lambda): when a
// workload assumes a role whose policy grants wildcard or sensitive
// actions (*, s3:*, iam:*, sts:AssumeRole, iam:PassRole), the chain shows
// exactly which workload inherits which privilege and where it's defined.
// ---------------------------------------------------------------------------

type iamPrivilegeChain struct{}

func (iamPrivilegeChain) ID() string { return "AEGIS-AWS-630" }
func (iamPrivilegeChain) Title() string {
	return "IAM privilege chain: workload inherits sensitive actions"
}
func (iamPrivilegeChain) Description() string {
	return "A workload (EC2, Lambda) assumes an IAM role whose policy " +
		"grants wildcard or sensitive actions. The chain traces role → " +
		"policy → workload with evidence at each hop, showing the exact " +
		"privilege inheritance path an attacker would abuse."
}
func (iamPrivilegeChain) Severity() ir.Severity { return ir.SeverityHigh }

func (iamPrivilegeChain) AppliesTo(resType string) bool  { return false }
func (iamPrivilegeChain) Check(ir.Resource) []ir.Finding { return nil }

func (iamPrivilegeChain) CheckAll(resources []ir.Resource) []ir.Finding {
	// findIAMChains is unexported; rebuild via Builder through a small
	// exported surface: use kill-chain IAM hops indirectly. For a focused
	// rule, re-derive chains here via the builder's exported method.
	b := attackpath.NewBuilder(resources)
	chains := b.IAMChains()
	var out []ir.Finding
	for _, ic := range chains {
		steps := []ir.PathStep{
			{Resource: ic.Role.Resource, Detail: ic.Role.Detail, Span: ic.Role.Evidence.Span},
			{Resource: ic.Policy.Resource, Detail: ic.Policy.Detail, Span: ic.Policy.Evidence.Span},
			{Resource: ic.Workload.Resource, Detail: ic.Workload.Detail, Span: ic.Workload.Evidence.Span},
		}
		out = append(out, ir.Finding{
			RuleID:      "AEGIS-AWS-630",
			Title:       (iamPrivilegeChain{}).Title(),
			Description: (iamPrivilegeChain{}).Description(),
			Severity:    ir.SeverityHigh,
			Resource:    ic.Workload.Resource,
			Evidence: ir.Evidence{
				Attribute: "iam_role",
				Span:      ic.Workload.Evidence.Span,
				Actual:    ic.Role.Resource + " grants " + joinActions(ic.Actions),
				Expected:  "least-privilege actions",
			},
			Path: steps,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Resource < out[j].Resource
	})
	return out
}

var _ ir.CrossResourceRule = iamPrivilegeChain{}

func joinActions(a []string) string {
	if len(a) == 0 {
		return "none"
	}
	out := a[0]
	for _, s := range a[1:] {
		out += ", " + s
	}
	return out
}

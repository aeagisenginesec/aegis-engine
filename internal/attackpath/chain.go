// Package attackpath builds evidence-backed attack chains (kill chains).
//
// A Chain is an ordered sequence of Hops from an entry point (internet-
// reachable) through workloads to sensitive data or privileged identity.
// Every hop cites concrete configuration evidence: the Terraform resource,
// the attribute, and the file:line where it was found.
//
// Chains NEVER invent hops. When variables, count/for_each, dynamic blocks,
// data sources, or unknown values prevent a definitive conclusion, the hop
// is marked UNCERTAIN with an explicit reason.
package attackpath

import (
	"aegis/internal/ir"
)

// Confidence levels for a hop or chain.
const (
	ConfidenceHigh   = "high"   // all values are concrete literals
	ConfidenceMedium = "medium" // some hops rely on defaults or resolvable refs
	ConfidenceLow    = "low"    // any hop involves variables, conditionals, data sources
)

// Hop kinds — the role a resource plays in the chain.
const (
	KindEntry    = "entry"    // internet-reachable: public ALB, world-open SG
	KindWorkload = "workload" // compute: EC2, Lambda, ECS task
	KindData     = "data"     // sensitive: RDS, S3, DynamoDB
	KindIdentity = "identity" // IAM: role, policy, instance profile
	KindNetwork  = "network"  // SG, subnet, route — the connective tissue
)

// Hop is one step in an attack chain.
type Hop struct {
	Resource   string      `json:"resource"`   // "aws_instance.web"
	Kind       string      `json:"kind"`       // entry | workload | data | identity | network
	Detail     string      `json:"detail"`     // why this hop matters
	Evidence   ir.Evidence `json:"evidence"`   // attribute + span + actual value
	Confidence string      `json:"confidence"` // high | medium | low
	// Uncertain, when non-empty, is the explicit reason this hop cannot
	// be proven: "UNCERTAIN: <reason>". The chain still reports the hop
	// but flags it so no conclusion is invented.
	Uncertain string `json:"uncertain,omitempty"`
}

// Chain is an ordered attack path from entry to objective.
type Chain struct {
	Hops []Hop `json:"hops"`
	// Confidence is the minimum confidence across all hops.
	Confidence string `json:"confidence"`
	// Uncertain is true if any hop is uncertain.
	Uncertain bool `json:"uncertain"`
}

// computeConfidence returns the minimum confidence across hops.
func computeConfidence(hops []Hop) string {
	conf := ConfidenceHigh
	rank := map[string]int{ConfidenceHigh: 3, ConfidenceMedium: 2, ConfidenceLow: 1}
	for _, h := range hops {
		if rank[h.Confidence] < rank[conf] {
			conf = h.Confidence
		}
		if h.Uncertain != "" && rank[ConfidenceLow] < rank[conf] {
			conf = ConfidenceLow
		}
	}
	return conf
}

// NewChain builds a Chain from hops, computing aggregate confidence.
func NewChain(hops []Hop) Chain {
	uncertain := false
	for _, h := range hops {
		if h.Uncertain != "" {
			uncertain = true
			break
		}
	}
	return Chain{
		Hops:       hops,
		Confidence: computeConfidence(hops),
		Uncertain:  uncertain,
	}
}

// ToPathSteps converts a Chain to ir.PathStep for Finding.Path.
func (c Chain) ToPathSteps() []ir.PathStep {
	steps := make([]ir.PathStep, 0, len(c.Hops))
	for _, h := range c.Hops {
		detail := h.Detail
		if h.Uncertain != "" {
			detail += " [" + h.Uncertain + "]"
		}
		steps = append(steps, ir.PathStep{
			Resource: h.Resource,
			Detail:   detail,
			Span:     h.Evidence.Span,
		})
	}
	return steps
}

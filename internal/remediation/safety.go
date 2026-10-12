// Remediation safety gates: dangerous-resource blocklist.
//
// Rationale: some Terraform resource types encode authorization or network
// reachability decisions. A "helpful" auto-patch on these — tightening a
// policy, rewriting an ingress block, touching a trust policy — can lock
// out legitimate traffic or, worse, silently broaden access when the
// fixer misreads the intent. Those fixes need human review, so ProposeAll
// refuses to propose any patch whose target resource type is blocked,
// unless the operator explicitly opts in with AllowBlocked (CLI --force).
package remediation

// BlockedResourceTypes lists resource types for which ProposeAll proposes
// no patch unless AllowBlocked is set. This is a type-level backstop:
// none of the shipped fixers (fixers.go) address these types today, so the
// blocklist also guards any future fixer that would.
var BlockedResourceTypes = map[string]bool{
	// IAM authorization surface. Policy rewrites need least-privilege
	// review; a wrong auto-fix can lock out workloads or widen access.
	"aws_iam_policy":       true,
	"aws_iam_role_policy":  true,
	"aws_iam_group_policy": true,
	"aws_iam_user_policy":  true,
	// aws_iam_role is blocked because its assume_role_policy (trust
	// policy) controls who may assume the role — changes need review.
	"aws_iam_role": true,
	// Network reachability surface. Ingress/egress changes are
	// availability decisions; which CIDRs are legitimate is a human call.
	"aws_security_group":                  true,
	"aws_security_group_rule":             true,
	"aws_vpc_security_group_ingress_rule": true,
	"aws_vpc_security_group_egress_rule":  true,
	"aws_network_acl":                     true,
}

// IsBlocked reports whether resType is on the dangerous-resource blocklist.
func IsBlocked(resType string) bool {
	return BlockedResourceTypes[resType]
}

// AllowBlocked opts ProposeAll into proposing patches for blocked resource
// types. Default false. The `aegis fix` CLI sets it from --force and warns
// the operator. Tests flip it directly; reset with defer when doing so.
var AllowBlocked = false

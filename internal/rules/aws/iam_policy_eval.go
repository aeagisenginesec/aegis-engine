package aws

import (
	"strings"
)

// ---------------------------------------------------------------------------
// Policy-evaluation semantics for NotAction / NotResource (v2.4.0).
//
// AWS evaluates an Allow statement with NotAction as granting every action
// EXCEPT the listed ones, and NotResource as granting on every resource
// EXCEPT the listed ones. Before v2.4.0 the IAM pack skipped such
// statements entirely ("cannot decide -> silent"), so a near-admin grant
// such as `NotAction: ["iam:DeleteUser"]` on `*` was silently missed.
// This file is the single evaluation core every IAM rule now uses:
//
//   - iamNormalizedStmt: one Allow statement, normalized to positive grants
//     plus negative exclusions. Statement keys are matched
//     case-insensitively (some adapters snake_case document keys).
//   - grantsAction: does the statement grant a (concrete or patterned)
//     action? For NotAction statements the answer is "yes unless an
//     exclusion pattern covers it".
//   - grantsOnStar / grantsOnClass / grantsResource: does the statement
//     grant on `*`, on a resource class (e.g. all IAM role ARNs, all S3
//     bucket ARNs), or on one concrete ARN? For NotResource statements the
//     answer is "yes unless an exclusion pattern covers it".
//   - isAdmin: the administrative-access test shared by AEGIS-AWS-006,
//     -102, -333 and -859. A positive statement is admin when its Action
//     list contains `*` or `iam:*` (unchanged). A NotAction statement is
//     admin when no single exclusion pattern covers `*` and none covers
//     `iam:*` — i.e. the exclusion leaves the IAM action class (or the
//     whole action space) intact. `NotAction: ["iam:*"]` therefore stays
//     quiet (no IAM action is granted at all), while
//     `NotAction: ["iam:DeleteUser"]` fires (iam:* minus one action is
//     still administrative access).
//
// Deliberate limits (documented, not oversights):
//
//   - Coverage is tested per exclusion pattern, not over the union of the
//     list: an exclusion list that only collectively covers `iam:*`
//     (e.g. ["iam:Put*", "iam:Create*", "iam:Delete*", ...]) is still
//     treated as admin. Such lists are rare, and the finding's evidence
//     names the exclusions so a reviewer can see exactly what was left out.
//   - Pattern-vs-pattern coverage is exact for the shapes that occur in
//     real policies (a single trailing `*`, or no `*` at all). For exotic
//     multi-`*` patterns the prefix/suffix check is necessary but not
//     sufficient, so coverage may be over-approximated (a finding may be
//     suppressed). Multi-`*` action/resource patterns are vanishingly rare
//     in IAM policies.
//   - `?` single-character wildcards are treated as literals, matching
//     the pre-existing glob matcher.
//   - Only Allow statements are evaluated. Explicit Deny interaction
//     (including Deny with NotAction/NotResource) is out of scope: Aegis
//     evaluates grants, and Deny precedence needs full policy evaluation.
//   - Conditions are not evaluated here; each rule keeps its own
//     Condition handling (101/676 skip conditioned statements, 859
//     requires an MFA condition, the privilege rules ignore conditions
//     as before).
// ---------------------------------------------------------------------------

// iamRoleARNClass is the resource class iam:PassRole acts on: every IAM
// role ARN in any account.
const iamRoleARNClass = "arn:aws:iam::*:role/*"

// iamS3BucketARNClass is the resource class S3 data-plane actions act on:
// every S3 bucket ARN.
const iamS3BucketARNClass = "arn:aws:s3:::*"

// iamNormalizedStmt is one Allow statement normalized for evaluation.
// Actions are lower-cased (IAM actions are case-insensitive); resource
// patterns keep their original case (ARN matching is case-sensitive in
// the resource part).
type iamNormalizedStmt struct {
	actions        []string
	notActions     []string
	resources      []string
	notResources   []string
	hasAction      bool
	hasNotAction   bool
	hasResource    bool
	hasNotResource bool
}

// normalizeIAMStmt normalizes one raw policy statement for evaluation.
// It returns nil when the statement is not an Allow statement or when it
// carries both Action and NotAction (or both Resource and NotResource —
// invalid AWS policy, cannot evaluate). A statement with no action
// element at all still normalizes (hasAction and hasNotAction both
// false); grantsAction/isAdmin answer false for it, and the trust rules
// preserve their historical treatment of such statements — see
// trustPolicyOpenToAnyoneNote. A statement with neither Resource nor
// NotResource normalizes fine: a missing Resource defaults to "*"
// (the same default the privilege parser has always applied).
func normalizeIAMStmt(s map[string]any) *iamNormalizedStmt {
	eff, _ := lookupMapFold(s, "Effect").(string)
	if !strings.EqualFold(strings.TrimSpace(eff), "Allow") {
		return nil
	}
	n := &iamNormalizedStmt{}
	if v := lookupMapFold(s, "Action"); v != nil {
		n.actions = iamDeepStmtStrings(v)
		n.hasAction = len(n.actions) > 0
	}
	if v := lookupMapFold(s, "NotAction"); v != nil {
		raw := iamDeepStmtStrings(v)
		n.notActions = make([]string, 0, len(raw))
		for _, a := range raw {
			a = strings.TrimSpace(a)
			if a != "" {
				n.notActions = append(n.notActions, strings.ToLower(a))
			}
		}
		n.hasNotAction = len(n.notActions) > 0
	}
	if n.hasAction && n.hasNotAction {
		return nil // invalid: Action and NotAction together
	}
	if v := lookupMapFold(s, "Resource"); v != nil {
		n.resources = iamDeepStmtStrings(v)
		n.hasResource = len(n.resources) > 0
	}
	if v := lookupMapFold(s, "NotResource"); v != nil {
		n.notResources = iamDeepStmtStrings(v)
		n.hasNotResource = len(n.notResources) > 0
	}
	if n.hasResource && n.hasNotResource {
		return nil // invalid: Resource and NotResource together
	}
	for i, a := range n.actions {
		n.actions[i] = strings.ToLower(strings.TrimSpace(a))
	}
	return n
}

// grantsAction reports whether the statement grants the wanted action.
// Wanted may be a concrete action ("iam:passrole") or a pattern
// ("iam:*", "*"). For a positive statement, some granted pattern must
// cover wanted. For a NotAction statement, wanted is granted unless an
// exclusion pattern covers it.
func (n *iamNormalizedStmt) grantsAction(wanted string) bool {
	wanted = strings.ToLower(strings.TrimSpace(wanted))
	if wanted == "" {
		return false
	}
	if n.hasAction {
		for _, a := range n.actions {
			if iamPatternCovers(a, wanted, true) {
				return true
			}
		}
		return false
	}
	if n.hasNotAction {
		for _, na := range n.notActions {
			if iamPatternCovers(na, wanted, true) {
				return false
			}
		}
		return true
	}
	return false
}

// grantsOnStar reports whether the statement grants on Resource "*".
// A positive statement needs an explicit "*" resource (or no Resource
// element, which defaults to "*"). A NotResource statement grants on "*"
// unless an exclusion pattern covers "*" itself.
func (n *iamNormalizedStmt) grantsOnStar() bool {
	if n.hasResource {
		for _, r := range n.resources {
			if strings.TrimSpace(r) == "*" {
				return true
			}
		}
		return false
	}
	if n.hasNotResource {
		for _, nr := range n.notResources {
			if iamPatternCovers(nr, "*", false) {
				return false
			}
		}
		return true
	}
	return true // Resource omitted defaults to "*"
}

// grantsOnClass reports whether the statement grants on the whole
// resource class described by classGlob (e.g. iamRoleARNClass,
// iamS3BucketARNClass). A positive statement needs a resource pattern
// covering the class; a NotResource statement grants on the class unless
// an exclusion pattern covers it.
func (n *iamNormalizedStmt) grantsOnClass(classGlob string) bool {
	if n.hasResource {
		for _, r := range n.resources {
			if iamPatternCovers(strings.TrimSpace(r), classGlob, false) {
				return true
			}
		}
		return false
	}
	if n.hasNotResource {
		for _, nr := range n.notResources {
			if iamPatternCovers(strings.TrimSpace(nr), classGlob, false) {
				return false
			}
		}
		return true
	}
	return true // Resource omitted defaults to "*"
}

// grantsResource reports whether the statement grants on one concrete
// resource ARN.
func (n *iamNormalizedStmt) grantsResource(arn string) bool {
	arn = strings.TrimSpace(arn)
	if arn == "" {
		return false
	}
	if n.hasResource {
		for _, r := range n.resources {
			if iamGlobMatch(strings.TrimSpace(r), arn, false) {
				return true
			}
		}
		return false
	}
	if n.hasNotResource {
		for _, nr := range n.notResources {
			if iamGlobMatch(strings.TrimSpace(nr), arn, false) {
				return false
			}
		}
		return true
	}
	return true // Resource omitted defaults to "*"
}

// isAdmin reports whether the statement grants administrative access:
// Action "*" or "iam:*" on the (separately checked) resource scope.
// See the file header for the NotAction definition.
func (n *iamNormalizedStmt) isAdmin() bool {
	if n.hasAction {
		for _, a := range n.actions {
			if a == "*" || a == "iam:*" {
				return true
			}
		}
		return false
	}
	if n.hasNotAction {
		return n.notActionIsAdmin()
	}
	return false
}

// grantsStarAction reports whether the statement grants Action "*" — the
// AEGIS-AWS-006 definition, which (unlike isAdmin) does not count a bare
// "iam:*". A NotAction statement counts under the same near-admin test
// as isAdmin: its exclusion list must leave the IAM action class intact.
func (n *iamNormalizedStmt) grantsStarAction() bool {
	if n.hasAction {
		for _, a := range n.actions {
			if a == "*" {
				return true
			}
		}
		return false
	}
	if n.hasNotAction {
		return n.notActionIsAdmin()
	}
	return false
}

// notActionIsAdmin is the shared NotAction branch of isAdmin and
// grantsStarAction: no single exclusion pattern covers "*" and none
// covers "iam:*".
func (n *iamNormalizedStmt) notActionIsAdmin() bool {
	for _, na := range n.notActions {
		if iamPatternCovers(na, "*", true) || iamPatternCovers(na, "iam:*", true) {
			return false
		}
	}
	return true
}

// exclusionNote renders the statement's exclusions for finding evidence,
// so a finding never claims a scope the policy explicitly excludes.
// Returns "" when the statement has no exclusions.
func (n *iamNormalizedStmt) exclusionNote() string {
	var parts []string
	if n.hasNotAction {
		parts = append(parts, "NotAction excludes ["+strings.Join(n.notActions, ", ")+"]")
	}
	if n.hasNotResource {
		parts = append(parts, "NotResource excludes ["+strings.Join(n.notResources, ", ")+"]")
	}
	return strings.Join(parts, "; ")
}

// iamGlobMatch reports whether a glob pattern (with "*" wildcards)
// matches a concrete value. When fold is true the match is
// case-insensitive.
func iamGlobMatch(pattern, value string, fold bool) bool {
	if fold {
		pattern = strings.ToLower(pattern)
		value = strings.ToLower(value)
	}
	pattern = strings.TrimSpace(pattern)
	value = strings.TrimSpace(value)
	if pattern == "" {
		return false
	}
	if !strings.Contains(pattern, "*") {
		return pattern == value
	}
	// Split on "*" and require ordered segment containment.
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, p := range parts {
		if p == "" {
			continue
		}
		if i == 0 && !strings.HasPrefix(pattern, "*") {
			if !strings.HasPrefix(value[pos:], p) {
				return false
			}
			pos += len(p)
			continue
		}
		idx := strings.Index(value[pos:], p)
		if idx < 0 {
			return false
		}
		pos += idx + len(p)
	}
	if last := parts[len(parts)-1]; last != "" && !strings.HasSuffix(pattern, "*") {
		return strings.HasSuffix(value, last)
	}
	return true
}

// iamPatternCovers reports whether every string matched by the wanted
// pattern is also matched by pattern — i.e. whether pattern's language
// is a superset of wanted's. Exact when both patterns carry at most one
// "*" (all shapes that occur in real policies); for exotic multi-"*"
// patterns the prefix/suffix test is necessary but not sufficient, so
// coverage may be over-approximated (see the file header).
func iamPatternCovers(pattern, wanted string, fold bool) bool {
	if fold {
		pattern = strings.ToLower(pattern)
		wanted = strings.ToLower(wanted)
	}
	pattern = strings.TrimSpace(pattern)
	wanted = strings.TrimSpace(wanted)
	if pattern == "" || wanted == "" {
		return false
	}
	if pattern == "*" {
		return true
	}
	if !strings.Contains(wanted, "*") {
		// Concrete wanted: plain glob match.
		return iamGlobMatch(pattern, wanted, false)
	}
	if !strings.Contains(pattern, "*") {
		// A single concrete string cannot cover a multi-string language.
		return false
	}
	preP := pattern[:strings.Index(pattern, "*")]
	sufP := pattern[strings.LastIndex(pattern, "*")+1:]
	preW := wanted[:strings.Index(wanted, "*")]
	sufW := wanted[strings.LastIndex(wanted, "*")+1:]
	return strings.HasPrefix(preW, preP) && strings.HasSuffix(sufW, sufP)
}

// firstAdminStmtNote returns the exclusion note of the first
// administrative Allow statement in a policy document, or "" when there
// is none (or the admin grant uses plain Action/Resource). Rules whose
// admin predicate is a bare bool use this to keep their evidence honest
// about NotAction/NotResource scope. When starOnly is true the match
// uses grantsStarAction (AEGIS-AWS-006); otherwise isAdmin.
func firstAdminStmtNote(doc string, starOnly bool) string {
	for _, s := range policyStatements(doc) {
		n := normalizeIAMStmt(s)
		if n == nil || !n.grantsOnStar() {
			continue
		}
		admin := n.isAdmin()
		if starOnly {
			admin = n.grantsStarAction()
		}
		if !admin {
			continue
		}
		return n.exclusionNote()
	}
	return ""
}

// IAM permission reachability for attack chains (v2.4.0, IAM #19).
//
// Before v2.4.0 a kill chain needed a network/reference edge between a
// workload and a data store: an over-broad IAM grant (e.g. `s3:*` on `*`)
// attached to a workload's role could not form a chain link, because IAM
// reachability was not modeled in the graph builder. This file adds it —
// without inventing hops.
//
// A link exists only when ALL of the following are proven from the
// configuration in scope:
//
//  1. The principal: an aws_iam_role that a workload assumes (Lambda role,
//     EC2 instance profile, or a role anyone can assume via an open trust
//     policy), resolved through a real reference, a role name, or an IAM
//     ARN literal naming a role that exists in scope. References to roles
//     outside the scanned configuration never create links.
//  2. The grant: an Allow statement (parsed from the policy JSON) whose
//     Action matches a data-plane action of the target's service and whose
//     Resource matches the target's ARN (or `*`). Statements using
//     NotAction/NotResource are skipped: their effective permissions need
//     full policy-evaluation semantics, and silently treating them as
//     grants would invent hops. Unparseable or unknown policy documents
//     yield no links.
//  3. The target: a data store resource present in the scanned
//     configuration. A grant naming an ARN outside the scope links to
//     nothing.
//
// Two link classes exist, and they are gated differently:
//
//   - Workload links (role assumed by a workload): the grant must be
//     OVER-BROAD in at least one dimension — a service-wildcard action
//     (`s3:*`, `*`) or a wildcard resource (`*`, `arn:aws:s3:::*`). A
//     fully-scoped grant (one action on one ARN) is ordinary
//     least-privilege use and does not by itself create an attack path:
//     the workload would still have to be compromised first, and flagging
//     every scoped read would drown the signal. Over-broad grants are the
//     ones whose blast radius makes the IAM edge itself the story.
//   - Open-trust links (role assumable by any AWS principal): any
//     data-plane grant counts, however scoped, because the openness is the
//     broadness — anyone with any AWS account can assume the role and use
//     the grant. A trust statement only counts when its Principal is `*`
//     (or `{"AWS": "*"}`), its Action allows sts:AssumeRole, and it carries
//     NO Condition: a conditioned trust (org ID, external ID, OIDC sub) is
//     restricted, not open.
//
// Every link carries its evidence: the policy statement (actions +
// resource pattern) and the role/trust spans that prove it. Links are
// labeled in the chain as IAM-reachability hops so a reader can tell a
// permission edge from a network edge.
//
// Deliberately NOT modeled (follow-ups, not oversights):
//   - Inline `inline_policy` blocks on aws_iam_role (the separate
//     aws_iam_role_policy resource, attachments, and managed_policy_arns
//     are covered).
//   - ECS task roles (aws_ecs_task_definition.task_role_arn): the service
//     references the role only indirectly via the task definition.
//   - Data access through an assumed-role chain (role A can assume role B
//     which can read the bucket): transitive assume-role reachability.
//   - Resource patterns granting index-level access (e.g. a DynamoDB GSI
//     ARN) — only the table ARN itself matches.
package attackpath

import (
	"encoding/json"
	"sort"
	"strings"

	"aegis/internal/ir"
)

// IAMReachLink is one evidence-backed IAM permission reachability link:
// a role's policy grants data-plane actions on an in-scope data store.
type IAMReachLink struct {
	Role     string   // "aws_iam_role.app" — the principal
	Policy   string   // resource carrying the grant (policy, attachment, or role for managed_policy_arns)
	Workload string   // workload address; "" for open-trust (role-only) links
	Target   string   // data store address, e.g. "aws_s3_bucket.assets"
	Actions  []string // granted action patterns as written, e.g. ["s3:*"]
	Resource string   // Resource pattern as written, e.g. "*" or "arn:aws:s3:::assets/*"
	// Evidence cites the policy attribute + span proving the grant.
	Evidence ir.Evidence
	// OpenTrust is true when the role is assumable by any AWS principal.
	OpenTrust bool
	// TrustEvidence cites the assume_role_policy statement proving the
	// open trust (only set when OpenTrust is true).
	TrustEvidence ir.Evidence
}

// IAMReachLinks returns every IAM permission reachability link found by
// the builder, deterministically sorted. Exported for rule use and tests.
func (b *Builder) IAMReachLinks() []IAMReachLink {
	return b.findIAMReachLinks()
}

// ---------------------------------------------------------------------------
// Policy document parsing (local copy of the rules/aws parser shape —
// attackpath cannot import rules/aws, which imports attackpath).
// ---------------------------------------------------------------------------

// parsePolicyStatements parses the Statement element of an IAM policy
// document, accepting a single object or a list. Anything unparseable
// yields nil. Statement keys are matched case-insensitively by callers.
func parsePolicyStatements(doc string) []map[string]any {
	var parsed struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &parsed); err != nil {
		return nil
	}
	if len(parsed.Statement) == 0 {
		return nil
	}
	if parsed.Statement[0] == '[' {
		var stmts []map[string]any
		if err := json.Unmarshal(parsed.Statement, &stmts); err != nil {
			return nil
		}
		return stmts
	}
	var one map[string]any
	if err := json.Unmarshal(parsed.Statement, &one); err != nil {
		return nil
	}
	return []map[string]any{one}
}

// stmtField returns the value of key (case-insensitive) in a statement.
func stmtField(stmt map[string]any, key string) (any, bool) {
	for k, v := range stmt {
		if strings.EqualFold(k, key) {
			return v, true
		}
	}
	return nil, false
}

// stmtHas reports whether the statement carries key (case-insensitive).
func stmtHas(stmt map[string]any, key string) bool {
	_, ok := stmtField(stmt, key)
	return ok
}

// stmtStringList returns the string(s) in a statement field: a single
// string or a list of strings. Anything else yields nil.
func stmtStringList(stmt map[string]any, key string) []string {
	v, ok := stmtField(stmt, key)
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, item := range t {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// stmtEffectAllow reports whether the statement is an Allow.
func stmtEffectAllow(stmt map[string]any) bool {
	v, ok := stmtField(stmt, "Effect")
	if !ok {
		return false
	}
	s, ok := v.(string)
	return ok && strings.EqualFold(strings.TrimSpace(s), "Allow")
}

// ---------------------------------------------------------------------------
// Action / resource matching
// ---------------------------------------------------------------------------

// iamDataPlaneActions lists representative data-plane actions per service.
// A granted action pattern matches a service when it is `*`, the
// service wildcard (`<svc>:*`), or glob-matches one of these actions.
// Control-plane actions (Describe*, Create*, PutBucketPolicy, ...) do not
// match: they do not read or write the data itself. Services with an empty
// list (ElastiCache, Redshift) match only on `*` / `<svc>:*`.
var iamDataPlaneActions = map[string][]string{
	"s3": {
		"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:ListBucket",
	},
	"dynamodb": {
		"dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem",
		"dynamodb:UpdateItem", "dynamodb:Query", "dynamodb:Scan",
		"dynamodb:BatchGetItem", "dynamodb:BatchWriteItem",
	},
	"rds": {
		"rds-db:connect", "rds-data:ExecuteStatement",
		"rds-data:BatchExecuteStatement",
	},
	"elasticache": {},
	"redshift":    {},
}

// globMatch reports whether an IAM-style pattern (with `*` wildcards,
// case-insensitive for actions) matches s. Linear-time, no regex: the
// matcher is called per statement x service x action on every scan, and
// matcher is called per statement x service x action on every scan, and
// compiling a regexp per call would be pure overhead on that hot path.
func globMatch(pattern, s string) bool {
	return wildcardMatch(pattern, s, true)
}

// wildcardMatch matches pattern against s where `*` matches any run of
// characters (including none). Classic greedy two-pointer algorithm.
func wildcardMatch(pattern, s string, fold bool) bool {
	if fold {
		pattern = strings.ToLower(pattern)
		s = strings.ToLower(s)
	}
	px, sx := 0, 0
	star, mark := -1, -1
	for sx < len(s) {
		if px < len(pattern) && pattern[px] == s[sx] {
			px++
			sx++
		} else if px < len(pattern) && pattern[px] == '*' {
			star = px
			mark = sx
			px++
		} else if star != -1 {
			px = star + 1
			mark++
			sx = mark
		} else {
			return false
		}
	}
	for px < len(pattern) && pattern[px] == '*' {
		px++
	}
	return px == len(pattern)
}

// iamDataGrant checks one Allow statement against one service. It returns
// the granted action patterns that reach the service's data plane, the
// statement's resource patterns, and false when the statement cannot grant
// data access (Deny, NotAction/NotResource, unparseable actions/resources).
func iamDataGrant(stmt map[string]any, service string) (actions, resources []string, ok bool) {
	if !stmtEffectAllow(stmt) {
		return nil, nil, false
	}
	// Negative logic needs full policy-evaluation semantics — never treat
	// it as a grant (same deliberate blind spot as rules/aws).
	if stmtHas(stmt, "NotAction") || stmtHas(stmt, "NotResource") {
		return nil, nil, false
	}
	granted := stmtStringList(stmt, "Action")
	if len(granted) == 0 {
		return nil, nil, false
	}
	resources = stmtStringList(stmt, "Resource")
	if len(resources) == 0 {
		return nil, nil, false
	}
	reps := iamDataPlaneActions[service]
	for _, pattern := range granted {
		p := strings.TrimSpace(pattern)
		if p == "*" {
			actions = append(actions, p)
			continue
		}
		// A "<service>:*" wildcard matches only when the service's
		// data-plane actions actually live under that prefix. "rds:*"
		// does NOT grant "rds-db:connect" (different prefix), so the
		// shortcut must not fire for RDS; "s3:*" does grant
		// "s3:GetObject" (same prefix). Services with no fine-grained
		// representatives (ElastiCache, Redshift) match on "<svc>:*".
		if strings.EqualFold(p, service+":*") && serviceWildcardOK(service, reps) {
			actions = append(actions, p)
			continue
		}
		for _, rep := range reps {
			if globMatch(p, rep) {
				actions = append(actions, p)
				break
			}
		}
	}
	if len(actions) == 0 {
		return nil, nil, false
	}
	return actions, resources, true
}

// isOverBroadGrant reports whether a grant is over-broad in at least one
// dimension: a service-wildcard action (`s3:*`, `*`) or a wildcard
// resource (`*`, `arn:aws:s3:::*`). Workload links require this; fully
// scoped grants do not create workload attack paths.
func isOverBroadGrant(actions, resources []string) bool {
	for _, a := range actions {
		a = strings.TrimSpace(a)
		if a == "*" || strings.HasSuffix(a, ":*") {
			return true
		}
	}
	for _, r := range resources {
		r = strings.TrimSpace(r)
		if r == "*" || strings.HasSuffix(r, ":*") {
			return true
		}
	}
	return false
}

// serviceWildcardOK reports whether "<service>:*" genuinely covers the
// service's data plane: every representative action shares the service
// prefix (or there are no representatives, so the wildcard is the only
// signal). "rds:*" fails this for RDS, whose data actions live under
// rds-db: / rds-data:.
func serviceWildcardOK(service string, reps []string) bool {
	for _, rep := range reps {
		if i := strings.Index(rep, ":"); i < 0 || !strings.EqualFold(rep[:i], service) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Target ARN matching
// ---------------------------------------------------------------------------

// iamServiceOfTarget returns the IAM service prefix for a data store type.
func iamServiceOfTarget(resType string) (string, bool) {
	switch resType {
	case "aws_s3_bucket":
		return "s3", true
	case "aws_dynamodb_table":
		return "dynamodb", true
	case "aws_db_instance", "aws_rds_cluster":
		return "rds", true
	case "aws_elasticache_cluster":
		return "elasticache", true
	case "aws_redshift_cluster":
		return "redshift", true
	}
	return "", false
}

// targetName returns the resource's AWS-side name: the identifying
// attribute when present, else the Terraform label.
func targetName(r ir.Resource, attrs ...string) string {
	for _, a := range attrs {
		if v, ok := r.Attributes[a]; ok {
			if s := strings.TrimSpace(rawString(v)); s != "" {
				return strings.Trim(s, `"`)
			}
		}
	}
	return r.Name
}

// targetARNs returns the canonical IAM ARNs for a data store: the bare
// ARN and, where IAM accepts it, the /*-suffixed form. The region and
// account segments are `*`: the target's real region/account are not
// knowable from Terraform, and matching compares segment-wise with `*`
// on either side treated as a wildcard — so only the service and the
// resource name decide a match.
func targetARNs(r ir.Resource) []string {
	name := ""
	var arns []string
	switch r.Type {
	case "aws_s3_bucket":
		name = targetName(r, "bucket")
		// S3 ARNs carry no region/account segments: arn:aws:s3:::name.
		arns = []string{"arn:aws:s3:::" + name, "arn:aws:s3:::" + name + "/*"}
	case "aws_dynamodb_table":
		name = targetName(r, "name")
		arns = []string{"arn:aws:dynamodb:*:*:table/" + name, "arn:aws:dynamodb:*:*:table/" + name + "/*"}
	case "aws_db_instance":
		name = targetName(r, "identifier")
		arns = []string{"arn:aws:rds:*:*:db:" + name}
	case "aws_rds_cluster":
		name = targetName(r, "cluster_identifier")
		arns = []string{"arn:aws:rds:*:*:cluster:" + name}
	case "aws_elasticache_cluster":
		name = targetName(r, "cluster_id")
		arns = []string{"arn:aws:elasticache:*:*:cluster:" + name}
	case "aws_redshift_cluster":
		name = targetName(r, "cluster_identifier")
		arns = []string{"arn:aws:redshift:*:*:cluster:" + name}
	}
	return arns
}

// resourceMatchesTarget reports whether a Resource pattern from a policy
// statement covers the target data store. `*` covers everything; anything
// else must segment-match one of the target's canonical ARNs: the two
// ARNs match segment-wise (a `*` segment on either side matches anything,
// so a pattern's region/account wildcards match and a concrete region in
// the pattern must equal the target's — the target's region is unknown,
// so only the service and resource-name segments can decide), and the
// resource segment itself glob-matches (case-sensitive — names are).
func resourceMatchesTarget(pattern string, r ir.Resource) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "*" {
		return true
	}
	if !strings.HasPrefix(pattern, "arn:") {
		return false
	}
	for _, arn := range targetARNs(r) {
		if arnSegmentsMatch(pattern, arn) {
			return true
		}
	}
	return false
}

// arnSegmentsMatch compares two ARNs segment by segment (split on ":").
// Segments match when equal or when either side is exactly "*"; the final
// (resource) segment glob-matches instead, so "table/*" covers
// "table/orders" and "assets/*" covers "assets/*".
func arnSegmentsMatch(pattern, arn string) bool {
	pSegs := strings.Split(pattern, ":")
	aSegs := strings.Split(arn, ":")
	if len(pSegs) != len(aSegs) {
		return false
	}
	for i := 0; i < len(pSegs); i++ {
		if i == len(pSegs)-1 {
			if !globMatchARN(pSegs[i], aSegs[i]) {
				return false
			}
			continue
		}
		if pSegs[i] != aSegs[i] && pSegs[i] != "*" && aSegs[i] != "*" {
			return false
		}
	}
	return true
}

// globMatchARN is globMatch without case folding: IAM resource names are
// case-sensitive.
func globMatchARN(pattern, s string) bool {
	return wildcardMatch(pattern, s, false)
}

// ---------------------------------------------------------------------------
// Role <-> policy and workload <-> role resolution
// ---------------------------------------------------------------------------

// rolePolicyDoc is one policy document attached to a role, with the
// resource that carries the grant as evidence.
type rolePolicyDoc struct {
	addr     string // policy / attachment / role-policy / role resource
	doc      string // JSON policy document
	evidence ir.Evidence
}

// adminPolicyDoc is the synthetic document for AWS-managed
// AdministratorAccess: Action "*" on Resource "*".
const adminPolicyDoc = `{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`

// managedAdminARN is the AWS-managed AdministratorAccess policy ARN.
const managedAdminARN = "arn:aws:iam::aws:policy/AdministratorAccess"

// roleByName resolves a role by its Terraform label or its AWS `name`
// attribute. Ambiguous names (two roles matching) resolve to nothing:
// an ambiguous link is no link.
func (b *Builder) roleByName(name string) (string, bool) {
	name = strings.Trim(name, `"`)
	addrs := b.roleNames[name]
	if len(addrs) != 1 {
		return "", false
	}
	return addrs[0], true
}

// refOrNameToRole resolves a role reference value: a Terraform reference
// (aws_iam_role.app.arn), an IAM ARN literal
// (arn:aws:iam::123456789012:role/name), or a plain role name.
func (b *Builder) refOrNameToRole(raw string) string {
	raw = strings.TrimSpace(strings.Trim(raw, `"`))
	if raw == "" {
		return ""
	}
	if addr := refToAddr(raw, "aws_iam_role"); addr != "" {
		if _, ok := b.byAddr[addr]; ok {
			return addr
		}
		return ""
	}
	if strings.HasPrefix(raw, "arn:aws:iam::") {
		// ARN literal: take the role name after "role/" (last segment).
		if i := strings.Index(raw, ":role/"); i >= 0 {
			name := raw[i+len(":role/"):]
			if j := strings.LastIndex(name, "/"); j >= 0 {
				name = name[j+1:]
			}
			if addr, ok := b.roleByName(name); ok {
				return addr
			}
		}
		return ""
	}
	if addr, ok := b.roleByName(raw); ok {
		return addr
	}
	return ""
}

// rolePolicyDocs maps each role address to the policy documents attached
// to it: aws_iam_role_policy_attachment (ref or AdministratorAccess
// literal), aws_iam_policy_attachment (roles list), inline
// aws_iam_role_policy resources, and managed_policy_arns on the role.
// The result is cached on the Builder: findIAMChains and
// findIAMReachLinks both need it on every scan.
func (b *Builder) rolePolicyDocs() map[string][]rolePolicyDoc {
	if b.roleDocsCached {
		return b.roleDocsCache
	}
	b.roleDocsCache = b.computeRolePolicyDocs()
	b.roleDocsCached = true
	return b.roleDocsCache
}

func (b *Builder) computeRolePolicyDocs() map[string][]rolePolicyDoc {
	out := map[string][]rolePolicyDoc{}
	add := func(roleAddr string, doc rolePolicyDoc) {
		if roleAddr == "" {
			return
		}
		out[roleAddr] = append(out[roleAddr], doc)
	}
	// Deduped view: never merge attributes across same-address resources.
	for _, r := range b.dedupedResources() {
		switch r.Type {
		case "aws_iam_role_policy_attachment":
			roleAddr := ""
			if v, ok := getString(r, "role"); ok {
				roleAddr = b.refOrNameToRole(rawOrRef(v))
			}
			if roleAddr == "" {
				continue
			}
			if v, ok := getString(r, "policy_arn"); ok {
				raw := rawOrRef(v)
				if strings.TrimSpace(strings.Trim(raw, `"`)) == managedAdminARN {
					add(roleAddr, rolePolicyDoc{addr: r.Address(), doc: adminPolicyDoc,
						evidence: ir.Evidence{Attribute: "policy_arn", Span: v.Span, Actual: managedAdminARN, Expected: "scoped managed policy"}})
					continue
				}
				if polAddr := refToAddr(raw, "aws_iam_policy"); polAddr != "" {
					if pol, ok := b.byAddr[polAddr]; ok {
						if pv, ok := getString(pol, "policy"); ok {
							add(roleAddr, rolePolicyDoc{addr: polAddr, doc: rawString(pv),
								evidence: ir.Evidence{Attribute: "policy", Span: pv.Span, Actual: polAddr, Expected: "scoped actions/resources"}})
						}
					}
				}
			}
		case "aws_iam_policy_attachment":
			var roles []string
			if v, ok := r.Attributes["roles"]; ok {
				roles = append(roles, asStringList(v)...)
				// asStringList misses ref items in unknown lists; walk raw.
				if l, ok := v.Raw.([]ir.Value); ok {
					for _, item := range l {
						if item.Ref != "" {
							roles = append(roles, item.Ref)
						}
					}
				}
			}
			if len(roles) == 0 {
				continue
			}
			if v, ok := getString(r, "policy_arn"); ok {
				raw := rawOrRef(v)
				if strings.TrimSpace(strings.Trim(raw, `"`)) == managedAdminARN {
					for _, role := range roles {
						add(b.refOrNameToRole(role), rolePolicyDoc{addr: r.Address(), doc: adminPolicyDoc,
							evidence: ir.Evidence{Attribute: "policy_arn", Span: v.Span, Actual: managedAdminARN, Expected: "scoped managed policy"}})
					}
					continue
				}
				if polAddr := refToAddr(raw, "aws_iam_policy"); polAddr != "" {
					if pol, ok := b.byAddr[polAddr]; ok {
						if pv, ok := getString(pol, "policy"); ok {
							for _, role := range roles {
								add(b.refOrNameToRole(role), rolePolicyDoc{addr: polAddr, doc: rawString(pv),
									evidence: ir.Evidence{Attribute: "policy", Span: pv.Span, Actual: polAddr, Expected: "scoped actions/resources"}})
							}
						}
					}
				}
			}
		case "aws_iam_role_policy":
			roleAddr := ""
			if v, ok := getString(r, "role"); ok {
				roleAddr = b.refOrNameToRole(rawOrRef(v))
			}
			if roleAddr == "" {
				continue
			}
			if v, ok := getString(r, "policy"); ok {
				add(roleAddr, rolePolicyDoc{addr: r.Address(), doc: rawString(v),
					evidence: ir.Evidence{Attribute: "policy", Span: v.Span, Actual: r.Address(), Expected: "scoped actions/resources"}})
			}
		case "aws_iam_role":
			if v, ok := r.Attributes["managed_policy_arns"]; ok {
				for _, arn := range asStringList(v) {
					if strings.TrimSpace(strings.Trim(arn, `"`)) == managedAdminARN {
						add(r.Address(), rolePolicyDoc{addr: r.Address(), doc: adminPolicyDoc,
							evidence: ir.Evidence{Attribute: "managed_policy_arns", Span: v.Span, Actual: managedAdminARN, Expected: "scoped managed policy"}})
					}
				}
				// Ref items in unknown lists carry the ARN in Ref.
				if l, ok := v.Raw.([]ir.Value); ok {
					for _, item := range l {
						if strings.TrimSpace(item.Ref) == managedAdminARN {
							add(r.Address(), rolePolicyDoc{addr: r.Address(), doc: adminPolicyDoc,
								evidence: ir.Evidence{Attribute: "managed_policy_arns", Span: v.Span, Actual: managedAdminARN, Expected: "scoped managed policy"}})
						}
					}
				}
			}
		}
	}
	// Dedupe identical (role, addr, doc) triples.
	for role, docs := range out {
		seen := map[string]bool{}
		var deduped []rolePolicyDoc
		for _, d := range docs {
			k := d.addr + "\x00" + d.doc
			if !seen[k] {
				seen[k] = true
				deduped = append(deduped, d)
			}
		}
		out[role] = deduped
	}
	return out
}

// workloadRoleAddrs maps each workload address to the IAM role it assumes:
// Lambda `role`, EC2 `iam_instance_profile` (via the profile's role).
// ECS task roles are not mapped (service -> task definition -> role is
// indirect; see the package doc). Cached on the Builder, like
// rolePolicyDocs.
func (b *Builder) workloadRoleAddrs() map[string]string {
	if b.workloadRolesCached {
		return b.workloadRolesCache
	}
	b.workloadRolesCache = b.computeWorkloadRoleAddrs()
	b.workloadRolesCached = true
	return b.workloadRolesCache
}

func (b *Builder) computeWorkloadRoleAddrs() map[string]string {
	out := map[string]string{}
	for _, r := range b.dedupedResources() {
		switch r.Type {
		case "aws_lambda_function":
			if v, ok := getString(r, "role"); ok {
				if addr := b.refOrNameToRole(rawOrRef(v)); addr != "" {
					out[r.Address()] = addr
				}
			}
		case "aws_instance":
			if v, ok := getString(r, "iam_instance_profile"); ok {
				if addr := b.resolveInstanceProfileRole(rawOrRef(v)); addr != "" {
					out[r.Address()] = addr
				}
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Open-trust detection
// ---------------------------------------------------------------------------

// openTrustEvidence returns the evidence for a role whose trust policy lets
// any AWS principal assume it: an Allow statement with Principal "*" (or
// {"AWS": "*"}) and Action sts:AssumeRole (or "*"), and NO Condition.
// A conditioned trust is restricted, not open. Service principals
// (ec2.amazonaws.com, ...) are not "anyone".
func openTrustEvidence(role ir.Resource) (ir.Evidence, bool) {
	v, ok := getString(role, "assume_role_policy")
	if !ok {
		return ir.Evidence{}, false
	}
	doc := rawString(v)
	if doc == "" {
		return ir.Evidence{}, false
	}
	for _, stmt := range parsePolicyStatements(doc) {
		if !stmtEffectAllow(stmt) {
			continue
		}
		if stmtHas(stmt, "Condition") {
			continue
		}
		p, ok := stmtField(stmt, "Principal")
		if !ok || !principalIsAnyone(p) {
			continue
		}
		acts := stmtStringList(stmt, "Action")
		assume := false
		for _, a := range acts {
			a = strings.TrimSpace(a)
			if a == "*" || globMatch(a, "sts:AssumeRole") {
				assume = true
				break
			}
		}
		if !assume {
			continue
		}
		return ir.Evidence{
			Attribute: "assume_role_policy",
			Span:      v.Span,
			Actual:    `Principal "*" with no Condition`,
			Expected:  "specific principal (service, account, or federated provider)",
		}, true
	}
	return ir.Evidence{}, false
}

// principalIsAnyone reports whether a Principal value is everyone: the
// string "*" or a map with an AWS key of "*" (string or list).
func principalIsAnyone(p any) bool {
	switch t := p.(type) {
	case string:
		return strings.TrimSpace(t) == "*"
	case map[string]any:
		for k, v := range t {
			if !strings.EqualFold(k, "AWS") {
				continue
			}
			switch vv := v.(type) {
			case string:
				if strings.TrimSpace(vv) == "*" {
					return true
				}
			case []any:
				for _, item := range vv {
					if s, ok := item.(string); ok && strings.TrimSpace(s) == "*" {
						return true
					}
				}
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Link computation
// ---------------------------------------------------------------------------

// findIAMReachLinks computes every IAM permission reachability link:
// workload-role links (over-broad grants only) and open-trust links (any
// data-plane grant on an assumable-by-anyone role).
func (b *Builder) findIAMReachLinks() []IAMReachLink {
	dataStores := b.findDataStores()
	// Index data stores by IAM service.
	byService := map[string][]ir.Resource{}
	for _, d := range dataStores {
		res, ok := b.byAddr[d.Resource]
		if !ok {
			continue
		}
		svc, ok := iamServiceOfTarget(res.Type)
		if !ok {
			continue
		}
		byService[svc] = append(byService[svc], res)
	}
	if len(byService) == 0 {
		return nil
	}
	roleDocs := b.rolePolicyDocs()

	// grantsFor returns (actions, resources, service) triples for one
	// policy document: every Allow statement's data-plane grant, per
	// service it reaches.
	type grant struct {
		actions   []string
		resources []string
		service   string
	}
	grantsFor := func(doc string) []grant {
		var out []grant
		for _, stmt := range parsePolicyStatements(doc) {
			for svc := range iamDataPlaneActions {
				actions, resources, ok := iamDataGrant(stmt, svc)
				if !ok {
					continue
				}
				out = append(out, grant{actions: actions, resources: resources, service: svc})
			}
		}
		return out
	}

	seen := map[string]bool{}
	var links []IAMReachLink
	addLink := func(l IAMReachLink) {
		k := strings.Join([]string{l.Role, l.Policy, l.Workload, l.Target,
			strings.Join(l.Actions, ","), l.Resource}, "\x00")
		if !seen[k] {
			seen[k] = true
			links = append(links, l)
		}
	}

	// Workload links: role assumed by a workload, over-broad grant only.
	workloadRoles := b.workloadRoleAddrs()
	workloads := make([]string, 0, len(workloadRoles))
	for w := range workloadRoles {
		workloads = append(workloads, w)
	}
	sort.Strings(workloads)
	for _, wl := range workloads {
		roleAddr := workloadRoles[wl]
		for _, doc := range roleDocs[roleAddr] {
			for _, g := range grantsFor(doc.doc) {
				if !isOverBroadGrant(g.actions, g.resources) {
					continue
				}
				for _, resPat := range g.resources {
					for _, target := range byService[g.service] {
						if !resourceMatchesTarget(resPat, target) {
							continue
						}
						ev := doc.evidence
						ev.Actual = "Action " + strings.Join(g.actions, ", ") + " on Resource " + resPat
						addLink(IAMReachLink{
							Role: roleAddr, Policy: doc.addr, Workload: wl,
							Target: target.Address(), Actions: append([]string(nil), g.actions...),
							Resource: resPat, Evidence: ev,
						})
					}
				}
			}
		}
	}

	// Open-trust links: any data-plane grant on an assumable-by-anyone role.
	// Deduped view: a duplicate-address role must not merge trust from
	// one copy with policies from another.
	for _, role := range b.dedupedResources() {
		if role.Type != "aws_iam_role" {
			continue
		}
		trustEv, open := openTrustEvidence(role)
		if !open {
			continue
		}
		for _, doc := range roleDocs[role.Address()] {
			for _, g := range grantsFor(doc.doc) {
				for _, resPat := range g.resources {
					for _, target := range byService[g.service] {
						if !resourceMatchesTarget(resPat, target) {
							continue
						}
						ev := doc.evidence
						ev.Actual = "Action " + strings.Join(g.actions, ", ") + " on Resource " + resPat
						addLink(IAMReachLink{
							Role: role.Address(), Policy: doc.addr, Workload: "",
							Target: target.Address(), Actions: append([]string(nil), g.actions...),
							Resource: resPat, Evidence: ev,
							OpenTrust: true, TrustEvidence: trustEv,
						})
					}
				}
			}
		}
	}

	sort.Slice(links, func(i, j int) bool {
		if links[i].Workload != links[j].Workload {
			return links[i].Workload < links[j].Workload
		}
		if links[i].Target != links[j].Target {
			return links[i].Target < links[j].Target
		}
		if links[i].Role != links[j].Role {
			return links[i].Role < links[j].Role
		}
		return links[i].Policy < links[j].Policy
	})
	return links
}

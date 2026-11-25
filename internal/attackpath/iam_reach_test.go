package attackpath

import (
	"reflect"
	"strings"
	"testing"

	"aegis/internal/ir"
)

// --- helpers ---------------------------------------------------------------

func iamPolicyDoc(actions, resources string) string {
	return `{"Statement":[{"Effect":"Allow","Action":` + actions + `,"Resource":` + resources + `}]}`
}

func iamRoleWithPolicy(roleName, policyDoc string) []ir.Resource {
	return []ir.Resource{
		testResource("aws_iam_role", roleName, map[string]ir.Value{
			"assume_role_policy": strVal(`{"Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`),
		}),
		testResource("aws_iam_policy", "pol", map[string]ir.Value{
			"policy": strVal(policyDoc),
		}),
		testResource("aws_iam_role_policy_attachment", "att", map[string]ir.Value{
			"role":       refVal("aws_iam_role." + roleName + ".name"),
			"policy_arn": refVal("aws_iam_policy.pol.arn"),
		}),
	}
}

// lambdaWithRole returns a Lambda assuming the named role, with NO network
// entry point anywhere: any chain to a data store must come from IAM.
func lambdaWithRole(roleName string) ir.Resource {
	return testResource("aws_lambda_function", "api", map[string]ir.Value{
		"role": refVal("aws_iam_role." + roleName + ".arn"),
	})
}

func s3Bucket(name string) ir.Resource {
	return testResource("aws_s3_bucket", name, map[string]ir.Value{
		"bucket": strVal(name),
	})
}

func hasIAMLinkHop(c Chain) bool {
	for _, h := range c.Hops {
		if h.Kind == KindIdentity && strings.Contains(h.Detail, "IAM reachability:") {
			return true
		}
	}
	return false
}

func chainTargets(c Chain) []string {
	var out []string
	for _, h := range c.Hops {
		if h.Kind == KindData {
			out = append(out, h.Resource)
		}
	}
	return out
}

// --- positive: workload links ----------------------------------------------

func TestIAMReach_S3WildcardOnStar(t *testing.T) {
	resources := append(iamRoleWithPolicy("app",
		iamPolicyDoc(`"s3:*"`, `"*"`)),
		lambdaWithRole("app"), s3Bucket("assets"))
	links := NewBuilder(resources).IAMReachLinks()
	if len(links) != 1 {
		t.Fatalf("expected 1 IAM reach link for s3:* on *, got %d: %+v", len(links), links)
	}
	l := links[0]
	if l.Target != "aws_s3_bucket.assets" {
		t.Errorf("target = %s, want aws_s3_bucket.assets", l.Target)
	}
	if l.Workload != "aws_lambda_function.api" {
		t.Errorf("workload = %s, want aws_lambda_function.api", l.Workload)
	}
	if l.Evidence.Attribute == "" || l.Evidence.Span.File == "" {
		t.Error("link must cite policy evidence with a file span")
	}
	if !strings.Contains(l.Evidence.Actual, "s3:*") {
		t.Errorf("link evidence should name the granted action, got %q", l.Evidence.Actual)
	}

	chains := NewBuilder(resources).BuildKillChains()
	found := false
	for _, c := range chains {
		if !hasIAMLinkHop(c) {
			continue
		}
		found = true
		if got := chainTargets(c); len(got) != 1 || got[0] != "aws_s3_bucket.assets" {
			t.Errorf("IAM chain targets = %v, want [aws_s3_bucket.assets]", got)
		}
		// No proven entry: the entry hop must be UNCERTAIN, never invented.
		if c.Hops[0].Uncertain == "" {
			t.Error("IAM-only chain with no entry must carry an UNCERTAIN entry hop")
		}
	}
	if !found {
		t.Fatal("expected a kill chain with an IAM-reachability hop")
	}
}

func TestIAMReach_ScopedActionOnNamedBucket(t *testing.T) {
	// s3:* on one named bucket is over-broad by action: it links to that
	// bucket only, never to a sibling bucket.
	resources := append(iamRoleWithPolicy("app",
		iamPolicyDoc(`"s3:*"`, `"arn:aws:s3:::assets/*"`)),
		lambdaWithRole("app"), s3Bucket("assets"), s3Bucket("other"))
	links := NewBuilder(resources).IAMReachLinks()
	if len(links) != 1 {
		t.Fatalf("expected 1 link (assets only), got %d: %+v", len(links), links)
	}
	if links[0].Target != "aws_s3_bucket.assets" {
		t.Errorf("target = %s, want aws_s3_bucket.assets", links[0].Target)
	}
}

func TestIAMReach_GetObjectOnStar(t *testing.T) {
	// A specific action on a wildcard resource is over-broad by resource.
	resources := append(iamRoleWithPolicy("app",
		iamPolicyDoc(`"s3:GetObject"`, `"*"`)),
		lambdaWithRole("app"), s3Bucket("assets"))
	if links := NewBuilder(resources).IAMReachLinks(); len(links) != 1 {
		t.Fatalf("expected 1 link for s3:GetObject on *, got %d", len(links))
	}
}

func TestIAMReach_DynamoDBTableARN(t *testing.T) {
	resources := append(iamRoleWithPolicy("app",
		iamPolicyDoc(`"dynamodb:*"`, `"arn:aws:dynamodb:eu-west-1:123456789012:table/orders"`)),
		lambdaWithRole("app"),
		testResource("aws_dynamodb_table", "orders", map[string]ir.Value{
			"name": strVal("orders"),
		}))
	links := NewBuilder(resources).IAMReachLinks()
	if len(links) != 1 {
		t.Fatalf("expected 1 link to the orders table, got %d: %+v", len(links), links)
	}
	if links[0].Target != "aws_dynamodb_table.orders" {
		t.Errorf("target = %s", links[0].Target)
	}
}

func TestIAMReach_InlinePolicyAndManagedAdmin(t *testing.T) {
	// Inline aws_iam_role_policy with s3:* on * links the workload.
	inline := []ir.Resource{
		testResource("aws_iam_role", "app", map[string]ir.Value{
			"assume_role_policy": strVal(`{"Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`),
		}),
		testResource("aws_iam_role_policy", "inline", map[string]ir.Value{
			"role":   refVal("aws_iam_role.app.name"),
			"policy": strVal(iamPolicyDoc(`"s3:*"`, `"*"`)),
		}),
		lambdaWithRole("app"), s3Bucket("assets"),
	}
	if links := NewBuilder(inline).IAMReachLinks(); len(links) != 1 {
		t.Fatalf("inline policy: expected 1 link, got %d", len(links))
	}

	// Managed AdministratorAccess via managed_policy_arns links too, and
	// the chain's policy hop must not duplicate the role hop.
	managed := []ir.Resource{
		testResource("aws_iam_role", "app", map[string]ir.Value{
			"assume_role_policy": strVal(`{"Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`),
			"managed_policy_arns": ir.Value{Raw: []ir.Value{
				strVal("arn:aws:iam::aws:policy/AdministratorAccess"),
			}, Known: true},
		}),
		lambdaWithRole("app"), s3Bucket("assets"),
	}
	links := NewBuilder(managed).IAMReachLinks()
	if len(links) != 1 {
		t.Fatalf("managed admin: expected 1 link, got %d: %+v", len(links), links)
	}
	if links[0].Policy != "aws_iam_role.app" {
		t.Errorf("managed admin link policy = %s, want the role address (no policy resource)", links[0].Policy)
	}
	chains := NewBuilder(managed).BuildKillChains()
	for _, c := range chains {
		if !hasIAMLinkHop(c) {
			continue
		}
		for i := 1; i < len(c.Hops); i++ {
			if c.Hops[i].Resource == c.Hops[i-1].Resource && c.Hops[i].Kind == c.Hops[i-1].Kind {
				t.Errorf("managed-admin chain repeats hop %s twice in a row: %+v", c.Hops[i].Resource, c.Hops)
			}
		}
	}
}

// --- positive: open-trust links --------------------------------------------

func TestIAMReach_OpenTrustScopedGrant(t *testing.T) {
	// Open trust + a SCOPED grant still links: the openness is the
	// broadness, so the over-broad gate does not apply here.
	resources := []ir.Resource{
		testResource("aws_iam_role", "open", map[string]ir.Value{
			"assume_role_policy": strVal(`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}`),
		}),
		testResource("aws_iam_policy", "pol", map[string]ir.Value{
			"policy": strVal(iamPolicyDoc(`"s3:GetObject"`, `"arn:aws:s3:::assets/*"`)),
		}),
		testResource("aws_iam_role_policy_attachment", "att", map[string]ir.Value{
			"role":       refVal("aws_iam_role.open.name"),
			"policy_arn": refVal("aws_iam_policy.pol.arn"),
		}),
		s3Bucket("assets"),
	}
	links := NewBuilder(resources).IAMReachLinks()
	if len(links) != 1 {
		t.Fatalf("expected 1 open-trust link, got %d: %+v", len(links), links)
	}
	if !links[0].OpenTrust {
		t.Error("link must be marked OpenTrust")
	}
	if links[0].Workload != "" {
		t.Errorf("open-trust link workload = %q, want empty (role-only)", links[0].Workload)
	}
	if links[0].TrustEvidence.Attribute != "assume_role_policy" {
		t.Errorf("link must cite the trust policy as evidence, got %+v", links[0].TrustEvidence)
	}
	chains := NewBuilder(resources).BuildKillChains()
	found := false
	for _, c := range chains {
		if !hasIAMLinkHop(c) {
			continue
		}
		found = true
		if c.Uncertain {
			t.Error("open-trust chain must not be uncertain: the internet entry is proven by the trust policy")
		}
		if c.Hops[0].Resource != "internet" || c.Hops[0].Kind != KindEntry {
			t.Errorf("open-trust chain must start at the internet entry, got %+v", c.Hops[0])
		}
		if !strings.Contains(c.Hops[0].Detail, "aws_iam_role.open") {
			t.Errorf("entry hop must name the assumable role, got %q", c.Hops[0].Detail)
		}
	}
	if !found {
		t.Fatal("expected an open-trust kill chain")
	}
}

func TestIAMReach_OpenTrustAdminViaManagedPolicy(t *testing.T) {
	// Demo scenario 10 shape (open trust added): role with
	// managed_policy_arns AdministratorAccess, no workload, one bucket.
	resources := []ir.Resource{
		testResource("aws_iam_role", "demo", map[string]ir.Value{
			"assume_role_policy": strVal(`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}`),
			"managed_policy_arns": ir.Value{Raw: []ir.Value{
				strVal("arn:aws:iam::aws:policy/AdministratorAccess"),
			}, Known: true},
		}),
		s3Bucket("assets"),
	}
	links := NewBuilder(resources).IAMReachLinks()
	if len(links) != 1 {
		t.Fatalf("expected 1 open-trust link via managed admin, got %d: %+v", len(links), links)
	}
}

// --- negative: no invented hops --------------------------------------------

func TestIAMReach_NoLinkScopedGrant(t *testing.T) {
	// Fully scoped grant (one action, one ARN) on a workload role: no
	// workload link — least-privilege use is not an attack path.
	resources := append(iamRoleWithPolicy("app",
		iamPolicyDoc(`"s3:GetObject"`, `"arn:aws:s3:::assets/*"`)),
		lambdaWithRole("app"), s3Bucket("assets"))
	if links := NewBuilder(resources).IAMReachLinks(); len(links) != 0 {
		t.Fatalf("scoped grant: expected 0 links, got %d: %+v", len(links), links)
	}
	if chains := NewBuilder(resources).BuildKillChains(); len(chains) != 0 {
		t.Fatalf("scoped grant: expected 0 chains, got %d", len(chains))
	}
}

func TestIAMReach_NoLinkGrantToOtherBucket(t *testing.T) {
	// Over-broad action, but the Resource names a bucket outside the
	// scanned configuration: the grant links to nothing in scope.
	resources := append(iamRoleWithPolicy("app",
		iamPolicyDoc(`"s3:*"`, `"arn:aws:s3:::elsewhere/*"`)),
		lambdaWithRole("app"), s3Bucket("assets"))
	if links := NewBuilder(resources).IAMReachLinks(); len(links) != 0 {
		t.Fatalf("out-of-scope ARN: expected 0 links, got %d", len(links))
	}
}

func TestIAMReach_NoLinkNotAction(t *testing.T) {
	// A broad grant via NotAction is silently skipped (documented blind
	// spot): negative logic must never be read as a grant.
	resources := append(iamRoleWithPolicy("app",
		`{"Statement":[{"Effect":"Allow","NotAction":"s3:GetObject","Resource":"*"}]}`),
		lambdaWithRole("app"), s3Bucket("assets"))
	if links := NewBuilder(resources).IAMReachLinks(); len(links) != 0 {
		t.Fatalf("NotAction: expected 0 links, got %d", len(links))
	}
}

func TestIAMReach_NoLinkDenyOnly(t *testing.T) {
	resources := append(iamRoleWithPolicy("app",
		`{"Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*"}]}`),
		lambdaWithRole("app"), s3Bucket("assets"))
	if links := NewBuilder(resources).IAMReachLinks(); len(links) != 0 {
		t.Fatalf("Deny-only: expected 0 links, got %d", len(links))
	}
}

func TestIAMReach_NoLinkControlPlaneOnly(t *testing.T) {
	// Describe* is control-plane, not data access: no data-plane link.
	resources := append(iamRoleWithPolicy("app",
		iamPolicyDoc(`"s3:ListAllMyBuckets"`, `"*"`)),
		lambdaWithRole("app"), s3Bucket("assets"))
	if links := NewBuilder(resources).IAMReachLinks(); len(links) != 0 {
		t.Fatalf("control-plane action: expected 0 links, got %d", len(links))
	}
}

func TestIAMReach_NoLinkUnknownPolicy(t *testing.T) {
	// Policy document from a variable: unknown means no link, never a
	// guessed one.
	resources := []ir.Resource{
		testResource("aws_iam_role", "app", map[string]ir.Value{
			"assume_role_policy": strVal(`{"Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}`),
		}),
		testResource("aws_iam_policy", "pol", map[string]ir.Value{
			"policy": {Raw: "var.policy", Known: true, Ref: "var.policy"},
		}),
		testResource("aws_iam_role_policy_attachment", "att", map[string]ir.Value{
			"role":       refVal("aws_iam_role.app.name"),
			"policy_arn": refVal("aws_iam_policy.pol.arn"),
		}),
		lambdaWithRole("app"), s3Bucket("assets"),
	}
	if links := NewBuilder(resources).IAMReachLinks(); len(links) != 0 {
		t.Fatalf("unknown policy: expected 0 links, got %d", len(links))
	}
}

func TestIAMReach_NoLinkNoDataStore(t *testing.T) {
	// Over-broad grant but no data store in scope: nothing to reach.
	resources := append(iamRoleWithPolicy("app",
		iamPolicyDoc(`"s3:*"`, `"*"`)),
		lambdaWithRole("app"))
	if links := NewBuilder(resources).IAMReachLinks(); len(links) != 0 {
		t.Fatalf("no data store: expected 0 links, got %d", len(links))
	}
}

func TestIAMReach_NoLinkNoWorkloadNoTrust(t *testing.T) {
	// A role with an over-broad policy but no workload and no open trust:
	// the grant is not reachable from anywhere in the chain model.
	resources := append(iamRoleWithPolicy("app",
		iamPolicyDoc(`"s3:*"`, `"*"`)),
		s3Bucket("assets"))
	if links := NewBuilder(resources).IAMReachLinks(); len(links) != 0 {
		t.Fatalf("unattached role: expected 0 links, got %d", len(links))
	}
}

func TestIAMReach_NoLinkConditionedTrust(t *testing.T) {
	// Principal "*" WITH a Condition (org restriction) is not open.
	resources := []ir.Resource{
		testResource("aws_iam_role", "open", map[string]ir.Value{
			"assume_role_policy": strVal(`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-123"}}}]}`),
		}),
		testResource("aws_iam_policy", "pol", map[string]ir.Value{
			"policy": strVal(iamPolicyDoc(`"s3:*"`, `"*"`)),
		}),
		testResource("aws_iam_role_policy_attachment", "att", map[string]ir.Value{
			"role":       refVal("aws_iam_role.open.name"),
			"policy_arn": refVal("aws_iam_policy.pol.arn"),
		}),
		s3Bucket("assets"),
	}
	for _, l := range NewBuilder(resources).IAMReachLinks() {
		if l.OpenTrust {
			t.Fatalf("conditioned trust must not produce an open-trust link: %+v", l)
		}
	}
	// And with no workload, no chain at all.
	if chains := NewBuilder(resources).BuildKillChains(); len(chains) != 0 {
		t.Fatalf("conditioned trust, no workload: expected 0 chains, got %d", len(chains))
	}
}

func TestIAMReach_NoLinkServicePrincipalTrust(t *testing.T) {
	// Trust limited to a service principal is not assumable by anyone.
	resources := []ir.Resource{
		testResource("aws_iam_role", "svc", map[string]ir.Value{
			"assume_role_policy": strVal(`{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`),
		}),
		testResource("aws_iam_policy", "pol", map[string]ir.Value{
			"policy": strVal(iamPolicyDoc(`"s3:*"`, `"*"`)),
		}),
		testResource("aws_iam_role_policy_attachment", "att", map[string]ir.Value{
			"role":       refVal("aws_iam_role.svc.name"),
			"policy_arn": refVal("aws_iam_policy.pol.arn"),
		}),
		s3Bucket("assets"),
	}
	for _, l := range NewBuilder(resources).IAMReachLinks() {
		if l.OpenTrust {
			t.Fatalf("service-principal trust must not produce an open-trust link: %+v", l)
		}
	}
}

func TestIAMReach_NoLinkDuplicateRoleAddress(t *testing.T) {
	// Two resources share one address — open trust in one file,
	// AdministratorAccess in the other (the aws-security-demo layout when
	// its 34 scenario files are scanned as one directory). Attributes must
	// never merge across the duplicates into a Frankenstein role that
	// exists in neither file: the deduped view (first wins) has an open
	// trust with no policy, so there is no link.
	resources := []ir.Resource{
		testResource("aws_iam_role", "demo", map[string]ir.Value{
			"assume_role_policy": strVal(`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"}]}`),
		}),
		testResource("aws_iam_role", "demo", map[string]ir.Value{
			"assume_role_policy": strVal(`{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}`),
			"managed_policy_arns": ir.Value{Raw: []ir.Value{
				strVal("arn:aws:iam::aws:policy/AdministratorAccess"),
			}, Known: true},
		}),
		s3Bucket("assets"),
	}
	if links := NewBuilder(resources).IAMReachLinks(); len(links) != 0 {
		t.Fatalf("duplicate role address: expected 0 links, got %d: %+v", len(links), links)
	}
	if chains := NewBuilder(resources).BuildKillChains(); len(chains) != 0 {
		t.Fatalf("duplicate role address: expected 0 chains, got %d", len(chains))
	}
}

func TestIAMReach_NoLinkRoleOutsideScope(t *testing.T) {
	// Lambda role is an ARN literal naming a role that does not exist in
	// the scanned configuration: no workload link, no invented role.
	resources := append(iamRoleWithPolicy("app",
		iamPolicyDoc(`"s3:*"`, `"*"`)),
		testResource("aws_lambda_function", "api", map[string]ir.Value{
			"role": strVal("arn:aws:iam::123456789012:role/someone-else"),
		}),
		s3Bucket("assets"))
	if links := NewBuilder(resources).IAMReachLinks(); len(links) != 0 {
		t.Fatalf("out-of-scope role ARN: expected 0 links, got %d", len(links))
	}
}

// --- regression: network chains keep their shape ---------------------------

func TestIAMReach_NetworkChainUnchanged(t *testing.T) {
	// A network chain with an IAM-chained workload keeps its exact hop
	// shape: the IAM permission edge hop appears ONLY on IAM-only
	// bridges, so existing chains (and their golden outputs) do not churn.
	resources := []ir.Resource{
		testResource("aws_security_group", "web", map[string]ir.Value{
			"ingress": ingressBlock("0.0.0.0/0"),
		}),
		testResource("aws_instance", "web", map[string]ir.Value{
			"vpc_security_group_ids": refVal("aws_security_group.web.id"),
		}),
		testResource("aws_db_instance", "prod", map[string]ir.Value{
			"vpc_security_group_ids": refVal("aws_security_group.web.id"),
		}),
	}
	chains := NewBuilder(resources).BuildKillChains()
	if len(chains) != 1 {
		t.Fatalf("expected exactly 1 chain, got %d", len(chains))
	}
	if len(chains[0].Hops) != 3 {
		t.Fatalf("network chain must stay 3 hops (entry, workload, data), got %d", len(chains[0].Hops))
	}
	for _, h := range chains[0].Hops {
		if strings.Contains(h.Detail, "IAM reachability:") {
			t.Errorf("network chain must not carry an IAM-reachability hop: %+v", h)
		}
	}
}

// --- parser unit tests -----------------------------------------------------

func TestIAMDataGrant_Matching(t *testing.T) {
	cases := []struct {
		doc     string
		service string
		want    bool
	}{
		{iamPolicyDoc(`"s3:*"`, `"*"`), "s3", true},
		{iamPolicyDoc(`"s3:Get*"`, `"*"`), "s3", true},
		{iamPolicyDoc(`"s3:GetObject"`, `"*"`), "s3", true},
		{iamPolicyDoc(`"s3:PutBucketPolicy"`, `"*"`), "s3", false}, // control-plane
		{iamPolicyDoc(`"dynamodb:Query"`, `"*"`), "dynamodb", true},
		{iamPolicyDoc(`"dynamodb:DescribeTable"`, `"*"`), "dynamodb", false},
		{iamPolicyDoc(`"rds-db:connect"`, `"*"`), "rds", true},
		{iamPolicyDoc(`"rds:*"`, `"*"`), "rds", false}, // rds:* is not rds-db:*
		{iamPolicyDoc(`"*"`, `"*"`), "s3", true},
		{iamPolicyDoc(`"*"`, `"*"`), "redshift", true},
		{iamPolicyDoc(`"elasticache:*"`, `"*"`), "elasticache", true},
		{iamPolicyDoc(`"s3:GetObject"`, `"*"`), "dynamodb", false},
	}
	for _, tc := range cases {
		stmts := parsePolicyStatements(tc.doc)
		if len(stmts) != 1 {
			t.Fatalf("doc %s: expected 1 statement", tc.doc)
		}
		_, _, ok := iamDataGrant(stmts[0], tc.service)
		if ok != tc.want {
			t.Errorf("doc %s service %s: match = %v, want %v", tc.doc, tc.service, ok, tc.want)
		}
	}
}

func TestIAMReach_Deterministic(t *testing.T) {
	resources := append(iamRoleWithPolicy("app",
		iamPolicyDoc(`["s3:*", "dynamodb:*"]`, `"*"`)),
		lambdaWithRole("app"), s3Bucket("assets"),
		testResource("aws_dynamodb_table", "orders", map[string]ir.Value{
			"name": strVal("orders"),
		}))
	a := NewBuilder(resources).IAMReachLinks()
	b := NewBuilder(resources).IAMReachLinks()
	if len(a) != len(b) {
		t.Fatalf("link count differs between runs: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if !reflect.DeepEqual(a[i], b[i]) {
			t.Fatalf("link %d differs between runs: %+v vs %+v", i, a[i], b[i])
		}
	}
	if len(a) != 2 {
		t.Fatalf("expected 2 links (s3 + dynamodb), got %d", len(a))
	}
}

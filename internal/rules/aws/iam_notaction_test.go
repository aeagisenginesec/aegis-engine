package aws

import (
	"strings"
	"testing"

	"aegis/internal/ir"
)

// ---------------------------------------------------------------------------
// NotAction / NotResource policy-evaluation semantics (v2.4.0).
//
// Positive evidence: broad grants via NotAction now fire, with the
// finding's evidence naming the exclusion so the claimed scope is exact.
// Negative evidence: exclusions that cover the checked action / resource
// class suppress the finding. Regression: ordinary Action/Resource
// statements behave exactly as before (also covered by the pre-existing
// rule tests, which pass unmodified except Test501_505_NotActionSilent,
// whose old "silent" expectation is the behavior this feature replaces).
// ---------------------------------------------------------------------------

func naPolicyRes(stmt string) ir.Resource {
	return res("aws_iam_policy", "p", map[string]ir.Value{
		"policy": ks(`{"Statement":[`+stmt+`]}`, 3),
	})
}

func naRoleTrustRes(stmt string) ir.Resource {
	return res("aws_iam_role", "r", map[string]ir.Value{
		"assume_role_policy": ks(`{"Statement":[`+stmt+`]}`, 3),
	})
}

func naRolePolicyRes(stmt string) ir.Resource {
	return res("aws_iam_role_policy", "rp", map[string]ir.Value{
		"policy": ks(`{"Statement":[`+stmt+`]}`, 3),
	})
}

// --- Evaluator unit tests -------------------------------------------------

func TestNotAction_EvaluatorGrantsExceptExcluded(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","NotAction":["iam:DeleteUser"],"Resource":"*"}]}`
	stmts := policyStatements(doc)
	if len(stmts) != 1 {
		t.Fatalf("expected 1 statement, got %d", len(stmts))
	}
	n := normalizeIAMStmt(stmts[0])
	if n == nil {
		t.Fatal("NotAction statement must normalize")
	}
	if !n.grantsAction("iam:createpolicy") {
		t.Fatal("NotAction [iam:DeleteUser] must grant iam:CreatePolicy")
	}
	if n.grantsAction("iam:deleteuser") {
		t.Fatal("NotAction [iam:DeleteUser] must NOT grant iam:DeleteUser")
	}
	if !n.grantsAction("s3:getobject") {
		t.Fatal("NotAction [iam:DeleteUser] must grant s3:GetObject")
	}
	if !n.grantsAction("iam:*") {
		t.Fatal("NotAction [iam:DeleteUser] must grant the iam:* class")
	}
	if !n.isAdmin() {
		t.Fatal("NotAction [iam:DeleteUser] must be admin")
	}
	// An exclusion covering the whole IAM class is not admin.
	doc2 := `{"Statement":[{"Effect":"Allow","NotAction":["iam:*"],"Resource":"*"}]}`
	n2 := normalizeIAMStmt(policyStatements(doc2)[0])
	if n2 == nil || n2.isAdmin() {
		t.Fatal("NotAction [iam:*] must NOT be admin")
	}
	if n2.grantsAction("iam:createpolicy") {
		t.Fatal("NotAction [iam:*] must NOT grant iam:CreatePolicy")
	}
	if !n2.grantsAction("s3:getobject") {
		t.Fatal("NotAction [iam:*] must still grant s3:GetObject")
	}
	// An exclusion covering everything grants nothing.
	doc3 := `{"Statement":[{"Effect":"Allow","NotAction":"*","Resource":"*"}]}`
	n3 := normalizeIAMStmt(policyStatements(doc3)[0])
	if n3 == nil || n3.isAdmin() || n3.grantsAction("s3:getobject") {
		t.Fatal("NotAction [*] must grant nothing")
	}
}

func TestNotResource_EvaluatorNarrowsScope(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"s3:*","NotResource":"arn:aws:s3:::secret/*"}]}`
	n := normalizeIAMStmt(policyStatements(doc)[0])
	if n == nil {
		t.Fatal("NotResource statement must normalize")
	}
	if !n.grantsOnStar() {
		t.Fatal("NotResource [secret bucket] must still grant on *")
	}
	if n.grantsResource("arn:aws:s3:::secret/obj") {
		t.Fatal("NotResource must NOT grant the excluded bucket's objects")
	}
	if !n.grantsResource("arn:aws:s3:::other/obj") {
		t.Fatal("NotResource must still grant other buckets' objects")
	}
	// Excluding the whole S3 class narrows the S3 grant to nothing.
	doc2 := `{"Statement":[{"Effect":"Allow","Action":"s3:*","NotResource":"arn:aws:s3:::*"}]}`
	n2 := normalizeIAMStmt(policyStatements(doc2)[0])
	if n2 == nil || n2.grantsOnClass(iamS3BucketARNClass) {
		t.Fatal("NotResource [arn:aws:s3:::*] must NOT grant the S3 class")
	}
	// Excluding every role ARN narrows PassRole to nothing.
	doc3 := `{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","NotResource":"arn:aws:iam::*:role/*"}]}`
	n3 := normalizeIAMStmt(policyStatements(doc3)[0])
	if n3 == nil || n3.grantsOnClass(iamRoleARNClass) {
		t.Fatal("NotResource [role/*] must NOT grant the role class")
	}
	// Excluding "*" grants nothing anywhere.
	doc4 := `{"Statement":[{"Effect":"Allow","Action":"*","NotResource":"*"}]}`
	n4 := normalizeIAMStmt(policyStatements(doc4)[0])
	if n4 == nil || n4.grantsOnStar() {
		t.Fatal("NotResource [*] must NOT grant on *")
	}
}

func TestNotAction_InvalidStatementsNormalizeToNil(t *testing.T) {
	docs := []string{
		`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","NotAction":"s3:PutObject","Resource":"*"}]}`,
		`{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*","NotResource":"arn:aws:s3:::x/*"}]}`,
		`{"Statement":[{"Effect":"Deny","NotAction":"iam:*","Resource":"*"}]}`,
	}
	for i, doc := range docs {
		if n := normalizeIAMStmt(policyStatements(doc)[0]); n != nil {
			t.Fatalf("case %d: invalid statement must normalize to nil", i)
		}
	}
}

// --- Admin wildcard: 006 / 102 / 333 --------------------------------------

func TestNotAction_AdminWildcardFires(t *testing.T) {
	// The task's headline case: NotAction excluding one harmless action
	// is a near-admin grant and must fire, with the exclusion in evidence.
	for _, rule := range []ir.Rule{iamAdminPolicy{}, iamAdminManagedPolicy{}} {
		f := runRule(rule, naPolicyRes(`{"Effect":"Allow","NotAction":"iam:DeleteUser","Resource":"*"}`))
		if len(f) != 1 {
			t.Fatalf("%s: expected 1 finding on NotAction [iam:DeleteUser], got %d", rule.ID(), len(f))
		}
		if !strings.Contains(f[0].Evidence.Actual, "NotAction excludes [iam:deleteuser]") {
			t.Fatalf("%s: evidence must name the exclusion, got %q", rule.ID(), f[0].Evidence.Actual)
		}
	}
	// Inline admin (333) sees the same grant.
	f := runRule(inlineAdminPolicyRule{}, naRolePolicyRes(`{"Effect":"Allow","NotAction":"iam:DeleteUser","Resource":"*"}`))
	if len(f) != 1 {
		t.Fatalf("333: expected 1 finding on NotAction [iam:DeleteUser], got %d", len(f))
	}
}

func TestNotAction_AdminWildcardSilent(t *testing.T) {
	cases := []string{
		`{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}`,
		`{"Effect":"Allow","NotAction":"*","Resource":"*"}`,
		`{"Effect":"Allow","Action":"*","NotResource":"*"}`,
	}
	for i, stmt := range cases {
		for _, rule := range []ir.Rule{iamAdminPolicy{}, iamAdminManagedPolicy{}} {
			if f := runRule(rule, naPolicyRes(stmt)); len(f) != 0 {
				t.Fatalf("case %d: %s must stay quiet, got %+v", i, rule.ID(), f)
			}
		}
	}
}

func TestNotResource_AdminWildcardFiresWithNote(t *testing.T) {
	// Action "*" with a NotResource that excludes one bucket is still
	// admin on everything else; the finding must carve the bucket out.
	f := runRule(iamAdminPolicy{}, naPolicyRes(`{"Effect":"Allow","Action":"*","NotResource":"arn:aws:s3:::secret/*"}`))
	if len(f) != 1 {
		t.Fatalf("006: expected 1 finding, got %d", len(f))
	}
	if !strings.Contains(f[0].Evidence.Actual, "NotResource excludes [arn:aws:s3:::secret/*]") {
		t.Fatalf("006: evidence must name the excluded bucket, got %q", f[0].Evidence.Actual)
	}
}

// --- Open trust: 101 -------------------------------------------------------

func TestNotAction_OpenTrust(t *testing.T) {
	// NotAction excluding an unrelated action still lets anyone assume.
	out := (iamRoleOpenTrust{}).CheckAll([]ir.Resource{
		naRoleTrustRes(`{"Effect":"Allow","Principal":"*","NotAction":"sts:TagSession"}`),
	})
	if len(out) != 1 {
		t.Fatalf("101: expected 1 finding on NotAction [sts:TagSession], got %d", len(out))
	}
	if !strings.Contains(out[0].Evidence.Actual, "NotAction excludes [sts:tagsession]") {
		t.Fatalf("101: evidence must name the exclusion, got %q", out[0].Evidence.Actual)
	}
	// NotAction excluding AssumeRole itself: no open trust.
	for _, stmt := range []string{
		`{"Effect":"Allow","Principal":"*","NotAction":"sts:AssumeRole"}`,
		`{"Effect":"Allow","Principal":"*","NotAction":"*"}`,
	} {
		out := (iamRoleOpenTrust{}).CheckAll([]ir.Resource{naRoleTrustRes(stmt)})
		if len(out) != 0 {
			t.Fatalf("101: expected 0 findings on %s, got %+v", stmt, out)
		}
	}
}

// --- MFA: 859 ---------------------------------------------------------------

func TestNotAction_MFA859(t *testing.T) {
	// Near-admin grant via NotAction without MFA: fires.
	f := runRule(iamAdminAccessNoMFA{}, naPolicyRes(`{"Effect":"Allow","NotAction":"iam:DeleteUser","Resource":"*"}`))
	if len(f) != 1 {
		t.Fatalf("859: expected 1 finding on NotAction [iam:DeleteUser], got %d", len(f))
	}
	// Exclusions that remove the admin grant: quiet.
	for _, stmt := range []string{
		`{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}`,
		`{"Effect":"Allow","Action":"*","NotResource":"*"}`,
	} {
		if f := runRule(iamAdminAccessNoMFA{}, naPolicyRes(stmt)); len(f) != 0 {
			t.Fatalf("859: expected 0 findings on %s, got %+v", stmt, f)
		}
	}
	// Action "*" with a NotResource excluding one bucket: still admin,
	// still no MFA: fires with the exclusion noted.
	f = runRule(iamAdminAccessNoMFA{}, naPolicyRes(`{"Effect":"Allow","Action":"*","NotResource":"arn:aws:s3:::secret/*"}`))
	if len(f) != 1 || !strings.Contains(f[0].Evidence.Actual, "NotResource excludes [arn:aws:s3:::secret/*]") {
		t.Fatalf("859: expected 1 noted finding, got %+v", f)
	}
	// Trust branch: NotAction excluding TagSession still opens AssumeRole.
	f = runRule(iamAdminAccessNoMFA{}, naRoleTrustRes(`{"Effect":"Allow","Principal":"*","NotAction":"sts:TagSession"}`))
	if len(f) != 1 {
		t.Fatalf("859 trust: expected 1 finding on NotAction [sts:TagSession], got %d", len(f))
	}
	// Trust branch: NotAction excluding AssumeRole: quiet.
	f = runRule(iamAdminAccessNoMFA{}, naRoleTrustRes(`{"Effect":"Allow","Principal":"*","NotAction":"sts:AssumeRole"}`))
	if len(f) != 0 {
		t.Fatalf("859 trust: expected 0 findings on NotAction [sts:AssumeRole], got %+v", f)
	}
}

// --- Privilege escalation: 501 / 502 / 503 / 504 / 505 ----------------------

func TestNotAction_Privesc501_AdversarialHarmlessExclusion(t *testing.T) {
	// Adversarial: the exclusion removes only s3:GetObject — a harmless
	// action — while the statement still grants policy authoring AND
	// attachment. 501 must fire.
	p := naPolicyRes(`{"Effect":"Allow","NotAction":"s3:GetObject","Resource":"*"}`)
	f := runRule(iamPrivilegeEscalation{}, p)
	if len(f) != 1 {
		t.Fatalf("501: expected 1 finding, got %d", len(f))
	}
	if !strings.Contains(f[0].Evidence.Actual, "NotAction excludes [s3:getobject]") {
		t.Fatalf("501: evidence must name the exclusion, got %q", f[0].Evidence.Actual)
	}
	// Excluding one authoring action still leaves PutRolePolicy + Attach.
	p = naPolicyRes(`{"Effect":"Allow","NotAction":"iam:CreatePolicy","Resource":"*"}`)
	if f := runRule(iamPrivilegeEscalation{}, p); len(f) != 1 {
		t.Fatalf("501: expected 1 finding with CreatePolicy excluded, got %d", len(f))
	}
	// Excluding every authoring action: quiet.
	p = naPolicyRes(`{"Effect":"Allow","NotAction":["iam:CreatePolicy","iam:PutRolePolicy","iam:PutUserPolicy","iam:PutGroupPolicy","iam:CreatePolicyVersion"],"Resource":"*"}`)
	if f := runRule(iamPrivilegeEscalation{}, p); len(f) != 0 {
		t.Fatalf("501: expected 0 findings with all authoring excluded, got %+v", f)
	}
}

func TestNotAction_PassRole502(t *testing.T) {
	// One NotAction statement grants both PassRole and the primitive.
	p := naPolicyRes(`{"Effect":"Allow","NotAction":"s3:GetObject","Resource":"*"}`)
	if f := runRule(iamPassRoleEscalation{}, p); len(f) != 1 {
		t.Fatalf("502: expected 1 finding, got %d", len(f))
	}
	// NotAction excluding PassRole itself: quiet.
	p = naPolicyRes(`{"Effect":"Allow","NotAction":"iam:PassRole","Resource":"*"}`)
	if f := runRule(iamPassRoleEscalation{}, p); len(f) != 0 {
		t.Fatalf("502: expected 0 findings with PassRole excluded, got %+v", f)
	}
	// NotResource excluding every role ARN: PassRole is granted nowhere
	// that matters — quiet.
	p = res("aws_iam_policy", "p", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":["iam:PassRole","ec2:RunInstances"],"NotResource":"arn:aws:iam::*:role/*"}]}`, 3),
	})
	if f := runRule(iamPassRoleEscalation{}, p); len(f) != 0 {
		t.Fatalf("502: expected 0 findings with all roles excluded, got %+v", f)
	}
	// Adversarial: NotResource excluding only the sensitive bucket leaves
	// PassRole on roles untouched — still fires, with the exclusion noted.
	p = res("aws_iam_policy", "p", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":["iam:PassRole","ec2:RunInstances"],"NotResource":"arn:aws:s3:::secret/*"}]}`, 3),
	})
	f := runRule(iamPassRoleEscalation{}, p)
	if len(f) != 1 {
		t.Fatalf("502: expected 1 finding with only a bucket excluded, got %d", len(f))
	}
	if !strings.Contains(f[0].Evidence.Actual, "NotResource excludes [arn:aws:s3:::secret/*]") {
		t.Fatalf("502: evidence must name the excluded bucket, got %q", f[0].Evidence.Actual)
	}
}

func TestNotResource_Exfiltration503(t *testing.T) {
	// s3 pair granted via NotAction: fires.
	p := naPolicyRes(`{"Effect":"Allow","NotAction":"iam:GetUser","Resource":"*"}`)
	if f := runRule(iamDataExfiltration{}, p); len(f) != 1 {
		t.Fatalf("503: expected 1 finding, got %d", len(f))
	}
	// NotResource excluding the whole S3 class: the pair is granted on no
	// bucket — quiet.
	p = res("aws_iam_policy", "p", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"NotResource":"arn:aws:s3:::*"}]}`, 3),
	})
	if f := runRule(iamDataExfiltration{}, p); len(f) != 0 {
		t.Fatalf("503: expected 0 findings with all buckets excluded, got %+v", f)
	}
	// NotResource excluding only the sensitive bucket: other buckets are
	// still exposed — fires, with the exclusion noted (narrowed claim).
	p = res("aws_iam_policy", "p", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"NotResource":"arn:aws:s3:::secret/*"}]}`, 3),
	})
	f := runRule(iamDataExfiltration{}, p)
	if len(f) != 1 {
		t.Fatalf("503: expected 1 finding with only one bucket excluded, got %d", len(f))
	}
	if !strings.Contains(f[0].Evidence.Actual, "NotResource excludes [arn:aws:s3:::secret/*]") {
		t.Fatalf("503: evidence must name the excluded bucket, got %q", f[0].Evidence.Actual)
	}
}

func TestNotAction_Mgmt504AndWrite505(t *testing.T) {
	// NotAction ["iam:Get*"] still grants IAM writes and s3 writes.
	p := naPolicyRes(`{"Effect":"Allow","NotAction":"iam:Get*","Resource":"*"}`)
	if f := runRule(iamPermissionsMgmt{}, p); len(f) != 1 {
		t.Fatalf("504: expected 1 finding, got %d", len(f))
	}
	if f := runRule(iamWriteNoConstraints{}, p); len(f) != 1 {
		t.Fatalf("505: expected 1 finding, got %d", len(f))
	}
	// NotAction ["iam:*"] grants no IAM action: 504 quiet, 505 still
	// fires (s3/ec2 writes are granted).
	p = naPolicyRes(`{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}`)
	if f := runRule(iamPermissionsMgmt{}, p); len(f) != 0 {
		t.Fatalf("504: expected 0 findings with IAM excluded, got %+v", f)
	}
	if f := runRule(iamWriteNoConstraints{}, p); len(f) != 1 {
		t.Fatalf("505: expected 1 finding with only IAM excluded, got %d", len(f))
	}
	// NotAction ["*"] grants nothing: both quiet.
	p = naPolicyRes(`{"Effect":"Allow","NotAction":"*","Resource":"*"}`)
	for _, rule := range []ir.Rule{iamPermissionsMgmt{}, iamWriteNoConstraints{}} {
		if f := runRule(rule, p); len(f) != 0 {
			t.Fatalf("%s: expected 0 findings on NotAction [*], got %d", rule.ID(), len(f))
		}
	}
}

// --- Deep rules: 660 / 661 / 670 / 676 --------------------------------------

func TestNotAction_SensitiveWildcard660(t *testing.T) {
	// NotAction ["iam:*"] grants kms:* and sts:* in full: 660 fires.
	// (It is not 102's territory: no iam:* is granted.)
	f := runRule(iamPolicySensitiveWildcard{}, naPolicyRes(`{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}`))
	if len(f) != 1 {
		t.Fatalf("660: expected 1 finding on NotAction [iam:*], got %d", len(f))
	}
	// NotAction ["*"] grants nothing: quiet.
	f = runRule(iamPolicySensitiveWildcard{}, naPolicyRes(`{"Effect":"Allow","NotAction":"*","Resource":"*"}`))
	if len(f) != 0 {
		t.Fatalf("660: expected 0 findings on NotAction [*], got %+v", f)
	}
	// kms:* with a NotResource excluding one bucket: still fires, noted.
	f = runRule(iamPolicySensitiveWildcard{}, naPolicyRes(`{"Effect":"Allow","Action":"kms:*","NotResource":"arn:aws:s3:::secret/*"}`))
	if len(f) != 1 || !strings.Contains(f[0].Evidence.Actual, "NotResource excludes [arn:aws:s3:::secret/*]") {
		t.Fatalf("660: expected 1 noted finding, got %+v", f)
	}
	// kms:* with NotResource ["*"]: quiet.
	f = runRule(iamPolicySensitiveWildcard{}, naPolicyRes(`{"Effect":"Allow","Action":"kms:*","NotResource":"*"}`))
	if len(f) != 0 {
		t.Fatalf("660: expected 0 findings on NotResource [*], got %+v", f)
	}
}

func TestNotAction_PassRoleStar661(t *testing.T) {
	// NotAction excluding only a harmless action grants PassRole on *.
	f := runRule(iamPolicyPassRoleStar{}, naPolicyRes(`{"Effect":"Allow","NotAction":"s3:GetObject","Resource":"*"}`))
	if len(f) != 1 {
		t.Fatalf("661: expected 1 finding, got %d", len(f))
	}
	// NotAction excluding PassRole: quiet.
	f = runRule(iamPolicyPassRoleStar{}, naPolicyRes(`{"Effect":"Allow","NotAction":"iam:PassRole","Resource":"*"}`))
	if len(f) != 0 {
		t.Fatalf("661: expected 0 findings with PassRole excluded, got %+v", f)
	}
	// NotResource excluding every role ARN: quiet.
	p := res("aws_iam_policy", "p", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","NotResource":"arn:aws:iam::*:role/*"}]}`, 3),
	})
	if f := runRule(iamPolicyPassRoleStar{}, p); len(f) != 0 {
		t.Fatalf("661: expected 0 findings with all roles excluded, got %+v", f)
	}
	// NotResource excluding only a bucket: still fires, noted.
	p = res("aws_iam_policy", "p", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","NotResource":"arn:aws:s3:::secret/*"}]}`, 3),
	})
	f = runRule(iamPolicyPassRoleStar{}, p)
	if len(f) != 1 || !strings.Contains(f[0].Evidence.Actual, "NotResource excludes [arn:aws:s3:::secret/*]") {
		t.Fatalf("661: expected 1 noted finding, got %+v", f)
	}
}

func TestNotAction_IamStarScoped670(t *testing.T) {
	// NotAction excluding one action still grants iam:* on the scoped
	// resource: 670 fires.
	f := runRule(iamPolicyIamStarScoped{}, naPolicyRes(`{"Effect":"Allow","NotAction":"iam:DeleteUser","Resource":"arn:aws:iam::123:role/app"}`))
	if len(f) != 1 {
		t.Fatalf("670: expected 1 finding, got %d", len(f))
	}
	// NotAction excluding all of iam:*: quiet.
	f = runRule(iamPolicyIamStarScoped{}, naPolicyRes(`{"Effect":"Allow","NotAction":"iam:*","Resource":"arn:aws:iam::123:role/app"}`))
	if len(f) != 0 {
		t.Fatalf("670: expected 0 findings with iam:* excluded, got %+v", f)
	}
	// Action iam:* with NotResource is a near-"*" grant: 102's territory,
	// not 670's.
	f = runRule(iamPolicyIamStarScoped{}, naPolicyRes(`{"Effect":"Allow","Action":"iam:*","NotResource":"arn:aws:iam::123:role/app"}`))
	if len(f) != 0 {
		t.Fatalf("670: expected 0 findings on NotResource (102 territory), got %+v", f)
	}
}

func TestNotAction_TagSession676(t *testing.T) {
	// Trust policy granting everything except an unrelated action grants
	// sts:TagSession: 676 fires.
	f := runRule(iamRoleTagSessionOpen{}, naRoleTrustRes(`{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"NotAction":"s3:GetObject"}`))
	if len(f) != 1 {
		t.Fatalf("676: expected 1 finding, got %d", len(f))
	}
	// NotAction excluding TagSession itself: quiet.
	f = runRule(iamRoleTagSessionOpen{}, naRoleTrustRes(`{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"NotAction":"sts:TagSession"}`))
	if len(f) != 0 {
		t.Fatalf("676: expected 0 findings with TagSession excluded, got %+v", f)
	}
}

// --- Attack path: 104 ---------------------------------------------------------

func TestNotAction_PublicRead104(t *testing.T) {
	// Bucket policy granting everything except DeleteObject to everyone
	// grants s3:GetObject: the exfiltration path fires.
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","NotAction":"s3:DeleteObject","Resource":"arn:aws:s3:::assets/*"}]}`
	if !policyGrantsPublicRead(doc) {
		t.Fatal("104: NotAction [s3:DeleteObject] must count as a public-read grant")
	}
	// NotAction excluding GetObject itself: no grant.
	doc = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","NotAction":"s3:GetObject","Resource":"arn:aws:s3:::assets/*"}]}`
	if policyGrantsPublicRead(doc) {
		t.Fatal("104: NotAction [s3:GetObject] must NOT count as a public-read grant")
	}
	// End-to-end: NotResource excluding this bucket's objects silences
	// the path for that bucket.
	b := bucketFixture("assets")
	excluded := bucketPolicyFixture("pol", "aws_s3_bucket.assets.id",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","NotResource":"arn:aws:s3:::assets/*"}]}`, 10)
	if out := (s3ExfiltrationPath{}).CheckAll([]ir.Resource{b, excluded}); len(out) != 0 {
		t.Fatalf("104: expected 0 findings with this bucket excluded, got %+v", out)
	}
	// NotResource excluding a different bucket leaves this bucket exposed.
	other := bucketPolicyFixture("pol", "aws_s3_bucket.assets.id",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","NotResource":"arn:aws:s3:::other/*"}]}`, 10)
	if out := (s3ExfiltrationPath{}).CheckAll([]ir.Resource{b, other}); len(out) != 1 {
		t.Fatalf("104: expected 1 finding with another bucket excluded, got %d", len(out))
	}
	// NotResource excluding only the bare bucket ARN does not exclude
	// object reads: still fires.
	bare := bucketPolicyFixture("pol", "aws_s3_bucket.assets.id",
		`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","NotResource":"arn:aws:s3:::assets"}]}`, 10)
	if out := (s3ExfiltrationPath{}).CheckAll([]ir.Resource{b, bare}); len(out) != 1 {
		t.Fatalf("104: expected 1 finding with only the bare bucket ARN excluded, got %d", len(out))
	}
}

// --- Pattern flags are unchanged: 553 / 671 ----------------------------------

func TestNotAction_PatternFlagsUnchanged(t *testing.T) {
	// 553 still flags the NotAction+Allow construct itself, 671 still
	// flags NotResource+Allow — neither rule's trigger changed.
	f := runRule(iamPolicyNotActionAllow{}, naPolicyRes(`{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}`))
	if len(f) != 1 {
		t.Fatalf("553: expected 1 finding, got %d", len(f))
	}
	f = runRule(iamPolicyNotResourceAllow{}, naPolicyRes(`{"Effect":"Allow","Action":"s3:*","NotResource":"arn:aws:s3:::secret/*"}`))
	if len(f) != 1 {
		t.Fatalf("671: expected 1 finding, got %d", len(f))
	}
}

// --- Regression: ordinary statements are unchanged ----------------------------

func TestNotAction_OrdinaryStatementsUnchanged(t *testing.T) {
	// Least-privilege statements stay quiet everywhere.
	quiet := naPolicyRes(`{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::app/*"}`)
	for _, rule := range []ir.Rule{
		iamAdminPolicy{}, iamAdminManagedPolicy{}, inlineAdminPolicyRule{},
		iamPrivilegeEscalation{}, iamPassRoleEscalation{}, iamDataExfiltration{},
		iamPermissionsMgmt{}, iamWriteNoConstraints{}, iamPolicySensitiveWildcard{},
		iamPolicyPassRoleStar{}, iamPolicyIamStarScoped{}, iamAdminAccessNoMFA{},
	} {
		if f := runRule(rule, quiet); len(f) != 0 {
			t.Fatalf("%s: least-privilege must stay quiet, got %d", rule.ID(), len(f))
		}
	}
	// Explicit admin still fires on 006/102 only (no new duplicates).
	admin := naPolicyRes(`{"Effect":"Allow","Action":"*","Resource":"*"}`)
	for _, rule := range []ir.Rule{iamAdminPolicy{}, iamAdminManagedPolicy{}} {
		if f := runRule(rule, admin); len(f) != 1 {
			t.Fatalf("%s: explicit admin must fire exactly once, got %d", rule.ID(), len(f))
		}
	}
	if f := runRule(iamPolicySensitiveWildcard{}, admin); len(f) != 0 {
		t.Fatalf("660: explicit admin must stay 102's territory, got %d", len(f))
	}
	if f := runRule(iamPolicyIamStarScoped{}, admin); len(f) != 0 {
		t.Fatalf("670: explicit admin must stay 102's territory, got %d", len(f))
	}
	// Scoped PassRole stays quiet on 502/661.
	scoped := res("aws_iam_policy", "p", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::123456789012:role/app"},{"Effect":"Allow","Action":"ec2:RunInstances","Resource":"*"}]}`, 3),
	})
	if f := runRule(iamPassRoleEscalation{}, scoped); len(f) != 0 {
		t.Fatalf("502: single-role PassRole must stay quiet, got %d", len(f))
	}
	if f := runRule(iamPolicyPassRoleStar{}, res("aws_iam_policy", "p", map[string]ir.Value{
		"policy": ks(`{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::123:role/app"}]}`, 3),
	})); len(f) != 0 {
		t.Fatalf("661: single-role PassRole must stay quiet, got %d", len(f))
	}
}

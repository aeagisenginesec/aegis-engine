package aws

import (
	"testing"

	"aegis/internal/ir"
)

// kn is defined in coverage2_test.go (known float64 numeric value).

// ---------------------------------------------------------------------------
// 650: password minimum length
// ---------------------------------------------------------------------------

func Test650_ShortPasswordFires(t *testing.T) {
	r := res("aws_iam_account_password_policy", "p", map[string]ir.Value{
		"minimum_password_length": kn(8, 4),
	})
	if got := runRule(iamPasswordMinLength{}, r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
}

func Test650_GoodPasswordQuiet(t *testing.T) {
	r := res("aws_iam_account_password_policy", "p", map[string]ir.Value{
		"minimum_password_length": kn(14, 4),
	})
	if got := runRule(iamPasswordMinLength{}, r); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
}

func Test650_AbsentFiresUnknownQuiet(t *testing.T) {
	absent := res("aws_iam_account_password_policy", "p", map[string]ir.Value{})
	if got := runRule(iamPasswordMinLength{}, absent); len(got) != 1 {
		t.Fatalf("absent: expected 1 finding, got %d", len(got))
	}
	unknown := res("aws_iam_account_password_policy", "p", map[string]ir.Value{
		"minimum_password_length": ku(4),
	})
	if got := runRule(iamPasswordMinLength{}, unknown); len(got) != 0 {
		t.Fatalf("unknown: expected 0 findings, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// 651-654: character-class requirements
// ---------------------------------------------------------------------------

func Test651_NoUppercaseFires(t *testing.T) {
	for name, rule := range map[string]ir.Rule{
		"require_uppercase_characters": iamPasswordNoUppercase{},
		"require_lowercase_characters": iamPasswordNoLowercase{},
		"require_numbers":              iamPasswordNoNumbers{},
		"require_symbols":              iamPasswordNoSymbols{},
	} {
		r := res("aws_iam_account_password_policy", "p", map[string]ir.Value{name: kv(false, 4)})
		if got := runRule(rule, r); len(got) != 1 {
			t.Fatalf("%s=false: expected 1 finding, got %d", name, len(got))
		}
		ok := res("aws_iam_account_password_policy", "p", map[string]ir.Value{name: kv(true, 4)})
		if got := runRule(rule, ok); len(got) != 0 {
			t.Fatalf("%s=true: expected 0 findings, got %d", name, len(got))
		}
		absent := res("aws_iam_account_password_policy", "p", map[string]ir.Value{})
		if got := runRule(rule, absent); len(got) != 1 {
			t.Fatalf("%s absent: expected 1 finding, got %d", name, len(got))
		}
		unk := res("aws_iam_account_password_policy", "p", map[string]ir.Value{name: ku(4)})
		if got := runRule(rule, unk); len(got) != 0 {
			t.Fatalf("%s unknown: expected 0 findings, got %d", name, len(got))
		}
	}
}

// ---------------------------------------------------------------------------
// 655: password reuse prevention
// ---------------------------------------------------------------------------

func Test655_WeakReuseFires(t *testing.T) {
	r := res("aws_iam_account_password_policy", "p", map[string]ir.Value{
		"password_reuse_prevention": kn(0, 4),
	})
	if got := runRule(iamPasswordReuseAllowed{}, r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
}

func Test655_StrongReuseQuiet(t *testing.T) {
	r := res("aws_iam_account_password_policy", "p", map[string]ir.Value{
		"password_reuse_prevention": kn(24, 4),
	})
	if got := runRule(iamPasswordReuseAllowed{}, r); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
}

func Test655_ExplicitPositiveQuiet(t *testing.T) {
	// Any explicit positive value is a conscious choice; only absent or 0 fires.
	for _, n := range []float64{1, 5, 12} {
		r := res("aws_iam_account_password_policy", "p", map[string]ir.Value{
			"password_reuse_prevention": kn(n, 4),
		})
		if got := runRule(iamPasswordReuseAllowed{}, r); len(got) != 0 {
			t.Fatalf("n=%v: expected 0 findings, got %d", n, len(got))
		}
	}
}

func Test655_AbsentFiresUnknownQuiet(t *testing.T) {
	absent := res("aws_iam_account_password_policy", "p", map[string]ir.Value{})
	if got := runRule(iamPasswordReuseAllowed{}, absent); len(got) != 1 {
		t.Fatalf("absent: expected 1 finding, got %d", len(got))
	}
	unk := res("aws_iam_account_password_policy", "p", map[string]ir.Value{
		"password_reuse_prevention": ku(4),
	})
	if got := runRule(iamPasswordReuseAllowed{}, unk); len(got) != 0 {
		t.Fatalf("unknown: expected 0 findings, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// 656: max password age
// ---------------------------------------------------------------------------

func Test656_NeverExpiresFires(t *testing.T) {
	r := res("aws_iam_account_password_policy", "p", map[string]ir.Value{
		"max_password_age": kn(0, 4),
	})
	if got := runRule(iamPasswordMaxAgeWeak{}, r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
}

func Test656_LongAgeFires(t *testing.T) {
	r := res("aws_iam_account_password_policy", "p", map[string]ir.Value{
		"max_password_age": kn(120, 4),
	})
	if got := runRule(iamPasswordMaxAgeWeak{}, r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
}

func Test656_GoodAgeQuiet(t *testing.T) {
	r := res("aws_iam_account_password_policy", "p", map[string]ir.Value{
		"max_password_age": kn(60, 4),
	})
	if got := runRule(iamPasswordMaxAgeWeak{}, r); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
	unk := res("aws_iam_account_password_policy", "p", map[string]ir.Value{
		"max_password_age": ku(4),
	})
	if got := runRule(iamPasswordMaxAgeWeak{}, unk); len(got) != 0 {
		t.Fatalf("unknown: expected 0 findings, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// 657-659: inline policies
// ---------------------------------------------------------------------------

func Test657_GroupInlinePolicyFires(t *testing.T) {
	r := res("aws_iam_group_policy", "g", map[string]ir.Value{
		"policy": ks("{}", 4),
	})
	if got := runRule(iamGroupInlinePolicy{}, r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	other := res("aws_iam_policy", "p", map[string]ir.Value{})
	if got := runRule(iamGroupInlinePolicy{}, other); len(got) != 0 {
		t.Fatalf("wrong type: expected 0 findings, got %d", len(got))
	}
}

func Test658_RoleInlinePolicyFires(t *testing.T) {
	r := res("aws_iam_role_policy", "g", map[string]ir.Value{
		"policy": ks("{}", 4),
	})
	if got := runRule(iamRoleInlinePolicy{}, r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	other := res("aws_iam_policy", "p", map[string]ir.Value{})
	if got := runRule(iamRoleInlinePolicy{}, other); len(got) != 0 {
		t.Fatalf("wrong type: expected 0 findings, got %d", len(got))
	}
}

func Test659_UserInlinePolicyFires(t *testing.T) {
	r := res("aws_iam_user_policy", "g", map[string]ir.Value{
		"policy": ks("{}", 4),
	})
	if got := runRule(iamUserInlinePolicy{}, r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	other := res("aws_iam_policy", "p", map[string]ir.Value{})
	if got := runRule(iamUserInlinePolicy{}, other); len(got) != 0 {
		t.Fatalf("wrong type: expected 0 findings, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// 660: sensitive service wildcard on "*"
// ---------------------------------------------------------------------------

func Test660_KmsStarFires(t *testing.T) {
	doc := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kms:*","Resource":"*"}]}`
	r := res("aws_iam_policy", "p", map[string]ir.Value{"policy": ks(doc, 4)})
	if got := runRule(iamPolicySensitiveWildcard{}, r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
}

func Test660_ScopedResourceQuiet(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"kms:*","Resource":"arn:aws:kms:us-east-1:123:key/abc"}]}`
	r := res("aws_iam_policy", "p", map[string]ir.Value{"policy": ks(doc, 4)})
	if got := runRule(iamPolicySensitiveWildcard{}, r); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
}

func Test660_AdminOverlapSkipped(t *testing.T) {
	// Action "iam:*" on "*" is AEGIS-AWS-102's territory: no duplicate here.
	doc := `{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}`
	r := res("aws_iam_policy", "p", map[string]ir.Value{"policy": ks(doc, 4)})
	if got := runRule(iamPolicySensitiveWildcard{}, r); len(got) != 0 {
		t.Fatalf("expected 0 findings (102 overlap), got %d", len(got))
	}
	unk := res("aws_iam_policy", "p", map[string]ir.Value{"policy": ku(4)})
	if got := runRule(iamPolicySensitiveWildcard{}, unk); len(got) != 0 {
		t.Fatalf("unknown: expected 0 findings, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// 661: iam:PassRole on "*"
// ---------------------------------------------------------------------------

func Test661_PassRoleStarFires(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":["iam:PassRole"],"Resource":"*"}]}`
	r := res("aws_iam_policy", "p", map[string]ir.Value{"policy": ks(doc, 4)})
	if got := runRule(iamPolicyPassRoleStar{}, r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
}

func Test661_ScopedPassRoleQuiet(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"arn:aws:iam::123:role/app"}]}`
	r := res("aws_iam_policy", "p", map[string]ir.Value{"policy": ks(doc, 4)})
	if got := runRule(iamPolicyPassRoleStar{}, r); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
	unk := res("aws_iam_policy", "p", map[string]ir.Value{"policy": ku(4)})
	if got := runRule(iamPolicyPassRoleStar{}, unk); len(got) != 0 {
		t.Fatalf("unknown: expected 0 findings, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// 662: account alias missing (cross-resource)
// ---------------------------------------------------------------------------

func Test662_MissingAliasFires(t *testing.T) {
	pol := res("aws_iam_account_password_policy", "p", map[string]ir.Value{})
	if got := (iamAccountAliasMissing{}).CheckAll([]ir.Resource{pol}); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
}

func Test662_AliasPresentQuiet(t *testing.T) {
	pol := res("aws_iam_account_password_policy", "p", map[string]ir.Value{})
	alias := res("aws_iam_account_alias", "a", map[string]ir.Value{"account_alias": ks("myco", 3)})
	if got := (iamAccountAliasMissing{}).CheckAll([]ir.Resource{pol, alias}); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
}

func Test662_NoAnchorQuiet(t *testing.T) {
	other := res("aws_iam_user", "u", map[string]ir.Value{})
	if got := (iamAccountAliasMissing{}).CheckAll([]ir.Resource{other}); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// 663: max_password_age absent
// ---------------------------------------------------------------------------

func Test663_AbsentFires(t *testing.T) {
	r := res("aws_iam_account_password_policy", "p", map[string]ir.Value{})
	if got := runRule(iamPasswordExpiryAbsent{}, r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
}

func Test663_PresentQuiet(t *testing.T) {
	r := res("aws_iam_account_password_policy", "p", map[string]ir.Value{
		"max_password_age": kn(90, 4),
	})
	if got := runRule(iamPasswordExpiryAbsent{}, r); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// 664: force_destroy on user
// ---------------------------------------------------------------------------

func Test664_ForceDestroyFires(t *testing.T) {
	r := res("aws_iam_user", "u", map[string]ir.Value{"force_destroy": kv(true, 4)})
	if got := runRule(iamUserForceDestroy{}, r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
}

func Test664_DefaultQuiet(t *testing.T) {
	off := res("aws_iam_user", "u", map[string]ir.Value{"force_destroy": kv(false, 4)})
	if got := runRule(iamUserForceDestroy{}, off); len(got) != 0 {
		t.Fatalf("false: expected 0 findings, got %d", len(got))
	}
	absent := res("aws_iam_user", "u", map[string]ir.Value{})
	if got := runRule(iamUserForceDestroy{}, absent); len(got) != 0 {
		t.Fatalf("absent: expected 0 findings, got %d", len(got))
	}
	unk := res("aws_iam_user", "u", map[string]ir.Value{"force_destroy": ku(4)})
	if got := runRule(iamUserForceDestroy{}, unk); len(got) != 0 {
		t.Fatalf("unknown: expected 0 findings, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// 665: force_detach_policies on role
// ---------------------------------------------------------------------------

func Test665_ForceDetachFires(t *testing.T) {
	r := res("aws_iam_role", "r", map[string]ir.Value{"force_detach_policies": kv(true, 4)})
	if got := runRule(iamRoleForceDetach{}, r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
}

func Test665_DefaultQuiet(t *testing.T) {
	absent := res("aws_iam_role", "r", map[string]ir.Value{})
	if got := runRule(iamRoleForceDetach{}, absent); len(got) != 0 {
		t.Fatalf("absent: expected 0 findings, got %d", len(got))
	}
	unk := res("aws_iam_role", "r", map[string]ir.Value{"force_detach_policies": ku(4)})
	if got := runRule(iamRoleForceDetach{}, unk); len(got) != 0 {
		t.Fatalf("unknown: expected 0 findings, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// 666: AdministratorAccess attachment
// ---------------------------------------------------------------------------

func Test666_AdminAccessFires(t *testing.T) {
	r := res("aws_iam_policy_attachment", "a", map[string]ir.Value{
		"policy_arn": ks("arn:aws:iam::aws:policy/AdministratorAccess", 4),
	})
	if got := runRule(iamAttachmentAdminAccess{}, r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
}

func Test666_OtherPolicyQuiet(t *testing.T) {
	r := res("aws_iam_policy_attachment", "a", map[string]ir.Value{
		"policy_arn": ks("arn:aws:iam::aws:policy/ReadOnlyAccess", 4),
	})
	if got := runRule(iamAttachmentAdminAccess{}, r); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
	unk := res("aws_iam_policy_attachment", "a", map[string]ir.Value{"policy_arn": ku(4)})
	if got := runRule(iamAttachmentAdminAccess{}, unk); len(got) != 0 {
		t.Fatalf("unknown: expected 0 findings, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// D1 regression: AdministratorAccess via every attachment vector
// ---------------------------------------------------------------------------

func Test666_ManagedPolicyArnsFires(t *testing.T) {
	for _, typ := range []string{"aws_iam_role", "aws_iam_user", "aws_iam_group"} {
		r := res(typ, "x", map[string]ir.Value{
			"managed_policy_arns": strList(4,
				"arn:aws:iam::aws:policy/ReadOnlyAccess",
				"arn:aws:iam::aws:policy/AdministratorAccess"),
		})
		if got := runRule(iamAttachmentAdminAccess{}, r); len(got) != 1 {
			t.Fatalf("%s: expected 1 finding, got %d", typ, len(got))
		}
	}
}

func Test666_AttachmentResourcesFires(t *testing.T) {
	for _, typ := range []string{
		"aws_iam_role_policy_attachment",
		"aws_iam_user_policy_attachment",
		"aws_iam_group_policy_attachment",
	} {
		r := res(typ, "x", map[string]ir.Value{
			"policy_arn": ks("arn:aws:iam::aws:policy/AdministratorAccess", 4),
		})
		if got := runRule(iamAttachmentAdminAccess{}, r); len(got) != 1 {
			t.Fatalf("%s: expected 1 finding, got %d", typ, len(got))
		}
	}
}

func Test666_ScopedManagedPoliciesQuiet(t *testing.T) {
	// D1 must not generalize: scoped policies via the same vectors stay quiet.
	r := res("aws_iam_role", "x", map[string]ir.Value{
		"managed_policy_arns": strList(4, "arn:aws:iam::aws:policy/ReadOnlyAccess"),
	})
	if got := runRule(iamAttachmentAdminAccess{}, r); len(got) != 0 {
		t.Fatalf("scoped managed policies: expected 0 findings, got %d", len(got))
	}
	r2 := res("aws_iam_role_policy_attachment", "x", map[string]ir.Value{
		"policy_arn": ks("arn:aws:iam::aws:policy/PowerUserAccess", 4),
	})
	if got := runRule(iamAttachmentAdminAccess{}, r2); len(got) != 0 {
		t.Fatalf("scoped attachment: expected 0 findings, got %d", len(got))
	}
	// Unknown list or unknown element: cannot decide, no finding.
	unk := res("aws_iam_role", "x", map[string]ir.Value{"managed_policy_arns": ku(4)})
	if got := runRule(iamAttachmentAdminAccess{}, unk); len(got) != 0 {
		t.Fatalf("unknown list: expected 0 findings, got %d", len(got))
	}
	mixed := res("aws_iam_role", "x", map[string]ir.Value{
		"managed_policy_arns": ir.Value{Raw: []ir.Value{
			{Raw: "arn:aws:iam::aws:policy/ReadOnlyAccess", Known: true, Span: spanAt(4)},
			{Known: false, Span: spanAt(5)},
		}, Known: true, Span: spanAt(4)},
	})
	if got := runRule(iamAttachmentAdminAccess{}, mixed); len(got) != 0 {
		t.Fatalf("unknown element: expected 0 findings, got %d", len(got))
	}
}

func Test666_CaseInsensitiveArn(t *testing.T) {
	r := res("aws_iam_role", "x", map[string]ir.Value{
		"managed_policy_arns": strList(4, "arn:aws:iam::123456789012:policy/administratoraccess-custom"),
	})
	if got := runRule(iamAttachmentAdminAccess{}, r); len(got) != 1 {
		t.Fatalf("case-insensitive match: expected 1 finding, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// 667: role without permissions boundary
// ---------------------------------------------------------------------------

func Test667_NoBoundaryFires(t *testing.T) {
	r := res("aws_iam_role", "r", map[string]ir.Value{})
	if got := runRule(iamRoleNoBoundary{}, r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
}

func Test667_BoundarySetQuiet(t *testing.T) {
	r := res("aws_iam_role", "r", map[string]ir.Value{
		"permissions_boundary": ks("arn:aws:iam::123:policy/boundary", 4),
	})
	if got := runRule(iamRoleNoBoundary{}, r); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
	unk := res("aws_iam_role", "r", map[string]ir.Value{"permissions_boundary": ku(4)})
	if got := runRule(iamRoleNoBoundary{}, unk); len(got) != 0 {
		t.Fatalf("unknown: expected 0 findings, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// 668: access key without pgp_key
// ---------------------------------------------------------------------------

func Test668_ActiveNoPgpFires(t *testing.T) {
	r := res("aws_iam_access_key", "k", map[string]ir.Value{
		"status": ks("Active", 3),
	})
	if got := runRule(iamAccessKeyUnencrypted{}, r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	// status absent: provider default is Active.
	def := res("aws_iam_access_key", "k", map[string]ir.Value{})
	if got := runRule(iamAccessKeyUnencrypted{}, def); len(got) != 1 {
		t.Fatalf("default status: expected 1 finding, got %d", len(got))
	}
}

func Test668_InactiveOrEncryptedQuiet(t *testing.T) {
	inactive := res("aws_iam_access_key", "k", map[string]ir.Value{
		"status": ks("Inactive", 3),
	})
	if got := runRule(iamAccessKeyUnencrypted{}, inactive); len(got) != 0 {
		t.Fatalf("inactive: expected 0 findings, got %d", len(got))
	}
	enc := res("aws_iam_access_key", "k", map[string]ir.Value{
		"status":  ks("Active", 3),
		"pgp_key": ks("keybase:someone", 4),
	})
	if got := runRule(iamAccessKeyUnencrypted{}, enc); len(got) != 0 {
		t.Fatalf("encrypted: expected 0 findings, got %d", len(got))
	}
	unk := res("aws_iam_access_key", "k", map[string]ir.Value{"status": ku(3)})
	if got := runRule(iamAccessKeyUnencrypted{}, unk); len(got) != 0 {
		t.Fatalf("unknown status: expected 0 findings, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// 669: PowerUserAccess attachment
// ---------------------------------------------------------------------------

func Test669_PowerUserFires(t *testing.T) {
	r := res("aws_iam_role_policy_attachment", "a", map[string]ir.Value{
		"policy_arn": ks("arn:aws:iam::aws:policy/PowerUserAccess", 4),
	})
	if got := runRule(iamAttachmentPowerUser{}, r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
}

func Test669_OtherPolicyQuiet(t *testing.T) {
	r := res("aws_iam_role_policy_attachment", "a", map[string]ir.Value{
		"policy_arn": ks("arn:aws:iam::aws:policy/ReadOnlyAccess", 4),
	})
	if got := runRule(iamAttachmentPowerUser{}, r); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
	unk := res("aws_iam_role_policy_attachment", "a", map[string]ir.Value{"policy_arn": ku(4)})
	if got := runRule(iamAttachmentPowerUser{}, unk); len(got) != 0 {
		t.Fatalf("unknown: expected 0 findings, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// 670: iam:* on a scoped resource
// ---------------------------------------------------------------------------

func Test670_IamStarScopedFires(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"arn:aws:iam::123:role/app"}]}`
	r := res("aws_iam_policy", "p", map[string]ir.Value{"policy": ks(doc, 4)})
	if got := runRule(iamPolicyIamStarScoped{}, r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
}

func Test670_StarResourceQuiet(t *testing.T) {
	// Resource "*": AEGIS-AWS-102's territory, no duplicate here.
	doc := `{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"*"}]}`
	r := res("aws_iam_policy", "p", map[string]ir.Value{"policy": ks(doc, 4)})
	if got := runRule(iamPolicyIamStarScoped{}, r); len(got) != 0 {
		t.Fatalf("expected 0 findings (102 overlap), got %d", len(got))
	}
	scoped := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::data/*"}]}`
	rs := res("aws_iam_policy", "p", map[string]ir.Value{"policy": ks(scoped, 4)})
	if got := runRule(iamPolicyIamStarScoped{}, rs); len(got) != 0 {
		t.Fatalf("scoped non-iam: expected 0 findings, got %d", len(got))
	}
	unk := res("aws_iam_policy", "p", map[string]ir.Value{"policy": ku(4)})
	if got := runRule(iamPolicyIamStarScoped{}, unk); len(got) != 0 {
		t.Fatalf("unknown: expected 0 findings, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// 671: NotResource + Allow
// ---------------------------------------------------------------------------

func Test671_NotResourceFires(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"s3:*","NotResource":"arn:aws:s3:::secret/*"}]}`
	r := res("aws_iam_policy", "p", map[string]ir.Value{"policy": ks(doc, 4)})
	if got := runRule(iamPolicyNotResourceAllow{}, r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
}

func Test671_NormalAllowQuiet(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::data/*"}]}`
	r := res("aws_iam_policy", "p", map[string]ir.Value{"policy": ks(doc, 4)})
	if got := runRule(iamPolicyNotResourceAllow{}, r); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
	unk := res("aws_iam_policy", "p", map[string]ir.Value{"policy": ku(4)})
	if got := runRule(iamPolicyNotResourceAllow{}, unk); len(got) != 0 {
		t.Fatalf("unknown: expected 0 findings, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// 672: untagged user
// ---------------------------------------------------------------------------

func Test672_NoTagsFires(t *testing.T) {
	absent := res("aws_iam_user", "u", map[string]ir.Value{})
	if got := runRule(iamUserUntagged{}, absent); len(got) != 1 {
		t.Fatalf("absent: expected 1 finding, got %d", len(got))
	}
	empty := res("aws_iam_user", "u", map[string]ir.Value{
		"tags": ir.Value{Raw: map[string]ir.Value{}, Known: true, Span: spanAt(4)},
	})
	if got := runRule(iamUserUntagged{}, empty); len(got) != 1 {
		t.Fatalf("empty: expected 1 finding, got %d", len(got))
	}
}

func Test672_TaggedQuiet(t *testing.T) {
	tagged := res("aws_iam_user", "u", map[string]ir.Value{
		"tags": ir.Value{Raw: map[string]ir.Value{"owner": ks("team", 5)}, Known: true, Span: spanAt(4)},
	})
	if got := runRule(iamUserUntagged{}, tagged); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
	unk := res("aws_iam_user", "u", map[string]ir.Value{"tags": ku(4)})
	if got := runRule(iamUserUntagged{}, unk); len(got) != 0 {
		t.Fatalf("unknown: expected 0 findings, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// 673: role without description
// ---------------------------------------------------------------------------

func Test673_NoDescriptionFires(t *testing.T) {
	absent := res("aws_iam_role", "r", map[string]ir.Value{})
	if got := runRule(iamRoleNoDescription{}, absent); len(got) != 1 {
		t.Fatalf("absent: expected 1 finding, got %d", len(got))
	}
	empty := res("aws_iam_role", "r", map[string]ir.Value{"description": ks("  ", 4)})
	if got := runRule(iamRoleNoDescription{}, empty); len(got) != 1 {
		t.Fatalf("empty: expected 1 finding, got %d", len(got))
	}
}

func Test673_DescribedQuiet(t *testing.T) {
	r := res("aws_iam_role", "r", map[string]ir.Value{"description": ks("CI deploy role", 4)})
	if got := runRule(iamRoleNoDescription{}, r); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
	unk := res("aws_iam_role", "r", map[string]ir.Value{"description": ku(4)})
	if got := runRule(iamRoleNoDescription{}, unk); len(got) != 0 {
		t.Fatalf("unknown: expected 0 findings, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// 674: group named admin
// ---------------------------------------------------------------------------

func Test674_AdminGroupFires(t *testing.T) {
	r := res("aws_iam_group", "g", map[string]ir.Value{"name": ks("Admin", 3)})
	if got := runRule(iamGroupNamedAdmin{}, r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
}

func Test674_NormalGroupQuiet(t *testing.T) {
	r := res("aws_iam_group", "g", map[string]ir.Value{"name": ks("developers", 3)})
	if got := runRule(iamGroupNamedAdmin{}, r); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
	unk := res("aws_iam_group", "g", map[string]ir.Value{"name": ku(3)})
	if got := runRule(iamGroupNamedAdmin{}, unk); len(got) != 0 {
		t.Fatalf("unknown: expected 0 findings, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// 675: hard_expiry off
// ---------------------------------------------------------------------------

func Test675_HardExpiryOffFires(t *testing.T) {
	r := res("aws_iam_account_password_policy", "p", map[string]ir.Value{
		"hard_expiry": kv(false, 4),
	})
	if got := runRule(iamPasswordHardExpiryOff{}, r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	absent := res("aws_iam_account_password_policy", "p", map[string]ir.Value{})
	if got := runRule(iamPasswordHardExpiryOff{}, absent); len(got) != 1 {
		t.Fatalf("absent: expected 1 finding, got %d", len(got))
	}
}

func Test675_HardExpiryOnQuiet(t *testing.T) {
	r := res("aws_iam_account_password_policy", "p", map[string]ir.Value{
		"hard_expiry": kv(true, 4),
	})
	if got := runRule(iamPasswordHardExpiryOff{}, r); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
	unk := res("aws_iam_account_password_policy", "p", map[string]ir.Value{
		"hard_expiry": ku(4),
	})
	if got := runRule(iamPasswordHardExpiryOff{}, unk); len(got) != 0 {
		t.Fatalf("unknown: expected 0 findings, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// 676: sts:TagSession without condition
// ---------------------------------------------------------------------------

func Test676_TagSessionOpenFires(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:TagSession"}]}`
	r := res("aws_iam_role", "r", map[string]ir.Value{"assume_role_policy": ks(doc, 4)})
	if got := runRule(iamRoleTagSessionOpen{}, r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
}

func Test676_ConditionedQuiet(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Action":"sts:TagSession","Condition":{"StringEquals":{"aws:RequestTag/team":"a"}}}]}`
	r := res("aws_iam_role", "r", map[string]ir.Value{"assume_role_policy": ks(doc, 4)})
	if got := runRule(iamRoleTagSessionOpen{}, r); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
	unk := res("aws_iam_role", "r", map[string]ir.Value{"assume_role_policy": ku(4)})
	if got := runRule(iamRoleTagSessionOpen{}, unk); len(got) != 0 {
		t.Fatalf("unknown: expected 0 findings, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// 677: statement without Sid
// ---------------------------------------------------------------------------

func Test677_MissingSidFires(t *testing.T) {
	doc := `{"Statement":[{"Sid":"ReadOnly","Effect":"Allow","Action":"s3:GetObject","Resource":"*"},{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"}]}`
	r := res("aws_iam_policy", "p", map[string]ir.Value{"policy": ks(doc, 4)})
	if got := runRule(iamPolicyStatementNoSid{}, r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
}

func Test677_AllSidQuiet(t *testing.T) {
	doc := `{"Statement":[{"Sid":"ReadOnly","Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`
	r := res("aws_iam_policy", "p", map[string]ir.Value{"policy": ks(doc, 4)})
	if got := runRule(iamPolicyStatementNoSid{}, r); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
	unk := res("aws_iam_policy", "p", map[string]ir.Value{"policy": ku(4)})
	if got := runRule(iamPolicyStatementNoSid{}, unk); len(got) != 0 {
		t.Fatalf("unknown: expected 0 findings, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// 678: login profile without forced reset
// ---------------------------------------------------------------------------

func Test678_NoResetFires(t *testing.T) {
	r := res("aws_iam_user_login_profile", "l", map[string]ir.Value{
		"password_reset_required": kv(false, 4),
	})
	if got := runRule(iamLoginProfileNoReset{}, r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	absent := res("aws_iam_user_login_profile", "l", map[string]ir.Value{})
	if got := runRule(iamLoginProfileNoReset{}, absent); len(got) != 1 {
		t.Fatalf("absent: expected 1 finding, got %d", len(got))
	}
}

func Test678_ResetRequiredQuiet(t *testing.T) {
	r := res("aws_iam_user_login_profile", "l", map[string]ir.Value{
		"password_reset_required": kv(true, 4),
	})
	if got := runRule(iamLoginProfileNoReset{}, r); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
	unk := res("aws_iam_user_login_profile", "l", map[string]ir.Value{
		"password_reset_required": ku(4),
	})
	if got := runRule(iamLoginProfileNoReset{}, unk); len(got) != 0 {
		t.Fatalf("unknown: expected 0 findings, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// 679: prod-like role with ReadOnlyAccess
// ---------------------------------------------------------------------------

func Test679_ProdReadOnlyFires(t *testing.T) {
	r := res("aws_iam_role", "r", map[string]ir.Value{
		"name":                ks("prod-app", 3),
		"managed_policy_arns": strList(4, "arn:aws:iam::aws:policy/ReadOnlyAccess"),
	})
	if got := runRule(iamRoleReadOnlyProd{}, r); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
}

func Test679_NonProdQuiet(t *testing.T) {
	r := res("aws_iam_role", "r", map[string]ir.Value{
		"name":                ks("dev-app", 3),
		"managed_policy_arns": strList(4, "arn:aws:iam::aws:policy/ReadOnlyAccess"),
	})
	if got := runRule(iamRoleReadOnlyProd{}, r); len(got) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(got))
	}
	noarns := res("aws_iam_role", "r", map[string]ir.Value{"name": ks("prod-app", 3)})
	if got := runRule(iamRoleReadOnlyProd{}, noarns); len(got) != 0 {
		t.Fatalf("no arns: expected 0 findings, got %d", len(got))
	}
	unk := res("aws_iam_role", "r", map[string]ir.Value{
		"name":                ks("prod-app", 3),
		"managed_policy_arns": ku(4),
	})
	if got := runRule(iamRoleReadOnlyProd{}, unk); len(got) != 0 {
		t.Fatalf("unknown arns: expected 0 findings, got %d", len(got))
	}
}

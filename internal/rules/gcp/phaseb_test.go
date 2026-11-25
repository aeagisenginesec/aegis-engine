package gcp

import (
	"testing"

	"aegis/internal/ir"
)

// Phase B tests: AEGIS-GCP-295 (Cloud Function invoker granted to
// allUsers), invoker-role-scoped across iam_member / iam_binding /
// iam_policy for both Cloud Functions generations.

func TestGCP295_IAMMemberAllUsersFires(t *testing.T) {
	r := res("google_cloudfunctions_function_iam_member", "invoker", map[string]ir.Value{
		"role":   ks("roles/cloudfunctions.invoker", 2),
		"member": ks("allUsers", 3),
	})
	mustFinding(t, runRule(cloudFunctionPublicInvoker{}, r), "AEGIS-GCP-295")
}

func TestGCP295_IAMMemberV2Fires(t *testing.T) {
	r := res("google_cloudfunctions2_function_iam_member", "invoker", map[string]ir.Value{
		"role":   ks("roles/cloudfunctions.invoker", 2),
		"member": ks("allAuthenticatedUsers", 3),
	})
	mustFinding(t, runRule(cloudFunctionPublicInvoker{}, r), "AEGIS-GCP-295")
}

func TestGCP295_IAMMemberPrivateQuiet(t *testing.T) {
	r := res("google_cloudfunctions_function_iam_member", "invoker", map[string]ir.Value{
		"role":   ks("roles/cloudfunctions.invoker", 2),
		"member": ks("user:dev@example.com", 3),
	})
	mustQuiet(t, runRule(cloudFunctionPublicInvoker{}, r))
}

func TestGCP295_NonInvokerRoleQuiet(t *testing.T) {
	// allUsers on a non-invoker role is out of scope: the rule is
	// invoker-role-scoped, not any-public-member.
	r := res("google_cloudfunctions_function_iam_member", "viewer", map[string]ir.Value{
		"role":   ks("roles/cloudfunctions.viewer", 2),
		"member": ks("allUsers", 3),
	})
	mustQuiet(t, runRule(cloudFunctionPublicInvoker{}, r))
}

func TestGCP295_IAMBindingAllUsersFires(t *testing.T) {
	r := res("google_cloudfunctions2_function_iam_binding", "invoker", map[string]ir.Value{
		"role":    ks("roles/cloudfunctions.invoker", 2),
		"members": strList(3, "serviceAccount:sa@proj.iam.gserviceaccount.com", "allUsers"),
	})
	mustFinding(t, runRule(cloudFunctionPublicInvoker{}, r), "AEGIS-GCP-295")
}

func TestGCP295_IAMBindingPrivateQuiet(t *testing.T) {
	r := res("google_cloudfunctions_function_iam_binding", "invoker", map[string]ir.Value{
		"role":    ks("roles/cloudfunctions.invoker", 2),
		"members": strList(3, "serviceAccount:sa@proj.iam.gserviceaccount.com"),
	})
	mustQuiet(t, runRule(cloudFunctionPublicInvoker{}, r))
}

func TestGCP295_IAMPolicyAllUsersFires(t *testing.T) {
	doc := `{"bindings":[{"role":"roles/cloudfunctions.invoker","members":["allUsers"]}]}`
	r := res("google_cloudfunctions_function_iam_policy", "policy", map[string]ir.Value{
		"policy_data": ks(doc, 2),
	})
	mustFinding(t, runRule(cloudFunctionPublicInvoker{}, r), "AEGIS-GCP-295")
}

func TestGCP295_IAMPolicyPrivateQuiet(t *testing.T) {
	doc := `{"bindings":[{"role":"roles/cloudfunctions.invoker","members":["user:dev@example.com"]}]}`
	r := res("google_cloudfunctions_function_iam_policy", "policy", map[string]ir.Value{
		"policy_data": ks(doc, 2),
	})
	mustQuiet(t, runRule(cloudFunctionPublicInvoker{}, r))
}

func TestGCP295_IAMPolicyNonInvokerQuiet(t *testing.T) {
	// allUsers in a viewer binding must not fire: role-scoped.
	doc := `{"bindings":[{"role":"roles/cloudfunctions.viewer","members":["allUsers"]}]}`
	r := res("google_cloudfunctions_function_iam_policy", "policy", map[string]ir.Value{
		"policy_data": ks(doc, 2),
	})
	mustQuiet(t, runRule(cloudFunctionPublicInvoker{}, r))
}

func TestGCP295_IAMPolicyBadJSONQuiet(t *testing.T) {
	r := res("google_cloudfunctions_function_iam_policy", "policy", map[string]ir.Value{
		"policy_data": ks("{not json", 2),
	})
	mustQuiet(t, runRule(cloudFunctionPublicInvoker{}, r))
}

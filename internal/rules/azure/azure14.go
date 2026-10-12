// Package azure — identity & access expansion (AEGIS-AZURE-170..185).
//
// Covers Entra ID Conditional Access enforcement, Azure RBAC hygiene
// (Owner/Contributor assignments, wildcard custom roles, Key Vault access
// policies), policy enforcement, and managed-identity adoption across
// PaaS services.
//
// Absent-attribute policy for this file: an absent attribute yields a
// finding when the provider default is the insecure one. Present-but-
// unresolved values yield NO finding.
package azure

import (
	"strings"

	"aegis/internal/ir"
)

// Azure14Rules returns identity & access rules in ID order.
func Azure14Rules() []ir.Rule {
	return []ir.Rule{
		caPolicyNotEnforced{},       // AEGIS-AZURE-170
		ownerRoleAssignment{},       // AEGIS-AZURE-171
		wildcardCustomRole{},        // AEGIS-AZURE-172
		contributorAtScope{},        // AEGIS-AZURE-173
		kvWildcardAccessPolicy{},    // AEGIS-AZURE-174
		policyAssignmentNoEnforce{}, // AEGIS-AZURE-175
		aadUserHardcodedPassword{},  // AEGIS-AZURE-176
		apimNoIdentity{},            // AEGIS-AZURE-177
		linuxWebAppNoIdentity{},     // AEGIS-AZURE-179
		mssqlServerNoIdentity{},     // AEGIS-AZURE-180
		storageNoIdentity{},         // AEGIS-AZURE-181
		dataFactoryNoIdentity{},     // AEGIS-AZURE-182
		synapseNoIdentity{},         // AEGIS-AZURE-183
		cosmosNoIdentity{},          // AEGIS-AZURE-184
		eventHubNoIdentity{},        // AEGIS-AZURE-185
	}
}

// absentInsecureFalse reports a finding when a boolean attribute is absent
// (provider default false, the insecure choice) or explicitly false.
// Present-but-unresolved values yield no finding.
func absentInsecureFalse(rule ir.Rule, r ir.Resource, attr, expected string) []ir.Finding {
	val, span, present, known := getBool(r, attr)
	if present && !known {
		return nil
	}
	if present && val {
		return nil
	}
	actual := "false"
	if !present {
		actual = "absent (provider default: false)"
	}
	return []ir.Finding{mkFinding(rule, r, attr,
		evidenceSpan(span, r.Span), actual, expected)}
}

// identityAbsent reports a finding when a resource has no identity block
// (absent) or an empty one. Present-but-unresolved yields no finding.
func identityAbsent(rule ir.Rule, r ir.Resource, expected string) []ir.Finding {
	blks, span, present, known := getBlocks(r, "identity")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(rule, r, "identity",
		evidenceSpan(span, r.Span), "absent (no managed identity)", expected)}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-170: Conditional Access policy not enforced
// ---------------------------------------------------------------------------

type caPolicyNotEnforced struct{}

func (caPolicyNotEnforced) ID() string { return "AEGIS-AZURE-170" }
func (caPolicyNotEnforced) Title() string {
	return "Conditional Access policy not enforced"
}
func (caPolicyNotEnforced) Description() string {
	return "azuread_conditional_access_policy with state other than " +
		"\"enabled\" (disabled or report-only) does not enforce its " +
		"controls. Access policies that are not enforced give a false " +
		"sense of protection. Set state = \"enabled\"."
}
func (caPolicyNotEnforced) Severity() ir.Severity { return ir.SeverityHigh }

func (caPolicyNotEnforced) AppliesTo(resType string) bool {
	return resType == "azuread_conditional_access_policy"
}

func (s caPolicyNotEnforced) Check(r ir.Resource) []ir.Finding {
	st, span, present, known := getString(r, "state")
	if !present || !known {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(st), "enabled") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "state", span,
		st, "state = \"enabled\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-171: Owner role assignment
// ---------------------------------------------------------------------------

type ownerRoleAssignment struct{}

func (ownerRoleAssignment) ID() string { return "AEGIS-AZURE-171" }
func (ownerRoleAssignment) Title() string {
	return "Owner role assignment"
}
func (ownerRoleAssignment) Description() string {
	return "azurerm_role_assignment granting the Owner role confers full " +
		"control including access management. Owner should be restricted " +
		"to break-glass accounts; use least-privilege roles instead."
}
func (ownerRoleAssignment) Severity() ir.Severity { return ir.SeverityHigh }

func (ownerRoleAssignment) AppliesTo(resType string) bool {
	return resType == "azurerm_role_assignment"
}

func (s ownerRoleAssignment) Check(r ir.Resource) []ir.Finding {
	name, span, present, known := getString(r, "role_definition_name")
	if !present || !known {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(name), "Owner") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "role_definition_name", span,
		name, "least-privilege role instead of Owner")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-172: Custom role with wildcard actions
// ---------------------------------------------------------------------------

type wildcardCustomRole struct{}

func (wildcardCustomRole) ID() string { return "AEGIS-AZURE-172" }
func (wildcardCustomRole) Title() string {
	return "Custom role definition with wildcard actions"
}
func (wildcardCustomRole) Description() string {
	return "azurerm_role_definition with \"*\" in permissions.actions " +
		"grants unrestricted control over the assignable scopes, " +
		"defeating least privilege. Enumerate the specific actions the " +
		"role needs."
}
func (wildcardCustomRole) Severity() ir.Severity { return ir.SeverityHigh }

func (wildcardCustomRole) AppliesTo(resType string) bool {
	return resType == "azurerm_role_definition"
}

func (s wildcardCustomRole) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "permissions")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		actions, _, ok := getStringListFromMap(b, "actions")
		if !ok {
			continue
		}
		for _, a := range actions {
			if strings.TrimSpace(a) == "*" {
				return []ir.Finding{mkFinding(s, r, "permissions",
					evidenceSpan(span, r.Span), "actions includes \"*\"",
					"explicit action list, no wildcards")}
			}
		}
	}
	return nil
}

// getStringListFromMap extracts a known string list from a block map.
func getStringListFromMap(m map[string]ir.Value, name string) ([]string, ir.Span, bool) {
	v, ok := m[name]
	if !ok || !v.Known {
		return nil, ir.Span{}, false
	}
	l, ok := v.AsList()
	if !ok {
		return nil, v.Span, false
	}
	out := make([]string, 0, len(l))
	for _, item := range l {
		s, ok := item.AsString()
		if !ok {
			return nil, v.Span, false
		}
		out = append(out, s)
	}
	return out, v.Span, true
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-173: Contributor role at subscription scope
// ---------------------------------------------------------------------------

type contributorAtScope struct{}

func (contributorAtScope) ID() string { return "AEGIS-AZURE-173" }
func (contributorAtScope) Title() string {
	return "Contributor role assigned at subscription scope"
}
func (contributorAtScope) Description() string {
	return "azurerm_role_assignment granting Contributor at subscription " +
		"scope (\"/subscriptions/<id>\") gives broad write access across " +
		"every resource group. Scope privileged assignments to the " +
		"resource groups that need them."
}
func (contributorAtScope) Severity() ir.Severity { return ir.SeverityMedium }

func (contributorAtScope) AppliesTo(resType string) bool {
	return resType == "azurerm_role_assignment"
}

func (s contributorAtScope) Check(r ir.Resource) []ir.Finding {
	name, _, npresent, nknown := getString(r, "role_definition_name")
	scope, span, spresent, sknown := getString(r, "scope")
	if !npresent || !nknown || !spresent || !sknown {
		return nil
	}
	if !strings.EqualFold(strings.TrimSpace(name), "Contributor") {
		return nil
	}
	sc := strings.TrimSpace(scope)
	if strings.HasPrefix(sc, "/subscriptions/") && !strings.Contains(strings.TrimSuffix(sc, "/"), "/resourceGroups/") &&
		!strings.Contains(sc, "/providers/") {
		return []ir.Finding{mkFinding(s, r, "scope", span,
			scope, "resource-group or resource scope")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-174: Key Vault access policy with wildcard permissions
// ---------------------------------------------------------------------------

type kvWildcardAccessPolicy struct{}

func (kvWildcardAccessPolicy) ID() string { return "AEGIS-AZURE-174" }
func (kvWildcardAccessPolicy) Title() string {
	return "Key Vault access policy with wildcard permissions"
}
func (kvWildcardAccessPolicy) Description() string {
	return "azurerm_key_vault_access_policy with \"*\" in key, secret, " +
		"certificate or storage permissions grants unrestricted vault " +
		"operations. Grant only the specific permissions the principal " +
		"needs, or migrate to Azure RBAC."
}
func (kvWildcardAccessPolicy) Severity() ir.Severity { return ir.SeverityHigh }

func (kvWildcardAccessPolicy) AppliesTo(resType string) bool {
	return resType == "azurerm_key_vault_access_policy"
}

func (s kvWildcardAccessPolicy) Check(r ir.Resource) []ir.Finding {
	for _, attr := range []string{"key_permissions", "secret_permissions", "certificate_permissions", "storage_permissions"} {
		perms, span, ok := getStringList(r, attr)
		if !ok {
			continue
		}
		for _, p := range perms {
			if strings.TrimSpace(p) == "*" {
				return []ir.Finding{mkFinding(s, r, attr, span,
					"permissions include \"*\"",
					"explicit permission list, no wildcards")}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-175: Policy assignment not enforced
// ---------------------------------------------------------------------------

type policyAssignmentNoEnforce struct{}

func (policyAssignmentNoEnforce) ID() string { return "AEGIS-AZURE-175" }
func (policyAssignmentNoEnforce) Title() string {
	return "Azure Policy assignment not enforced"
}
func (policyAssignmentNoEnforce) Description() string {
	return "azurerm_policy_assignment with enforce = false runs in " +
		"audit-only mode and does not deny non-compliant deployments. " +
		"Set enforce = true for guardrail policies."
}
func (policyAssignmentNoEnforce) Severity() ir.Severity { return ir.SeverityMedium }

func (policyAssignmentNoEnforce) AppliesTo(resType string) bool {
	return resType == "azurerm_policy_assignment"
}

func (s policyAssignmentNoEnforce) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "enforce")
	if !present || !known {
		return nil // default true: cannot decide against
	}
	if en {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "enforce", span,
		"false", "enforce = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-176: Entra ID user with hardcoded password
// ---------------------------------------------------------------------------

type aadUserHardcodedPassword struct{}

func (aadUserHardcodedPassword) ID() string { return "AEGIS-AZURE-176" }
func (aadUserHardcodedPassword) Title() string {
	return "Entra ID user with hardcoded password"
}
func (aadUserHardcodedPassword) Description() string {
	return "azuread_user with a password attribute embeds a credential in " +
		"Terraform state and version control. Provision users without " +
		"passwords and use self-service password reset or federation."
}
func (aadUserHardcodedPassword) Severity() ir.Severity { return ir.SeverityHigh }

func (aadUserHardcodedPassword) AppliesTo(resType string) bool {
	return resType == "azuread_user"
}

func (s aadUserHardcodedPassword) Check(r ir.Resource) []ir.Finding {
	pw, span, present, known := getString(r, "password")
	if !present || !known {
		return nil
	}
	if strings.TrimSpace(pw) == "" {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "password", span,
		"<hardcoded>", "remove password attribute")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-177..185: managed identity adoption family
// ---------------------------------------------------------------------------

type apimNoIdentity struct{}

func (apimNoIdentity) ID() string { return "AEGIS-AZURE-177" }
func (apimNoIdentity) Title() string {
	return "API Management without managed identity"
}
func (apimNoIdentity) Description() string {
	return "azurerm_api_management without an identity block cannot use " +
		"managed identities for backend authentication and tends to rely " +
		"on stored credentials. Enable a system-assigned identity."
}
func (apimNoIdentity) Severity() ir.Severity { return ir.SeverityMedium }
func (apimNoIdentity) AppliesTo(resType string) bool {
	return resType == "azurerm_api_management"
}
func (s apimNoIdentity) Check(r ir.Resource) []ir.Finding {
	return identityAbsent(s, r, "identity { type = \"SystemAssigned\" }")
}

type linuxWebAppNoIdentity struct{}

func (linuxWebAppNoIdentity) ID() string { return "AEGIS-AZURE-179" }
func (linuxWebAppNoIdentity) Title() string {
	return "Linux Web App without managed identity"
}
func (linuxWebAppNoIdentity) Description() string {
	return "azurerm_linux_web_app without an identity block cannot use " +
		"managed identities for Key Vault references or database access. " +
		"Enable a system-assigned identity."
}
func (linuxWebAppNoIdentity) Severity() ir.Severity { return ir.SeverityMedium }
func (linuxWebAppNoIdentity) AppliesTo(resType string) bool {
	return resType == "azurerm_linux_web_app"
}
func (s linuxWebAppNoIdentity) Check(r ir.Resource) []ir.Finding {
	return identityAbsent(s, r, "identity { type = \"SystemAssigned\" }")
}

type mssqlServerNoIdentity struct{}

func (mssqlServerNoIdentity) ID() string { return "AEGIS-AZURE-180" }
func (mssqlServerNoIdentity) Title() string {
	return "SQL server without managed identity"
}
func (mssqlServerNoIdentity) Description() string {
	return "azurerm_mssql_server without an identity block cannot use " +
		"customer-managed keys for transparent data encryption or Entra " +
		"ID authentication cleanly. Enable a system-assigned identity."
}
func (mssqlServerNoIdentity) Severity() ir.Severity { return ir.SeverityMedium }
func (mssqlServerNoIdentity) AppliesTo(resType string) bool {
	return resType == "azurerm_mssql_server"
}
func (s mssqlServerNoIdentity) Check(r ir.Resource) []ir.Finding {
	return identityAbsent(s, r, "identity { type = \"SystemAssigned\" }")
}

type storageNoIdentity struct{}

func (storageNoIdentity) ID() string { return "AEGIS-AZURE-181" }
func (storageNoIdentity) Title() string {
	return "Storage account without managed identity"
}
func (storageNoIdentity) Description() string {
	return "azurerm_storage_account without an identity block cannot use " +
		"customer-managed keys stored in Key Vault. Enable a " +
		"system-assigned identity when CMK encryption is required."
}
func (storageNoIdentity) Severity() ir.Severity { return ir.SeverityMedium }
func (storageNoIdentity) AppliesTo(resType string) bool {
	return resType == "azurerm_storage_account"
}
func (s storageNoIdentity) Check(r ir.Resource) []ir.Finding {
	return identityAbsent(s, r, "identity { type = \"SystemAssigned\" }")
}

type dataFactoryNoIdentity struct{}

func (dataFactoryNoIdentity) ID() string { return "AEGIS-AZURE-182" }
func (dataFactoryNoIdentity) Title() string {
	return "Data Factory without managed identity"
}
func (dataFactoryNoIdentity) Description() string {
	return "azurerm_data_factory without an identity block cannot " +
		"authenticate to linked services with managed identities and " +
		"tends to rely on stored credentials. Enable a system-assigned " +
		"identity."
}
func (dataFactoryNoIdentity) Severity() ir.Severity { return ir.SeverityMedium }
func (dataFactoryNoIdentity) AppliesTo(resType string) bool {
	return resType == "azurerm_data_factory"
}
func (s dataFactoryNoIdentity) Check(r ir.Resource) []ir.Finding {
	return identityAbsent(s, r, "identity { type = \"SystemAssigned\" }")
}

type synapseNoIdentity struct{}

func (synapseNoIdentity) ID() string { return "AEGIS-AZURE-183" }
func (synapseNoIdentity) Title() string {
	return "Synapse workspace without managed identity"
}
func (synapseNoIdentity) Description() string {
	return "azurerm_synapse_workspace without an identity block cannot " +
		"use managed identities for linked services and storage access. " +
		"Enable a system-assigned identity."
}
func (synapseNoIdentity) Severity() ir.Severity { return ir.SeverityMedium }
func (synapseNoIdentity) AppliesTo(resType string) bool {
	return resType == "azurerm_synapse_workspace"
}
func (s synapseNoIdentity) Check(r ir.Resource) []ir.Finding {
	return identityAbsent(s, r, "identity { type = \"SystemAssigned\" }")
}

type cosmosNoIdentity struct{}

func (cosmosNoIdentity) ID() string { return "AEGIS-AZURE-184" }
func (cosmosNoIdentity) Title() string {
	return "Cosmos DB account without managed identity"
}
func (cosmosNoIdentity) Description() string {
	return "azurerm_cosmosdb_account without an identity block cannot use " +
		"customer-managed keys from Key Vault. Enable a system-assigned " +
		"identity when CMK encryption is required."
}
func (cosmosNoIdentity) Severity() ir.Severity { return ir.SeverityMedium }
func (cosmosNoIdentity) AppliesTo(resType string) bool {
	return resType == "azurerm_cosmosdb_account"
}
func (s cosmosNoIdentity) Check(r ir.Resource) []ir.Finding {
	return identityAbsent(s, r, "identity { type = \"SystemAssigned\" }")
}

type eventHubNoIdentity struct{}

func (eventHubNoIdentity) ID() string { return "AEGIS-AZURE-185" }
func (eventHubNoIdentity) Title() string {
	return "Event Hub namespace without managed identity"
}
func (eventHubNoIdentity) Description() string {
	return "azurerm_eventhub_namespace without an identity block cannot " +
		"use customer-managed keys from Key Vault. Enable a " +
		"system-assigned identity when CMK encryption is required."
}
func (eventHubNoIdentity) Severity() ir.Severity { return ir.SeverityMedium }
func (eventHubNoIdentity) AppliesTo(resType string) bool {
	return resType == "azurerm_eventhub_namespace"
}
func (s eventHubNoIdentity) Check(r ir.Resource) []ir.Finding {
	return identityAbsent(s, r, "identity { type = \"SystemAssigned\" }")
}

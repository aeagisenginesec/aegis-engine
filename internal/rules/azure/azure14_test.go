package azure

import (
	"strconv"
	"testing"

	"aegis/internal/ir"
)

// Pack registration: Azure14Rules must be wired into Rules() in ID order.
func TestAzure14RegisteredInIDOrder(t *testing.T) {
	rules := Rules()
	idx := map[string]int{}
	for i, r := range rules {
		idx[r.ID()] = i
	}
	for n := 170; n <= 185; n++ {
		id := "AEGIS-AZURE-" + strconv.Itoa(n)
		i, ok := idx[id]
		if !ok {
			t.Fatalf("rule %s not registered", id)
		}
		if n > 170 {
			prev := "AEGIS-AZURE-" + strconv.Itoa(n-1)
			if idx[prev] != i-1 {
				t.Fatalf("rules out of order: %s at %d, %s at %d", prev, idx[prev], id, i)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-170: Conditional Access policy not enforced
// ---------------------------------------------------------------------------

func TestAZURE170(t *testing.T) {
	id := "AEGIS-AZURE-170"
	mustFinding(t, runRule(caPolicyNotEnforced{}, res("azuread_conditional_access_policy", "p", map[string]ir.Value{"state": ks("disabled", 3)})), id)
	mustFinding(t, runRule(caPolicyNotEnforced{}, res("azuread_conditional_access_policy", "p", map[string]ir.Value{"state": ks("enabledForReportingButNotEnforced", 3)})), id)
	r := res("azuread_conditional_access_policy", "p", map[string]ir.Value{"state": ks("enabled", 3)})
	if f := runRule(caPolicyNotEnforced{}, r); len(f) != 0 {
		t.Fatalf("enabled policy must not fire, got %d", len(f))
	}
	if f := runRule(caPolicyNotEnforced{}, res("azuread_conditional_access_policy", "p", map[string]ir.Value{"state": ku(3)})); len(f) != 0 {
		t.Fatalf("unknown state must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-171: Owner role assignment
// ---------------------------------------------------------------------------

func TestAZURE171(t *testing.T) {
	id := "AEGIS-AZURE-171"
	f := mustFinding(t, runRule(ownerRoleAssignment{}, res("azurerm_role_assignment", "o", map[string]ir.Value{"role_definition_name": ks("Owner", 3)})), id)
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity %s", f.Severity)
	}
	r := res("azurerm_role_assignment", "o", map[string]ir.Value{"role_definition_name": ks("Reader", 3)})
	if f := runRule(ownerRoleAssignment{}, r); len(f) != 0 {
		t.Fatalf("Reader must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-172: Custom role with wildcard actions
// ---------------------------------------------------------------------------

func TestAZURE172(t *testing.T) {
	id := "AEGIS-AZURE-172"
	r := res("azurerm_role_definition", "c", map[string]ir.Value{
		"permissions": blks(3, blk("actions", strList(4, "Microsoft.Storage/*"))),
	})
	if f := runRule(wildcardCustomRole{}, r); len(f) != 0 {
		t.Fatalf("scoped wildcard must not fire, got %d", len(f))
	}
	r2 := res("azurerm_role_definition", "c", map[string]ir.Value{
		"permissions": blks(3, blk("actions", strList(4, "*"))),
	})
	mustFinding(t, runRule(wildcardCustomRole{}, r2), id)
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-173: Contributor role at subscription scope
// ---------------------------------------------------------------------------

func TestAZURE173(t *testing.T) {
	id := "AEGIS-AZURE-173"
	r := res("azurerm_role_assignment", "c", map[string]ir.Value{
		"role_definition_name": ks("Contributor", 3),
		"scope":                ks("/subscriptions/11111111-2222-3333-4444-555555555555", 4),
	})
	mustFinding(t, runRule(contributorAtScope{}, r), id)
	r2 := res("azurerm_role_assignment", "c", map[string]ir.Value{
		"role_definition_name": ks("Contributor", 3),
		"scope":                ks("/subscriptions/11111111-2222-3333-4444-555555555555/resourceGroups/rg1", 4),
	})
	if f := runRule(contributorAtScope{}, r2); len(f) != 0 {
		t.Fatalf("RG-scoped Contributor must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-174: Key Vault access policy with wildcard permissions
// ---------------------------------------------------------------------------

func TestAZURE174(t *testing.T) {
	id := "AEGIS-AZURE-174"
	r := res("azurerm_key_vault_access_policy", "p", map[string]ir.Value{
		"secret_permissions": strList(3, "Get", "List"),
		"key_permissions":    strList(4, "*"),
	})
	mustFinding(t, runRule(kvWildcardAccessPolicy{}, r), id)
	r2 := res("azurerm_key_vault_access_policy", "p", map[string]ir.Value{
		"secret_permissions": strList(3, "Get", "List"),
	})
	if f := runRule(kvWildcardAccessPolicy{}, r2); len(f) != 0 {
		t.Fatalf("explicit permissions must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-175: Policy assignment not enforced
// ---------------------------------------------------------------------------

func TestAZURE175(t *testing.T) {
	id := "AEGIS-AZURE-175"
	mustFinding(t, runRule(policyAssignmentNoEnforce{}, res("azurerm_policy_assignment", "p", map[string]ir.Value{"enforce": kv(false, 3)})), id)
	r := res("azurerm_policy_assignment", "p", map[string]ir.Value{"enforce": kv(true, 3)})
	if f := runRule(policyAssignmentNoEnforce{}, r); len(f) != 0 {
		t.Fatalf("enforced must not fire, got %d", len(f))
	}
	if f := runRule(policyAssignmentNoEnforce{}, res("azurerm_policy_assignment", "p", nil)); len(f) != 0 {
		t.Fatalf("absent (default true) must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-176: Entra ID user with hardcoded password
// ---------------------------------------------------------------------------

func TestAZURE176(t *testing.T) {
	id := "AEGIS-AZURE-176"
	mustFinding(t, runRule(aadUserHardcodedPassword{}, res("azuread_user", "u", map[string]ir.Value{"password": ks("P@ssw0rd!", 3)})), id)
	if f := runRule(aadUserHardcodedPassword{}, res("azuread_user", "u", nil)); len(f) != 0 {
		t.Fatalf("no password must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-177..185: managed identity family
// ---------------------------------------------------------------------------

func identityCases() []struct {
	rule ir.Rule
	id   string
	typ  string
} {
	return []struct {
		rule ir.Rule
		id   string
		typ  string
	}{
		{apimNoIdentity{}, "AEGIS-AZURE-177", "azurerm_api_management"},
		{appServiceNoIdentity{}, "AEGIS-AZURE-178", "azurerm_app_service"},
		{linuxWebAppNoIdentity{}, "AEGIS-AZURE-179", "azurerm_linux_web_app"},
		{mssqlServerNoIdentity{}, "AEGIS-AZURE-180", "azurerm_mssql_server"},
		{storageNoIdentity{}, "AEGIS-AZURE-181", "azurerm_storage_account"},
		{dataFactoryNoIdentity{}, "AEGIS-AZURE-182", "azurerm_data_factory"},
		{synapseNoIdentity{}, "AEGIS-AZURE-183", "azurerm_synapse_workspace"},
		{cosmosNoIdentity{}, "AEGIS-AZURE-184", "azurerm_cosmosdb_account"},
		{eventHubNoIdentity{}, "AEGIS-AZURE-185", "azurerm_eventhub_namespace"},
	}
}

func TestAZURE177_185_IdentityFamily(t *testing.T) {
	for _, c := range identityCases() {
		f := mustFinding(t, runRule(c.rule, res(c.typ, "x", nil)), c.id)
		if f.Severity != ir.SeverityMedium {
			t.Fatalf("%s: wrong severity %s", c.id, f.Severity)
		}
		r := res(c.typ, "x", map[string]ir.Value{
			"identity": blks(3, blk("type", ks("SystemAssigned", 4))),
		})
		if fs := runRule(c.rule, r); len(fs) != 0 {
			t.Fatalf("%s: identity present must not fire", c.id)
		}
		if fs := runRule(c.rule, res(c.typ, "x", map[string]ir.Value{"identity": ku(3)})); len(fs) != 0 {
			t.Fatalf("%s: unknown identity must not fire", c.id)
		}
	}
}

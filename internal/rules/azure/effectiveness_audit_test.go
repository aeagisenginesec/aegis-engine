package azure

import (
	"testing"

	"aegis/internal/ir"
)

// Effectiveness audit (ITEM 3): hand-written pos+neg tests for rules the
// black-box probe could not drive, plus regression tests for rules fixed
// by this audit (unknown-value contract, dead rules, empty evidence).
// Generated replay tests for probe-covered rules live below, appended by
// the audit generator. eaRef/eaNum are local to this file; kv/ks/ku/kn/
// blk/blks/strList/res/runRule/mustFinding/mustQuiet come from the pack's
// shared test helpers.

// eaRef builds an unresolved reference value.
func eaRef(ref string, line int) ir.Value {
	return ir.Value{Known: false, Span: spanAt(line), Ref: ref}
}

// eaNum builds a known numeric value.
func eaNum(n float64, line int) ir.Value {
	return ir.Value{Raw: n, Known: true, Span: spanAt(line)}
}

var _ = eaNum // used by generated replay tests in this file

// AEGIS-AZURE-033 (FIXED: was a dead rule returning nil unconditionally):
// storage account without a customer_managed_key block uses
// Microsoft-managed keys.
func TestEffectiveness_AZURE033_StorageNoCMK(t *testing.T) {
	pos := res("azurerm_storage_account", "sa", map[string]ir.Value{})
	if got := runRule(storageNoCMK{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding for absent block, got %d", len(got))
	}
	neg := res("azurerm_storage_account", "sa", map[string]ir.Value{
		"customer_managed_key": blks(2, blk("key_vault_key_id", ks("https://kv.vault.azure.net/keys/k/1", 3))),
	})
	if got := runRule(storageNoCMK{}, neg); len(got) != 0 {
		t.Fatalf("present block must be quiet, got %d", len(got))
	}
	unk := res("azurerm_storage_account", "sa", map[string]ir.Value{
		"customer_managed_key": ku(2),
	})
	if got := runRule(storageNoCMK{}, unk); len(got) != 0 {
		t.Fatalf("unknown block must be quiet, got %d", len(got))
	}
}

// AEGIS-AZURE-035: storage account NFSv3 without secure transfer.
func TestEffectiveness_AZURE035_StorageNoNFSv3Secure(t *testing.T) {
	pos := res("azurerm_storage_account", "sa", map[string]ir.Value{
		"nfsv3_enabled":              kv(true, 2),
		"https_traffic_only_enabled": kv(false, 3),
	})
	if got := runRule(storageNoNFSv3Secure{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	neg := res("azurerm_storage_account", "sa", map[string]ir.Value{
		"nfsv3_enabled":              kv(true, 2),
		"https_traffic_only_enabled": kv(true, 3),
	})
	if got := runRule(storageNoNFSv3Secure{}, neg); len(got) != 0 {
		t.Fatalf("https-only must be quiet, got %d", len(got))
	}
	neg2 := res("azurerm_storage_account", "sa", map[string]ir.Value{
		"nfsv3_enabled":              kv(false, 2),
		"https_traffic_only_enabled": kv(false, 3),
	})
	if got := runRule(storageNoNFSv3Secure{}, neg2); len(got) != 0 {
		t.Fatalf("nfsv3 disabled must be quiet, got %d", len(got))
	}
	unk := res("azurerm_storage_account", "sa", map[string]ir.Value{
		"nfsv3_enabled":              kv(true, 2),
		"https_traffic_only_enabled": ku(3),
	})
	if got := runRule(storageNoNFSv3Secure{}, unk); len(got) != 0 {
		t.Fatalf("unknown https flag must be quiet, got %d", len(got))
	}
}

// AEGIS-AZURE-058 (FIXED: unknown dns_servers used to fire): vnet without
// custom DNS servers. Absent fires (provider default DNS); unknown is
// undecidable and must stay quiet.
func TestEffectiveness_AZURE058_VnetNoCustomDNS_UnknownQuiet(t *testing.T) {
	pos := res("azurerm_virtual_network", "v", map[string]ir.Value{})
	if got := runRule(vnetNoFlowTimeout{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding for absent dns_servers, got %d", len(got))
	}
	neg := res("azurerm_virtual_network", "v", map[string]ir.Value{
		"dns_servers": strList(2, "10.0.0.4"),
	})
	if got := runRule(vnetNoFlowTimeout{}, neg); len(got) != 0 {
		t.Fatalf("present dns_servers must be quiet, got %d", len(got))
	}
	unk := res("azurerm_virtual_network", "v", map[string]ir.Value{"dns_servers": ku(2)})
	if got := runRule(vnetNoFlowTimeout{}, unk); len(got) != 0 {
		t.Fatalf("unknown dns_servers must be quiet, got %d", len(got))
	}
	ref := res("azurerm_virtual_network", "v", map[string]ir.Value{"dns_servers": eaRef("var.dns", 2)})
	if got := runRule(vnetNoFlowTimeout{}, ref); len(got) != 0 {
		t.Fatalf("ref dns_servers must be quiet, got %d", len(got))
	}
}

// AEGIS-AZURE-059 (FIXED: was a dead rule returning nil unconditionally):
// subnet without an NSG association. Cross-resource: fires for each
// subnet with no azurerm_subnet_network_security_group_association
// referencing it.
func TestEffectiveness_AZURE059_SubnetNoNSG(t *testing.T) {
	subnet := res("azurerm_subnet", "web", map[string]ir.Value{})
	if got := (subnetNoNSG{}).CheckAll([]ir.Resource{subnet}); len(got) != 1 {
		t.Fatalf("expected 1 finding without association, got %d", len(got))
	}
	assoc := res("azurerm_subnet_network_security_group_association", "a", map[string]ir.Value{
		"subnet_id": eaRef("azurerm_subnet.web.id", 2),
	})
	if got := (subnetNoNSG{}).CheckAll([]ir.Resource{subnet, assoc}); len(got) != 0 {
		t.Fatalf("associated subnet must be quiet, got %d", len(got))
	}
	other := res("azurerm_subnet", "db", map[string]ir.Value{})
	if got := (subnetNoNSG{}).CheckAll([]ir.Resource{subnet, other, assoc}); len(got) != 1 {
		t.Fatalf("only the unassociated subnet must fire, got %d", len(got))
	}
	// An association whose link is unresolvable cannot prove protection.
	unkAssoc := res("azurerm_subnet_network_security_group_association", "a", map[string]ir.Value{
		"subnet_id": ku(2),
	})
	if got := (subnetNoNSG{}).CheckAll([]ir.Resource{subnet, unkAssoc}); len(got) != 1 {
		t.Fatalf("unresolvable association must not suppress, got %d", len(got))
	}
}

// AEGIS-AZURE-060 (FIXED: unknown service_endpoints used to fire):
// subnet without service endpoints.
func TestEffectiveness_AZURE060_SubnetNoServiceEndpoint_UnknownQuiet(t *testing.T) {
	pos := res("azurerm_subnet", "s", map[string]ir.Value{})
	if got := runRule(subnetNoServiceEndpoint{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding for absent service_endpoints, got %d", len(got))
	}
	neg := res("azurerm_subnet", "s", map[string]ir.Value{
		"service_endpoints": strList(2, "Microsoft.Storage"),
	})
	if got := runRule(subnetNoServiceEndpoint{}, neg); len(got) != 0 {
		t.Fatalf("present endpoints must be quiet, got %d", len(got))
	}
	unk := res("azurerm_subnet", "s", map[string]ir.Value{"service_endpoints": ku(2)})
	if got := runRule(subnetNoServiceEndpoint{}, unk); len(got) != 0 {
		t.Fatalf("unknown service_endpoints must be quiet, got %d", len(got))
	}
}

// AEGIS-AZURE-061 (FIXED: present-but-unknown auth_settings used to fire):
// App Service without authentication.
func TestEffectiveness_AZURE061_AppSvcNoAuth_UnknownQuiet(t *testing.T) {
	pos := res("azurerm_app_service", "app", map[string]ir.Value{})
	if got := runRule(appSvcNoAuth{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding for absent auth_settings, got %d", len(got))
	}
	neg := res("azurerm_app_service", "app", map[string]ir.Value{
		"auth_settings": blks(2, blk("enabled", ks("true", 3))),
	})
	if got := runRule(appSvcNoAuth{}, neg); len(got) != 0 {
		t.Fatalf("enabled auth must be quiet, got %d", len(got))
	}
	unk := res("azurerm_app_service", "app", map[string]ir.Value{"auth_settings": ku(2)})
	if got := runRule(appSvcNoAuth{}, unk); len(got) != 0 {
		t.Fatalf("unknown auth_settings must be quiet, got %d", len(got))
	}
}

// AEGIS-AZURE-072 (FIXED: was a dead rule returning nil unconditionally):
// AKS cluster without pod-managed identity and without workload identity.
func TestEffectiveness_AZURE072_AKSNoPodIdentity(t *testing.T) {
	pos := res("azurerm_kubernetes_cluster", "c", map[string]ir.Value{})
	if got := runRule(aksNoPodIdentity{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding for no identity mechanism, got %d", len(got))
	}
	negPod := res("azurerm_kubernetes_cluster", "c", map[string]ir.Value{
		"pod_identity": blks(2, blk("identity_ids", strList(3, "/subscriptions/x/resourceGroups/r/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id"))),
	})
	if got := runRule(aksNoPodIdentity{}, negPod); len(got) != 0 {
		t.Fatalf("pod_identity block must be quiet, got %d", len(got))
	}
	negWI := res("azurerm_kubernetes_cluster", "c", map[string]ir.Value{
		"workload_identity_enabled": kv(true, 2),
	})
	if got := runRule(aksNoPodIdentity{}, negWI); len(got) != 0 {
		t.Fatalf("workload_identity_enabled must be quiet, got %d", len(got))
	}
	negOIDC := res("azurerm_kubernetes_cluster", "c", map[string]ir.Value{
		"oidc_issuer_enabled": kv(true, 2),
	})
	if got := runRule(aksNoPodIdentity{}, negOIDC); len(got) != 0 {
		t.Fatalf("oidc_issuer_enabled must be quiet, got %d", len(got))
	}
	unk := res("azurerm_kubernetes_cluster", "c", map[string]ir.Value{
		"workload_identity_enabled": ku(2),
	})
	if got := runRule(aksNoPodIdentity{}, unk); len(got) != 0 {
		t.Fatalf("unknown workload_identity_enabled must be quiet, got %d", len(got))
	}
}

// AEGIS-AZURE-075 (FIXED: present-but-unknown api_server_access_profile
// used to fire): AKS API server without authorized IP ranges.
// AEGIS-AZURE-083: CosmosDB account with eventual consistency.
func TestEffectiveness_AZURE083_CosmosWeakConsistency(t *testing.T) {
	pos := res("azurerm_cosmosdb_account", "c", map[string]ir.Value{
		"consistency_policy": blks(2, blk("consistency_level", ks("Eventual", 3))),
	})
	if got := runRule(cosmosWeakConsistency{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	neg := res("azurerm_cosmosdb_account", "c", map[string]ir.Value{
		"consistency_policy": blks(2, blk("consistency_level", ks("Session", 3))),
	})
	if got := runRule(cosmosWeakConsistency{}, neg); len(got) != 0 {
		t.Fatalf("Session must be quiet, got %d", len(got))
	}
	if got := runRule(cosmosWeakConsistency{}, res("azurerm_cosmosdb_account", "c", map[string]ir.Value{})); len(got) != 0 {
		t.Fatalf("absent policy must be quiet, got %d", len(got))
	}
}

// AEGIS-AZURE-086: Container Registry without geo-replication.
func TestEffectiveness_AZURE086_ACRNoGeoReplication(t *testing.T) {
	pos := res("azurerm_container_registry", "r", map[string]ir.Value{"sku": ks("Premium", 2)})
	if got := runRule(acrNoGeoReplication{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	neg := res("azurerm_container_registry", "r", map[string]ir.Value{"sku": ks("Standard", 2)})
	if got := runRule(acrNoGeoReplication{}, neg); len(got) != 0 {
		t.Fatalf("Standard SKU must be quiet (no geo-replication available), got %d", len(got))
	}
	neg2 := res("azurerm_container_registry", "r", map[string]ir.Value{
		"sku":             ks("Premium", 2),
		"georeplications": blks(2, blk("location", ks("westeurope", 3))),
	})
	if got := runRule(acrNoGeoReplication{}, neg2); len(got) != 0 {
		t.Fatalf("Premium with georeplications must be quiet, got %d", len(got))
	}
	unk := res("azurerm_container_registry", "r", map[string]ir.Value{"sku": ku(2)})
	if got := runRule(acrNoGeoReplication{}, unk); len(got) != 0 {
		t.Fatalf("unknown sku must be quiet, got %d", len(got))
	}
}

// AEGIS-AZURE-088 (FIXED: empty evidence Actual): ACR without content trust.
func TestEffectiveness_AZURE088_ACRNoContentTrust_Evidence(t *testing.T) {
	empty := res("azurerm_container_registry", "r", map[string]ir.Value{
		"trust_policy": blks(2, blk("enabled", ks("", 3))),
	})
	f := mustFinding(t, runRule(acrNoContentTrust{}, empty), "AEGIS-AZURE-088")
	if f.Evidence.Actual == "" || f.Evidence.Expected == "" || f.Evidence.Attribute == "" {
		t.Fatalf("evidence must be non-empty, got %+v", f.Evidence)
	}
	neg := res("azurerm_container_registry", "r", map[string]ir.Value{
		"trust_policy": blks(2, blk("enabled", ks("true", 3))),
	})
	if got := runRule(acrNoContentTrust{}, neg); len(got) != 0 {
		t.Fatalf("enabled trust policy must be quiet, got %d", len(got))
	}
}

// AEGIS-AZURE-089 (FIXED: empty evidence Actual): ACR without quarantine.
func TestEffectiveness_AZURE089_ACRNoQuarantine_Evidence(t *testing.T) {
	empty := res("azurerm_container_registry", "r", map[string]ir.Value{
		"quarantine_policy": blks(2, blk("enabled", ks("", 3))),
	})
	f := mustFinding(t, runRule(acrNoQuarantine{}, empty), "AEGIS-AZURE-089")
	if f.Evidence.Actual == "" || f.Evidence.Expected == "" || f.Evidence.Attribute == "" {
		t.Fatalf("evidence must be non-empty, got %+v", f.Evidence)
	}
	neg := res("azurerm_container_registry", "r", map[string]ir.Value{
		"quarantine_policy": blks(2, blk("enabled", ks("true", 3))),
	})
	if got := runRule(acrNoQuarantine{}, neg); len(got) != 0 {
		t.Fatalf("enabled quarantine must be quiet, got %d", len(got))
	}
}

// AEGIS-AZURE-091 (FIXED: unknown categories used to fire): Monitor log
// profile without categories.
func TestEffectiveness_AZURE091_MonitorNoActivityLog_UnknownQuiet(t *testing.T) {
	pos := res("azurerm_monitor_log_profile", "p", map[string]ir.Value{})
	if got := runRule(monitorNoActivityLog{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding for absent categories, got %d", len(got))
	}
	neg := res("azurerm_monitor_log_profile", "p", map[string]ir.Value{
		"categories": strList(2, "Write", "Delete", "Action"),
	})
	if got := runRule(monitorNoActivityLog{}, neg); len(got) != 0 {
		t.Fatalf("present categories must be quiet, got %d", len(got))
	}
	unk := res("azurerm_monitor_log_profile", "p", map[string]ir.Value{"categories": ku(2)})
	if got := runRule(monitorNoActivityLog{}, unk); len(got) != 0 {
		t.Fatalf("unknown categories must be quiet, got %d", len(got))
	}
}

// AEGIS-AZURE-173: Contributor role assigned at subscription scope.
func TestEffectiveness_AZURE173_ContributorAtScope(t *testing.T) {
	pos := res("azurerm_role_assignment", "a", map[string]ir.Value{
		"role_definition_name": ks("Contributor", 2),
		"scope":                ks("/subscriptions/11111111-1111-1111-1111-111111111111", 3),
	})
	if got := runRule(contributorAtScope{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	neg := res("azurerm_role_assignment", "a", map[string]ir.Value{
		"role_definition_name": ks("Contributor", 2),
		"scope":                ks("/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg", 3),
	})
	if got := runRule(contributorAtScope{}, neg); len(got) != 0 {
		t.Fatalf("resource-group scope must be quiet, got %d", len(got))
	}
	neg2 := res("azurerm_role_assignment", "a", map[string]ir.Value{
		"role_definition_name": ks("Reader", 2),
		"scope":                ks("/subscriptions/11111111-1111-1111-1111-111111111111", 3),
	})
	if got := runRule(contributorAtScope{}, neg2); len(got) != 0 {
		t.Fatalf("Reader must be quiet, got %d", len(got))
	}
}

// AEGIS-AZURE-199 (FIXED: empty evidence Actual): storage network rules
// with default_action not Deny.
func TestEffectiveness_AZURE199_StorageNetRulesOpen_Evidence(t *testing.T) {
	empty := res("azurerm_storage_account_network_rules", "n", map[string]ir.Value{
		"default_action": ks("", 2),
	})
	f := mustFinding(t, runRule(storageNetRulesOpen{}, empty), "AEGIS-AZURE-199")
	if f.Evidence.Actual == "" || f.Evidence.Expected == "" || f.Evidence.Attribute == "" {
		t.Fatalf("evidence must be non-empty, got %+v", f.Evidence)
	}
	neg := res("azurerm_storage_account_network_rules", "n", map[string]ir.Value{
		"default_action": ks("Deny", 2),
	})
	if got := runRule(storageNetRulesOpen{}, neg); len(got) != 0 {
		t.Fatalf("Deny must be quiet, got %d", len(got))
	}
}

// AEGIS-AZURE-205: Key Vault firewall without IP rules (Deny with no
// allowances).
func TestEffectiveness_AZURE205_KVNoFirewallRules(t *testing.T) {
	pos := res("azurerm_key_vault", "kv", map[string]ir.Value{
		"network_acls": blks(2, blk("default_action", ks("Deny", 3))),
	})
	if got := runRule(kvNoFirewallRules{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	neg := res("azurerm_key_vault", "kv", map[string]ir.Value{
		"network_acls": blks(2, blk("default_action", ks("Deny", 3), "ip_rules", strList(4, "203.0.113.0/24"))),
	})
	if got := runRule(kvNoFirewallRules{}, neg); len(got) != 0 {
		t.Fatalf("Deny with ip_rules must be quiet, got %d", len(got))
	}
	neg2 := res("azurerm_key_vault", "kv", map[string]ir.Value{
		"network_acls": blks(2, blk("default_action", ks("Allow", 3))),
	})
	if got := runRule(kvNoFirewallRules{}, neg2); len(got) != 0 {
		t.Fatalf("Allow is covered by AZURE-187, not 205, got %d", len(got))
	}
}

// AEGIS-AZURE-230: AKS cluster without Entra ID RBAC.
// AEGIS-AZURE-260: Defender for Resource Manager plan not enabled.
func TestEffectiveness_AZURE260_DefenderARMPlanOff(t *testing.T) {
	pos := res("azurerm_security_center_subscription_pricing", "p", map[string]ir.Value{
		"resource_type": ks("Arm", 2),
		"tier":          ks("Free", 3),
	})
	if got := runRule(defenderARMPlanOff{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	neg := res("azurerm_security_center_subscription_pricing", "p", map[string]ir.Value{
		"resource_type": ks("Arm", 2),
		"tier":          ks("Standard", 3),
	})
	if got := runRule(defenderARMPlanOff{}, neg); len(got) != 0 {
		t.Fatalf("Standard must be quiet, got %d", len(got))
	}
	neg2 := res("azurerm_security_center_subscription_pricing", "p", map[string]ir.Value{
		"resource_type": ks("KeyVault", 2),
		"tier":          ks("Free", 3),
	})
	if got := runRule(defenderARMPlanOff{}, neg2); len(got) != 0 {
		t.Fatalf("non-Arm resource_type must be quiet, got %d", len(got))
	}
	unk := res("azurerm_security_center_subscription_pricing", "p", map[string]ir.Value{
		"resource_type": ks("Arm", 2),
		"tier":          ku(3),
	})
	if got := runRule(defenderARMPlanOff{}, unk); len(got) != 0 {
		t.Fatalf("unknown tier must be quiet, got %d", len(got))
	}
}

// AEGIS-AZURE-285 (FIXED: present-but-unknown routing_rule used to fire):
// Front Door without HTTP-to-HTTPS redirect rule.
func TestEffectiveness_AZURE285_FrontDoorNoRedirect_UnknownQuiet(t *testing.T) {
	pos := res("azurerm_frontdoor", "fd", map[string]ir.Value{})
	if got := runRule(fdNoHTTPSRedirect{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding for absent routing_rule, got %d", len(got))
	}
	neg := res("azurerm_frontdoor", "fd", map[string]ir.Value{
		"routing_rule": blks(2, blk("redirect_configuration", blks(3, blk("redirect_type", ks("HttpsRedirect", 4))))),
	})
	if got := runRule(fdNoHTTPSRedirect{}, neg); len(got) != 0 {
		t.Fatalf("redirect_configuration present must be quiet, got %d", len(got))
	}
	unk := res("azurerm_frontdoor", "fd", map[string]ir.Value{"routing_rule": ku(2)})
	if got := runRule(fdNoHTTPSRedirect{}, unk); len(got) != 0 {
		t.Fatalf("unknown routing_rule must be quiet, got %d", len(got))
	}
}

// AEGIS-AZURE-304 (FIXED: present-but-unknown custom_parameters used to
// fire): Databricks workspace with public IPs on clusters.
func TestEffectiveness_AZURE304_DatabricksNoPublicIP_UnknownQuiet(t *testing.T) {
	pos := res("azurerm_databricks_workspace", "w", map[string]ir.Value{})
	if got := runRule(databricksNoPublicIP{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding for absent custom_parameters, got %d", len(got))
	}
	neg := res("azurerm_databricks_workspace", "w", map[string]ir.Value{
		"custom_parameters": blks(2, blk("no_public_ip", kv(true, 3))),
	})
	if got := runRule(databricksNoPublicIP{}, neg); len(got) != 0 {
		t.Fatalf("no_public_ip=true must be quiet, got %d", len(got))
	}
	unk := res("azurerm_databricks_workspace", "w", map[string]ir.Value{"custom_parameters": ku(2)})
	if got := runRule(databricksNoPublicIP{}, unk); len(got) != 0 {
		t.Fatalf("unknown custom_parameters must be quiet, got %d", len(got))
	}
}

// AEGIS-AZURE-051 (FIXED: empty evidence Actual): MSSQL vulnerability
// assessment with recurring scans disabled.
func TestEffectiveness_AZURE051_MSSQLNoVulnAssess_Evidence(t *testing.T) {
	empty := res("azurerm_mssql_server_vulnerability_assessment", "v", map[string]ir.Value{
		"recurring_scans": blks(2, blk("enabled", ks("", 3))),
	})
	f := mustFinding(t, runRule(mssqlNoVulnAssess{}, empty), "AEGIS-AZURE-051")
	if f.Evidence.Actual == "" || f.Evidence.Expected == "" || f.Evidence.Attribute == "" {
		t.Fatalf("evidence must be non-empty, got %+v", f.Evidence)
	}
	neg := res("azurerm_mssql_server_vulnerability_assessment", "v", map[string]ir.Value{
		"recurring_scans": blks(2, blk("enabled", ks("true", 3))),
	})
	if got := runRule(mssqlNoVulnAssess{}, neg); len(got) != 0 {
		t.Fatalf("enabled scans must be quiet, got %d", len(got))
	}
}

// ---- shared replay helpers (ea- prefix; local to this file) ----

func eaB(b bool) ir.Value { return ir.Value{Raw: b, Known: true} }

func eaS(s string) ir.Value { return ir.Value{Raw: s, Known: true} }

func eaN(n float64) ir.Value { return ir.Value{Raw: n, Known: true} }

func eaL(items ...ir.Value) ir.Value { return ir.Value{Raw: items, Known: true} }

func eaM(pairs ...any) ir.Value {
	m := map[string]ir.Value{}
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i].(string)] = pairs[i+1].(ir.Value)
	}
	return ir.Value{Raw: m, Known: true}
}

func eaU() ir.Value { return ir.Value{Known: false} }

func eaRes(typ, name string, attrs map[string]ir.Value) ir.Resource {
	return ir.Resource{Type: typ, Name: name, Provider: "audit", Attributes: attrs}
}

// eaRun evaluates rule the way the engine does: CheckAll for
// cross-resource rules, Check per applicable resource otherwise.
func eaRun(rule ir.Rule, resources ...ir.Resource) []ir.Finding {
	var out []ir.Finding
	if cr, ok := rule.(ir.CrossResourceRule); ok {
		out = append(out, cr.CheckAll(resources)...)
	} else {
		for _, r := range resources {
			if rule.AppliesTo(r.Type) {
				out = append(out, rule.Check(r)...)
			}
		}
	}
	var filtered []ir.Finding
	for _, f := range out {
		if f.RuleID == rule.ID() {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// eaRuleFor looks a rule up by ID in this pack's registry.
func eaRuleFor(t *testing.T, id string) ir.Rule {
	t.Helper()
	for _, r := range Rules() {
		if r.ID() == id {
			return r
		}
	}
	t.Fatalf("rule %s not found in pack registry", id)
	return nil
}
func TestEffectivenessReplay_AZURE_030(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-030")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_storage_account", "probe", map[string]ir.Value{
			"blob_properties": eaM("AWS_SECRET_ACCESS_KEY", eaS("x"), "api_key", eaS("x"), "password", eaS("x"), "private_key", eaS("x"), "secret", eaS("x"), "token", eaS("x")),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-030: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-030: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-030: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_storage_account", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-030: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_storage_account", "probe", map[string]ir.Value{
		"AutoRenew":                         eaU(),
		"TLS1_2":                            eaU(),
		"TLS1_3":                            eaU(),
		"absent":                            eaU(),
		"action":                            eaU(),
		"blob_properties":                   eaU(),
		"certificate_policy":                eaU(),
		"container_delete_retention_policy": eaU(),
		"customer_managed_key":              eaU(),
		"days":                              eaU(),
		"delete_retention_policy":           eaU(),
		"empty":                             eaU(),
		"enable_rbac_authorization":         eaU(),
		"expiration_date":                   eaU(),
		"false":                             eaU(),
		"https_traffic_only_enabled":        eaU(),
		"infrastructure_encryption_enabled": eaU(),
		"lifetime_action":                   eaU(),
		"logging":                           eaU(),
		"min_tls_version":                   eaU(),
		"nfsv3_enabled":                     eaU(),
		"premium":                           eaU(),
		"public_network_access_enabled":     eaU(),
		"queue_properties":                  eaU(),
		"rotation_policy":                   eaU(),
		"shared_access_key_enabled":         eaU(),
		"sku_name":                          eaU(),
		"soft_delete_retention_days":        eaU(),
		"true":                              eaU(),
		"versioning_enabled":                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-030: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_037(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-037")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_key_vault", "probe", map[string]ir.Value{
			"AutoRenew":                         eaS("public"),
			"TLS1_2":                            eaS("public"),
			"TLS1_3":                            eaS("public"),
			"absent":                            eaS("public"),
			"action":                            eaL(eaS("*")),
			"blob_properties":                   eaS("public"),
			"certificate_policy":                eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"container_delete_retention_policy": eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"customer_managed_key":              eaS("password123"),
			"days":                              eaN(1.0),
			"delete_retention_policy":           eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"empty":                             eaS("public"),
			"enable_rbac_authorization":         eaB(false),
			"expiration_date":                   eaS("public"),
			"https_traffic_only_enabled":        eaB(false),
			"infrastructure_encryption_enabled": eaB(false),
			"lifetime_action":                   eaL(eaS("*")),
			"logging":                           eaB(false),
			"min_tls_version":                   eaS("TLS1.0"),
			"nfsv3_enabled":                     eaB(false),
			"premium":                           eaS("public"),
			"public_network_access_enabled":     eaS("Allow"),
			"queue_properties":                  eaS("public"),
			"rotation_policy":                   eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"shared_access_key_enabled":         eaB(false),
			"sku_name":                          eaS("my_password"),
			"soft_delete_retention_days":        eaN(1.0),
			"versioning_enabled":                eaB(false),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-037: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-037: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-037: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_key_vault", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-037: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_key_vault", "probe", map[string]ir.Value{
		"AutoRenew":                         eaU(),
		"TLS1_2":                            eaU(),
		"TLS1_3":                            eaU(),
		"absent":                            eaU(),
		"action":                            eaU(),
		"blob_properties":                   eaU(),
		"certificate_policy":                eaU(),
		"container_delete_retention_policy": eaU(),
		"customer_managed_key":              eaU(),
		"days":                              eaU(),
		"delete_retention_policy":           eaU(),
		"empty":                             eaU(),
		"enable_rbac_authorization":         eaU(),
		"expiration_date":                   eaU(),
		"false":                             eaU(),
		"https_traffic_only_enabled":        eaU(),
		"infrastructure_encryption_enabled": eaU(),
		"lifetime_action":                   eaU(),
		"logging":                           eaU(),
		"min_tls_version":                   eaU(),
		"nfsv3_enabled":                     eaU(),
		"premium":                           eaU(),
		"public_network_access_enabled":     eaU(),
		"queue_properties":                  eaU(),
		"rotation_policy":                   eaU(),
		"shared_access_key_enabled":         eaU(),
		"sku_name":                          eaU(),
		"soft_delete_retention_days":        eaU(),
		"true":                              eaU(),
		"versioning_enabled":                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-037: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_041(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-041")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_key_vault_key", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-041: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-041: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-041: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_key_vault_key", "probe", map[string]ir.Value{
			"AutoRenew":                         eaS("public"),
			"TLS1_2":                            eaS("public"),
			"TLS1_3":                            eaS("public"),
			"absent":                            eaS("public"),
			"action":                            eaL(eaS("*")),
			"blob_properties":                   eaS("public"),
			"certificate_policy":                eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"container_delete_retention_policy": eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"customer_managed_key":              eaS("password123"),
			"days":                              eaN(1.0),
			"delete_retention_policy":           eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"empty":                             eaS("public"),
			"enable_rbac_authorization":         eaB(false),
			"expiration_date":                   eaS("public"),
			"https_traffic_only_enabled":        eaB(false),
			"infrastructure_encryption_enabled": eaB(false),
			"lifetime_action":                   eaL(eaS("*")),
			"logging":                           eaB(false),
			"min_tls_version":                   eaS("TLS1.0"),
			"nfsv3_enabled":                     eaB(false),
			"premium":                           eaS("public"),
			"public_network_access_enabled":     eaS("Allow"),
			"queue_properties":                  eaS("public"),
			"rotation_policy":                   eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"shared_access_key_enabled":         eaB(false),
			"sku_name":                          eaS("my_password"),
			"soft_delete_retention_days":        eaN(1.0),
			"versioning_enabled":                eaB(false),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-041: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_key_vault_key", "probe", map[string]ir.Value{
		"AutoRenew":                         eaU(),
		"TLS1_2":                            eaU(),
		"TLS1_3":                            eaU(),
		"absent":                            eaU(),
		"action":                            eaU(),
		"blob_properties":                   eaU(),
		"certificate_policy":                eaU(),
		"container_delete_retention_policy": eaU(),
		"customer_managed_key":              eaU(),
		"days":                              eaU(),
		"delete_retention_policy":           eaU(),
		"empty":                             eaU(),
		"enable_rbac_authorization":         eaU(),
		"expiration_date":                   eaU(),
		"false":                             eaU(),
		"https_traffic_only_enabled":        eaU(),
		"infrastructure_encryption_enabled": eaU(),
		"lifetime_action":                   eaU(),
		"logging":                           eaU(),
		"min_tls_version":                   eaU(),
		"nfsv3_enabled":                     eaU(),
		"premium":                           eaU(),
		"public_network_access_enabled":     eaU(),
		"queue_properties":                  eaU(),
		"rotation_policy":                   eaU(),
		"shared_access_key_enabled":         eaU(),
		"sku_name":                          eaU(),
		"soft_delete_retention_days":        eaU(),
		"true":                              eaU(),
		"versioning_enabled":                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-041: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_042(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-042")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_key_vault_certificate", "probe", map[string]ir.Value{
			"certificate_policy": eaL(eaM("AutoRenew", eaS("public"), "TLS1_2", eaS("public"), "TLS1_3", eaS("public"), "absent", eaS("public"), "action", eaL(eaS("*")), "blob_properties", eaS("public"), "certificate_policy", eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"), "container_delete_retention_policy", eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"), "customer_managed_key", eaS("password123"), "days", eaN(1.0), "delete_retention_policy", eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"), "empty", eaS("public"), "enable_rbac_authorization", eaB(false), "expiration_date", eaS("public"), "https_traffic_only_enabled", eaB(false), "infrastructure_encryption_enabled", eaB(false), "lifetime_action", eaL(eaS("*")), "logging", eaB(false), "min_tls_version", eaS("TLS1.0"), "nfsv3_enabled", eaB(false), "premium", eaS("public"), "public_network_access_enabled", eaS("Allow"), "queue_properties", eaS("public"), "rotation_policy", eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"), "shared_access_key_enabled", eaB(false), "sku_name", eaS("my_password"), "soft_delete_retention_days", eaN(1.0), "versioning_enabled", eaB(false))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-042: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-042: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-042: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_key_vault_certificate", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-042: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_key_vault_certificate", "probe", map[string]ir.Value{
		"AutoRenew":                         eaU(),
		"TLS1_2":                            eaU(),
		"TLS1_3":                            eaU(),
		"absent":                            eaU(),
		"action":                            eaU(),
		"blob_properties":                   eaU(),
		"certificate_policy":                eaU(),
		"container_delete_retention_policy": eaU(),
		"customer_managed_key":              eaU(),
		"days":                              eaU(),
		"delete_retention_policy":           eaU(),
		"empty":                             eaU(),
		"enable_rbac_authorization":         eaU(),
		"expiration_date":                   eaU(),
		"false":                             eaU(),
		"https_traffic_only_enabled":        eaU(),
		"infrastructure_encryption_enabled": eaU(),
		"lifetime_action":                   eaU(),
		"logging":                           eaU(),
		"min_tls_version":                   eaU(),
		"nfsv3_enabled":                     eaU(),
		"premium":                           eaU(),
		"public_network_access_enabled":     eaU(),
		"queue_properties":                  eaU(),
		"rotation_policy":                   eaU(),
		"shared_access_key_enabled":         eaU(),
		"sku_name":                          eaU(),
		"soft_delete_retention_days":        eaU(),
		"true":                              eaU(),
		"versioning_enabled":                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-042: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_046(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-046")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_mssql_server", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-046: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-046: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-046: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_mssql_server", "probe", map[string]ir.Value{
			"Allow":                               eaS("public"),
			"Inbound":                             eaS("public"),
			"Internet":                            eaB(true),
			"RDP":                                 eaS("public"),
			"SSH":                                 eaS("public"),
			"Tcp":                                 eaS("public"),
			"absent":                              eaS("public"),
			"access":                              eaS("Allow"),
			"azuread_administrator":               eaB(true),
			"ddos_protection_plan":                eaB(false),
			"destination_port_range":              eaS("3389"),
			"destination_port_ranges":             eaS("3389"),
			"direction":                           eaS("Inbound"),
			"dns_servers":                         eaS("public"),
			"enable":                              eaB(false),
			"enabled":                             eaB(false),
			"end_ip_address":                      eaS("http://example.com"),
			"extended_auditing_policy":            eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"protocol":                            eaS("Tcp"),
			"public_network_access_enabled":       eaS("Allow"),
			"recurring_scans":                     eaS("public"),
			"retention_days":                      eaN(1.0),
			"security_alert_policy":               eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"security_rule":                       eaB(false),
			"service_endpoints":                   eaS("LoadBalancer"),
			"short_term_retention_policy":         eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"source_address_prefix":               eaS("*"),
			"source_address_prefixes":             eaS("*"),
			"start_ip_address":                    eaS("http://example.com"),
			"transparent_data_encryption_enabled": eaB(false),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-046: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_mssql_server", "probe", map[string]ir.Value{
		"Allow":                               eaU(),
		"Inbound":                             eaU(),
		"Internet":                            eaU(),
		"RDP":                                 eaU(),
		"SSH":                                 eaU(),
		"Tcp":                                 eaU(),
		"absent":                              eaU(),
		"access":                              eaU(),
		"azuread_administrator":               eaU(),
		"ddos_protection_plan":                eaU(),
		"destination_port_range":              eaU(),
		"destination_port_ranges":             eaU(),
		"direction":                           eaU(),
		"dns_servers":                         eaU(),
		"enable":                              eaU(),
		"enabled":                             eaU(),
		"end_ip_address":                      eaU(),
		"extended_auditing_policy":            eaU(),
		"false":                               eaU(),
		"protocol":                            eaU(),
		"public_network_access_enabled":       eaU(),
		"recurring_scans":                     eaU(),
		"retention_days":                      eaU(),
		"security_alert_policy":               eaU(),
		"security_rule":                       eaU(),
		"service_endpoints":                   eaU(),
		"short_term_retention_policy":         eaU(),
		"source_address_prefix":               eaU(),
		"source_address_prefixes":             eaU(),
		"start_ip_address":                    eaU(),
		"transparent_data_encryption_enabled": eaU(),
		"true":                                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-046: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_051(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-051")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_mssql_server_vulnerability_assessment", "probe", map[string]ir.Value{
			"recurring_scans": eaL(eaM("Allow", eaS(""), "Inbound", eaS(""), "Internet", eaS(""), "RDP", eaS(""), "SSH", eaS(""), "Tcp", eaS(""), "absent", eaS(""), "access", eaS(""), "azuread_administrator", eaS(""), "ddos_protection_plan", eaS(""), "destination_port_range", eaS(""), "destination_port_ranges", eaS(""), "direction", eaS(""), "dns_servers", eaS(""), "enable", eaS(""), "enabled", eaS(""), "end_ip_address", eaS(""), "extended_auditing_policy", eaS(""), "protocol", eaS(""), "public_network_access_enabled", eaS(""), "recurring_scans", eaS(""), "retention_days", eaS(""), "security_alert_policy", eaS(""), "security_rule", eaS(""), "service_endpoints", eaS(""), "short_term_retention_policy", eaS(""), "source_address_prefix", eaS(""), "source_address_prefixes", eaS(""), "start_ip_address", eaS(""), "transparent_data_encryption_enabled", eaS(""))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-051: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-051: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-051: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_mssql_server_vulnerability_assessment", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-051: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_mssql_server_vulnerability_assessment", "probe", map[string]ir.Value{
		"Allow":                               eaU(),
		"Inbound":                             eaU(),
		"Internet":                            eaU(),
		"RDP":                                 eaU(),
		"SSH":                                 eaU(),
		"Tcp":                                 eaU(),
		"absent":                              eaU(),
		"access":                              eaU(),
		"azuread_administrator":               eaU(),
		"ddos_protection_plan":                eaU(),
		"destination_port_range":              eaU(),
		"destination_port_ranges":             eaU(),
		"direction":                           eaU(),
		"dns_servers":                         eaU(),
		"enable":                              eaU(),
		"enabled":                             eaU(),
		"end_ip_address":                      eaU(),
		"extended_auditing_policy":            eaU(),
		"false":                               eaU(),
		"protocol":                            eaU(),
		"public_network_access_enabled":       eaU(),
		"recurring_scans":                     eaU(),
		"retention_days":                      eaU(),
		"security_alert_policy":               eaU(),
		"security_rule":                       eaU(),
		"service_endpoints":                   eaU(),
		"short_term_retention_policy":         eaU(),
		"source_address_prefix":               eaU(),
		"source_address_prefixes":             eaU(),
		"start_ip_address":                    eaU(),
		"transparent_data_encryption_enabled": eaU(),
		"true":                                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-051: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_052(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-052")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_mssql_database", "probe", map[string]ir.Value{
			"short_term_retention_policy": eaL(eaM("Allow", eaS("public"), "Inbound", eaS("public"), "Internet", eaB(true), "RDP", eaS("public"), "SSH", eaS("public"), "Tcp", eaS("public"), "absent", eaS("public"), "access", eaS("Allow"), "azuread_administrator", eaB(true), "ddos_protection_plan", eaB(false), "destination_port_range", eaS("3389"), "destination_port_ranges", eaS("3389"), "direction", eaS("Inbound"), "dns_servers", eaS("public"), "enable", eaB(false), "enabled", eaB(false), "end_ip_address", eaS("http://example.com"), "extended_auditing_policy", eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"), "protocol", eaS("Tcp"), "public_network_access_enabled", eaS("Allow"), "recurring_scans", eaS("public"), "retention_days", eaN(1.0), "security_alert_policy", eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"), "security_rule", eaB(false), "service_endpoints", eaS("LoadBalancer"), "short_term_retention_policy", eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"), "source_address_prefix", eaS("*"), "source_address_prefixes", eaS("*"), "start_ip_address", eaS("http://example.com"), "transparent_data_encryption_enabled", eaB(false))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-052: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-052: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-052: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_mssql_database", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-052: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_mssql_database", "probe", map[string]ir.Value{
		"Allow":                               eaU(),
		"Inbound":                             eaU(),
		"Internet":                            eaU(),
		"RDP":                                 eaU(),
		"SSH":                                 eaU(),
		"Tcp":                                 eaU(),
		"absent":                              eaU(),
		"access":                              eaU(),
		"azuread_administrator":               eaU(),
		"ddos_protection_plan":                eaU(),
		"destination_port_range":              eaU(),
		"destination_port_ranges":             eaU(),
		"direction":                           eaU(),
		"dns_servers":                         eaU(),
		"enable":                              eaU(),
		"enabled":                             eaU(),
		"end_ip_address":                      eaU(),
		"extended_auditing_policy":            eaU(),
		"false":                               eaU(),
		"protocol":                            eaU(),
		"public_network_access_enabled":       eaU(),
		"recurring_scans":                     eaU(),
		"retention_days":                      eaU(),
		"security_alert_policy":               eaU(),
		"security_rule":                       eaU(),
		"service_endpoints":                   eaU(),
		"short_term_retention_policy":         eaU(),
		"source_address_prefix":               eaU(),
		"source_address_prefixes":             eaU(),
		"start_ip_address":                    eaU(),
		"transparent_data_encryption_enabled": eaU(),
		"true":                                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-052: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_056(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-056")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_network_watcher_flow_log", "probe", map[string]ir.Value{
			"Allow":                               eaS("public"),
			"Inbound":                             eaS("public"),
			"Internet":                            eaB(true),
			"RDP":                                 eaS("public"),
			"SSH":                                 eaS("public"),
			"Tcp":                                 eaS("public"),
			"absent":                              eaS("public"),
			"access":                              eaS("Allow"),
			"azuread_administrator":               eaB(true),
			"ddos_protection_plan":                eaB(false),
			"destination_port_range":              eaS("3389"),
			"destination_port_ranges":             eaS("3389"),
			"direction":                           eaS("Inbound"),
			"dns_servers":                         eaS("public"),
			"enable":                              eaB(false),
			"enabled":                             eaB(false),
			"end_ip_address":                      eaS("http://example.com"),
			"extended_auditing_policy":            eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"protocol":                            eaS("Tcp"),
			"public_network_access_enabled":       eaS("Allow"),
			"recurring_scans":                     eaS("public"),
			"retention_days":                      eaN(1.0),
			"security_alert_policy":               eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"security_rule":                       eaB(false),
			"service_endpoints":                   eaS("LoadBalancer"),
			"short_term_retention_policy":         eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"source_address_prefix":               eaS("*"),
			"source_address_prefixes":             eaS("*"),
			"start_ip_address":                    eaS("http://example.com"),
			"transparent_data_encryption_enabled": eaB(false),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-056: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-056: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-056: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_network_watcher_flow_log", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-056: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_network_watcher_flow_log", "probe", map[string]ir.Value{
		"Allow":                               eaU(),
		"Inbound":                             eaU(),
		"Internet":                            eaU(),
		"RDP":                                 eaU(),
		"SSH":                                 eaU(),
		"Tcp":                                 eaU(),
		"absent":                              eaU(),
		"access":                              eaU(),
		"azuread_administrator":               eaU(),
		"ddos_protection_plan":                eaU(),
		"destination_port_range":              eaU(),
		"destination_port_ranges":             eaU(),
		"direction":                           eaU(),
		"dns_servers":                         eaU(),
		"enable":                              eaU(),
		"enabled":                             eaU(),
		"end_ip_address":                      eaU(),
		"extended_auditing_policy":            eaU(),
		"false":                               eaU(),
		"protocol":                            eaU(),
		"public_network_access_enabled":       eaU(),
		"recurring_scans":                     eaU(),
		"retention_days":                      eaU(),
		"security_alert_policy":               eaU(),
		"security_rule":                       eaU(),
		"service_endpoints":                   eaU(),
		"short_term_retention_policy":         eaU(),
		"source_address_prefix":               eaU(),
		"source_address_prefixes":             eaU(),
		"start_ip_address":                    eaU(),
		"transparent_data_encryption_enabled": eaU(),
		"true":                                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-056: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_057(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-057")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_virtual_network", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-057: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-057: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-057: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_virtual_network", "probe", map[string]ir.Value{
			"Allow":                               eaS("public"),
			"Inbound":                             eaS("public"),
			"Internet":                            eaB(true),
			"RDP":                                 eaS("public"),
			"SSH":                                 eaS("public"),
			"Tcp":                                 eaS("public"),
			"absent":                              eaS("public"),
			"access":                              eaS("Allow"),
			"azuread_administrator":               eaB(true),
			"ddos_protection_plan":                eaB(false),
			"destination_port_range":              eaS("3389"),
			"destination_port_ranges":             eaS("3389"),
			"direction":                           eaS("Inbound"),
			"dns_servers":                         eaS("public"),
			"enable":                              eaB(false),
			"enabled":                             eaB(false),
			"end_ip_address":                      eaS("http://example.com"),
			"extended_auditing_policy":            eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"protocol":                            eaS("Tcp"),
			"public_network_access_enabled":       eaS("Allow"),
			"recurring_scans":                     eaS("public"),
			"retention_days":                      eaN(1.0),
			"security_alert_policy":               eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"security_rule":                       eaB(false),
			"service_endpoints":                   eaS("LoadBalancer"),
			"short_term_retention_policy":         eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"source_address_prefix":               eaS("*"),
			"source_address_prefixes":             eaS("*"),
			"start_ip_address":                    eaS("http://example.com"),
			"transparent_data_encryption_enabled": eaB(false),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-057: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_virtual_network", "probe", map[string]ir.Value{
		"Allow":                               eaU(),
		"Inbound":                             eaU(),
		"Internet":                            eaU(),
		"RDP":                                 eaU(),
		"SSH":                                 eaU(),
		"Tcp":                                 eaU(),
		"absent":                              eaU(),
		"access":                              eaU(),
		"azuread_administrator":               eaU(),
		"ddos_protection_plan":                eaU(),
		"destination_port_range":              eaU(),
		"destination_port_ranges":             eaU(),
		"direction":                           eaU(),
		"dns_servers":                         eaU(),
		"enable":                              eaU(),
		"enabled":                             eaU(),
		"end_ip_address":                      eaU(),
		"extended_auditing_policy":            eaU(),
		"false":                               eaU(),
		"protocol":                            eaU(),
		"public_network_access_enabled":       eaU(),
		"recurring_scans":                     eaU(),
		"retention_days":                      eaU(),
		"security_alert_policy":               eaU(),
		"security_rule":                       eaU(),
		"service_endpoints":                   eaU(),
		"short_term_retention_policy":         eaU(),
		"source_address_prefix":               eaU(),
		"source_address_prefixes":             eaU(),
		"start_ip_address":                    eaU(),
		"transparent_data_encryption_enabled": eaU(),
		"true":                                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-057: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_058(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-058")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_virtual_network", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-058: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-058: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-058: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_virtual_network", "probe", map[string]ir.Value{
			"dns_servers": eaL(eaS(""), eaS("")),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-058: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_060(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-060")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_subnet", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-060: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-060: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-060: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_subnet", "probe", map[string]ir.Value{
			"service_endpoints": eaL(eaS(""), eaS("")),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-060: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_062(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-062")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_app_service", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-062: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-062: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-062: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_app_service", "probe", map[string]ir.Value{
			"AutomaticByPlatform":       eaS("public"),
			"Disabled":                  eaB(true),
			"FtpsOnly":                  eaS("public"),
			"absent":                    eaS("public"),
			"addon_profile":             eaS("public"),
			"api_server_access_profile": eaS("Allow"),
			"auth_settings":             eaS("public"),
			"authorized_ip_ranges":      eaL(eaS("0.0.0.0/0")),
			"automatic_upgrade_channel": eaS("public"),
			"azure_policy":              eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"default_node_pool":         eaS("public"),
			"disk_encryption_set_id":    eaB(false),
			"enabled":                   eaB(false),
			"ftps_state":                eaS("public"),
			"health_check_path":         eaB(false),
			"https_only":                eaS("public"),
			"identity":                  eaS("public"),
			"ip_configuration":          eaS("public"),
			"min_tls_version":           eaS("TLS1.0"),
			"none":                      eaS("public"),
			"oidc_issuer_enabled":       eaB(false),
			"oms_agent":                 eaS("public"),
			"os_disk":                   eaS("public"),
			"patch_mode":                eaS("public"),
			"private_cluster_enabled":   eaB(false),
			"public_ip_address_id":      eaB(true),
			"remote_debugging_enabled":  eaB(false),
			"site_config":               eaS("public"),
			"virtual_network_subnet_id": eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-062: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_app_service", "probe", map[string]ir.Value{
		"AutomaticByPlatform":       eaU(),
		"Disabled":                  eaU(),
		"FtpsOnly":                  eaU(),
		"absent":                    eaU(),
		"addon_profile":             eaU(),
		"api_server_access_profile": eaU(),
		"auth_settings":             eaU(),
		"authorized_ip_ranges":      eaU(),
		"automatic_upgrade_channel": eaU(),
		"azure_policy":              eaU(),
		"default_node_pool":         eaU(),
		"disk_encryption_set_id":    eaU(),
		"enabled":                   eaU(),
		"false":                     eaU(),
		"ftps_state":                eaU(),
		"health_check_path":         eaU(),
		"https_only":                eaU(),
		"identity":                  eaU(),
		"ip_configuration":          eaU(),
		"min_tls_version":           eaU(),
		"none":                      eaU(),
		"oidc_issuer_enabled":       eaU(),
		"oms_agent":                 eaU(),
		"os_disk":                   eaU(),
		"patch_mode":                eaU(),
		"private_cluster_enabled":   eaU(),
		"public_ip_address_id":      eaU(),
		"remote_debugging_enabled":  eaU(),
		"site_config":               eaU(),
		"true":                      eaU(),
		"virtual_network_subnet_id": eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-062: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_063(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-063")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_app_service", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-063: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-063: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-063: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_app_service", "probe", map[string]ir.Value{
			"AutomaticByPlatform":       eaS("public"),
			"Disabled":                  eaB(true),
			"FtpsOnly":                  eaS("public"),
			"absent":                    eaS("public"),
			"addon_profile":             eaS("public"),
			"api_server_access_profile": eaS("Allow"),
			"auth_settings":             eaS("public"),
			"authorized_ip_ranges":      eaL(eaS("0.0.0.0/0")),
			"automatic_upgrade_channel": eaS("public"),
			"azure_policy":              eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"default_node_pool":         eaS("public"),
			"disk_encryption_set_id":    eaB(false),
			"enabled":                   eaB(false),
			"ftps_state":                eaS("public"),
			"health_check_path":         eaB(false),
			"https_only":                eaS("public"),
			"identity":                  eaS("public"),
			"ip_configuration":          eaS("public"),
			"min_tls_version":           eaS("TLS1.0"),
			"none":                      eaS("public"),
			"oidc_issuer_enabled":       eaB(false),
			"oms_agent":                 eaS("public"),
			"os_disk":                   eaS("public"),
			"patch_mode":                eaS("public"),
			"private_cluster_enabled":   eaB(false),
			"public_ip_address_id":      eaB(true),
			"remote_debugging_enabled":  eaB(false),
			"site_config":               eaS("public"),
			"virtual_network_subnet_id": eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-063: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_app_service", "probe", map[string]ir.Value{
		"AutomaticByPlatform":       eaU(),
		"Disabled":                  eaU(),
		"FtpsOnly":                  eaU(),
		"absent":                    eaU(),
		"addon_profile":             eaU(),
		"api_server_access_profile": eaU(),
		"auth_settings":             eaU(),
		"authorized_ip_ranges":      eaU(),
		"automatic_upgrade_channel": eaU(),
		"azure_policy":              eaU(),
		"default_node_pool":         eaU(),
		"disk_encryption_set_id":    eaU(),
		"enabled":                   eaU(),
		"false":                     eaU(),
		"ftps_state":                eaU(),
		"health_check_path":         eaU(),
		"https_only":                eaU(),
		"identity":                  eaU(),
		"ip_configuration":          eaU(),
		"min_tls_version":           eaU(),
		"none":                      eaU(),
		"oidc_issuer_enabled":       eaU(),
		"oms_agent":                 eaU(),
		"os_disk":                   eaU(),
		"patch_mode":                eaU(),
		"private_cluster_enabled":   eaU(),
		"public_ip_address_id":      eaU(),
		"remote_debugging_enabled":  eaU(),
		"site_config":               eaU(),
		"true":                      eaU(),
		"virtual_network_subnet_id": eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-063: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_065(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-065")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_app_service", "probe", map[string]ir.Value{
			"site_config": eaL(eaM("AutomaticByPlatform", eaS("private"), "Disabled", eaB(false), "FtpsOnly", eaS("private"), "absent", eaS("private"), "addon_profile", eaS("private"), "api_server_access_profile", eaS("Deny"), "auth_settings", eaS("private"), "authorized_ip_ranges", eaL(eaS("10.0.0.0/8")), "automatic_upgrade_channel", eaS("private"), "azure_policy", eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"sts:AssumeRole\"}]}"), "default_node_pool", eaS("private"), "disk_encryption_set_id", eaB(true), "enabled", eaB(true), "ftps_state", eaS("private"), "health_check_path", eaB(true), "https_only", eaS("private"), "identity", eaS("private"), "ip_configuration", eaS("private"), "min_tls_version", eaS("TLS1.2"), "none", eaS("private"), "oidc_issuer_enabled", eaB(true), "oms_agent", eaS("private"), "os_disk", eaS("private"), "patch_mode", eaS("private"), "private_cluster_enabled", eaB(true), "public_ip_address_id", eaB(false), "remote_debugging_enabled", eaB(true), "site_config", eaS("private"), "virtual_network_subnet_id", eaS("private"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-065: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-065: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-065: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_app_service", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-065: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_app_service", "probe", map[string]ir.Value{
		"AutomaticByPlatform":       eaU(),
		"Disabled":                  eaU(),
		"FtpsOnly":                  eaU(),
		"absent":                    eaU(),
		"addon_profile":             eaU(),
		"api_server_access_profile": eaU(),
		"auth_settings":             eaU(),
		"authorized_ip_ranges":      eaU(),
		"automatic_upgrade_channel": eaU(),
		"azure_policy":              eaU(),
		"default_node_pool":         eaU(),
		"disk_encryption_set_id":    eaU(),
		"enabled":                   eaU(),
		"false":                     eaU(),
		"ftps_state":                eaU(),
		"health_check_path":         eaU(),
		"https_only":                eaU(),
		"identity":                  eaU(),
		"ip_configuration":          eaU(),
		"min_tls_version":           eaU(),
		"none":                      eaU(),
		"oidc_issuer_enabled":       eaU(),
		"oms_agent":                 eaU(),
		"os_disk":                   eaU(),
		"patch_mode":                eaU(),
		"private_cluster_enabled":   eaU(),
		"public_ip_address_id":      eaU(),
		"remote_debugging_enabled":  eaU(),
		"site_config":               eaU(),
		"true":                      eaU(),
		"virtual_network_subnet_id": eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-065: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_067(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-067")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_app_service_slot", "probe", map[string]ir.Value{
			"AutomaticByPlatform":       eaB(false),
			"Disabled":                  eaB(false),
			"FtpsOnly":                  eaB(false),
			"absent":                    eaB(false),
			"addon_profile":             eaB(false),
			"api_server_access_profile": eaB(false),
			"auth_settings":             eaB(false),
			"authorized_ip_ranges":      eaB(false),
			"automatic_upgrade_channel": eaB(false),
			"azure_policy":              eaB(false),
			"default_node_pool":         eaB(false),
			"disk_encryption_set_id":    eaB(false),
			"enabled":                   eaB(false),
			"ftps_state":                eaB(false),
			"health_check_path":         eaB(false),
			"https_only":                eaB(false),
			"identity":                  eaB(false),
			"ip_configuration":          eaB(false),
			"min_tls_version":           eaB(false),
			"none":                      eaB(false),
			"oidc_issuer_enabled":       eaB(false),
			"oms_agent":                 eaB(false),
			"os_disk":                   eaB(false),
			"patch_mode":                eaB(false),
			"private_cluster_enabled":   eaB(false),
			"public_ip_address_id":      eaB(false),
			"remote_debugging_enabled":  eaB(false),
			"site_config":               eaB(false),
			"virtual_network_subnet_id": eaB(false),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-067: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-067: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-067: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_app_service_slot", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-067: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_app_service_slot", "probe", map[string]ir.Value{
		"AutomaticByPlatform":       eaU(),
		"Disabled":                  eaU(),
		"FtpsOnly":                  eaU(),
		"absent":                    eaU(),
		"addon_profile":             eaU(),
		"api_server_access_profile": eaU(),
		"auth_settings":             eaU(),
		"authorized_ip_ranges":      eaU(),
		"automatic_upgrade_channel": eaU(),
		"azure_policy":              eaU(),
		"default_node_pool":         eaU(),
		"disk_encryption_set_id":    eaU(),
		"enabled":                   eaU(),
		"false":                     eaU(),
		"ftps_state":                eaU(),
		"health_check_path":         eaU(),
		"https_only":                eaU(),
		"identity":                  eaU(),
		"ip_configuration":          eaU(),
		"min_tls_version":           eaU(),
		"none":                      eaU(),
		"oidc_issuer_enabled":       eaU(),
		"oms_agent":                 eaU(),
		"os_disk":                   eaU(),
		"patch_mode":                eaU(),
		"private_cluster_enabled":   eaU(),
		"public_ip_address_id":      eaU(),
		"remote_debugging_enabled":  eaU(),
		"site_config":               eaU(),
		"true":                      eaU(),
		"virtual_network_subnet_id": eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-067: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_068(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-068")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_app_service", "probe", map[string]ir.Value{
			"site_config": eaL(eaM("AutomaticByPlatform", eaS("public"), "Disabled", eaB(true), "FtpsOnly", eaS("public"), "absent", eaS("public"), "addon_profile", eaS("public"), "api_server_access_profile", eaS("Allow"), "auth_settings", eaS("public"), "authorized_ip_ranges", eaL(eaS("0.0.0.0/0")), "automatic_upgrade_channel", eaS("public"), "azure_policy", eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"), "default_node_pool", eaS("public"), "disk_encryption_set_id", eaB(false), "enabled", eaB(false), "ftps_state", eaS("public"), "health_check_path", eaB(false), "https_only", eaS("public"), "identity", eaS("public"), "ip_configuration", eaS("public"), "min_tls_version", eaS("TLS1.0"), "none", eaS("public"), "oidc_issuer_enabled", eaB(false), "oms_agent", eaS("public"), "os_disk", eaS("public"), "patch_mode", eaS("public"), "private_cluster_enabled", eaB(false), "public_ip_address_id", eaB(true), "remote_debugging_enabled", eaB(false), "site_config", eaS("public"), "virtual_network_subnet_id", eaS("public"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-068: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-068: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-068: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_app_service", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-068: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_app_service", "probe", map[string]ir.Value{
		"AutomaticByPlatform":       eaU(),
		"Disabled":                  eaU(),
		"FtpsOnly":                  eaU(),
		"absent":                    eaU(),
		"addon_profile":             eaU(),
		"api_server_access_profile": eaU(),
		"auth_settings":             eaU(),
		"authorized_ip_ranges":      eaU(),
		"automatic_upgrade_channel": eaU(),
		"azure_policy":              eaU(),
		"default_node_pool":         eaU(),
		"disk_encryption_set_id":    eaU(),
		"enabled":                   eaU(),
		"false":                     eaU(),
		"ftps_state":                eaU(),
		"health_check_path":         eaU(),
		"https_only":                eaU(),
		"identity":                  eaU(),
		"ip_configuration":          eaU(),
		"min_tls_version":           eaU(),
		"none":                      eaU(),
		"oidc_issuer_enabled":       eaU(),
		"oms_agent":                 eaU(),
		"os_disk":                   eaU(),
		"patch_mode":                eaU(),
		"private_cluster_enabled":   eaU(),
		"public_ip_address_id":      eaU(),
		"remote_debugging_enabled":  eaU(),
		"site_config":               eaU(),
		"true":                      eaU(),
		"virtual_network_subnet_id": eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-068: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_070(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-070")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{
			"addon_profile": eaL(eaM("AutomaticByPlatform", eaS("public"), "Disabled", eaB(true), "FtpsOnly", eaS("public"), "absent", eaS("public"), "addon_profile", eaS("public"), "api_server_access_profile", eaS("Allow"), "auth_settings", eaS("public"), "authorized_ip_ranges", eaL(eaS("0.0.0.0/0")), "automatic_upgrade_channel", eaS("public"), "azure_policy", eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"), "default_node_pool", eaS("public"), "disk_encryption_set_id", eaB(false), "enabled", eaB(false), "ftps_state", eaS("public"), "health_check_path", eaB(false), "https_only", eaS("public"), "identity", eaS("public"), "ip_configuration", eaS("public"), "min_tls_version", eaS("TLS1.0"), "none", eaS("public"), "oidc_issuer_enabled", eaB(false), "oms_agent", eaS("public"), "os_disk", eaS("public"), "patch_mode", eaS("public"), "private_cluster_enabled", eaB(false), "public_ip_address_id", eaB(true), "remote_debugging_enabled", eaB(false), "site_config", eaS("public"), "virtual_network_subnet_id", eaS("public"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-070: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-070: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-070: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-070: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{
		"AutomaticByPlatform":       eaU(),
		"Disabled":                  eaU(),
		"FtpsOnly":                  eaU(),
		"absent":                    eaU(),
		"addon_profile":             eaU(),
		"api_server_access_profile": eaU(),
		"auth_settings":             eaU(),
		"authorized_ip_ranges":      eaU(),
		"automatic_upgrade_channel": eaU(),
		"azure_policy":              eaU(),
		"default_node_pool":         eaU(),
		"disk_encryption_set_id":    eaU(),
		"enabled":                   eaU(),
		"false":                     eaU(),
		"ftps_state":                eaU(),
		"health_check_path":         eaU(),
		"https_only":                eaU(),
		"identity":                  eaU(),
		"ip_configuration":          eaU(),
		"min_tls_version":           eaU(),
		"none":                      eaU(),
		"oidc_issuer_enabled":       eaU(),
		"oms_agent":                 eaU(),
		"os_disk":                   eaU(),
		"patch_mode":                eaU(),
		"private_cluster_enabled":   eaU(),
		"public_ip_address_id":      eaU(),
		"remote_debugging_enabled":  eaU(),
		"site_config":               eaU(),
		"true":                      eaU(),
		"virtual_network_subnet_id": eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-070: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_071(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-071")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{
			"addon_profile": eaL(eaM("AutomaticByPlatform", eaS("public"), "Disabled", eaB(true), "FtpsOnly", eaS("public"), "absent", eaS("public"), "addon_profile", eaS("public"), "api_server_access_profile", eaS("Allow"), "auth_settings", eaS("public"), "authorized_ip_ranges", eaL(eaS("0.0.0.0/0")), "automatic_upgrade_channel", eaS("public"), "azure_policy", eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"), "default_node_pool", eaS("public"), "disk_encryption_set_id", eaB(false), "enabled", eaB(false), "ftps_state", eaS("public"), "health_check_path", eaB(false), "https_only", eaS("public"), "identity", eaS("public"), "ip_configuration", eaS("public"), "min_tls_version", eaS("TLS1.0"), "none", eaS("public"), "oidc_issuer_enabled", eaB(false), "oms_agent", eaS("public"), "os_disk", eaS("public"), "patch_mode", eaS("public"), "private_cluster_enabled", eaB(false), "public_ip_address_id", eaB(true), "remote_debugging_enabled", eaB(false), "site_config", eaS("public"), "virtual_network_subnet_id", eaS("public"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-071: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-071: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-071: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-071: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{
		"AutomaticByPlatform":       eaU(),
		"Disabled":                  eaU(),
		"FtpsOnly":                  eaU(),
		"absent":                    eaU(),
		"addon_profile":             eaU(),
		"api_server_access_profile": eaU(),
		"auth_settings":             eaU(),
		"authorized_ip_ranges":      eaU(),
		"automatic_upgrade_channel": eaU(),
		"azure_policy":              eaU(),
		"default_node_pool":         eaU(),
		"disk_encryption_set_id":    eaU(),
		"enabled":                   eaU(),
		"false":                     eaU(),
		"ftps_state":                eaU(),
		"health_check_path":         eaU(),
		"https_only":                eaU(),
		"identity":                  eaU(),
		"ip_configuration":          eaU(),
		"min_tls_version":           eaU(),
		"none":                      eaU(),
		"oidc_issuer_enabled":       eaU(),
		"oms_agent":                 eaU(),
		"os_disk":                   eaU(),
		"patch_mode":                eaU(),
		"private_cluster_enabled":   eaU(),
		"public_ip_address_id":      eaU(),
		"remote_debugging_enabled":  eaU(),
		"site_config":               eaU(),
		"true":                      eaU(),
		"virtual_network_subnet_id": eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-071: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_074(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-074")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{
			"default_node_pool": eaM("AWS_SECRET_ACCESS_KEY", eaS("x"), "api_key", eaS("x"), "password", eaS("x"), "private_key", eaS("x"), "secret", eaS("x"), "token", eaS("x")),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-074: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-074: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-074: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-074: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{
		"AutomaticByPlatform":       eaU(),
		"Disabled":                  eaU(),
		"FtpsOnly":                  eaU(),
		"absent":                    eaU(),
		"addon_profile":             eaU(),
		"api_server_access_profile": eaU(),
		"auth_settings":             eaU(),
		"authorized_ip_ranges":      eaU(),
		"automatic_upgrade_channel": eaU(),
		"azure_policy":              eaU(),
		"default_node_pool":         eaU(),
		"disk_encryption_set_id":    eaU(),
		"enabled":                   eaU(),
		"false":                     eaU(),
		"ftps_state":                eaU(),
		"health_check_path":         eaU(),
		"https_only":                eaU(),
		"identity":                  eaU(),
		"ip_configuration":          eaU(),
		"min_tls_version":           eaU(),
		"none":                      eaU(),
		"oidc_issuer_enabled":       eaU(),
		"oms_agent":                 eaU(),
		"os_disk":                   eaU(),
		"patch_mode":                eaU(),
		"private_cluster_enabled":   eaU(),
		"public_ip_address_id":      eaU(),
		"remote_debugging_enabled":  eaU(),
		"site_config":               eaU(),
		"true":                      eaU(),
		"virtual_network_subnet_id": eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-074: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_076(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-076")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{
			"AutomaticByPlatform":       eaS("public"),
			"Disabled":                  eaB(true),
			"FtpsOnly":                  eaS("public"),
			"absent":                    eaS("public"),
			"addon_profile":             eaS("public"),
			"api_server_access_profile": eaS("Allow"),
			"auth_settings":             eaS("public"),
			"authorized_ip_ranges":      eaL(eaS("0.0.0.0/0")),
			"automatic_upgrade_channel": eaS("public"),
			"azure_policy":              eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"default_node_pool":         eaS("public"),
			"disk_encryption_set_id":    eaB(false),
			"enabled":                   eaB(false),
			"ftps_state":                eaS("public"),
			"health_check_path":         eaB(false),
			"https_only":                eaS("public"),
			"identity":                  eaS("public"),
			"ip_configuration":          eaS("public"),
			"min_tls_version":           eaS("TLS1.0"),
			"none":                      eaS("public"),
			"oidc_issuer_enabled":       eaB(false),
			"oms_agent":                 eaS("public"),
			"os_disk":                   eaS("public"),
			"patch_mode":                eaS("public"),
			"private_cluster_enabled":   eaB(false),
			"public_ip_address_id":      eaB(true),
			"remote_debugging_enabled":  eaB(false),
			"site_config":               eaS("public"),
			"virtual_network_subnet_id": eaS("public"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-076: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-076: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-076: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-076: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{
		"AutomaticByPlatform":       eaU(),
		"Disabled":                  eaU(),
		"FtpsOnly":                  eaU(),
		"absent":                    eaU(),
		"addon_profile":             eaU(),
		"api_server_access_profile": eaU(),
		"auth_settings":             eaU(),
		"authorized_ip_ranges":      eaU(),
		"automatic_upgrade_channel": eaU(),
		"azure_policy":              eaU(),
		"default_node_pool":         eaU(),
		"disk_encryption_set_id":    eaU(),
		"enabled":                   eaU(),
		"false":                     eaU(),
		"ftps_state":                eaU(),
		"health_check_path":         eaU(),
		"https_only":                eaU(),
		"identity":                  eaU(),
		"ip_configuration":          eaU(),
		"min_tls_version":           eaU(),
		"none":                      eaU(),
		"oidc_issuer_enabled":       eaU(),
		"oms_agent":                 eaU(),
		"os_disk":                   eaU(),
		"patch_mode":                eaU(),
		"private_cluster_enabled":   eaU(),
		"public_ip_address_id":      eaU(),
		"remote_debugging_enabled":  eaU(),
		"site_config":               eaU(),
		"true":                      eaU(),
		"virtual_network_subnet_id": eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-076: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_077(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-077")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_linux_virtual_machine", "probe", map[string]ir.Value{
			"os_disk": eaM("AWS_SECRET_ACCESS_KEY", eaS("x"), "api_key", eaS("x"), "password", eaS("x"), "private_key", eaS("x"), "secret", eaS("x"), "token", eaS("x")),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-077: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-077: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-077: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_linux_virtual_machine", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-077: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_linux_virtual_machine", "probe", map[string]ir.Value{
		"AutomaticByPlatform":       eaU(),
		"Disabled":                  eaU(),
		"FtpsOnly":                  eaU(),
		"absent":                    eaU(),
		"addon_profile":             eaU(),
		"api_server_access_profile": eaU(),
		"auth_settings":             eaU(),
		"authorized_ip_ranges":      eaU(),
		"automatic_upgrade_channel": eaU(),
		"azure_policy":              eaU(),
		"default_node_pool":         eaU(),
		"disk_encryption_set_id":    eaU(),
		"enabled":                   eaU(),
		"false":                     eaU(),
		"ftps_state":                eaU(),
		"health_check_path":         eaU(),
		"https_only":                eaU(),
		"identity":                  eaU(),
		"ip_configuration":          eaU(),
		"min_tls_version":           eaU(),
		"none":                      eaU(),
		"oidc_issuer_enabled":       eaU(),
		"oms_agent":                 eaU(),
		"os_disk":                   eaU(),
		"patch_mode":                eaU(),
		"private_cluster_enabled":   eaU(),
		"public_ip_address_id":      eaU(),
		"remote_debugging_enabled":  eaU(),
		"site_config":               eaU(),
		"true":                      eaU(),
		"virtual_network_subnet_id": eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-077: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_078(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-078")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_linux_virtual_machine", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-078: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-078: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-078: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_linux_virtual_machine", "probe", map[string]ir.Value{
			"AutomaticByPlatform":       eaS("public"),
			"Disabled":                  eaB(true),
			"FtpsOnly":                  eaS("public"),
			"absent":                    eaS("public"),
			"addon_profile":             eaS("public"),
			"api_server_access_profile": eaS("Allow"),
			"auth_settings":             eaS("public"),
			"authorized_ip_ranges":      eaL(eaS("0.0.0.0/0")),
			"automatic_upgrade_channel": eaS("public"),
			"azure_policy":              eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"default_node_pool":         eaS("public"),
			"disk_encryption_set_id":    eaB(false),
			"enabled":                   eaB(false),
			"ftps_state":                eaS("public"),
			"health_check_path":         eaB(false),
			"https_only":                eaS("public"),
			"identity":                  eaS("public"),
			"ip_configuration":          eaS("public"),
			"min_tls_version":           eaS("TLS1.0"),
			"none":                      eaS("public"),
			"oidc_issuer_enabled":       eaB(false),
			"oms_agent":                 eaS("public"),
			"os_disk":                   eaS("public"),
			"patch_mode":                eaS("public"),
			"private_cluster_enabled":   eaB(false),
			"public_ip_address_id":      eaB(true),
			"remote_debugging_enabled":  eaB(false),
			"site_config":               eaS("public"),
			"virtual_network_subnet_id": eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-078: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_linux_virtual_machine", "probe", map[string]ir.Value{
		"AutomaticByPlatform":       eaU(),
		"Disabled":                  eaU(),
		"FtpsOnly":                  eaU(),
		"absent":                    eaU(),
		"addon_profile":             eaU(),
		"api_server_access_profile": eaU(),
		"auth_settings":             eaU(),
		"authorized_ip_ranges":      eaU(),
		"automatic_upgrade_channel": eaU(),
		"azure_policy":              eaU(),
		"default_node_pool":         eaU(),
		"disk_encryption_set_id":    eaU(),
		"enabled":                   eaU(),
		"false":                     eaU(),
		"ftps_state":                eaU(),
		"health_check_path":         eaU(),
		"https_only":                eaU(),
		"identity":                  eaU(),
		"ip_configuration":          eaU(),
		"min_tls_version":           eaU(),
		"none":                      eaU(),
		"oidc_issuer_enabled":       eaU(),
		"oms_agent":                 eaU(),
		"os_disk":                   eaU(),
		"patch_mode":                eaU(),
		"private_cluster_enabled":   eaU(),
		"public_ip_address_id":      eaU(),
		"remote_debugging_enabled":  eaU(),
		"site_config":               eaU(),
		"true":                      eaU(),
		"virtual_network_subnet_id": eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-078: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_080(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-080")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_linux_virtual_machine", "probe", map[string]ir.Value{
			"AutomaticByPlatform":       eaS("public"),
			"Disabled":                  eaB(true),
			"FtpsOnly":                  eaS("public"),
			"absent":                    eaS("public"),
			"addon_profile":             eaS("public"),
			"api_server_access_profile": eaS("Allow"),
			"auth_settings":             eaS("public"),
			"authorized_ip_ranges":      eaL(eaS("0.0.0.0/0")),
			"automatic_upgrade_channel": eaS("public"),
			"azure_policy":              eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"default_node_pool":         eaS("public"),
			"disk_encryption_set_id":    eaB(false),
			"enabled":                   eaB(false),
			"ftps_state":                eaS("public"),
			"health_check_path":         eaB(false),
			"https_only":                eaS("public"),
			"identity":                  eaS("public"),
			"ip_configuration":          eaS("public"),
			"min_tls_version":           eaS("TLS1.0"),
			"none":                      eaS("public"),
			"oidc_issuer_enabled":       eaB(false),
			"oms_agent":                 eaS("public"),
			"os_disk":                   eaS("public"),
			"patch_mode":                eaS("public"),
			"private_cluster_enabled":   eaB(false),
			"public_ip_address_id":      eaB(true),
			"remote_debugging_enabled":  eaB(false),
			"site_config":               eaS("public"),
			"virtual_network_subnet_id": eaS("public"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-080: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-080: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-080: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_linux_virtual_machine", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-080: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_linux_virtual_machine", "probe", map[string]ir.Value{
		"AutomaticByPlatform":       eaU(),
		"Disabled":                  eaU(),
		"FtpsOnly":                  eaU(),
		"absent":                    eaU(),
		"addon_profile":             eaU(),
		"api_server_access_profile": eaU(),
		"auth_settings":             eaU(),
		"authorized_ip_ranges":      eaU(),
		"automatic_upgrade_channel": eaU(),
		"azure_policy":              eaU(),
		"default_node_pool":         eaU(),
		"disk_encryption_set_id":    eaU(),
		"enabled":                   eaU(),
		"false":                     eaU(),
		"ftps_state":                eaU(),
		"health_check_path":         eaU(),
		"https_only":                eaU(),
		"identity":                  eaU(),
		"ip_configuration":          eaU(),
		"min_tls_version":           eaU(),
		"none":                      eaU(),
		"oidc_issuer_enabled":       eaU(),
		"oms_agent":                 eaU(),
		"os_disk":                   eaU(),
		"patch_mode":                eaU(),
		"private_cluster_enabled":   eaU(),
		"public_ip_address_id":      eaU(),
		"remote_debugging_enabled":  eaU(),
		"site_config":               eaU(),
		"true":                      eaU(),
		"virtual_network_subnet_id": eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-080: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_082(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-082")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-082: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-082: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-082: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{
			"Eventual":                      eaS("public"),
			"HTTPS":                         eaS("public"),
			"Premium":                       eaS("public"),
			"absent":                        eaS("public"),
			"backup":                        eaB(false),
			"categories":                    eaS("public"),
			"consistency_level":             eaS("public"),
			"consistency_policy":            eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"customer_managed_key":          eaS("password123"),
			"days":                          eaN(1.0),
			"enabled":                       eaB(false),
			"frontend_endpoint":             eaS("http://example.com"),
			"georeplications":               eaS("public"),
			"ip_range_filter":               eaL(eaS("0.0.0.0/0")),
			"key_vault_key_id":              eaS("password123"),
			"monitor_config":                eaB(false),
			"network_rule_set":              eaS("public"),
			"protocol":                      eaS("Tcp"),
			"public_network_access_enabled": eaS("Allow"),
			"quarantine_policy":             eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"retention_in_days":             eaN(1.0),
			"retention_policy":              eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"sku":                           eaS("public"),
			"ssl_enforcement_enabled":       eaB(false),
			"trust_policy":                  eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"web_application_firewall_policy_link_id": eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-082: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{
		"Eventual":                      eaU(),
		"HTTPS":                         eaU(),
		"Premium":                       eaU(),
		"absent":                        eaU(),
		"backup":                        eaU(),
		"categories":                    eaU(),
		"consistency_level":             eaU(),
		"consistency_policy":            eaU(),
		"customer_managed_key":          eaU(),
		"days":                          eaU(),
		"enabled":                       eaU(),
		"false":                         eaU(),
		"frontend_endpoint":             eaU(),
		"georeplications":               eaU(),
		"ip_range_filter":               eaU(),
		"key_vault_key_id":              eaU(),
		"monitor_config":                eaU(),
		"network_rule_set":              eaU(),
		"protocol":                      eaU(),
		"public_network_access_enabled": eaU(),
		"quarantine_policy":             eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"sku":                           eaU(),
		"ssl_enforcement_enabled":       eaU(),
		"true":                          eaU(),
		"trust_policy":                  eaU(),
		"web_application_firewall_policy_link_id": eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-082: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_085(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-085")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-085: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-085: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-085: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{
			"Eventual":                      eaS("public"),
			"HTTPS":                         eaS("public"),
			"Premium":                       eaS("public"),
			"absent":                        eaS("public"),
			"backup":                        eaB(false),
			"categories":                    eaS("public"),
			"consistency_level":             eaS("public"),
			"consistency_policy":            eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"customer_managed_key":          eaS("password123"),
			"days":                          eaN(1.0),
			"enabled":                       eaB(false),
			"frontend_endpoint":             eaS("http://example.com"),
			"georeplications":               eaS("public"),
			"ip_range_filter":               eaL(eaS("0.0.0.0/0")),
			"key_vault_key_id":              eaS("password123"),
			"monitor_config":                eaB(false),
			"network_rule_set":              eaS("public"),
			"protocol":                      eaS("Tcp"),
			"public_network_access_enabled": eaS("Allow"),
			"quarantine_policy":             eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"retention_in_days":             eaN(1.0),
			"retention_policy":              eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"sku":                           eaS("public"),
			"ssl_enforcement_enabled":       eaB(false),
			"trust_policy":                  eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"web_application_firewall_policy_link_id": eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-085: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{
		"Eventual":                      eaU(),
		"HTTPS":                         eaU(),
		"Premium":                       eaU(),
		"absent":                        eaU(),
		"backup":                        eaU(),
		"categories":                    eaU(),
		"consistency_level":             eaU(),
		"consistency_policy":            eaU(),
		"customer_managed_key":          eaU(),
		"days":                          eaU(),
		"enabled":                       eaU(),
		"false":                         eaU(),
		"frontend_endpoint":             eaU(),
		"georeplications":               eaU(),
		"ip_range_filter":               eaU(),
		"key_vault_key_id":              eaU(),
		"monitor_config":                eaU(),
		"network_rule_set":              eaU(),
		"protocol":                      eaU(),
		"public_network_access_enabled": eaU(),
		"quarantine_policy":             eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"sku":                           eaU(),
		"ssl_enforcement_enabled":       eaU(),
		"true":                          eaU(),
		"trust_policy":                  eaU(),
		"web_application_firewall_policy_link_id": eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-085: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_088(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-088")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_container_registry", "probe", map[string]ir.Value{
			"trust_policy": eaL(eaM("Eventual", eaS(""), "HTTPS", eaS(""), "Premium", eaS(""), "absent", eaS(""), "backup", eaS(""), "categories", eaS(""), "consistency_level", eaS(""), "consistency_policy", eaS(""), "customer_managed_key", eaS(""), "days", eaS(""), "enabled", eaS(""), "frontend_endpoint", eaS(""), "georeplications", eaS(""), "ip_range_filter", eaS(""), "key_vault_key_id", eaS(""), "monitor_config", eaS(""), "network_rule_set", eaS(""), "protocol", eaS(""), "public_network_access_enabled", eaS(""), "quarantine_policy", eaS(""), "retention_in_days", eaS(""), "retention_policy", eaS(""), "sku", eaS(""), "ssl_enforcement_enabled", eaS(""), "trust_policy", eaS(""), "web_application_firewall_policy_link_id", eaS(""))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-088: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-088: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-088: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_container_registry", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-088: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_container_registry", "probe", map[string]ir.Value{
		"Eventual":                      eaU(),
		"HTTPS":                         eaU(),
		"Premium":                       eaU(),
		"absent":                        eaU(),
		"backup":                        eaU(),
		"categories":                    eaU(),
		"consistency_level":             eaU(),
		"consistency_policy":            eaU(),
		"customer_managed_key":          eaU(),
		"days":                          eaU(),
		"enabled":                       eaU(),
		"false":                         eaU(),
		"frontend_endpoint":             eaU(),
		"georeplications":               eaU(),
		"ip_range_filter":               eaU(),
		"key_vault_key_id":              eaU(),
		"monitor_config":                eaU(),
		"network_rule_set":              eaU(),
		"protocol":                      eaU(),
		"public_network_access_enabled": eaU(),
		"quarantine_policy":             eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"sku":                           eaU(),
		"ssl_enforcement_enabled":       eaU(),
		"true":                          eaU(),
		"trust_policy":                  eaU(),
		"web_application_firewall_policy_link_id": eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-088: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_089(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-089")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_container_registry", "probe", map[string]ir.Value{
			"quarantine_policy": eaL(eaM("Eventual", eaS(""), "HTTPS", eaS(""), "Premium", eaS(""), "absent", eaS(""), "backup", eaS(""), "categories", eaS(""), "consistency_level", eaS(""), "consistency_policy", eaS(""), "customer_managed_key", eaS(""), "days", eaS(""), "enabled", eaS(""), "frontend_endpoint", eaS(""), "georeplications", eaS(""), "ip_range_filter", eaS(""), "key_vault_key_id", eaS(""), "monitor_config", eaS(""), "network_rule_set", eaS(""), "protocol", eaS(""), "public_network_access_enabled", eaS(""), "quarantine_policy", eaS(""), "retention_in_days", eaS(""), "retention_policy", eaS(""), "sku", eaS(""), "ssl_enforcement_enabled", eaS(""), "trust_policy", eaS(""), "web_application_firewall_policy_link_id", eaS(""))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-089: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-089: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-089: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_container_registry", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-089: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_container_registry", "probe", map[string]ir.Value{
		"Eventual":                      eaU(),
		"HTTPS":                         eaU(),
		"Premium":                       eaU(),
		"absent":                        eaU(),
		"backup":                        eaU(),
		"categories":                    eaU(),
		"consistency_level":             eaU(),
		"consistency_policy":            eaU(),
		"customer_managed_key":          eaU(),
		"days":                          eaU(),
		"enabled":                       eaU(),
		"false":                         eaU(),
		"frontend_endpoint":             eaU(),
		"georeplications":               eaU(),
		"ip_range_filter":               eaU(),
		"key_vault_key_id":              eaU(),
		"monitor_config":                eaU(),
		"network_rule_set":              eaU(),
		"protocol":                      eaU(),
		"public_network_access_enabled": eaU(),
		"quarantine_policy":             eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"sku":                           eaU(),
		"ssl_enforcement_enabled":       eaU(),
		"true":                          eaU(),
		"trust_policy":                  eaU(),
		"web_application_firewall_policy_link_id": eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-089: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_090(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-090")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_container_registry", "probe", map[string]ir.Value{
			"Eventual":                      eaB(true),
			"HTTPS":                         eaB(true),
			"Premium":                       eaB(true),
			"absent":                        eaB(true),
			"backup":                        eaB(true),
			"categories":                    eaB(true),
			"consistency_level":             eaB(true),
			"consistency_policy":            eaB(true),
			"customer_managed_key":          eaB(true),
			"days":                          eaB(true),
			"enabled":                       eaB(true),
			"frontend_endpoint":             eaB(true),
			"georeplications":               eaB(true),
			"ip_range_filter":               eaB(true),
			"key_vault_key_id":              eaB(true),
			"monitor_config":                eaB(true),
			"network_rule_set":              eaB(true),
			"protocol":                      eaB(true),
			"public_network_access_enabled": eaB(true),
			"quarantine_policy":             eaB(true),
			"retention_in_days":             eaB(true),
			"retention_policy":              eaB(true),
			"sku":                           eaB(true),
			"ssl_enforcement_enabled":       eaB(true),
			"trust_policy":                  eaB(true),
			"web_application_firewall_policy_link_id": eaB(true),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-090: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-090: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-090: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_container_registry", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-090: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_container_registry", "probe", map[string]ir.Value{
		"Eventual":                      eaU(),
		"HTTPS":                         eaU(),
		"Premium":                       eaU(),
		"absent":                        eaU(),
		"backup":                        eaU(),
		"categories":                    eaU(),
		"consistency_level":             eaU(),
		"consistency_policy":            eaU(),
		"customer_managed_key":          eaU(),
		"days":                          eaU(),
		"enabled":                       eaU(),
		"false":                         eaU(),
		"frontend_endpoint":             eaU(),
		"georeplications":               eaU(),
		"ip_range_filter":               eaU(),
		"key_vault_key_id":              eaU(),
		"monitor_config":                eaU(),
		"network_rule_set":              eaU(),
		"protocol":                      eaU(),
		"public_network_access_enabled": eaU(),
		"quarantine_policy":             eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"sku":                           eaU(),
		"ssl_enforcement_enabled":       eaU(),
		"true":                          eaU(),
		"trust_policy":                  eaU(),
		"web_application_firewall_policy_link_id": eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-090: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_091(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-091")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_monitor_log_profile", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-091: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-091: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-091: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_monitor_log_profile", "probe", map[string]ir.Value{
			"categories": eaL(eaS(""), eaS("")),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-091: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_092(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-092")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_monitor_log_profile", "probe", map[string]ir.Value{
			"retention_policy": eaL(eaM("Eventual", eaS("public"), "HTTPS", eaS("public"), "Premium", eaS("public"), "absent", eaS("public"), "backup", eaB(false), "categories", eaS("public"), "consistency_level", eaS("public"), "consistency_policy", eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"), "customer_managed_key", eaS("password123"), "days", eaN(1.0), "enabled", eaB(false), "frontend_endpoint", eaS("http://example.com"), "georeplications", eaS("public"), "ip_range_filter", eaL(eaS("0.0.0.0/0")), "key_vault_key_id", eaS("password123"), "monitor_config", eaB(false), "network_rule_set", eaS("public"), "protocol", eaS("Tcp"), "public_network_access_enabled", eaS("Allow"), "quarantine_policy", eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"), "retention_in_days", eaN(1.0), "retention_policy", eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"), "sku", eaS("public"), "ssl_enforcement_enabled", eaB(false), "trust_policy", eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"), "web_application_firewall_policy_link_id", eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-092: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-092: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-092: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_monitor_log_profile", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-092: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_monitor_log_profile", "probe", map[string]ir.Value{
		"Eventual":                      eaU(),
		"HTTPS":                         eaU(),
		"Premium":                       eaU(),
		"absent":                        eaU(),
		"backup":                        eaU(),
		"categories":                    eaU(),
		"consistency_level":             eaU(),
		"consistency_policy":            eaU(),
		"customer_managed_key":          eaU(),
		"days":                          eaU(),
		"enabled":                       eaU(),
		"false":                         eaU(),
		"frontend_endpoint":             eaU(),
		"georeplications":               eaU(),
		"ip_range_filter":               eaU(),
		"key_vault_key_id":              eaU(),
		"monitor_config":                eaU(),
		"network_rule_set":              eaU(),
		"protocol":                      eaU(),
		"public_network_access_enabled": eaU(),
		"quarantine_policy":             eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"sku":                           eaU(),
		"ssl_enforcement_enabled":       eaU(),
		"true":                          eaU(),
		"trust_policy":                  eaU(),
		"web_application_firewall_policy_link_id": eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-092: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_093(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-093")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_application_insights", "probe", map[string]ir.Value{
			"Eventual":                      eaS("public"),
			"HTTPS":                         eaS("public"),
			"Premium":                       eaS("public"),
			"absent":                        eaS("public"),
			"backup":                        eaB(false),
			"categories":                    eaS("public"),
			"consistency_level":             eaS("public"),
			"consistency_policy":            eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"customer_managed_key":          eaS("password123"),
			"days":                          eaN(1.0),
			"enabled":                       eaB(false),
			"frontend_endpoint":             eaS("http://example.com"),
			"georeplications":               eaS("public"),
			"ip_range_filter":               eaL(eaS("0.0.0.0/0")),
			"key_vault_key_id":              eaS("password123"),
			"monitor_config":                eaB(false),
			"network_rule_set":              eaS("public"),
			"protocol":                      eaS("Tcp"),
			"public_network_access_enabled": eaS("Allow"),
			"quarantine_policy":             eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"retention_in_days":             eaN(1.0),
			"retention_policy":              eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"sku":                           eaS("public"),
			"ssl_enforcement_enabled":       eaB(false),
			"trust_policy":                  eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"web_application_firewall_policy_link_id": eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-093: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-093: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-093: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_application_insights", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-093: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_application_insights", "probe", map[string]ir.Value{
		"Eventual":                      eaU(),
		"HTTPS":                         eaU(),
		"Premium":                       eaU(),
		"absent":                        eaU(),
		"backup":                        eaU(),
		"categories":                    eaU(),
		"consistency_level":             eaU(),
		"consistency_policy":            eaU(),
		"customer_managed_key":          eaU(),
		"days":                          eaU(),
		"enabled":                       eaU(),
		"false":                         eaU(),
		"frontend_endpoint":             eaU(),
		"georeplications":               eaU(),
		"ip_range_filter":               eaU(),
		"key_vault_key_id":              eaU(),
		"monitor_config":                eaU(),
		"network_rule_set":              eaU(),
		"protocol":                      eaU(),
		"public_network_access_enabled": eaU(),
		"quarantine_policy":             eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"sku":                           eaU(),
		"ssl_enforcement_enabled":       eaU(),
		"true":                          eaU(),
		"trust_policy":                  eaU(),
		"web_application_firewall_policy_link_id": eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-093: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_094(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-094")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_eventhub_namespace", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-094: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-094: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-094: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_eventhub_namespace", "probe", map[string]ir.Value{
			"Eventual":                      eaS("public"),
			"HTTPS":                         eaS("public"),
			"Premium":                       eaS("public"),
			"absent":                        eaS("public"),
			"backup":                        eaB(false),
			"categories":                    eaS("public"),
			"consistency_level":             eaS("public"),
			"consistency_policy":            eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"customer_managed_key":          eaS("password123"),
			"days":                          eaN(1.0),
			"enabled":                       eaB(false),
			"frontend_endpoint":             eaS("http://example.com"),
			"georeplications":               eaS("public"),
			"ip_range_filter":               eaL(eaS("0.0.0.0/0")),
			"key_vault_key_id":              eaS("password123"),
			"monitor_config":                eaB(false),
			"network_rule_set":              eaS("public"),
			"protocol":                      eaS("Tcp"),
			"public_network_access_enabled": eaS("Allow"),
			"quarantine_policy":             eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"retention_in_days":             eaN(1.0),
			"retention_policy":              eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"sku":                           eaS("public"),
			"ssl_enforcement_enabled":       eaB(false),
			"trust_policy":                  eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"web_application_firewall_policy_link_id": eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-094: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_eventhub_namespace", "probe", map[string]ir.Value{
		"Eventual":                      eaU(),
		"HTTPS":                         eaU(),
		"Premium":                       eaU(),
		"absent":                        eaU(),
		"backup":                        eaU(),
		"categories":                    eaU(),
		"consistency_level":             eaU(),
		"consistency_policy":            eaU(),
		"customer_managed_key":          eaU(),
		"days":                          eaU(),
		"enabled":                       eaU(),
		"false":                         eaU(),
		"frontend_endpoint":             eaU(),
		"georeplications":               eaU(),
		"ip_range_filter":               eaU(),
		"key_vault_key_id":              eaU(),
		"monitor_config":                eaU(),
		"network_rule_set":              eaU(),
		"protocol":                      eaU(),
		"public_network_access_enabled": eaU(),
		"quarantine_policy":             eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"sku":                           eaU(),
		"ssl_enforcement_enabled":       eaU(),
		"true":                          eaU(),
		"trust_policy":                  eaU(),
		"web_application_firewall_policy_link_id": eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-094: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_095(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-095")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_servicebus_namespace", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-095: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-095: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-095: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_servicebus_namespace", "probe", map[string]ir.Value{
			"Eventual":                      eaS("public"),
			"HTTPS":                         eaS("public"),
			"Premium":                       eaS("public"),
			"absent":                        eaS("public"),
			"backup":                        eaB(false),
			"categories":                    eaS("public"),
			"consistency_level":             eaS("public"),
			"consistency_policy":            eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"customer_managed_key":          eaS("password123"),
			"days":                          eaN(1.0),
			"enabled":                       eaB(false),
			"frontend_endpoint":             eaS("http://example.com"),
			"georeplications":               eaS("public"),
			"ip_range_filter":               eaL(eaS("0.0.0.0/0")),
			"key_vault_key_id":              eaS("password123"),
			"monitor_config":                eaB(false),
			"network_rule_set":              eaS("public"),
			"protocol":                      eaS("Tcp"),
			"public_network_access_enabled": eaS("Allow"),
			"quarantine_policy":             eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"retention_in_days":             eaN(1.0),
			"retention_policy":              eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"sku":                           eaS("public"),
			"ssl_enforcement_enabled":       eaB(false),
			"trust_policy":                  eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"web_application_firewall_policy_link_id": eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-095: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_servicebus_namespace", "probe", map[string]ir.Value{
		"Eventual":                      eaU(),
		"HTTPS":                         eaU(),
		"Premium":                       eaU(),
		"absent":                        eaU(),
		"backup":                        eaU(),
		"categories":                    eaU(),
		"consistency_level":             eaU(),
		"consistency_policy":            eaU(),
		"customer_managed_key":          eaU(),
		"days":                          eaU(),
		"enabled":                       eaU(),
		"false":                         eaU(),
		"frontend_endpoint":             eaU(),
		"georeplications":               eaU(),
		"ip_range_filter":               eaU(),
		"key_vault_key_id":              eaU(),
		"monitor_config":                eaU(),
		"network_rule_set":              eaU(),
		"protocol":                      eaU(),
		"public_network_access_enabled": eaU(),
		"quarantine_policy":             eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"sku":                           eaU(),
		"ssl_enforcement_enabled":       eaU(),
		"true":                          eaU(),
		"trust_policy":                  eaU(),
		"web_application_firewall_policy_link_id": eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-095: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_099(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-099")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_frontdoor", "probe", map[string]ir.Value{
			"frontend_endpoint": eaM("AWS_SECRET_ACCESS_KEY", eaS("x"), "api_key", eaS("x"), "password", eaS("x"), "private_key", eaS("x"), "secret", eaS("x"), "token", eaS("x")),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-099: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-099: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-099: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_frontdoor", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-099: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_frontdoor", "probe", map[string]ir.Value{
		"Eventual":                      eaU(),
		"HTTPS":                         eaU(),
		"Premium":                       eaU(),
		"absent":                        eaU(),
		"backup":                        eaU(),
		"categories":                    eaU(),
		"consistency_level":             eaU(),
		"consistency_policy":            eaU(),
		"customer_managed_key":          eaU(),
		"days":                          eaU(),
		"enabled":                       eaU(),
		"false":                         eaU(),
		"frontend_endpoint":             eaU(),
		"georeplications":               eaU(),
		"ip_range_filter":               eaU(),
		"key_vault_key_id":              eaU(),
		"monitor_config":                eaU(),
		"network_rule_set":              eaU(),
		"protocol":                      eaU(),
		"public_network_access_enabled": eaU(),
		"quarantine_policy":             eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"sku":                           eaU(),
		"ssl_enforcement_enabled":       eaU(),
		"true":                          eaU(),
		"trust_policy":                  eaU(),
		"web_application_firewall_policy_link_id": eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-099: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_150(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-150")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_function_app", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-150: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-150: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-150: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_function_app", "probe", map[string]ir.Value{
			"None":                                 eaS("public"),
			"customer_managed_key":                 eaS("password123"),
			"data_exfiltration_protection_enabled": eaB(false),
			"https_only":                           eaS("public"),
			"identity":                             eaS("public"),
			"ip_restriction":                       eaB(false),
			"local_auth_enabled":                   eaB(false),
			"managed_virtual_network_enabled":      eaB(false),
			"public_network_access_enabled":        eaS("Allow"),
			"public_network_enabled":               eaB(true),
			"purge_protection_enabled":             eaB(false),
			"site_config":                          eaS("public"),
			"virtual_network_type":                 eaS("String"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-150: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_function_app", "probe", map[string]ir.Value{
		"None":                                 eaU(),
		"customer_managed_key":                 eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"false":                                eaU(),
		"https_only":                           eaU(),
		"identity":                             eaU(),
		"ip_restriction":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"public_network_access_enabled":        eaU(),
		"public_network_enabled":               eaU(),
		"purge_protection_enabled":             eaU(),
		"site_config":                          eaU(),
		"true":                                 eaU(),
		"virtual_network_type":                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-150: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_151(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-151")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_function_app", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-151: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-151: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-151: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_function_app", "probe", map[string]ir.Value{
			"None":                                 eaS("public"),
			"customer_managed_key":                 eaS("password123"),
			"data_exfiltration_protection_enabled": eaB(false),
			"https_only":                           eaS("public"),
			"identity":                             eaS("public"),
			"ip_restriction":                       eaB(false),
			"local_auth_enabled":                   eaB(false),
			"managed_virtual_network_enabled":      eaB(false),
			"public_network_access_enabled":        eaS("Allow"),
			"public_network_enabled":               eaB(true),
			"purge_protection_enabled":             eaB(false),
			"site_config":                          eaS("public"),
			"virtual_network_type":                 eaS("String"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-151: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_function_app", "probe", map[string]ir.Value{
		"None":                                 eaU(),
		"customer_managed_key":                 eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"false":                                eaU(),
		"https_only":                           eaU(),
		"identity":                             eaU(),
		"ip_restriction":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"public_network_access_enabled":        eaU(),
		"public_network_enabled":               eaU(),
		"purge_protection_enabled":             eaU(),
		"site_config":                          eaU(),
		"true":                                 eaU(),
		"virtual_network_type":                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-151: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_152(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-152")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_function_app", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-152: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-152: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-152: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_function_app", "probe", map[string]ir.Value{
			"None":                                 eaS("public"),
			"customer_managed_key":                 eaS("password123"),
			"data_exfiltration_protection_enabled": eaB(false),
			"https_only":                           eaS("public"),
			"identity":                             eaS("public"),
			"ip_restriction":                       eaB(false),
			"local_auth_enabled":                   eaB(false),
			"managed_virtual_network_enabled":      eaB(false),
			"public_network_access_enabled":        eaS("Allow"),
			"public_network_enabled":               eaB(true),
			"purge_protection_enabled":             eaB(false),
			"site_config":                          eaS("public"),
			"virtual_network_type":                 eaS("String"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-152: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_function_app", "probe", map[string]ir.Value{
		"None":                                 eaU(),
		"customer_managed_key":                 eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"false":                                eaU(),
		"https_only":                           eaU(),
		"identity":                             eaU(),
		"ip_restriction":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"public_network_access_enabled":        eaU(),
		"public_network_enabled":               eaU(),
		"purge_protection_enabled":             eaU(),
		"site_config":                          eaU(),
		"true":                                 eaU(),
		"virtual_network_type":                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-152: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_153(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-153")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_api_management", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-153: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-153: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-153: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_api_management", "probe", map[string]ir.Value{
			"None":                                 eaS("public"),
			"customer_managed_key":                 eaS("password123"),
			"data_exfiltration_protection_enabled": eaB(false),
			"https_only":                           eaS("public"),
			"identity":                             eaS("public"),
			"ip_restriction":                       eaB(false),
			"local_auth_enabled":                   eaB(false),
			"managed_virtual_network_enabled":      eaB(false),
			"public_network_access_enabled":        eaS("Allow"),
			"public_network_enabled":               eaB(true),
			"purge_protection_enabled":             eaB(false),
			"site_config":                          eaS("public"),
			"virtual_network_type":                 eaS("String"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-153: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_api_management", "probe", map[string]ir.Value{
		"None":                                 eaU(),
		"customer_managed_key":                 eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"false":                                eaU(),
		"https_only":                           eaU(),
		"identity":                             eaU(),
		"ip_restriction":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"public_network_access_enabled":        eaU(),
		"public_network_enabled":               eaU(),
		"purge_protection_enabled":             eaU(),
		"site_config":                          eaU(),
		"true":                                 eaU(),
		"virtual_network_type":                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-153: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_154(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-154")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_api_management", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-154: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-154: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-154: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_api_management", "probe", map[string]ir.Value{
			"None":                                 eaS("public"),
			"azurerm_api_management":               eaS("public"),
			"customer_managed_key":                 eaS("password123"),
			"data_exfiltration_protection_enabled": eaB(false),
			"https_only":                           eaS("public"),
			"identity":                             eaS("public"),
			"ip_restriction":                       eaB(false),
			"local_auth_enabled":                   eaB(false),
			"managed_virtual_network_enabled":      eaB(false),
			"public_network_access_enabled":        eaS("Allow"),
			"public_network_enabled":               eaB(true),
			"purge_protection_enabled":             eaB(false),
			"site_config":                          eaS("public"),
			"virtual_network_type":                 eaS("String"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-154: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_api_management", "probe", map[string]ir.Value{
		"None":                                 eaU(),
		"azurerm_api_management":               eaU(),
		"customer_managed_key":                 eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"false":                                eaU(),
		"https_only":                           eaU(),
		"identity":                             eaU(),
		"ip_restriction":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"public_network_access_enabled":        eaU(),
		"public_network_enabled":               eaU(),
		"purge_protection_enabled":             eaU(),
		"site_config":                          eaU(),
		"true":                                 eaU(),
		"virtual_network_type":                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-154: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_155(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-155")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_data_factory", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-155: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-155: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-155: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_data_factory", "probe", map[string]ir.Value{
			"None":                                 eaS("private"),
			"azurerm_data_factory":                 eaS("private"),
			"customer_managed_key":                 eaS("P@ssw0rd!2024Strong"),
			"data_exfiltration_protection_enabled": eaB(true),
			"https_only":                           eaS("private"),
			"identity":                             eaS("private"),
			"ip_restriction":                       eaB(true),
			"local_auth_enabled":                   eaB(true),
			"managed_virtual_network_enabled":      eaB(true),
			"public_network_access_enabled":        eaS("Deny"),
			"public_network_enabled":               eaB(false),
			"purge_protection_enabled":             eaB(true),
			"site_config":                          eaS("private"),
			"virtual_network_type":                 eaS("SecureString"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-155: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_data_factory", "probe", map[string]ir.Value{
		"None":                                 eaU(),
		"azurerm_data_factory":                 eaU(),
		"customer_managed_key":                 eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"false":                                eaU(),
		"https_only":                           eaU(),
		"identity":                             eaU(),
		"ip_restriction":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"public_network_access_enabled":        eaU(),
		"public_network_enabled":               eaU(),
		"purge_protection_enabled":             eaU(),
		"site_config":                          eaU(),
		"true":                                 eaU(),
		"virtual_network_type":                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-155: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_156(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-156")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_synapse_workspace", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-156: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-156: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-156: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_synapse_workspace", "probe", map[string]ir.Value{
			"None":                                 eaS("private"),
			"customer_managed_key":                 eaS("P@ssw0rd!2024Strong"),
			"data_exfiltration_protection_enabled": eaB(true),
			"https_only":                           eaS("private"),
			"identity":                             eaS("private"),
			"ip_restriction":                       eaB(true),
			"local_auth_enabled":                   eaB(true),
			"managed_virtual_network_enabled":      eaB(true),
			"public_network_access_enabled":        eaS("Deny"),
			"public_network_enabled":               eaB(false),
			"purge_protection_enabled":             eaB(true),
			"site_config":                          eaS("private"),
			"virtual_network_type":                 eaS("SecureString"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-156: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_synapse_workspace", "probe", map[string]ir.Value{
		"None":                                 eaU(),
		"customer_managed_key":                 eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"false":                                eaU(),
		"https_only":                           eaU(),
		"identity":                             eaU(),
		"ip_restriction":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"public_network_access_enabled":        eaU(),
		"public_network_enabled":               eaU(),
		"purge_protection_enabled":             eaU(),
		"site_config":                          eaU(),
		"true":                                 eaU(),
		"virtual_network_type":                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-156: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_157(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-157")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_synapse_workspace", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-157: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-157: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-157: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_synapse_workspace", "probe", map[string]ir.Value{
			"None":                                 eaS("private"),
			"customer_managed_key":                 eaS("P@ssw0rd!2024Strong"),
			"data_exfiltration_protection_enabled": eaB(true),
			"https_only":                           eaS("private"),
			"identity":                             eaS("private"),
			"ip_restriction":                       eaB(true),
			"local_auth_enabled":                   eaB(true),
			"managed_virtual_network_enabled":      eaB(true),
			"public_network_access_enabled":        eaS("Deny"),
			"public_network_enabled":               eaB(false),
			"purge_protection_enabled":             eaB(true),
			"site_config":                          eaS("private"),
			"virtual_network_type":                 eaS("SecureString"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-157: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_synapse_workspace", "probe", map[string]ir.Value{
		"None":                                 eaU(),
		"customer_managed_key":                 eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"false":                                eaU(),
		"https_only":                           eaU(),
		"identity":                             eaU(),
		"ip_restriction":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"public_network_access_enabled":        eaU(),
		"public_network_enabled":               eaU(),
		"purge_protection_enabled":             eaU(),
		"site_config":                          eaU(),
		"true":                                 eaU(),
		"virtual_network_type":                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-157: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_158(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-158")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_databricks_workspace", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-158: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-158: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-158: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_databricks_workspace", "probe", map[string]ir.Value{
			"None":                                 eaS("public"),
			"customer_managed_key":                 eaS("password123"),
			"data_exfiltration_protection_enabled": eaB(false),
			"https_only":                           eaS("public"),
			"identity":                             eaS("public"),
			"ip_restriction":                       eaB(false),
			"local_auth_enabled":                   eaB(false),
			"managed_virtual_network_enabled":      eaB(false),
			"public_network_access_enabled":        eaS("Allow"),
			"public_network_enabled":               eaB(true),
			"purge_protection_enabled":             eaB(false),
			"site_config":                          eaS("public"),
			"virtual_network_type":                 eaS("String"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-158: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_databricks_workspace", "probe", map[string]ir.Value{
		"None":                                 eaU(),
		"customer_managed_key":                 eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"false":                                eaU(),
		"https_only":                           eaU(),
		"identity":                             eaU(),
		"ip_restriction":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"public_network_access_enabled":        eaU(),
		"public_network_enabled":               eaU(),
		"purge_protection_enabled":             eaU(),
		"site_config":                          eaU(),
		"true":                                 eaU(),
		"virtual_network_type":                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-158: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_159(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-159")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_databricks_workspace", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-159: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-159: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-159: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_databricks_workspace", "probe", map[string]ir.Value{
			"None":                                 eaS("public"),
			"azurerm_databricks_workspace":         eaS("public"),
			"customer_managed_key":                 eaS("password123"),
			"data_exfiltration_protection_enabled": eaB(false),
			"https_only":                           eaS("public"),
			"identity":                             eaS("public"),
			"ip_restriction":                       eaB(false),
			"local_auth_enabled":                   eaB(false),
			"managed_virtual_network_enabled":      eaB(false),
			"public_network_access_enabled":        eaS("Allow"),
			"public_network_enabled":               eaB(true),
			"purge_protection_enabled":             eaB(false),
			"site_config":                          eaS("public"),
			"virtual_network_type":                 eaS("String"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-159: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_databricks_workspace", "probe", map[string]ir.Value{
		"None":                                 eaU(),
		"azurerm_databricks_workspace":         eaU(),
		"customer_managed_key":                 eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"false":                                eaU(),
		"https_only":                           eaU(),
		"identity":                             eaU(),
		"ip_restriction":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"public_network_access_enabled":        eaU(),
		"public_network_enabled":               eaU(),
		"purge_protection_enabled":             eaU(),
		"site_config":                          eaU(),
		"true":                                 eaU(),
		"virtual_network_type":                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-159: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_160(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-160")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_eventgrid_domain", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-160: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-160: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-160: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_eventgrid_domain", "probe", map[string]ir.Value{
			"None":                                 eaS("public"),
			"customer_managed_key":                 eaS("password123"),
			"data_exfiltration_protection_enabled": eaB(false),
			"https_only":                           eaS("public"),
			"identity":                             eaS("public"),
			"ip_restriction":                       eaB(false),
			"local_auth_enabled":                   eaB(false),
			"managed_virtual_network_enabled":      eaB(false),
			"public_network_access_enabled":        eaS("Allow"),
			"public_network_enabled":               eaB(true),
			"purge_protection_enabled":             eaB(false),
			"site_config":                          eaS("public"),
			"virtual_network_type":                 eaS("String"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-160: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_eventgrid_domain", "probe", map[string]ir.Value{
		"None":                                 eaU(),
		"customer_managed_key":                 eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"false":                                eaU(),
		"https_only":                           eaU(),
		"identity":                             eaU(),
		"ip_restriction":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"public_network_access_enabled":        eaU(),
		"public_network_enabled":               eaU(),
		"purge_protection_enabled":             eaU(),
		"site_config":                          eaU(),
		"true":                                 eaU(),
		"virtual_network_type":                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-160: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_161(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-161")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_eventgrid_domain", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-161: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-161: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-161: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_eventgrid_domain", "probe", map[string]ir.Value{
			"None":                                 eaS("public"),
			"customer_managed_key":                 eaS("password123"),
			"data_exfiltration_protection_enabled": eaB(false),
			"https_only":                           eaS("public"),
			"identity":                             eaS("public"),
			"ip_restriction":                       eaB(false),
			"local_auth_enabled":                   eaB(false),
			"managed_virtual_network_enabled":      eaB(false),
			"public_network_access_enabled":        eaS("Allow"),
			"public_network_enabled":               eaB(true),
			"purge_protection_enabled":             eaB(false),
			"site_config":                          eaS("public"),
			"virtual_network_type":                 eaS("String"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-161: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_eventgrid_domain", "probe", map[string]ir.Value{
		"None":                                 eaU(),
		"customer_managed_key":                 eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"false":                                eaU(),
		"https_only":                           eaU(),
		"identity":                             eaU(),
		"ip_restriction":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"public_network_access_enabled":        eaU(),
		"public_network_enabled":               eaU(),
		"purge_protection_enabled":             eaU(),
		"site_config":                          eaU(),
		"true":                                 eaU(),
		"virtual_network_type":                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-161: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_162(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-162")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_machine_learning_workspace", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-162: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-162: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-162: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_machine_learning_workspace", "probe", map[string]ir.Value{
			"None":                                 eaS("public"),
			"azurerm_machine_learning_workspace":   eaS("arn:aws:iam::123456789012:role/Other"),
			"customer_managed_key":                 eaS("password123"),
			"data_exfiltration_protection_enabled": eaB(false),
			"https_only":                           eaS("public"),
			"identity":                             eaS("public"),
			"ip_restriction":                       eaB(false),
			"local_auth_enabled":                   eaB(false),
			"managed_virtual_network_enabled":      eaB(false),
			"public_network_access_enabled":        eaS("Allow"),
			"public_network_enabled":               eaB(true),
			"purge_protection_enabled":             eaB(false),
			"site_config":                          eaS("public"),
			"virtual_network_type":                 eaS("String"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-162: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_machine_learning_workspace", "probe", map[string]ir.Value{
		"None":                                 eaU(),
		"azurerm_machine_learning_workspace":   eaU(),
		"customer_managed_key":                 eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"false":                                eaU(),
		"https_only":                           eaU(),
		"identity":                             eaU(),
		"ip_restriction":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"public_network_access_enabled":        eaU(),
		"public_network_enabled":               eaU(),
		"purge_protection_enabled":             eaU(),
		"site_config":                          eaU(),
		"true":                                 eaU(),
		"virtual_network_type":                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-162: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_163(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-163")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_app_configuration", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-163: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-163: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-163: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_app_configuration", "probe", map[string]ir.Value{
			"None":                                 eaS("private"),
			"customer_managed_key":                 eaS("P@ssw0rd!2024Strong"),
			"data_exfiltration_protection_enabled": eaB(true),
			"https_only":                           eaS("private"),
			"identity":                             eaS("private"),
			"ip_restriction":                       eaB(true),
			"local_auth_enabled":                   eaB(true),
			"managed_virtual_network_enabled":      eaB(true),
			"public_network_access_enabled":        eaS("Deny"),
			"public_network_enabled":               eaB(false),
			"purge_protection_enabled":             eaB(true),
			"site_config":                          eaS("private"),
			"virtual_network_type":                 eaS("SecureString"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-163: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_app_configuration", "probe", map[string]ir.Value{
		"None":                                 eaU(),
		"customer_managed_key":                 eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"false":                                eaU(),
		"https_only":                           eaU(),
		"identity":                             eaU(),
		"ip_restriction":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"public_network_access_enabled":        eaU(),
		"public_network_enabled":               eaU(),
		"purge_protection_enabled":             eaU(),
		"site_config":                          eaU(),
		"true":                                 eaU(),
		"virtual_network_type":                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-163: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_164(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-164")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_app_configuration", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-164: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-164: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-164: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_app_configuration", "probe", map[string]ir.Value{
			"None":                                 eaS("public"),
			"azurerm_app_configuration":            eaS("public"),
			"customer_managed_key":                 eaS("password123"),
			"data_exfiltration_protection_enabled": eaB(false),
			"https_only":                           eaS("public"),
			"identity":                             eaS("public"),
			"ip_restriction":                       eaB(false),
			"local_auth_enabled":                   eaB(false),
			"managed_virtual_network_enabled":      eaB(false),
			"public_network_access_enabled":        eaS("Allow"),
			"public_network_enabled":               eaB(true),
			"purge_protection_enabled":             eaB(false),
			"site_config":                          eaS("public"),
			"virtual_network_type":                 eaS("String"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-164: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_app_configuration", "probe", map[string]ir.Value{
		"None":                                 eaU(),
		"azurerm_app_configuration":            eaU(),
		"customer_managed_key":                 eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"false":                                eaU(),
		"https_only":                           eaU(),
		"identity":                             eaU(),
		"ip_restriction":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"public_network_access_enabled":        eaU(),
		"public_network_enabled":               eaU(),
		"purge_protection_enabled":             eaU(),
		"site_config":                          eaU(),
		"true":                                 eaU(),
		"virtual_network_type":                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-164: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_165(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-165")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_automation_account", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-165: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-165: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-165: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_automation_account", "probe", map[string]ir.Value{
			"None":                                 eaS("public"),
			"azurerm_automation_account":           eaN(0.0),
			"customer_managed_key":                 eaS("password123"),
			"data_exfiltration_protection_enabled": eaB(false),
			"https_only":                           eaS("public"),
			"identity":                             eaS("public"),
			"ip_restriction":                       eaB(false),
			"local_auth_enabled":                   eaB(false),
			"managed_virtual_network_enabled":      eaB(false),
			"public_network_access_enabled":        eaS("Allow"),
			"public_network_enabled":               eaB(true),
			"purge_protection_enabled":             eaB(false),
			"site_config":                          eaS("public"),
			"virtual_network_type":                 eaS("String"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-165: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_automation_account", "probe", map[string]ir.Value{
		"None":                                 eaU(),
		"azurerm_automation_account":           eaU(),
		"customer_managed_key":                 eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"false":                                eaU(),
		"https_only":                           eaU(),
		"identity":                             eaU(),
		"ip_restriction":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"public_network_access_enabled":        eaU(),
		"public_network_enabled":               eaU(),
		"purge_protection_enabled":             eaU(),
		"site_config":                          eaU(),
		"true":                                 eaU(),
		"virtual_network_type":                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-165: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_166(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-166")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_search_service", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-166: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-166: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-166: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_search_service", "probe", map[string]ir.Value{
			"None":                                 eaS("public"),
			"azurerm_search_service":               eaS("LoadBalancer"),
			"customer_managed_key":                 eaS("password123"),
			"data_exfiltration_protection_enabled": eaB(false),
			"https_only":                           eaS("public"),
			"identity":                             eaS("public"),
			"ip_restriction":                       eaB(false),
			"local_auth_enabled":                   eaB(false),
			"managed_virtual_network_enabled":      eaB(false),
			"public_network_access_enabled":        eaS("Allow"),
			"public_network_enabled":               eaB(true),
			"purge_protection_enabled":             eaB(false),
			"site_config":                          eaS("public"),
			"virtual_network_type":                 eaS("String"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-166: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_search_service", "probe", map[string]ir.Value{
		"None":                                 eaU(),
		"azurerm_search_service":               eaU(),
		"customer_managed_key":                 eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"false":                                eaU(),
		"https_only":                           eaU(),
		"identity":                             eaU(),
		"ip_restriction":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"public_network_access_enabled":        eaU(),
		"public_network_enabled":               eaU(),
		"purge_protection_enabled":             eaU(),
		"site_config":                          eaU(),
		"true":                                 eaU(),
		"virtual_network_type":                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-166: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_167(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-167")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_cognitive_account", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-167: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-167: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-167: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_cognitive_account", "probe", map[string]ir.Value{
			"None":                                 eaS("public"),
			"azurerm_cognitive_account":            eaN(0.0),
			"customer_managed_key":                 eaS("password123"),
			"data_exfiltration_protection_enabled": eaB(false),
			"https_only":                           eaS("public"),
			"identity":                             eaS("public"),
			"ip_restriction":                       eaB(false),
			"local_auth_enabled":                   eaB(false),
			"managed_virtual_network_enabled":      eaB(false),
			"public_network_access_enabled":        eaS("Allow"),
			"public_network_enabled":               eaB(true),
			"purge_protection_enabled":             eaB(false),
			"site_config":                          eaS("public"),
			"virtual_network_type":                 eaS("String"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-167: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_cognitive_account", "probe", map[string]ir.Value{
		"None":                                 eaU(),
		"azurerm_cognitive_account":            eaU(),
		"customer_managed_key":                 eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"false":                                eaU(),
		"https_only":                           eaU(),
		"identity":                             eaU(),
		"ip_restriction":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"public_network_access_enabled":        eaU(),
		"public_network_enabled":               eaU(),
		"purge_protection_enabled":             eaU(),
		"site_config":                          eaU(),
		"true":                                 eaU(),
		"virtual_network_type":                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-167: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_168(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-168")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_iothub", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-168: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-168: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-168: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_iothub", "probe", map[string]ir.Value{
			"None":                                 eaS("public"),
			"azurerm_iothub":                       eaS("public"),
			"customer_managed_key":                 eaS("password123"),
			"data_exfiltration_protection_enabled": eaB(false),
			"https_only":                           eaS("public"),
			"identity":                             eaS("public"),
			"ip_restriction":                       eaB(false),
			"local_auth_enabled":                   eaB(false),
			"managed_virtual_network_enabled":      eaB(false),
			"public_network_access_enabled":        eaS("Allow"),
			"public_network_enabled":               eaB(true),
			"purge_protection_enabled":             eaB(false),
			"site_config":                          eaS("public"),
			"virtual_network_type":                 eaS("String"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-168: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_iothub", "probe", map[string]ir.Value{
		"None":                                 eaU(),
		"azurerm_iothub":                       eaU(),
		"customer_managed_key":                 eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"false":                                eaU(),
		"https_only":                           eaU(),
		"identity":                             eaU(),
		"ip_restriction":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"public_network_access_enabled":        eaU(),
		"public_network_enabled":               eaU(),
		"purge_protection_enabled":             eaU(),
		"site_config":                          eaU(),
		"true":                                 eaU(),
		"virtual_network_type":                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-168: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_169(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-169")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_postgresql_flexible_server", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-169: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-169: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-169: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_postgresql_flexible_server", "probe", map[string]ir.Value{
			"None":                                 eaS("public"),
			"azurerm_postgresql_flexible_server":   eaS("public"),
			"customer_managed_key":                 eaS("password123"),
			"data_exfiltration_protection_enabled": eaB(false),
			"https_only":                           eaS("public"),
			"identity":                             eaS("public"),
			"ip_restriction":                       eaB(false),
			"local_auth_enabled":                   eaB(false),
			"managed_virtual_network_enabled":      eaB(false),
			"public_network_access_enabled":        eaS("Allow"),
			"public_network_enabled":               eaB(true),
			"purge_protection_enabled":             eaB(false),
			"site_config":                          eaS("public"),
			"virtual_network_type":                 eaS("String"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-169: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_postgresql_flexible_server", "probe", map[string]ir.Value{
		"None":                                 eaU(),
		"azurerm_postgresql_flexible_server":   eaU(),
		"customer_managed_key":                 eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"false":                                eaU(),
		"https_only":                           eaU(),
		"identity":                             eaU(),
		"ip_restriction":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"public_network_access_enabled":        eaU(),
		"public_network_enabled":               eaU(),
		"purge_protection_enabled":             eaU(),
		"site_config":                          eaU(),
		"true":                                 eaU(),
		"virtual_network_type":                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-169: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_170(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-170")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azuread_conditional_access_policy", "probe", map[string]ir.Value{
			"Contributor":             eaS("public"),
			"Owner":                   eaS("public"),
			"actions":                 eaL(eaS("*")),
			"certificate_permissions": eaL(eaS("*")),
			"enabled":                 eaB(false),
			"enforce":                 eaB(false),
			"identity":                eaS("public"),
			"key_permissions":         eaS("password123"),
			"password":                eaS("password123"),
			"permissions":             eaL(eaS("*")),
			"role_definition_name":    eaS("roles/owner"),
			"scope":                   eaS("public"),
			"secret_permissions":      eaS("password123"),
			"state":                   eaS("public"),
			"storage_permissions":     eaL(eaS("*")),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-170: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-170: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-170: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azuread_conditional_access_policy", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-170: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azuread_conditional_access_policy", "probe", map[string]ir.Value{
		"Contributor":             eaU(),
		"Owner":                   eaU(),
		"actions":                 eaU(),
		"certificate_permissions": eaU(),
		"enabled":                 eaU(),
		"enforce":                 eaU(),
		"false":                   eaU(),
		"identity":                eaU(),
		"key_permissions":         eaU(),
		"password":                eaU(),
		"permissions":             eaU(),
		"role_definition_name":    eaU(),
		"scope":                   eaU(),
		"secret_permissions":      eaU(),
		"state":                   eaU(),
		"storage_permissions":     eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-170: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_171(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-171")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_role_assignment", "probe", map[string]ir.Value{
			"Contributor":             eaS("Owner"),
			"Owner":                   eaS("Owner"),
			"actions":                 eaS("Owner"),
			"certificate_permissions": eaS("Owner"),
			"enabled":                 eaS("Owner"),
			"enforce":                 eaS("Owner"),
			"identity":                eaS("Owner"),
			"key_permissions":         eaS("Owner"),
			"password":                eaS("Owner"),
			"permissions":             eaS("Owner"),
			"role_definition_name":    eaS("Owner"),
			"scope":                   eaS("Owner"),
			"secret_permissions":      eaS("Owner"),
			"state":                   eaS("Owner"),
			"storage_permissions":     eaS("Owner"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-171: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-171: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-171: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_role_assignment", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-171: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_role_assignment", "probe", map[string]ir.Value{
		"Contributor":             eaU(),
		"Owner":                   eaU(),
		"actions":                 eaU(),
		"certificate_permissions": eaU(),
		"enabled":                 eaU(),
		"enforce":                 eaU(),
		"false":                   eaU(),
		"identity":                eaU(),
		"key_permissions":         eaU(),
		"password":                eaU(),
		"permissions":             eaU(),
		"role_definition_name":    eaU(),
		"scope":                   eaU(),
		"secret_permissions":      eaU(),
		"state":                   eaU(),
		"storage_permissions":     eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-171: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_172(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-172")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_role_definition", "probe", map[string]ir.Value{
			"permissions": eaL(eaM("Contributor", eaS("public"), "Owner", eaS("public"), "actions", eaL(eaS("*")), "certificate_permissions", eaL(eaS("*")), "enabled", eaB(false), "enforce", eaB(false), "identity", eaS("public"), "key_permissions", eaS("password123"), "password", eaS("password123"), "permissions", eaL(eaS("*")), "role_definition_name", eaS("roles/owner"), "scope", eaS("public"), "secret_permissions", eaS("password123"), "state", eaS("public"), "storage_permissions", eaL(eaS("*")))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-172: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-172: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-172: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_role_definition", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-172: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_role_definition", "probe", map[string]ir.Value{
		"Contributor":             eaU(),
		"Owner":                   eaU(),
		"actions":                 eaU(),
		"certificate_permissions": eaU(),
		"enabled":                 eaU(),
		"enforce":                 eaU(),
		"false":                   eaU(),
		"identity":                eaU(),
		"key_permissions":         eaU(),
		"password":                eaU(),
		"permissions":             eaU(),
		"role_definition_name":    eaU(),
		"scope":                   eaU(),
		"secret_permissions":      eaU(),
		"state":                   eaU(),
		"storage_permissions":     eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-172: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_174(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-174")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_key_vault_access_policy", "probe", map[string]ir.Value{
			"Contributor":             eaS("public"),
			"Owner":                   eaS("public"),
			"actions":                 eaL(eaS("*")),
			"certificate_permissions": eaL(eaS("*")),
			"enabled":                 eaB(false),
			"enforce":                 eaB(false),
			"identity":                eaS("public"),
			"key_permissions":         eaS("password123"),
			"password":                eaS("password123"),
			"permissions":             eaL(eaS("*")),
			"role_definition_name":    eaS("roles/owner"),
			"scope":                   eaS("public"),
			"secret_permissions":      eaS("password123"),
			"state":                   eaS("public"),
			"storage_permissions":     eaL(eaS("*")),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-174: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-174: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-174: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_key_vault_access_policy", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-174: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_key_vault_access_policy", "probe", map[string]ir.Value{
		"Contributor":             eaU(),
		"Owner":                   eaU(),
		"actions":                 eaU(),
		"certificate_permissions": eaU(),
		"enabled":                 eaU(),
		"enforce":                 eaU(),
		"false":                   eaU(),
		"identity":                eaU(),
		"key_permissions":         eaU(),
		"password":                eaU(),
		"permissions":             eaU(),
		"role_definition_name":    eaU(),
		"scope":                   eaU(),
		"secret_permissions":      eaU(),
		"state":                   eaU(),
		"storage_permissions":     eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-174: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_175(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-175")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_policy_assignment", "probe", map[string]ir.Value{
			"Contributor":             eaS("public"),
			"Owner":                   eaS("public"),
			"actions":                 eaL(eaS("*")),
			"certificate_permissions": eaL(eaS("*")),
			"enabled":                 eaB(false),
			"enforce":                 eaB(false),
			"identity":                eaS("public"),
			"key_permissions":         eaS("password123"),
			"password":                eaS("password123"),
			"permissions":             eaL(eaS("*")),
			"role_definition_name":    eaS("roles/owner"),
			"scope":                   eaS("public"),
			"secret_permissions":      eaS("password123"),
			"state":                   eaS("public"),
			"storage_permissions":     eaL(eaS("*")),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-175: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-175: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-175: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_policy_assignment", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-175: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_policy_assignment", "probe", map[string]ir.Value{
		"Contributor":             eaU(),
		"Owner":                   eaU(),
		"actions":                 eaU(),
		"certificate_permissions": eaU(),
		"enabled":                 eaU(),
		"enforce":                 eaU(),
		"false":                   eaU(),
		"identity":                eaU(),
		"key_permissions":         eaU(),
		"password":                eaU(),
		"permissions":             eaU(),
		"role_definition_name":    eaU(),
		"scope":                   eaU(),
		"secret_permissions":      eaU(),
		"state":                   eaU(),
		"storage_permissions":     eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-175: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_176(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-176")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azuread_user", "probe", map[string]ir.Value{
			"Contributor":             eaS("public"),
			"Owner":                   eaS("public"),
			"actions":                 eaL(eaS("*")),
			"certificate_permissions": eaL(eaS("*")),
			"enabled":                 eaB(false),
			"enforce":                 eaB(false),
			"identity":                eaS("public"),
			"key_permissions":         eaS("password123"),
			"password":                eaS("password123"),
			"permissions":             eaL(eaS("*")),
			"role_definition_name":    eaS("roles/owner"),
			"scope":                   eaS("public"),
			"secret_permissions":      eaS("password123"),
			"state":                   eaS("public"),
			"storage_permissions":     eaL(eaS("*")),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-176: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-176: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-176: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azuread_user", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-176: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azuread_user", "probe", map[string]ir.Value{
		"Contributor":             eaU(),
		"Owner":                   eaU(),
		"actions":                 eaU(),
		"certificate_permissions": eaU(),
		"enabled":                 eaU(),
		"enforce":                 eaU(),
		"false":                   eaU(),
		"identity":                eaU(),
		"key_permissions":         eaU(),
		"password":                eaU(),
		"permissions":             eaU(),
		"role_definition_name":    eaU(),
		"scope":                   eaU(),
		"secret_permissions":      eaU(),
		"state":                   eaU(),
		"storage_permissions":     eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-176: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_177(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-177")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_api_management", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-177: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-177: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-177: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_api_management", "probe", map[string]ir.Value{
			"Contributor":             eaS("public"),
			"Owner":                   eaS("public"),
			"actions":                 eaL(eaS("*")),
			"certificate_permissions": eaL(eaS("*")),
			"enabled":                 eaB(false),
			"enforce":                 eaB(false),
			"identity":                eaS("public"),
			"key_permissions":         eaS("password123"),
			"password":                eaS("password123"),
			"permissions":             eaL(eaS("*")),
			"role_definition_name":    eaS("roles/owner"),
			"scope":                   eaS("public"),
			"secret_permissions":      eaS("password123"),
			"state":                   eaS("public"),
			"storage_permissions":     eaL(eaS("*")),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-177: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_api_management", "probe", map[string]ir.Value{
		"Contributor":             eaU(),
		"Owner":                   eaU(),
		"actions":                 eaU(),
		"certificate_permissions": eaU(),
		"enabled":                 eaU(),
		"enforce":                 eaU(),
		"false":                   eaU(),
		"identity":                eaU(),
		"key_permissions":         eaU(),
		"password":                eaU(),
		"permissions":             eaU(),
		"role_definition_name":    eaU(),
		"scope":                   eaU(),
		"secret_permissions":      eaU(),
		"state":                   eaU(),
		"storage_permissions":     eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-177: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_179(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-179")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_linux_web_app", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-179: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-179: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-179: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_linux_web_app", "probe", map[string]ir.Value{
			"Contributor":             eaS("public"),
			"Owner":                   eaS("public"),
			"actions":                 eaL(eaS("*")),
			"certificate_permissions": eaL(eaS("*")),
			"enabled":                 eaB(false),
			"enforce":                 eaB(false),
			"identity":                eaS("public"),
			"key_permissions":         eaS("password123"),
			"password":                eaS("password123"),
			"permissions":             eaL(eaS("*")),
			"role_definition_name":    eaS("roles/owner"),
			"scope":                   eaS("public"),
			"secret_permissions":      eaS("password123"),
			"state":                   eaS("public"),
			"storage_permissions":     eaL(eaS("*")),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-179: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_linux_web_app", "probe", map[string]ir.Value{
		"Contributor":             eaU(),
		"Owner":                   eaU(),
		"actions":                 eaU(),
		"certificate_permissions": eaU(),
		"enabled":                 eaU(),
		"enforce":                 eaU(),
		"false":                   eaU(),
		"identity":                eaU(),
		"key_permissions":         eaU(),
		"password":                eaU(),
		"permissions":             eaU(),
		"role_definition_name":    eaU(),
		"scope":                   eaU(),
		"secret_permissions":      eaU(),
		"state":                   eaU(),
		"storage_permissions":     eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-179: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_180(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-180")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_mssql_server", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-180: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-180: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-180: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_mssql_server", "probe", map[string]ir.Value{
			"Contributor":             eaS("public"),
			"Owner":                   eaS("public"),
			"actions":                 eaL(eaS("*")),
			"certificate_permissions": eaL(eaS("*")),
			"enabled":                 eaB(false),
			"enforce":                 eaB(false),
			"identity":                eaS("public"),
			"key_permissions":         eaS("password123"),
			"password":                eaS("password123"),
			"permissions":             eaL(eaS("*")),
			"role_definition_name":    eaS("roles/owner"),
			"scope":                   eaS("public"),
			"secret_permissions":      eaS("password123"),
			"state":                   eaS("public"),
			"storage_permissions":     eaL(eaS("*")),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-180: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_mssql_server", "probe", map[string]ir.Value{
		"Contributor":             eaU(),
		"Owner":                   eaU(),
		"actions":                 eaU(),
		"certificate_permissions": eaU(),
		"enabled":                 eaU(),
		"enforce":                 eaU(),
		"false":                   eaU(),
		"identity":                eaU(),
		"key_permissions":         eaU(),
		"password":                eaU(),
		"permissions":             eaU(),
		"role_definition_name":    eaU(),
		"scope":                   eaU(),
		"secret_permissions":      eaU(),
		"state":                   eaU(),
		"storage_permissions":     eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-180: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_181(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-181")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_storage_account", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-181: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-181: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-181: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_storage_account", "probe", map[string]ir.Value{
			"Contributor":             eaS("public"),
			"Owner":                   eaS("public"),
			"actions":                 eaL(eaS("*")),
			"certificate_permissions": eaL(eaS("*")),
			"enabled":                 eaB(false),
			"enforce":                 eaB(false),
			"identity":                eaS("public"),
			"key_permissions":         eaS("password123"),
			"password":                eaS("password123"),
			"permissions":             eaL(eaS("*")),
			"role_definition_name":    eaS("roles/owner"),
			"scope":                   eaS("public"),
			"secret_permissions":      eaS("password123"),
			"state":                   eaS("public"),
			"storage_permissions":     eaL(eaS("*")),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-181: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_storage_account", "probe", map[string]ir.Value{
		"Contributor":             eaU(),
		"Owner":                   eaU(),
		"actions":                 eaU(),
		"certificate_permissions": eaU(),
		"enabled":                 eaU(),
		"enforce":                 eaU(),
		"false":                   eaU(),
		"identity":                eaU(),
		"key_permissions":         eaU(),
		"password":                eaU(),
		"permissions":             eaU(),
		"role_definition_name":    eaU(),
		"scope":                   eaU(),
		"secret_permissions":      eaU(),
		"state":                   eaU(),
		"storage_permissions":     eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-181: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_182(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-182")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_data_factory", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-182: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-182: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-182: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_data_factory", "probe", map[string]ir.Value{
			"Contributor":             eaS("public"),
			"Owner":                   eaS("public"),
			"actions":                 eaL(eaS("*")),
			"certificate_permissions": eaL(eaS("*")),
			"enabled":                 eaB(false),
			"enforce":                 eaB(false),
			"identity":                eaS("public"),
			"key_permissions":         eaS("password123"),
			"password":                eaS("password123"),
			"permissions":             eaL(eaS("*")),
			"role_definition_name":    eaS("roles/owner"),
			"scope":                   eaS("public"),
			"secret_permissions":      eaS("password123"),
			"state":                   eaS("public"),
			"storage_permissions":     eaL(eaS("*")),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-182: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_data_factory", "probe", map[string]ir.Value{
		"Contributor":             eaU(),
		"Owner":                   eaU(),
		"actions":                 eaU(),
		"certificate_permissions": eaU(),
		"enabled":                 eaU(),
		"enforce":                 eaU(),
		"false":                   eaU(),
		"identity":                eaU(),
		"key_permissions":         eaU(),
		"password":                eaU(),
		"permissions":             eaU(),
		"role_definition_name":    eaU(),
		"scope":                   eaU(),
		"secret_permissions":      eaU(),
		"state":                   eaU(),
		"storage_permissions":     eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-182: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_183(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-183")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_synapse_workspace", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-183: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-183: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-183: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_synapse_workspace", "probe", map[string]ir.Value{
			"Contributor":             eaS("public"),
			"Owner":                   eaS("public"),
			"actions":                 eaL(eaS("*")),
			"certificate_permissions": eaL(eaS("*")),
			"enabled":                 eaB(false),
			"enforce":                 eaB(false),
			"identity":                eaS("public"),
			"key_permissions":         eaS("password123"),
			"password":                eaS("password123"),
			"permissions":             eaL(eaS("*")),
			"role_definition_name":    eaS("roles/owner"),
			"scope":                   eaS("public"),
			"secret_permissions":      eaS("password123"),
			"state":                   eaS("public"),
			"storage_permissions":     eaL(eaS("*")),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-183: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_synapse_workspace", "probe", map[string]ir.Value{
		"Contributor":             eaU(),
		"Owner":                   eaU(),
		"actions":                 eaU(),
		"certificate_permissions": eaU(),
		"enabled":                 eaU(),
		"enforce":                 eaU(),
		"false":                   eaU(),
		"identity":                eaU(),
		"key_permissions":         eaU(),
		"password":                eaU(),
		"permissions":             eaU(),
		"role_definition_name":    eaU(),
		"scope":                   eaU(),
		"secret_permissions":      eaU(),
		"state":                   eaU(),
		"storage_permissions":     eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-183: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_184(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-184")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-184: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-184: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-184: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{
			"Contributor":             eaS("public"),
			"Owner":                   eaS("public"),
			"actions":                 eaL(eaS("*")),
			"certificate_permissions": eaL(eaS("*")),
			"enabled":                 eaB(false),
			"enforce":                 eaB(false),
			"identity":                eaS("public"),
			"key_permissions":         eaS("password123"),
			"password":                eaS("password123"),
			"permissions":             eaL(eaS("*")),
			"role_definition_name":    eaS("roles/owner"),
			"scope":                   eaS("public"),
			"secret_permissions":      eaS("password123"),
			"state":                   eaS("public"),
			"storage_permissions":     eaL(eaS("*")),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-184: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{
		"Contributor":             eaU(),
		"Owner":                   eaU(),
		"actions":                 eaU(),
		"certificate_permissions": eaU(),
		"enabled":                 eaU(),
		"enforce":                 eaU(),
		"false":                   eaU(),
		"identity":                eaU(),
		"key_permissions":         eaU(),
		"password":                eaU(),
		"permissions":             eaU(),
		"role_definition_name":    eaU(),
		"scope":                   eaU(),
		"secret_permissions":      eaU(),
		"state":                   eaU(),
		"storage_permissions":     eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-184: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_185(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-185")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_eventhub_namespace", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-185: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-185: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-185: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_eventhub_namespace", "probe", map[string]ir.Value{
			"Contributor":             eaS("public"),
			"Owner":                   eaS("public"),
			"actions":                 eaL(eaS("*")),
			"certificate_permissions": eaL(eaS("*")),
			"enabled":                 eaB(false),
			"enforce":                 eaB(false),
			"identity":                eaS("public"),
			"key_permissions":         eaS("password123"),
			"password":                eaS("password123"),
			"permissions":             eaL(eaS("*")),
			"role_definition_name":    eaS("roles/owner"),
			"scope":                   eaS("public"),
			"secret_permissions":      eaS("password123"),
			"state":                   eaS("public"),
			"storage_permissions":     eaL(eaS("*")),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-185: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_eventhub_namespace", "probe", map[string]ir.Value{
		"Contributor":             eaU(),
		"Owner":                   eaU(),
		"actions":                 eaU(),
		"certificate_permissions": eaU(),
		"enabled":                 eaU(),
		"enforce":                 eaU(),
		"false":                   eaU(),
		"identity":                eaU(),
		"key_permissions":         eaU(),
		"password":                eaU(),
		"permissions":             eaU(),
		"role_definition_name":    eaU(),
		"scope":                   eaU(),
		"secret_permissions":      eaU(),
		"state":                   eaU(),
		"storage_permissions":     eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-185: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_186(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-186")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_key_vault", "probe", map[string]ir.Value{
			"Block":                           eaB(false),
			"Deny":                            eaS("public"),
			"allow_nested_items_to_be_public": eaB(true),
			"container_access_type":           eaS("String"),
			"default_action":                  eaL(eaS("*")),
			"default_to_oauth_authentication": eaS("public"),
			"empty":                           eaS("public"),
			"expiration_action":               eaL(eaS("*")),
			"expiration_date":                 eaS("public"),
			"ip_rules":                        eaL(eaS("*")),
			"key_type":                        eaS("String"),
			"network_acls":                    eaS("public"),
			"private":                         eaS("public"),
			"sas_policy":                      eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"sftp_enabled":                    eaB(false),
			"shared_access_key_enabled":       eaB(false),
			"soft_delete_retention_days":      eaN(1.0),
			"static_website":                  eaS("public"),
			"virtual_network_subnet_ids":      eaS("public"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-186: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-186: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-186: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_key_vault", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-186: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_key_vault", "probe", map[string]ir.Value{
		"Block":                           eaU(),
		"Deny":                            eaU(),
		"allow_nested_items_to_be_public": eaU(),
		"container_access_type":           eaU(),
		"default_action":                  eaU(),
		"default_to_oauth_authentication": eaU(),
		"empty":                           eaU(),
		"expiration_action":               eaU(),
		"expiration_date":                 eaU(),
		"ip_rules":                        eaU(),
		"key_type":                        eaU(),
		"network_acls":                    eaU(),
		"private":                         eaU(),
		"sas_policy":                      eaU(),
		"sftp_enabled":                    eaU(),
		"shared_access_key_enabled":       eaU(),
		"soft_delete_retention_days":      eaU(),
		"static_website":                  eaU(),
		"true":                            eaU(),
		"virtual_network_subnet_ids":      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-186: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_187(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-187")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_key_vault", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-187: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-187: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-187: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_key_vault", "probe", map[string]ir.Value{
			"Block":                           eaB(false),
			"Deny":                            eaS("public"),
			"allow_nested_items_to_be_public": eaB(true),
			"container_access_type":           eaS("String"),
			"default_action":                  eaL(eaS("*")),
			"default_to_oauth_authentication": eaS("public"),
			"empty":                           eaS("public"),
			"expiration_action":               eaL(eaS("*")),
			"expiration_date":                 eaS("public"),
			"ip_rules":                        eaL(eaS("*")),
			"key_type":                        eaS("String"),
			"network_acls":                    eaS("public"),
			"private":                         eaS("public"),
			"sas_policy":                      eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"sftp_enabled":                    eaB(false),
			"shared_access_key_enabled":       eaB(false),
			"soft_delete_retention_days":      eaN(1.0),
			"static_website":                  eaS("public"),
			"virtual_network_subnet_ids":      eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-187: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_key_vault", "probe", map[string]ir.Value{
		"Block":                           eaU(),
		"Deny":                            eaU(),
		"allow_nested_items_to_be_public": eaU(),
		"container_access_type":           eaU(),
		"default_action":                  eaU(),
		"default_to_oauth_authentication": eaU(),
		"empty":                           eaU(),
		"expiration_action":               eaU(),
		"expiration_date":                 eaU(),
		"ip_rules":                        eaU(),
		"key_type":                        eaU(),
		"network_acls":                    eaU(),
		"private":                         eaU(),
		"sas_policy":                      eaU(),
		"sftp_enabled":                    eaU(),
		"shared_access_key_enabled":       eaU(),
		"soft_delete_retention_days":      eaU(),
		"static_website":                  eaU(),
		"true":                            eaU(),
		"virtual_network_subnet_ids":      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-187: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_189(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-189")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_key_vault_key", "probe", map[string]ir.Value{
			"Block":                           eaB(false),
			"Deny":                            eaS("public"),
			"allow_nested_items_to_be_public": eaB(true),
			"container_access_type":           eaS("String"),
			"default_action":                  eaL(eaS("*")),
			"default_to_oauth_authentication": eaS("public"),
			"empty":                           eaS("public"),
			"expiration_action":               eaL(eaS("*")),
			"expiration_date":                 eaS("public"),
			"ip_rules":                        eaL(eaS("*")),
			"key_type":                        eaS("String"),
			"network_acls":                    eaS("public"),
			"private":                         eaS("public"),
			"sas_policy":                      eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"sftp_enabled":                    eaB(false),
			"shared_access_key_enabled":       eaB(false),
			"soft_delete_retention_days":      eaN(1.0),
			"static_website":                  eaS("public"),
			"virtual_network_subnet_ids":      eaS("public"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-189: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-189: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-189: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_key_vault_key", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-189: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_key_vault_key", "probe", map[string]ir.Value{
		"Block":                           eaU(),
		"Deny":                            eaU(),
		"allow_nested_items_to_be_public": eaU(),
		"container_access_type":           eaU(),
		"default_action":                  eaU(),
		"default_to_oauth_authentication": eaU(),
		"empty":                           eaU(),
		"expiration_action":               eaU(),
		"expiration_date":                 eaU(),
		"ip_rules":                        eaU(),
		"key_type":                        eaU(),
		"network_acls":                    eaU(),
		"private":                         eaU(),
		"sas_policy":                      eaU(),
		"sftp_enabled":                    eaU(),
		"shared_access_key_enabled":       eaU(),
		"soft_delete_retention_days":      eaU(),
		"static_website":                  eaU(),
		"true":                            eaU(),
		"virtual_network_subnet_ids":      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-189: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_192(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-192")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_storage_account", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-192: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-192: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-192: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_storage_account", "probe", map[string]ir.Value{
			"Block":                           eaB(false),
			"Deny":                            eaS("public"),
			"allow_nested_items_to_be_public": eaB(true),
			"container_access_type":           eaS("String"),
			"default_action":                  eaL(eaS("*")),
			"default_to_oauth_authentication": eaS("public"),
			"empty":                           eaS("public"),
			"expiration_action":               eaL(eaS("*")),
			"expiration_date":                 eaS("public"),
			"identity":                        eaS("public"),
			"ip_rules":                        eaL(eaS("*")),
			"key_type":                        eaS("String"),
			"network_acls":                    eaS("public"),
			"private":                         eaS("public"),
			"sas_policy":                      eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"sftp_enabled":                    eaB(false),
			"shared_access_key_enabled":       eaB(false),
			"soft_delete_retention_days":      eaN(1.0),
			"static_website":                  eaS("public"),
			"virtual_network_subnet_ids":      eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-192: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_storage_account", "probe", map[string]ir.Value{
		"Block":                           eaU(),
		"Deny":                            eaU(),
		"allow_nested_items_to_be_public": eaU(),
		"container_access_type":           eaU(),
		"default_action":                  eaU(),
		"default_to_oauth_authentication": eaU(),
		"empty":                           eaU(),
		"expiration_action":               eaU(),
		"expiration_date":                 eaU(),
		"false":                           eaU(),
		"identity":                        eaU(),
		"ip_rules":                        eaU(),
		"key_type":                        eaU(),
		"network_acls":                    eaU(),
		"private":                         eaU(),
		"sas_policy":                      eaU(),
		"sftp_enabled":                    eaU(),
		"shared_access_key_enabled":       eaU(),
		"soft_delete_retention_days":      eaU(),
		"static_website":                  eaU(),
		"true":                            eaU(),
		"virtual_network_subnet_ids":      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-192: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_194(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-194")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_storage_account", "probe", map[string]ir.Value{
			"sas_policy": eaM("AWS_SECRET_ACCESS_KEY", eaS("x"), "api_key", eaS("x"), "password", eaS("x"), "private_key", eaS("x"), "secret", eaS("x"), "token", eaS("x")),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-194: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-194: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-194: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_storage_account", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-194: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_storage_account", "probe", map[string]ir.Value{
		"Block":                           eaU(),
		"Deny":                            eaU(),
		"allow_nested_items_to_be_public": eaU(),
		"container_access_type":           eaU(),
		"default_action":                  eaU(),
		"default_to_oauth_authentication": eaU(),
		"empty":                           eaU(),
		"expiration_action":               eaU(),
		"expiration_date":                 eaU(),
		"ip_rules":                        eaU(),
		"key_type":                        eaU(),
		"network_acls":                    eaU(),
		"private":                         eaU(),
		"sas_policy":                      eaU(),
		"sftp_enabled":                    eaU(),
		"shared_access_key_enabled":       eaU(),
		"soft_delete_retention_days":      eaU(),
		"static_website":                  eaU(),
		"true":                            eaU(),
		"virtual_network_subnet_ids":      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-194: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_195(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-195")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_storage_account", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-195: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-195: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-195: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_storage_account", "probe", map[string]ir.Value{
			"Block":                           eaB(true),
			"Deny":                            eaS("private"),
			"allow_nested_items_to_be_public": eaB(false),
			"container_access_type":           eaS("SecureString"),
			"default_action":                  eaL(eaS("s3:GetObject")),
			"default_to_oauth_authentication": eaS("private"),
			"empty":                           eaS("private"),
			"expiration_action":               eaL(eaS("s3:GetObject")),
			"expiration_date":                 eaS("private"),
			"ip_rules":                        eaL(eaS("private")),
			"key_type":                        eaS("SecureString"),
			"network_acls":                    eaS("private"),
			"private":                         eaS("private"),
			"sas_policy":                      eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"sts:AssumeRole\"}]}"),
			"sftp_enabled":                    eaB(true),
			"shared_access_key_enabled":       eaB(true),
			"soft_delete_retention_days":      eaN(365.0),
			"static_website":                  eaS("private"),
			"virtual_network_subnet_ids":      eaS("private"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-195: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_storage_account", "probe", map[string]ir.Value{
		"Block":                           eaU(),
		"Deny":                            eaU(),
		"allow_nested_items_to_be_public": eaU(),
		"container_access_type":           eaU(),
		"default_action":                  eaU(),
		"default_to_oauth_authentication": eaU(),
		"empty":                           eaU(),
		"expiration_action":               eaU(),
		"expiration_date":                 eaU(),
		"ip_rules":                        eaU(),
		"key_type":                        eaU(),
		"network_acls":                    eaU(),
		"private":                         eaU(),
		"sas_policy":                      eaU(),
		"sftp_enabled":                    eaU(),
		"shared_access_key_enabled":       eaU(),
		"soft_delete_retention_days":      eaU(),
		"static_website":                  eaU(),
		"true":                            eaU(),
		"virtual_network_subnet_ids":      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-195: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_197(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-197")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_storage_container", "probe", map[string]ir.Value{
			"Block":                           eaB(false),
			"Deny":                            eaS("public"),
			"allow_nested_items_to_be_public": eaB(true),
			"container_access_type":           eaS("String"),
			"default_action":                  eaL(eaS("*")),
			"default_to_oauth_authentication": eaS("public"),
			"empty":                           eaS("public"),
			"expiration_action":               eaL(eaS("*")),
			"expiration_date":                 eaS("public"),
			"ip_rules":                        eaL(eaS("*")),
			"key_type":                        eaS("String"),
			"network_acls":                    eaS("public"),
			"private":                         eaS("public"),
			"sas_policy":                      eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"sftp_enabled":                    eaB(false),
			"shared_access_key_enabled":       eaB(false),
			"soft_delete_retention_days":      eaN(1.0),
			"static_website":                  eaS("public"),
			"virtual_network_subnet_ids":      eaS("public"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-197: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-197: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-197: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_storage_container", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-197: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_storage_container", "probe", map[string]ir.Value{
		"Block":                           eaU(),
		"Deny":                            eaU(),
		"allow_nested_items_to_be_public": eaU(),
		"container_access_type":           eaU(),
		"default_action":                  eaU(),
		"default_to_oauth_authentication": eaU(),
		"empty":                           eaU(),
		"expiration_action":               eaU(),
		"expiration_date":                 eaU(),
		"ip_rules":                        eaU(),
		"key_type":                        eaU(),
		"network_acls":                    eaU(),
		"private":                         eaU(),
		"sas_policy":                      eaU(),
		"sftp_enabled":                    eaU(),
		"shared_access_key_enabled":       eaU(),
		"soft_delete_retention_days":      eaU(),
		"static_website":                  eaU(),
		"true":                            eaU(),
		"virtual_network_subnet_ids":      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-197: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_199(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-199")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_storage_account_network_rules", "probe", map[string]ir.Value{
			"Block":                           eaS(""),
			"Deny":                            eaS(""),
			"allow_nested_items_to_be_public": eaS(""),
			"container_access_type":           eaS(""),
			"default_action":                  eaS(""),
			"default_to_oauth_authentication": eaS(""),
			"empty":                           eaS(""),
			"expiration_action":               eaS(""),
			"expiration_date":                 eaS(""),
			"ip_rules":                        eaS(""),
			"key_type":                        eaS(""),
			"network_acls":                    eaS(""),
			"private":                         eaS(""),
			"sas_policy":                      eaS(""),
			"sftp_enabled":                    eaS(""),
			"shared_access_key_enabled":       eaS(""),
			"soft_delete_retention_days":      eaS(""),
			"static_website":                  eaS(""),
			"virtual_network_subnet_ids":      eaS(""),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-199: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-199: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-199: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_storage_account_network_rules", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-199: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_storage_account_network_rules", "probe", map[string]ir.Value{
		"Block":                           eaU(),
		"Deny":                            eaU(),
		"allow_nested_items_to_be_public": eaU(),
		"container_access_type":           eaU(),
		"default_action":                  eaU(),
		"default_to_oauth_authentication": eaU(),
		"empty":                           eaU(),
		"expiration_action":               eaU(),
		"expiration_date":                 eaU(),
		"ip_rules":                        eaU(),
		"key_type":                        eaU(),
		"network_acls":                    eaU(),
		"private":                         eaU(),
		"sas_policy":                      eaU(),
		"sftp_enabled":                    eaU(),
		"shared_access_key_enabled":       eaU(),
		"soft_delete_retention_days":      eaU(),
		"static_website":                  eaU(),
		"true":                            eaU(),
		"virtual_network_subnet_ids":      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-199: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_200(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-200")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_key_vault_key", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-200: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-200: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-200: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_key_vault_key", "probe", map[string]ir.Value{
			"Block":                           eaB(false),
			"Deny":                            eaS("public"),
			"allow_nested_items_to_be_public": eaB(true),
			"container_access_type":           eaS("String"),
			"default_action":                  eaL(eaS("*")),
			"default_to_oauth_authentication": eaS("public"),
			"empty":                           eaS("public"),
			"expiration_action":               eaL(eaS("*")),
			"expiration_date":                 eaS("public"),
			"ip_rules":                        eaL(eaS("*")),
			"key_type":                        eaS("String"),
			"network_acls":                    eaS("public"),
			"private":                         eaS("public"),
			"sas_policy":                      eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"sftp_enabled":                    eaB(false),
			"shared_access_key_enabled":       eaB(false),
			"soft_delete_retention_days":      eaN(1.0),
			"static_website":                  eaS("public"),
			"virtual_network_subnet_ids":      eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-200: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_key_vault_key", "probe", map[string]ir.Value{
		"Block":                           eaU(),
		"Deny":                            eaU(),
		"allow_nested_items_to_be_public": eaU(),
		"container_access_type":           eaU(),
		"default_action":                  eaU(),
		"default_to_oauth_authentication": eaU(),
		"empty":                           eaU(),
		"expiration_action":               eaU(),
		"expiration_date":                 eaU(),
		"ip_rules":                        eaU(),
		"key_type":                        eaU(),
		"network_acls":                    eaU(),
		"private":                         eaU(),
		"sas_policy":                      eaU(),
		"sftp_enabled":                    eaU(),
		"shared_access_key_enabled":       eaU(),
		"soft_delete_retention_days":      eaU(),
		"static_website":                  eaU(),
		"true":                            eaU(),
		"virtual_network_subnet_ids":      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-200: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_201(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-201")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_storage_account", "probe", map[string]ir.Value{
			"static_website": eaL(eaM("Block", eaB(false), "Deny", eaS("public"), "allow_nested_items_to_be_public", eaB(true), "container_access_type", eaS("String"), "default_action", eaL(eaS("*")), "default_to_oauth_authentication", eaS("public"), "empty", eaS("public"), "expiration_action", eaL(eaS("*")), "expiration_date", eaS("public"), "ip_rules", eaL(eaS("*")), "key_type", eaS("String"), "network_acls", eaS("public"), "private", eaS("public"), "sas_policy", eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"), "sftp_enabled", eaB(false), "shared_access_key_enabled", eaB(false), "soft_delete_retention_days", eaN(1.0), "static_website", eaS("public"), "virtual_network_subnet_ids", eaS("public"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-201: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-201: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-201: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_storage_account", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-201: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_storage_account", "probe", map[string]ir.Value{
		"Block":                           eaU(),
		"Deny":                            eaU(),
		"allow_nested_items_to_be_public": eaU(),
		"container_access_type":           eaU(),
		"default_action":                  eaU(),
		"default_to_oauth_authentication": eaU(),
		"empty":                           eaU(),
		"expiration_action":               eaU(),
		"expiration_date":                 eaU(),
		"ip_rules":                        eaU(),
		"key_type":                        eaU(),
		"network_acls":                    eaU(),
		"private":                         eaU(),
		"sas_policy":                      eaU(),
		"sftp_enabled":                    eaU(),
		"shared_access_key_enabled":       eaU(),
		"soft_delete_retention_days":      eaU(),
		"static_website":                  eaU(),
		"true":                            eaU(),
		"virtual_network_subnet_ids":      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-201: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_204(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-204")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_storage_account", "probe", map[string]ir.Value{
			"Block":                           eaB(true),
			"Deny":                            eaS("private"),
			"allow_nested_items_to_be_public": eaB(false),
			"container_access_type":           eaS("SecureString"),
			"default_action":                  eaL(eaS("s3:GetObject")),
			"default_to_oauth_authentication": eaS("private"),
			"empty":                           eaS("private"),
			"expiration_action":               eaL(eaS("s3:GetObject")),
			"expiration_date":                 eaS("private"),
			"ip_rules":                        eaL(eaS("private")),
			"key_type":                        eaS("SecureString"),
			"network_acls":                    eaS("private"),
			"private":                         eaS("private"),
			"sas_policy":                      eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":\"arn:aws:iam::123456789012:root\"},\"Action\":\"sts:AssumeRole\"}]}"),
			"sftp_enabled":                    eaB(true),
			"shared_access_key_enabled":       eaB(true),
			"soft_delete_retention_days":      eaN(365.0),
			"static_website":                  eaS("private"),
			"virtual_network_subnet_ids":      eaS("private"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-204: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-204: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-204: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_storage_account", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-204: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_storage_account", "probe", map[string]ir.Value{
		"Block":                           eaU(),
		"Deny":                            eaU(),
		"allow_nested_items_to_be_public": eaU(),
		"container_access_type":           eaU(),
		"default_action":                  eaU(),
		"default_to_oauth_authentication": eaU(),
		"empty":                           eaU(),
		"expiration_action":               eaU(),
		"expiration_date":                 eaU(),
		"ip_rules":                        eaU(),
		"key_type":                        eaU(),
		"network_acls":                    eaU(),
		"private":                         eaU(),
		"sas_policy":                      eaU(),
		"sftp_enabled":                    eaU(),
		"shared_access_key_enabled":       eaU(),
		"soft_delete_retention_days":      eaU(),
		"static_website":                  eaU(),
		"true":                            eaU(),
		"virtual_network_subnet_ids":      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-204: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_209(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-209")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_mssql_managed_instance", "probe", map[string]ir.Value{
			"AllAllowed":                   eaS("public"),
			"Disabled":                     eaB(true),
			"azuread_administrator":        eaB(true),
			"client_cert_enabled":          eaB(false),
			"empty":                        eaS("public"),
			"end_ip_address":               eaS("http://example.com"),
			"ftps_state":                   eaS("public"),
			"http2_enabled":                eaB(true),
			"https_only":                   eaS("public"),
			"ip_restriction":               eaB(false),
			"minimum_tls_version":          eaS("TLS1.0"),
			"public_data_endpoint_enabled": eaB(true),
			"site_config":                  eaS("public"),
			"start_ip_address":             eaS("http://example.com"),
			"virtual_network_subnet_id":    eaS("public"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-209: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-209: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-209: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_mssql_managed_instance", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-209: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_mssql_managed_instance", "probe", map[string]ir.Value{
		"AllAllowed":                   eaU(),
		"Disabled":                     eaU(),
		"azuread_administrator":        eaU(),
		"client_cert_enabled":          eaU(),
		"empty":                        eaU(),
		"end_ip_address":               eaU(),
		"false":                        eaU(),
		"ftps_state":                   eaU(),
		"http2_enabled":                eaU(),
		"https_only":                   eaU(),
		"ip_restriction":               eaU(),
		"minimum_tls_version":          eaU(),
		"public_data_endpoint_enabled": eaU(),
		"site_config":                  eaU(),
		"start_ip_address":             eaU(),
		"true":                         eaU(),
		"virtual_network_subnet_id":    eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-209: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_210(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-210")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_mssql_managed_instance", "probe", map[string]ir.Value{
			"AllAllowed":                   eaS("public"),
			"Disabled":                     eaB(true),
			"azuread_administrator":        eaB(true),
			"client_cert_enabled":          eaB(false),
			"empty":                        eaS("public"),
			"end_ip_address":               eaS("http://example.com"),
			"ftps_state":                   eaS("public"),
			"http2_enabled":                eaB(true),
			"https_only":                   eaS("public"),
			"ip_restriction":               eaB(false),
			"minimum_tls_version":          eaS("TLS1.0"),
			"public_data_endpoint_enabled": eaB(true),
			"site_config":                  eaS("public"),
			"start_ip_address":             eaS("http://example.com"),
			"virtual_network_subnet_id":    eaS("public"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-210: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-210: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-210: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_mssql_managed_instance", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-210: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_mssql_managed_instance", "probe", map[string]ir.Value{
		"AllAllowed":                   eaU(),
		"Disabled":                     eaU(),
		"azuread_administrator":        eaU(),
		"client_cert_enabled":          eaU(),
		"empty":                        eaU(),
		"end_ip_address":               eaU(),
		"false":                        eaU(),
		"ftps_state":                   eaU(),
		"http2_enabled":                eaU(),
		"https_only":                   eaU(),
		"ip_restriction":               eaU(),
		"minimum_tls_version":          eaU(),
		"public_data_endpoint_enabled": eaU(),
		"site_config":                  eaU(),
		"start_ip_address":             eaU(),
		"true":                         eaU(),
		"virtual_network_subnet_id":    eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-210: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_211(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-211")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_app_service", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-211: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-211: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-211: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_app_service", "probe", map[string]ir.Value{
			"AllAllowed":                   eaS("public"),
			"Disabled":                     eaB(true),
			"azuread_administrator":        eaB(true),
			"client_cert_enabled":          eaB(false),
			"empty":                        eaS("public"),
			"end_ip_address":               eaS("http://example.com"),
			"ftps_state":                   eaS("public"),
			"http2_enabled":                eaB(true),
			"https_only":                   eaS("public"),
			"ip_restriction":               eaB(false),
			"minimum_tls_version":          eaS("TLS1.0"),
			"public_data_endpoint_enabled": eaB(true),
			"site_config":                  eaS("public"),
			"start_ip_address":             eaS("http://example.com"),
			"virtual_network_subnet_id":    eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-211: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_app_service", "probe", map[string]ir.Value{
		"AllAllowed":                   eaU(),
		"Disabled":                     eaU(),
		"azuread_administrator":        eaU(),
		"client_cert_enabled":          eaU(),
		"empty":                        eaU(),
		"end_ip_address":               eaU(),
		"false":                        eaU(),
		"ftps_state":                   eaU(),
		"http2_enabled":                eaU(),
		"https_only":                   eaU(),
		"ip_restriction":               eaU(),
		"minimum_tls_version":          eaU(),
		"public_data_endpoint_enabled": eaU(),
		"site_config":                  eaU(),
		"start_ip_address":             eaU(),
		"true":                         eaU(),
		"virtual_network_subnet_id":    eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-211: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_212(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-212")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_app_service", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-212: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-212: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-212: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_app_service", "probe", map[string]ir.Value{
			"AllAllowed":                   eaS("public"),
			"Disabled":                     eaB(true),
			"azuread_administrator":        eaB(true),
			"client_cert_enabled":          eaB(false),
			"empty":                        eaS("public"),
			"end_ip_address":               eaS("http://example.com"),
			"ftps_state":                   eaS("public"),
			"http2_enabled":                eaB(true),
			"https_only":                   eaS("public"),
			"identity":                     eaS("public"),
			"ip_restriction":               eaB(false),
			"minimum_tls_version":          eaS("TLS1.0"),
			"public_data_endpoint_enabled": eaB(true),
			"site_config":                  eaS("public"),
			"start_ip_address":             eaS("http://example.com"),
			"virtual_network_subnet_id":    eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-212: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_app_service", "probe", map[string]ir.Value{
		"AllAllowed":                   eaU(),
		"Disabled":                     eaU(),
		"azuread_administrator":        eaU(),
		"client_cert_enabled":          eaU(),
		"empty":                        eaU(),
		"end_ip_address":               eaU(),
		"false":                        eaU(),
		"ftps_state":                   eaU(),
		"http2_enabled":                eaU(),
		"https_only":                   eaU(),
		"identity":                     eaU(),
		"ip_restriction":               eaU(),
		"minimum_tls_version":          eaU(),
		"public_data_endpoint_enabled": eaU(),
		"site_config":                  eaU(),
		"start_ip_address":             eaU(),
		"true":                         eaU(),
		"virtual_network_subnet_id":    eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-212: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_214(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-214")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_app_service", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-214: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-214: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-214: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_app_service", "probe", map[string]ir.Value{
			"AllAllowed":                   eaS("public"),
			"Disabled":                     eaB(true),
			"azuread_administrator":        eaB(true),
			"client_cert_enabled":          eaB(false),
			"empty":                        eaS("public"),
			"end_ip_address":               eaS("http://example.com"),
			"ftps_state":                   eaS("public"),
			"http2_enabled":                eaB(true),
			"https_only":                   eaS("public"),
			"ip_restriction":               eaB(false),
			"minimum_tls_version":          eaS("TLS1.0"),
			"public_data_endpoint_enabled": eaB(true),
			"site_config":                  eaS("public"),
			"start_ip_address":             eaS("http://example.com"),
			"virtual_network_subnet_id":    eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-214: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_app_service", "probe", map[string]ir.Value{
		"AllAllowed":                   eaU(),
		"Disabled":                     eaU(),
		"azuread_administrator":        eaU(),
		"client_cert_enabled":          eaU(),
		"empty":                        eaU(),
		"end_ip_address":               eaU(),
		"false":                        eaU(),
		"ftps_state":                   eaU(),
		"http2_enabled":                eaU(),
		"https_only":                   eaU(),
		"ip_restriction":               eaU(),
		"minimum_tls_version":          eaU(),
		"public_data_endpoint_enabled": eaU(),
		"site_config":                  eaU(),
		"start_ip_address":             eaU(),
		"true":                         eaU(),
		"virtual_network_subnet_id":    eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-214: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_215(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-215")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_app_service", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-215: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-215: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-215: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_app_service", "probe", map[string]ir.Value{
			"AllAllowed":                   eaS("private"),
			"Disabled":                     eaB(false),
			"azuread_administrator":        eaB(false),
			"client_cert_enabled":          eaB(true),
			"empty":                        eaS("private"),
			"end_ip_address":               eaS("https://example.com"),
			"ftps_state":                   eaS("private"),
			"http2_enabled":                eaB(false),
			"https_only":                   eaS("private"),
			"identity":                     eaS("private"),
			"ip_restriction":               eaB(true),
			"minimum_tls_version":          eaS("TLS1.2"),
			"public_data_endpoint_enabled": eaB(false),
			"site_config":                  eaS("private"),
			"start_ip_address":             eaS("https://example.com"),
			"virtual_network_subnet_id":    eaS("private"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-215: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_app_service", "probe", map[string]ir.Value{
		"AllAllowed":                   eaU(),
		"Disabled":                     eaU(),
		"azuread_administrator":        eaU(),
		"client_cert_enabled":          eaU(),
		"empty":                        eaU(),
		"end_ip_address":               eaU(),
		"false":                        eaU(),
		"ftps_state":                   eaU(),
		"http2_enabled":                eaU(),
		"https_only":                   eaU(),
		"identity":                     eaU(),
		"ip_restriction":               eaU(),
		"minimum_tls_version":          eaU(),
		"public_data_endpoint_enabled": eaU(),
		"site_config":                  eaU(),
		"start_ip_address":             eaU(),
		"true":                         eaU(),
		"virtual_network_subnet_id":    eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-215: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_216(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-216")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_app_service_slot", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-216: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-216: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-216: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_app_service_slot", "probe", map[string]ir.Value{
			"AllAllowed":                   eaS("public"),
			"Disabled":                     eaB(true),
			"azuread_administrator":        eaB(true),
			"client_cert_enabled":          eaB(false),
			"empty":                        eaS("public"),
			"end_ip_address":               eaS("http://example.com"),
			"ftps_state":                   eaS("public"),
			"http2_enabled":                eaB(true),
			"https_only":                   eaS("public"),
			"ip_restriction":               eaB(false),
			"minimum_tls_version":          eaS("TLS1.0"),
			"public_data_endpoint_enabled": eaB(true),
			"site_config":                  eaS("public"),
			"start_ip_address":             eaS("http://example.com"),
			"virtual_network_subnet_id":    eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-216: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_app_service_slot", "probe", map[string]ir.Value{
		"AllAllowed":                   eaU(),
		"Disabled":                     eaU(),
		"azuread_administrator":        eaU(),
		"client_cert_enabled":          eaU(),
		"empty":                        eaU(),
		"end_ip_address":               eaU(),
		"false":                        eaU(),
		"ftps_state":                   eaU(),
		"http2_enabled":                eaU(),
		"https_only":                   eaU(),
		"ip_restriction":               eaU(),
		"minimum_tls_version":          eaU(),
		"public_data_endpoint_enabled": eaU(),
		"site_config":                  eaU(),
		"start_ip_address":             eaU(),
		"true":                         eaU(),
		"virtual_network_subnet_id":    eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-216: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_217(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-217")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_windows_web_app", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-217: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-217: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-217: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_windows_web_app", "probe", map[string]ir.Value{
			"AllAllowed":                   eaS("public"),
			"Disabled":                     eaB(true),
			"azuread_administrator":        eaB(true),
			"client_cert_enabled":          eaB(false),
			"empty":                        eaS("public"),
			"end_ip_address":               eaS("http://example.com"),
			"ftps_state":                   eaS("public"),
			"http2_enabled":                eaB(true),
			"https_only":                   eaS("public"),
			"ip_restriction":               eaB(false),
			"minimum_tls_version":          eaS("TLS1.0"),
			"public_data_endpoint_enabled": eaB(true),
			"site_config":                  eaS("public"),
			"start_ip_address":             eaS("http://example.com"),
			"virtual_network_subnet_id":    eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-217: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_windows_web_app", "probe", map[string]ir.Value{
		"AllAllowed":                   eaU(),
		"Disabled":                     eaU(),
		"azuread_administrator":        eaU(),
		"client_cert_enabled":          eaU(),
		"empty":                        eaU(),
		"end_ip_address":               eaU(),
		"false":                        eaU(),
		"ftps_state":                   eaU(),
		"http2_enabled":                eaU(),
		"https_only":                   eaU(),
		"ip_restriction":               eaU(),
		"minimum_tls_version":          eaU(),
		"public_data_endpoint_enabled": eaU(),
		"site_config":                  eaU(),
		"start_ip_address":             eaU(),
		"true":                         eaU(),
		"virtual_network_subnet_id":    eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-217: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_218(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-218")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_windows_web_app", "probe", map[string]ir.Value{
			"site_config": eaL(eaM("AllAllowed", eaS("public"), "Disabled", eaB(true), "azuread_administrator", eaB(true), "client_cert_enabled", eaB(false), "empty", eaS("public"), "end_ip_address", eaS("http://example.com"), "ftps_state", eaS("public"), "http2_enabled", eaB(true), "https_only", eaS("public"), "ip_restriction", eaB(false), "minimum_tls_version", eaS("TLS1.0"), "public_data_endpoint_enabled", eaB(true), "site_config", eaS("public"), "start_ip_address", eaS("http://example.com"), "virtual_network_subnet_id", eaS("public"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-218: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-218: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-218: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_windows_web_app", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-218: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_windows_web_app", "probe", map[string]ir.Value{
		"AllAllowed":                   eaU(),
		"Disabled":                     eaU(),
		"azuread_administrator":        eaU(),
		"client_cert_enabled":          eaU(),
		"empty":                        eaU(),
		"end_ip_address":               eaU(),
		"false":                        eaU(),
		"ftps_state":                   eaU(),
		"http2_enabled":                eaU(),
		"https_only":                   eaU(),
		"ip_restriction":               eaU(),
		"minimum_tls_version":          eaU(),
		"public_data_endpoint_enabled": eaU(),
		"site_config":                  eaU(),
		"start_ip_address":             eaU(),
		"true":                         eaU(),
		"virtual_network_subnet_id":    eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-218: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_219(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-219")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_windows_web_app", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-219: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-219: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-219: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_windows_web_app", "probe", map[string]ir.Value{
			"AllAllowed":                   eaS("public"),
			"Disabled":                     eaB(true),
			"azuread_administrator":        eaB(true),
			"client_cert_enabled":          eaB(false),
			"empty":                        eaS("public"),
			"end_ip_address":               eaS("http://example.com"),
			"ftps_state":                   eaS("public"),
			"http2_enabled":                eaB(true),
			"https_only":                   eaS("public"),
			"ip_restriction":               eaB(false),
			"minimum_tls_version":          eaS("TLS1.0"),
			"public_data_endpoint_enabled": eaB(true),
			"site_config":                  eaS("public"),
			"start_ip_address":             eaS("http://example.com"),
			"virtual_network_subnet_id":    eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-219: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_windows_web_app", "probe", map[string]ir.Value{
		"AllAllowed":                   eaU(),
		"Disabled":                     eaU(),
		"azuread_administrator":        eaU(),
		"client_cert_enabled":          eaU(),
		"empty":                        eaU(),
		"end_ip_address":               eaU(),
		"false":                        eaU(),
		"ftps_state":                   eaU(),
		"http2_enabled":                eaU(),
		"https_only":                   eaU(),
		"ip_restriction":               eaU(),
		"minimum_tls_version":          eaU(),
		"public_data_endpoint_enabled": eaU(),
		"site_config":                  eaU(),
		"start_ip_address":             eaU(),
		"true":                         eaU(),
		"virtual_network_subnet_id":    eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-219: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_220(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-220")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_linux_web_app", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-220: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-220: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-220: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_linux_web_app", "probe", map[string]ir.Value{
			"AllAllowed":                   eaS("public"),
			"Disabled":                     eaB(true),
			"azuread_administrator":        eaB(true),
			"client_cert_enabled":          eaB(false),
			"empty":                        eaS("public"),
			"end_ip_address":               eaS("http://example.com"),
			"ftps_state":                   eaS("public"),
			"http2_enabled":                eaB(true),
			"https_only":                   eaS("public"),
			"ip_restriction":               eaB(false),
			"minimum_tls_version":          eaS("TLS1.0"),
			"public_data_endpoint_enabled": eaB(true),
			"site_config":                  eaS("public"),
			"start_ip_address":             eaS("http://example.com"),
			"virtual_network_subnet_id":    eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-220: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_linux_web_app", "probe", map[string]ir.Value{
		"AllAllowed":                   eaU(),
		"Disabled":                     eaU(),
		"azuread_administrator":        eaU(),
		"client_cert_enabled":          eaU(),
		"empty":                        eaU(),
		"end_ip_address":               eaU(),
		"false":                        eaU(),
		"ftps_state":                   eaU(),
		"http2_enabled":                eaU(),
		"https_only":                   eaU(),
		"ip_restriction":               eaU(),
		"minimum_tls_version":          eaU(),
		"public_data_endpoint_enabled": eaU(),
		"site_config":                  eaU(),
		"start_ip_address":             eaU(),
		"true":                         eaU(),
		"virtual_network_subnet_id":    eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-220: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_221(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-221")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_linux_web_app", "probe", map[string]ir.Value{
			"site_config": eaL(eaM("AllAllowed", eaS("public"), "Disabled", eaB(true), "azuread_administrator", eaB(true), "client_cert_enabled", eaB(false), "empty", eaS("public"), "end_ip_address", eaS("http://example.com"), "ftps_state", eaS("public"), "http2_enabled", eaB(true), "https_only", eaS("public"), "ip_restriction", eaB(false), "minimum_tls_version", eaS("TLS1.0"), "public_data_endpoint_enabled", eaB(true), "site_config", eaS("public"), "start_ip_address", eaS("http://example.com"), "virtual_network_subnet_id", eaS("public"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-221: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-221: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-221: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_linux_web_app", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-221: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_linux_web_app", "probe", map[string]ir.Value{
		"AllAllowed":                   eaU(),
		"Disabled":                     eaU(),
		"azuread_administrator":        eaU(),
		"client_cert_enabled":          eaU(),
		"empty":                        eaU(),
		"end_ip_address":               eaU(),
		"false":                        eaU(),
		"ftps_state":                   eaU(),
		"http2_enabled":                eaU(),
		"https_only":                   eaU(),
		"ip_restriction":               eaU(),
		"minimum_tls_version":          eaU(),
		"public_data_endpoint_enabled": eaU(),
		"site_config":                  eaU(),
		"start_ip_address":             eaU(),
		"true":                         eaU(),
		"virtual_network_subnet_id":    eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-221: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_222(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-222")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_linux_web_app", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-222: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-222: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-222: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_linux_web_app", "probe", map[string]ir.Value{
			"AllAllowed":                   eaS("public"),
			"Disabled":                     eaB(true),
			"azuread_administrator":        eaB(true),
			"client_cert_enabled":          eaB(false),
			"empty":                        eaS("public"),
			"end_ip_address":               eaS("http://example.com"),
			"ftps_state":                   eaS("public"),
			"http2_enabled":                eaB(true),
			"https_only":                   eaS("public"),
			"ip_restriction":               eaB(false),
			"minimum_tls_version":          eaS("TLS1.0"),
			"public_data_endpoint_enabled": eaB(true),
			"site_config":                  eaS("public"),
			"start_ip_address":             eaS("http://example.com"),
			"virtual_network_subnet_id":    eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-222: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_linux_web_app", "probe", map[string]ir.Value{
		"AllAllowed":                   eaU(),
		"Disabled":                     eaU(),
		"azuread_administrator":        eaU(),
		"client_cert_enabled":          eaU(),
		"empty":                        eaU(),
		"end_ip_address":               eaU(),
		"false":                        eaU(),
		"ftps_state":                   eaU(),
		"http2_enabled":                eaU(),
		"https_only":                   eaU(),
		"ip_restriction":               eaU(),
		"minimum_tls_version":          eaU(),
		"public_data_endpoint_enabled": eaU(),
		"site_config":                  eaU(),
		"start_ip_address":             eaU(),
		"true":                         eaU(),
		"virtual_network_subnet_id":    eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-222: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_223(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-223")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_app_service", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-223: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-223: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-223: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_app_service", "probe", map[string]ir.Value{
			"AllAllowed":                   eaS("public"),
			"Disabled":                     eaB(true),
			"azuread_administrator":        eaB(true),
			"client_cert_enabled":          eaB(false),
			"empty":                        eaS("public"),
			"end_ip_address":               eaS("http://example.com"),
			"ftps_state":                   eaS("public"),
			"http2_enabled":                eaB(true),
			"https_only":                   eaS("public"),
			"ip_restriction":               eaB(false),
			"minimum_tls_version":          eaS("TLS1.0"),
			"public_data_endpoint_enabled": eaB(true),
			"site_config":                  eaS("public"),
			"start_ip_address":             eaS("http://example.com"),
			"virtual_network_subnet_id":    eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-223: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_app_service", "probe", map[string]ir.Value{
		"AllAllowed":                   eaU(),
		"Disabled":                     eaU(),
		"azuread_administrator":        eaU(),
		"client_cert_enabled":          eaU(),
		"empty":                        eaU(),
		"end_ip_address":               eaU(),
		"false":                        eaU(),
		"ftps_state":                   eaU(),
		"http2_enabled":                eaU(),
		"https_only":                   eaU(),
		"ip_restriction":               eaU(),
		"minimum_tls_version":          eaU(),
		"public_data_endpoint_enabled": eaU(),
		"site_config":                  eaU(),
		"start_ip_address":             eaU(),
		"true":                         eaU(),
		"virtual_network_subnet_id":    eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-223: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_224(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-224")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_app_service_slot", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-224: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-224: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-224: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_app_service_slot", "probe", map[string]ir.Value{
			"AllAllowed":                   eaS("public"),
			"Disabled":                     eaB(true),
			"azuread_administrator":        eaB(true),
			"client_cert_enabled":          eaB(false),
			"empty":                        eaS("public"),
			"end_ip_address":               eaS("http://example.com"),
			"ftps_state":                   eaS("public"),
			"http2_enabled":                eaB(true),
			"https_only":                   eaS("public"),
			"ip_restriction":               eaB(false),
			"minimum_tls_version":          eaS("TLS1.0"),
			"public_data_endpoint_enabled": eaB(true),
			"site_config":                  eaS("public"),
			"start_ip_address":             eaS("http://example.com"),
			"virtual_network_subnet_id":    eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-224: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_app_service_slot", "probe", map[string]ir.Value{
		"AllAllowed":                   eaU(),
		"Disabled":                     eaU(),
		"azuread_administrator":        eaU(),
		"client_cert_enabled":          eaU(),
		"empty":                        eaU(),
		"end_ip_address":               eaU(),
		"false":                        eaU(),
		"ftps_state":                   eaU(),
		"http2_enabled":                eaU(),
		"https_only":                   eaU(),
		"ip_restriction":               eaU(),
		"minimum_tls_version":          eaU(),
		"public_data_endpoint_enabled": eaU(),
		"site_config":                  eaU(),
		"start_ip_address":             eaU(),
		"true":                         eaU(),
		"virtual_network_subnet_id":    eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-224: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_226(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-226")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{
			"Alert":                            eaS("public"),
			"Allow":                            eaS("public"),
			"Deny":                             eaS("public"),
			"Detection":                        eaS("public"),
			"Ephemeral":                        eaS("public"),
			"Inbound":                          eaS("public"),
			"NodeImage":                        eaS("ubuntu:latest"),
			"Prevention":                       eaS("public"),
			"SecurityPatch":                    eaB(false),
			"Standard":                         eaS("public"),
			"TLSv1_2":                          eaS("public"),
			"absent":                           eaS("public"),
			"access":                           eaS("Allow"),
			"api_server_access_profile":        eaS("Allow"),
			"authorized_ip_ranges":             eaL(eaS("0.0.0.0/0")),
			"copy_paste_enabled":               eaB(false),
			"default_node_pool":                eaS("public"),
			"direction":                        eaS("Inbound"),
			"enable_auto_scaling":              eaB(false),
			"enabled":                          eaB(false),
			"http_application_routing_enabled": eaB(true),
			"load_balancer_sku":                eaS("public"),
			"local_account_disabled":           eaB(true),
			"min_protocol_version":             eaS(">= 1.0"),
			"mode":                             eaS("public"),
			"network_profile":                  eaS("public"),
			"node_os_upgrade_channel":          eaS("public"),
			"os_disk_type":                     eaS("String"),
			"private_cluster_enabled":          eaB(false),
			"run_command_enabled":              eaL(eaS("curl https://example.com/install.sh | sh")),
			"security_rule":                    eaB(false),
			"sku":                              eaS("public"),
			"source_address_prefix":            eaS("*"),
			"source_address_prefixes":          eaS("*"),
			"ssl_policy":                       eaS("TLS_1_0"),
			"standard":                         eaS("public"),
			"threat_intel_mode":                eaS("public"),
			"waf_configuration":                eaS("public"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-226: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-226: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-226: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-226: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{
		"Alert":                            eaU(),
		"Allow":                            eaU(),
		"Deny":                             eaU(),
		"Detection":                        eaU(),
		"Ephemeral":                        eaU(),
		"Inbound":                          eaU(),
		"NodeImage":                        eaU(),
		"Prevention":                       eaU(),
		"SecurityPatch":                    eaU(),
		"Standard":                         eaU(),
		"TLSv1_2":                          eaU(),
		"absent":                           eaU(),
		"access":                           eaU(),
		"api_server_access_profile":        eaU(),
		"authorized_ip_ranges":             eaU(),
		"copy_paste_enabled":               eaU(),
		"default_node_pool":                eaU(),
		"direction":                        eaU(),
		"enable_auto_scaling":              eaU(),
		"enabled":                          eaU(),
		"false":                            eaU(),
		"http_application_routing_enabled": eaU(),
		"load_balancer_sku":                eaU(),
		"local_account_disabled":           eaU(),
		"min_protocol_version":             eaU(),
		"mode":                             eaU(),
		"network_profile":                  eaU(),
		"node_os_upgrade_channel":          eaU(),
		"os_disk_type":                     eaU(),
		"private_cluster_enabled":          eaU(),
		"run_command_enabled":              eaU(),
		"security_rule":                    eaU(),
		"sku":                              eaU(),
		"source_address_prefix":            eaU(),
		"source_address_prefixes":          eaU(),
		"ssl_policy":                       eaU(),
		"standard":                         eaU(),
		"threat_intel_mode":                eaU(),
		"true":                             eaU(),
		"waf_configuration":                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-226: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_227(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-227")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{
			"default_node_pool": eaL(eaM("Alert", eaS("public"), "Allow", eaS("public"), "Deny", eaS("public"), "Detection", eaS("public"), "Ephemeral", eaS("public"), "Inbound", eaS("public"), "NodeImage", eaS("ubuntu:latest"), "Prevention", eaS("public"), "SecurityPatch", eaB(false), "Standard", eaS("public"), "TLSv1_2", eaS("public"), "absent", eaS("public"), "access", eaS("Allow"), "api_server_access_profile", eaS("Allow"), "authorized_ip_ranges", eaL(eaS("0.0.0.0/0")), "copy_paste_enabled", eaB(false), "default_node_pool", eaS("public"), "direction", eaS("Inbound"), "enable_auto_scaling", eaB(false), "enabled", eaB(false), "http_application_routing_enabled", eaB(true), "load_balancer_sku", eaS("public"), "local_account_disabled", eaB(true), "min_protocol_version", eaS(">= 1.0"), "mode", eaS("public"), "network_profile", eaS("public"), "node_os_upgrade_channel", eaS("public"), "os_disk_type", eaS("String"), "private_cluster_enabled", eaB(false), "run_command_enabled", eaL(eaS("curl https://example.com/install.sh | sh")), "security_rule", eaB(false), "sku", eaS("public"), "source_address_prefix", eaS("*"), "source_address_prefixes", eaS("*"), "ssl_policy", eaS("TLS_1_0"), "standard", eaS("public"), "threat_intel_mode", eaS("public"), "waf_configuration", eaS("public"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-227: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-227: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-227: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-227: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{
		"Alert":                            eaU(),
		"Allow":                            eaU(),
		"Deny":                             eaU(),
		"Detection":                        eaU(),
		"Ephemeral":                        eaU(),
		"Inbound":                          eaU(),
		"NodeImage":                        eaU(),
		"Prevention":                       eaU(),
		"SecurityPatch":                    eaU(),
		"Standard":                         eaU(),
		"TLSv1_2":                          eaU(),
		"absent":                           eaU(),
		"access":                           eaU(),
		"api_server_access_profile":        eaU(),
		"authorized_ip_ranges":             eaU(),
		"copy_paste_enabled":               eaU(),
		"default_node_pool":                eaU(),
		"direction":                        eaU(),
		"enable_auto_scaling":              eaU(),
		"enabled":                          eaU(),
		"false":                            eaU(),
		"http_application_routing_enabled": eaU(),
		"load_balancer_sku":                eaU(),
		"local_account_disabled":           eaU(),
		"min_protocol_version":             eaU(),
		"mode":                             eaU(),
		"network_profile":                  eaU(),
		"node_os_upgrade_channel":          eaU(),
		"os_disk_type":                     eaU(),
		"private_cluster_enabled":          eaU(),
		"run_command_enabled":              eaU(),
		"security_rule":                    eaU(),
		"sku":                              eaU(),
		"source_address_prefix":            eaU(),
		"source_address_prefixes":          eaU(),
		"ssl_policy":                       eaU(),
		"standard":                         eaU(),
		"threat_intel_mode":                eaU(),
		"true":                             eaU(),
		"waf_configuration":                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-227: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_228(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-228")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-228: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-228: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-228: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{
			"node_os_upgrade_channel": eaL(eaM("Alert", eaS("public"), "Allow", eaS("public"), "Deny", eaS("public"), "Detection", eaS("public"), "Ephemeral", eaS("public"), "Inbound", eaS("public"), "NodeImage", eaS("ubuntu:latest"), "Prevention", eaS("public"), "SecurityPatch", eaB(false), "Standard", eaS("public"), "TLSv1_2", eaS("public"), "absent", eaS("public"), "access", eaS("Allow"), "api_server_access_profile", eaS("Allow"), "authorized_ip_ranges", eaL(eaS("0.0.0.0/0")), "copy_paste_enabled", eaB(false), "default_node_pool", eaS("public"), "direction", eaS("Inbound"), "enable_auto_scaling", eaB(false), "enabled", eaB(false), "http_application_routing_enabled", eaB(true), "load_balancer_sku", eaS("public"), "local_account_disabled", eaB(true), "min_protocol_version", eaS(">= 1.0"), "mode", eaS("public"), "network_profile", eaS("public"), "node_os_upgrade_channel", eaS("public"), "os_disk_type", eaS("String"), "private_cluster_enabled", eaB(false), "run_command_enabled", eaL(eaS("curl https://example.com/install.sh | sh")), "security_rule", eaB(false), "sku", eaS("public"), "source_address_prefix", eaS("*"), "source_address_prefixes", eaS("*"), "ssl_policy", eaS("TLS_1_0"), "standard", eaS("public"), "threat_intel_mode", eaS("public"), "waf_configuration", eaS("public"))),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-228: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{
		"Alert":                            eaU(),
		"Allow":                            eaU(),
		"Deny":                             eaU(),
		"Detection":                        eaU(),
		"Ephemeral":                        eaU(),
		"Inbound":                          eaU(),
		"NodeImage":                        eaU(),
		"Prevention":                       eaU(),
		"SecurityPatch":                    eaU(),
		"Standard":                         eaU(),
		"TLSv1_2":                          eaU(),
		"absent":                           eaU(),
		"access":                           eaU(),
		"api_server_access_profile":        eaU(),
		"authorized_ip_ranges":             eaU(),
		"copy_paste_enabled":               eaU(),
		"default_node_pool":                eaU(),
		"direction":                        eaU(),
		"enable_auto_scaling":              eaU(),
		"enabled":                          eaU(),
		"false":                            eaU(),
		"http_application_routing_enabled": eaU(),
		"load_balancer_sku":                eaU(),
		"local_account_disabled":           eaU(),
		"min_protocol_version":             eaU(),
		"mode":                             eaU(),
		"network_profile":                  eaU(),
		"node_os_upgrade_channel":          eaU(),
		"os_disk_type":                     eaU(),
		"private_cluster_enabled":          eaU(),
		"run_command_enabled":              eaU(),
		"security_rule":                    eaU(),
		"sku":                              eaU(),
		"source_address_prefix":            eaU(),
		"source_address_prefixes":          eaU(),
		"ssl_policy":                       eaU(),
		"standard":                         eaU(),
		"threat_intel_mode":                eaU(),
		"true":                             eaU(),
		"waf_configuration":                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-228: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_229(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-229")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-229: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-229: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-229: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{
			"Alert":                            eaS("public"),
			"Allow":                            eaS("public"),
			"Deny":                             eaS("public"),
			"Detection":                        eaS("public"),
			"Ephemeral":                        eaS("public"),
			"Inbound":                          eaS("public"),
			"NodeImage":                        eaS("ubuntu:latest"),
			"Prevention":                       eaS("public"),
			"SecurityPatch":                    eaB(false),
			"Standard":                         eaS("public"),
			"TLSv1_2":                          eaS("public"),
			"absent":                           eaS("public"),
			"access":                           eaS("Allow"),
			"api_server_access_profile":        eaS("Allow"),
			"authorized_ip_ranges":             eaL(eaS("0.0.0.0/0")),
			"copy_paste_enabled":               eaB(false),
			"default_node_pool":                eaS("public"),
			"direction":                        eaS("Inbound"),
			"enable_auto_scaling":              eaB(false),
			"enabled":                          eaB(false),
			"http_application_routing_enabled": eaB(true),
			"load_balancer_sku":                eaS("public"),
			"local_account_disabled":           eaB(true),
			"min_protocol_version":             eaS(">= 1.0"),
			"mode":                             eaS("public"),
			"network_profile":                  eaS("public"),
			"node_os_upgrade_channel":          eaS("public"),
			"os_disk_type":                     eaS("String"),
			"private_cluster_enabled":          eaB(false),
			"run_command_enabled":              eaL(eaS("curl https://example.com/install.sh | sh")),
			"security_rule":                    eaB(false),
			"sku":                              eaS("public"),
			"source_address_prefix":            eaS("*"),
			"source_address_prefixes":          eaS("*"),
			"ssl_policy":                       eaS("TLS_1_0"),
			"standard":                         eaS("public"),
			"threat_intel_mode":                eaS("public"),
			"waf_configuration":                eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-229: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{
		"Alert":                            eaU(),
		"Allow":                            eaU(),
		"Deny":                             eaU(),
		"Detection":                        eaU(),
		"Ephemeral":                        eaU(),
		"Inbound":                          eaU(),
		"NodeImage":                        eaU(),
		"Prevention":                       eaU(),
		"SecurityPatch":                    eaU(),
		"Standard":                         eaU(),
		"TLSv1_2":                          eaU(),
		"absent":                           eaU(),
		"access":                           eaU(),
		"api_server_access_profile":        eaU(),
		"authorized_ip_ranges":             eaU(),
		"copy_paste_enabled":               eaU(),
		"default_node_pool":                eaU(),
		"direction":                        eaU(),
		"enable_auto_scaling":              eaU(),
		"enabled":                          eaU(),
		"false":                            eaU(),
		"http_application_routing_enabled": eaU(),
		"load_balancer_sku":                eaU(),
		"local_account_disabled":           eaU(),
		"min_protocol_version":             eaU(),
		"mode":                             eaU(),
		"network_profile":                  eaU(),
		"node_os_upgrade_channel":          eaU(),
		"os_disk_type":                     eaU(),
		"private_cluster_enabled":          eaU(),
		"run_command_enabled":              eaU(),
		"security_rule":                    eaU(),
		"sku":                              eaU(),
		"source_address_prefix":            eaU(),
		"source_address_prefixes":          eaU(),
		"ssl_policy":                       eaU(),
		"standard":                         eaU(),
		"threat_intel_mode":                eaU(),
		"true":                             eaU(),
		"waf_configuration":                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-229: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_231(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-231")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-231: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-231: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-231: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{
			"Alert":                            eaS("public"),
			"Allow":                            eaS("public"),
			"Deny":                             eaS("public"),
			"Detection":                        eaS("public"),
			"Ephemeral":                        eaS("public"),
			"Inbound":                          eaS("public"),
			"NodeImage":                        eaS("ubuntu:latest"),
			"Prevention":                       eaS("public"),
			"SecurityPatch":                    eaB(false),
			"Standard":                         eaS("public"),
			"TLSv1_2":                          eaS("public"),
			"absent":                           eaS("public"),
			"access":                           eaS("Allow"),
			"api_server_access_profile":        eaS("Allow"),
			"authorized_ip_ranges":             eaL(eaS("0.0.0.0/0")),
			"copy_paste_enabled":               eaB(false),
			"default_node_pool":                eaS("public"),
			"direction":                        eaS("Inbound"),
			"enable_auto_scaling":              eaB(false),
			"enabled":                          eaB(false),
			"http_application_routing_enabled": eaB(true),
			"load_balancer_sku":                eaS("public"),
			"local_account_disabled":           eaB(true),
			"min_protocol_version":             eaS(">= 1.0"),
			"mode":                             eaS("public"),
			"network_profile":                  eaS("public"),
			"node_os_upgrade_channel":          eaS("public"),
			"os_disk_type":                     eaS("String"),
			"private_cluster_enabled":          eaB(false),
			"run_command_enabled":              eaL(eaS("curl https://example.com/install.sh | sh")),
			"security_rule":                    eaB(false),
			"sku":                              eaS("public"),
			"source_address_prefix":            eaS("*"),
			"source_address_prefixes":          eaS("*"),
			"ssl_policy":                       eaS("TLS_1_0"),
			"standard":                         eaS("public"),
			"threat_intel_mode":                eaS("public"),
			"waf_configuration":                eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-231: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{
		"Alert":                            eaU(),
		"Allow":                            eaU(),
		"Deny":                             eaU(),
		"Detection":                        eaU(),
		"Ephemeral":                        eaU(),
		"Inbound":                          eaU(),
		"NodeImage":                        eaU(),
		"Prevention":                       eaU(),
		"SecurityPatch":                    eaU(),
		"Standard":                         eaU(),
		"TLSv1_2":                          eaU(),
		"absent":                           eaU(),
		"access":                           eaU(),
		"api_server_access_profile":        eaU(),
		"authorized_ip_ranges":             eaU(),
		"copy_paste_enabled":               eaU(),
		"default_node_pool":                eaU(),
		"direction":                        eaU(),
		"enable_auto_scaling":              eaU(),
		"enabled":                          eaU(),
		"false":                            eaU(),
		"http_application_routing_enabled": eaU(),
		"load_balancer_sku":                eaU(),
		"local_account_disabled":           eaU(),
		"min_protocol_version":             eaU(),
		"mode":                             eaU(),
		"network_profile":                  eaU(),
		"node_os_upgrade_channel":          eaU(),
		"os_disk_type":                     eaU(),
		"private_cluster_enabled":          eaU(),
		"run_command_enabled":              eaU(),
		"security_rule":                    eaU(),
		"sku":                              eaU(),
		"source_address_prefix":            eaU(),
		"source_address_prefixes":          eaU(),
		"ssl_policy":                       eaU(),
		"standard":                         eaU(),
		"threat_intel_mode":                eaU(),
		"true":                             eaU(),
		"waf_configuration":                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-231: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_232(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-232")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{
			"network_profile": eaL(eaM("Alert", eaS("public"), "Allow", eaS("public"), "Deny", eaS("public"), "Detection", eaS("public"), "Ephemeral", eaS("public"), "Inbound", eaS("public"), "NodeImage", eaS("ubuntu:latest"), "Prevention", eaS("public"), "SecurityPatch", eaB(false), "Standard", eaS("public"), "TLSv1_2", eaS("public"), "absent", eaS("public"), "access", eaS("Allow"), "api_server_access_profile", eaS("Allow"), "authorized_ip_ranges", eaL(eaS("0.0.0.0/0")), "copy_paste_enabled", eaB(false), "default_node_pool", eaS("public"), "direction", eaS("Inbound"), "enable_auto_scaling", eaB(false), "enabled", eaB(false), "http_application_routing_enabled", eaB(true), "load_balancer_sku", eaS("public"), "local_account_disabled", eaB(true), "min_protocol_version", eaS(">= 1.0"), "mode", eaS("public"), "network_profile", eaS("public"), "node_os_upgrade_channel", eaS("public"), "os_disk_type", eaS("String"), "private_cluster_enabled", eaB(false), "run_command_enabled", eaL(eaS("curl https://example.com/install.sh | sh")), "security_rule", eaB(false), "sku", eaS("public"), "source_address_prefix", eaS("*"), "source_address_prefixes", eaS("*"), "ssl_policy", eaS("TLS_1_0"), "standard", eaS("public"), "threat_intel_mode", eaS("public"), "waf_configuration", eaS("public"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-232: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-232: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-232: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-232: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{
		"Alert":                            eaU(),
		"Allow":                            eaU(),
		"Deny":                             eaU(),
		"Detection":                        eaU(),
		"Ephemeral":                        eaU(),
		"Inbound":                          eaU(),
		"NodeImage":                        eaU(),
		"Prevention":                       eaU(),
		"SecurityPatch":                    eaU(),
		"Standard":                         eaU(),
		"TLSv1_2":                          eaU(),
		"absent":                           eaU(),
		"access":                           eaU(),
		"api_server_access_profile":        eaU(),
		"authorized_ip_ranges":             eaU(),
		"copy_paste_enabled":               eaU(),
		"default_node_pool":                eaU(),
		"direction":                        eaU(),
		"enable_auto_scaling":              eaU(),
		"enabled":                          eaU(),
		"false":                            eaU(),
		"http_application_routing_enabled": eaU(),
		"load_balancer_sku":                eaU(),
		"local_account_disabled":           eaU(),
		"min_protocol_version":             eaU(),
		"mode":                             eaU(),
		"network_profile":                  eaU(),
		"node_os_upgrade_channel":          eaU(),
		"os_disk_type":                     eaU(),
		"private_cluster_enabled":          eaU(),
		"run_command_enabled":              eaU(),
		"security_rule":                    eaU(),
		"sku":                              eaU(),
		"source_address_prefix":            eaU(),
		"source_address_prefixes":          eaU(),
		"ssl_policy":                       eaU(),
		"standard":                         eaU(),
		"threat_intel_mode":                eaU(),
		"true":                             eaU(),
		"waf_configuration":                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-232: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_233(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-233")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{
			"default_node_pool": eaL(eaM("Alert", eaS("public"), "Allow", eaS("public"), "Deny", eaS("public"), "Detection", eaS("public"), "Ephemeral", eaS("public"), "Inbound", eaS("public"), "NodeImage", eaS("ubuntu:latest"), "Prevention", eaS("public"), "SecurityPatch", eaB(false), "Standard", eaS("public"), "TLSv1_2", eaS("public"), "absent", eaS("public"), "access", eaS("Allow"), "api_server_access_profile", eaS("Allow"), "authorized_ip_ranges", eaL(eaS("0.0.0.0/0")), "copy_paste_enabled", eaB(false), "default_node_pool", eaS("public"), "direction", eaS("Inbound"), "enable_auto_scaling", eaB(false), "enabled", eaB(false), "http_application_routing_enabled", eaB(true), "load_balancer_sku", eaS("public"), "local_account_disabled", eaB(true), "min_protocol_version", eaS(">= 1.0"), "mode", eaS("public"), "network_profile", eaS("public"), "node_os_upgrade_channel", eaS("public"), "os_disk_type", eaS("String"), "private_cluster_enabled", eaB(false), "run_command_enabled", eaL(eaS("curl https://example.com/install.sh | sh")), "security_rule", eaB(false), "sku", eaS("public"), "source_address_prefix", eaS("*"), "source_address_prefixes", eaS("*"), "ssl_policy", eaS("TLS_1_0"), "standard", eaS("public"), "threat_intel_mode", eaS("public"), "waf_configuration", eaS("public"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-233: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-233: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-233: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-233: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_kubernetes_cluster", "probe", map[string]ir.Value{
		"Alert":                            eaU(),
		"Allow":                            eaU(),
		"Deny":                             eaU(),
		"Detection":                        eaU(),
		"Ephemeral":                        eaU(),
		"Inbound":                          eaU(),
		"NodeImage":                        eaU(),
		"Prevention":                       eaU(),
		"SecurityPatch":                    eaU(),
		"Standard":                         eaU(),
		"TLSv1_2":                          eaU(),
		"absent":                           eaU(),
		"access":                           eaU(),
		"api_server_access_profile":        eaU(),
		"authorized_ip_ranges":             eaU(),
		"copy_paste_enabled":               eaU(),
		"default_node_pool":                eaU(),
		"direction":                        eaU(),
		"enable_auto_scaling":              eaU(),
		"enabled":                          eaU(),
		"false":                            eaU(),
		"http_application_routing_enabled": eaU(),
		"load_balancer_sku":                eaU(),
		"local_account_disabled":           eaU(),
		"min_protocol_version":             eaU(),
		"mode":                             eaU(),
		"network_profile":                  eaU(),
		"node_os_upgrade_channel":          eaU(),
		"os_disk_type":                     eaU(),
		"private_cluster_enabled":          eaU(),
		"run_command_enabled":              eaU(),
		"security_rule":                    eaU(),
		"sku":                              eaU(),
		"source_address_prefix":            eaU(),
		"source_address_prefixes":          eaU(),
		"ssl_policy":                       eaU(),
		"standard":                         eaU(),
		"threat_intel_mode":                eaU(),
		"true":                             eaU(),
		"waf_configuration":                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-233: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_235(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-235")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_network_watcher_flow_log", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-235: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-235: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-235: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_network_watcher_flow_log", "probe", map[string]ir.Value{
			"Alert":                            eaS("private"),
			"Allow":                            eaS("private"),
			"Deny":                             eaS("private"),
			"Detection":                        eaS("private"),
			"Ephemeral":                        eaS("private"),
			"Inbound":                          eaS("private"),
			"NodeImage":                        eaS("ubuntu:22.04"),
			"Prevention":                       eaS("private"),
			"SecurityPatch":                    eaB(true),
			"Standard":                         eaS("private"),
			"TLSv1_2":                          eaS("private"),
			"absent":                           eaS("private"),
			"access":                           eaS("Deny"),
			"api_server_access_profile":        eaS("Deny"),
			"authorized_ip_ranges":             eaL(eaS("10.0.0.0/8")),
			"copy_paste_enabled":               eaB(true),
			"default_node_pool":                eaS("private"),
			"direction":                        eaS("Inbound"),
			"enable_auto_scaling":              eaB(true),
			"enabled":                          eaB(true),
			"http_application_routing_enabled": eaB(false),
			"load_balancer_sku":                eaS("private"),
			"local_account_disabled":           eaB(false),
			"min_protocol_version":             eaS("~> 5.0"),
			"mode":                             eaS("private"),
			"network_profile":                  eaS("private"),
			"node_os_upgrade_channel":          eaS("private"),
			"os_disk_type":                     eaS("SecureString"),
			"private_cluster_enabled":          eaB(true),
			"run_command_enabled":              eaL(eaS("echo hello")),
			"security_rule":                    eaB(true),
			"sku":                              eaS("private"),
			"source_address_prefix":            eaS("10.0.0.0/8"),
			"source_address_prefixes":          eaS("10.0.0.0/8"),
			"ssl_policy":                       eaS("TLS_1_2"),
			"standard":                         eaS("private"),
			"threat_intel_mode":                eaS("private"),
			"waf_configuration":                eaS("private"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-235: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_network_watcher_flow_log", "probe", map[string]ir.Value{
		"Alert":                            eaU(),
		"Allow":                            eaU(),
		"Deny":                             eaU(),
		"Detection":                        eaU(),
		"Ephemeral":                        eaU(),
		"Inbound":                          eaU(),
		"NodeImage":                        eaU(),
		"Prevention":                       eaU(),
		"SecurityPatch":                    eaU(),
		"Standard":                         eaU(),
		"TLSv1_2":                          eaU(),
		"absent":                           eaU(),
		"access":                           eaU(),
		"api_server_access_profile":        eaU(),
		"authorized_ip_ranges":             eaU(),
		"copy_paste_enabled":               eaU(),
		"default_node_pool":                eaU(),
		"direction":                        eaU(),
		"enable_auto_scaling":              eaU(),
		"enabled":                          eaU(),
		"false":                            eaU(),
		"http_application_routing_enabled": eaU(),
		"load_balancer_sku":                eaU(),
		"local_account_disabled":           eaU(),
		"min_protocol_version":             eaU(),
		"mode":                             eaU(),
		"network_profile":                  eaU(),
		"node_os_upgrade_channel":          eaU(),
		"os_disk_type":                     eaU(),
		"private_cluster_enabled":          eaU(),
		"run_command_enabled":              eaU(),
		"security_rule":                    eaU(),
		"sku":                              eaU(),
		"source_address_prefix":            eaU(),
		"source_address_prefixes":          eaU(),
		"ssl_policy":                       eaU(),
		"standard":                         eaU(),
		"threat_intel_mode":                eaU(),
		"true":                             eaU(),
		"waf_configuration":                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-235: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_236(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-236")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_firewall", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-236: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-236: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-236: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_firewall", "probe", map[string]ir.Value{
			"threat_intel_mode": eaL(eaM("Alert", eaS("public"), "Allow", eaS("public"), "Deny", eaS("public"), "Detection", eaS("public"), "Ephemeral", eaS("public"), "Inbound", eaS("public"), "NodeImage", eaS("ubuntu:latest"), "Prevention", eaS("public"), "SecurityPatch", eaB(false), "Standard", eaS("public"), "TLSv1_2", eaS("public"), "absent", eaS("public"), "access", eaS("Allow"), "api_server_access_profile", eaS("Allow"), "authorized_ip_ranges", eaL(eaS("0.0.0.0/0")), "copy_paste_enabled", eaB(false), "default_node_pool", eaS("public"), "direction", eaS("Inbound"), "enable_auto_scaling", eaB(false), "enabled", eaB(false), "http_application_routing_enabled", eaB(true), "load_balancer_sku", eaS("public"), "local_account_disabled", eaB(true), "min_protocol_version", eaS(">= 1.0"), "mode", eaS("public"), "network_profile", eaS("public"), "node_os_upgrade_channel", eaS("public"), "os_disk_type", eaS("String"), "private_cluster_enabled", eaB(false), "run_command_enabled", eaL(eaS("curl https://example.com/install.sh | sh")), "security_rule", eaB(false), "sku", eaS("public"), "source_address_prefix", eaS("*"), "source_address_prefixes", eaS("*"), "ssl_policy", eaS("TLS_1_0"), "standard", eaS("public"), "threat_intel_mode", eaS("public"), "waf_configuration", eaS("public"))),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-236: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_firewall", "probe", map[string]ir.Value{
		"Alert":                            eaU(),
		"Allow":                            eaU(),
		"Deny":                             eaU(),
		"Detection":                        eaU(),
		"Ephemeral":                        eaU(),
		"Inbound":                          eaU(),
		"NodeImage":                        eaU(),
		"Prevention":                       eaU(),
		"SecurityPatch":                    eaU(),
		"Standard":                         eaU(),
		"TLSv1_2":                          eaU(),
		"absent":                           eaU(),
		"access":                           eaU(),
		"api_server_access_profile":        eaU(),
		"authorized_ip_ranges":             eaU(),
		"copy_paste_enabled":               eaU(),
		"default_node_pool":                eaU(),
		"direction":                        eaU(),
		"enable_auto_scaling":              eaU(),
		"enabled":                          eaU(),
		"false":                            eaU(),
		"http_application_routing_enabled": eaU(),
		"load_balancer_sku":                eaU(),
		"local_account_disabled":           eaU(),
		"min_protocol_version":             eaU(),
		"mode":                             eaU(),
		"network_profile":                  eaU(),
		"node_os_upgrade_channel":          eaU(),
		"os_disk_type":                     eaU(),
		"private_cluster_enabled":          eaU(),
		"run_command_enabled":              eaU(),
		"security_rule":                    eaU(),
		"sku":                              eaU(),
		"source_address_prefix":            eaU(),
		"source_address_prefixes":          eaU(),
		"ssl_policy":                       eaU(),
		"standard":                         eaU(),
		"threat_intel_mode":                eaU(),
		"true":                             eaU(),
		"waf_configuration":                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-236: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_237(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-237")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_bastion_host", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-237: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-237: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-237: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_bastion_host", "probe", map[string]ir.Value{
			"Alert":                            eaS("public"),
			"Allow":                            eaS("public"),
			"Deny":                             eaS("public"),
			"Detection":                        eaS("public"),
			"Ephemeral":                        eaS("public"),
			"Inbound":                          eaS("public"),
			"NodeImage":                        eaS("ubuntu:latest"),
			"Prevention":                       eaS("public"),
			"SecurityPatch":                    eaB(false),
			"Standard":                         eaS("public"),
			"TLSv1_2":                          eaS("public"),
			"absent":                           eaS("public"),
			"access":                           eaS("Allow"),
			"api_server_access_profile":        eaS("Allow"),
			"authorized_ip_ranges":             eaL(eaS("0.0.0.0/0")),
			"copy_paste_enabled":               eaB(false),
			"default_node_pool":                eaS("public"),
			"direction":                        eaS("Inbound"),
			"enable_auto_scaling":              eaB(false),
			"enabled":                          eaB(false),
			"http_application_routing_enabled": eaB(true),
			"load_balancer_sku":                eaS("public"),
			"local_account_disabled":           eaB(true),
			"min_protocol_version":             eaS(">= 1.0"),
			"mode":                             eaS("public"),
			"network_profile":                  eaS("public"),
			"node_os_upgrade_channel":          eaS("public"),
			"os_disk_type":                     eaS("String"),
			"private_cluster_enabled":          eaB(false),
			"run_command_enabled":              eaL(eaS("curl https://example.com/install.sh | sh")),
			"security_rule":                    eaB(false),
			"sku":                              eaS("public"),
			"source_address_prefix":            eaS("*"),
			"source_address_prefixes":          eaS("*"),
			"ssl_policy":                       eaS("TLS_1_0"),
			"standard":                         eaS("public"),
			"threat_intel_mode":                eaS("public"),
			"waf_configuration":                eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-237: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_bastion_host", "probe", map[string]ir.Value{
		"Alert":                            eaU(),
		"Allow":                            eaU(),
		"Deny":                             eaU(),
		"Detection":                        eaU(),
		"Ephemeral":                        eaU(),
		"Inbound":                          eaU(),
		"NodeImage":                        eaU(),
		"Prevention":                       eaU(),
		"SecurityPatch":                    eaU(),
		"Standard":                         eaU(),
		"TLSv1_2":                          eaU(),
		"absent":                           eaU(),
		"access":                           eaU(),
		"api_server_access_profile":        eaU(),
		"authorized_ip_ranges":             eaU(),
		"copy_paste_enabled":               eaU(),
		"default_node_pool":                eaU(),
		"direction":                        eaU(),
		"enable_auto_scaling":              eaU(),
		"enabled":                          eaU(),
		"false":                            eaU(),
		"http_application_routing_enabled": eaU(),
		"load_balancer_sku":                eaU(),
		"local_account_disabled":           eaU(),
		"min_protocol_version":             eaU(),
		"mode":                             eaU(),
		"network_profile":                  eaU(),
		"node_os_upgrade_channel":          eaU(),
		"os_disk_type":                     eaU(),
		"private_cluster_enabled":          eaU(),
		"run_command_enabled":              eaU(),
		"security_rule":                    eaU(),
		"sku":                              eaU(),
		"source_address_prefix":            eaU(),
		"source_address_prefixes":          eaU(),
		"ssl_policy":                       eaU(),
		"standard":                         eaU(),
		"threat_intel_mode":                eaU(),
		"true":                             eaU(),
		"waf_configuration":                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-237: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_238(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-238")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_frontdoor_firewall_policy", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-238: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-238: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-238: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_frontdoor_firewall_policy", "probe", map[string]ir.Value{
			"mode": eaL(eaM("Alert", eaS("public"), "Allow", eaS("public"), "Deny", eaS("public"), "Detection", eaS("public"), "Ephemeral", eaS("public"), "Inbound", eaS("public"), "NodeImage", eaS("ubuntu:latest"), "Prevention", eaS("public"), "SecurityPatch", eaB(false), "Standard", eaS("public"), "TLSv1_2", eaS("public"), "absent", eaS("public"), "access", eaS("Allow"), "api_server_access_profile", eaS("Allow"), "authorized_ip_ranges", eaL(eaS("0.0.0.0/0")), "copy_paste_enabled", eaB(false), "default_node_pool", eaS("public"), "direction", eaS("Inbound"), "enable_auto_scaling", eaB(false), "enabled", eaB(false), "http_application_routing_enabled", eaB(true), "load_balancer_sku", eaS("public"), "local_account_disabled", eaB(true), "min_protocol_version", eaS(">= 1.0"), "mode", eaS("public"), "network_profile", eaS("public"), "node_os_upgrade_channel", eaS("public"), "os_disk_type", eaS("String"), "private_cluster_enabled", eaB(false), "run_command_enabled", eaL(eaS("curl https://example.com/install.sh | sh")), "security_rule", eaB(false), "sku", eaS("public"), "source_address_prefix", eaS("*"), "source_address_prefixes", eaS("*"), "ssl_policy", eaS("TLS_1_0"), "standard", eaS("public"), "threat_intel_mode", eaS("public"), "waf_configuration", eaS("public"))),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-238: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_frontdoor_firewall_policy", "probe", map[string]ir.Value{
		"Alert":                            eaU(),
		"Allow":                            eaU(),
		"Deny":                             eaU(),
		"Detection":                        eaU(),
		"Ephemeral":                        eaU(),
		"Inbound":                          eaU(),
		"NodeImage":                        eaU(),
		"Prevention":                       eaU(),
		"SecurityPatch":                    eaU(),
		"Standard":                         eaU(),
		"TLSv1_2":                          eaU(),
		"absent":                           eaU(),
		"access":                           eaU(),
		"api_server_access_profile":        eaU(),
		"authorized_ip_ranges":             eaU(),
		"copy_paste_enabled":               eaU(),
		"default_node_pool":                eaU(),
		"direction":                        eaU(),
		"enable_auto_scaling":              eaU(),
		"enabled":                          eaU(),
		"false":                            eaU(),
		"http_application_routing_enabled": eaU(),
		"load_balancer_sku":                eaU(),
		"local_account_disabled":           eaU(),
		"min_protocol_version":             eaU(),
		"mode":                             eaU(),
		"network_profile":                  eaU(),
		"node_os_upgrade_channel":          eaU(),
		"os_disk_type":                     eaU(),
		"private_cluster_enabled":          eaU(),
		"run_command_enabled":              eaU(),
		"security_rule":                    eaU(),
		"sku":                              eaU(),
		"source_address_prefix":            eaU(),
		"source_address_prefixes":          eaU(),
		"ssl_policy":                       eaU(),
		"standard":                         eaU(),
		"threat_intel_mode":                eaU(),
		"true":                             eaU(),
		"waf_configuration":                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-238: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_239(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-239")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_application_gateway", "probe", map[string]ir.Value{
			"waf_configuration": eaL(eaM("Alert", eaS("public"), "Allow", eaS("public"), "Deny", eaS("public"), "Detection", eaS("public"), "Ephemeral", eaS("public"), "Inbound", eaS("public"), "NodeImage", eaS("ubuntu:latest"), "Prevention", eaS("public"), "SecurityPatch", eaB(false), "Standard", eaS("public"), "TLSv1_2", eaS("public"), "absent", eaS("public"), "access", eaS("Allow"), "api_server_access_profile", eaS("Allow"), "authorized_ip_ranges", eaL(eaS("0.0.0.0/0")), "copy_paste_enabled", eaB(false), "default_node_pool", eaS("public"), "direction", eaS("Inbound"), "enable_auto_scaling", eaB(false), "enabled", eaB(false), "http_application_routing_enabled", eaB(true), "load_balancer_sku", eaS("public"), "local_account_disabled", eaB(true), "min_protocol_version", eaS(">= 1.0"), "mode", eaS("public"), "network_profile", eaS("public"), "node_os_upgrade_channel", eaS("public"), "os_disk_type", eaS("String"), "private_cluster_enabled", eaB(false), "run_command_enabled", eaL(eaS("curl https://example.com/install.sh | sh")), "security_rule", eaB(false), "sku", eaS("public"), "source_address_prefix", eaS("*"), "source_address_prefixes", eaS("*"), "ssl_policy", eaS("TLS_1_0"), "standard", eaS("public"), "threat_intel_mode", eaS("public"), "waf_configuration", eaS("public"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-239: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-239: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-239: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_application_gateway", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-239: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_application_gateway", "probe", map[string]ir.Value{
		"Alert":                            eaU(),
		"Allow":                            eaU(),
		"Deny":                             eaU(),
		"Detection":                        eaU(),
		"Ephemeral":                        eaU(),
		"Inbound":                          eaU(),
		"NodeImage":                        eaU(),
		"Prevention":                       eaU(),
		"SecurityPatch":                    eaU(),
		"Standard":                         eaU(),
		"TLSv1_2":                          eaU(),
		"absent":                           eaU(),
		"access":                           eaU(),
		"api_server_access_profile":        eaU(),
		"authorized_ip_ranges":             eaU(),
		"copy_paste_enabled":               eaU(),
		"default_node_pool":                eaU(),
		"direction":                        eaU(),
		"enable_auto_scaling":              eaU(),
		"enabled":                          eaU(),
		"false":                            eaU(),
		"http_application_routing_enabled": eaU(),
		"load_balancer_sku":                eaU(),
		"local_account_disabled":           eaU(),
		"min_protocol_version":             eaU(),
		"mode":                             eaU(),
		"network_profile":                  eaU(),
		"node_os_upgrade_channel":          eaU(),
		"os_disk_type":                     eaU(),
		"private_cluster_enabled":          eaU(),
		"run_command_enabled":              eaU(),
		"security_rule":                    eaU(),
		"sku":                              eaU(),
		"source_address_prefix":            eaU(),
		"source_address_prefixes":          eaU(),
		"ssl_policy":                       eaU(),
		"standard":                         eaU(),
		"threat_intel_mode":                eaU(),
		"true":                             eaU(),
		"waf_configuration":                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-239: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_240(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-240")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_application_gateway", "probe", map[string]ir.Value{
			"ssl_policy": eaL(eaM("Alert", eaS("public"), "Allow", eaS("public"), "Deny", eaS("public"), "Detection", eaS("public"), "Ephemeral", eaS("public"), "Inbound", eaS("public"), "NodeImage", eaS("ubuntu:latest"), "Prevention", eaS("public"), "SecurityPatch", eaB(false), "Standard", eaS("public"), "TLSv1_2", eaS("public"), "absent", eaS("public"), "access", eaS("Allow"), "api_server_access_profile", eaS("Allow"), "authorized_ip_ranges", eaL(eaS("0.0.0.0/0")), "copy_paste_enabled", eaB(false), "default_node_pool", eaS("public"), "direction", eaS("Inbound"), "enable_auto_scaling", eaB(false), "enabled", eaB(false), "http_application_routing_enabled", eaB(true), "load_balancer_sku", eaS("public"), "local_account_disabled", eaB(true), "min_protocol_version", eaS(">= 1.0"), "mode", eaS("public"), "network_profile", eaS("public"), "node_os_upgrade_channel", eaS("public"), "os_disk_type", eaS("String"), "private_cluster_enabled", eaB(false), "run_command_enabled", eaL(eaS("curl https://example.com/install.sh | sh")), "security_rule", eaB(false), "sku", eaS("public"), "source_address_prefix", eaS("*"), "source_address_prefixes", eaS("*"), "ssl_policy", eaS("TLS_1_0"), "standard", eaS("public"), "threat_intel_mode", eaS("public"), "waf_configuration", eaS("public"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-240: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-240: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-240: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_application_gateway", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-240: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_application_gateway", "probe", map[string]ir.Value{
		"Alert":                            eaU(),
		"Allow":                            eaU(),
		"Deny":                             eaU(),
		"Detection":                        eaU(),
		"Ephemeral":                        eaU(),
		"Inbound":                          eaU(),
		"NodeImage":                        eaU(),
		"Prevention":                       eaU(),
		"SecurityPatch":                    eaU(),
		"Standard":                         eaU(),
		"TLSv1_2":                          eaU(),
		"absent":                           eaU(),
		"access":                           eaU(),
		"api_server_access_profile":        eaU(),
		"authorized_ip_ranges":             eaU(),
		"copy_paste_enabled":               eaU(),
		"default_node_pool":                eaU(),
		"direction":                        eaU(),
		"enable_auto_scaling":              eaU(),
		"enabled":                          eaU(),
		"false":                            eaU(),
		"http_application_routing_enabled": eaU(),
		"load_balancer_sku":                eaU(),
		"local_account_disabled":           eaU(),
		"min_protocol_version":             eaU(),
		"mode":                             eaU(),
		"network_profile":                  eaU(),
		"node_os_upgrade_channel":          eaU(),
		"os_disk_type":                     eaU(),
		"private_cluster_enabled":          eaU(),
		"run_command_enabled":              eaU(),
		"security_rule":                    eaU(),
		"sku":                              eaU(),
		"source_address_prefix":            eaU(),
		"source_address_prefixes":          eaU(),
		"ssl_policy":                       eaU(),
		"standard":                         eaU(),
		"threat_intel_mode":                eaU(),
		"true":                             eaU(),
		"waf_configuration":                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-240: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_241(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-241")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_public_ip", "probe", map[string]ir.Value{
			"Alert":                            eaS("public"),
			"Allow":                            eaS("public"),
			"Deny":                             eaS("public"),
			"Detection":                        eaS("public"),
			"Ephemeral":                        eaS("public"),
			"Inbound":                          eaS("public"),
			"NodeImage":                        eaS("ubuntu:latest"),
			"Prevention":                       eaS("public"),
			"SecurityPatch":                    eaB(false),
			"Standard":                         eaS("public"),
			"TLSv1_2":                          eaS("public"),
			"absent":                           eaS("public"),
			"access":                           eaS("Allow"),
			"api_server_access_profile":        eaS("Allow"),
			"authorized_ip_ranges":             eaL(eaS("0.0.0.0/0")),
			"copy_paste_enabled":               eaB(false),
			"default_node_pool":                eaS("public"),
			"direction":                        eaS("Inbound"),
			"enable_auto_scaling":              eaB(false),
			"enabled":                          eaB(false),
			"http_application_routing_enabled": eaB(true),
			"load_balancer_sku":                eaS("public"),
			"local_account_disabled":           eaB(true),
			"min_protocol_version":             eaS(">= 1.0"),
			"mode":                             eaS("public"),
			"network_profile":                  eaS("public"),
			"node_os_upgrade_channel":          eaS("public"),
			"os_disk_type":                     eaS("String"),
			"private_cluster_enabled":          eaB(false),
			"run_command_enabled":              eaL(eaS("curl https://example.com/install.sh | sh")),
			"security_rule":                    eaB(false),
			"sku":                              eaS("public"),
			"source_address_prefix":            eaS("*"),
			"source_address_prefixes":          eaS("*"),
			"ssl_policy":                       eaS("TLS_1_0"),
			"standard":                         eaS("public"),
			"threat_intel_mode":                eaS("public"),
			"waf_configuration":                eaS("public"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-241: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-241: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-241: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_public_ip", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-241: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_public_ip", "probe", map[string]ir.Value{
		"Alert":                            eaU(),
		"Allow":                            eaU(),
		"Deny":                             eaU(),
		"Detection":                        eaU(),
		"Ephemeral":                        eaU(),
		"Inbound":                          eaU(),
		"NodeImage":                        eaU(),
		"Prevention":                       eaU(),
		"SecurityPatch":                    eaU(),
		"Standard":                         eaU(),
		"TLSv1_2":                          eaU(),
		"absent":                           eaU(),
		"access":                           eaU(),
		"api_server_access_profile":        eaU(),
		"authorized_ip_ranges":             eaU(),
		"copy_paste_enabled":               eaU(),
		"default_node_pool":                eaU(),
		"direction":                        eaU(),
		"enable_auto_scaling":              eaU(),
		"enabled":                          eaU(),
		"false":                            eaU(),
		"http_application_routing_enabled": eaU(),
		"load_balancer_sku":                eaU(),
		"local_account_disabled":           eaU(),
		"min_protocol_version":             eaU(),
		"mode":                             eaU(),
		"network_profile":                  eaU(),
		"node_os_upgrade_channel":          eaU(),
		"os_disk_type":                     eaU(),
		"private_cluster_enabled":          eaU(),
		"run_command_enabled":              eaU(),
		"security_rule":                    eaU(),
		"sku":                              eaU(),
		"source_address_prefix":            eaU(),
		"source_address_prefixes":          eaU(),
		"ssl_policy":                       eaU(),
		"standard":                         eaU(),
		"threat_intel_mode":                eaU(),
		"true":                             eaU(),
		"waf_configuration":                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-241: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_242(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-242")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_lb", "probe", map[string]ir.Value{
			"Alert":                            eaS("public"),
			"Allow":                            eaS("public"),
			"Deny":                             eaS("public"),
			"Detection":                        eaS("public"),
			"Ephemeral":                        eaS("public"),
			"Inbound":                          eaS("public"),
			"NodeImage":                        eaS("ubuntu:latest"),
			"Prevention":                       eaS("public"),
			"SecurityPatch":                    eaB(false),
			"Standard":                         eaS("public"),
			"TLSv1_2":                          eaS("public"),
			"absent":                           eaS("public"),
			"access":                           eaS("Allow"),
			"api_server_access_profile":        eaS("Allow"),
			"authorized_ip_ranges":             eaL(eaS("0.0.0.0/0")),
			"copy_paste_enabled":               eaB(false),
			"default_node_pool":                eaS("public"),
			"direction":                        eaS("Inbound"),
			"enable_auto_scaling":              eaB(false),
			"enabled":                          eaB(false),
			"http_application_routing_enabled": eaB(true),
			"load_balancer_sku":                eaS("public"),
			"local_account_disabled":           eaB(true),
			"min_protocol_version":             eaS(">= 1.0"),
			"mode":                             eaS("public"),
			"network_profile":                  eaS("public"),
			"node_os_upgrade_channel":          eaS("public"),
			"os_disk_type":                     eaS("String"),
			"private_cluster_enabled":          eaB(false),
			"run_command_enabled":              eaL(eaS("curl https://example.com/install.sh | sh")),
			"security_rule":                    eaB(false),
			"sku":                              eaS("public"),
			"source_address_prefix":            eaS("*"),
			"source_address_prefixes":          eaS("*"),
			"ssl_policy":                       eaS("TLS_1_0"),
			"standard":                         eaS("public"),
			"threat_intel_mode":                eaS("public"),
			"waf_configuration":                eaS("public"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-242: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-242: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-242: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_lb", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-242: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_lb", "probe", map[string]ir.Value{
		"Alert":                            eaU(),
		"Allow":                            eaU(),
		"Deny":                             eaU(),
		"Detection":                        eaU(),
		"Ephemeral":                        eaU(),
		"Inbound":                          eaU(),
		"NodeImage":                        eaU(),
		"Prevention":                       eaU(),
		"SecurityPatch":                    eaU(),
		"Standard":                         eaU(),
		"TLSv1_2":                          eaU(),
		"absent":                           eaU(),
		"access":                           eaU(),
		"api_server_access_profile":        eaU(),
		"authorized_ip_ranges":             eaU(),
		"copy_paste_enabled":               eaU(),
		"default_node_pool":                eaU(),
		"direction":                        eaU(),
		"enable_auto_scaling":              eaU(),
		"enabled":                          eaU(),
		"false":                            eaU(),
		"http_application_routing_enabled": eaU(),
		"load_balancer_sku":                eaU(),
		"local_account_disabled":           eaU(),
		"min_protocol_version":             eaU(),
		"mode":                             eaU(),
		"network_profile":                  eaU(),
		"node_os_upgrade_channel":          eaU(),
		"os_disk_type":                     eaU(),
		"private_cluster_enabled":          eaU(),
		"run_command_enabled":              eaU(),
		"security_rule":                    eaU(),
		"sku":                              eaU(),
		"source_address_prefix":            eaU(),
		"source_address_prefixes":          eaU(),
		"ssl_policy":                       eaU(),
		"standard":                         eaU(),
		"threat_intel_mode":                eaU(),
		"true":                             eaU(),
		"waf_configuration":                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-242: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_244(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-244")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_network_security_group", "probe", map[string]ir.Value{
			"security_rule": eaL(eaM("Alert", eaS("public"), "Allow", eaS("public"), "Deny", eaS("public"), "Detection", eaS("public"), "Ephemeral", eaS("public"), "Inbound", eaS("public"), "NodeImage", eaS("ubuntu:latest"), "Prevention", eaS("public"), "SecurityPatch", eaB(false), "Standard", eaS("public"), "TLSv1_2", eaS("public"), "absent", eaS("public"), "access", eaS("Allow"), "api_server_access_profile", eaS("Allow"), "authorized_ip_ranges", eaL(eaS("0.0.0.0/0")), "copy_paste_enabled", eaB(false), "default_node_pool", eaS("public"), "direction", eaS("Inbound"), "enable_auto_scaling", eaB(false), "enabled", eaB(false), "http_application_routing_enabled", eaB(true), "load_balancer_sku", eaS("public"), "local_account_disabled", eaB(true), "min_protocol_version", eaS(">= 1.0"), "mode", eaS("public"), "network_profile", eaS("public"), "node_os_upgrade_channel", eaS("public"), "os_disk_type", eaS("String"), "private_cluster_enabled", eaB(false), "run_command_enabled", eaL(eaS("curl https://example.com/install.sh | sh")), "security_rule", eaB(false), "sku", eaS("public"), "source_address_prefix", eaS("*"), "source_address_prefixes", eaS("*"), "ssl_policy", eaS("TLS_1_0"), "standard", eaS("public"), "threat_intel_mode", eaS("public"), "waf_configuration", eaS("public"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-244: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-244: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-244: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_network_security_group", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-244: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_network_security_group", "probe", map[string]ir.Value{
		"Alert":                            eaU(),
		"Allow":                            eaU(),
		"Deny":                             eaU(),
		"Detection":                        eaU(),
		"Ephemeral":                        eaU(),
		"Inbound":                          eaU(),
		"NodeImage":                        eaU(),
		"Prevention":                       eaU(),
		"SecurityPatch":                    eaU(),
		"Standard":                         eaU(),
		"TLSv1_2":                          eaU(),
		"absent":                           eaU(),
		"access":                           eaU(),
		"api_server_access_profile":        eaU(),
		"authorized_ip_ranges":             eaU(),
		"copy_paste_enabled":               eaU(),
		"default_node_pool":                eaU(),
		"direction":                        eaU(),
		"enable_auto_scaling":              eaU(),
		"enabled":                          eaU(),
		"false":                            eaU(),
		"http_application_routing_enabled": eaU(),
		"load_balancer_sku":                eaU(),
		"local_account_disabled":           eaU(),
		"min_protocol_version":             eaU(),
		"mode":                             eaU(),
		"network_profile":                  eaU(),
		"node_os_upgrade_channel":          eaU(),
		"os_disk_type":                     eaU(),
		"private_cluster_enabled":          eaU(),
		"run_command_enabled":              eaU(),
		"security_rule":                    eaU(),
		"sku":                              eaU(),
		"source_address_prefix":            eaU(),
		"source_address_prefixes":          eaU(),
		"ssl_policy":                       eaU(),
		"standard":                         eaU(),
		"threat_intel_mode":                eaU(),
		"true":                             eaU(),
		"waf_configuration":                eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-244: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_246(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-246")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_security_center_subscription_pricing", "probe", map[string]ir.Value{
			"Arm":                           eaS("public"),
			"Deny":                          eaS("public"),
			"Standard":                      eaS("public"),
			"absent":                        eaS("public"),
			"alert_notifications":           eaS("public"),
			"anonymous_pull_enabled":        eaB(true),
			"customer_managed_key_id":       eaS("password123"),
			"default_action":                eaL(eaS("*")),
			"empty":                         eaS("public"),
			"enabled":                       eaB(false),
			"encoded_values":                eaS("public"),
			"encryption":                    eaB(false),
			"export_policy_enabled":         eaS("3389"),
			"internet_ingestion_enabled":    eaB(false),
			"internet_query_enabled":        eaB(false),
			"key":                           eaS("password123"),
			"network_rule_set":              eaS("public"),
			"password":                      eaS("password123"),
			"public_network_access_enabled": eaS("Allow"),
			"resource_type":                 eaS("String"),
			"retention_in_days":             eaN(1.0),
			"retention_policy":              eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"secret":                        eaS("password123"),
			"tier":                          eaS("public"),
			"token":                         eaS("password123"),
			"trust_policy_enabled":          eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-246: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-246: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-246: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_security_center_subscription_pricing", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-246: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_security_center_subscription_pricing", "probe", map[string]ir.Value{
		"Arm":                           eaU(),
		"Deny":                          eaU(),
		"Standard":                      eaU(),
		"absent":                        eaU(),
		"alert_notifications":           eaU(),
		"anonymous_pull_enabled":        eaU(),
		"customer_managed_key_id":       eaU(),
		"default_action":                eaU(),
		"empty":                         eaU(),
		"enabled":                       eaU(),
		"encoded_values":                eaU(),
		"encryption":                    eaU(),
		"export_policy_enabled":         eaU(),
		"internet_ingestion_enabled":    eaU(),
		"internet_query_enabled":        eaU(),
		"key":                           eaU(),
		"network_rule_set":              eaU(),
		"password":                      eaU(),
		"public_network_access_enabled": eaU(),
		"resource_type":                 eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"secret":                        eaU(),
		"tier":                          eaU(),
		"token":                         eaU(),
		"true":                          eaU(),
		"trust_policy_enabled":          eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-246: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_247(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-247")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_security_center_contact", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-247: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-247: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-247: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_security_center_contact", "probe", map[string]ir.Value{
			"Arm":                           eaS("public"),
			"Deny":                          eaS("public"),
			"Standard":                      eaS("public"),
			"absent":                        eaS("public"),
			"alert_notifications":           eaS("public"),
			"anonymous_pull_enabled":        eaB(true),
			"customer_managed_key_id":       eaS("password123"),
			"default_action":                eaL(eaS("*")),
			"empty":                         eaS("public"),
			"enabled":                       eaB(false),
			"encoded_values":                eaS("public"),
			"encryption":                    eaB(false),
			"export_policy_enabled":         eaS("3389"),
			"identity":                      eaS("public"),
			"internet_ingestion_enabled":    eaB(false),
			"internet_query_enabled":        eaB(false),
			"key":                           eaS("password123"),
			"network_rule_set":              eaS("public"),
			"password":                      eaS("password123"),
			"public_network_access_enabled": eaS("Allow"),
			"resource_type":                 eaS("String"),
			"retention_in_days":             eaN(1.0),
			"retention_policy":              eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"secret":                        eaS("password123"),
			"tier":                          eaS("public"),
			"token":                         eaS("password123"),
			"trust_policy_enabled":          eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-247: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_security_center_contact", "probe", map[string]ir.Value{
		"Arm":                           eaU(),
		"Deny":                          eaU(),
		"Standard":                      eaU(),
		"absent":                        eaU(),
		"alert_notifications":           eaU(),
		"anonymous_pull_enabled":        eaU(),
		"customer_managed_key_id":       eaU(),
		"default_action":                eaU(),
		"empty":                         eaU(),
		"enabled":                       eaU(),
		"encoded_values":                eaU(),
		"encryption":                    eaU(),
		"export_policy_enabled":         eaU(),
		"false":                         eaU(),
		"identity":                      eaU(),
		"internet_ingestion_enabled":    eaU(),
		"internet_query_enabled":        eaU(),
		"key":                           eaU(),
		"network_rule_set":              eaU(),
		"password":                      eaU(),
		"public_network_access_enabled": eaU(),
		"resource_type":                 eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"secret":                        eaU(),
		"tier":                          eaU(),
		"token":                         eaU(),
		"true":                          eaU(),
		"trust_policy_enabled":          eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-247: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_248(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-248")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_log_analytics_workspace", "probe", map[string]ir.Value{
			"Arm":                           eaS("public"),
			"Deny":                          eaS("public"),
			"Standard":                      eaS("public"),
			"absent":                        eaS("public"),
			"alert_notifications":           eaS("public"),
			"anonymous_pull_enabled":        eaB(true),
			"customer_managed_key_id":       eaS("password123"),
			"default_action":                eaL(eaS("*")),
			"empty":                         eaS("public"),
			"enabled":                       eaB(false),
			"encoded_values":                eaS("public"),
			"encryption":                    eaB(false),
			"export_policy_enabled":         eaS("3389"),
			"internet_ingestion_enabled":    eaB(false),
			"internet_query_enabled":        eaB(false),
			"key":                           eaS("password123"),
			"network_rule_set":              eaS("public"),
			"password":                      eaS("password123"),
			"public_network_access_enabled": eaS("Allow"),
			"resource_type":                 eaS("String"),
			"retention_in_days":             eaN(1.0),
			"retention_policy":              eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"secret":                        eaS("password123"),
			"tier":                          eaS("public"),
			"token":                         eaS("password123"),
			"trust_policy_enabled":          eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-248: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-248: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-248: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_log_analytics_workspace", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-248: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_log_analytics_workspace", "probe", map[string]ir.Value{
		"Arm":                           eaU(),
		"Deny":                          eaU(),
		"Standard":                      eaU(),
		"absent":                        eaU(),
		"alert_notifications":           eaU(),
		"anonymous_pull_enabled":        eaU(),
		"customer_managed_key_id":       eaU(),
		"default_action":                eaU(),
		"empty":                         eaU(),
		"enabled":                       eaU(),
		"encoded_values":                eaU(),
		"encryption":                    eaU(),
		"export_policy_enabled":         eaU(),
		"internet_ingestion_enabled":    eaU(),
		"internet_query_enabled":        eaU(),
		"key":                           eaU(),
		"network_rule_set":              eaU(),
		"password":                      eaU(),
		"public_network_access_enabled": eaU(),
		"resource_type":                 eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"secret":                        eaU(),
		"tier":                          eaU(),
		"token":                         eaU(),
		"true":                          eaU(),
		"trust_policy_enabled":          eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-248: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_249(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-249")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_log_analytics_workspace", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-249: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-249: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-249: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_log_analytics_workspace", "probe", map[string]ir.Value{
			"Arm":                           eaS("public"),
			"Deny":                          eaS("public"),
			"Standard":                      eaS("public"),
			"absent":                        eaS("public"),
			"alert_notifications":           eaS("public"),
			"anonymous_pull_enabled":        eaB(true),
			"customer_managed_key_id":       eaS("password123"),
			"default_action":                eaL(eaS("*")),
			"empty":                         eaS("public"),
			"enabled":                       eaB(false),
			"encoded_values":                eaS("public"),
			"encryption":                    eaB(false),
			"export_policy_enabled":         eaS("3389"),
			"internet_ingestion_enabled":    eaB(false),
			"internet_query_enabled":        eaB(false),
			"key":                           eaS("password123"),
			"network_rule_set":              eaS("public"),
			"password":                      eaS("password123"),
			"public_network_access_enabled": eaS("Allow"),
			"resource_type":                 eaS("String"),
			"retention_in_days":             eaN(1.0),
			"retention_policy":              eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"secret":                        eaS("password123"),
			"tier":                          eaS("public"),
			"token":                         eaS("password123"),
			"trust_policy_enabled":          eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-249: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_log_analytics_workspace", "probe", map[string]ir.Value{
		"Arm":                           eaU(),
		"Deny":                          eaU(),
		"Standard":                      eaU(),
		"absent":                        eaU(),
		"alert_notifications":           eaU(),
		"anonymous_pull_enabled":        eaU(),
		"customer_managed_key_id":       eaU(),
		"default_action":                eaU(),
		"empty":                         eaU(),
		"enabled":                       eaU(),
		"encoded_values":                eaU(),
		"encryption":                    eaU(),
		"export_policy_enabled":         eaU(),
		"internet_ingestion_enabled":    eaU(),
		"internet_query_enabled":        eaU(),
		"key":                           eaU(),
		"network_rule_set":              eaU(),
		"password":                      eaU(),
		"public_network_access_enabled": eaU(),
		"resource_type":                 eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"secret":                        eaU(),
		"tier":                          eaU(),
		"token":                         eaU(),
		"true":                          eaU(),
		"trust_policy_enabled":          eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-249: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_250(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-250")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_log_analytics_workspace", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-250: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-250: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-250: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_log_analytics_workspace", "probe", map[string]ir.Value{
			"Arm":                           eaS("public"),
			"Deny":                          eaS("public"),
			"Standard":                      eaS("public"),
			"absent":                        eaS("public"),
			"alert_notifications":           eaS("public"),
			"anonymous_pull_enabled":        eaB(true),
			"customer_managed_key_id":       eaS("password123"),
			"default_action":                eaL(eaS("*")),
			"empty":                         eaS("public"),
			"enabled":                       eaB(false),
			"encoded_values":                eaS("public"),
			"encryption":                    eaB(false),
			"export_policy_enabled":         eaS("3389"),
			"internet_ingestion_enabled":    eaB(false),
			"internet_query_enabled":        eaB(false),
			"key":                           eaS("password123"),
			"network_rule_set":              eaS("public"),
			"password":                      eaS("password123"),
			"public_network_access_enabled": eaS("Allow"),
			"resource_type":                 eaS("String"),
			"retention_in_days":             eaN(1.0),
			"retention_policy":              eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"secret":                        eaS("password123"),
			"tier":                          eaS("public"),
			"token":                         eaS("password123"),
			"trust_policy_enabled":          eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-250: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_log_analytics_workspace", "probe", map[string]ir.Value{
		"Arm":                           eaU(),
		"Deny":                          eaU(),
		"Standard":                      eaU(),
		"absent":                        eaU(),
		"alert_notifications":           eaU(),
		"anonymous_pull_enabled":        eaU(),
		"customer_managed_key_id":       eaU(),
		"default_action":                eaU(),
		"empty":                         eaU(),
		"enabled":                       eaU(),
		"encoded_values":                eaU(),
		"encryption":                    eaU(),
		"export_policy_enabled":         eaU(),
		"internet_ingestion_enabled":    eaU(),
		"internet_query_enabled":        eaU(),
		"key":                           eaU(),
		"network_rule_set":              eaU(),
		"password":                      eaU(),
		"public_network_access_enabled": eaU(),
		"resource_type":                 eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"secret":                        eaU(),
		"tier":                          eaU(),
		"token":                         eaU(),
		"true":                          eaU(),
		"trust_policy_enabled":          eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-250: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_251(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-251")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_container_registry", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-251: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-251: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-251: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_container_registry", "probe", map[string]ir.Value{
			"Arm":                           eaS("public"),
			"Deny":                          eaS("public"),
			"Standard":                      eaS("public"),
			"absent":                        eaS("public"),
			"alert_notifications":           eaS("public"),
			"anonymous_pull_enabled":        eaB(true),
			"customer_managed_key_id":       eaS("password123"),
			"default_action":                eaL(eaS("*")),
			"empty":                         eaS("public"),
			"enabled":                       eaB(false),
			"encoded_values":                eaS("public"),
			"encryption":                    eaB(false),
			"export_policy_enabled":         eaS("3389"),
			"identity":                      eaS("public"),
			"internet_ingestion_enabled":    eaB(false),
			"internet_query_enabled":        eaB(false),
			"key":                           eaS("password123"),
			"network_rule_set":              eaS("public"),
			"password":                      eaS("password123"),
			"public_network_access_enabled": eaS("Allow"),
			"resource_type":                 eaS("String"),
			"retention_in_days":             eaN(1.0),
			"retention_policy":              eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"secret":                        eaS("password123"),
			"tier":                          eaS("public"),
			"token":                         eaS("password123"),
			"trust_policy_enabled":          eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-251: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_container_registry", "probe", map[string]ir.Value{
		"Arm":                           eaU(),
		"Deny":                          eaU(),
		"Standard":                      eaU(),
		"absent":                        eaU(),
		"alert_notifications":           eaU(),
		"anonymous_pull_enabled":        eaU(),
		"customer_managed_key_id":       eaU(),
		"default_action":                eaU(),
		"empty":                         eaU(),
		"enabled":                       eaU(),
		"encoded_values":                eaU(),
		"encryption":                    eaU(),
		"export_policy_enabled":         eaU(),
		"false":                         eaU(),
		"identity":                      eaU(),
		"internet_ingestion_enabled":    eaU(),
		"internet_query_enabled":        eaU(),
		"key":                           eaU(),
		"network_rule_set":              eaU(),
		"password":                      eaU(),
		"public_network_access_enabled": eaU(),
		"resource_type":                 eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"secret":                        eaU(),
		"tier":                          eaU(),
		"token":                         eaU(),
		"true":                          eaU(),
		"trust_policy_enabled":          eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-251: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_252(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-252")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_container_registry", "probe", map[string]ir.Value{
			"Arm":                           eaS("public"),
			"Deny":                          eaS("public"),
			"Standard":                      eaS("public"),
			"absent":                        eaS("public"),
			"alert_notifications":           eaS("public"),
			"anonymous_pull_enabled":        eaB(true),
			"customer_managed_key_id":       eaS("password123"),
			"default_action":                eaL(eaS("*")),
			"empty":                         eaS("public"),
			"enabled":                       eaB(false),
			"encoded_values":                eaS("public"),
			"encryption":                    eaB(false),
			"export_policy_enabled":         eaS("3389"),
			"internet_ingestion_enabled":    eaB(false),
			"internet_query_enabled":        eaB(false),
			"key":                           eaS("password123"),
			"network_rule_set":              eaS("public"),
			"password":                      eaS("password123"),
			"public_network_access_enabled": eaS("Allow"),
			"resource_type":                 eaS("String"),
			"retention_in_days":             eaN(1.0),
			"retention_policy":              eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"secret":                        eaS("password123"),
			"tier":                          eaS("public"),
			"token":                         eaS("password123"),
			"trust_policy_enabled":          eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-252: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-252: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-252: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_container_registry", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-252: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_container_registry", "probe", map[string]ir.Value{
		"Arm":                           eaU(),
		"Deny":                          eaU(),
		"Standard":                      eaU(),
		"absent":                        eaU(),
		"alert_notifications":           eaU(),
		"anonymous_pull_enabled":        eaU(),
		"customer_managed_key_id":       eaU(),
		"default_action":                eaU(),
		"empty":                         eaU(),
		"enabled":                       eaU(),
		"encoded_values":                eaU(),
		"encryption":                    eaU(),
		"export_policy_enabled":         eaU(),
		"internet_ingestion_enabled":    eaU(),
		"internet_query_enabled":        eaU(),
		"key":                           eaU(),
		"network_rule_set":              eaU(),
		"password":                      eaU(),
		"public_network_access_enabled": eaU(),
		"resource_type":                 eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"secret":                        eaU(),
		"tier":                          eaU(),
		"token":                         eaU(),
		"true":                          eaU(),
		"trust_policy_enabled":          eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-252: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_253(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-253")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_container_registry", "probe", map[string]ir.Value{
			"network_rule_set": eaM("AWS_SECRET_ACCESS_KEY", eaS("x"), "api_key", eaS("x"), "password", eaS("x"), "private_key", eaS("x"), "secret", eaS("x"), "token", eaS("x")),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-253: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-253: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-253: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_container_registry", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-253: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_container_registry", "probe", map[string]ir.Value{
		"Arm":                           eaU(),
		"Deny":                          eaU(),
		"Standard":                      eaU(),
		"absent":                        eaU(),
		"alert_notifications":           eaU(),
		"anonymous_pull_enabled":        eaU(),
		"customer_managed_key_id":       eaU(),
		"default_action":                eaU(),
		"empty":                         eaU(),
		"enabled":                       eaU(),
		"encoded_values":                eaU(),
		"encryption":                    eaU(),
		"export_policy_enabled":         eaU(),
		"internet_ingestion_enabled":    eaU(),
		"internet_query_enabled":        eaU(),
		"key":                           eaU(),
		"network_rule_set":              eaU(),
		"password":                      eaU(),
		"public_network_access_enabled": eaU(),
		"resource_type":                 eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"secret":                        eaU(),
		"tier":                          eaU(),
		"token":                         eaU(),
		"true":                          eaU(),
		"trust_policy_enabled":          eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-253: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_254(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-254")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_container_registry", "probe", map[string]ir.Value{
			"Arm":                           eaB(true),
			"Deny":                          eaB(true),
			"Standard":                      eaB(true),
			"absent":                        eaB(true),
			"alert_notifications":           eaB(true),
			"anonymous_pull_enabled":        eaB(true),
			"customer_managed_key_id":       eaB(true),
			"default_action":                eaB(true),
			"empty":                         eaB(true),
			"enabled":                       eaB(true),
			"encoded_values":                eaB(true),
			"encryption":                    eaB(true),
			"export_policy_enabled":         eaB(true),
			"internet_ingestion_enabled":    eaB(true),
			"internet_query_enabled":        eaB(true),
			"key":                           eaB(true),
			"network_rule_set":              eaB(true),
			"password":                      eaB(true),
			"public_network_access_enabled": eaB(true),
			"resource_type":                 eaB(true),
			"retention_in_days":             eaB(true),
			"retention_policy":              eaB(true),
			"secret":                        eaB(true),
			"tier":                          eaB(true),
			"token":                         eaB(true),
			"trust_policy_enabled":          eaB(true),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-254: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-254: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-254: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_container_registry", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-254: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_container_registry", "probe", map[string]ir.Value{
		"Arm":                           eaU(),
		"Deny":                          eaU(),
		"Standard":                      eaU(),
		"absent":                        eaU(),
		"alert_notifications":           eaU(),
		"anonymous_pull_enabled":        eaU(),
		"customer_managed_key_id":       eaU(),
		"default_action":                eaU(),
		"empty":                         eaU(),
		"enabled":                       eaU(),
		"encoded_values":                eaU(),
		"encryption":                    eaU(),
		"export_policy_enabled":         eaU(),
		"internet_ingestion_enabled":    eaU(),
		"internet_query_enabled":        eaU(),
		"key":                           eaU(),
		"network_rule_set":              eaU(),
		"password":                      eaU(),
		"public_network_access_enabled": eaU(),
		"resource_type":                 eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"secret":                        eaU(),
		"tier":                          eaU(),
		"token":                         eaU(),
		"true":                          eaU(),
		"trust_policy_enabled":          eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-254: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_255(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-255")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_container_registry", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-255: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-255: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-255: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_container_registry", "probe", map[string]ir.Value{
			"Arm":                           eaS("public"),
			"Deny":                          eaS("public"),
			"Standard":                      eaS("public"),
			"absent":                        eaS("public"),
			"alert_notifications":           eaS("public"),
			"anonymous_pull_enabled":        eaB(true),
			"azurerm_container_registry":    eaS("public"),
			"customer_managed_key_id":       eaS("password123"),
			"default_action":                eaL(eaS("*")),
			"empty":                         eaS("public"),
			"enabled":                       eaB(false),
			"encoded_values":                eaS("public"),
			"encryption":                    eaB(false),
			"export_policy_enabled":         eaS("3389"),
			"internet_ingestion_enabled":    eaB(false),
			"internet_query_enabled":        eaB(false),
			"key":                           eaS("password123"),
			"network_rule_set":              eaS("public"),
			"password":                      eaS("password123"),
			"public_network_access_enabled": eaS("Allow"),
			"resource_type":                 eaS("String"),
			"retention_in_days":             eaN(1.0),
			"retention_policy":              eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"secret":                        eaS("password123"),
			"tier":                          eaS("public"),
			"token":                         eaS("password123"),
			"trust_policy_enabled":          eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-255: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_container_registry", "probe", map[string]ir.Value{
		"Arm":                           eaU(),
		"Deny":                          eaU(),
		"Standard":                      eaU(),
		"absent":                        eaU(),
		"alert_notifications":           eaU(),
		"anonymous_pull_enabled":        eaU(),
		"azurerm_container_registry":    eaU(),
		"customer_managed_key_id":       eaU(),
		"default_action":                eaU(),
		"empty":                         eaU(),
		"enabled":                       eaU(),
		"encoded_values":                eaU(),
		"encryption":                    eaU(),
		"export_policy_enabled":         eaU(),
		"internet_ingestion_enabled":    eaU(),
		"internet_query_enabled":        eaU(),
		"key":                           eaU(),
		"network_rule_set":              eaU(),
		"password":                      eaU(),
		"public_network_access_enabled": eaU(),
		"resource_type":                 eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"secret":                        eaU(),
		"tier":                          eaU(),
		"token":                         eaU(),
		"true":                          eaU(),
		"trust_policy_enabled":          eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-255: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_256(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-256")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_container_registry_task", "probe", map[string]ir.Value{
			"encoded_values": eaM("Arm", eaS("public"), "Deny", eaS("public"), "Standard", eaS("public"), "absent", eaS("public"), "alert_notifications", eaS("public"), "anonymous_pull_enabled", eaB(true), "customer_managed_key_id", eaS("password123"), "default_action", eaL(eaS("*")), "empty", eaS("public"), "enabled", eaB(false), "encoded_values", eaS("public"), "encryption", eaB(false), "export_policy_enabled", eaS("3389"), "internet_ingestion_enabled", eaB(false), "internet_query_enabled", eaB(false), "key", eaS("password123"), "network_rule_set", eaS("public"), "password", eaS("password123"), "public_network_access_enabled", eaS("Allow"), "resource_type", eaS("String"), "retention_in_days", eaN(1.0), "retention_policy", eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"), "secret", eaS("password123"), "tier", eaS("public"), "token", eaS("password123"), "trust_policy_enabled", eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}")),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-256: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-256: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-256: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_container_registry_task", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-256: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_container_registry_task", "probe", map[string]ir.Value{
		"Arm":                           eaU(),
		"Deny":                          eaU(),
		"Standard":                      eaU(),
		"absent":                        eaU(),
		"alert_notifications":           eaU(),
		"anonymous_pull_enabled":        eaU(),
		"customer_managed_key_id":       eaU(),
		"default_action":                eaU(),
		"empty":                         eaU(),
		"enabled":                       eaU(),
		"encoded_values":                eaU(),
		"encryption":                    eaU(),
		"export_policy_enabled":         eaU(),
		"internet_ingestion_enabled":    eaU(),
		"internet_query_enabled":        eaU(),
		"key":                           eaU(),
		"network_rule_set":              eaU(),
		"password":                      eaU(),
		"public_network_access_enabled": eaU(),
		"resource_type":                 eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"secret":                        eaU(),
		"tier":                          eaU(),
		"token":                         eaU(),
		"true":                          eaU(),
		"trust_policy_enabled":          eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-256: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_257(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-257")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_container_registry", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-257: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-257: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-257: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_container_registry", "probe", map[string]ir.Value{
			"Arm":                           eaS("public"),
			"Deny":                          eaS("public"),
			"Standard":                      eaS("public"),
			"absent":                        eaS("public"),
			"alert_notifications":           eaS("public"),
			"anonymous_pull_enabled":        eaB(true),
			"customer_managed_key_id":       eaS("password123"),
			"default_action":                eaL(eaS("*")),
			"empty":                         eaS("public"),
			"enabled":                       eaB(false),
			"encoded_values":                eaS("public"),
			"encryption":                    eaB(false),
			"export_policy_enabled":         eaS("3389"),
			"internet_ingestion_enabled":    eaB(false),
			"internet_query_enabled":        eaB(false),
			"key":                           eaS("password123"),
			"network_rule_set":              eaS("public"),
			"password":                      eaS("password123"),
			"public_network_access_enabled": eaS("Allow"),
			"resource_type":                 eaS("String"),
			"retention_in_days":             eaN(1.0),
			"retention_policy":              eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"secret":                        eaS("password123"),
			"tier":                          eaS("public"),
			"token":                         eaS("password123"),
			"trust_policy_enabled":          eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-257: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_container_registry", "probe", map[string]ir.Value{
		"Arm":                           eaU(),
		"Deny":                          eaU(),
		"Standard":                      eaU(),
		"absent":                        eaU(),
		"alert_notifications":           eaU(),
		"anonymous_pull_enabled":        eaU(),
		"customer_managed_key_id":       eaU(),
		"default_action":                eaU(),
		"empty":                         eaU(),
		"enabled":                       eaU(),
		"encoded_values":                eaU(),
		"encryption":                    eaU(),
		"export_policy_enabled":         eaU(),
		"internet_ingestion_enabled":    eaU(),
		"internet_query_enabled":        eaU(),
		"key":                           eaU(),
		"network_rule_set":              eaU(),
		"password":                      eaU(),
		"public_network_access_enabled": eaU(),
		"resource_type":                 eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"secret":                        eaU(),
		"tier":                          eaU(),
		"token":                         eaU(),
		"true":                          eaU(),
		"trust_policy_enabled":          eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-257: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_258(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-258")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_application_insights", "probe", map[string]ir.Value{
			"Arm":                           eaS("public"),
			"Deny":                          eaS("public"),
			"Standard":                      eaS("public"),
			"absent":                        eaS("public"),
			"alert_notifications":           eaS("public"),
			"anonymous_pull_enabled":        eaB(true),
			"customer_managed_key_id":       eaS("password123"),
			"default_action":                eaL(eaS("*")),
			"empty":                         eaS("public"),
			"enabled":                       eaB(false),
			"encoded_values":                eaS("public"),
			"encryption":                    eaB(false),
			"export_policy_enabled":         eaS("3389"),
			"internet_ingestion_enabled":    eaB(false),
			"internet_query_enabled":        eaB(false),
			"key":                           eaS("password123"),
			"network_rule_set":              eaS("public"),
			"password":                      eaS("password123"),
			"public_network_access_enabled": eaS("Allow"),
			"resource_type":                 eaS("String"),
			"retention_in_days":             eaN(1.0),
			"retention_policy":              eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"secret":                        eaS("password123"),
			"tier":                          eaS("public"),
			"token":                         eaS("password123"),
			"trust_policy_enabled":          eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-258: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-258: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-258: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_application_insights", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-258: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_application_insights", "probe", map[string]ir.Value{
		"Arm":                           eaU(),
		"Deny":                          eaU(),
		"Standard":                      eaU(),
		"absent":                        eaU(),
		"alert_notifications":           eaU(),
		"anonymous_pull_enabled":        eaU(),
		"customer_managed_key_id":       eaU(),
		"default_action":                eaU(),
		"empty":                         eaU(),
		"enabled":                       eaU(),
		"encoded_values":                eaU(),
		"encryption":                    eaU(),
		"export_policy_enabled":         eaU(),
		"internet_ingestion_enabled":    eaU(),
		"internet_query_enabled":        eaU(),
		"key":                           eaU(),
		"network_rule_set":              eaU(),
		"password":                      eaU(),
		"public_network_access_enabled": eaU(),
		"resource_type":                 eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"secret":                        eaU(),
		"tier":                          eaU(),
		"token":                         eaU(),
		"true":                          eaU(),
		"trust_policy_enabled":          eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-258: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_259(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-259")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_log_analytics_workspace", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-259: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-259: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-259: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_log_analytics_workspace", "probe", map[string]ir.Value{
			"Arm":                           eaS("public"),
			"Deny":                          eaS("public"),
			"Standard":                      eaS("public"),
			"absent":                        eaS("public"),
			"alert_notifications":           eaS("public"),
			"anonymous_pull_enabled":        eaB(true),
			"customer_managed_key_id":       eaS("password123"),
			"default_action":                eaL(eaS("*")),
			"empty":                         eaS("public"),
			"enabled":                       eaB(false),
			"encoded_values":                eaS("public"),
			"encryption":                    eaB(false),
			"export_policy_enabled":         eaS("3389"),
			"internet_ingestion_enabled":    eaB(false),
			"internet_query_enabled":        eaB(false),
			"key":                           eaS("password123"),
			"network_rule_set":              eaS("public"),
			"password":                      eaS("password123"),
			"public_network_access_enabled": eaS("Allow"),
			"resource_type":                 eaS("String"),
			"retention_in_days":             eaN(1.0),
			"retention_policy":              eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"secret":                        eaS("password123"),
			"tier":                          eaS("public"),
			"token":                         eaS("password123"),
			"trust_policy_enabled":          eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-259: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_log_analytics_workspace", "probe", map[string]ir.Value{
		"Arm":                           eaU(),
		"Deny":                          eaU(),
		"Standard":                      eaU(),
		"absent":                        eaU(),
		"alert_notifications":           eaU(),
		"anonymous_pull_enabled":        eaU(),
		"customer_managed_key_id":       eaU(),
		"default_action":                eaU(),
		"empty":                         eaU(),
		"enabled":                       eaU(),
		"encoded_values":                eaU(),
		"encryption":                    eaU(),
		"export_policy_enabled":         eaU(),
		"internet_ingestion_enabled":    eaU(),
		"internet_query_enabled":        eaU(),
		"key":                           eaU(),
		"network_rule_set":              eaU(),
		"password":                      eaU(),
		"public_network_access_enabled": eaU(),
		"resource_type":                 eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"secret":                        eaU(),
		"tier":                          eaU(),
		"token":                         eaU(),
		"true":                          eaU(),
		"trust_policy_enabled":          eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-259: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_261(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-261")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_container_registry", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-261: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-261: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-261: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_container_registry", "probe", map[string]ir.Value{
			"Arm":                           eaS("public"),
			"Deny":                          eaS("public"),
			"Standard":                      eaS("public"),
			"absent":                        eaS("public"),
			"alert_notifications":           eaS("public"),
			"anonymous_pull_enabled":        eaB(true),
			"customer_managed_key_id":       eaS("password123"),
			"default_action":                eaL(eaS("*")),
			"empty":                         eaS("public"),
			"enabled":                       eaB(false),
			"encoded_values":                eaS("public"),
			"encryption":                    eaB(false),
			"export_policy_enabled":         eaS("3389"),
			"internet_ingestion_enabled":    eaB(false),
			"internet_query_enabled":        eaB(false),
			"key":                           eaS("password123"),
			"network_rule_set":              eaS("public"),
			"password":                      eaS("password123"),
			"public_network_access_enabled": eaS("Allow"),
			"resource_type":                 eaS("String"),
			"retention_in_days":             eaN(1.0),
			"retention_policy":              eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"secret":                        eaS("password123"),
			"tier":                          eaS("public"),
			"token":                         eaS("password123"),
			"trust_policy_enabled":          eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-261: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_container_registry", "probe", map[string]ir.Value{
		"Arm":                           eaU(),
		"Deny":                          eaU(),
		"Standard":                      eaU(),
		"absent":                        eaU(),
		"alert_notifications":           eaU(),
		"anonymous_pull_enabled":        eaU(),
		"customer_managed_key_id":       eaU(),
		"default_action":                eaU(),
		"empty":                         eaU(),
		"enabled":                       eaU(),
		"encoded_values":                eaU(),
		"encryption":                    eaU(),
		"export_policy_enabled":         eaU(),
		"internet_ingestion_enabled":    eaU(),
		"internet_query_enabled":        eaU(),
		"key":                           eaU(),
		"network_rule_set":              eaU(),
		"password":                      eaU(),
		"public_network_access_enabled": eaU(),
		"resource_type":                 eaU(),
		"retention_in_days":             eaU(),
		"retention_policy":              eaU(),
		"secret":                        eaU(),
		"tier":                          eaU(),
		"token":                         eaU(),
		"true":                          eaU(),
		"trust_policy_enabled":          eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-261: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_262(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-262")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-262: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-262: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-262: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{
			"Continuous":                         eaS("public"),
			"Deny":                               eaS("public"),
			"Tls12":                              eaS("public"),
			"absent":                             eaS("public"),
			"access_key_metadata_writes_enabled": eaB(false),
			"analytical_storage_enabled":         eaB(false),
			"backup":                             eaB(false),
			"capture_description":                eaS("public"),
			"default_action":                     eaL(eaS("*")),
			"empty":                              eaS("public"),
			"enabled":                            eaB(false),
			"http":                               eaB(true),
			"local_auth_enabled":                 eaB(false),
			"local_authentication_disabled":      eaB(true),
			"manage":                             eaS("public"),
			"minimal_tls_version":                eaS("TLS1.0"),
			"minimum_tls_version":                eaS("TLS1.0"),
			"network_rule_set":                   eaS("public"),
			"network_rulesets":                   eaS("public"),
			"protocols":                          eaS("Tcp"),
			"public_network_access_enabled":      eaS("Allow"),
			"requires_duplicate_detection":       eaB(false),
			"subscription_required":              eaB(false),
			"type":                               eaS("String"),
			"versioning_scheme":                  eaB(false),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-262: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{
		"Continuous":                         eaU(),
		"Deny":                               eaU(),
		"Tls12":                              eaU(),
		"absent":                             eaU(),
		"access_key_metadata_writes_enabled": eaU(),
		"analytical_storage_enabled":         eaU(),
		"backup":                             eaU(),
		"capture_description":                eaU(),
		"default_action":                     eaU(),
		"empty":                              eaU(),
		"enabled":                            eaU(),
		"false":                              eaU(),
		"http":                               eaU(),
		"local_auth_enabled":                 eaU(),
		"local_authentication_disabled":      eaU(),
		"manage":                             eaU(),
		"minimal_tls_version":                eaU(),
		"minimum_tls_version":                eaU(),
		"network_rule_set":                   eaU(),
		"network_rulesets":                   eaU(),
		"protocols":                          eaU(),
		"public_network_access_enabled":      eaU(),
		"requires_duplicate_detection":       eaU(),
		"subscription_required":              eaU(),
		"true":                               eaU(),
		"type":                               eaU(),
		"versioning_scheme":                  eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-262: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_263(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-263")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-263: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-263: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-263: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{
			"Continuous":                         eaS("public"),
			"Deny":                               eaS("public"),
			"Tls12":                              eaS("public"),
			"absent":                             eaS("public"),
			"access_key_metadata_writes_enabled": eaB(false),
			"analytical_storage_enabled":         eaB(false),
			"azurerm_cosmosdb_account":           eaN(0.0),
			"backup":                             eaB(false),
			"capture_description":                eaS("public"),
			"default_action":                     eaL(eaS("*")),
			"empty":                              eaS("public"),
			"enabled":                            eaB(false),
			"http":                               eaB(true),
			"local_auth_enabled":                 eaB(false),
			"local_authentication_disabled":      eaB(true),
			"manage":                             eaS("public"),
			"minimal_tls_version":                eaS("TLS1.0"),
			"minimum_tls_version":                eaS("TLS1.0"),
			"network_rule_set":                   eaS("public"),
			"network_rulesets":                   eaS("public"),
			"protocols":                          eaS("Tcp"),
			"public_network_access_enabled":      eaS("Allow"),
			"requires_duplicate_detection":       eaB(false),
			"subscription_required":              eaB(false),
			"type":                               eaS("String"),
			"versioning_scheme":                  eaB(false),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-263: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{
		"Continuous":                         eaU(),
		"Deny":                               eaU(),
		"Tls12":                              eaU(),
		"absent":                             eaU(),
		"access_key_metadata_writes_enabled": eaU(),
		"analytical_storage_enabled":         eaU(),
		"azurerm_cosmosdb_account":           eaU(),
		"backup":                             eaU(),
		"capture_description":                eaU(),
		"default_action":                     eaU(),
		"empty":                              eaU(),
		"enabled":                            eaU(),
		"false":                              eaU(),
		"http":                               eaU(),
		"local_auth_enabled":                 eaU(),
		"local_authentication_disabled":      eaU(),
		"manage":                             eaU(),
		"minimal_tls_version":                eaU(),
		"minimum_tls_version":                eaU(),
		"network_rule_set":                   eaU(),
		"network_rulesets":                   eaU(),
		"protocols":                          eaU(),
		"public_network_access_enabled":      eaU(),
		"requires_duplicate_detection":       eaU(),
		"subscription_required":              eaU(),
		"true":                               eaU(),
		"type":                               eaU(),
		"versioning_scheme":                  eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-263: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_264(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-264")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{
			"Continuous":                         eaS("public"),
			"Deny":                               eaS("public"),
			"Tls12":                              eaS("public"),
			"absent":                             eaS("public"),
			"access_key_metadata_writes_enabled": eaB(false),
			"analytical_storage_enabled":         eaB(false),
			"backup":                             eaB(false),
			"capture_description":                eaS("public"),
			"default_action":                     eaL(eaS("*")),
			"empty":                              eaS("public"),
			"enabled":                            eaB(false),
			"http":                               eaB(true),
			"local_auth_enabled":                 eaB(false),
			"local_authentication_disabled":      eaB(true),
			"manage":                             eaS("public"),
			"minimal_tls_version":                eaS("TLS1.0"),
			"minimum_tls_version":                eaS("TLS1.0"),
			"network_rule_set":                   eaS("public"),
			"network_rulesets":                   eaS("public"),
			"protocols":                          eaS("Tcp"),
			"public_network_access_enabled":      eaS("Allow"),
			"requires_duplicate_detection":       eaB(false),
			"subscription_required":              eaB(false),
			"type":                               eaS("String"),
			"versioning_scheme":                  eaB(false),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-264: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-264: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-264: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-264: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{
		"Continuous":                         eaU(),
		"Deny":                               eaU(),
		"Tls12":                              eaU(),
		"absent":                             eaU(),
		"access_key_metadata_writes_enabled": eaU(),
		"analytical_storage_enabled":         eaU(),
		"backup":                             eaU(),
		"capture_description":                eaU(),
		"default_action":                     eaU(),
		"empty":                              eaU(),
		"enabled":                            eaU(),
		"false":                              eaU(),
		"http":                               eaU(),
		"local_auth_enabled":                 eaU(),
		"local_authentication_disabled":      eaU(),
		"manage":                             eaU(),
		"minimal_tls_version":                eaU(),
		"minimum_tls_version":                eaU(),
		"network_rule_set":                   eaU(),
		"network_rulesets":                   eaU(),
		"protocols":                          eaU(),
		"public_network_access_enabled":      eaU(),
		"requires_duplicate_detection":       eaU(),
		"subscription_required":              eaU(),
		"true":                               eaU(),
		"type":                               eaU(),
		"versioning_scheme":                  eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-264: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_265(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-265")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-265: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-265: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-265: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{
			"Continuous":                         eaS("public"),
			"Deny":                               eaS("public"),
			"Tls12":                              eaS("public"),
			"absent":                             eaS("public"),
			"access_key_metadata_writes_enabled": eaB(false),
			"analytical_storage_enabled":         eaB(false),
			"backup":                             eaB(false),
			"capture_description":                eaS("public"),
			"default_action":                     eaL(eaS("*")),
			"empty":                              eaS("public"),
			"enabled":                            eaB(false),
			"http":                               eaB(true),
			"identity":                           eaS("public"),
			"local_auth_enabled":                 eaB(false),
			"local_authentication_disabled":      eaB(true),
			"manage":                             eaS("public"),
			"minimal_tls_version":                eaS("TLS1.0"),
			"minimum_tls_version":                eaS("TLS1.0"),
			"network_rule_set":                   eaS("public"),
			"network_rulesets":                   eaS("public"),
			"protocols":                          eaS("Tcp"),
			"public_network_access_enabled":      eaS("Allow"),
			"requires_duplicate_detection":       eaB(false),
			"subscription_required":              eaB(false),
			"type":                               eaS("String"),
			"versioning_scheme":                  eaB(false),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-265: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{
		"Continuous":                         eaU(),
		"Deny":                               eaU(),
		"Tls12":                              eaU(),
		"absent":                             eaU(),
		"access_key_metadata_writes_enabled": eaU(),
		"analytical_storage_enabled":         eaU(),
		"backup":                             eaU(),
		"capture_description":                eaU(),
		"default_action":                     eaU(),
		"empty":                              eaU(),
		"enabled":                            eaU(),
		"false":                              eaU(),
		"http":                               eaU(),
		"identity":                           eaU(),
		"local_auth_enabled":                 eaU(),
		"local_authentication_disabled":      eaU(),
		"manage":                             eaU(),
		"minimal_tls_version":                eaU(),
		"minimum_tls_version":                eaU(),
		"network_rule_set":                   eaU(),
		"network_rulesets":                   eaU(),
		"protocols":                          eaU(),
		"public_network_access_enabled":      eaU(),
		"requires_duplicate_detection":       eaU(),
		"subscription_required":              eaU(),
		"true":                               eaU(),
		"type":                               eaU(),
		"versioning_scheme":                  eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-265: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_266(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-266")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_eventhub_namespace", "probe", map[string]ir.Value{
			"Continuous":                         eaS("public"),
			"Deny":                               eaS("public"),
			"Tls12":                              eaS("public"),
			"absent":                             eaS("public"),
			"access_key_metadata_writes_enabled": eaB(false),
			"analytical_storage_enabled":         eaB(false),
			"backup":                             eaB(false),
			"capture_description":                eaS("public"),
			"default_action":                     eaL(eaS("*")),
			"empty":                              eaS("public"),
			"enabled":                            eaB(false),
			"http":                               eaB(true),
			"local_auth_enabled":                 eaB(false),
			"local_authentication_disabled":      eaB(true),
			"manage":                             eaS("public"),
			"minimal_tls_version":                eaS("TLS1.0"),
			"minimum_tls_version":                eaS("TLS1.0"),
			"network_rule_set":                   eaS("public"),
			"network_rulesets":                   eaS("public"),
			"protocols":                          eaS("Tcp"),
			"public_network_access_enabled":      eaS("Allow"),
			"requires_duplicate_detection":       eaB(false),
			"subscription_required":              eaB(false),
			"type":                               eaS("String"),
			"versioning_scheme":                  eaB(false),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-266: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-266: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-266: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_eventhub_namespace", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-266: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_eventhub_namespace", "probe", map[string]ir.Value{
		"Continuous":                         eaU(),
		"Deny":                               eaU(),
		"Tls12":                              eaU(),
		"absent":                             eaU(),
		"access_key_metadata_writes_enabled": eaU(),
		"analytical_storage_enabled":         eaU(),
		"backup":                             eaU(),
		"capture_description":                eaU(),
		"default_action":                     eaU(),
		"empty":                              eaU(),
		"enabled":                            eaU(),
		"false":                              eaU(),
		"http":                               eaU(),
		"local_auth_enabled":                 eaU(),
		"local_authentication_disabled":      eaU(),
		"manage":                             eaU(),
		"minimal_tls_version":                eaU(),
		"minimum_tls_version":                eaU(),
		"network_rule_set":                   eaU(),
		"network_rulesets":                   eaU(),
		"protocols":                          eaU(),
		"public_network_access_enabled":      eaU(),
		"requires_duplicate_detection":       eaU(),
		"subscription_required":              eaU(),
		"true":                               eaU(),
		"type":                               eaU(),
		"versioning_scheme":                  eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-266: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_267(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-267")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_eventhub_namespace", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-267: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-267: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-267: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_eventhub_namespace", "probe", map[string]ir.Value{
			"Continuous":                         eaS("public"),
			"Deny":                               eaS("public"),
			"Tls12":                              eaS("public"),
			"absent":                             eaS("public"),
			"access_key_metadata_writes_enabled": eaB(false),
			"analytical_storage_enabled":         eaB(false),
			"azurerm_eventhub_namespace":         eaS("my_password"),
			"backup":                             eaB(false),
			"capture_description":                eaS("public"),
			"default_action":                     eaL(eaS("*")),
			"empty":                              eaS("public"),
			"enabled":                            eaB(false),
			"http":                               eaB(true),
			"local_auth_enabled":                 eaB(false),
			"local_authentication_disabled":      eaB(true),
			"manage":                             eaS("public"),
			"minimal_tls_version":                eaS("TLS1.0"),
			"minimum_tls_version":                eaS("TLS1.0"),
			"network_rule_set":                   eaS("public"),
			"network_rulesets":                   eaS("public"),
			"protocols":                          eaS("Tcp"),
			"public_network_access_enabled":      eaS("Allow"),
			"requires_duplicate_detection":       eaB(false),
			"subscription_required":              eaB(false),
			"type":                               eaS("String"),
			"versioning_scheme":                  eaB(false),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-267: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_eventhub_namespace", "probe", map[string]ir.Value{
		"Continuous":                         eaU(),
		"Deny":                               eaU(),
		"Tls12":                              eaU(),
		"absent":                             eaU(),
		"access_key_metadata_writes_enabled": eaU(),
		"analytical_storage_enabled":         eaU(),
		"azurerm_eventhub_namespace":         eaU(),
		"backup":                             eaU(),
		"capture_description":                eaU(),
		"default_action":                     eaU(),
		"empty":                              eaU(),
		"enabled":                            eaU(),
		"false":                              eaU(),
		"http":                               eaU(),
		"local_auth_enabled":                 eaU(),
		"local_authentication_disabled":      eaU(),
		"manage":                             eaU(),
		"minimal_tls_version":                eaU(),
		"minimum_tls_version":                eaU(),
		"network_rule_set":                   eaU(),
		"network_rulesets":                   eaU(),
		"protocols":                          eaU(),
		"public_network_access_enabled":      eaU(),
		"requires_duplicate_detection":       eaU(),
		"subscription_required":              eaU(),
		"true":                               eaU(),
		"type":                               eaU(),
		"versioning_scheme":                  eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-267: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_268(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-268")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_eventhub_namespace", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-268: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-268: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-268: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_eventhub_namespace", "probe", map[string]ir.Value{
			"Continuous":                         eaS("public"),
			"Deny":                               eaS("public"),
			"Tls12":                              eaS("public"),
			"absent":                             eaS("public"),
			"access_key_metadata_writes_enabled": eaB(false),
			"analytical_storage_enabled":         eaB(false),
			"backup":                             eaB(false),
			"capture_description":                eaS("public"),
			"default_action":                     eaL(eaS("*")),
			"empty":                              eaS("public"),
			"enabled":                            eaB(false),
			"http":                               eaB(true),
			"local_auth_enabled":                 eaB(false),
			"local_authentication_disabled":      eaB(true),
			"manage":                             eaS("public"),
			"minimal_tls_version":                eaS("TLS1.0"),
			"minimum_tls_version":                eaS("TLS1.0"),
			"network_rule_set":                   eaS("public"),
			"network_rulesets":                   eaS("public"),
			"protocols":                          eaS("Tcp"),
			"public_network_access_enabled":      eaS("Allow"),
			"requires_duplicate_detection":       eaB(false),
			"subscription_required":              eaB(false),
			"type":                               eaS("String"),
			"versioning_scheme":                  eaB(false),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-268: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_eventhub_namespace", "probe", map[string]ir.Value{
		"Continuous":                         eaU(),
		"Deny":                               eaU(),
		"Tls12":                              eaU(),
		"absent":                             eaU(),
		"access_key_metadata_writes_enabled": eaU(),
		"analytical_storage_enabled":         eaU(),
		"backup":                             eaU(),
		"capture_description":                eaU(),
		"default_action":                     eaU(),
		"empty":                              eaU(),
		"enabled":                            eaU(),
		"false":                              eaU(),
		"http":                               eaU(),
		"local_auth_enabled":                 eaU(),
		"local_authentication_disabled":      eaU(),
		"manage":                             eaU(),
		"minimal_tls_version":                eaU(),
		"minimum_tls_version":                eaU(),
		"network_rule_set":                   eaU(),
		"network_rulesets":                   eaU(),
		"protocols":                          eaU(),
		"public_network_access_enabled":      eaU(),
		"requires_duplicate_detection":       eaU(),
		"subscription_required":              eaU(),
		"true":                               eaU(),
		"type":                               eaU(),
		"versioning_scheme":                  eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-268: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_269(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-269")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_eventhub_authorization_rule", "probe", map[string]ir.Value{
			"Continuous":                         eaB(true),
			"Deny":                               eaB(true),
			"Tls12":                              eaB(true),
			"absent":                             eaB(true),
			"access_key_metadata_writes_enabled": eaB(true),
			"analytical_storage_enabled":         eaB(true),
			"backup":                             eaB(true),
			"capture_description":                eaB(true),
			"default_action":                     eaB(true),
			"empty":                              eaB(true),
			"enabled":                            eaB(true),
			"http":                               eaB(true),
			"local_auth_enabled":                 eaB(true),
			"local_authentication_disabled":      eaB(true),
			"manage":                             eaB(true),
			"minimal_tls_version":                eaB(true),
			"minimum_tls_version":                eaB(true),
			"network_rule_set":                   eaB(true),
			"network_rulesets":                   eaB(true),
			"protocols":                          eaB(true),
			"public_network_access_enabled":      eaB(true),
			"requires_duplicate_detection":       eaB(true),
			"subscription_required":              eaB(true),
			"type":                               eaB(true),
			"versioning_scheme":                  eaB(true),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-269: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-269: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-269: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_eventhub_authorization_rule", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-269: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_eventhub_authorization_rule", "probe", map[string]ir.Value{
		"Continuous":                         eaU(),
		"Deny":                               eaU(),
		"Tls12":                              eaU(),
		"absent":                             eaU(),
		"access_key_metadata_writes_enabled": eaU(),
		"analytical_storage_enabled":         eaU(),
		"backup":                             eaU(),
		"capture_description":                eaU(),
		"default_action":                     eaU(),
		"empty":                              eaU(),
		"enabled":                            eaU(),
		"false":                              eaU(),
		"http":                               eaU(),
		"local_auth_enabled":                 eaU(),
		"local_authentication_disabled":      eaU(),
		"manage":                             eaU(),
		"minimal_tls_version":                eaU(),
		"minimum_tls_version":                eaU(),
		"network_rule_set":                   eaU(),
		"network_rulesets":                   eaU(),
		"protocols":                          eaU(),
		"public_network_access_enabled":      eaU(),
		"requires_duplicate_detection":       eaU(),
		"subscription_required":              eaU(),
		"true":                               eaU(),
		"type":                               eaU(),
		"versioning_scheme":                  eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-269: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_270(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-270")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_servicebus_namespace", "probe", map[string]ir.Value{
			"Continuous":                         eaS("public"),
			"Deny":                               eaS("public"),
			"Tls12":                              eaS("public"),
			"absent":                             eaS("public"),
			"access_key_metadata_writes_enabled": eaB(false),
			"analytical_storage_enabled":         eaB(false),
			"backup":                             eaB(false),
			"capture_description":                eaS("public"),
			"default_action":                     eaL(eaS("*")),
			"empty":                              eaS("public"),
			"enabled":                            eaB(false),
			"http":                               eaB(true),
			"local_auth_enabled":                 eaB(false),
			"local_authentication_disabled":      eaB(true),
			"manage":                             eaS("public"),
			"minimal_tls_version":                eaS("TLS1.0"),
			"minimum_tls_version":                eaS("TLS1.0"),
			"network_rule_set":                   eaS("public"),
			"network_rulesets":                   eaS("public"),
			"protocols":                          eaS("Tcp"),
			"public_network_access_enabled":      eaS("Allow"),
			"requires_duplicate_detection":       eaB(false),
			"subscription_required":              eaB(false),
			"type":                               eaS("String"),
			"versioning_scheme":                  eaB(false),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-270: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-270: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-270: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_servicebus_namespace", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-270: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_servicebus_namespace", "probe", map[string]ir.Value{
		"Continuous":                         eaU(),
		"Deny":                               eaU(),
		"Tls12":                              eaU(),
		"absent":                             eaU(),
		"access_key_metadata_writes_enabled": eaU(),
		"analytical_storage_enabled":         eaU(),
		"backup":                             eaU(),
		"capture_description":                eaU(),
		"default_action":                     eaU(),
		"empty":                              eaU(),
		"enabled":                            eaU(),
		"false":                              eaU(),
		"http":                               eaU(),
		"local_auth_enabled":                 eaU(),
		"local_authentication_disabled":      eaU(),
		"manage":                             eaU(),
		"minimal_tls_version":                eaU(),
		"minimum_tls_version":                eaU(),
		"network_rule_set":                   eaU(),
		"network_rulesets":                   eaU(),
		"protocols":                          eaU(),
		"public_network_access_enabled":      eaU(),
		"requires_duplicate_detection":       eaU(),
		"subscription_required":              eaU(),
		"true":                               eaU(),
		"type":                               eaU(),
		"versioning_scheme":                  eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-270: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_271(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-271")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_servicebus_namespace", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-271: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-271: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-271: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_servicebus_namespace", "probe", map[string]ir.Value{
			"Continuous":                         eaS("public"),
			"Deny":                               eaS("public"),
			"Tls12":                              eaS("public"),
			"absent":                             eaS("public"),
			"access_key_metadata_writes_enabled": eaB(false),
			"analytical_storage_enabled":         eaB(false),
			"azurerm_servicebus_namespace":       eaS("my_password"),
			"backup":                             eaB(false),
			"capture_description":                eaS("public"),
			"default_action":                     eaL(eaS("*")),
			"empty":                              eaS("public"),
			"enabled":                            eaB(false),
			"http":                               eaB(true),
			"local_auth_enabled":                 eaB(false),
			"local_authentication_disabled":      eaB(true),
			"manage":                             eaS("public"),
			"minimal_tls_version":                eaS("TLS1.0"),
			"minimum_tls_version":                eaS("TLS1.0"),
			"network_rule_set":                   eaS("public"),
			"network_rulesets":                   eaS("public"),
			"protocols":                          eaS("Tcp"),
			"public_network_access_enabled":      eaS("Allow"),
			"requires_duplicate_detection":       eaB(false),
			"subscription_required":              eaB(false),
			"type":                               eaS("String"),
			"versioning_scheme":                  eaB(false),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-271: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_servicebus_namespace", "probe", map[string]ir.Value{
		"Continuous":                         eaU(),
		"Deny":                               eaU(),
		"Tls12":                              eaU(),
		"absent":                             eaU(),
		"access_key_metadata_writes_enabled": eaU(),
		"analytical_storage_enabled":         eaU(),
		"azurerm_servicebus_namespace":       eaU(),
		"backup":                             eaU(),
		"capture_description":                eaU(),
		"default_action":                     eaU(),
		"empty":                              eaU(),
		"enabled":                            eaU(),
		"false":                              eaU(),
		"http":                               eaU(),
		"local_auth_enabled":                 eaU(),
		"local_authentication_disabled":      eaU(),
		"manage":                             eaU(),
		"minimal_tls_version":                eaU(),
		"minimum_tls_version":                eaU(),
		"network_rule_set":                   eaU(),
		"network_rulesets":                   eaU(),
		"protocols":                          eaU(),
		"public_network_access_enabled":      eaU(),
		"requires_duplicate_detection":       eaU(),
		"subscription_required":              eaU(),
		"true":                               eaU(),
		"type":                               eaU(),
		"versioning_scheme":                  eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-271: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_272(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-272")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_servicebus_namespace", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-272: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-272: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-272: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_servicebus_namespace", "probe", map[string]ir.Value{
			"Continuous":                         eaS("public"),
			"Deny":                               eaS("public"),
			"Tls12":                              eaS("public"),
			"absent":                             eaS("public"),
			"access_key_metadata_writes_enabled": eaB(false),
			"analytical_storage_enabled":         eaB(false),
			"backup":                             eaB(false),
			"capture_description":                eaS("public"),
			"default_action":                     eaL(eaS("*")),
			"empty":                              eaS("public"),
			"enabled":                            eaB(false),
			"http":                               eaB(true),
			"local_auth_enabled":                 eaB(false),
			"local_authentication_disabled":      eaB(true),
			"manage":                             eaS("public"),
			"minimal_tls_version":                eaS("TLS1.0"),
			"minimum_tls_version":                eaS("TLS1.0"),
			"network_rule_set":                   eaS("public"),
			"network_rulesets":                   eaS("public"),
			"protocols":                          eaS("Tcp"),
			"public_network_access_enabled":      eaS("Allow"),
			"requires_duplicate_detection":       eaB(false),
			"subscription_required":              eaB(false),
			"type":                               eaS("String"),
			"versioning_scheme":                  eaB(false),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-272: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_servicebus_namespace", "probe", map[string]ir.Value{
		"Continuous":                         eaU(),
		"Deny":                               eaU(),
		"Tls12":                              eaU(),
		"absent":                             eaU(),
		"access_key_metadata_writes_enabled": eaU(),
		"analytical_storage_enabled":         eaU(),
		"backup":                             eaU(),
		"capture_description":                eaU(),
		"default_action":                     eaU(),
		"empty":                              eaU(),
		"enabled":                            eaU(),
		"false":                              eaU(),
		"http":                               eaU(),
		"local_auth_enabled":                 eaU(),
		"local_authentication_disabled":      eaU(),
		"manage":                             eaU(),
		"minimal_tls_version":                eaU(),
		"minimum_tls_version":                eaU(),
		"network_rule_set":                   eaU(),
		"network_rulesets":                   eaU(),
		"protocols":                          eaU(),
		"public_network_access_enabled":      eaU(),
		"requires_duplicate_detection":       eaU(),
		"subscription_required":              eaU(),
		"true":                               eaU(),
		"type":                               eaU(),
		"versioning_scheme":                  eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-272: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_273(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-273")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_servicebus_namespace", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-273: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-273: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-273: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_servicebus_namespace", "probe", map[string]ir.Value{
			"Continuous":                         eaS("public"),
			"Deny":                               eaS("public"),
			"Tls12":                              eaS("public"),
			"absent":                             eaS("public"),
			"access_key_metadata_writes_enabled": eaB(false),
			"analytical_storage_enabled":         eaB(false),
			"backup":                             eaB(false),
			"capture_description":                eaS("public"),
			"default_action":                     eaL(eaS("*")),
			"empty":                              eaS("public"),
			"enabled":                            eaB(false),
			"http":                               eaB(true),
			"local_auth_enabled":                 eaB(false),
			"local_authentication_disabled":      eaB(true),
			"manage":                             eaS("public"),
			"minimal_tls_version":                eaS("TLS1.0"),
			"minimum_tls_version":                eaS("TLS1.0"),
			"network_rule_set":                   eaS("public"),
			"network_rulesets":                   eaS("public"),
			"protocols":                          eaS("Tcp"),
			"public_network_access_enabled":      eaS("Allow"),
			"requires_duplicate_detection":       eaB(false),
			"subscription_required":              eaB(false),
			"type":                               eaS("String"),
			"versioning_scheme":                  eaB(false),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-273: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_servicebus_namespace", "probe", map[string]ir.Value{
		"Continuous":                         eaU(),
		"Deny":                               eaU(),
		"Tls12":                              eaU(),
		"absent":                             eaU(),
		"access_key_metadata_writes_enabled": eaU(),
		"analytical_storage_enabled":         eaU(),
		"backup":                             eaU(),
		"capture_description":                eaU(),
		"default_action":                     eaU(),
		"empty":                              eaU(),
		"enabled":                            eaU(),
		"false":                              eaU(),
		"http":                               eaU(),
		"local_auth_enabled":                 eaU(),
		"local_authentication_disabled":      eaU(),
		"manage":                             eaU(),
		"minimal_tls_version":                eaU(),
		"minimum_tls_version":                eaU(),
		"network_rule_set":                   eaU(),
		"network_rulesets":                   eaU(),
		"protocols":                          eaU(),
		"public_network_access_enabled":      eaU(),
		"requires_duplicate_detection":       eaU(),
		"subscription_required":              eaU(),
		"true":                               eaU(),
		"type":                               eaU(),
		"versioning_scheme":                  eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-273: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_274(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-274")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_api_management_api", "probe", map[string]ir.Value{
			"Continuous":                         eaS("public"),
			"Deny":                               eaS("public"),
			"Tls12":                              eaS("public"),
			"absent":                             eaS("public"),
			"access_key_metadata_writes_enabled": eaB(false),
			"analytical_storage_enabled":         eaB(false),
			"backup":                             eaB(false),
			"capture_description":                eaS("public"),
			"default_action":                     eaL(eaS("*")),
			"empty":                              eaS("public"),
			"enabled":                            eaB(false),
			"http":                               eaB(true),
			"local_auth_enabled":                 eaB(false),
			"local_authentication_disabled":      eaB(true),
			"manage":                             eaS("public"),
			"minimal_tls_version":                eaS("TLS1.0"),
			"minimum_tls_version":                eaS("TLS1.0"),
			"network_rule_set":                   eaS("public"),
			"network_rulesets":                   eaS("public"),
			"protocols":                          eaS("Tcp"),
			"public_network_access_enabled":      eaS("Allow"),
			"requires_duplicate_detection":       eaB(false),
			"subscription_required":              eaB(false),
			"type":                               eaS("String"),
			"versioning_scheme":                  eaB(false),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-274: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-274: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-274: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_api_management_api", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-274: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_api_management_api", "probe", map[string]ir.Value{
		"Continuous":                         eaU(),
		"Deny":                               eaU(),
		"Tls12":                              eaU(),
		"absent":                             eaU(),
		"access_key_metadata_writes_enabled": eaU(),
		"analytical_storage_enabled":         eaU(),
		"backup":                             eaU(),
		"capture_description":                eaU(),
		"default_action":                     eaU(),
		"empty":                              eaU(),
		"enabled":                            eaU(),
		"false":                              eaU(),
		"http":                               eaU(),
		"local_auth_enabled":                 eaU(),
		"local_authentication_disabled":      eaU(),
		"manage":                             eaU(),
		"minimal_tls_version":                eaU(),
		"minimum_tls_version":                eaU(),
		"network_rule_set":                   eaU(),
		"network_rulesets":                   eaU(),
		"protocols":                          eaU(),
		"public_network_access_enabled":      eaU(),
		"requires_duplicate_detection":       eaU(),
		"subscription_required":              eaU(),
		"true":                               eaU(),
		"type":                               eaU(),
		"versioning_scheme":                  eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-274: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_275(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-275")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_api_management_api", "probe", map[string]ir.Value{
			"protocols": eaL(eaS("HTTP"), eaS("HTTP")),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-275: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-275: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-275: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_api_management_api", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-275: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_api_management_api", "probe", map[string]ir.Value{
		"Continuous":                         eaU(),
		"Deny":                               eaU(),
		"Tls12":                              eaU(),
		"absent":                             eaU(),
		"access_key_metadata_writes_enabled": eaU(),
		"analytical_storage_enabled":         eaU(),
		"backup":                             eaU(),
		"capture_description":                eaU(),
		"default_action":                     eaU(),
		"empty":                              eaU(),
		"enabled":                            eaU(),
		"false":                              eaU(),
		"http":                               eaU(),
		"local_auth_enabled":                 eaU(),
		"local_authentication_disabled":      eaU(),
		"manage":                             eaU(),
		"minimal_tls_version":                eaU(),
		"minimum_tls_version":                eaU(),
		"network_rule_set":                   eaU(),
		"network_rulesets":                   eaU(),
		"protocols":                          eaU(),
		"public_network_access_enabled":      eaU(),
		"requires_duplicate_detection":       eaU(),
		"subscription_required":              eaU(),
		"true":                               eaU(),
		"type":                               eaU(),
		"versioning_scheme":                  eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-275: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_276(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-276")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-276: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-276: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-276: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{
			"Continuous":                         eaS("public"),
			"Deny":                               eaS("public"),
			"Tls12":                              eaS("public"),
			"absent":                             eaS("public"),
			"access_key_metadata_writes_enabled": eaB(false),
			"analytical_storage_enabled":         eaB(false),
			"backup":                             eaB(false),
			"capture_description":                eaS("public"),
			"default_action":                     eaL(eaS("*")),
			"empty":                              eaS("public"),
			"enabled":                            eaB(false),
			"http":                               eaB(true),
			"local_auth_enabled":                 eaB(false),
			"local_authentication_disabled":      eaB(true),
			"manage":                             eaS("public"),
			"minimal_tls_version":                eaS("TLS1.0"),
			"minimum_tls_version":                eaS("TLS1.0"),
			"network_rule_set":                   eaS("public"),
			"network_rulesets":                   eaS("public"),
			"protocols":                          eaS("Tcp"),
			"public_network_access_enabled":      eaS("Allow"),
			"requires_duplicate_detection":       eaB(false),
			"subscription_required":              eaB(false),
			"type":                               eaS("String"),
			"versioning_scheme":                  eaB(false),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-276: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{
		"Continuous":                         eaU(),
		"Deny":                               eaU(),
		"Tls12":                              eaU(),
		"absent":                             eaU(),
		"access_key_metadata_writes_enabled": eaU(),
		"analytical_storage_enabled":         eaU(),
		"backup":                             eaU(),
		"capture_description":                eaU(),
		"default_action":                     eaU(),
		"empty":                              eaU(),
		"enabled":                            eaU(),
		"false":                              eaU(),
		"http":                               eaU(),
		"local_auth_enabled":                 eaU(),
		"local_authentication_disabled":      eaU(),
		"manage":                             eaU(),
		"minimal_tls_version":                eaU(),
		"minimum_tls_version":                eaU(),
		"network_rule_set":                   eaU(),
		"network_rulesets":                   eaU(),
		"protocols":                          eaU(),
		"public_network_access_enabled":      eaU(),
		"requires_duplicate_detection":       eaU(),
		"subscription_required":              eaU(),
		"true":                               eaU(),
		"type":                               eaU(),
		"versioning_scheme":                  eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-276: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_277(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-277")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_eventhub", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-277: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-277: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-277: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_eventhub", "probe", map[string]ir.Value{
			"Continuous":                         eaS("public"),
			"Deny":                               eaS("public"),
			"Tls12":                              eaS("public"),
			"absent":                             eaS("public"),
			"access_key_metadata_writes_enabled": eaB(false),
			"analytical_storage_enabled":         eaB(false),
			"backup":                             eaB(false),
			"capture_description":                eaS("public"),
			"default_action":                     eaL(eaS("*")),
			"empty":                              eaS("public"),
			"enabled":                            eaB(false),
			"http":                               eaB(true),
			"local_auth_enabled":                 eaB(false),
			"local_authentication_disabled":      eaB(true),
			"manage":                             eaS("public"),
			"minimal_tls_version":                eaS("TLS1.0"),
			"minimum_tls_version":                eaS("TLS1.0"),
			"network_rule_set":                   eaS("public"),
			"network_rulesets":                   eaS("public"),
			"protocols":                          eaS("Tcp"),
			"public_network_access_enabled":      eaS("Allow"),
			"requires_duplicate_detection":       eaB(false),
			"subscription_required":              eaB(false),
			"type":                               eaS("String"),
			"versioning_scheme":                  eaB(false),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-277: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_eventhub", "probe", map[string]ir.Value{
		"Continuous":                         eaU(),
		"Deny":                               eaU(),
		"Tls12":                              eaU(),
		"absent":                             eaU(),
		"access_key_metadata_writes_enabled": eaU(),
		"analytical_storage_enabled":         eaU(),
		"backup":                             eaU(),
		"capture_description":                eaU(),
		"default_action":                     eaU(),
		"empty":                              eaU(),
		"enabled":                            eaU(),
		"false":                              eaU(),
		"http":                               eaU(),
		"local_auth_enabled":                 eaU(),
		"local_authentication_disabled":      eaU(),
		"manage":                             eaU(),
		"minimal_tls_version":                eaU(),
		"minimum_tls_version":                eaU(),
		"network_rule_set":                   eaU(),
		"network_rulesets":                   eaU(),
		"protocols":                          eaU(),
		"public_network_access_enabled":      eaU(),
		"requires_duplicate_detection":       eaU(),
		"subscription_required":              eaU(),
		"true":                               eaU(),
		"type":                               eaU(),
		"versioning_scheme":                  eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-277: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_278(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-278")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_servicebus_queue", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-278: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-278: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-278: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_servicebus_queue", "probe", map[string]ir.Value{
			"Continuous":                         eaS("private"),
			"Deny":                               eaS("private"),
			"Tls12":                              eaS("private"),
			"absent":                             eaS("private"),
			"access_key_metadata_writes_enabled": eaB(true),
			"analytical_storage_enabled":         eaB(true),
			"backup":                             eaB(true),
			"capture_description":                eaS("private"),
			"default_action":                     eaL(eaS("s3:GetObject")),
			"empty":                              eaS("private"),
			"enabled":                            eaB(true),
			"http":                               eaB(false),
			"identity":                           eaS("private"),
			"local_auth_enabled":                 eaB(true),
			"local_authentication_disabled":      eaB(false),
			"manage":                             eaS("private"),
			"minimal_tls_version":                eaS("TLS1.2"),
			"minimum_tls_version":                eaS("TLS1.2"),
			"network_rule_set":                   eaS("private"),
			"network_rulesets":                   eaS("private"),
			"protocols":                          eaS("Tcp"),
			"public_network_access_enabled":      eaS("Deny"),
			"requires_duplicate_detection":       eaB(true),
			"subscription_required":              eaB(true),
			"type":                               eaS("SecureString"),
			"versioning_scheme":                  eaB(true),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-278: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_servicebus_queue", "probe", map[string]ir.Value{
		"Continuous":                         eaU(),
		"Deny":                               eaU(),
		"Tls12":                              eaU(),
		"absent":                             eaU(),
		"access_key_metadata_writes_enabled": eaU(),
		"analytical_storage_enabled":         eaU(),
		"backup":                             eaU(),
		"capture_description":                eaU(),
		"default_action":                     eaU(),
		"empty":                              eaU(),
		"enabled":                            eaU(),
		"false":                              eaU(),
		"http":                               eaU(),
		"identity":                           eaU(),
		"local_auth_enabled":                 eaU(),
		"local_authentication_disabled":      eaU(),
		"manage":                             eaU(),
		"minimal_tls_version":                eaU(),
		"minimum_tls_version":                eaU(),
		"network_rule_set":                   eaU(),
		"network_rulesets":                   eaU(),
		"protocols":                          eaU(),
		"public_network_access_enabled":      eaU(),
		"requires_duplicate_detection":       eaU(),
		"subscription_required":              eaU(),
		"true":                               eaU(),
		"type":                               eaU(),
		"versioning_scheme":                  eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-278: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_279(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-279")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_api_management_api_version_set", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-279: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-279: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-279: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_api_management_api_version_set", "probe", map[string]ir.Value{
			"Continuous":                         eaS("0.0.0.0/0"),
			"Deny":                               eaS("0.0.0.0/0"),
			"Tls12":                              eaS("0.0.0.0/0"),
			"absent":                             eaS("0.0.0.0/0"),
			"access_key_metadata_writes_enabled": eaS("0.0.0.0/0"),
			"analytical_storage_enabled":         eaS("0.0.0.0/0"),
			"backup":                             eaS("0.0.0.0/0"),
			"capture_description":                eaS("0.0.0.0/0"),
			"default_action":                     eaS("0.0.0.0/0"),
			"empty":                              eaS("0.0.0.0/0"),
			"enabled":                            eaS("0.0.0.0/0"),
			"http":                               eaS("0.0.0.0/0"),
			"local_auth_enabled":                 eaS("0.0.0.0/0"),
			"local_authentication_disabled":      eaS("0.0.0.0/0"),
			"manage":                             eaS("0.0.0.0/0"),
			"minimal_tls_version":                eaS("0.0.0.0/0"),
			"minimum_tls_version":                eaS("0.0.0.0/0"),
			"network_rule_set":                   eaS("0.0.0.0/0"),
			"network_rulesets":                   eaS("0.0.0.0/0"),
			"protocols":                          eaS("0.0.0.0/0"),
			"public_network_access_enabled":      eaS("0.0.0.0/0"),
			"requires_duplicate_detection":       eaS("0.0.0.0/0"),
			"subscription_required":              eaS("0.0.0.0/0"),
			"type":                               eaS("0.0.0.0/0"),
			"versioning_scheme":                  eaS("0.0.0.0/0"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-279: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_api_management_api_version_set", "probe", map[string]ir.Value{
		"Continuous":                         eaU(),
		"Deny":                               eaU(),
		"Tls12":                              eaU(),
		"absent":                             eaU(),
		"access_key_metadata_writes_enabled": eaU(),
		"analytical_storage_enabled":         eaU(),
		"backup":                             eaU(),
		"capture_description":                eaU(),
		"default_action":                     eaU(),
		"empty":                              eaU(),
		"enabled":                            eaU(),
		"false":                              eaU(),
		"http":                               eaU(),
		"local_auth_enabled":                 eaU(),
		"local_authentication_disabled":      eaU(),
		"manage":                             eaU(),
		"minimal_tls_version":                eaU(),
		"minimum_tls_version":                eaU(),
		"network_rule_set":                   eaU(),
		"network_rulesets":                   eaU(),
		"protocols":                          eaU(),
		"public_network_access_enabled":      eaU(),
		"requires_duplicate_detection":       eaU(),
		"subscription_required":              eaU(),
		"true":                               eaU(),
		"type":                               eaU(),
		"versioning_scheme":                  eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-279: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_280(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-280")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{
			"Continuous":                         eaS("private"),
			"Deny":                               eaS("private"),
			"Tls12":                              eaS("private"),
			"absent":                             eaS("private"),
			"access_key_metadata_writes_enabled": eaB(true),
			"analytical_storage_enabled":         eaB(true),
			"backup":                             eaB(true),
			"capture_description":                eaS("private"),
			"default_action":                     eaL(eaS("s3:GetObject")),
			"empty":                              eaS("private"),
			"enabled":                            eaB(true),
			"http":                               eaB(false),
			"local_auth_enabled":                 eaB(true),
			"local_authentication_disabled":      eaB(false),
			"manage":                             eaS("private"),
			"minimal_tls_version":                eaS("TLS1.2"),
			"minimum_tls_version":                eaS("TLS1.2"),
			"network_rule_set":                   eaS("private"),
			"network_rulesets":                   eaS("private"),
			"protocols":                          eaS("Tcp"),
			"public_network_access_enabled":      eaS("Deny"),
			"requires_duplicate_detection":       eaB(true),
			"subscription_required":              eaB(true),
			"type":                               eaS("SecureString"),
			"versioning_scheme":                  eaB(true),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-280: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-280: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-280: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-280: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_cosmosdb_account", "probe", map[string]ir.Value{
		"Continuous":                         eaU(),
		"Deny":                               eaU(),
		"Tls12":                              eaU(),
		"absent":                             eaU(),
		"access_key_metadata_writes_enabled": eaU(),
		"analytical_storage_enabled":         eaU(),
		"backup":                             eaU(),
		"capture_description":                eaU(),
		"default_action":                     eaU(),
		"empty":                              eaU(),
		"enabled":                            eaU(),
		"false":                              eaU(),
		"http":                               eaU(),
		"local_auth_enabled":                 eaU(),
		"local_authentication_disabled":      eaU(),
		"manage":                             eaU(),
		"minimal_tls_version":                eaU(),
		"minimum_tls_version":                eaU(),
		"network_rule_set":                   eaU(),
		"network_rulesets":                   eaU(),
		"protocols":                          eaU(),
		"public_network_access_enabled":      eaU(),
		"requires_duplicate_detection":       eaU(),
		"subscription_required":              eaU(),
		"true":                               eaU(),
		"type":                               eaU(),
		"versioning_scheme":                  eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-280: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_281(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-281")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_eventhub_namespace", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-281: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-281: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-281: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_eventhub_namespace", "probe", map[string]ir.Value{
			"Continuous":                         eaS("public"),
			"Deny":                               eaS("public"),
			"Tls12":                              eaS("public"),
			"absent":                             eaS("public"),
			"access_key_metadata_writes_enabled": eaB(false),
			"analytical_storage_enabled":         eaB(false),
			"backup":                             eaB(false),
			"capture_description":                eaS("public"),
			"default_action":                     eaL(eaS("*")),
			"empty":                              eaS("public"),
			"enabled":                            eaB(false),
			"http":                               eaB(true),
			"local_auth_enabled":                 eaB(false),
			"local_authentication_disabled":      eaB(true),
			"manage":                             eaS("public"),
			"minimal_tls_version":                eaS("TLS1.0"),
			"minimum_tls_version":                eaS("TLS1.0"),
			"network_rule_set":                   eaS("public"),
			"network_rulesets":                   eaS("public"),
			"protocols":                          eaS("Tcp"),
			"public_network_access_enabled":      eaS("Allow"),
			"requires_duplicate_detection":       eaB(false),
			"subscription_required":              eaB(false),
			"type":                               eaS("String"),
			"versioning_scheme":                  eaB(false),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-281: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_eventhub_namespace", "probe", map[string]ir.Value{
		"Continuous":                         eaU(),
		"Deny":                               eaU(),
		"Tls12":                              eaU(),
		"absent":                             eaU(),
		"access_key_metadata_writes_enabled": eaU(),
		"analytical_storage_enabled":         eaU(),
		"backup":                             eaU(),
		"capture_description":                eaU(),
		"default_action":                     eaU(),
		"empty":                              eaU(),
		"enabled":                            eaU(),
		"false":                              eaU(),
		"http":                               eaU(),
		"local_auth_enabled":                 eaU(),
		"local_authentication_disabled":      eaU(),
		"manage":                             eaU(),
		"minimal_tls_version":                eaU(),
		"minimum_tls_version":                eaU(),
		"network_rule_set":                   eaU(),
		"network_rulesets":                   eaU(),
		"protocols":                          eaU(),
		"public_network_access_enabled":      eaU(),
		"requires_duplicate_detection":       eaU(),
		"subscription_required":              eaU(),
		"true":                               eaU(),
		"type":                               eaU(),
		"versioning_scheme":                  eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-281: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_282(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-282")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_frontdoor_firewall_policy", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-282: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-282: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-282: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_frontdoor_firewall_policy", "probe", map[string]ir.Value{
			"Disabled":                     eaB(true),
			"Https":                        eaS("public"),
			"Locked":                       eaB(false),
			"TLS12":                        eaS("public"),
			"absent":                       eaS("public"),
			"backend_pool_health_probe":    eaS("s3"),
			"boot_diagnostics":             eaS("public"),
			"cross_region_restore_enabled": eaB(false),
			"custom_rule":                  eaS("public"),
			"customer_managed_key_id":      eaS("password123"),
			"empty":                        eaS("public"),
			"enabled":                      eaB(false),
			"encrypted":                    eaB(false),
			"encryption_at_host_enabled":   eaB(false),
			"identity":                     eaS("public"),
			"immutability":                 eaS("public"),
			"is_https_allowed":             eaS("public"),
			"managed_rule":                 eaS("public"),
			"minimum_tls_version":          eaS("TLS1.0"),
			"protocol":                     eaS("Tcp"),
			"redirect_configuration":       eaS("public"),
			"routing_rule":                 eaS("public"),
			"secure_boot_enabled":          eaB(false),
			"soft_delete_enabled":          eaB(false),
			"storage_os_disk":              eaS("public"),
			"vhd_uri":                      eaS("http://example.com"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-282: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_frontdoor_firewall_policy", "probe", map[string]ir.Value{
		"Disabled":                     eaU(),
		"Https":                        eaU(),
		"Locked":                       eaU(),
		"TLS12":                        eaU(),
		"absent":                       eaU(),
		"backend_pool_health_probe":    eaU(),
		"boot_diagnostics":             eaU(),
		"cross_region_restore_enabled": eaU(),
		"custom_rule":                  eaU(),
		"customer_managed_key_id":      eaU(),
		"empty":                        eaU(),
		"enabled":                      eaU(),
		"encrypted":                    eaU(),
		"encryption_at_host_enabled":   eaU(),
		"false":                        eaU(),
		"identity":                     eaU(),
		"immutability":                 eaU(),
		"is_https_allowed":             eaU(),
		"managed_rule":                 eaU(),
		"minimum_tls_version":          eaU(),
		"protocol":                     eaU(),
		"redirect_configuration":       eaU(),
		"routing_rule":                 eaU(),
		"secure_boot_enabled":          eaU(),
		"soft_delete_enabled":          eaU(),
		"storage_os_disk":              eaU(),
		"vhd_uri":                      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-282: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_283(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-283")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_frontdoor_firewall_policy", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-283: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-283: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-283: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_frontdoor_firewall_policy", "probe", map[string]ir.Value{
			"Disabled":                     eaB(true),
			"Https":                        eaS("public"),
			"Locked":                       eaB(false),
			"TLS12":                        eaS("public"),
			"absent":                       eaS("public"),
			"backend_pool_health_probe":    eaS("s3"),
			"boot_diagnostics":             eaS("public"),
			"cross_region_restore_enabled": eaB(false),
			"custom_rule":                  eaS("public"),
			"customer_managed_key_id":      eaS("password123"),
			"empty":                        eaS("public"),
			"enabled":                      eaB(false),
			"encrypted":                    eaB(false),
			"encryption_at_host_enabled":   eaB(false),
			"identity":                     eaS("public"),
			"immutability":                 eaS("public"),
			"is_https_allowed":             eaS("public"),
			"managed_rule":                 eaS("public"),
			"minimum_tls_version":          eaS("TLS1.0"),
			"protocol":                     eaS("Tcp"),
			"redirect_configuration":       eaS("public"),
			"routing_rule":                 eaS("public"),
			"secure_boot_enabled":          eaB(false),
			"soft_delete_enabled":          eaB(false),
			"storage_os_disk":              eaS("public"),
			"vhd_uri":                      eaS("http://example.com"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-283: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_frontdoor_firewall_policy", "probe", map[string]ir.Value{
		"Disabled":                     eaU(),
		"Https":                        eaU(),
		"Locked":                       eaU(),
		"TLS12":                        eaU(),
		"absent":                       eaU(),
		"backend_pool_health_probe":    eaU(),
		"boot_diagnostics":             eaU(),
		"cross_region_restore_enabled": eaU(),
		"custom_rule":                  eaU(),
		"customer_managed_key_id":      eaU(),
		"empty":                        eaU(),
		"enabled":                      eaU(),
		"encrypted":                    eaU(),
		"encryption_at_host_enabled":   eaU(),
		"false":                        eaU(),
		"identity":                     eaU(),
		"immutability":                 eaU(),
		"is_https_allowed":             eaU(),
		"managed_rule":                 eaU(),
		"minimum_tls_version":          eaU(),
		"protocol":                     eaU(),
		"redirect_configuration":       eaU(),
		"routing_rule":                 eaU(),
		"secure_boot_enabled":          eaU(),
		"soft_delete_enabled":          eaU(),
		"storage_os_disk":              eaU(),
		"vhd_uri":                      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-283: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_284(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-284")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_frontdoor", "probe", map[string]ir.Value{
			"backend_pool_health_probe": eaL(eaM("Disabled", eaB(true), "Https", eaS("public"), "Locked", eaB(false), "TLS12", eaS("public"), "absent", eaS("public"), "backend_pool_health_probe", eaS("s3"), "boot_diagnostics", eaS("public"), "cross_region_restore_enabled", eaB(false), "custom_rule", eaS("public"), "customer_managed_key_id", eaS("password123"), "empty", eaS("public"), "enabled", eaB(false), "encrypted", eaB(false), "encryption_at_host_enabled", eaB(false), "identity", eaS("public"), "immutability", eaS("public"), "is_https_allowed", eaS("public"), "managed_rule", eaS("public"), "minimum_tls_version", eaS("TLS1.0"), "protocol", eaS("Tcp"), "redirect_configuration", eaS("public"), "routing_rule", eaS("public"), "secure_boot_enabled", eaB(false), "soft_delete_enabled", eaB(false), "storage_os_disk", eaS("public"), "vhd_uri", eaS("http://example.com"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-284: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-284: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-284: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_frontdoor", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-284: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_frontdoor", "probe", map[string]ir.Value{
		"Disabled":                     eaU(),
		"Https":                        eaU(),
		"Locked":                       eaU(),
		"TLS12":                        eaU(),
		"absent":                       eaU(),
		"backend_pool_health_probe":    eaU(),
		"boot_diagnostics":             eaU(),
		"cross_region_restore_enabled": eaU(),
		"custom_rule":                  eaU(),
		"customer_managed_key_id":      eaU(),
		"empty":                        eaU(),
		"enabled":                      eaU(),
		"encrypted":                    eaU(),
		"encryption_at_host_enabled":   eaU(),
		"false":                        eaU(),
		"identity":                     eaU(),
		"immutability":                 eaU(),
		"is_https_allowed":             eaU(),
		"managed_rule":                 eaU(),
		"minimum_tls_version":          eaU(),
		"protocol":                     eaU(),
		"redirect_configuration":       eaU(),
		"routing_rule":                 eaU(),
		"secure_boot_enabled":          eaU(),
		"soft_delete_enabled":          eaU(),
		"storage_os_disk":              eaU(),
		"vhd_uri":                      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-284: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_285(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-285")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_frontdoor", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-285: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-285: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-285: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_frontdoor", "probe", map[string]ir.Value{
			"routing_rule": eaL(eaM("redirect_configuration", eaL(eaM("Disabled", eaB(false), "Https", eaB(false), "Locked", eaB(false), "TLS12", eaB(false), "absent", eaB(false), "backend_pool_health_probe", eaB(false), "boot_diagnostics", eaB(false), "cross_region_restore_enabled", eaB(false), "custom_rule", eaB(false), "customer_managed_key_id", eaB(false), "empty", eaB(false), "enabled", eaB(false), "encrypted", eaB(false), "encryption_at_host_enabled", eaB(false), "identity", eaB(false), "immutability", eaB(false), "is_https_allowed", eaB(false), "managed_rule", eaB(false), "minimum_tls_version", eaB(false), "protocol", eaB(false), "redirect_configuration", eaB(false), "routing_rule", eaB(false), "secure_boot_enabled", eaB(false), "soft_delete_enabled", eaB(false), "storage_os_disk", eaB(false), "vhd_uri", eaB(false))))),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-285: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_286(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-286")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_cdn_endpoint", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-286: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-286: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-286: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_cdn_endpoint", "probe", map[string]ir.Value{
			"Disabled":                     eaB(true),
			"Https":                        eaS("public"),
			"Locked":                       eaB(false),
			"TLS12":                        eaS("public"),
			"absent":                       eaS("public"),
			"backend_pool_health_probe":    eaS("s3"),
			"boot_diagnostics":             eaS("public"),
			"cross_region_restore_enabled": eaB(false),
			"custom_rule":                  eaS("public"),
			"customer_managed_key_id":      eaS("password123"),
			"empty":                        eaS("public"),
			"enabled":                      eaB(false),
			"encrypted":                    eaB(false),
			"encryption_at_host_enabled":   eaB(false),
			"identity":                     eaS("public"),
			"immutability":                 eaS("public"),
			"is_https_allowed":             eaS("public"),
			"managed_rule":                 eaS("public"),
			"minimum_tls_version":          eaS("TLS1.0"),
			"protocol":                     eaS("Tcp"),
			"redirect_configuration":       eaS("public"),
			"routing_rule":                 eaS("public"),
			"secure_boot_enabled":          eaB(false),
			"soft_delete_enabled":          eaB(false),
			"storage_os_disk":              eaS("public"),
			"vhd_uri":                      eaS("http://example.com"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-286: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_cdn_endpoint", "probe", map[string]ir.Value{
		"Disabled":                     eaU(),
		"Https":                        eaU(),
		"Locked":                       eaU(),
		"TLS12":                        eaU(),
		"absent":                       eaU(),
		"backend_pool_health_probe":    eaU(),
		"boot_diagnostics":             eaU(),
		"cross_region_restore_enabled": eaU(),
		"custom_rule":                  eaU(),
		"customer_managed_key_id":      eaU(),
		"empty":                        eaU(),
		"enabled":                      eaU(),
		"encrypted":                    eaU(),
		"encryption_at_host_enabled":   eaU(),
		"false":                        eaU(),
		"identity":                     eaU(),
		"immutability":                 eaU(),
		"is_https_allowed":             eaU(),
		"managed_rule":                 eaU(),
		"minimum_tls_version":          eaU(),
		"protocol":                     eaU(),
		"redirect_configuration":       eaU(),
		"routing_rule":                 eaU(),
		"secure_boot_enabled":          eaU(),
		"soft_delete_enabled":          eaU(),
		"storage_os_disk":              eaU(),
		"vhd_uri":                      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-286: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_287(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-287")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_cdn_endpoint", "probe", map[string]ir.Value{
			"Disabled":                     eaB(true),
			"Https":                        eaS("public"),
			"Locked":                       eaB(false),
			"TLS12":                        eaS("public"),
			"absent":                       eaS("public"),
			"backend_pool_health_probe":    eaS("s3"),
			"boot_diagnostics":             eaS("public"),
			"cross_region_restore_enabled": eaB(false),
			"custom_rule":                  eaS("public"),
			"customer_managed_key_id":      eaS("password123"),
			"empty":                        eaS("public"),
			"enabled":                      eaB(false),
			"encrypted":                    eaB(false),
			"encryption_at_host_enabled":   eaB(false),
			"identity":                     eaS("public"),
			"immutability":                 eaS("public"),
			"is_https_allowed":             eaS("public"),
			"managed_rule":                 eaS("public"),
			"minimum_tls_version":          eaS("TLS1.0"),
			"protocol":                     eaS("Tcp"),
			"redirect_configuration":       eaS("public"),
			"routing_rule":                 eaS("public"),
			"secure_boot_enabled":          eaB(false),
			"soft_delete_enabled":          eaB(false),
			"storage_os_disk":              eaS("public"),
			"vhd_uri":                      eaS("http://example.com"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-287: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-287: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-287: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_cdn_endpoint", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-287: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_cdn_endpoint", "probe", map[string]ir.Value{
		"Disabled":                     eaU(),
		"Https":                        eaU(),
		"Locked":                       eaU(),
		"TLS12":                        eaU(),
		"absent":                       eaU(),
		"backend_pool_health_probe":    eaU(),
		"boot_diagnostics":             eaU(),
		"cross_region_restore_enabled": eaU(),
		"custom_rule":                  eaU(),
		"customer_managed_key_id":      eaU(),
		"empty":                        eaU(),
		"enabled":                      eaU(),
		"encrypted":                    eaU(),
		"encryption_at_host_enabled":   eaU(),
		"false":                        eaU(),
		"identity":                     eaU(),
		"immutability":                 eaU(),
		"is_https_allowed":             eaU(),
		"managed_rule":                 eaU(),
		"minimum_tls_version":          eaU(),
		"protocol":                     eaU(),
		"redirect_configuration":       eaU(),
		"routing_rule":                 eaU(),
		"secure_boot_enabled":          eaU(),
		"soft_delete_enabled":          eaU(),
		"storage_os_disk":              eaU(),
		"vhd_uri":                      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-287: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_288(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-288")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_recovery_services_vault", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-288: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-288: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-288: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_recovery_services_vault", "probe", map[string]ir.Value{
			"Disabled":                     eaB(false),
			"Https":                        eaS("private"),
			"Locked":                       eaB(true),
			"TLS12":                        eaS("private"),
			"absent":                       eaS("private"),
			"backend_pool_health_probe":    eaS("s3"),
			"boot_diagnostics":             eaS("private"),
			"cross_region_restore_enabled": eaB(true),
			"custom_rule":                  eaS("private"),
			"customer_managed_key_id":      eaS("P@ssw0rd!2024Strong"),
			"empty":                        eaS("private"),
			"enabled":                      eaB(true),
			"encrypted":                    eaB(true),
			"encryption_at_host_enabled":   eaB(true),
			"identity":                     eaS("private"),
			"immutability":                 eaS("private"),
			"is_https_allowed":             eaS("private"),
			"managed_rule":                 eaS("private"),
			"minimum_tls_version":          eaS("TLS1.2"),
			"protocol":                     eaS("Tcp"),
			"redirect_configuration":       eaS("private"),
			"routing_rule":                 eaS("private"),
			"secure_boot_enabled":          eaB(true),
			"soft_delete_enabled":          eaB(true),
			"storage_os_disk":              eaS("private"),
			"vhd_uri":                      eaS("https://example.com"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-288: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_recovery_services_vault", "probe", map[string]ir.Value{
		"Disabled":                     eaU(),
		"Https":                        eaU(),
		"Locked":                       eaU(),
		"TLS12":                        eaU(),
		"absent":                       eaU(),
		"backend_pool_health_probe":    eaU(),
		"boot_diagnostics":             eaU(),
		"cross_region_restore_enabled": eaU(),
		"custom_rule":                  eaU(),
		"customer_managed_key_id":      eaU(),
		"empty":                        eaU(),
		"enabled":                      eaU(),
		"encrypted":                    eaU(),
		"encryption_at_host_enabled":   eaU(),
		"false":                        eaU(),
		"identity":                     eaU(),
		"immutability":                 eaU(),
		"is_https_allowed":             eaU(),
		"managed_rule":                 eaU(),
		"minimum_tls_version":          eaU(),
		"protocol":                     eaU(),
		"redirect_configuration":       eaU(),
		"routing_rule":                 eaU(),
		"secure_boot_enabled":          eaU(),
		"soft_delete_enabled":          eaU(),
		"storage_os_disk":              eaU(),
		"vhd_uri":                      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-288: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_289(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-289")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_recovery_services_vault", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-289: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-289: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-289: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_recovery_services_vault", "probe", map[string]ir.Value{
			"Disabled":                     eaB(true),
			"Https":                        eaS("public"),
			"Locked":                       eaB(false),
			"TLS12":                        eaS("public"),
			"absent":                       eaS("public"),
			"backend_pool_health_probe":    eaS("s3"),
			"boot_diagnostics":             eaS("public"),
			"cross_region_restore_enabled": eaB(false),
			"custom_rule":                  eaS("public"),
			"customer_managed_key_id":      eaS("password123"),
			"empty":                        eaS("public"),
			"enabled":                      eaB(false),
			"encrypted":                    eaB(false),
			"encryption_at_host_enabled":   eaB(false),
			"identity":                     eaS("public"),
			"immutability":                 eaS("public"),
			"is_https_allowed":             eaS("public"),
			"managed_rule":                 eaS("public"),
			"minimum_tls_version":          eaS("TLS1.0"),
			"protocol":                     eaS("Tcp"),
			"redirect_configuration":       eaS("public"),
			"routing_rule":                 eaS("public"),
			"secure_boot_enabled":          eaB(false),
			"soft_delete_enabled":          eaB(false),
			"storage_os_disk":              eaS("public"),
			"vhd_uri":                      eaS("http://example.com"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-289: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_recovery_services_vault", "probe", map[string]ir.Value{
		"Disabled":                     eaU(),
		"Https":                        eaU(),
		"Locked":                       eaU(),
		"TLS12":                        eaU(),
		"absent":                       eaU(),
		"backend_pool_health_probe":    eaU(),
		"boot_diagnostics":             eaU(),
		"cross_region_restore_enabled": eaU(),
		"custom_rule":                  eaU(),
		"customer_managed_key_id":      eaU(),
		"empty":                        eaU(),
		"enabled":                      eaU(),
		"encrypted":                    eaU(),
		"encryption_at_host_enabled":   eaU(),
		"false":                        eaU(),
		"identity":                     eaU(),
		"immutability":                 eaU(),
		"is_https_allowed":             eaU(),
		"managed_rule":                 eaU(),
		"minimum_tls_version":          eaU(),
		"protocol":                     eaU(),
		"redirect_configuration":       eaU(),
		"routing_rule":                 eaU(),
		"secure_boot_enabled":          eaU(),
		"soft_delete_enabled":          eaU(),
		"storage_os_disk":              eaU(),
		"vhd_uri":                      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-289: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_290(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-290")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_recovery_services_vault", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-290: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-290: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-290: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_recovery_services_vault", "probe", map[string]ir.Value{
			"immutability": eaL(eaM("Disabled", eaB(true), "Https", eaS("public"), "Locked", eaB(false), "TLS12", eaS("public"), "absent", eaS("public"), "backend_pool_health_probe", eaS("s3"), "boot_diagnostics", eaS("public"), "cross_region_restore_enabled", eaB(false), "custom_rule", eaS("public"), "customer_managed_key_id", eaS("password123"), "empty", eaS("public"), "enabled", eaB(false), "encrypted", eaB(false), "encryption_at_host_enabled", eaB(false), "identity", eaS("public"), "immutability", eaS("public"), "is_https_allowed", eaS("public"), "managed_rule", eaS("public"), "minimum_tls_version", eaS("TLS1.0"), "protocol", eaS("Tcp"), "redirect_configuration", eaS("public"), "routing_rule", eaS("public"), "secure_boot_enabled", eaB(false), "soft_delete_enabled", eaB(false), "storage_os_disk", eaS("public"), "vhd_uri", eaS("http://example.com"))),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-290: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_recovery_services_vault", "probe", map[string]ir.Value{
		"Disabled":                     eaU(),
		"Https":                        eaU(),
		"Locked":                       eaU(),
		"TLS12":                        eaU(),
		"absent":                       eaU(),
		"backend_pool_health_probe":    eaU(),
		"boot_diagnostics":             eaU(),
		"cross_region_restore_enabled": eaU(),
		"custom_rule":                  eaU(),
		"customer_managed_key_id":      eaU(),
		"empty":                        eaU(),
		"enabled":                      eaU(),
		"encrypted":                    eaU(),
		"encryption_at_host_enabled":   eaU(),
		"false":                        eaU(),
		"identity":                     eaU(),
		"immutability":                 eaU(),
		"is_https_allowed":             eaU(),
		"managed_rule":                 eaU(),
		"minimum_tls_version":          eaU(),
		"protocol":                     eaU(),
		"redirect_configuration":       eaU(),
		"routing_rule":                 eaU(),
		"secure_boot_enabled":          eaU(),
		"soft_delete_enabled":          eaU(),
		"storage_os_disk":              eaU(),
		"vhd_uri":                      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-290: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_291(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-291")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_recovery_services_vault", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-291: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-291: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-291: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_recovery_services_vault", "probe", map[string]ir.Value{
			"Disabled":                     eaB(false),
			"Https":                        eaS("private"),
			"Locked":                       eaB(true),
			"TLS12":                        eaS("private"),
			"absent":                       eaS("private"),
			"backend_pool_health_probe":    eaS("s3"),
			"boot_diagnostics":             eaS("private"),
			"cross_region_restore_enabled": eaB(true),
			"custom_rule":                  eaS("private"),
			"customer_managed_key_id":      eaS("P@ssw0rd!2024Strong"),
			"empty":                        eaS("private"),
			"enabled":                      eaB(true),
			"encrypted":                    eaB(true),
			"encryption_at_host_enabled":   eaB(true),
			"identity":                     eaS("private"),
			"immutability":                 eaS("private"),
			"is_https_allowed":             eaS("private"),
			"managed_rule":                 eaS("private"),
			"minimum_tls_version":          eaS("TLS1.2"),
			"protocol":                     eaS("Tcp"),
			"redirect_configuration":       eaS("private"),
			"routing_rule":                 eaS("private"),
			"secure_boot_enabled":          eaB(true),
			"soft_delete_enabled":          eaB(true),
			"storage_os_disk":              eaS("private"),
			"vhd_uri":                      eaS("https://example.com"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-291: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_recovery_services_vault", "probe", map[string]ir.Value{
		"Disabled":                     eaU(),
		"Https":                        eaU(),
		"Locked":                       eaU(),
		"TLS12":                        eaU(),
		"absent":                       eaU(),
		"backend_pool_health_probe":    eaU(),
		"boot_diagnostics":             eaU(),
		"cross_region_restore_enabled": eaU(),
		"custom_rule":                  eaU(),
		"customer_managed_key_id":      eaU(),
		"empty":                        eaU(),
		"enabled":                      eaU(),
		"encrypted":                    eaU(),
		"encryption_at_host_enabled":   eaU(),
		"false":                        eaU(),
		"identity":                     eaU(),
		"immutability":                 eaU(),
		"is_https_allowed":             eaU(),
		"managed_rule":                 eaU(),
		"minimum_tls_version":          eaU(),
		"protocol":                     eaU(),
		"redirect_configuration":       eaU(),
		"routing_rule":                 eaU(),
		"secure_boot_enabled":          eaU(),
		"soft_delete_enabled":          eaU(),
		"storage_os_disk":              eaU(),
		"vhd_uri":                      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-291: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_292(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-292")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_automation_account", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-292: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-292: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-292: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_automation_account", "probe", map[string]ir.Value{
			"Disabled":                     eaB(true),
			"Https":                        eaS("public"),
			"Locked":                       eaB(false),
			"TLS12":                        eaS("public"),
			"absent":                       eaS("public"),
			"backend_pool_health_probe":    eaS("s3"),
			"boot_diagnostics":             eaS("public"),
			"cross_region_restore_enabled": eaB(false),
			"custom_rule":                  eaS("public"),
			"customer_managed_key_id":      eaS("password123"),
			"empty":                        eaS("public"),
			"enabled":                      eaB(false),
			"encrypted":                    eaB(false),
			"encryption_at_host_enabled":   eaB(false),
			"identity":                     eaS("public"),
			"immutability":                 eaS("public"),
			"is_https_allowed":             eaS("public"),
			"managed_rule":                 eaS("public"),
			"minimum_tls_version":          eaS("TLS1.0"),
			"protocol":                     eaS("Tcp"),
			"redirect_configuration":       eaS("public"),
			"routing_rule":                 eaS("public"),
			"secure_boot_enabled":          eaB(false),
			"soft_delete_enabled":          eaB(false),
			"storage_os_disk":              eaS("public"),
			"vhd_uri":                      eaS("http://example.com"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-292: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_automation_account", "probe", map[string]ir.Value{
		"Disabled":                     eaU(),
		"Https":                        eaU(),
		"Locked":                       eaU(),
		"TLS12":                        eaU(),
		"absent":                       eaU(),
		"backend_pool_health_probe":    eaU(),
		"boot_diagnostics":             eaU(),
		"cross_region_restore_enabled": eaU(),
		"custom_rule":                  eaU(),
		"customer_managed_key_id":      eaU(),
		"empty":                        eaU(),
		"enabled":                      eaU(),
		"encrypted":                    eaU(),
		"encryption_at_host_enabled":   eaU(),
		"false":                        eaU(),
		"identity":                     eaU(),
		"immutability":                 eaU(),
		"is_https_allowed":             eaU(),
		"managed_rule":                 eaU(),
		"minimum_tls_version":          eaU(),
		"protocol":                     eaU(),
		"redirect_configuration":       eaU(),
		"routing_rule":                 eaU(),
		"secure_boot_enabled":          eaU(),
		"soft_delete_enabled":          eaU(),
		"storage_os_disk":              eaU(),
		"vhd_uri":                      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-292: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_293(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-293")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_automation_variable_string", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-293: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-293: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-293: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_automation_variable_string", "probe", map[string]ir.Value{
			"Disabled":                     eaB(false),
			"Https":                        eaS("private"),
			"Locked":                       eaB(true),
			"TLS12":                        eaS("private"),
			"absent":                       eaS("private"),
			"backend_pool_health_probe":    eaS("s3"),
			"boot_diagnostics":             eaS("private"),
			"cross_region_restore_enabled": eaB(true),
			"custom_rule":                  eaS("private"),
			"customer_managed_key_id":      eaS("P@ssw0rd!2024Strong"),
			"empty":                        eaS("private"),
			"enabled":                      eaB(true),
			"encrypted":                    eaB(true),
			"encryption_at_host_enabled":   eaB(true),
			"identity":                     eaS("private"),
			"immutability":                 eaS("private"),
			"is_https_allowed":             eaS("private"),
			"managed_rule":                 eaS("private"),
			"minimum_tls_version":          eaS("TLS1.2"),
			"protocol":                     eaS("Tcp"),
			"redirect_configuration":       eaS("private"),
			"routing_rule":                 eaS("private"),
			"secure_boot_enabled":          eaB(true),
			"soft_delete_enabled":          eaB(true),
			"storage_os_disk":              eaS("private"),
			"vhd_uri":                      eaS("https://example.com"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-293: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_automation_variable_string", "probe", map[string]ir.Value{
		"Disabled":                     eaU(),
		"Https":                        eaU(),
		"Locked":                       eaU(),
		"TLS12":                        eaU(),
		"absent":                       eaU(),
		"backend_pool_health_probe":    eaU(),
		"boot_diagnostics":             eaU(),
		"cross_region_restore_enabled": eaU(),
		"custom_rule":                  eaU(),
		"customer_managed_key_id":      eaU(),
		"empty":                        eaU(),
		"enabled":                      eaU(),
		"encrypted":                    eaU(),
		"encryption_at_host_enabled":   eaU(),
		"false":                        eaU(),
		"identity":                     eaU(),
		"immutability":                 eaU(),
		"is_https_allowed":             eaU(),
		"managed_rule":                 eaU(),
		"minimum_tls_version":          eaU(),
		"protocol":                     eaU(),
		"redirect_configuration":       eaU(),
		"routing_rule":                 eaU(),
		"secure_boot_enabled":          eaU(),
		"soft_delete_enabled":          eaU(),
		"storage_os_disk":              eaU(),
		"vhd_uri":                      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-293: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_294(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-294")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_linux_virtual_machine", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-294: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-294: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-294: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_linux_virtual_machine", "probe", map[string]ir.Value{
			"Disabled":                     eaB(false),
			"Https":                        eaS("private"),
			"Locked":                       eaB(true),
			"TLS12":                        eaS("private"),
			"absent":                       eaS("private"),
			"backend_pool_health_probe":    eaS("s3"),
			"boot_diagnostics":             eaS("private"),
			"cross_region_restore_enabled": eaB(true),
			"custom_rule":                  eaS("private"),
			"customer_managed_key_id":      eaS("P@ssw0rd!2024Strong"),
			"empty":                        eaS("private"),
			"enabled":                      eaB(true),
			"encrypted":                    eaB(true),
			"encryption_at_host_enabled":   eaB(true),
			"identity":                     eaS("private"),
			"immutability":                 eaS("private"),
			"is_https_allowed":             eaS("private"),
			"managed_rule":                 eaS("private"),
			"minimum_tls_version":          eaS("TLS1.2"),
			"protocol":                     eaS("Tcp"),
			"redirect_configuration":       eaS("private"),
			"routing_rule":                 eaS("private"),
			"secure_boot_enabled":          eaB(true),
			"soft_delete_enabled":          eaB(true),
			"storage_os_disk":              eaS("private"),
			"vhd_uri":                      eaS("https://example.com"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-294: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_linux_virtual_machine", "probe", map[string]ir.Value{
		"Disabled":                     eaU(),
		"Https":                        eaU(),
		"Locked":                       eaU(),
		"TLS12":                        eaU(),
		"absent":                       eaU(),
		"backend_pool_health_probe":    eaU(),
		"boot_diagnostics":             eaU(),
		"cross_region_restore_enabled": eaU(),
		"custom_rule":                  eaU(),
		"customer_managed_key_id":      eaU(),
		"empty":                        eaU(),
		"enabled":                      eaU(),
		"encrypted":                    eaU(),
		"encryption_at_host_enabled":   eaU(),
		"false":                        eaU(),
		"identity":                     eaU(),
		"immutability":                 eaU(),
		"is_https_allowed":             eaU(),
		"managed_rule":                 eaU(),
		"minimum_tls_version":          eaU(),
		"protocol":                     eaU(),
		"redirect_configuration":       eaU(),
		"routing_rule":                 eaU(),
		"secure_boot_enabled":          eaU(),
		"soft_delete_enabled":          eaU(),
		"storage_os_disk":              eaU(),
		"vhd_uri":                      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-294: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_295(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-295")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_linux_virtual_machine", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-295: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-295: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-295: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_linux_virtual_machine", "probe", map[string]ir.Value{
			"Disabled":                     eaB(false),
			"Https":                        eaS("private"),
			"Locked":                       eaB(true),
			"TLS12":                        eaS("private"),
			"absent":                       eaS("private"),
			"backend_pool_health_probe":    eaS("s3"),
			"boot_diagnostics":             eaS("private"),
			"cross_region_restore_enabled": eaB(true),
			"custom_rule":                  eaS("private"),
			"customer_managed_key_id":      eaS("P@ssw0rd!2024Strong"),
			"empty":                        eaS("private"),
			"enabled":                      eaB(true),
			"encrypted":                    eaB(true),
			"encryption_at_host_enabled":   eaB(true),
			"identity":                     eaS("private"),
			"immutability":                 eaS("private"),
			"is_https_allowed":             eaS("private"),
			"managed_rule":                 eaS("private"),
			"minimum_tls_version":          eaS("TLS1.2"),
			"protocol":                     eaS("Tcp"),
			"redirect_configuration":       eaS("private"),
			"routing_rule":                 eaS("private"),
			"secure_boot_enabled":          eaB(true),
			"soft_delete_enabled":          eaB(true),
			"storage_os_disk":              eaS("private"),
			"vhd_uri":                      eaS("https://example.com"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-295: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_linux_virtual_machine", "probe", map[string]ir.Value{
		"Disabled":                     eaU(),
		"Https":                        eaU(),
		"Locked":                       eaU(),
		"TLS12":                        eaU(),
		"absent":                       eaU(),
		"backend_pool_health_probe":    eaU(),
		"boot_diagnostics":             eaU(),
		"cross_region_restore_enabled": eaU(),
		"custom_rule":                  eaU(),
		"customer_managed_key_id":      eaU(),
		"empty":                        eaU(),
		"enabled":                      eaU(),
		"encrypted":                    eaU(),
		"encryption_at_host_enabled":   eaU(),
		"false":                        eaU(),
		"identity":                     eaU(),
		"immutability":                 eaU(),
		"is_https_allowed":             eaU(),
		"managed_rule":                 eaU(),
		"minimum_tls_version":          eaU(),
		"protocol":                     eaU(),
		"redirect_configuration":       eaU(),
		"routing_rule":                 eaU(),
		"secure_boot_enabled":          eaU(),
		"soft_delete_enabled":          eaU(),
		"storage_os_disk":              eaU(),
		"vhd_uri":                      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-295: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_296(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-296")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_virtual_machine", "probe", map[string]ir.Value{
			"storage_os_disk": eaL(eaM("Disabled", eaB(true), "Https", eaS("public"), "Locked", eaB(false), "TLS12", eaS("public"), "absent", eaS("public"), "backend_pool_health_probe", eaS("s3"), "boot_diagnostics", eaS("public"), "cross_region_restore_enabled", eaB(false), "custom_rule", eaS("public"), "customer_managed_key_id", eaS("password123"), "empty", eaS("public"), "enabled", eaB(false), "encrypted", eaB(false), "encryption_at_host_enabled", eaB(false), "identity", eaS("public"), "immutability", eaS("public"), "is_https_allowed", eaS("public"), "managed_rule", eaS("public"), "minimum_tls_version", eaS("TLS1.0"), "protocol", eaS("Tcp"), "redirect_configuration", eaS("public"), "routing_rule", eaS("public"), "secure_boot_enabled", eaB(false), "soft_delete_enabled", eaB(false), "storage_os_disk", eaS("public"), "vhd_uri", eaS("http://example.com"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-296: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-296: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-296: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_virtual_machine", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-296: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_virtual_machine", "probe", map[string]ir.Value{
		"Disabled":                     eaU(),
		"Https":                        eaU(),
		"Locked":                       eaU(),
		"TLS12":                        eaU(),
		"absent":                       eaU(),
		"backend_pool_health_probe":    eaU(),
		"boot_diagnostics":             eaU(),
		"cross_region_restore_enabled": eaU(),
		"custom_rule":                  eaU(),
		"customer_managed_key_id":      eaU(),
		"empty":                        eaU(),
		"enabled":                      eaU(),
		"encrypted":                    eaU(),
		"encryption_at_host_enabled":   eaU(),
		"false":                        eaU(),
		"identity":                     eaU(),
		"immutability":                 eaU(),
		"is_https_allowed":             eaU(),
		"managed_rule":                 eaU(),
		"minimum_tls_version":          eaU(),
		"protocol":                     eaU(),
		"redirect_configuration":       eaU(),
		"routing_rule":                 eaU(),
		"secure_boot_enabled":          eaU(),
		"soft_delete_enabled":          eaU(),
		"storage_os_disk":              eaU(),
		"vhd_uri":                      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-296: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_297(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-297")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_linux_virtual_machine", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-297: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-297: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-297: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_linux_virtual_machine", "probe", map[string]ir.Value{
			"Disabled":                     eaB(true),
			"Https":                        eaS("public"),
			"Locked":                       eaB(false),
			"TLS12":                        eaS("public"),
			"absent":                       eaS("public"),
			"backend_pool_health_probe":    eaS("s3"),
			"boot_diagnostics":             eaS("public"),
			"cross_region_restore_enabled": eaB(false),
			"custom_rule":                  eaS("public"),
			"customer_managed_key_id":      eaS("password123"),
			"empty":                        eaS("public"),
			"enabled":                      eaB(false),
			"encrypted":                    eaB(false),
			"encryption_at_host_enabled":   eaB(false),
			"identity":                     eaS("public"),
			"immutability":                 eaS("public"),
			"is_https_allowed":             eaS("public"),
			"managed_rule":                 eaS("public"),
			"minimum_tls_version":          eaS("TLS1.0"),
			"protocol":                     eaS("Tcp"),
			"redirect_configuration":       eaS("public"),
			"routing_rule":                 eaS("public"),
			"secure_boot_enabled":          eaB(false),
			"soft_delete_enabled":          eaB(false),
			"storage_os_disk":              eaS("public"),
			"vhd_uri":                      eaS("http://example.com"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-297: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_linux_virtual_machine", "probe", map[string]ir.Value{
		"Disabled":                     eaU(),
		"Https":                        eaU(),
		"Locked":                       eaU(),
		"TLS12":                        eaU(),
		"absent":                       eaU(),
		"backend_pool_health_probe":    eaU(),
		"boot_diagnostics":             eaU(),
		"cross_region_restore_enabled": eaU(),
		"custom_rule":                  eaU(),
		"customer_managed_key_id":      eaU(),
		"empty":                        eaU(),
		"enabled":                      eaU(),
		"encrypted":                    eaU(),
		"encryption_at_host_enabled":   eaU(),
		"false":                        eaU(),
		"identity":                     eaU(),
		"immutability":                 eaU(),
		"is_https_allowed":             eaU(),
		"managed_rule":                 eaU(),
		"minimum_tls_version":          eaU(),
		"protocol":                     eaU(),
		"redirect_configuration":       eaU(),
		"routing_rule":                 eaU(),
		"secure_boot_enabled":          eaU(),
		"soft_delete_enabled":          eaU(),
		"storage_os_disk":              eaU(),
		"vhd_uri":                      eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-297: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_299(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-299")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_data_factory", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-299: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-299: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-299: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_data_factory", "probe", map[string]ir.Value{
			"Deny":                                 eaS("public"),
			"absent":                               eaS("public"),
			"custom_parameters":                    eaS("public"),
			"customer_managed_key":                 eaS("password123"),
			"customer_managed_key_id":              eaS("password123"),
			"data_exfiltration_protection_enabled": eaB(false),
			"default_action":                       eaL(eaS("*")),
			"empty":                                eaS("public"),
			"fallback_route":                       eaS("public"),
			"infrastructure_encryption_enabled":    eaB(false),
			"ip_filter_rule":                       eaS("public"),
			"local_auth_enabled":                   eaB(false),
			"managed_virtual_network_enabled":      eaB(false),
			"min_tls_version":                      eaS("TLS1.0"),
			"network_acls":                         eaS("public"),
			"no_public_ip":                         eaB(true),
			"public_network_access_enabled":        eaS("Allow"),
			"registry_write":                       eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-299: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_data_factory", "probe", map[string]ir.Value{
		"Deny":                                 eaU(),
		"absent":                               eaU(),
		"custom_parameters":                    eaU(),
		"customer_managed_key":                 eaU(),
		"customer_managed_key_id":              eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"default_action":                       eaU(),
		"empty":                                eaU(),
		"fallback_route":                       eaU(),
		"infrastructure_encryption_enabled":    eaU(),
		"ip_filter_rule":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"min_tls_version":                      eaU(),
		"network_acls":                         eaU(),
		"no_public_ip":                         eaU(),
		"public_network_access_enabled":        eaU(),
		"registry_write":                       eaU(),
		"true":                                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-299: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_300(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-300")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_data_factory", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-300: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-300: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-300: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_data_factory", "probe", map[string]ir.Value{
			"Deny":                                 eaS("private"),
			"absent":                               eaS("private"),
			"custom_parameters":                    eaS("private"),
			"customer_managed_key":                 eaS("P@ssw0rd!2024Strong"),
			"customer_managed_key_id":              eaS("P@ssw0rd!2024Strong"),
			"data_exfiltration_protection_enabled": eaB(true),
			"default_action":                       eaL(eaS("s3:GetObject")),
			"empty":                                eaS("private"),
			"fallback_route":                       eaS("private"),
			"identity":                             eaS("private"),
			"infrastructure_encryption_enabled":    eaB(true),
			"ip_filter_rule":                       eaS("private"),
			"local_auth_enabled":                   eaB(true),
			"managed_virtual_network_enabled":      eaB(true),
			"min_tls_version":                      eaS("TLS1.2"),
			"network_acls":                         eaS("private"),
			"no_public_ip":                         eaB(false),
			"public_network_access_enabled":        eaS("Deny"),
			"registry_write":                       eaS("private"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-300: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_data_factory", "probe", map[string]ir.Value{
		"Deny":                                 eaU(),
		"absent":                               eaU(),
		"custom_parameters":                    eaU(),
		"customer_managed_key":                 eaU(),
		"customer_managed_key_id":              eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"default_action":                       eaU(),
		"empty":                                eaU(),
		"fallback_route":                       eaU(),
		"false":                                eaU(),
		"identity":                             eaU(),
		"infrastructure_encryption_enabled":    eaU(),
		"ip_filter_rule":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"min_tls_version":                      eaU(),
		"network_acls":                         eaU(),
		"no_public_ip":                         eaU(),
		"public_network_access_enabled":        eaU(),
		"registry_write":                       eaU(),
		"true":                                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-300: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_301(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-301")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_synapse_workspace", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-301: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-301: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-301: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_synapse_workspace", "probe", map[string]ir.Value{
			"Deny":                                 eaS("private"),
			"absent":                               eaS("private"),
			"custom_parameters":                    eaS("private"),
			"customer_managed_key":                 eaS("P@ssw0rd!2024Strong"),
			"customer_managed_key_id":              eaS("P@ssw0rd!2024Strong"),
			"data_exfiltration_protection_enabled": eaB(true),
			"default_action":                       eaL(eaS("s3:GetObject")),
			"empty":                                eaS("private"),
			"fallback_route":                       eaS("private"),
			"identity":                             eaS("private"),
			"infrastructure_encryption_enabled":    eaB(true),
			"ip_filter_rule":                       eaS("private"),
			"local_auth_enabled":                   eaB(true),
			"managed_virtual_network_enabled":      eaB(true),
			"min_tls_version":                      eaS("TLS1.2"),
			"network_acls":                         eaS("private"),
			"no_public_ip":                         eaB(false),
			"public_network_access_enabled":        eaS("Deny"),
			"registry_write":                       eaS("private"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-301: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_synapse_workspace", "probe", map[string]ir.Value{
		"Deny":                                 eaU(),
		"absent":                               eaU(),
		"custom_parameters":                    eaU(),
		"customer_managed_key":                 eaU(),
		"customer_managed_key_id":              eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"default_action":                       eaU(),
		"empty":                                eaU(),
		"fallback_route":                       eaU(),
		"false":                                eaU(),
		"identity":                             eaU(),
		"infrastructure_encryption_enabled":    eaU(),
		"ip_filter_rule":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"min_tls_version":                      eaU(),
		"network_acls":                         eaU(),
		"no_public_ip":                         eaU(),
		"public_network_access_enabled":        eaU(),
		"registry_write":                       eaU(),
		"true":                                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-301: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_302(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-302")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_synapse_workspace", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-302: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-302: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-302: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_synapse_workspace", "probe", map[string]ir.Value{
			"Deny":                                 eaS("public"),
			"absent":                               eaS("public"),
			"custom_parameters":                    eaS("public"),
			"customer_managed_key":                 eaS("password123"),
			"customer_managed_key_id":              eaS("password123"),
			"data_exfiltration_protection_enabled": eaB(false),
			"default_action":                       eaL(eaS("*")),
			"empty":                                eaS("public"),
			"fallback_route":                       eaS("public"),
			"infrastructure_encryption_enabled":    eaB(false),
			"ip_filter_rule":                       eaS("public"),
			"local_auth_enabled":                   eaB(false),
			"managed_virtual_network_enabled":      eaB(false),
			"min_tls_version":                      eaS("TLS1.0"),
			"network_acls":                         eaS("public"),
			"no_public_ip":                         eaB(true),
			"public_network_access_enabled":        eaS("Allow"),
			"registry_write":                       eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-302: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_synapse_workspace", "probe", map[string]ir.Value{
		"Deny":                                 eaU(),
		"absent":                               eaU(),
		"custom_parameters":                    eaU(),
		"customer_managed_key":                 eaU(),
		"customer_managed_key_id":              eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"default_action":                       eaU(),
		"empty":                                eaU(),
		"fallback_route":                       eaU(),
		"infrastructure_encryption_enabled":    eaU(),
		"ip_filter_rule":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"min_tls_version":                      eaU(),
		"network_acls":                         eaU(),
		"no_public_ip":                         eaU(),
		"public_network_access_enabled":        eaU(),
		"registry_write":                       eaU(),
		"true":                                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-302: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_303(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-303")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_databricks_workspace", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-303: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-303: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-303: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_databricks_workspace", "probe", map[string]ir.Value{
			"Deny":                                 eaS("private"),
			"absent":                               eaS("private"),
			"custom_parameters":                    eaS("private"),
			"customer_managed_key":                 eaS("P@ssw0rd!2024Strong"),
			"customer_managed_key_id":              eaS("P@ssw0rd!2024Strong"),
			"data_exfiltration_protection_enabled": eaB(true),
			"default_action":                       eaL(eaS("s3:GetObject")),
			"empty":                                eaS("private"),
			"fallback_route":                       eaS("private"),
			"identity":                             eaS("private"),
			"infrastructure_encryption_enabled":    eaB(true),
			"ip_filter_rule":                       eaS("private"),
			"local_auth_enabled":                   eaB(true),
			"managed_virtual_network_enabled":      eaB(true),
			"min_tls_version":                      eaS("TLS1.2"),
			"network_acls":                         eaS("private"),
			"no_public_ip":                         eaB(false),
			"public_network_access_enabled":        eaS("Deny"),
			"registry_write":                       eaS("private"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-303: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_databricks_workspace", "probe", map[string]ir.Value{
		"Deny":                                 eaU(),
		"absent":                               eaU(),
		"custom_parameters":                    eaU(),
		"customer_managed_key":                 eaU(),
		"customer_managed_key_id":              eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"default_action":                       eaU(),
		"empty":                                eaU(),
		"fallback_route":                       eaU(),
		"false":                                eaU(),
		"identity":                             eaU(),
		"infrastructure_encryption_enabled":    eaU(),
		"ip_filter_rule":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"min_tls_version":                      eaU(),
		"network_acls":                         eaU(),
		"no_public_ip":                         eaU(),
		"public_network_access_enabled":        eaU(),
		"registry_write":                       eaU(),
		"true":                                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-303: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_304(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-304")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_databricks_workspace", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-304: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-304: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-304: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_databricks_workspace", "probe", map[string]ir.Value{
			"custom_parameters": eaL(eaM("Deny", eaS("public"), "absent", eaS("public"), "custom_parameters", eaS("public"), "customer_managed_key", eaS("password123"), "customer_managed_key_id", eaS("password123"), "data_exfiltration_protection_enabled", eaB(false), "default_action", eaL(eaS("*")), "empty", eaS("public"), "fallback_route", eaS("public"), "infrastructure_encryption_enabled", eaB(false), "ip_filter_rule", eaS("public"), "local_auth_enabled", eaB(false), "managed_virtual_network_enabled", eaB(false), "min_tls_version", eaS("TLS1.0"), "network_acls", eaS("public"), "no_public_ip", eaB(true), "public_network_access_enabled", eaS("Allow"), "registry_write", eaS("public"))),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-304: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_305(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-305")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_iothub", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-305: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-305: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-305: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_iothub", "probe", map[string]ir.Value{
			"Deny":                                 eaS("public"),
			"absent":                               eaS("public"),
			"custom_parameters":                    eaS("public"),
			"customer_managed_key":                 eaS("password123"),
			"customer_managed_key_id":              eaS("password123"),
			"data_exfiltration_protection_enabled": eaB(false),
			"default_action":                       eaL(eaS("*")),
			"empty":                                eaS("public"),
			"fallback_route":                       eaS("public"),
			"infrastructure_encryption_enabled":    eaB(false),
			"ip_filter_rule":                       eaS("public"),
			"local_auth_enabled":                   eaB(false),
			"managed_virtual_network_enabled":      eaB(false),
			"min_tls_version":                      eaS("TLS1.0"),
			"network_acls":                         eaS("public"),
			"no_public_ip":                         eaB(true),
			"public_network_access_enabled":        eaS("Allow"),
			"registry_write":                       eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-305: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_iothub", "probe", map[string]ir.Value{
		"Deny":                                 eaU(),
		"absent":                               eaU(),
		"custom_parameters":                    eaU(),
		"customer_managed_key":                 eaU(),
		"customer_managed_key_id":              eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"default_action":                       eaU(),
		"empty":                                eaU(),
		"fallback_route":                       eaU(),
		"infrastructure_encryption_enabled":    eaU(),
		"ip_filter_rule":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"min_tls_version":                      eaU(),
		"network_acls":                         eaU(),
		"no_public_ip":                         eaU(),
		"public_network_access_enabled":        eaU(),
		"registry_write":                       eaU(),
		"true":                                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-305: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_306(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-306")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_iothub_shared_access_policy", "probe", map[string]ir.Value{
			"Deny":                                 eaB(true),
			"absent":                               eaB(true),
			"custom_parameters":                    eaB(true),
			"customer_managed_key":                 eaB(true),
			"customer_managed_key_id":              eaB(true),
			"data_exfiltration_protection_enabled": eaB(true),
			"default_action":                       eaB(true),
			"empty":                                eaB(true),
			"fallback_route":                       eaB(true),
			"infrastructure_encryption_enabled":    eaB(true),
			"ip_filter_rule":                       eaB(true),
			"local_auth_enabled":                   eaB(true),
			"managed_virtual_network_enabled":      eaB(true),
			"min_tls_version":                      eaB(true),
			"network_acls":                         eaB(true),
			"no_public_ip":                         eaB(true),
			"public_network_access_enabled":        eaB(true),
			"registry_write":                       eaB(true),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-306: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-306: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-306: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_iothub_shared_access_policy", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-306: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_iothub_shared_access_policy", "probe", map[string]ir.Value{
		"Deny":                                 eaU(),
		"absent":                               eaU(),
		"custom_parameters":                    eaU(),
		"customer_managed_key":                 eaU(),
		"customer_managed_key_id":              eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"default_action":                       eaU(),
		"empty":                                eaU(),
		"fallback_route":                       eaU(),
		"infrastructure_encryption_enabled":    eaU(),
		"ip_filter_rule":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"min_tls_version":                      eaU(),
		"network_acls":                         eaU(),
		"no_public_ip":                         eaU(),
		"public_network_access_enabled":        eaU(),
		"registry_write":                       eaU(),
		"true":                                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-306: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_307(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-307")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_iothub", "probe", map[string]ir.Value{
			"Deny":                                 eaS("public"),
			"absent":                               eaS("public"),
			"custom_parameters":                    eaS("public"),
			"customer_managed_key":                 eaS("password123"),
			"customer_managed_key_id":              eaS("password123"),
			"data_exfiltration_protection_enabled": eaB(false),
			"default_action":                       eaL(eaS("*")),
			"empty":                                eaS("public"),
			"fallback_route":                       eaS("public"),
			"infrastructure_encryption_enabled":    eaB(false),
			"ip_filter_rule":                       eaS("public"),
			"local_auth_enabled":                   eaB(false),
			"managed_virtual_network_enabled":      eaB(false),
			"min_tls_version":                      eaS("TLS1.0"),
			"network_acls":                         eaS("public"),
			"no_public_ip":                         eaB(true),
			"public_network_access_enabled":        eaS("Allow"),
			"registry_write":                       eaS("public"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-307: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-307: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-307: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_iothub", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-307: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_iothub", "probe", map[string]ir.Value{
		"Deny":                                 eaU(),
		"absent":                               eaU(),
		"custom_parameters":                    eaU(),
		"customer_managed_key":                 eaU(),
		"customer_managed_key_id":              eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"default_action":                       eaU(),
		"empty":                                eaU(),
		"fallback_route":                       eaU(),
		"infrastructure_encryption_enabled":    eaU(),
		"ip_filter_rule":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"min_tls_version":                      eaU(),
		"network_acls":                         eaU(),
		"no_public_ip":                         eaU(),
		"public_network_access_enabled":        eaU(),
		"registry_write":                       eaU(),
		"true":                                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-307: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_308(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-308")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_iothub", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-308: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-308: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-308: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_iothub", "probe", map[string]ir.Value{
			"Deny":                                 eaS("public"),
			"absent":                               eaS("public"),
			"custom_parameters":                    eaS("public"),
			"customer_managed_key":                 eaS("password123"),
			"customer_managed_key_id":              eaS("password123"),
			"data_exfiltration_protection_enabled": eaB(false),
			"default_action":                       eaL(eaS("*")),
			"empty":                                eaS("public"),
			"fallback_route":                       eaS("public"),
			"infrastructure_encryption_enabled":    eaB(false),
			"ip_filter_rule":                       eaS("public"),
			"local_auth_enabled":                   eaB(false),
			"managed_virtual_network_enabled":      eaB(false),
			"min_tls_version":                      eaS("TLS1.0"),
			"network_acls":                         eaS("public"),
			"no_public_ip":                         eaB(true),
			"public_network_access_enabled":        eaS("Allow"),
			"registry_write":                       eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-308: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_iothub", "probe", map[string]ir.Value{
		"Deny":                                 eaU(),
		"absent":                               eaU(),
		"custom_parameters":                    eaU(),
		"customer_managed_key":                 eaU(),
		"customer_managed_key_id":              eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"default_action":                       eaU(),
		"empty":                                eaU(),
		"fallback_route":                       eaU(),
		"infrastructure_encryption_enabled":    eaU(),
		"ip_filter_rule":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"min_tls_version":                      eaU(),
		"network_acls":                         eaU(),
		"no_public_ip":                         eaU(),
		"public_network_access_enabled":        eaU(),
		"registry_write":                       eaU(),
		"true":                                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-308: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_309(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-309")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_cognitive_account", "probe", map[string]ir.Value{
			"network_acls": eaM("AWS_SECRET_ACCESS_KEY", eaS("x"), "api_key", eaS("x"), "password", eaS("x"), "private_key", eaS("x"), "secret", eaS("x"), "token", eaS("x")),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-309: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-309: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-309: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_cognitive_account", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-309: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_cognitive_account", "probe", map[string]ir.Value{
		"Deny":                                 eaU(),
		"absent":                               eaU(),
		"custom_parameters":                    eaU(),
		"customer_managed_key":                 eaU(),
		"customer_managed_key_id":              eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"default_action":                       eaU(),
		"empty":                                eaU(),
		"fallback_route":                       eaU(),
		"infrastructure_encryption_enabled":    eaU(),
		"ip_filter_rule":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"min_tls_version":                      eaU(),
		"network_acls":                         eaU(),
		"no_public_ip":                         eaU(),
		"public_network_access_enabled":        eaU(),
		"registry_write":                       eaU(),
		"true":                                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-309: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_310(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-310")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_cognitive_account", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-310: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-310: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-310: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_cognitive_account", "probe", map[string]ir.Value{
			"Deny":                                 eaS("public"),
			"absent":                               eaS("public"),
			"custom_parameters":                    eaS("public"),
			"customer_managed_key":                 eaS("password123"),
			"customer_managed_key_id":              eaS("password123"),
			"data_exfiltration_protection_enabled": eaB(false),
			"default_action":                       eaL(eaS("*")),
			"empty":                                eaS("public"),
			"fallback_route":                       eaS("public"),
			"infrastructure_encryption_enabled":    eaB(false),
			"ip_filter_rule":                       eaS("public"),
			"local_auth_enabled":                   eaB(false),
			"managed_virtual_network_enabled":      eaB(false),
			"min_tls_version":                      eaS("TLS1.0"),
			"network_acls":                         eaS("public"),
			"no_public_ip":                         eaB(true),
			"public_network_access_enabled":        eaS("Allow"),
			"registry_write":                       eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-310: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_cognitive_account", "probe", map[string]ir.Value{
		"Deny":                                 eaU(),
		"absent":                               eaU(),
		"custom_parameters":                    eaU(),
		"customer_managed_key":                 eaU(),
		"customer_managed_key_id":              eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"default_action":                       eaU(),
		"empty":                                eaU(),
		"fallback_route":                       eaU(),
		"infrastructure_encryption_enabled":    eaU(),
		"ip_filter_rule":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"min_tls_version":                      eaU(),
		"network_acls":                         eaU(),
		"no_public_ip":                         eaU(),
		"public_network_access_enabled":        eaU(),
		"registry_write":                       eaU(),
		"true":                                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-310: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_311(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-311")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("azurerm_cognitive_account", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-311: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-311: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-311: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_cognitive_account", "probe", map[string]ir.Value{
			"Deny":                                 eaS("public"),
			"absent":                               eaS("public"),
			"custom_parameters":                    eaS("public"),
			"customer_managed_key":                 eaS("password123"),
			"customer_managed_key_id":              eaS("password123"),
			"data_exfiltration_protection_enabled": eaB(false),
			"default_action":                       eaL(eaS("*")),
			"empty":                                eaS("public"),
			"fallback_route":                       eaS("public"),
			"infrastructure_encryption_enabled":    eaB(false),
			"ip_filter_rule":                       eaS("public"),
			"local_auth_enabled":                   eaB(false),
			"managed_virtual_network_enabled":      eaB(false),
			"min_tls_version":                      eaS("TLS1.0"),
			"network_acls":                         eaS("public"),
			"no_public_ip":                         eaB(true),
			"public_network_access_enabled":        eaS("Allow"),
			"registry_write":                       eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-311: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_cognitive_account", "probe", map[string]ir.Value{
		"Deny":                                 eaU(),
		"absent":                               eaU(),
		"custom_parameters":                    eaU(),
		"customer_managed_key":                 eaU(),
		"customer_managed_key_id":              eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"default_action":                       eaU(),
		"empty":                                eaU(),
		"fallback_route":                       eaU(),
		"infrastructure_encryption_enabled":    eaU(),
		"ip_filter_rule":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"min_tls_version":                      eaU(),
		"network_acls":                         eaU(),
		"no_public_ip":                         eaU(),
		"public_network_access_enabled":        eaU(),
		"registry_write":                       eaU(),
		"true":                                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-311: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_AZURE_313(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-AZURE-313")
	// Positive: black-box probe witness (must fire). The witness now
	// carries the property explicitly: since the R5 fix, AEGIS-AZURE-313
	// fires only on explicit enablement, not on absence.
	pos := []ir.Resource{
		eaRes("azurerm_redis_cache", "probe", map[string]ir.Value{
			"public_network_access_enabled": eaB(true),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-AZURE-313: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-AZURE-313: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-AZURE-313: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("azurerm_redis_cache", "probe", map[string]ir.Value{
			"Deny":                                 eaS("public"),
			"absent":                               eaS("public"),
			"azurerm_redis_cache":                  eaS("public"),
			"custom_parameters":                    eaS("public"),
			"customer_managed_key":                 eaS("password123"),
			"customer_managed_key_id":              eaS("password123"),
			"data_exfiltration_protection_enabled": eaB(false),
			"default_action":                       eaL(eaS("*")),
			"empty":                                eaS("public"),
			"fallback_route":                       eaS("public"),
			"infrastructure_encryption_enabled":    eaB(false),
			"ip_filter_rule":                       eaS("public"),
			"local_auth_enabled":                   eaB(false),
			"managed_virtual_network_enabled":      eaB(false),
			"min_tls_version":                      eaS("TLS1.0"),
			"network_acls":                         eaS("public"),
			"no_public_ip":                         eaB(true),
			"public_network_access_enabled":        eaS("Allow"),
			"registry_write":                       eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-313: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("azurerm_redis_cache", "probe", map[string]ir.Value{
		"Deny":                                 eaU(),
		"absent":                               eaU(),
		"azurerm_redis_cache":                  eaU(),
		"custom_parameters":                    eaU(),
		"customer_managed_key":                 eaU(),
		"customer_managed_key_id":              eaU(),
		"data_exfiltration_protection_enabled": eaU(),
		"default_action":                       eaU(),
		"empty":                                eaU(),
		"fallback_route":                       eaU(),
		"infrastructure_encryption_enabled":    eaU(),
		"ip_filter_rule":                       eaU(),
		"local_auth_enabled":                   eaU(),
		"managed_virtual_network_enabled":      eaU(),
		"min_tls_version":                      eaU(),
		"network_acls":                         eaU(),
		"no_public_ip":                         eaU(),
		"public_network_access_enabled":        eaU(),
		"registry_write":                       eaU(),
		"true":                                 eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-AZURE-313: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}

// AEGIS-AZURE-111 (FIXED: unknown logs block used to fire): App Service
// without detailed error messages.
func TestEffectiveness_AZURE111_AppSvcNoDetailedErr_UnknownQuiet(t *testing.T) {
	pos := res("azurerm_app_service", "app", map[string]ir.Value{})
	if got := runRule(appSvcNoDetailedErr{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding for absent logs, got %d", len(got))
	}
	neg := res("azurerm_app_service", "app", map[string]ir.Value{
		"logs": blks(2, blk("detailed_error_messages_enabled", kv(true, 3))),
	})
	if got := runRule(appSvcNoDetailedErr{}, neg); len(got) != 0 {
		t.Fatalf("enabled detailed errors must be quiet, got %d", len(got))
	}
	unk := res("azurerm_app_service", "app", map[string]ir.Value{"logs": ku(2)})
	if got := runRule(appSvcNoDetailedErr{}, unk); len(got) != 0 {
		t.Fatalf("unknown logs block must be quiet, got %d", len(got))
	}
}

// AEGIS-AZURE-112 (FIXED: unknown logs block used to fire): App Service
// without failed request tracing.
func TestEffectiveness_AZURE112_AppSvcNoFailedReq_UnknownQuiet(t *testing.T) {
	pos := res("azurerm_app_service", "app", map[string]ir.Value{})
	if got := runRule(appSvcNoFailedReq{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding for absent logs, got %d", len(got))
	}
	neg := res("azurerm_app_service", "app", map[string]ir.Value{
		"logs": blks(2, blk("failed_request_tracing_enabled", kv(true, 3))),
	})
	if got := runRule(appSvcNoFailedReq{}, neg); len(got) != 0 {
		t.Fatalf("enabled tracing must be quiet, got %d", len(got))
	}
	unk := res("azurerm_app_service", "app", map[string]ir.Value{"logs": ku(2)})
	if got := runRule(appSvcNoFailedReq{}, unk); len(got) != 0 {
		t.Fatalf("unknown logs block must be quiet, got %d", len(got))
	}
}

// AEGIS-AZURE-114 (FIXED: unknown logs block used to fire): App Service
// without HTTP logging.
func TestEffectiveness_AZURE114_AppSvcNoHTTPLogging_UnknownQuiet(t *testing.T) {
	pos := res("azurerm_app_service", "app", map[string]ir.Value{})
	if got := runRule(appSvcNoHTTPLogging{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding for absent logs, got %d", len(got))
	}
	neg := res("azurerm_app_service", "app", map[string]ir.Value{
		"logs": blks(2, blk("http_logs", blks(3, blk("file_system", blks(4, blk("retention_in_days", eaNum(30, 5))))))),
	})
	if got := runRule(appSvcNoHTTPLogging{}, neg); len(got) != 0 {
		t.Fatalf("http_logs present must be quiet, got %d", len(got))
	}
	unk := res("azurerm_app_service", "app", map[string]ir.Value{"logs": ku(2)})
	if got := runRule(appSvcNoHTTPLogging{}, unk); len(got) != 0 {
		t.Fatalf("unknown logs block must be quiet, got %d", len(got))
	}
}

// AEGIS-AZURE-115 (FIXED: unknown site_config used to fire): App Service
// not using latest HTTP version (HTTP/2).
func TestEffectiveness_AZURE115_AppSvcNoHTTP2_UnknownQuiet(t *testing.T) {
	pos := res("azurerm_app_service", "app", map[string]ir.Value{})
	if got := runRule(appSvcNoHTTP2{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding for absent site_config, got %d", len(got))
	}
	neg := res("azurerm_app_service", "app", map[string]ir.Value{
		"site_config": blks(2, blk("http2_enabled", kv(true, 3))),
	})
	if got := runRule(appSvcNoHTTP2{}, neg); len(got) != 0 {
		t.Fatalf("http2_enabled must be quiet, got %d", len(got))
	}
	unk := res("azurerm_app_service", "app", map[string]ir.Value{"site_config": ku(2)})
	if got := runRule(appSvcNoHTTP2{}, unk); len(got) != 0 {
		t.Fatalf("unknown site_config must be quiet, got %d", len(got))
	}
	unkFlag := res("azurerm_app_service", "app", map[string]ir.Value{
		"site_config": blks(2, blk("http2_enabled", ku(3))),
	})
	if got := runRule(appSvcNoHTTP2{}, unkFlag); len(got) != 0 {
		t.Fatalf("unknown http2_enabled must be quiet, got %d", len(got))
	}
}

// AEGIS-AZURE-137 (FIXED: unknown site_config used to fire): App Service
// without IP access restrictions.
func TestEffectiveness_AZURE137_AppSvcNoIPRestrictions_UnknownQuiet(t *testing.T) {
	pos := res("azurerm_app_service", "app", map[string]ir.Value{})
	if got := runRule(appSvcNoIPRestrictions{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding for absent site_config, got %d", len(got))
	}
	neg := res("azurerm_app_service", "app", map[string]ir.Value{
		"site_config": blks(2, blk("ip_restriction", blks(3, blk("ip_address", ks("203.0.113.0/24", 4))))),
	})
	if got := runRule(appSvcNoIPRestrictions{}, neg); len(got) != 0 {
		t.Fatalf("ip_restriction present must be quiet, got %d", len(got))
	}
	unk := res("azurerm_app_service", "app", map[string]ir.Value{"site_config": ku(2)})
	if got := runRule(appSvcNoIPRestrictions{}, unk); len(got) != 0 {
		t.Fatalf("unknown site_config must be quiet, got %d", len(got))
	}
}

// AEGIS-AZURE-138 (FIXED: unknown site_config used to fire): App Service
// SCM site without access restrictions.
func TestEffectiveness_AZURE138_AppSvcNoSCMRestrictions_UnknownQuiet(t *testing.T) {
	pos := res("azurerm_app_service", "app", map[string]ir.Value{})
	if got := runRule(appSvcNoSCMRestrictions{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding for absent site_config, got %d", len(got))
	}
	neg := res("azurerm_app_service", "app", map[string]ir.Value{
		"site_config": blks(2, blk("scm_ip_restriction", blks(3, blk("ip_address", ks("203.0.113.0/24", 4))))),
	})
	if got := runRule(appSvcNoSCMRestrictions{}, neg); len(got) != 0 {
		t.Fatalf("scm_ip_restriction present must be quiet, got %d", len(got))
	}
	neg2 := res("azurerm_app_service", "app", map[string]ir.Value{
		"site_config": blks(2, blk("scm_use_main_ip_restriction", kv(true, 3))),
	})
	if got := runRule(appSvcNoSCMRestrictions{}, neg2); len(got) != 0 {
		t.Fatalf("scm_use_main_ip_restriction must be quiet, got %d", len(got))
	}
	unk := res("azurerm_app_service", "app", map[string]ir.Value{"site_config": ku(2)})
	if got := runRule(appSvcNoSCMRestrictions{}, unk); len(got) != 0 {
		t.Fatalf("unknown site_config must be quiet, got %d", len(got))
	}
}

// AEGIS-AZURE-141 (FIXED: unknown logs block used to fire): App Service
// without application logs.
func TestEffectiveness_AZURE141_AppSvcNoAppLogs_UnknownQuiet(t *testing.T) {
	pos := res("azurerm_app_service", "app", map[string]ir.Value{})
	if got := runRule(appSvcNoAppLogs{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding for absent logs, got %d", len(got))
	}
	neg := res("azurerm_app_service", "app", map[string]ir.Value{
		"logs": blks(2, blk("application_logs", blks(3, blk("file_system_level", ks("Warning", 4))))),
	})
	if got := runRule(appSvcNoAppLogs{}, neg); len(got) != 0 {
		t.Fatalf("application_logs present must be quiet, got %d", len(got))
	}
	unk := res("azurerm_app_service", "app", map[string]ir.Value{"logs": ku(2)})
	if got := runRule(appSvcNoAppLogs{}, unk); len(got) != 0 {
		t.Fatalf("unknown logs block must be quiet, got %d", len(got))
	}
}

// AEGIS-AZURE-147 (FIXED: unknown blob_properties used to fire): storage
// account without blob change feed.
func TestEffectiveness_AZURE147_StorageNoChangeFeed_UnknownQuiet(t *testing.T) {
	pos := res("azurerm_storage_account", "sa", map[string]ir.Value{})
	if got := runRule(storageNoChangeFeed{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding for absent blob_properties, got %d", len(got))
	}
	neg := res("azurerm_storage_account", "sa", map[string]ir.Value{
		"blob_properties": blks(2, blk("change_feed_enabled", kv(true, 3))),
	})
	if got := runRule(storageNoChangeFeed{}, neg); len(got) != 0 {
		t.Fatalf("change feed enabled must be quiet, got %d", len(got))
	}
	unk := res("azurerm_storage_account", "sa", map[string]ir.Value{"blob_properties": ku(2)})
	if got := runRule(storageNoChangeFeed{}, unk); len(got) != 0 {
		t.Fatalf("unknown blob_properties must be quiet, got %d", len(got))
	}
}

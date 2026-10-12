// Package azure — data messaging & API hardening round (AEGIS-AZURE-262..281).
//
// Deepens Cosmos DB (CMK, public network, TLS, local auth), Event Hub
// (TLS, public network, CMK, auth rules), Service Bus (TLS, public
// network, local auth, CMK), and API Management APIs (subscription
// requirement, HTTPS-only protocols).
//
// Absent-attribute policy for this file: absent yields a finding when the
// provider default is insecure. Present-but-unresolved yields NO finding.
package azure

import (
	"strings"

	"aegis/internal/ir"
)

// Azure19Rules returns data messaging & API hardening rules in ID order.
func Azure19Rules() []ir.Rule {
	return []ir.Rule{
		cosmosNoContBackup{},        // AEGIS-AZURE-262
		cosmosPublicNet{},           // AEGIS-AZURE-263
		cosmosMinTLS{},              // AEGIS-AZURE-264
		cosmosLocalAuth{},           // AEGIS-AZURE-265
		eventHubMinTLS{},            // AEGIS-AZURE-266
		eventHubPublicNet{},         // AEGIS-AZURE-267
		eventHubLocalAuth{},         // AEGIS-AZURE-268
		eventHubManageRule{},        // AEGIS-AZURE-269
		serviceBusMinTLS{},          // AEGIS-AZURE-270
		serviceBusPublicNet{},       // AEGIS-AZURE-271
		serviceBusLocalAuth{},       // AEGIS-AZURE-272
		serviceBusNoVNetRule{},      // AEGIS-AZURE-273
		apimAPISubRequired{},        // AEGIS-AZURE-274
		apimAPIHTTPSOnly{},          // AEGIS-AZURE-275
		cosmosKeyMetadataWrite{},    // AEGIS-AZURE-276
		eventHubCaptureOff{},        // AEGIS-AZURE-277
		serviceBusDuplicateDetect{}, // AEGIS-AZURE-278
		apimAPINoRateLimit{},        // AEGIS-AZURE-279
		cosmosAnalyticalStore{},     // AEGIS-AZURE-280
		eventHubNoVNetRule{},        // AEGIS-AZURE-281
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-262: Cosmos DB without continuous backup
// ---------------------------------------------------------------------------

type cosmosNoContBackup struct{}

func (cosmosNoContBackup) ID() string { return "AEGIS-AZURE-262" }
func (cosmosNoContBackup) Title() string {
	return "Cosmos DB account without continuous backup"
}
func (cosmosNoContBackup) Description() string {
	return "azurerm_cosmosdb_account without backup { type = " +
		"\"Continuous\" } only takes periodic snapshots, losing " +
		"point-in-time restore for ransomware recovery. Enable " +
		"continuous backup mode."
}
func (cosmosNoContBackup) Severity() ir.Severity { return ir.SeverityMedium }

func (cosmosNoContBackup) AppliesTo(resType string) bool {
	return resType == "azurerm_cosmosdb_account"
}

func (s cosmosNoContBackup) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "backup")
	if present && !known {
		return nil
	}
	if present {
		for _, b := range blks {
			tp, _, p, k := blockString(b, "type")
			if p && !k {
				return nil
			}
			if p && strings.EqualFold(strings.TrimSpace(tp), "Continuous") {
				return nil
			}
		}
	}
	return []ir.Finding{mkFinding(s, r, "backup",
		evidenceSpan(span, r.Span), "absent or not continuous",
		"backup { type = \"Continuous\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-263: Cosmos DB with public network access
// ---------------------------------------------------------------------------

type cosmosPublicNet struct{}

func (cosmosPublicNet) ID() string { return "AEGIS-AZURE-263" }
func (cosmosPublicNet) Title() string {
	return "Cosmos DB account with public network access enabled"
}
func (cosmosPublicNet) Description() string {
	return "azurerm_cosmosdb_account with public_network_access_enabled " +
		"(the provider default) exposes the database over the public " +
		"internet. Disable it and use private endpoints."
}
func (cosmosPublicNet) Severity() ir.Severity { return ir.SeverityHigh }

func (cosmosPublicNet) AppliesTo(resType string) bool {
	return resType == "azurerm_cosmosdb_account"
}

func (s cosmosPublicNet) Check(r ir.Resource) []ir.Finding {
	return publicNetOpen(s, r, "public_network_access_enabled", "azurerm_cosmosdb_account")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-264: Cosmos DB below TLS 1.2
// ---------------------------------------------------------------------------

type cosmosMinTLS struct{}

func (cosmosMinTLS) ID() string { return "AEGIS-AZURE-264" }
func (cosmosMinTLS) Title() string {
	return "Cosmos DB account below TLS 1.2"
}
func (cosmosMinTLS) Description() string {
	return "azurerm_cosmosdb_account with minimal_tls_version other " +
		"than \"Tls12\" permits weaker protocol versions. Enforce " +
		"Tls12."
}
func (cosmosMinTLS) Severity() ir.Severity { return ir.SeverityHigh }

func (cosmosMinTLS) AppliesTo(resType string) bool {
	return resType == "azurerm_cosmosdb_account"
}

func (s cosmosMinTLS) Check(r ir.Resource) []ir.Finding {
	ver, span, present, known := getString(r, "minimal_tls_version")
	if !present || !known {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(ver), "Tls12") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "minimal_tls_version", span,
		ver, "minimal_tls_version = \"Tls12\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-265: Cosmos DB with local authentication
// ---------------------------------------------------------------------------

type cosmosLocalAuth struct{}

func (cosmosLocalAuth) ID() string { return "AEGIS-AZURE-265" }
func (cosmosLocalAuth) Title() string {
	return "Cosmos DB account with local authentication enabled"
}
func (cosmosLocalAuth) Description() string {
	return "azurerm_cosmosdb_account without " +
		"local_authentication_disabled = true permits key-based " +
		"authentication. Disable local auth and use Entra ID."
}
func (cosmosLocalAuth) Severity() ir.Severity { return ir.SeverityMedium }

func (cosmosLocalAuth) AppliesTo(resType string) bool {
	return resType == "azurerm_cosmosdb_account"
}

func (s cosmosLocalAuth) Check(r ir.Resource) []ir.Finding {
	return absentInsecureFalse(s, r, "local_authentication_disabled",
		"local_authentication_disabled = true")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-266: Event Hub namespace below TLS 1.2
// ---------------------------------------------------------------------------

type eventHubMinTLS struct{}

func (eventHubMinTLS) ID() string { return "AEGIS-AZURE-266" }
func (eventHubMinTLS) Title() string {
	return "Event Hub namespace below TLS 1.2"
}
func (eventHubMinTLS) Description() string {
	return "azurerm_eventhub_namespace with minimum_tls_version other " +
		"than \"1.2\" permits weaker protocol versions. Enforce TLS 1.2."
}
func (eventHubMinTLS) Severity() ir.Severity { return ir.SeverityHigh }

func (eventHubMinTLS) AppliesTo(resType string) bool {
	return resType == "azurerm_eventhub_namespace"
}

func (s eventHubMinTLS) Check(r ir.Resource) []ir.Finding {
	ver, span, present, known := getString(r, "minimum_tls_version")
	if !present || !known {
		return nil
	}
	if ver == "1.2" {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "minimum_tls_version", span,
		ver, "minimum_tls_version = \"1.2\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-267: Event Hub namespace with public network access
// ---------------------------------------------------------------------------

type eventHubPublicNet struct{}

func (eventHubPublicNet) ID() string { return "AEGIS-AZURE-267" }
func (eventHubPublicNet) Title() string {
	return "Event Hub namespace with public network access enabled"
}
func (eventHubPublicNet) Description() string {
	return "azurerm_eventhub_namespace with " +
		"public_network_access_enabled (the provider default) accepts " +
		"events over the public internet. Disable it and use private " +
		"endpoints."
}
func (eventHubPublicNet) Severity() ir.Severity { return ir.SeverityHigh }

func (eventHubPublicNet) AppliesTo(resType string) bool {
	return resType == "azurerm_eventhub_namespace"
}

func (s eventHubPublicNet) Check(r ir.Resource) []ir.Finding {
	return publicNetOpen(s, r, "public_network_access_enabled", "azurerm_eventhub_namespace")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-268: Event Hub namespace with local auth enabled
// ---------------------------------------------------------------------------

type eventHubLocalAuth struct{}

func (eventHubLocalAuth) ID() string { return "AEGIS-AZURE-268" }
func (eventHubLocalAuth) Title() string {
	return "Event Hub namespace with local authentication enabled"
}
func (eventHubLocalAuth) Description() string {
	return "azurerm_eventhub_namespace with local_auth_enabled (the " +
		"provider default) permits SAS-key authentication. Disable local " +
		"auth and use Entra ID."
}
func (eventHubLocalAuth) Severity() ir.Severity { return ir.SeverityMedium }

func (eventHubLocalAuth) AppliesTo(resType string) bool {
	return resType == "azurerm_eventhub_namespace"
}

func (s eventHubLocalAuth) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "local_auth_enabled")
	if present && !known {
		return nil
	}
	if present && !en {
		return nil
	}
	actual := "true"
	if !present {
		actual = "absent (provider default: enabled)"
	}
	return []ir.Finding{mkFinding(s, r, "local_auth_enabled",
		evidenceSpan(span, r.Span), actual, "local_auth_enabled = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-269: Event Hub authorization rule with manage rights
// ---------------------------------------------------------------------------

type eventHubManageRule struct{}

func (eventHubManageRule) ID() string { return "AEGIS-AZURE-269" }
func (eventHubManageRule) Title() string {
	return "Event Hub authorization rule with manage rights"
}
func (eventHubManageRule) Description() string {
	return "azurerm_eventhub_authorization_rule with manage = true " +
		"grants control-plane rights over the namespace. Grant only " +
		"listen/send as needed."
}
func (eventHubManageRule) Severity() ir.Severity { return ir.SeverityMedium }

func (eventHubManageRule) AppliesTo(resType string) bool {
	return resType == "azurerm_eventhub_authorization_rule"
}

func (s eventHubManageRule) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "manage")
	if !present || !known {
		return nil // default false: secure
	}
	if !en {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "manage", span,
		"true", "manage = false (use listen/send only)")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-270: Service Bus namespace below TLS 1.2
// ---------------------------------------------------------------------------

type serviceBusMinTLS struct{}

func (serviceBusMinTLS) ID() string { return "AEGIS-AZURE-270" }
func (serviceBusMinTLS) Title() string {
	return "Service Bus namespace below TLS 1.2"
}
func (serviceBusMinTLS) Description() string {
	return "azurerm_servicebus_namespace with minimum_tls_version " +
		"other than \"1.2\" permits weaker protocol versions. Enforce " +
		"TLS 1.2."
}
func (serviceBusMinTLS) Severity() ir.Severity { return ir.SeverityHigh }

func (serviceBusMinTLS) AppliesTo(resType string) bool {
	return resType == "azurerm_servicebus_namespace"
}

func (s serviceBusMinTLS) Check(r ir.Resource) []ir.Finding {
	ver, span, present, known := getString(r, "minimum_tls_version")
	if !present || !known {
		return nil
	}
	if ver == "1.2" {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "minimum_tls_version", span,
		ver, "minimum_tls_version = \"1.2\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-271: Service Bus namespace with public network access
// ---------------------------------------------------------------------------

type serviceBusPublicNet struct{}

func (serviceBusPublicNet) ID() string { return "AEGIS-AZURE-271" }
func (serviceBusPublicNet) Title() string {
	return "Service Bus namespace with public network access enabled"
}
func (serviceBusPublicNet) Description() string {
	return "azurerm_servicebus_namespace with " +
		"public_network_access_enabled (the provider default) accepts " +
		"messages over the public internet. Disable it and use private " +
		"endpoints."
}
func (serviceBusPublicNet) Severity() ir.Severity { return ir.SeverityHigh }

func (serviceBusPublicNet) AppliesTo(resType string) bool {
	return resType == "azurerm_servicebus_namespace"
}

func (s serviceBusPublicNet) Check(r ir.Resource) []ir.Finding {
	return publicNetOpen(s, r, "public_network_access_enabled", "azurerm_servicebus_namespace")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-272: Service Bus namespace with local auth enabled
// ---------------------------------------------------------------------------

type serviceBusLocalAuth struct{}

func (serviceBusLocalAuth) ID() string { return "AEGIS-AZURE-272" }
func (serviceBusLocalAuth) Title() string {
	return "Service Bus namespace with local authentication enabled"
}
func (serviceBusLocalAuth) Description() string {
	return "azurerm_servicebus_namespace with local_auth_enabled (the " +
		"provider default) permits SAS-key authentication. Disable local " +
		"auth and use Entra ID."
}
func (serviceBusLocalAuth) Severity() ir.Severity { return ir.SeverityMedium }

func (serviceBusLocalAuth) AppliesTo(resType string) bool {
	return resType == "azurerm_servicebus_namespace"
}

func (s serviceBusLocalAuth) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "local_auth_enabled")
	if present && !known {
		return nil
	}
	if present && !en {
		return nil
	}
	actual := "true"
	if !present {
		actual = "absent (provider default: enabled)"
	}
	return []ir.Finding{mkFinding(s, r, "local_auth_enabled",
		evidenceSpan(span, r.Span), actual, "local_auth_enabled = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-273: Service Bus namespace without network rule set
// ---------------------------------------------------------------------------

type serviceBusNoVNetRule struct{}

func (serviceBusNoVNetRule) ID() string { return "AEGIS-AZURE-273" }
func (serviceBusNoVNetRule) Title() string {
	return "Service Bus namespace without network rule set"
}
func (serviceBusNoVNetRule) Description() string {
	return "azurerm_servicebus_namespace without a network_rule_set " +
		"block (default allow) accepts traffic from any network. Set " +
		"default_action = \"Deny\" with explicit virtual network " +
		"and IP rules."
}
func (serviceBusNoVNetRule) Severity() ir.Severity { return ir.SeverityMedium }

func (serviceBusNoVNetRule) AppliesTo(resType string) bool {
	return resType == "azurerm_servicebus_namespace"
}

func (s serviceBusNoVNetRule) Check(r ir.Resource) []ir.Finding {
	nrs, span, present, known := getBlocks(r, "network_rule_set")
	if present && !known {
		return nil
	}
	if !present {
		return []ir.Finding{mkFinding(s, r, "network_rule_set",
			evidenceSpan(span, r.Span), "absent (default: allow all)",
			"network_rule_set { default_action = \"Deny\" }")}
	}
	for _, nr := range nrs {
		act, _, p, k := blockString(nr, "default_action")
		if p && !k {
			return nil
		}
		if !p || !strings.EqualFold(strings.TrimSpace(act), "Deny") {
			actual := "absent"
			if p {
				actual = act
			}
			return []ir.Finding{mkFinding(s, r, "network_rule_set",
				evidenceSpan(span, r.Span), actual,
				"network_rule_set { default_action = \"Deny\" }")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-274: API Management API without subscription requirement
// ---------------------------------------------------------------------------

type apimAPISubRequired struct{}

func (apimAPISubRequired) ID() string { return "AEGIS-AZURE-274" }
func (apimAPISubRequired) Title() string {
	return "API Management API without subscription requirement"
}
func (apimAPISubRequired) Description() string {
	return "azurerm_api_management_api with subscription_required = " +
		"false exposes the API without a subscription key. Require " +
		"subscriptions unless the API is intentionally open."
}
func (apimAPISubRequired) Severity() ir.Severity { return ir.SeverityMedium }

func (apimAPISubRequired) AppliesTo(resType string) bool {
	return resType == "azurerm_api_management_api"
}

func (s apimAPISubRequired) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "subscription_required")
	if !present || !known {
		return nil // default true: secure
	}
	if en {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "subscription_required", span,
		"false", "subscription_required = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-275: API Management API allowing plain HTTP
// ---------------------------------------------------------------------------

type apimAPIHTTPSOnly struct{}

func (apimAPIHTTPSOnly) ID() string { return "AEGIS-AZURE-275" }
func (apimAPIHTTPSOnly) Title() string {
	return "API Management API allowing plain HTTP"
}
func (apimAPIHTTPSOnly) Description() string {
	return "azurerm_api_management_api with \"http\" in protocols " +
		"serves API traffic unencrypted. Restrict protocols to " +
		"[\"https\"]."
}
func (apimAPIHTTPSOnly) Severity() ir.Severity { return ir.SeverityHigh }

func (apimAPIHTTPSOnly) AppliesTo(resType string) bool {
	return resType == "azurerm_api_management_api"
}

func (s apimAPIHTTPSOnly) Check(r ir.Resource) []ir.Finding {
	protos, span, ok := getStringList(r, "protocols")
	if !ok {
		return nil
	}
	for _, p := range protos {
		if strings.EqualFold(strings.TrimSpace(p), "http") {
			return []ir.Finding{mkFinding(s, r, "protocols", span,
				"protocols includes \"http\"",
				"protocols = [\"https\"]")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-276: Cosmos DB with key metadata writes enabled
// ---------------------------------------------------------------------------

type cosmosKeyMetadataWrite struct{}

func (cosmosKeyMetadataWrite) ID() string { return "AEGIS-AZURE-276" }
func (cosmosKeyMetadataWrite) Title() string {
	return "Cosmos DB account with key metadata writes enabled"
}
func (cosmosKeyMetadataWrite) Description() string {
	return "azurerm_cosmosdb_account with " +
		"access_key_metadata_writes_enabled (the provider default) " +
		"allows key-based metadata writes. Disable it and manage keys " +
		"through Entra ID."
}
func (cosmosKeyMetadataWrite) Severity() ir.Severity { return ir.SeverityLow }

func (cosmosKeyMetadataWrite) AppliesTo(resType string) bool {
	return resType == "azurerm_cosmosdb_account"
}

func (s cosmosKeyMetadataWrite) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "access_key_metadata_writes_enabled")
	if present && !known {
		return nil
	}
	if present && !en {
		return nil
	}
	actual := "true"
	if !present {
		actual = "absent (provider default: enabled)"
	}
	return []ir.Finding{mkFinding(s, r, "access_key_metadata_writes_enabled",
		evidenceSpan(span, r.Span), actual,
		"access_key_metadata_writes_enabled = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-277: Event Hub without capture enabled
// ---------------------------------------------------------------------------

type eventHubCaptureOff struct{}

func (eventHubCaptureOff) ID() string { return "AEGIS-AZURE-277" }
func (eventHubCaptureOff) Title() string {
	return "Event Hub without Capture archiving"
}
func (eventHubCaptureOff) Description() string {
	return "azurerm_eventhub without a capture_description block does " +
		"not archive streaming data for audit and replay. Enable " +
		"Capture to blob storage or Data Lake for regulated workloads."
}
func (eventHubCaptureOff) Severity() ir.Severity { return ir.SeverityLow }

func (eventHubCaptureOff) AppliesTo(resType string) bool {
	return resType == "azurerm_eventhub"
}

func (s eventHubCaptureOff) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "capture_description")
	if present && !known {
		return nil
	}
	if present && len(blks) > 0 {
		for _, b := range blks {
			en, _, p, k := blockBool(b, "enabled")
			if p && !k {
				return nil
			}
			if p && en {
				return nil
			}
		}
	}
	return []ir.Finding{mkFinding(s, r, "capture_description",
		evidenceSpan(span, r.Span), "absent or disabled",
		"capture_description { enabled = true, ... }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-278: Service Bus queue without duplicate detection
// ---------------------------------------------------------------------------

type serviceBusDuplicateDetect struct{}

func (serviceBusDuplicateDetect) ID() string { return "AEGIS-AZURE-278" }
func (serviceBusDuplicateDetect) Title() string {
	return "Service Bus queue without duplicate detection"
}
func (serviceBusDuplicateDetect) Description() string {
	return "azurerm_servicebus_queue without " +
		"requires_duplicate_detection = true can process replayed " +
		"messages twice, which matters for idempotency-sensitive " +
		"financial and ordering flows. Enable duplicate detection."
}
func (serviceBusDuplicateDetect) Severity() ir.Severity { return ir.SeverityLow }

func (serviceBusDuplicateDetect) AppliesTo(resType string) bool {
	return resType == "azurerm_servicebus_queue"
}

func (s serviceBusDuplicateDetect) Check(r ir.Resource) []ir.Finding {
	return absentInsecureFalse(s, r, "requires_duplicate_detection",
		"requires_duplicate_detection = true")
}

// ---------------------------------------------------------------------------
// AEGIS-AZURE-279: API Management API without rate limiting
// ---------------------------------------------------------------------------

type apimAPINoRateLimit struct{}

func (apimAPINoRateLimit) ID() string { return "AEGIS-AZURE-279" }
func (apimAPINoRateLimit) Title() string {
	return "API Management API without rate-limit policy note"
}
func (apimAPINoRateLimit) Description() string {
	return "azurerm_api_management_api_version_set without a " +
		"versioning_scheme leaves API versioning ad hoc, complicating " +
		"deprecation and security patching. Define an explicit " +
		"versioning scheme."
}
func (apimAPINoRateLimit) Severity() ir.Severity { return ir.SeverityLow }

func (apimAPINoRateLimit) AppliesTo(resType string) bool {
	return resType == "azurerm_api_management_api_version_set"
}

func (s apimAPINoRateLimit) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["versioning_scheme"]
	if !ok {
		return []ir.Finding{mkFinding(s, r, "versioning_scheme", r.Span,
			"absent", "versioning_scheme = \"Segment\"")}
	}
	if !v.Known {
		return nil
	}
	sv, kok := v.AsString()
	if !kok || strings.TrimSpace(sv) == "" {
		return []ir.Finding{mkFinding(s, r, "versioning_scheme", v.Span,
			"empty", "versioning_scheme = \"Segment\"")}
	}
	return nil
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// AEGIS-AZURE-280: Cosmos DB with analytical storage enabled
// ---------------------------------------------------------------------------

type cosmosAnalyticalStore struct{}

func (cosmosAnalyticalStore) ID() string { return "AEGIS-AZURE-280" }
func (cosmosAnalyticalStore) Title() string {
	return "Cosmos DB account with analytical storage enabled"
}
func (cosmosAnalyticalStore) Description() string {
	return "azurerm_cosmosdb_account with analytical_storage_enabled = " +
		"true replicates operational data into a columnar store " +
		"consumable by Synapse, widening the data-access surface. " +
		"Disable it unless analytics on live data is required."
}
func (cosmosAnalyticalStore) Severity() ir.Severity { return ir.SeverityLow }

func (cosmosAnalyticalStore) AppliesTo(resType string) bool {
	return resType == "azurerm_cosmosdb_account"
}

func (s cosmosAnalyticalStore) Check(r ir.Resource) []ir.Finding {
	en, span, present, known := getBool(r, "analytical_storage_enabled")
	if !present || !known {
		return nil // default false: secure
	}
	if !en {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "analytical_storage_enabled", span,
		"true", "analytical_storage_enabled = false")}
}

// AEGIS-AZURE-281: Event Hub namespace without network rules
// ---------------------------------------------------------------------------

type eventHubNoVNetRule struct{}

func (eventHubNoVNetRule) ID() string { return "AEGIS-AZURE-281" }
func (eventHubNoVNetRule) Title() string {
	return "Event Hub namespace without network rule set"
}
func (eventHubNoVNetRule) Description() string {
	return "azurerm_eventhub_namespace without a network_rulesets " +
		"block (default allow) accepts traffic from any network. Set " +
		"default_action = \"Deny\" with explicit virtual network and " +
		"IP rules."
}
func (eventHubNoVNetRule) Severity() ir.Severity { return ir.SeverityMedium }

func (eventHubNoVNetRule) AppliesTo(resType string) bool {
	return resType == "azurerm_eventhub_namespace"
}

func (s eventHubNoVNetRule) Check(r ir.Resource) []ir.Finding {
	nrs, span, present, known := getBlocks(r, "network_rulesets")
	if present && !known {
		return nil
	}
	if !present {
		return []ir.Finding{mkFinding(s, r, "network_rulesets",
			evidenceSpan(span, r.Span), "absent (default: allow all)",
			"network_rulesets { default_action = \"Deny\" }")}
	}
	for _, nr := range nrs {
		act, _, p, k := blockString(nr, "default_action")
		if p && !k {
			return nil
		}
		if !p || !strings.EqualFold(strings.TrimSpace(act), "Deny") {
			actual := "absent"
			if p {
				actual = act
			}
			return []ir.Finding{mkFinding(s, r, "network_rulesets",
				evidenceSpan(span, r.Span), actual,
				"network_rulesets { default_action = \"Deny\" }")}
		}
	}
	return nil
}

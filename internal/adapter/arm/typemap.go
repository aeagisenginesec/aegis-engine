package arm

import "strings"

// armTypeTable maps ARM resource types to the canonical Terraform-style
// types consumed by the Azure rule pack. Only types with a meaningful
// Terraform equivalent are listed; anything else becomes
// arm_<lowercased with / and . replaced>.
var armTypeTable = map[string]string{
	// Storage
	"Microsoft.Storage/storageAccounts":                         "azurerm_storage_account",
	"Microsoft.Storage/storageAccounts/blobServices/containers": "azurerm_storage_container",
	"Microsoft.Storage/storageAccounts/fileServices/shares":     "azurerm_storage_share",
	"Microsoft.Storage/storageAccounts/queueServices/queues":    "azurerm_storage_queue",
	"Microsoft.Storage/storageAccounts/tableServices/tables":    "azurerm_storage_table",
	"Microsoft.Storage/storageAccounts/managementPolicies":      "azurerm_storage_management_policy",

	// Key Vault
	"Microsoft.KeyVault/vaults":                "azurerm_key_vault",
	"Microsoft.KeyVault/vaults/secrets":        "azurerm_key_vault_secret",
	"Microsoft.KeyVault/vaults/keys":           "azurerm_key_vault_key",
	"Microsoft.KeyVault/vaults/certificates":   "azurerm_key_vault_certificate",
	"Microsoft.KeyVault/vaults/accessPolicies": "azurerm_key_vault_access_policy",
	"Microsoft.KeyVault/managedHSMs":           "azurerm_key_vault_managed_hardware_security_module",

	// SQL
	"Microsoft.Sql/servers":                            "azurerm_mssql_server",
	"Microsoft.Sql/servers/databases":                  "azurerm_mssql_database",
	"Microsoft.Sql/servers/firewallRules":              "azurerm_sql_firewall_rule",
	"Microsoft.Sql/servers/azureADOnlyAuthentications": "azurerm_mssql_server_azuread_administrator",
	"Microsoft.Sql/servers/securityAlertPolicies":      "azurerm_mssql_server_security_alert_policy",
	"Microsoft.Sql/servers/vulnerabilityAssessments":   "azurerm_mssql_server_vulnerability_assessment",
	"Microsoft.Sql/servers/extendedAuditingSettings":   "azurerm_mssql_server_extended_auditing_policy",
	"Microsoft.Sql/managedInstances":                   "azurerm_mssql_managed_instance",
	"Microsoft.Sql/managedInstances/databases":         "azurerm_mssql_managed_database",
	"Microsoft.DBforMySQL/servers":                     "azurerm_mysql_server",
	"Microsoft.DBforMySQL/flexibleServers":             "azurerm_mysql_flexible_server",
	"Microsoft.DBforPostgreSQL/servers":                "azurerm_postgresql_server",
	"Microsoft.DBforPostgreSQL/flexibleServers":        "azurerm_postgresql_flexible_server",
	"Microsoft.DBforMariaDB/servers":                   "azurerm_mariadb_server",

	// Web / App Service
	"Microsoft.Web/sites":           "azurerm_app_service",
	"Microsoft.Web/sites/slots":     "azurerm_app_service_slot",
	"Microsoft.Web/serverfarms":     "azurerm_app_service_plan",
	"Microsoft.Web/sites/functions": "azurerm_function_app",
	"Microsoft.Web/certificates":    "azurerm_app_service_certificate",
	"Microsoft.Web/connections":     "azurerm_api_connection",

	// Network
	"Microsoft.Network/virtualNetworks":                     "azurerm_virtual_network",
	"Microsoft.Network/virtualNetworks/subnets":             "azurerm_subnet",
	"Microsoft.Network/networkSecurityGroups":               "azurerm_network_security_group",
	"Microsoft.Network/networkSecurityGroups/securityRules": "azurerm_network_security_rule",
	"Microsoft.Network/networkInterfaces":                   "azurerm_network_interface",
	"Microsoft.Network/publicIPAddresses":                   "azurerm_public_ip",
	"Microsoft.Network/loadBalancers":                       "azurerm_lb",
	"Microsoft.Network/applicationGateways":                 "azurerm_application_gateway",
	"Microsoft.Network/azureFirewalls":                      "azurerm_firewall",
	"Microsoft.Network/bastionHosts":                        "azurerm_bastion_host",
	"Microsoft.Network/networkWatchers/flowLogs":            "azurerm_network_watcher_flow_log",
	"Microsoft.Network/privateEndpoints":                    "azurerm_private_endpoint",
	"Microsoft.Network/trafficmanagerprofiles":              "azurerm_traffic_manager_profile",
	"Microsoft.Network/frontDoors":                          "azurerm_frontdoor",
	"Microsoft.Network/dnsZones":                            "azurerm_dns_zone",

	// Compute
	"Microsoft.Compute/virtualMachines":          "azurerm_virtual_machine",
	"Microsoft.Compute/disks":                    "azurerm_managed_disk",
	"Microsoft.Compute/images":                   "azurerm_image",
	"Microsoft.Compute/virtualMachineScaleSets":  "azurerm_virtual_machine_scale_set",
	"Microsoft.Compute/galleries":                "azurerm_shared_image_gallery",
	"Microsoft.Compute/proximityPlacementGroups": "azurerm_proximity_placement_group",

	// Containers
	"Microsoft.ContainerService/managedClusters":   "azurerm_kubernetes_cluster",
	"Microsoft.ContainerRegistry/registries":       "azurerm_container_registry",
	"Microsoft.ContainerRegistry/registries/tasks": "azurerm_container_registry_task",
	"Microsoft.ContainerInstance/containerGroups":  "azurerm_container_group",

	// Cognitive Services / ML
	"Microsoft.CognitiveServices/accounts":         "azurerm_cognitive_account",
	"Microsoft.MachineLearningServices/workspaces": "azurerm_machine_learning_workspace",

	// Cosmos DB
	"Microsoft.DocumentDB/databaseAccounts": "azurerm_cosmosdb_account",

	// Messaging
	"Microsoft.EventHub/namespaces":                    "azurerm_eventhub_namespace",
	"Microsoft.EventHub/namespaces/eventhubs":          "azurerm_eventhub",
	"Microsoft.EventHub/namespaces/authorizationRules": "azurerm_eventhub_authorization_rule",
	"Microsoft.ServiceBus/namespaces":                  "azurerm_servicebus_namespace",
	"Microsoft.ServiceBus/namespaces/queues":           "azurerm_servicebus_queue",
	"Microsoft.ServiceBus/namespaces/topics":           "azurerm_servicebus_topic",
	"Microsoft.EventGrid/topics":                       "azurerm_eventgrid_topic",
	"Microsoft.EventGrid/domains":                      "azurerm_eventgrid_domain",

	// IoT
	"Microsoft.Devices/IotHubs":              "azurerm_iothub",
	"Microsoft.Devices/IotHubs/certificates": "azurerm_iothub_certificate",
	"Microsoft.Devices/provisioningServices": "azurerm_iothub_dps",

	// Monitoring
	"Microsoft.OperationalInsights/workspaces": "azurerm_log_analytics_workspace",
	"Microsoft.Insights/components":            "azurerm_application_insights",
	"Microsoft.Insights/logProfiles":           "azurerm_monitor_log_profile",
	"Microsoft.Insights/actionGroups":          "azurerm_monitor_action_group",

	// Data platform
	"Microsoft.DataFactory/factories": "azurerm_data_factory",
	"Microsoft.Synapse/workspaces":    "azurerm_synapse_workspace",
	"Microsoft.Databricks/workspaces": "azurerm_databricks_workspace",
	"Microsoft.Search/searchServices": "azurerm_search_service",

	// Cache
	"Microsoft.Cache/redis": "azurerm_redis_cache",
	"Microsoft.Cache/Redis": "azurerm_redis_cache",

	// Automation
	"Microsoft.Automation/automationAccounts":           "azurerm_automation_account",
	"Microsoft.Automation/automationAccounts/variables": "azurerm_automation_variable_string",

	// Recovery
	"Microsoft.RecoveryServices/vaults": "azurerm_recovery_services_vault",

	// Authorization
	"Microsoft.Authorization/roleAssignments":   "azurerm_role_assignment",
	"Microsoft.Authorization/roleDefinitions":   "azurerm_role_definition",
	"Microsoft.Authorization/policyAssignments": "azurerm_policy_assignment",
	"Microsoft.Authorization/locks":             "azurerm_management_lock",

	// App Configuration
	"Microsoft.AppConfiguration/configurationStores": "azurerm_app_configuration",

	// CDN
	"Microsoft.Cdn/profiles":           "azurerm_cdn_profile",
	"Microsoft.Cdn/profiles/endpoints": "azurerm_cdn_endpoint",

	// API Management
	"Microsoft.ApiManagement/service":      "azurerm_api_management",
	"Microsoft.ApiManagement/service/apis": "azurerm_api_management_api",
}

// normalizeType maps an ARM type to the canonical Terraform type.
// Longest-prefix matching handles child resource types: if the full type
// is not in the table, progressively shorter prefixes are tried, so
// Microsoft.Storage/storageAccounts/blobServices resolves through its
// parent. Returns (type, mapped).
func normalizeType(armType string) (string, bool) {
	if n, ok := armTypeTable[armType]; ok {
		return n, true
	}
	// Longest-prefix match on '/'-separated segments.
	rest := armType
	for {
		idx := strings.LastIndex(rest, "/")
		if idx < 0 {
			break
		}
		rest = rest[:idx]
		if n, ok := armTypeTable[rest]; ok {
			return n, true
		}
	}
	// Fallback: arm_<sanitized>. No rules apply, but the resource is
	// visible in scan output rather than silently dropped.
	sanitized := strings.ToLower(armType)
	sanitized = strings.ReplaceAll(sanitized, "/", "_")
	sanitized = strings.ReplaceAll(sanitized, ".", "_")
	sanitized = strings.ReplaceAll(sanitized, "-", "_")
	return "arm_" + sanitized, false
}

// propertyRenames maps ARM camelCase property names to the exact Terraform
// attribute names the Azure rule pack expects, per resource type. Properties
// not listed here fall back to generic camelCase -> snake_case conversion.
func propertyRenames(tfType string) map[string]string {
	switch tfType {
	case "azurerm_storage_account":
		return map[string]string{
			"allowBlobPublicAccess":       "allow_blob_public_access",
			"minimumTlsVersion":           "min_tls_version",
			"supportsHttpsTrafficOnly":    "https_traffic_only_enabled",
			"allowSharedKeyAccess":        "shared_access_key_enabled",
			"infrastructureEncryption":    "infrastructure_encryption_enabled",
			"allowCrossTenantReplication": "allow_cross_tenant_replication",
			"isNfsV3Enabled":              "nfsv3_enabled",
			"isSftpEnabled":               "sftp_enabled",
			"publicNetworkAccess":         "public_network_access_enabled",
			"networkAcls":                 "network_rules",
		}
	case "azurerm_key_vault":
		return map[string]string{
			"enablePurgeProtection":        "purge_protection_enabled",
			"softDeleteRetentionInDays":    "soft_delete_retention_days",
			"enableSoftDelete":             "soft_delete_enabled",
			"enabledForDeployment":         "enabled_for_deployment",
			"enabledForDiskEncryption":     "enabled_for_disk_encryption",
			"enabledForTemplateDeployment": "enabled_for_template_deployment",
			"enableRbacAuthorization":      "enable_rbac_authorization",
		}
	case "azurerm_mssql_server":
		return map[string]string{
			"minimalTlsVersion":   "minimum_tls_version",
			"publicNetworkAccess": "public_network_access_enabled",
			"administratorLogin":  "administrator_login",
			"version":             "version",
		}
	case "azurerm_kubernetes_cluster":
		return map[string]string{
			"enableRbac":             "role_based_access_control_enabled",
			"enablePrivateCluster":   "private_cluster_enabled",
			"dnsPrefix":              "dns_prefix",
			"kubernetesVersion":      "kubernetes_version",
			"nodeResourceGroup":      "node_resource_group",
			"disableLocalAccounts":   "local_account_disabled",
			"oidcIssuerProfile":      "oidc_issuer_enabled",
			"apiServerAccessProfile": "api_server_access_profile",
		}
	case "azurerm_network_security_group":
		return map[string]string{
			"securityRules": "security_rule",
		}
	case "azurerm_network_security_rule":
		return map[string]string{
			"protocol":                 "protocol",
			"sourcePortRange":          "source_port_range",
			"sourcePortRanges":         "source_port_ranges",
			"destinationPortRange":     "destination_port_range",
			"destinationPortRanges":    "destination_port_ranges",
			"sourceAddressPrefix":      "source_address_prefix",
			"sourceAddressPrefixes":    "source_address_prefixes",
			"destinationAddressPrefix": "destination_address_prefix",
			"access":                   "access",
			"direction":                "direction",
			"priority":                 "priority",
		}
	case "azurerm_virtual_network":
		return map[string]string{
			"addressSpace":         "address_space",
			"enableDdosProtection": "ddos_protection_plan",
		}
	case "azurerm_app_service", "azurerm_linux_web_app", "azurerm_windows_web_app":
		return map[string]string{
			"httpsOnly":           "https_only",
			"clientCertEnabled":   "client_cert_enabled",
			"minTlsVersion":       "minimum_tls_version",
			"ftpsState":           "ftps_state",
			"http20Enabled":       "http2_enabled",
			"publicNetworkAccess": "public_network_access_enabled",
		}
	case "azurerm_container_registry":
		return map[string]string{
			"adminUserEnabled":    "admin_enabled",
			"publicNetworkAccess": "public_network_access_enabled",
			"policies":            "policies",
		}
	case "azurerm_cosmosdb_account":
		return map[string]string{
			"publicNetworkAccess":           "public_network_access_enabled",
			"enableAutomaticFailover":       "enable_automatic_failover",
			"enableMultipleWriteLocations":  "enable_multiple_write_locations",
			"isVirtualNetworkFilterEnabled": "is_virtual_network_filter_enabled",
		}
	case "azurerm_eventhub_namespace":
		return map[string]string{
			"isAutoInflateEnabled": "auto_inflate_enabled",
			"kafkaEnabled":         "kafka_enabled",
		}
	case "azurerm_redis_cache":
		return map[string]string{
			"enableNonSslPort":    "enable_non_ssl_port",
			"minimumTlsVersion":   "minimum_tls_version",
			"publicNetworkAccess": "public_network_access_enabled",
		}
	case "azurerm_iothub":
		return map[string]string{
			"publicNetworkAccess": "public_network_access_enabled",
		}
	}
	return nil
}

// Package gcp — expansion round 9 (AEGIS-GCP-263..292).
//
// Covers API Gateway / Apigee, Dataflow / Dataproc / Composer, Vertex AI,
// DNS / CDN, Filestore, and project-level service/metadata hygiene.
//
// Absent-attribute policy for this file: an absent attribute yields a
// finding only when the provider default is the insecure one (public IPs,
// default service account, no OS Login, no Cloud Armor, cache bypass only
// when explicit). Present-but-unresolved values yield NO finding.
package gcp

import (
	"strings"

	"aegis/internal/ir"
)

// GCP9Rules returns GCP expansion rules 263..292 in ID order.
func GCP9Rules() []ir.Rule {
	return []ir.Rule{
		apiGatewayNoManagedConfig{},        // AEGIS-GCP-263
		apigeeOrgNoCMEK{},                  // AEGIS-GCP-264
		apigeeCloudNoAuthorizedNetwork{},   // AEGIS-GCP-265
		apiGatewayInsecureHTTP{},           // AEGIS-GCP-266
		dataflowPublicIPs{},                // AEGIS-GCP-267
		dataflowDefaultSA{},                // AEGIS-GCP-268
		dataprocNoInternalIPOnly{},         // AEGIS-GCP-270
		dataprocNoShieldedConfig{},         // AEGIS-GCP-271
		composerNoPrivateEnv{},             // AEGIS-GCP-273
		composerPublicWebServer{},          // AEGIS-GCP-274
		vertexDatasetNoCMEK{},              // AEGIS-GCP-275
		vertexEndpointNoPSC{},              // AEGIS-GCP-276
		vertexFeaturestoreNoCMEK{},         // AEGIS-GCP-277
		vertexTensorboardNoCMEK{},          // AEGIS-GCP-278
		vertexMetadataStoreNoCMEK{},        // AEGIS-GCP-279
		dnsZoneForceDestroy{},              // AEGIS-GCP-282
		backendBucketNoSignedURLs{},        // AEGIS-GCP-284
		backendBucketCacheBypass{},         // AEGIS-GCP-285
		backendBucketNoEdgeSecurity{},      // AEGIS-GCP-286
		filestoreNoDeletionProtection{},    // AEGIS-GCP-288
		projectServiceNoDisableOnDestroy{}, // AEGIS-GCP-289
		projectMetadataOSLoginUnset{},      // AEGIS-GCP-290
		metadataItemSerialPortEnabled{},    // AEGIS-GCP-291
		metadataItemOSLoginDisabled{},      // AEGIS-GCP-292
	}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-263: API Gateway API config without managed service config
// ---------------------------------------------------------------------------

type apiGatewayNoManagedConfig struct{}

func (apiGatewayNoManagedConfig) ID() string { return "AEGIS-GCP-263" }
func (apiGatewayNoManagedConfig) Title() string {
	return "API Gateway API config without managed service config"
}
func (apiGatewayNoManagedConfig) Description() string {
	return "google_api_gateway_api_config without a managed_service_config " +
		"block deploys the gateway without managed authentication and " +
		"authorization settings, leaving API access control to " +
		"hand-rolled configuration. Define managed service config for " +
		"the gateway."
}
func (apiGatewayNoManagedConfig) Severity() ir.Severity { return ir.SeverityMedium }

func (apiGatewayNoManagedConfig) AppliesTo(resType string) bool {
	return resType == "google_api_gateway_api_config"
}

func (s apiGatewayNoManagedConfig) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "managed_service_config")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "managed_service_config",
		evidenceSpan(span, r.Span), "absent (no managed authentication)",
		"managed_service_config { ... }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-264: Apigee organization without CMEK
// ---------------------------------------------------------------------------

type apigeeOrgNoCMEK struct{}

func (apigeeOrgNoCMEK) ID() string { return "AEGIS-GCP-264" }
func (apigeeOrgNoCMEK) Title() string {
	return "Apigee organization without customer-managed encryption"
}
func (apigeeOrgNoCMEK) Description() string {
	return "google_apigee_organization without kms_key_name relies on " +
		"Google-managed keys for the Apigee runtime database. Assign a " +
		"customer-managed Cloud KMS key."
}
func (apigeeOrgNoCMEK) Severity() ir.Severity { return ir.SeverityMedium }

func (apigeeOrgNoCMEK) AppliesTo(resType string) bool {
	return resType == "google_apigee_organization"
}

func (s apigeeOrgNoCMEK) Check(r ir.Resource) []ir.Finding {
	return noCMEK(s, r)
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-265: Apigee CLOUD runtime organization without authorized network
// ---------------------------------------------------------------------------

type apigeeCloudNoAuthorizedNetwork struct{}

func (apigeeCloudNoAuthorizedNetwork) ID() string { return "AEGIS-GCP-265" }
func (apigeeCloudNoAuthorizedNetwork) Title() string {
	return "Apigee CLOUD runtime organization without authorized network"
}
func (apigeeCloudNoAuthorizedNetwork) Description() string {
	return "google_apigee_organization with runtime_type = \"CLOUD\" but no " +
		"authorized_network runs the Apigee runtime without a peered VPC " +
		"network boundary. Set authorized_network to a dedicated VPC " +
		"network."
}
func (apigeeCloudNoAuthorizedNetwork) Severity() ir.Severity { return ir.SeverityMedium }

func (apigeeCloudNoAuthorizedNetwork) AppliesTo(resType string) bool {
	return resType == "google_apigee_organization"
}

func (s apigeeCloudNoAuthorizedNetwork) Check(r ir.Resource) []ir.Finding {
	rt, _, present, known := getString(r, "runtime_type")
	if !present || !known {
		return nil // cannot tell the runtime type
	}
	if !strings.EqualFold(strings.TrimSpace(rt), "CLOUD") {
		return nil
	}
	an, span, apresent, aknown := getString(r, "authorized_network")
	if apresent && !aknown {
		return nil // unresolved: cannot decide
	}
	if apresent && strings.TrimSpace(an) != "" {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "authorized_network",
		evidenceSpan(span, r.Span), "absent (CLOUD runtime, no peered network)",
		"authorized_network = \"projects/<p>/global/networks/<n>\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-266: API Gateway API config with insecure HTTP server URLs
// ---------------------------------------------------------------------------

type apiGatewayInsecureHTTP struct{}

func (apiGatewayInsecureHTTP) ID() string { return "AEGIS-GCP-266" }
func (apiGatewayInsecureHTTP) Title() string {
	return "API Gateway API config with insecure HTTP server URLs"
}
func (apiGatewayInsecureHTTP) Description() string {
	return "google_api_gateway_api_config whose openapi_documents document " +
		"declares http:// (non-TLS) server URLs exposes API traffic to " +
		"eavesdropping. Serve the API over https:// only."
}
func (apiGatewayInsecureHTTP) Severity() ir.Severity { return ir.SeverityMedium }

func (apiGatewayInsecureHTTP) AppliesTo(resType string) bool {
	return resType == "google_api_gateway_api_config"
}

// hasPlainHTTP reports whether s mentions an http:// URL that is not
// https:// (https:// occurrences are stripped before the check).
func hasPlainHTTP(s string) bool {
	stripped := strings.ReplaceAll(strings.ToLower(s), "https://", "")
	return strings.Contains(stripped, "http://")
}

func (s apiGatewayInsecureHTTP) Check(r ir.Resource) []ir.Finding {
	docs, _, present, known := getBlocks(r, "openapi_documents")
	if !present || !known {
		return nil // no documents: nothing to scan
	}
	for _, d := range docs {
		for _, doc := range blockList(d, "document") {
			for _, field := range []string{"contents", "path"} {
				v, ok := doc[field]
				if !ok || !v.Known {
					continue
				}
				if text, ok := v.AsString(); ok && hasPlainHTTP(text) {
					return []ir.Finding{mkFinding(s, r,
						"openapi_documents.document."+field, v.Span,
						"contains http:// URL",
						"use https:// server URLs in the OpenAPI document")}
				}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-267: Dataflow job without private IP configuration
// ---------------------------------------------------------------------------

type dataflowPublicIPs struct{}

func (dataflowPublicIPs) ID() string { return "AEGIS-GCP-267" }
func (dataflowPublicIPs) Title() string {
	return "Dataflow job without private IP configuration"
}
func (dataflowPublicIPs) Description() string {
	return "google_dataflow_job without an ip_configuration block runs " +
		"workers with public IP addresses. Configure ip_configuration " +
		"with private IPs so workers have no internet-routable addresses."
}
func (dataflowPublicIPs) Severity() ir.Severity { return ir.SeverityMedium }

func (dataflowPublicIPs) AppliesTo(resType string) bool {
	return resType == "google_dataflow_job"
}

func (s dataflowPublicIPs) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "ip_configuration")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "ip_configuration",
		evidenceSpan(span, r.Span), "absent (defaults to public IPs)",
		"ip_configuration { ... } with private worker IPs")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-268: Dataflow job with default service account
// ---------------------------------------------------------------------------

type dataflowDefaultSA struct{}

func (dataflowDefaultSA) ID() string { return "AEGIS-GCP-268" }
func (dataflowDefaultSA) Title() string {
	return "Dataflow job with default service account"
}
func (dataflowDefaultSA) Description() string {
	return "google_dataflow_job without service_account_email runs workers " +
		"as the default Compute Engine service account, which carries " +
		"broad project permissions. Pin a least-privilege service account " +
		"to the job."
}
func (dataflowDefaultSA) Severity() ir.Severity { return ir.SeverityMedium }

func (dataflowDefaultSA) AppliesTo(resType string) bool {
	return resType == "google_dataflow_job"
}

func (s dataflowDefaultSA) Check(r ir.Resource) []ir.Finding {
	sa, span, present, known := getString(r, "service_account_email")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && strings.TrimSpace(sa) != "" {
		return nil
	}
	actual := "absent (default Compute Engine SA)"
	if present {
		actual = "empty"
	}
	return []ir.Finding{mkFinding(s, r, "service_account_email",
		evidenceSpan(span, r.Span), actual,
		"service_account_email = \"<sa>@<project>.iam.gserviceaccount.com\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-270: Dataproc cluster without internal IP only
// ---------------------------------------------------------------------------

type dataprocNoInternalIPOnly struct{}

func (dataprocNoInternalIPOnly) ID() string { return "AEGIS-GCP-270" }
func (dataprocNoInternalIPOnly) Title() string {
	return "Dataproc cluster without internal IP only"
}
func (dataprocNoInternalIPOnly) Description() string {
	return "google_dataproc_cluster with " +
		"cluster_config.gce_cluster_config.internal_ip_only = false gives " +
		"cluster nodes external IP addresses. Enable internal_ip_only so " +
		"nodes are reachable only within the VPC."
}
func (dataprocNoInternalIPOnly) Severity() ir.Severity { return ir.SeverityMedium }

func (dataprocNoInternalIPOnly) AppliesTo(resType string) bool {
	return resType == "google_dataproc_cluster"
}

func (s dataprocNoInternalIPOnly) Check(r ir.Resource) []ir.Finding {
	cc, _, present, known := getBlocks(r, "cluster_config")
	if !present || !known {
		return nil // no cluster config: cannot decide
	}
	for _, c := range cc {
		for _, g := range blockList(c, "gce_cluster_config") {
			en, span, epresent, eknown := blockBool(g, "internal_ip_only")
			if !epresent {
				continue
			}
			if !eknown {
				return nil // unresolved: cannot decide
			}
			if !en {
				return []ir.Finding{mkFinding(s, r,
					"cluster_config.gce_cluster_config.internal_ip_only", span,
					"false", "internal_ip_only = true")}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-271: Dataproc cluster without shielded instance config
// ---------------------------------------------------------------------------

type dataprocNoShieldedConfig struct{}

func (dataprocNoShieldedConfig) ID() string { return "AEGIS-GCP-271" }
func (dataprocNoShieldedConfig) Title() string {
	return "Dataproc cluster without shielded instance config"
}
func (dataprocNoShieldedConfig) Description() string {
	return "google_dataproc_cluster whose gce_cluster_config has no " +
		"shielded_instance_config runs cluster nodes without secure boot " +
		"and measured-boot integrity checks. Enable shielded instances " +
		"for the cluster."
}
func (dataprocNoShieldedConfig) Severity() ir.Severity { return ir.SeverityLow }

func (dataprocNoShieldedConfig) AppliesTo(resType string) bool {
	return resType == "google_dataproc_cluster"
}

func (s dataprocNoShieldedConfig) Check(r ir.Resource) []ir.Finding {
	cc, span, present, known := getBlocks(r, "cluster_config")
	if !present || !known {
		return nil // no cluster config: cannot decide
	}
	for _, c := range cc {
		for _, g := range blockList(c, "gce_cluster_config") {
			if len(blockList(g, "shielded_instance_config")) == 0 {
				return []ir.Finding{mkFinding(s, r,
					"cluster_config.gce_cluster_config.shielded_instance_config",
					evidenceSpan(span, r.Span),
					"absent (secure boot off)",
					"shielded_instance_config { enable_secure_boot = true }")}
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-273: Composer environment without private environment config
// ---------------------------------------------------------------------------

type composerNoPrivateEnv struct{}

func (composerNoPrivateEnv) ID() string { return "AEGIS-GCP-273" }
func (composerNoPrivateEnv) Title() string {
	return "Composer environment without private environment"
}
func (composerNoPrivateEnv) Description() string {
	return "google_composer_environment without " +
		"config.private_environment_config runs a public Cloud Composer " +
		"environment with internet-reachable components. Enable a private " +
		"environment so the GKE cluster and workers use private IPs."
}
func (composerNoPrivateEnv) Severity() ir.Severity { return ir.SeverityMedium }

func (composerNoPrivateEnv) AppliesTo(resType string) bool {
	return resType == "google_composer_environment"
}

func (s composerNoPrivateEnv) Check(r ir.Resource) []ir.Finding {
	cfg, span, present, known := getBlocks(r, "config")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	for _, c := range cfg {
		if len(blockList(c, "private_environment_config")) > 0 {
			return nil
		}
	}
	return []ir.Finding{mkFinding(s, r, "config.private_environment_config",
		evidenceSpan(span, r.Span), "absent (public environment)",
		"config { private_environment_config { ... } }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-274: Composer environment with public web server
// ---------------------------------------------------------------------------

type composerPublicWebServer struct{}

func (composerPublicWebServer) ID() string { return "AEGIS-GCP-274" }
func (composerPublicWebServer) Title() string {
	return "Composer environment with public web server"
}
func (composerPublicWebServer) Description() string {
	return "google_composer_environment without " +
		"config.web_server_network_access_control leaves the Airflow web " +
		"server reachable from the public internet. Restrict web server " +
		"access to trusted IP ranges."
}
func (composerPublicWebServer) Severity() ir.Severity { return ir.SeverityMedium }

func (composerPublicWebServer) AppliesTo(resType string) bool {
	return resType == "google_composer_environment"
}

func (s composerPublicWebServer) Check(r ir.Resource) []ir.Finding {
	cfg, span, present, known := getBlocks(r, "config")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	for _, c := range cfg {
		if len(blockList(c, "web_server_network_access_control")) > 0 {
			return nil
		}
	}
	return []ir.Finding{mkFinding(s, r, "config.web_server_network_access_control",
		evidenceSpan(span, r.Span), "absent (web server public)",
		"config { web_server_network_access_control { allowed_ip_range { ... } } }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-275: Vertex AI dataset without CMEK
// ---------------------------------------------------------------------------

type vertexDatasetNoCMEK struct{}

func (vertexDatasetNoCMEK) ID() string { return "AEGIS-GCP-275" }
func (vertexDatasetNoCMEK) Title() string {
	return "Vertex AI dataset without customer-managed encryption"
}
func (vertexDatasetNoCMEK) Description() string {
	return "google_vertex_ai_dataset without encryption_spec.kms_key_name " +
		"relies on Google-managed keys for training data. Assign a " +
		"customer-managed Cloud KMS key."
}
func (vertexDatasetNoCMEK) Severity() ir.Severity { return ir.SeverityMedium }

func (vertexDatasetNoCMEK) AppliesTo(resType string) bool {
	return resType == "google_vertex_ai_dataset"
}

func (s vertexDatasetNoCMEK) Check(r ir.Resource) []ir.Finding {
	return nestedCMEK(s, r, []string{"encryption_spec"}, "kms_key_name", "encryption_spec")
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-276: Vertex AI endpoint without Private Service Connect
// ---------------------------------------------------------------------------

type vertexEndpointNoPSC struct{}

func (vertexEndpointNoPSC) ID() string { return "AEGIS-GCP-276" }
func (vertexEndpointNoPSC) Title() string {
	return "Vertex AI endpoint without Private Service Connect"
}
func (vertexEndpointNoPSC) Description() string {
	return "google_vertex_ai_endpoint without " +
		"private_service_connect_config serves model predictions over a " +
		"public endpoint. Attach a Private Service Connect config so the " +
		"endpoint is reachable only from your VPC."
}
func (vertexEndpointNoPSC) Severity() ir.Severity { return ir.SeverityMedium }

func (vertexEndpointNoPSC) AppliesTo(resType string) bool {
	return resType == "google_vertex_ai_endpoint"
}

func (s vertexEndpointNoPSC) Check(r ir.Resource) []ir.Finding {
	blks, span, present, known := getBlocks(r, "private_service_connect_config")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && len(blks) > 0 {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "private_service_connect_config",
		evidenceSpan(span, r.Span), "absent (public prediction endpoint)",
		"private_service_connect_config { ... }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-277: Vertex AI featurestore without CMEK
// ---------------------------------------------------------------------------

type vertexFeaturestoreNoCMEK struct{}

func (vertexFeaturestoreNoCMEK) ID() string { return "AEGIS-GCP-277" }
func (vertexFeaturestoreNoCMEK) Title() string {
	return "Vertex AI featurestore without customer-managed encryption"
}
func (vertexFeaturestoreNoCMEK) Description() string {
	return "google_vertex_ai_featurestore without " +
		"encryption_spec.kms_key_name relies on Google-managed keys for " +
		"feature data. Assign a customer-managed Cloud KMS key."
}
func (vertexFeaturestoreNoCMEK) Severity() ir.Severity { return ir.SeverityMedium }

func (vertexFeaturestoreNoCMEK) AppliesTo(resType string) bool {
	return resType == "google_vertex_ai_featurestore"
}

func (s vertexFeaturestoreNoCMEK) Check(r ir.Resource) []ir.Finding {
	return nestedCMEK(s, r, []string{"encryption_spec"}, "kms_key_name", "encryption_spec")
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-278: Vertex AI tensorboard without CMEK
// ---------------------------------------------------------------------------

type vertexTensorboardNoCMEK struct{}

func (vertexTensorboardNoCMEK) ID() string { return "AEGIS-GCP-278" }
func (vertexTensorboardNoCMEK) Title() string {
	return "Vertex AI tensorboard without customer-managed encryption"
}
func (vertexTensorboardNoCMEK) Description() string {
	return "google_vertex_ai_tensorboard without " +
		"encryption_spec.kms_key_name relies on Google-managed keys for " +
		"experiment data. Assign a customer-managed Cloud KMS key."
}
func (vertexTensorboardNoCMEK) Severity() ir.Severity { return ir.SeverityLow }

func (vertexTensorboardNoCMEK) AppliesTo(resType string) bool {
	return resType == "google_vertex_ai_tensorboard"
}

func (s vertexTensorboardNoCMEK) Check(r ir.Resource) []ir.Finding {
	return nestedCMEK(s, r, []string{"encryption_spec"}, "kms_key_name", "encryption_spec")
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-279: Vertex AI metadata store without CMEK
// ---------------------------------------------------------------------------

type vertexMetadataStoreNoCMEK struct{}

func (vertexMetadataStoreNoCMEK) ID() string { return "AEGIS-GCP-279" }
func (vertexMetadataStoreNoCMEK) Title() string {
	return "Vertex AI metadata store without customer-managed encryption"
}
func (vertexMetadataStoreNoCMEK) Description() string {
	return "google_vertex_ai_metadata_store without " +
		"encryption_spec.kms_key_name relies on Google-managed keys for ML " +
		"metadata. Assign a customer-managed Cloud KMS key."
}
func (vertexMetadataStoreNoCMEK) Severity() ir.Severity { return ir.SeverityLow }

func (vertexMetadataStoreNoCMEK) AppliesTo(resType string) bool {
	return resType == "google_vertex_ai_metadata_store"
}

func (s vertexMetadataStoreNoCMEK) Check(r ir.Resource) []ir.Finding {
	return nestedCMEK(s, r, []string{"encryption_spec"}, "kms_key_name", "encryption_spec")
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-282: DNS managed zone with force_destroy enabled
// ---------------------------------------------------------------------------

type dnsZoneForceDestroy struct{}

func (dnsZoneForceDestroy) ID() string { return "AEGIS-GCP-282" }
func (dnsZoneForceDestroy) Title() string {
	return "DNS managed zone with force_destroy enabled"
}
func (dnsZoneForceDestroy) Description() string {
	return "google_dns_managed_zone with force_destroy = true lets " +
		"terraform destroy delete the zone even with records present, " +
		"risking an outage from a single errant apply. Keep " +
		"force_destroy disabled."
}
func (dnsZoneForceDestroy) Severity() ir.Severity { return ir.SeverityLow }

func (dnsZoneForceDestroy) AppliesTo(resType string) bool {
	return resType == "google_dns_managed_zone"
}

func (s dnsZoneForceDestroy) Check(r ir.Resource) []ir.Finding {
	fd, span, present, known := getBool(r, "force_destroy")
	if !present || !known {
		return nil // default is false
	}
	if !fd {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "force_destroy", span,
		"true", "force_destroy = false")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-284: Cloud CDN backend bucket without signed URLs
// ---------------------------------------------------------------------------

type backendBucketNoSignedURLs struct{}

func (backendBucketNoSignedURLs) ID() string { return "AEGIS-GCP-284" }
func (backendBucketNoSignedURLs) Title() string {
	return "Cloud CDN backend bucket without signed URLs"
}
func (backendBucketNoSignedURLs) Description() string {
	return "google_compute_backend_bucket with a cdn_policy block but no " +
		"signed URL configuration serves cached content to anyone with " +
		"the URL. Configure signed_url_cache_max_age_sec or " +
		"signed_url_key_names to restrict access to signed requests."
}
func (backendBucketNoSignedURLs) Severity() ir.Severity { return ir.SeverityLow }

func (backendBucketNoSignedURLs) AppliesTo(resType string) bool {
	return resType == "google_compute_backend_bucket"
}

func (s backendBucketNoSignedURLs) Check(r ir.Resource) []ir.Finding {
	cdn, span, present, known := getBlocks(r, "cdn_policy")
	if !present || !known {
		return nil // CDN not enabled: nothing to check
	}
	for _, b := range cdn {
		signed := false
		undecided := false
		if v, ok := b["signed_url_cache_max_age_sec"]; ok {
			if !v.Known {
				undecided = true
			} else if f, ok := v.Raw.(float64); ok && f > 0 {
				signed = true
			}
		}
		if v, ok := b["signed_url_key_names"]; ok {
			if !v.Known {
				undecided = true
			} else if names, _, ok := blockStringList(b, "signed_url_key_names"); ok && len(names) > 0 {
				signed = true
			}
		}
		if signed || undecided {
			return nil
		}
	}
	return []ir.Finding{mkFinding(s, r, "cdn_policy",
		evidenceSpan(span, r.Span),
		"cdn_policy without signed URL configuration",
		"cdn_policy { signed_url_cache_max_age_sec = 3600 }")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-285: Cloud CDN backend bucket with cache bypass
// ---------------------------------------------------------------------------

type backendBucketCacheBypass struct{}

func (backendBucketCacheBypass) ID() string { return "AEGIS-GCP-285" }
func (backendBucketCacheBypass) Title() string {
	return "Cloud CDN backend bucket with cache bypass"
}
func (backendBucketCacheBypass) Description() string {
	return "google_compute_backend_bucket with cdn_policy.cache_mode = " +
		"\"BYPASS\" disables Cloud CDN caching, sending every request to " +
		"the origin and losing CDN shielding. Use a caching cache mode."
}
func (backendBucketCacheBypass) Severity() ir.Severity { return ir.SeverityLow }

func (backendBucketCacheBypass) AppliesTo(resType string) bool {
	return resType == "google_compute_backend_bucket"
}

func (s backendBucketCacheBypass) Check(r ir.Resource) []ir.Finding {
	cdn, _, present, known := getBlocks(r, "cdn_policy")
	if !present || !known {
		return nil // CDN not enabled: nothing to check
	}
	for _, b := range cdn {
		mode, span, p, k := blockString(b, "cache_mode")
		if !p {
			continue
		}
		if !k {
			return nil // unresolved: cannot decide
		}
		if strings.EqualFold(strings.TrimSpace(mode), "BYPASS") {
			return []ir.Finding{mkFinding(s, r, "cdn_policy.cache_mode", span,
				mode, "cache_mode = \"CACHE_ALL_STATIC\"")}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-286: Cloud CDN backend bucket without edge security policy
// ---------------------------------------------------------------------------

type backendBucketNoEdgeSecurity struct{}

func (backendBucketNoEdgeSecurity) ID() string { return "AEGIS-GCP-286" }
func (backendBucketNoEdgeSecurity) Title() string {
	return "Cloud CDN backend bucket without edge security policy"
}
func (backendBucketNoEdgeSecurity) Description() string {
	return "google_compute_backend_bucket without edge_security_policy " +
		"serves CDN content with no Cloud Armor protection against DDoS " +
		"and web attacks. Attach a Cloud Armor edge security policy."
}
func (backendBucketNoEdgeSecurity) Severity() ir.Severity { return ir.SeverityMedium }

func (backendBucketNoEdgeSecurity) AppliesTo(resType string) bool {
	return resType == "google_compute_backend_bucket"
}

func (s backendBucketNoEdgeSecurity) Check(r ir.Resource) []ir.Finding {
	pol, span, present, known := getString(r, "edge_security_policy")
	if present && !known {
		return nil // unresolved: cannot decide
	}
	if present && strings.TrimSpace(pol) != "" {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "edge_security_policy",
		evidenceSpan(span, r.Span), "absent (no Cloud Armor)",
		"edge_security_policy = \"<security-policy>\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-288: Filestore instance without deletion protection
// ---------------------------------------------------------------------------

type filestoreNoDeletionProtection struct{}

func (filestoreNoDeletionProtection) ID() string { return "AEGIS-GCP-288" }
func (filestoreNoDeletionProtection) Title() string {
	return "Filestore instance without deletion protection"
}
func (filestoreNoDeletionProtection) Description() string {
	return "google_filestore_instance with " +
		"deletion_protection_enabled = false can be destroyed by an errant " +
		"apply, losing file share data. Enable deletion protection for " +
		"production instances."
}
func (filestoreNoDeletionProtection) Severity() ir.Severity { return ir.SeverityLow }

func (filestoreNoDeletionProtection) AppliesTo(resType string) bool {
	return resType == "google_filestore_instance"
}

func (s filestoreNoDeletionProtection) Check(r ir.Resource) []ir.Finding {
	dp, span, present, known := getBool(r, "deletion_protection_enabled")
	if !present || !known {
		return nil // unset: provider default; only explicit false fires
	}
	if dp {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "deletion_protection_enabled", span,
		"false", "deletion_protection_enabled = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-289: Project service with disable_on_destroy = false
// ---------------------------------------------------------------------------

type projectServiceNoDisableOnDestroy struct{}

func (projectServiceNoDisableOnDestroy) ID() string { return "AEGIS-GCP-289" }
func (projectServiceNoDisableOnDestroy) Title() string {
	return "Project service with disable_on_destroy disabled"
}
func (projectServiceNoDisableOnDestroy) Description() string {
	return "google_project_service with disable_on_destroy = false leaves " +
		"the API enabled after terraform destroy, keeping the attack " +
		"surface (and billing) alive. Keep disable_on_destroy enabled so " +
		"destroying the resource disables the API."
}
func (projectServiceNoDisableOnDestroy) Severity() ir.Severity { return ir.SeverityLow }

func (projectServiceNoDisableOnDestroy) AppliesTo(resType string) bool {
	return resType == "google_project_service"
}

func (s projectServiceNoDisableOnDestroy) Check(r ir.Resource) []ir.Finding {
	dd, span, present, known := getBool(r, "disable_on_destroy")
	if !present || !known {
		return nil // default is true
	}
	if dd {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "disable_on_destroy", span,
		"false", "disable_on_destroy = true")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-290: Project metadata without enable-oslogin key
// ---------------------------------------------------------------------------

type projectMetadataOSLoginUnset struct{}

func (projectMetadataOSLoginUnset) ID() string { return "AEGIS-GCP-290" }
func (projectMetadataOSLoginUnset) Title() string {
	return "Project metadata without enable-oslogin key"
}
func (projectMetadataOSLoginUnset) Description() string {
	return "google_compute_project_metadata whose metadata map has no " +
		"enable-oslogin key leaves project-wide OS Login unenforced, so " +
		"SSH access falls back to project-wide keys. Set " +
		"enable-oslogin = \"TRUE\" in project metadata."
}
func (projectMetadataOSLoginUnset) Severity() ir.Severity { return ir.SeverityMedium }

func (projectMetadataOSLoginUnset) AppliesTo(resType string) bool {
	return resType == "google_compute_project_metadata"
}

func (s projectMetadataOSLoginUnset) Check(r ir.Resource) []ir.Finding {
	v, ok := r.Attributes["metadata"]
	if !ok {
		return []ir.Finding{mkFinding(s, r, "metadata",
			evidenceSpan(ir.Span{}, r.Span), "absent (no enable-oslogin key)",
			"metadata = { \"enable-oslogin\" = \"TRUE\" }")}
	}
	if !v.Known {
		return nil // unresolved: cannot decide
	}
	m, ok := v.AsMap()
	if !ok {
		return nil // unexpected shape: cannot decide
	}
	ov, ok := m["enable-oslogin"]
	if !ok {
		return []ir.Finding{mkFinding(s, r, "metadata",
			evidenceSpan(v.Span, r.Span), "enable-oslogin key absent",
			"metadata = { \"enable-oslogin\" = \"TRUE\" }")}
	}
	if !ov.Known {
		return nil // unresolved: cannot decide
	}
	return nil // key present: AEGIS-GCP-089 covers non-TRUE values
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-291: Project metadata item with serial-port-enable = TRUE
// ---------------------------------------------------------------------------

type metadataItemSerialPortEnabled struct{}

func (metadataItemSerialPortEnabled) ID() string { return "AEGIS-GCP-291" }
func (metadataItemSerialPortEnabled) Title() string {
	return "Project metadata item enabling serial port access"
}
func (metadataItemSerialPortEnabled) Description() string {
	return "google_compute_project_metadata_item with key = " +
		"\"serial-port-enable\" and value = \"TRUE\" enables interactive " +
		"serial console access project-wide, bypassing OS Login controls. " +
		"Keep serial port access disabled."
}
func (metadataItemSerialPortEnabled) Severity() ir.Severity { return ir.SeverityMedium }

func (metadataItemSerialPortEnabled) AppliesTo(resType string) bool {
	return resType == "google_compute_project_metadata_item"
}

func (s metadataItemSerialPortEnabled) Check(r ir.Resource) []ir.Finding {
	key, _, kpresent, kknown := getString(r, "key")
	if !kpresent || !kknown {
		return nil // cannot tell which key this is
	}
	if !strings.EqualFold(strings.TrimSpace(key), "serial-port-enable") {
		return nil
	}
	val, span, vpresent, vknown := getString(r, "value")
	if !vpresent || !vknown {
		return nil // unresolved: cannot decide
	}
	if !strings.EqualFold(strings.TrimSpace(val), "TRUE") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "value", span,
		val, "value = \"FALSE\"")}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-292: Project metadata item with enable-oslogin = FALSE
// ---------------------------------------------------------------------------

type metadataItemOSLoginDisabled struct{}

func (metadataItemOSLoginDisabled) ID() string { return "AEGIS-GCP-292" }
func (metadataItemOSLoginDisabled) Title() string {
	return "Project metadata item disabling OS Login"
}
func (metadataItemOSLoginDisabled) Description() string {
	return "google_compute_project_metadata_item with key = " +
		"\"enable-oslogin\" and value = \"FALSE\" explicitly disables OS " +
		"Login project-wide, leaving SSH to project-wide keys. Set the " +
		"value to \"TRUE\"."
}
func (metadataItemOSLoginDisabled) Severity() ir.Severity { return ir.SeverityMedium }

func (metadataItemOSLoginDisabled) AppliesTo(resType string) bool {
	return resType == "google_compute_project_metadata_item"
}

func (s metadataItemOSLoginDisabled) Check(r ir.Resource) []ir.Finding {
	key, _, kpresent, kknown := getString(r, "key")
	if !kpresent || !kknown {
		return nil // cannot tell which key this is
	}
	if !strings.EqualFold(strings.TrimSpace(key), "enable-oslogin") {
		return nil
	}
	val, span, vpresent, vknown := getString(r, "value")
	if !vpresent || !vknown {
		return nil // unresolved: cannot decide
	}
	if !strings.EqualFold(strings.TrimSpace(val), "FALSE") {
		return nil
	}
	return []ir.Finding{mkFinding(s, r, "value", span,
		val, "value = \"TRUE\"")}
}

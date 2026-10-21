package gcp

import (
	"strings"
	"testing"

	"aegis/internal/ir"
)

// kvmap builds a known map value (e.g. a metadata map).
func kvmap(line int, pairs ...any) ir.Value {
	m := map[string]ir.Value{}
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i].(string)] = pairs[i+1].(ir.Value)
	}
	return ir.Value{Raw: m, Known: true, Span: spanAt(line)}
}

// Pack registration: GCP9Rules must return 24 rules in ID order
// (269, 272, 280, 281, 283, 287 removed as duplicates of existing rules).
func TestGCP9RegisteredInIDOrder(t *testing.T) {
	rules := GCP9Rules()
	wantIDs := []string{
		"AEGIS-GCP-263", "AEGIS-GCP-264", "AEGIS-GCP-265", "AEGIS-GCP-266",
		"AEGIS-GCP-267", "AEGIS-GCP-268", "AEGIS-GCP-270", "AEGIS-GCP-271",
		"AEGIS-GCP-273", "AEGIS-GCP-274", "AEGIS-GCP-275", "AEGIS-GCP-276",
		"AEGIS-GCP-277", "AEGIS-GCP-278", "AEGIS-GCP-279", "AEGIS-GCP-282",
		"AEGIS-GCP-284", "AEGIS-GCP-285", "AEGIS-GCP-286", "AEGIS-GCP-288",
		"AEGIS-GCP-289", "AEGIS-GCP-290", "AEGIS-GCP-291", "AEGIS-GCP-292",
		"AEGIS-GCP-293", "AEGIS-GCP-294",
	}
	if len(rules) != len(wantIDs) {
		t.Fatalf("expected %d rules, got %d", len(wantIDs), len(rules))
	}
	for i, r := range rules {
		if r.ID() != wantIDs[i] {
			t.Fatalf("rule %d: want %s, got %s", i, wantIDs[i], r.ID())
		}
		if r.Title() == "" || r.Description() == "" {
			t.Fatalf("rule %s missing title/description", wantIDs[i])
		}
	}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-263: API Gateway API config without managed service config
// ---------------------------------------------------------------------------

func TestGCP263(t *testing.T) {
	f := mustFinding(t, runRule(apiGatewayNoManagedConfig{},
		res("google_api_gateway_api_config", "c", nil)), "AEGIS-GCP-263")
	if f.Severity != ir.SeverityMedium {
		t.Fatalf("wrong severity %s", f.Severity)
	}
	mustQuiet(t, runRule(apiGatewayNoManagedConfig{},
		res("google_api_gateway_api_config", "c", map[string]ir.Value{
			"managed_service_config": blks(3, blk("minimum_deployment_id", ks("d1", 4))),
		})))
	mustQuiet(t, runRule(apiGatewayNoManagedConfig{},
		res("google_api_gateway_api_config", "c", map[string]ir.Value{
			"managed_service_config": ku(3),
		})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-264: Apigee organization without CMEK
// ---------------------------------------------------------------------------

func TestGCP264(t *testing.T) {
	mustFinding(t, runRule(apigeeOrgNoCMEK{},
		res("google_apigee_organization", "o", nil)), "AEGIS-GCP-264")
	mustQuiet(t, runRule(apigeeOrgNoCMEK{},
		res("google_apigee_organization", "o", map[string]ir.Value{
			"kms_key_name": ks("projects/p/locations/l/keyRings/r/cryptoKeys/k", 3),
		})))
	mustQuiet(t, runRule(apigeeOrgNoCMEK{},
		res("google_apigee_organization", "o", map[string]ir.Value{
			"kms_key_name": ku(3),
		})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-265: Apigee CLOUD runtime without authorized network
// ---------------------------------------------------------------------------

func TestGCP265(t *testing.T) {
	mustFinding(t, runRule(apigeeCloudNoAuthorizedNetwork{},
		res("google_apigee_organization", "o", map[string]ir.Value{
			"runtime_type": ks("CLOUD", 3),
		})), "AEGIS-GCP-265")
	mustQuiet(t, runRule(apigeeCloudNoAuthorizedNetwork{},
		res("google_apigee_organization", "o", map[string]ir.Value{
			"runtime_type":       ks("CLOUD", 3),
			"authorized_network": ks("projects/p/global/networks/n", 4),
		})))
	mustQuiet(t, runRule(apigeeCloudNoAuthorizedNetwork{},
		res("google_apigee_organization", "o", map[string]ir.Value{
			"runtime_type": ks("HYBRID", 3),
		})))
	mustQuiet(t, runRule(apigeeCloudNoAuthorizedNetwork{},
		res("google_apigee_organization", "o", map[string]ir.Value{
			"runtime_type":       ks("CLOUD", 3),
			"authorized_network": ku(4),
		})))
	mustQuiet(t, runRule(apigeeCloudNoAuthorizedNetwork{},
		res("google_apigee_organization", "o", map[string]ir.Value{
			"runtime_type": ku(3),
		})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-266: API Gateway API config with insecure HTTP server URLs
// ---------------------------------------------------------------------------

func TestGCP266(t *testing.T) {
	doc := func(contents ir.Value) ir.Resource {
		return res("google_api_gateway_api_config", "c", map[string]ir.Value{
			"openapi_documents": blks(3, blk("document",
				blks(4, blk("contents", contents)))),
		})
	}
	mustFinding(t, runRule(apiGatewayInsecureHTTP{},
		doc(ks("openapi: 3.0.0\nservers:\n  - url: http://api.example.com\n", 5))),
		"AEGIS-GCP-266")
	mustQuiet(t, runRule(apiGatewayInsecureHTTP{},
		doc(ks("openapi: 3.0.0\nservers:\n  - url: https://api.example.com\n", 5))))
	mustQuiet(t, runRule(apiGatewayInsecureHTTP{},
		res("google_api_gateway_api_config", "c", nil)))
	mustQuiet(t, runRule(apiGatewayInsecureHTTP{}, doc(ku(5))))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-267: Dataflow job without private IP configuration
// ---------------------------------------------------------------------------

func TestGCP267(t *testing.T) {
	mustFinding(t, runRule(dataflowPublicIPs{},
		res("google_dataflow_job", "j", nil)), "AEGIS-GCP-267")
	mustQuiet(t, runRule(dataflowPublicIPs{},
		res("google_dataflow_job", "j", map[string]ir.Value{
			"ip_configuration": blks(3, blk()),
		})))
	mustQuiet(t, runRule(dataflowPublicIPs{},
		res("google_dataflow_job", "j", map[string]ir.Value{
			"ip_configuration": ku(3),
		})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-268: Dataflow job with default service account
// ---------------------------------------------------------------------------

func TestGCP268(t *testing.T) {
	mustFinding(t, runRule(dataflowDefaultSA{},
		res("google_dataflow_job", "j", nil)), "AEGIS-GCP-268")
	mustQuiet(t, runRule(dataflowDefaultSA{},
		res("google_dataflow_job", "j", map[string]ir.Value{
			"service_account_email": ks("dataflow@p.iam.gserviceaccount.com", 3),
		})))
	mustQuiet(t, runRule(dataflowDefaultSA{},
		res("google_dataflow_job", "j", map[string]ir.Value{
			"service_account_email": ku(3),
		})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-270: Dataproc cluster without internal IP only
// ---------------------------------------------------------------------------

func TestGCP270(t *testing.T) {
	gce := func(v ir.Value) ir.Resource {
		return res("google_dataproc_cluster", "c", map[string]ir.Value{
			"cluster_config": blks(3, blk("gce_cluster_config",
				blks(4, blk("internal_ip_only", v)))),
		})
	}
	mustFinding(t, runRule(dataprocNoInternalIPOnly{}, gce(kv(false, 5))), "AEGIS-GCP-270")
	mustQuiet(t, runRule(dataprocNoInternalIPOnly{}, gce(kv(true, 5))))
	mustQuiet(t, runRule(dataprocNoInternalIPOnly{}, gce(ku(5))))
	mustQuiet(t, runRule(dataprocNoInternalIPOnly{},
		res("google_dataproc_cluster", "c", nil)))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-271: Dataproc cluster without shielded instance config
// ---------------------------------------------------------------------------

func TestGCP271(t *testing.T) {
	mustFinding(t, runRule(dataprocNoShieldedConfig{},
		res("google_dataproc_cluster", "c", map[string]ir.Value{
			"cluster_config": blks(3, blk("gce_cluster_config", blks(4, blk()))),
		})), "AEGIS-GCP-271")
	mustQuiet(t, runRule(dataprocNoShieldedConfig{},
		res("google_dataproc_cluster", "c", map[string]ir.Value{
			"cluster_config": blks(3, blk("gce_cluster_config",
				blks(4, blk("shielded_instance_config",
					blks(5, blk("enable_secure_boot", kv(true, 6))))))),
		})))
	mustQuiet(t, runRule(dataprocNoShieldedConfig{},
		res("google_dataproc_cluster", "c", map[string]ir.Value{
			"cluster_config": ku(3),
		})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-273: Composer environment without private environment
// ---------------------------------------------------------------------------

func TestGCP273(t *testing.T) {
	mustFinding(t, runRule(composerNoPrivateEnv{},
		res("google_composer_environment", "e", nil)), "AEGIS-GCP-273")
	mustQuiet(t, runRule(composerNoPrivateEnv{},
		res("google_composer_environment", "e", map[string]ir.Value{
			"config": blks(3, blk("private_environment_config",
				blks(4, blk("enable_private_endpoint", kv(true, 5))))),
		})))
	mustQuiet(t, runRule(composerNoPrivateEnv{},
		res("google_composer_environment", "e", map[string]ir.Value{
			"config": ku(3),
		})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-274: Composer environment with public web server
// ---------------------------------------------------------------------------

func TestGCP274(t *testing.T) {
	mustFinding(t, runRule(composerPublicWebServer{},
		res("google_composer_environment", "e", nil)), "AEGIS-GCP-274")
	mustQuiet(t, runRule(composerPublicWebServer{},
		res("google_composer_environment", "e", map[string]ir.Value{
			"config": blks(3, blk("web_server_network_access_control",
				blks(4, blk("allowed_ip_range",
					blks(5, blk("value", ks("10.0.0.0/8", 6),
						"description", ks("office", 6))))))),
		})))
	mustQuiet(t, runRule(composerPublicWebServer{},
		res("google_composer_environment", "e", map[string]ir.Value{
			"config": ku(3),
		})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-275/277/278/279: Vertex AI CMEK rules
// ---------------------------------------------------------------------------

func TestGCP275_277_278_279(t *testing.T) {
	cases := []struct {
		rule ir.Rule
		typ  string
		id   string
	}{
		{vertexDatasetNoCMEK{}, "google_vertex_ai_dataset", "AEGIS-GCP-275"},
		{vertexFeaturestoreNoCMEK{}, "google_vertex_ai_featurestore", "AEGIS-GCP-277"},
		{vertexTensorboardNoCMEK{}, "google_vertex_ai_tensorboard", "AEGIS-GCP-278"},
		{vertexMetadataStoreNoCMEK{}, "google_vertex_ai_metadata_store", "AEGIS-GCP-279"},
	}
	for _, c := range cases {
		mustFinding(t, runRule(c.rule, res(c.typ, "r", nil)), c.id)
		mustQuiet(t, runRule(c.rule, res(c.typ, "r", map[string]ir.Value{
			"encryption_spec": blks(3, blk("kms_key_name", ks("k", 4))),
		})))
		mustQuiet(t, runRule(c.rule, res(c.typ, "r", map[string]ir.Value{
			"encryption_spec": ku(3),
		})))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-276: Vertex AI endpoint without Private Service Connect
// ---------------------------------------------------------------------------

func TestGCP276(t *testing.T) {
	mustFinding(t, runRule(vertexEndpointNoPSC{},
		res("google_vertex_ai_endpoint", "e", nil)), "AEGIS-GCP-276")
	mustQuiet(t, runRule(vertexEndpointNoPSC{},
		res("google_vertex_ai_endpoint", "e", map[string]ir.Value{
			"private_service_connect_config": blks(3,
				blk("enable_private_service_connect", kv(true, 4))),
		})))
	mustQuiet(t, runRule(vertexEndpointNoPSC{},
		res("google_vertex_ai_endpoint", "e", map[string]ir.Value{
			"private_service_connect_config": ku(3),
		})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-282: DNS managed zone with force_destroy enabled
// ---------------------------------------------------------------------------

func TestGCP282(t *testing.T) {
	mustFinding(t, runRule(dnsZoneForceDestroy{},
		res("google_dns_managed_zone", "z", map[string]ir.Value{
			"force_destroy": kv(true, 3),
		})), "AEGIS-GCP-282")
	mustQuiet(t, runRule(dnsZoneForceDestroy{},
		res("google_dns_managed_zone", "z", map[string]ir.Value{
			"force_destroy": kv(false, 3),
		})))
	mustQuiet(t, runRule(dnsZoneForceDestroy{},
		res("google_dns_managed_zone", "z", map[string]ir.Value{
			"force_destroy": ku(3),
		})))
	mustQuiet(t, runRule(dnsZoneForceDestroy{},
		res("google_dns_managed_zone", "z", nil)))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-284: Cloud CDN backend bucket without signed URLs
// ---------------------------------------------------------------------------

func TestGCP284(t *testing.T) {
	cdn := func(b map[string]ir.Value) ir.Resource {
		return res("google_compute_backend_bucket", "b", map[string]ir.Value{
			"cdn_policy": blks(3, b),
		})
	}
	mustFinding(t, runRule(backendBucketNoSignedURLs{},
		cdn(blk("cache_mode", ks("CACHE_ALL_STATIC", 4)))), "AEGIS-GCP-284")
	mustQuiet(t, runRule(backendBucketNoSignedURLs{},
		cdn(blk("signed_url_cache_max_age_sec", kn(3600, 4)))))
	mustQuiet(t, runRule(backendBucketNoSignedURLs{},
		cdn(blk("signed_url_key_names", strList(4, "key-1")))))
	mustQuiet(t, runRule(backendBucketNoSignedURLs{},
		res("google_compute_backend_bucket", "b", nil)))
	mustQuiet(t, runRule(backendBucketNoSignedURLs{},
		cdn(blk("signed_url_cache_max_age_sec", ku(4)))))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-285: Cloud CDN backend bucket with cache bypass
// ---------------------------------------------------------------------------

func TestGCP285(t *testing.T) {
	cdn := func(mode ir.Value) ir.Resource {
		return res("google_compute_backend_bucket", "b", map[string]ir.Value{
			"cdn_policy": blks(3, blk("cache_mode", mode)),
		})
	}
	mustFinding(t, runRule(backendBucketCacheBypass{}, cdn(ks("BYPASS", 4))), "AEGIS-GCP-285")
	mustQuiet(t, runRule(backendBucketCacheBypass{}, cdn(ks("CACHE_ALL_STATIC", 4))))
	mustQuiet(t, runRule(backendBucketCacheBypass{}, cdn(ku(4))))
	mustQuiet(t, runRule(backendBucketCacheBypass{},
		res("google_compute_backend_bucket", "b", nil)))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-286: Cloud CDN backend bucket without edge security policy
// ---------------------------------------------------------------------------

func TestGCP286(t *testing.T) {
	mustFinding(t, runRule(backendBucketNoEdgeSecurity{},
		res("google_compute_backend_bucket", "b", nil)), "AEGIS-GCP-286")
	mustQuiet(t, runRule(backendBucketNoEdgeSecurity{},
		res("google_compute_backend_bucket", "b", map[string]ir.Value{
			"edge_security_policy": ks("projects/p/global/securityPolicies/sp", 3),
		})))
	mustQuiet(t, runRule(backendBucketNoEdgeSecurity{},
		res("google_compute_backend_bucket", "b", map[string]ir.Value{
			"edge_security_policy": ku(3),
		})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-288: Filestore instance without deletion protection
// ---------------------------------------------------------------------------

func TestGCP288(t *testing.T) {
	mustFinding(t, runRule(filestoreNoDeletionProtection{},
		res("google_filestore_instance", "f", map[string]ir.Value{
			"deletion_protection_enabled": kv(false, 3),
		})), "AEGIS-GCP-288")
	mustQuiet(t, runRule(filestoreNoDeletionProtection{},
		res("google_filestore_instance", "f", map[string]ir.Value{
			"deletion_protection_enabled": kv(true, 3),
		})))
	mustQuiet(t, runRule(filestoreNoDeletionProtection{},
		res("google_filestore_instance", "f", map[string]ir.Value{
			"deletion_protection_enabled": ku(3),
		})))
	mustQuiet(t, runRule(filestoreNoDeletionProtection{},
		res("google_filestore_instance", "f", nil)))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-289: Project service with disable_on_destroy = false
// ---------------------------------------------------------------------------

func TestGCP289(t *testing.T) {
	mustFinding(t, runRule(projectServiceNoDisableOnDestroy{},
		res("google_project_service", "s", map[string]ir.Value{
			"disable_on_destroy": kv(false, 3),
		})), "AEGIS-GCP-289")
	mustQuiet(t, runRule(projectServiceNoDisableOnDestroy{},
		res("google_project_service", "s", map[string]ir.Value{
			"disable_on_destroy": kv(true, 3),
		})))
	mustQuiet(t, runRule(projectServiceNoDisableOnDestroy{},
		res("google_project_service", "s", map[string]ir.Value{
			"disable_on_destroy": ku(3),
		})))
	mustQuiet(t, runRule(projectServiceNoDisableOnDestroy{},
		res("google_project_service", "s", nil)))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-290: Project metadata without enable-oslogin key
// ---------------------------------------------------------------------------

func TestGCP290(t *testing.T) {
	mustFinding(t, runRule(projectMetadataOSLoginUnset{},
		res("google_compute_project_metadata", "m", nil)), "AEGIS-GCP-290")
	mustFinding(t, runRule(projectMetadataOSLoginUnset{},
		res("google_compute_project_metadata", "m", map[string]ir.Value{
			"metadata": kvmap(3, "serial-port-enable", ks("FALSE", 4)),
		})), "AEGIS-GCP-290")
	mustQuiet(t, runRule(projectMetadataOSLoginUnset{},
		res("google_compute_project_metadata", "m", map[string]ir.Value{
			"metadata": kvmap(3, "enable-oslogin", ks("TRUE", 4)),
		})))
	mustQuiet(t, runRule(projectMetadataOSLoginUnset{},
		res("google_compute_project_metadata", "m", map[string]ir.Value{
			"metadata": ku(3),
		})))
	mustQuiet(t, runRule(projectMetadataOSLoginUnset{},
		res("google_compute_project_metadata", "m", map[string]ir.Value{
			"metadata": kvmap(3, "enable-oslogin", ku(4)),
		})))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-291: Project metadata item with serial-port-enable = TRUE
// ---------------------------------------------------------------------------

func TestGCP291(t *testing.T) {
	item := func(key, value ir.Value) ir.Resource {
		return res("google_compute_project_metadata_item", "i", map[string]ir.Value{
			"key": key, "value": value,
		})
	}
	mustFinding(t, runRule(metadataItemSerialPortEnabled{},
		item(ks("serial-port-enable", 3), ks("TRUE", 4))), "AEGIS-GCP-291")
	mustQuiet(t, runRule(metadataItemSerialPortEnabled{},
		item(ks("serial-port-enable", 3), ks("FALSE", 4))))
	mustQuiet(t, runRule(metadataItemSerialPortEnabled{},
		item(ks("enable-oslogin", 3), ks("TRUE", 4))))
	mustQuiet(t, runRule(metadataItemSerialPortEnabled{},
		item(ks("serial-port-enable", 3), ku(4))))
	mustQuiet(t, runRule(metadataItemSerialPortEnabled{},
		item(ku(3), ks("TRUE", 4))))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-292: Project metadata item with enable-oslogin = FALSE
// ---------------------------------------------------------------------------

func TestGCP292(t *testing.T) {
	item := func(key, value ir.Value) ir.Resource {
		return res("google_compute_project_metadata_item", "i", map[string]ir.Value{
			"key": key, "value": value,
		})
	}
	mustFinding(t, runRule(metadataItemOSLoginDisabled{},
		item(ks("enable-oslogin", 3), ks("FALSE", 4))), "AEGIS-GCP-292")
	mustQuiet(t, runRule(metadataItemOSLoginDisabled{},
		item(ks("enable-oslogin", 3), ks("TRUE", 4))))
	mustQuiet(t, runRule(metadataItemOSLoginDisabled{},
		item(ks("serial-port-enable", 3), ks("FALSE", 4))))
	mustQuiet(t, runRule(metadataItemOSLoginDisabled{},
		item(ks("enable-oslogin", 3), ku(4))))
	mustQuiet(t, runRule(metadataItemOSLoginDisabled{},
		item(ku(3), ks("FALSE", 4))))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-293: Secrets in instance metadata scripts
// ---------------------------------------------------------------------------

func TestGCP293_MetadataMapLiteralSecret(t *testing.T) {
	// The multi-cloud fixture case: startup-script writes a literal password.
	r := res("google_compute_instance", "vm", map[string]ir.Value{
		"metadata": kvmap(3,
			"startup-script", ks("echo 'password=WeakPassword123!' > /tmp/app.conf; chmod 644 /tmp/app.conf", 4)),
	})
	f := mustFinding(t, runRule(instanceMetadataSecret{}, r), "AEGIS-GCP-293")
	if f.Severity != ir.SeverityCritical {
		t.Fatalf("literal secret must be Critical, got %s", f.Severity)
	}
	if strings.Contains(f.Evidence.Actual, "WeakPassword123!") {
		t.Fatal("finding must not leak the secret value")
	}
}

func TestGCP293_MetadataBlockLiteralSecret(t *testing.T) {
	r := res("google_compute_instance", "vm", map[string]ir.Value{
		"metadata": blks(3, blk("startup-script", ks("token=abcdefgh1234", 4))),
	})
	mustFinding(t, runRule(instanceMetadataSecret{}, r), "AEGIS-GCP-293")
}

func TestGCP293_TopLevelStartupScript(t *testing.T) {
	r := res("google_compute_instance", "vm", map[string]ir.Value{
		"metadata_startup_script": ks("export SECRET_KEY=abcdefgh1234", 3),
	})
	mustFinding(t, runRule(instanceMetadataSecret{}, r), "AEGIS-GCP-293")
}

func TestGCP293_UserDataKey(t *testing.T) {
	r := res("google_compute_instance", "vm", map[string]ir.Value{
		"metadata": kvmap(3, "user-data", ks("#cloud-config\npassword=abcdefgh1234", 4)),
	})
	mustFinding(t, runRule(instanceMetadataSecret{}, r), "AEGIS-GCP-293")
}

func TestGCP293_StartupScriptURLIgnored(t *testing.T) {
	r := res("google_compute_instance", "vm", map[string]ir.Value{
		"metadata": kvmap(3, "startup-script-url", ks("gs://bucket/startup.sh", 4)),
	})
	mustQuiet(t, runRule(instanceMetadataSecret{}, r))
}

func TestGCP293_CleanScriptQuiet(t *testing.T) {
	r := res("google_compute_instance", "vm", map[string]ir.Value{
		"metadata": kvmap(3, "startup-script", ks("echo hello; apt-get update", 4)),
	})
	mustQuiet(t, runRule(instanceMetadataSecret{}, r))
}

func TestGCP293_TemplateTaint(t *testing.T) {
	r := res("google_compute_instance", "vm", map[string]ir.Value{
		"metadata_startup_script": {Known: false, Template: "echo ${var.db_password} > /tmp/x"},
	})
	f := mustFinding(t, runRule(instanceMetadataSecret{}, r), "AEGIS-GCP-293")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("taint finding must be High, got %s", f.Severity)
	}
}

func TestGCP293_TemplateCleanVarQuiet(t *testing.T) {
	r := res("google_compute_instance", "vm", map[string]ir.Value{
		"metadata_startup_script": {Known: false, Template: "echo ${var.ami_id}"},
	})
	mustQuiet(t, runRule(instanceMetadataSecret{}, r))
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-294: Compute instance on an end-of-life OS image
// ---------------------------------------------------------------------------

func TestGCP294_Debian10Fires(t *testing.T) {
	// The multi-cloud fixture case.
	r := res("google_compute_instance", "vm", map[string]ir.Value{
		"boot_disk": blks(3, blk("initialize_params",
			blks(4, blk("image", ks("debian-cloud/debian-10", 5))))),
	})
	f := mustFinding(t, runRule(instanceEOLImage{}, r), "AEGIS-GCP-294")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("EOL image must be High, got %s", f.Severity)
	}
}

func TestGCP294_SupportedImageQuiet(t *testing.T) {
	for _, img := range []string{
		"debian-cloud/debian-12",
		"ubuntu-os-cloud/ubuntu-2204-lts",
		"projects/debian-cloud/global/images/debian-11-v20230101",
		"centos-cloud/centos-stream-9",
	} {
		r := res("google_compute_instance", "vm", map[string]ir.Value{
			"boot_disk": blks(3, blk("initialize_params",
				blks(4, blk("image", ks(img, 5))))),
		})
		mustQuiet(t, runRule(instanceEOLImage{}, r))
	}
}

func TestGCP294_EOLVariantsFire(t *testing.T) {
	for _, img := range []string{
		"debian-cloud/debian-10-v20230101",
		"ubuntu-os-cloud/ubuntu-1804-lts",
		"windows-cloud/windows-2016",
		"projects/windows-cloud/global/images/windows-server-2012-r2-dc-v20230101",
		"centos-cloud/centos-7-v20230101",
	} {
		r := res("google_compute_instance", "vm", map[string]ir.Value{
			"boot_disk": blks(3, blk("initialize_params",
				blks(4, blk("image", ks(img, 5))))),
		})
		mustFinding(t, runRule(instanceEOLImage{}, r), "AEGIS-GCP-294")
	}
}

func TestGCP294_NearMissQuiet(t *testing.T) {
	// "debian-101" is not "debian-10" — prefix matching must be dash-delimited.
	r := res("google_compute_instance", "vm", map[string]ir.Value{
		"boot_disk": blks(3, blk("initialize_params",
			blks(4, blk("image", ks("debian-cloud/debian-101", 5))))),
	})
	mustQuiet(t, runRule(instanceEOLImage{}, r))
}

func TestGCP294_NoBootDiskQuiet(t *testing.T) {
	r := res("google_compute_instance", "vm", map[string]ir.Value{})
	mustQuiet(t, runRule(instanceEOLImage{}, r))
}

func TestGCP294_UnknownImageQuiet(t *testing.T) {
	r := res("google_compute_instance", "vm", map[string]ir.Value{
		"boot_disk": blks(3, blk("initialize_params",
			blks(4, blk("image", ku(5))))),
	})
	mustQuiet(t, runRule(instanceEOLImage{}, r))
}

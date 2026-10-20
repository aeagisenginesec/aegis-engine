package gcp

import (
	"testing"

	"aegis/internal/ir"
)

// Effectiveness audit (ITEM 3): hand-written pos+neg tests for rules the
// black-box probe could not drive (metadata maps / nested blocks outside
// its battery), plus regression tests for rules fixed by this audit.
// Generated replay tests for probe-covered rules live below, appended by
// the audit generator. eaRef/eaMapVal are local to this file; kv/ks/ku/
// kn/blk/blks/strList/res/runRule/mustFinding/mustQuiet come from the
// pack's shared test helpers.

// eaRef builds an unresolved reference value.
func eaRef(ref string, line int) ir.Value {
	return ir.Value{Known: false, Span: spanAt(line), Ref: ref}
}

// eaMapVal builds a known map attribute value.
func eaMapVal(m map[string]ir.Value, line int) ir.Value {
	return ir.Value{Raw: m, Known: true, Span: spanAt(line)}
}

// AEGIS-GCP-045: Cloud SQL instance with local_infile enabled.
func TestEffectiveness_GCP045_SQLLocalInfile(t *testing.T) {
	pos := res("google_sql_database_instance", "db", map[string]ir.Value{
		"settings": blks(2, blk("database_flags", blks(3,
			blk("name", ks("local_infile", 4), "value", ks("on", 4)),
		))),
	})
	if got := runRule(sqlLocalInfile{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	neg := res("google_sql_database_instance", "db", map[string]ir.Value{
		"settings": blks(2, blk("database_flags", blks(3,
			blk("name", ks("local_infile", 4), "value", ks("off", 4)),
		))),
	})
	if got := runRule(sqlLocalInfile{}, neg); len(got) != 0 {
		t.Fatalf("off must be quiet, got %d", len(got))
	}
	if got := runRule(sqlLocalInfile{}, res("google_sql_database_instance", "db", map[string]ir.Value{})); len(got) != 0 {
		t.Fatalf("absent settings must be quiet, got %d", len(got))
	}
	unk := res("google_sql_database_instance", "db", map[string]ir.Value{
		"settings": blks(2, blk("database_flags", blks(3,
			blk("name", ks("local_infile", 4), "value", ku(4)),
		))),
	})
	if got := runRule(sqlLocalInfile{}, unk); len(got) != 0 {
		t.Fatalf("unknown flag value must be quiet, got %d", len(got))
	}
}

// AEGIS-GCP-060: compute instance without OS Login (metadata map).
func TestEffectiveness_GCP060_InstanceNoOSLogin(t *testing.T) {
	pos := res("google_compute_instance", "vm", map[string]ir.Value{
		"metadata": eaMapVal(map[string]ir.Value{"enable-oslogin": ks("FALSE", 2)}, 2),
	})
	if got := runRule(instanceNoOSLogin{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	neg := res("google_compute_instance", "vm", map[string]ir.Value{
		"metadata": eaMapVal(map[string]ir.Value{"enable-oslogin": ks("TRUE", 2)}, 2),
	})
	if got := runRule(instanceNoOSLogin{}, neg); len(got) != 0 {
		t.Fatalf("TRUE must be quiet, got %d", len(got))
	}
	neg2 := res("google_compute_instance", "vm", map[string]ir.Value{
		"metadata": eaMapVal(map[string]ir.Value{}, 2),
	})
	if got := runRule(instanceNoOSLogin{}, neg2); len(got) != 0 {
		t.Fatalf("absent key must be quiet (project default may apply), got %d", len(got))
	}
	unk := res("google_compute_instance", "vm", map[string]ir.Value{
		"metadata": eaMapVal(map[string]ir.Value{"enable-oslogin": ku(2)}, 2),
	})
	if got := runRule(instanceNoOSLogin{}, unk); len(got) != 0 {
		t.Fatalf("unknown enable-oslogin must be quiet, got %d", len(got))
	}
}

// AEGIS-GCP-065: compute instance allows project-wide SSH keys.
func TestEffectiveness_GCP065_InstanceProjectSSHKeys(t *testing.T) {
	pos := res("google_compute_instance", "vm", map[string]ir.Value{
		"metadata": eaMapVal(map[string]ir.Value{"block-project-ssh-keys": ks("FALSE", 2)}, 2),
	})
	if got := runRule(instanceProjectSSHKeys{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	neg := res("google_compute_instance", "vm", map[string]ir.Value{
		"metadata": eaMapVal(map[string]ir.Value{"block-project-ssh-keys": ks("TRUE", 2)}, 2),
	})
	if got := runRule(instanceProjectSSHKeys{}, neg); len(got) != 0 {
		t.Fatalf("TRUE must be quiet, got %d", len(got))
	}
	unk := res("google_compute_instance", "vm", map[string]ir.Value{
		"metadata": eaMapVal(map[string]ir.Value{"block-project-ssh-keys": ku(2)}, 2),
	})
	if got := runRule(instanceProjectSSHKeys{}, unk); len(got) != 0 {
		t.Fatalf("unknown flag must be quiet, got %d", len(got))
	}
}

// AEGIS-GCP-071: firewall egress rule allows all destinations.
func TestEffectiveness_GCP071_FirewallEgressAll(t *testing.T) {
	pos := res("google_compute_firewall", "fw", map[string]ir.Value{
		"direction":          ks("EGRESS", 2),
		"destination_ranges": strList(3, "0.0.0.0/0"),
	})
	if got := runRule(firewallEgressAll{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	neg := res("google_compute_firewall", "fw", map[string]ir.Value{
		"direction":          ks("INGRESS", 2),
		"destination_ranges": strList(3, "0.0.0.0/0"),
	})
	if got := runRule(firewallEgressAll{}, neg); len(got) != 0 {
		t.Fatalf("INGRESS must be quiet, got %d", len(got))
	}
	neg2 := res("google_compute_firewall", "fw", map[string]ir.Value{
		"direction":          ks("EGRESS", 2),
		"destination_ranges": strList(3, "10.0.0.0/8"),
	})
	if got := runRule(firewallEgressAll{}, neg2); len(got) != 0 {
		t.Fatalf("restricted egress must be quiet, got %d", len(got))
	}
}

// AEGIS-GCP-088 (FIXED: unknown auto_create_network used to fire):
// project auto-creates the default network. Absent fires (provider
// default is true); unknown is undecidable and must stay quiet.
func TestEffectiveness_GCP088_ProjectAutoNetwork_UnknownQuiet(t *testing.T) {
	pos := res("google_project", "p", map[string]ir.Value{})
	if got := runRule(projectAutoNetwork{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding for absent auto_create_network, got %d", len(got))
	}
	pos2 := res("google_project", "p", map[string]ir.Value{"auto_create_network": kv(true, 2)})
	if got := runRule(projectAutoNetwork{}, pos2); len(got) != 1 {
		t.Fatalf("expected 1 finding for true, got %d", len(got))
	}
	neg := res("google_project", "p", map[string]ir.Value{"auto_create_network": kv(false, 2)})
	if got := runRule(projectAutoNetwork{}, neg); len(got) != 0 {
		t.Fatalf("false must be quiet, got %d", len(got))
	}
	unk := res("google_project", "p", map[string]ir.Value{"auto_create_network": ku(2)})
	if got := runRule(projectAutoNetwork{}, unk); len(got) != 0 {
		t.Fatalf("unknown auto_create_network must be quiet, got %d", len(got))
	}
	ref := res("google_project", "p", map[string]ir.Value{"auto_create_network": eaRef("var.auto", 2)})
	if got := runRule(projectAutoNetwork{}, ref); len(got) != 0 {
		t.Fatalf("ref auto_create_network must be quiet, got %d", len(got))
	}
}

// AEGIS-GCP-089: project metadata without OS Login enabled.
func TestEffectiveness_GCP089_ProjectMetadataNoOSLogin(t *testing.T) {
	pos := res("google_compute_project_metadata", "m", map[string]ir.Value{
		"metadata": eaMapVal(map[string]ir.Value{"enable-oslogin": ks("FALSE", 2)}, 2),
	})
	if got := runRule(projectMetadataNoOSLogin{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	neg := res("google_compute_project_metadata", "m", map[string]ir.Value{
		"metadata": eaMapVal(map[string]ir.Value{"enable-oslogin": ks("TRUE", 2)}, 2),
	})
	if got := runRule(projectMetadataNoOSLogin{}, neg); len(got) != 0 {
		t.Fatalf("TRUE must be quiet, got %d", len(got))
	}
	unk := res("google_compute_project_metadata", "m", map[string]ir.Value{
		"metadata": eaMapVal(map[string]ir.Value{"enable-oslogin": ku(2)}, 2),
	})
	if got := runRule(projectMetadataNoOSLogin{}, unk); len(got) != 0 {
		t.Fatalf("unknown enable-oslogin must be quiet, got %d", len(got))
	}
}

// AEGIS-GCP-091 (FIXED: unknown enable_logging used to fire): DNS policy
// without query logging. Absent fires; unknown must stay quiet.
func TestEffectiveness_GCP091_DNSPolicyNoLogging_UnknownQuiet(t *testing.T) {
	pos := res("google_dns_policy", "p", map[string]ir.Value{})
	if got := runRule(dnsPolicyNoLogging{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding for absent enable_logging, got %d", len(got))
	}
	pos2 := res("google_dns_policy", "p", map[string]ir.Value{"enable_logging": kv(false, 2)})
	if got := runRule(dnsPolicyNoLogging{}, pos2); len(got) != 1 {
		t.Fatalf("expected 1 finding for false, got %d", len(got))
	}
	neg := res("google_dns_policy", "p", map[string]ir.Value{"enable_logging": kv(true, 2)})
	if got := runRule(dnsPolicyNoLogging{}, neg); len(got) != 0 {
		t.Fatalf("true must be quiet, got %d", len(got))
	}
	unk := res("google_dns_policy", "p", map[string]ir.Value{"enable_logging": ku(2)})
	if got := runRule(dnsPolicyNoLogging{}, unk); len(got) != 0 {
		t.Fatalf("unknown enable_logging must be quiet, got %d", len(got))
	}
}

// AEGIS-GCP-093: DNSSEC with weak signing algorithm.
func TestEffectiveness_GCP093_DNSWeakDNSSEC(t *testing.T) {
	pos := res("google_dns_managed_zone", "z", map[string]ir.Value{
		"dnssec_config": blks(2, blk("default_key_specs", blks(3,
			blk("algorithm", ks("rsasha1", 4)),
		))),
	})
	if got := runRule(dnsWeakDNSSEC{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	neg := res("google_dns_managed_zone", "z", map[string]ir.Value{
		"dnssec_config": blks(2, blk("default_key_specs", blks(3,
			blk("algorithm", ks("rsasha256", 4)),
		))),
	})
	if got := runRule(dnsWeakDNSSEC{}, neg); len(got) != 0 {
		t.Fatalf("rsasha256 must be quiet, got %d", len(got))
	}
	if got := runRule(dnsWeakDNSSEC{}, res("google_dns_managed_zone", "z", map[string]ir.Value{})); len(got) != 0 {
		t.Fatalf("absent dnssec_config must be quiet (024 covers it), got %d", len(got))
	}
}

// AEGIS-GCP-224 (FIXED: empty evidence Actual): KMS key with a destroy
// scheduled duration under 24h.
func TestEffectiveness_GCP224_KMSShortDestroyDuration_Evidence(t *testing.T) {
	empty := res("google_kms_crypto_key", "k", map[string]ir.Value{
		"destroy_scheduled_duration": ks("", 2),
	})
	f := mustFinding(t, runRule(kmsShortDestroyDuration{}, empty), "AEGIS-GCP-224")
	if f.Evidence.Actual == "" || f.Evidence.Expected == "" || f.Evidence.Attribute == "" {
		t.Fatalf("evidence must be non-empty, got %+v", f.Evidence)
	}
	neg := res("google_kms_crypto_key", "k", map[string]ir.Value{
		"destroy_scheduled_duration": ks("86400s", 2),
	})
	if got := runRule(kmsShortDestroyDuration{}, neg); len(got) != 0 {
		t.Fatalf("86400s must be quiet, got %d", len(got))
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

func eaR(ref string) ir.Value { return ir.Value{Known: false, Ref: ref} }

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
func TestEffectivenessReplay_GCP_031(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-031")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_storage_bucket", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-031: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-031: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-031: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_storage_bucket", "probe", map[string]ir.Value{
			"MYSQL_5_6":                      eaS("public"),
			"MYSQL_5_7":                      eaS("public"),
			"POSTGRES_10":                    eaS("public"),
			"POSTGRES_11":                    eaS("public"),
			"POSTGRES_9_6":                   eaS("public"),
			"SQLSERVER_2017_ENTERPRISE":      eaS("public"),
			"SQLSERVER_2017_STANDARD":        eaS("public"),
			"absent":                         eaS("public"),
			"access":                         eaS("Allow"),
			"acl":                            eaS("public"),
			"admin":                          eaB(true),
			"allauthenticatedusers":          eaS("public"),
			"allusers":                       eaS("public"),
			"authorized_networks":            eaS("public"),
			"auto_upgrade":                   eaS("public"),
			"backup_configuration":           eaB(false),
			"binary_authorization":           eaS("public"),
			"cors":                           eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))),
			"database_flags":                 eaS("public"),
			"database_version":               eaS(">= 1.0"),
			"dataeditor":                     eaS("public"),
			"dataviewer":                     eaS("public"),
			"default_kms_key_name":           eaS("my_password"),
			"default_table_expiration_ms":    eaS("public"),
			"deletion_protection":            eaB(false),
			"domain":                         eaS("public"),
			"encryption":                     eaB(false),
			"encryption_configuration":       eaB(false),
			"enforced":                       eaB(false),
			"force_destroy":                  eaS("public"),
			"group_by_email":                 eaS("alice@example.com"),
			"host":                           eaS("public"),
			"ip_configuration":               eaS("public"),
			"lifecycle_rule":                 eaS("public"),
			"local_infile":                   eaS("public"),
			"log_disconnections":             eaB(false),
			"logging":                        eaB(false),
			"maintenance_window":             eaS("public"),
			"management":                     eaS("public"),
			"member":                         eaS("allUsers"),
			"members":                        eaL(eaS("allUsers")),
			"name":                           eaS("my_password"),
			"off":                            eaS("public"),
			"on":                             eaS("public"),
			"origin":                         eaS("public"),
			"point_in_time_recovery_enabled": eaB(false),
			"predefined_acl":                 eaS("public"),
			"public_access_prevention":       eaS("Allow"),
			"publicread":                     eaB(true),
			"publicreadwrite":                eaB(true),
			"role":                           eaS("roles/storage.objectViewer"),
			"role_entity":                    eaS("roles/owner"),
			"settings":                       eaS("public"),
			"special_group":                  eaS("public"),
			"user_by_email":                  eaS("alice@example.com"),
			"value":                          eaS("public"),
			"website":                        eaS("public"),
			"workload_identity_config":       eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-031: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_storage_bucket", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"auto_upgrade":                   eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"management":                     eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-031: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_034(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-034")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_bigquery_dataset", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-034: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-034: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-034: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_bigquery_dataset", "probe", map[string]ir.Value{
			"MYSQL_5_6":                      eaS("public"),
			"MYSQL_5_7":                      eaS("public"),
			"POSTGRES_10":                    eaS("public"),
			"POSTGRES_11":                    eaS("public"),
			"POSTGRES_9_6":                   eaS("public"),
			"SQLSERVER_2017_ENTERPRISE":      eaS("public"),
			"SQLSERVER_2017_STANDARD":        eaS("public"),
			"absent":                         eaS("public"),
			"access":                         eaS("Allow"),
			"acl":                            eaS("public"),
			"admin":                          eaB(true),
			"allauthenticatedusers":          eaS("public"),
			"allusers":                       eaS("public"),
			"authorized_networks":            eaS("public"),
			"auto_upgrade":                   eaS("public"),
			"backup_configuration":           eaB(false),
			"binary_authorization":           eaS("public"),
			"cors":                           eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))),
			"database_flags":                 eaS("public"),
			"database_version":               eaS(">= 1.0"),
			"dataeditor":                     eaS("public"),
			"dataviewer":                     eaS("public"),
			"default_kms_key_name":           eaS("my_password"),
			"default_table_expiration_ms":    eaS("public"),
			"deletion_protection":            eaB(false),
			"domain":                         eaS("public"),
			"encryption":                     eaB(false),
			"encryption_configuration":       eaB(false),
			"enforced":                       eaB(false),
			"force_destroy":                  eaS("public"),
			"group_by_email":                 eaS("alice@example.com"),
			"host":                           eaS("public"),
			"ip_configuration":               eaS("public"),
			"lifecycle_rule":                 eaS("public"),
			"local_infile":                   eaS("public"),
			"log_disconnections":             eaB(false),
			"logging":                        eaB(false),
			"maintenance_window":             eaS("public"),
			"management":                     eaS("public"),
			"member":                         eaS("allUsers"),
			"members":                        eaL(eaS("allUsers")),
			"name":                           eaS("my_password"),
			"off":                            eaS("public"),
			"on":                             eaS("public"),
			"origin":                         eaS("public"),
			"point_in_time_recovery_enabled": eaB(false),
			"predefined_acl":                 eaS("public"),
			"public_access_prevention":       eaS("Allow"),
			"publicread":                     eaB(true),
			"publicreadwrite":                eaB(true),
			"role":                           eaS("roles/storage.objectViewer"),
			"role_entity":                    eaS("roles/owner"),
			"settings":                       eaS("public"),
			"special_group":                  eaS("public"),
			"user_by_email":                  eaS("alice@example.com"),
			"value":                          eaS("public"),
			"website":                        eaS("public"),
			"workload_identity_config":       eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-034: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_bigquery_dataset", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"auto_upgrade":                   eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"management":                     eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-034: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_035(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-035")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_bigquery_table", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-035: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-035: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-035: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_bigquery_table", "probe", map[string]ir.Value{
			"MYSQL_5_6":                      eaS("public"),
			"MYSQL_5_7":                      eaS("public"),
			"POSTGRES_10":                    eaS("public"),
			"POSTGRES_11":                    eaS("public"),
			"POSTGRES_9_6":                   eaS("public"),
			"SQLSERVER_2017_ENTERPRISE":      eaS("public"),
			"SQLSERVER_2017_STANDARD":        eaS("public"),
			"absent":                         eaS("public"),
			"access":                         eaS("Allow"),
			"acl":                            eaS("public"),
			"admin":                          eaB(true),
			"allauthenticatedusers":          eaS("public"),
			"allusers":                       eaS("public"),
			"authorized_networks":            eaS("public"),
			"auto_upgrade":                   eaS("public"),
			"backup_configuration":           eaB(false),
			"binary_authorization":           eaS("public"),
			"cors":                           eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))),
			"database_flags":                 eaS("public"),
			"database_version":               eaS(">= 1.0"),
			"dataeditor":                     eaS("public"),
			"dataviewer":                     eaS("public"),
			"default_kms_key_name":           eaS("my_password"),
			"default_table_expiration_ms":    eaS("public"),
			"deletion_protection":            eaB(false),
			"domain":                         eaS("public"),
			"encryption":                     eaB(false),
			"encryption_configuration":       eaB(false),
			"enforced":                       eaB(false),
			"force_destroy":                  eaS("public"),
			"group_by_email":                 eaS("alice@example.com"),
			"host":                           eaS("public"),
			"ip_configuration":               eaS("public"),
			"lifecycle_rule":                 eaS("public"),
			"local_infile":                   eaS("public"),
			"log_disconnections":             eaB(false),
			"logging":                        eaB(false),
			"maintenance_window":             eaS("public"),
			"management":                     eaS("public"),
			"member":                         eaS("allUsers"),
			"members":                        eaL(eaS("allUsers")),
			"name":                           eaS("my_password"),
			"off":                            eaS("public"),
			"on":                             eaS("public"),
			"origin":                         eaS("public"),
			"point_in_time_recovery_enabled": eaB(false),
			"predefined_acl":                 eaS("public"),
			"public_access_prevention":       eaS("Allow"),
			"publicread":                     eaB(true),
			"publicreadwrite":                eaB(true),
			"role":                           eaS("roles/storage.objectViewer"),
			"role_entity":                    eaS("roles/owner"),
			"settings":                       eaS("public"),
			"special_group":                  eaS("public"),
			"user_by_email":                  eaS("alice@example.com"),
			"value":                          eaS("public"),
			"website":                        eaS("public"),
			"workload_identity_config":       eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-035: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_bigquery_table", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"auto_upgrade":                   eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"management":                     eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-035: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_037(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-037")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_bigquery_dataset", "probe", map[string]ir.Value{
			"MYSQL_5_6":                      eaS("public"),
			"MYSQL_5_7":                      eaS("public"),
			"POSTGRES_10":                    eaS("public"),
			"POSTGRES_11":                    eaS("public"),
			"POSTGRES_9_6":                   eaS("public"),
			"SQLSERVER_2017_ENTERPRISE":      eaS("public"),
			"SQLSERVER_2017_STANDARD":        eaS("public"),
			"absent":                         eaS("public"),
			"access":                         eaS("Allow"),
			"acl":                            eaS("public"),
			"admin":                          eaB(true),
			"allauthenticatedusers":          eaS("public"),
			"allusers":                       eaS("public"),
			"authorized_networks":            eaS("public"),
			"auto_upgrade":                   eaS("public"),
			"backup_configuration":           eaB(false),
			"binary_authorization":           eaS("public"),
			"cors":                           eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))),
			"database_flags":                 eaS("public"),
			"database_version":               eaS(">= 1.0"),
			"dataeditor":                     eaS("public"),
			"dataviewer":                     eaS("public"),
			"default_kms_key_name":           eaS("my_password"),
			"default_table_expiration_ms":    eaS("public"),
			"deletion_protection":            eaB(false),
			"domain":                         eaS("public"),
			"encryption":                     eaB(false),
			"encryption_configuration":       eaB(false),
			"enforced":                       eaB(false),
			"force_destroy":                  eaS("public"),
			"group_by_email":                 eaS("alice@example.com"),
			"host":                           eaS("public"),
			"ip_configuration":               eaS("public"),
			"lifecycle_rule":                 eaS("public"),
			"local_infile":                   eaS("public"),
			"log_disconnections":             eaB(false),
			"logging":                        eaB(false),
			"maintenance_window":             eaS("public"),
			"management":                     eaS("public"),
			"member":                         eaS("allUsers"),
			"members":                        eaL(eaS("allUsers")),
			"name":                           eaS("my_password"),
			"off":                            eaS("public"),
			"on":                             eaS("public"),
			"origin":                         eaS("public"),
			"point_in_time_recovery_enabled": eaB(false),
			"predefined_acl":                 eaS("public"),
			"public_access_prevention":       eaS("Allow"),
			"publicread":                     eaB(true),
			"publicreadwrite":                eaB(true),
			"role":                           eaS("roles/storage.objectViewer"),
			"role_entity":                    eaS("roles/owner"),
			"settings":                       eaS("public"),
			"special_group":                  eaS("public"),
			"user_by_email":                  eaS("alice@example.com"),
			"value":                          eaS("public"),
			"website":                        eaS("public"),
			"workload_identity_config":       eaS("public"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-037: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-037: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-037: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_bigquery_dataset", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-037: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_bigquery_dataset", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"auto_upgrade":                   eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"management":                     eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-037: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_042(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-042")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_sql_database_instance", "probe", map[string]ir.Value{
			"settings": eaL(eaM("MYSQL_5_6", eaS("public"), "MYSQL_5_7", eaS("public"), "POSTGRES_10", eaS("public"), "POSTGRES_11", eaS("public"), "POSTGRES_9_6", eaS("public"), "SQLSERVER_2017_ENTERPRISE", eaS("public"), "SQLSERVER_2017_STANDARD", eaS("public"), "absent", eaS("public"), "access", eaS("Allow"), "acl", eaS("public"), "admin", eaB(true), "allauthenticatedusers", eaS("public"), "allusers", eaS("public"), "authorized_networks", eaS("public"), "auto_upgrade", eaS("public"), "backup_configuration", eaB(false), "binary_authorization", eaS("public"), "cors", eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))), "database_flags", eaS("public"), "database_version", eaS(">= 1.0"), "dataeditor", eaS("public"), "dataviewer", eaS("public"), "default_kms_key_name", eaS("my_password"), "default_table_expiration_ms", eaS("public"), "deletion_protection", eaB(false), "domain", eaS("public"), "encryption", eaB(false), "encryption_configuration", eaB(false), "enforced", eaB(false), "force_destroy", eaS("public"), "group_by_email", eaS("alice@example.com"), "host", eaS("public"), "ip_configuration", eaS("public"), "lifecycle_rule", eaS("public"), "local_infile", eaS("public"), "log_disconnections", eaB(false), "logging", eaB(false), "maintenance_window", eaS("public"), "management", eaS("public"), "member", eaS("allUsers"), "members", eaL(eaS("allUsers")), "name", eaS("my_password"), "off", eaS("public"), "on", eaS("public"), "origin", eaS("public"), "point_in_time_recovery_enabled", eaB(false), "predefined_acl", eaS("public"), "public_access_prevention", eaS("Allow"), "publicread", eaB(true), "publicreadwrite", eaB(true), "role", eaS("roles/storage.objectViewer"), "role_entity", eaS("roles/owner"), "settings", eaS("public"), "special_group", eaS("public"), "user_by_email", eaS("alice@example.com"), "value", eaS("public"), "website", eaS("public"), "workload_identity_config", eaS("public"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-042: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-042: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-042: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_sql_database_instance", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-042: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_sql_database_instance", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"auto_upgrade":                   eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"management":                     eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-042: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_044(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-044")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_sql_database_instance", "probe", map[string]ir.Value{
			"settings": eaL(eaM("MYSQL_5_6", eaS("public"), "MYSQL_5_7", eaS("public"), "POSTGRES_10", eaS("public"), "POSTGRES_11", eaS("public"), "POSTGRES_9_6", eaS("public"), "SQLSERVER_2017_ENTERPRISE", eaS("public"), "SQLSERVER_2017_STANDARD", eaS("public"), "absent", eaS("public"), "access", eaS("Allow"), "acl", eaS("public"), "admin", eaB(true), "allauthenticatedusers", eaS("public"), "allusers", eaS("public"), "authorized_networks", eaS("public"), "auto_upgrade", eaS("public"), "backup_configuration", eaB(false), "binary_authorization", eaS("public"), "cors", eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))), "database_flags", eaS("public"), "database_version", eaS(">= 1.0"), "dataeditor", eaS("public"), "dataviewer", eaS("public"), "default_kms_key_name", eaS("my_password"), "default_table_expiration_ms", eaS("public"), "deletion_protection", eaB(false), "domain", eaS("public"), "encryption", eaB(false), "encryption_configuration", eaB(false), "enforced", eaB(false), "force_destroy", eaS("public"), "group_by_email", eaS("alice@example.com"), "host", eaS("public"), "ip_configuration", eaS("public"), "lifecycle_rule", eaS("public"), "local_infile", eaS("public"), "log_disconnections", eaB(false), "logging", eaB(false), "maintenance_window", eaS("public"), "management", eaS("public"), "member", eaS("allUsers"), "members", eaL(eaS("allUsers")), "name", eaS("my_password"), "off", eaS("public"), "on", eaS("public"), "origin", eaS("public"), "point_in_time_recovery_enabled", eaB(false), "predefined_acl", eaS("public"), "public_access_prevention", eaS("Allow"), "publicread", eaB(true), "publicreadwrite", eaB(true), "role", eaS("roles/storage.objectViewer"), "role_entity", eaS("roles/owner"), "settings", eaS("public"), "special_group", eaS("public"), "user_by_email", eaS("alice@example.com"), "value", eaS("public"), "website", eaS("public"), "workload_identity_config", eaS("public"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-044: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-044: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-044: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_sql_database_instance", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-044: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_sql_database_instance", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"auto_upgrade":                   eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"management":                     eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-044: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_046(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-046")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_sql_database_instance", "probe", map[string]ir.Value{
			"settings": eaL(eaM("MYSQL_5_6", eaS("public"), "MYSQL_5_7", eaS("public"), "POSTGRES_10", eaS("public"), "POSTGRES_11", eaS("public"), "POSTGRES_9_6", eaS("public"), "SQLSERVER_2017_ENTERPRISE", eaS("public"), "SQLSERVER_2017_STANDARD", eaS("public"), "absent", eaS("public"), "access", eaS("Allow"), "acl", eaS("public"), "admin", eaB(true), "allauthenticatedusers", eaS("public"), "allusers", eaS("public"), "authorized_networks", eaS("public"), "auto_upgrade", eaS("public"), "backup_configuration", eaB(false), "binary_authorization", eaS("public"), "cors", eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))), "database_flags", eaS("public"), "database_version", eaS(">= 1.0"), "dataeditor", eaS("public"), "dataviewer", eaS("public"), "default_kms_key_name", eaS("my_password"), "default_table_expiration_ms", eaS("public"), "deletion_protection", eaB(false), "domain", eaS("public"), "encryption", eaB(false), "encryption_configuration", eaB(false), "enforced", eaB(false), "force_destroy", eaS("public"), "group_by_email", eaS("alice@example.com"), "host", eaS("public"), "ip_configuration", eaS("public"), "lifecycle_rule", eaS("public"), "local_infile", eaS("public"), "log_disconnections", eaB(false), "logging", eaB(false), "maintenance_window", eaS("public"), "management", eaS("public"), "member", eaS("allUsers"), "members", eaL(eaS("allUsers")), "name", eaS("my_password"), "off", eaS("public"), "on", eaS("public"), "origin", eaS("public"), "point_in_time_recovery_enabled", eaB(false), "predefined_acl", eaS("public"), "public_access_prevention", eaS("Allow"), "publicread", eaB(true), "publicreadwrite", eaB(true), "role", eaS("roles/storage.objectViewer"), "role_entity", eaS("roles/owner"), "settings", eaS("public"), "special_group", eaS("public"), "user_by_email", eaS("alice@example.com"), "value", eaS("public"), "website", eaS("public"), "workload_identity_config", eaS("public"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-046: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-046: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-046: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_sql_database_instance", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-046: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_sql_database_instance", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"auto_upgrade":                   eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"management":                     eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-046: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_049(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-049")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_container_cluster", "probe", map[string]ir.Value{
			"management": eaL(eaM("MYSQL_5_6", eaB(false), "MYSQL_5_7", eaB(false), "POSTGRES_10", eaB(false), "POSTGRES_11", eaB(false), "POSTGRES_9_6", eaB(false), "SQLSERVER_2017_ENTERPRISE", eaB(false), "SQLSERVER_2017_STANDARD", eaB(false), "absent", eaB(false), "access", eaB(false), "acl", eaB(false), "admin", eaB(false), "allauthenticatedusers", eaB(false), "allusers", eaB(false), "authorized_networks", eaB(false), "auto_upgrade", eaB(false), "backup_configuration", eaB(false), "binary_authorization", eaB(false), "cors", eaB(false), "database_flags", eaB(false), "database_version", eaB(false), "dataeditor", eaB(false), "dataviewer", eaB(false), "default_kms_key_name", eaB(false), "default_table_expiration_ms", eaB(false), "deletion_protection", eaB(false), "domain", eaB(false), "encryption", eaB(false), "encryption_configuration", eaB(false), "enforced", eaB(false), "force_destroy", eaB(false), "group_by_email", eaB(false), "host", eaB(false), "ip_configuration", eaB(false), "lifecycle_rule", eaB(false), "local_infile", eaB(false), "log_disconnections", eaB(false), "logging", eaB(false), "maintenance_window", eaB(false), "management", eaB(false), "member", eaB(false), "members", eaB(false), "name", eaB(false), "off", eaB(false), "on", eaB(false), "origin", eaB(false), "point_in_time_recovery_enabled", eaB(false), "predefined_acl", eaB(false), "public_access_prevention", eaB(false), "publicread", eaB(false), "publicreadwrite", eaB(false), "role", eaB(false), "role_entity", eaB(false), "settings", eaB(false), "special_group", eaB(false), "user_by_email", eaB(false), "value", eaB(false), "website", eaB(false), "workload_identity_config", eaB(false))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-049: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-049: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-049: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_container_cluster", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-049: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_container_cluster", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"auto_upgrade":                   eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"management":                     eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-049: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_050(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-050")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_container_cluster", "probe", map[string]ir.Value{
			"management": eaL(eaM("MYSQL_5_6", eaB(false), "MYSQL_5_7", eaB(false), "POSTGRES_10", eaB(false), "POSTGRES_11", eaB(false), "POSTGRES_9_6", eaB(false), "SQLSERVER_2017_ENTERPRISE", eaB(false), "SQLSERVER_2017_STANDARD", eaB(false), "absent", eaB(false), "access", eaB(false), "acl", eaB(false), "admin", eaB(false), "allauthenticatedusers", eaB(false), "allusers", eaB(false), "authorized_networks", eaB(false), "auto_repair", eaB(false), "backup_configuration", eaB(false), "binary_authorization", eaB(false), "cors", eaB(false), "database_flags", eaB(false), "database_version", eaB(false), "dataeditor", eaB(false), "dataviewer", eaB(false), "default_kms_key_name", eaB(false), "default_table_expiration_ms", eaB(false), "deletion_protection", eaB(false), "domain", eaB(false), "encryption", eaB(false), "encryption_configuration", eaB(false), "enforced", eaB(false), "force_destroy", eaB(false), "group_by_email", eaB(false), "host", eaB(false), "ip_configuration", eaB(false), "lifecycle_rule", eaB(false), "local_infile", eaB(false), "log_disconnections", eaB(false), "logging", eaB(false), "maintenance_window", eaB(false), "management", eaB(false), "member", eaB(false), "members", eaB(false), "name", eaB(false), "off", eaB(false), "on", eaB(false), "origin", eaB(false), "point_in_time_recovery_enabled", eaB(false), "predefined_acl", eaB(false), "public_access_prevention", eaB(false), "publicread", eaB(false), "publicreadwrite", eaB(false), "role", eaB(false), "role_entity", eaB(false), "settings", eaB(false), "special_group", eaB(false), "user_by_email", eaB(false), "value", eaB(false), "website", eaB(false), "workload_identity_config", eaB(false))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-050: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-050: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-050: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_container_cluster", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-050: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_container_cluster", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"auto_repair":                    eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"management":                     eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-050: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_054(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-054")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_container_cluster", "probe", map[string]ir.Value{
			"MYSQL_5_6":                      eaS("public"),
			"MYSQL_5_7":                      eaS("public"),
			"POSTGRES_10":                    eaS("public"),
			"POSTGRES_11":                    eaS("public"),
			"POSTGRES_9_6":                   eaS("public"),
			"SQLSERVER_2017_ENTERPRISE":      eaS("public"),
			"SQLSERVER_2017_STANDARD":        eaS("public"),
			"absent":                         eaS("public"),
			"access":                         eaS("Allow"),
			"acl":                            eaS("public"),
			"admin":                          eaB(true),
			"allauthenticatedusers":          eaS("public"),
			"allusers":                       eaS("public"),
			"authorized_networks":            eaS("public"),
			"backup_configuration":           eaB(false),
			"binary_authorization":           eaS("public"),
			"cors":                           eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))),
			"database_flags":                 eaS("public"),
			"database_version":               eaS(">= 1.0"),
			"dataeditor":                     eaS("public"),
			"dataviewer":                     eaS("public"),
			"default_kms_key_name":           eaS("my_password"),
			"default_table_expiration_ms":    eaS("public"),
			"deletion_protection":            eaB(false),
			"domain":                         eaS("public"),
			"enable_intranode_visibility":    eaB(false),
			"encryption":                     eaB(false),
			"encryption_configuration":       eaB(false),
			"enforced":                       eaB(false),
			"force_destroy":                  eaS("public"),
			"group_by_email":                 eaS("alice@example.com"),
			"host":                           eaS("public"),
			"ip_configuration":               eaS("public"),
			"lifecycle_rule":                 eaS("public"),
			"local_infile":                   eaS("public"),
			"log_disconnections":             eaB(false),
			"logging":                        eaB(false),
			"maintenance_window":             eaS("public"),
			"management":                     eaS("public"),
			"member":                         eaS("allUsers"),
			"members":                        eaL(eaS("allUsers")),
			"name":                           eaS("my_password"),
			"off":                            eaS("public"),
			"on":                             eaS("public"),
			"origin":                         eaS("public"),
			"point_in_time_recovery_enabled": eaB(false),
			"predefined_acl":                 eaS("public"),
			"public_access_prevention":       eaS("Allow"),
			"publicread":                     eaB(true),
			"publicreadwrite":                eaB(true),
			"role":                           eaS("roles/storage.objectViewer"),
			"role_entity":                    eaS("roles/owner"),
			"settings":                       eaS("public"),
			"special_group":                  eaS("public"),
			"user_by_email":                  eaS("alice@example.com"),
			"value":                          eaS("public"),
			"website":                        eaS("public"),
			"workload_identity_config":       eaS("public"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-054: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-054: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-054: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_container_cluster", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-054: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_container_cluster", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"enable_intranode_visibility":    eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"management":                     eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-054: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_055(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-055")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_container_cluster", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-055: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-055: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-055: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_container_cluster", "probe", map[string]ir.Value{
			"MYSQL_5_6":                      eaS("public"),
			"MYSQL_5_7":                      eaS("public"),
			"POSTGRES_10":                    eaS("public"),
			"POSTGRES_11":                    eaS("public"),
			"POSTGRES_9_6":                   eaS("public"),
			"SQLSERVER_2017_ENTERPRISE":      eaS("public"),
			"SQLSERVER_2017_STANDARD":        eaS("public"),
			"absent":                         eaS("public"),
			"access":                         eaS("Allow"),
			"acl":                            eaS("public"),
			"admin":                          eaB(true),
			"allauthenticatedusers":          eaS("public"),
			"allusers":                       eaS("public"),
			"authorized_networks":            eaS("public"),
			"backup_configuration":           eaB(false),
			"binary_authorization":           eaS("public"),
			"cors":                           eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))),
			"database_flags":                 eaS("public"),
			"database_version":               eaS(">= 1.0"),
			"dataeditor":                     eaS("public"),
			"dataviewer":                     eaS("public"),
			"default_kms_key_name":           eaS("my_password"),
			"default_table_expiration_ms":    eaS("public"),
			"deletion_protection":            eaB(false),
			"domain":                         eaS("public"),
			"enabled":                        eaB(false),
			"encryption":                     eaB(false),
			"encryption_configuration":       eaB(false),
			"enforced":                       eaB(false),
			"force_destroy":                  eaS("public"),
			"group_by_email":                 eaS("alice@example.com"),
			"host":                           eaS("public"),
			"ip_configuration":               eaS("public"),
			"lifecycle_rule":                 eaS("public"),
			"local_infile":                   eaS("public"),
			"log_disconnections":             eaB(false),
			"logging":                        eaB(false),
			"maintenance_window":             eaS("public"),
			"member":                         eaS("allUsers"),
			"members":                        eaL(eaS("allUsers")),
			"name":                           eaS("my_password"),
			"off":                            eaS("public"),
			"on":                             eaS("public"),
			"origin":                         eaS("public"),
			"point_in_time_recovery_enabled": eaB(false),
			"predefined_acl":                 eaS("public"),
			"public_access_prevention":       eaS("Allow"),
			"publicread":                     eaB(true),
			"publicreadwrite":                eaB(true),
			"role":                           eaS("roles/storage.objectViewer"),
			"role_entity":                    eaS("roles/owner"),
			"settings":                       eaS("public"),
			"shielded_nodes":                 eaS("public"),
			"special_group":                  eaS("public"),
			"user_by_email":                  eaS("alice@example.com"),
			"value":                          eaS("public"),
			"website":                        eaS("public"),
			"workload_identity_config":       eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-055: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_container_cluster", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"enabled":                        eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"shielded_nodes":                 eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-055: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_056(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-056")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_container_cluster", "probe", map[string]ir.Value{
			"node_config": eaL(eaM("MYSQL_5_6", eaS("public"), "MYSQL_5_7", eaS("public"), "POSTGRES_10", eaS("public"), "POSTGRES_11", eaS("public"), "POSTGRES_9_6", eaS("public"), "SQLSERVER_2017_ENTERPRISE", eaS("public"), "SQLSERVER_2017_STANDARD", eaS("public"), "absent", eaS("public"), "access", eaS("Allow"), "acl", eaS("public"), "admin", eaB(true), "allauthenticatedusers", eaS("public"), "allusers", eaS("public"), "authorized_networks", eaS("public"), "backup_configuration", eaB(false), "binary_authorization", eaS("public"), "confidential_nodes", eaS("public"), "cors", eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))), "database_flags", eaS("public"), "database_version", eaS(">= 1.0"), "dataeditor", eaS("public"), "dataviewer", eaS("public"), "default_kms_key_name", eaS("my_password"), "default_table_expiration_ms", eaS("public"), "deletion_protection", eaB(false), "domain", eaS("public"), "encryption", eaB(false), "encryption_configuration", eaB(false), "enforced", eaB(false), "force_destroy", eaS("public"), "group_by_email", eaS("alice@example.com"), "host", eaS("public"), "ip_configuration", eaS("public"), "lifecycle_rule", eaS("public"), "local_infile", eaS("public"), "log_disconnections", eaB(false), "logging", eaB(false), "maintenance_window", eaS("public"), "member", eaS("allUsers"), "members", eaL(eaS("allUsers")), "name", eaS("my_password"), "node_config", eaS("public"), "off", eaS("public"), "on", eaS("public"), "origin", eaS("public"), "point_in_time_recovery_enabled", eaB(false), "predefined_acl", eaS("public"), "public_access_prevention", eaS("Allow"), "publicread", eaB(true), "publicreadwrite", eaB(true), "role", eaS("roles/storage.objectViewer"), "role_entity", eaS("roles/owner"), "settings", eaS("public"), "special_group", eaS("public"), "user_by_email", eaS("alice@example.com"), "value", eaS("public"), "website", eaS("public"), "workload_identity_config", eaS("public"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-056: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-056: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-056: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_container_cluster", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-056: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_container_cluster", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"confidential_nodes":             eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"node_config":                    eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-056: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_062(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-062")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_compute_instance", "probe", map[string]ir.Value{
			"service_account": eaL(eaM("MYSQL_5_6", eaB(true), "MYSQL_5_7", eaB(true), "POSTGRES_10", eaB(true), "POSTGRES_11", eaB(true), "POSTGRES_9_6", eaB(true), "SQLSERVER_2017_ENTERPRISE", eaB(true), "SQLSERVER_2017_STANDARD", eaB(true), "absent", eaB(true), "access", eaB(true), "acl", eaB(true), "admin", eaB(true), "allauthenticatedusers", eaB(true), "allusers", eaB(true), "authorized_networks", eaB(true), "backup_configuration", eaB(true), "cors", eaB(true), "database_flags", eaB(true), "database_version", eaB(true), "dataeditor", eaB(true), "dataviewer", eaB(true), "default", eaB(true), "default_kms_key_name", eaB(true), "default_table_expiration_ms", eaB(true), "deletion_protection", eaB(true), "domain", eaB(true), "email", eaB(true), "encryption", eaB(true), "encryption_configuration", eaB(true), "enforced", eaB(true), "force_destroy", eaB(true), "group_by_email", eaB(true), "host", eaB(true), "ip_configuration", eaB(true), "lifecycle_rule", eaB(true), "local_infile", eaB(true), "log_disconnections", eaB(true), "logging", eaB(true), "maintenance_window", eaB(true), "member", eaB(true), "members", eaB(true), "name", eaB(true), "off", eaB(true), "on", eaB(true), "origin", eaB(true), "point_in_time_recovery_enabled", eaB(true), "predefined_acl", eaB(true), "public_access_prevention", eaB(true), "publicread", eaB(true), "publicreadwrite", eaB(true), "role", eaB(true), "role_entity", eaB(true), "service_account", eaB(true), "settings", eaB(true), "special_group", eaB(true), "user_by_email", eaB(true), "value", eaB(true), "website", eaB(true), "workload_identity_config", eaB(true))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-062: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-062: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-062: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_compute_instance", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-062: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_compute_instance", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"backup_configuration":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default":                        eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"email":                          eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"service_account":                eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-062: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_064(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-064")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_compute_instance", "probe", map[string]ir.Value{
			"MYSQL_5_6":                      eaS("public"),
			"MYSQL_5_7":                      eaS("public"),
			"POSTGRES_10":                    eaS("public"),
			"POSTGRES_11":                    eaS("public"),
			"POSTGRES_9_6":                   eaS("public"),
			"SQLSERVER_2017_ENTERPRISE":      eaS("public"),
			"SQLSERVER_2017_STANDARD":        eaS("public"),
			"absent":                         eaS("public"),
			"access":                         eaS("Allow"),
			"acl":                            eaS("public"),
			"admin":                          eaB(true),
			"allauthenticatedusers":          eaS("public"),
			"allusers":                       eaS("public"),
			"authorized_networks":            eaS("public"),
			"auto_upgrade":                   eaS("public"),
			"backup_configuration":           eaB(false),
			"binary_authorization":           eaS("public"),
			"cors":                           eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))),
			"database_flags":                 eaS("public"),
			"database_version":               eaS(">= 1.0"),
			"dataeditor":                     eaS("public"),
			"dataviewer":                     eaS("public"),
			"default_kms_key_name":           eaS("my_password"),
			"default_table_expiration_ms":    eaS("public"),
			"deletion_protection":            eaB(false),
			"domain":                         eaS("public"),
			"encryption":                     eaB(false),
			"encryption_configuration":       eaB(false),
			"enforced":                       eaB(false),
			"force_destroy":                  eaS("public"),
			"group_by_email":                 eaS("alice@example.com"),
			"host":                           eaS("public"),
			"ip_configuration":               eaS("public"),
			"lifecycle_rule":                 eaS("public"),
			"local_infile":                   eaS("public"),
			"log_disconnections":             eaB(false),
			"logging":                        eaB(false),
			"maintenance_window":             eaS("public"),
			"management":                     eaS("public"),
			"member":                         eaS("allUsers"),
			"members":                        eaL(eaS("allUsers")),
			"name":                           eaS("my_password"),
			"off":                            eaS("public"),
			"on":                             eaS("public"),
			"origin":                         eaS("public"),
			"point_in_time_recovery_enabled": eaB(false),
			"predefined_acl":                 eaS("public"),
			"public_access_prevention":       eaS("Allow"),
			"publicread":                     eaB(true),
			"publicreadwrite":                eaB(true),
			"role":                           eaS("roles/storage.objectViewer"),
			"role_entity":                    eaS("roles/owner"),
			"settings":                       eaS("public"),
			"special_group":                  eaS("public"),
			"user_by_email":                  eaS("alice@example.com"),
			"value":                          eaS("public"),
			"website":                        eaS("public"),
			"workload_identity_config":       eaS("public"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-064: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-064: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-064: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_compute_instance", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-064: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_compute_instance", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"auto_upgrade":                   eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"management":                     eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-064: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_066(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-066")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_compute_disk", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-066: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-066: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-066: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_compute_disk", "probe", map[string]ir.Value{
			"MYSQL_5_6":                      eaS("public"),
			"MYSQL_5_7":                      eaS("public"),
			"POSTGRES_10":                    eaS("public"),
			"POSTGRES_11":                    eaS("public"),
			"POSTGRES_9_6":                   eaS("public"),
			"SQLSERVER_2017_ENTERPRISE":      eaS("public"),
			"SQLSERVER_2017_STANDARD":        eaS("public"),
			"absent":                         eaS("public"),
			"access":                         eaS("Allow"),
			"acl":                            eaS("public"),
			"admin":                          eaB(true),
			"allauthenticatedusers":          eaS("public"),
			"allusers":                       eaS("public"),
			"authorized_networks":            eaS("public"),
			"backup_configuration":           eaB(false),
			"binary_authorization":           eaS("public"),
			"cors":                           eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))),
			"database_flags":                 eaS("public"),
			"database_version":               eaS(">= 1.0"),
			"dataeditor":                     eaS("public"),
			"dataviewer":                     eaS("public"),
			"default_kms_key_name":           eaS("my_password"),
			"default_table_expiration_ms":    eaS("public"),
			"deletion_protection":            eaB(false),
			"disk_encryption_key":            eaB(false),
			"domain":                         eaS("public"),
			"encryption":                     eaB(false),
			"encryption_configuration":       eaB(false),
			"enforced":                       eaB(false),
			"force_destroy":                  eaS("public"),
			"group_by_email":                 eaS("alice@example.com"),
			"host":                           eaS("public"),
			"ip_configuration":               eaS("public"),
			"lifecycle_rule":                 eaS("public"),
			"local_infile":                   eaS("public"),
			"log_disconnections":             eaB(false),
			"logging":                        eaB(false),
			"maintenance_window":             eaS("public"),
			"management":                     eaS("public"),
			"member":                         eaS("allUsers"),
			"members":                        eaL(eaS("allUsers")),
			"name":                           eaS("my_password"),
			"off":                            eaS("public"),
			"on":                             eaS("public"),
			"origin":                         eaS("public"),
			"point_in_time_recovery_enabled": eaB(false),
			"predefined_acl":                 eaS("public"),
			"public_access_prevention":       eaS("Allow"),
			"publicread":                     eaB(true),
			"publicreadwrite":                eaB(true),
			"role":                           eaS("roles/storage.objectViewer"),
			"role_entity":                    eaS("roles/owner"),
			"settings":                       eaS("public"),
			"special_group":                  eaS("public"),
			"user_by_email":                  eaS("alice@example.com"),
			"value":                          eaS("public"),
			"website":                        eaS("public"),
			"workload_identity_config":       eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-066: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_compute_disk", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"disk_encryption_key":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"management":                     eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-066: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_069(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-069")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_compute_firewall", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-069: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-069: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-069: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_compute_firewall", "probe", map[string]ir.Value{
			"MYSQL_5_6":                      eaS("public"),
			"MYSQL_5_7":                      eaS("public"),
			"POSTGRES_10":                    eaS("public"),
			"POSTGRES_11":                    eaS("public"),
			"POSTGRES_9_6":                   eaS("public"),
			"SQLSERVER_2017_ENTERPRISE":      eaS("public"),
			"SQLSERVER_2017_STANDARD":        eaS("public"),
			"absent":                         eaS("public"),
			"access":                         eaS("Allow"),
			"acl":                            eaS("public"),
			"admin":                          eaB(true),
			"allauthenticatedusers":          eaS("public"),
			"allusers":                       eaS("public"),
			"authorized_networks":            eaS("public"),
			"backup_configuration":           eaB(false),
			"binary_authorization":           eaS("public"),
			"cors":                           eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))),
			"database_flags":                 eaS("public"),
			"database_version":               eaS(">= 1.0"),
			"dataeditor":                     eaS("public"),
			"dataviewer":                     eaS("public"),
			"default_kms_key_name":           eaS("my_password"),
			"default_table_expiration_ms":    eaS("public"),
			"deletion_protection":            eaB(false),
			"domain":                         eaS("public"),
			"encryption":                     eaB(false),
			"encryption_configuration":       eaB(false),
			"enforced":                       eaB(false),
			"force_destroy":                  eaS("public"),
			"group_by_email":                 eaS("alice@example.com"),
			"host":                           eaS("public"),
			"ip_configuration":               eaS("public"),
			"lifecycle_rule":                 eaS("public"),
			"local_infile":                   eaS("public"),
			"log_config":                     eaB(false),
			"log_disconnections":             eaB(false),
			"logging":                        eaB(false),
			"maintenance_window":             eaS("public"),
			"management":                     eaS("public"),
			"member":                         eaS("allUsers"),
			"members":                        eaL(eaS("allUsers")),
			"name":                           eaS("my_password"),
			"off":                            eaS("public"),
			"on":                             eaS("public"),
			"origin":                         eaS("public"),
			"point_in_time_recovery_enabled": eaB(false),
			"predefined_acl":                 eaS("public"),
			"public_access_prevention":       eaS("Allow"),
			"publicread":                     eaB(true),
			"publicreadwrite":                eaB(true),
			"role":                           eaS("roles/storage.objectViewer"),
			"role_entity":                    eaS("roles/owner"),
			"settings":                       eaS("public"),
			"special_group":                  eaS("public"),
			"user_by_email":                  eaS("alice@example.com"),
			"value":                          eaS("public"),
			"website":                        eaS("public"),
			"workload_identity_config":       eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-069: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_compute_firewall", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_config":                     eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"management":                     eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-069: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_074(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-074")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_project_iam_member", "probe", map[string]ir.Value{
			"MYSQL_5_6":                      eaS("private"),
			"MYSQL_5_7":                      eaS("private"),
			"POSTGRES_10":                    eaS("private"),
			"POSTGRES_11":                    eaS("private"),
			"POSTGRES_9_6":                   eaS("private"),
			"SQLSERVER_2017_ENTERPRISE":      eaS("private"),
			"SQLSERVER_2017_STANDARD":        eaS("private"),
			"absent":                         eaS("private"),
			"access":                         eaS("Deny"),
			"acl":                            eaS("private"),
			"admin":                          eaB(false),
			"allauthenticatedusers":          eaS("private"),
			"allusers":                       eaS("private"),
			"authorized_networks":            eaS("private"),
			"auto_upgrade":                   eaS("private"),
			"backup_configuration":           eaB(true),
			"binary_authorization":           eaS("private"),
			"cors":                           eaL(eaM("allow_origins", eaL(eaS("https://example.com")))),
			"database_flags":                 eaS("private"),
			"database_version":               eaS("~> 5.0"),
			"dataeditor":                     eaS("private"),
			"dataviewer":                     eaS("private"),
			"default_kms_key_name":           eaS("app"),
			"default_table_expiration_ms":    eaS("private"),
			"deletion_protection":            eaB(true),
			"domain":                         eaS("private"),
			"encryption":                     eaB(true),
			"encryption_configuration":       eaB(true),
			"enforced":                       eaB(true),
			"force_destroy":                  eaS("private"),
			"group_by_email":                 eaS("alice@example.com"),
			"host":                           eaS("private"),
			"ip_configuration":               eaS("private"),
			"lifecycle_rule":                 eaS("private"),
			"local_infile":                   eaS("private"),
			"log_disconnections":             eaB(true),
			"logging":                        eaB(true),
			"maintenance_window":             eaS("private"),
			"management":                     eaS("private"),
			"member":                         eaS("user:alice@example.com"),
			"members":                        eaL(eaS("user:alice@example.com")),
			"name":                           eaS("app"),
			"off":                            eaS("private"),
			"on":                             eaS("private"),
			"origin":                         eaS("private"),
			"point_in_time_recovery_enabled": eaB(true),
			"predefined_acl":                 eaS("private"),
			"public_access_prevention":       eaS("Deny"),
			"publicread":                     eaB(false),
			"publicreadwrite":                eaB(false),
			"role":                           eaS("roles/viewer"),
			"role_entity":                    eaS("roles/viewer"),
			"settings":                       eaS("private"),
			"special_group":                  eaS("private"),
			"user_by_email":                  eaS("alice@example.com"),
			"value":                          eaS("private"),
			"website":                        eaS("private"),
			"workload_identity_config":       eaS("private"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-074: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-074: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-074: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_project_iam_member", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-074: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_project_iam_member", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"auto_upgrade":                   eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"management":                     eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-074: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_078(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-078")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_organization_iam_custom_role", "probe", map[string]ir.Value{
			"MYSQL_5_6":                      eaS("public"),
			"MYSQL_5_7":                      eaS("public"),
			"POSTGRES_10":                    eaS("public"),
			"POSTGRES_11":                    eaS("public"),
			"POSTGRES_9_6":                   eaS("public"),
			"SQLSERVER_2017_ENTERPRISE":      eaS("public"),
			"SQLSERVER_2017_STANDARD":        eaS("public"),
			"absent":                         eaS("public"),
			"access":                         eaS("Allow"),
			"acl":                            eaS("public"),
			"admin":                          eaB(true),
			"allauthenticatedusers":          eaS("public"),
			"allusers":                       eaS("public"),
			"authorized_networks":            eaS("public"),
			"backup_configuration":           eaB(false),
			"binary_authorization":           eaS("public"),
			"cors":                           eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))),
			"database_flags":                 eaS("public"),
			"database_version":               eaS(">= 1.0"),
			"dataeditor":                     eaS("public"),
			"dataviewer":                     eaS("public"),
			"default_kms_key_name":           eaS("my_password"),
			"default_table_expiration_ms":    eaS("public"),
			"deletion_protection":            eaB(false),
			"domain":                         eaS("public"),
			"encryption":                     eaB(false),
			"encryption_configuration":       eaB(false),
			"enforced":                       eaB(false),
			"force_destroy":                  eaS("public"),
			"group_by_email":                 eaS("alice@example.com"),
			"host":                           eaS("public"),
			"ip_configuration":               eaS("public"),
			"lifecycle_rule":                 eaS("public"),
			"local_infile":                   eaS("public"),
			"log_disconnections":             eaB(false),
			"logging":                        eaB(false),
			"maintenance_window":             eaS("public"),
			"management":                     eaS("public"),
			"member":                         eaS("allUsers"),
			"members":                        eaL(eaS("allUsers")),
			"name":                           eaS("my_password"),
			"off":                            eaS("public"),
			"on":                             eaS("public"),
			"origin":                         eaS("public"),
			"permissions":                    eaL(eaS("*")),
			"point_in_time_recovery_enabled": eaB(false),
			"predefined_acl":                 eaS("public"),
			"public_access_prevention":       eaS("Allow"),
			"publicread":                     eaB(true),
			"publicreadwrite":                eaB(true),
			"role":                           eaS("roles/storage.objectViewer"),
			"role_entity":                    eaS("roles/owner"),
			"settings":                       eaS("public"),
			"special_group":                  eaS("public"),
			"user_by_email":                  eaS("alice@example.com"),
			"value":                          eaS("public"),
			"website":                        eaS("public"),
			"workload_identity_config":       eaS("public"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-078: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-078: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-078: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_organization_iam_custom_role", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-078: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_organization_iam_custom_role", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"management":                     eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"permissions":                    eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-078: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_079(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-079")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_project_iam_policy", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-079: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-079: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-079: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_project_iam_policy", "probe", map[string]ir.Value{
			"MYSQL_5_6":                      eaS("public"),
			"MYSQL_5_7":                      eaS("public"),
			"POSTGRES_10":                    eaS("public"),
			"POSTGRES_11":                    eaS("public"),
			"POSTGRES_9_6":                   eaS("public"),
			"SQLSERVER_2017_ENTERPRISE":      eaS("public"),
			"SQLSERVER_2017_STANDARD":        eaS("public"),
			"absent":                         eaS("public"),
			"access":                         eaS("Allow"),
			"acl":                            eaS("public"),
			"admin":                          eaB(true),
			"allauthenticatedusers":          eaS("public"),
			"allusers":                       eaS("public"),
			"audit_config":                   eaB(false),
			"authorized_networks":            eaS("public"),
			"backup_configuration":           eaB(false),
			"binary_authorization":           eaS("public"),
			"cors":                           eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))),
			"database_flags":                 eaS("public"),
			"database_version":               eaS(">= 1.0"),
			"dataeditor":                     eaS("public"),
			"dataviewer":                     eaS("public"),
			"default_kms_key_name":           eaS("my_password"),
			"default_table_expiration_ms":    eaS("public"),
			"deletion_protection":            eaB(false),
			"domain":                         eaS("public"),
			"encryption":                     eaB(false),
			"encryption_configuration":       eaB(false),
			"enforced":                       eaB(false),
			"force_destroy":                  eaS("public"),
			"group_by_email":                 eaS("alice@example.com"),
			"host":                           eaS("public"),
			"ip_configuration":               eaS("public"),
			"lifecycle_rule":                 eaS("public"),
			"local_infile":                   eaS("public"),
			"log_disconnections":             eaB(false),
			"logging":                        eaB(false),
			"maintenance_window":             eaS("public"),
			"management":                     eaS("public"),
			"member":                         eaS("allUsers"),
			"members":                        eaL(eaS("allUsers")),
			"name":                           eaS("my_password"),
			"off":                            eaS("public"),
			"on":                             eaS("public"),
			"origin":                         eaS("public"),
			"point_in_time_recovery_enabled": eaB(false),
			"predefined_acl":                 eaS("public"),
			"public_access_prevention":       eaS("Allow"),
			"publicread":                     eaB(true),
			"publicreadwrite":                eaB(true),
			"role":                           eaS("roles/storage.objectViewer"),
			"role_entity":                    eaS("roles/owner"),
			"settings":                       eaS("public"),
			"special_group":                  eaS("public"),
			"user_by_email":                  eaS("alice@example.com"),
			"value":                          eaS("public"),
			"website":                        eaS("public"),
			"workload_identity_config":       eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-079: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_project_iam_policy", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"audit_config":                   eaU(),
		"authorized_networks":            eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"management":                     eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-079: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_080(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-080")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_iam_workload_identity_pool_provider", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-080: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-080: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-080: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_iam_workload_identity_pool_provider", "probe", map[string]ir.Value{
			"MYSQL_5_6":                      eaS("public"),
			"MYSQL_5_7":                      eaS("public"),
			"POSTGRES_10":                    eaS("public"),
			"POSTGRES_11":                    eaS("public"),
			"POSTGRES_9_6":                   eaS("public"),
			"SQLSERVER_2017_ENTERPRISE":      eaS("public"),
			"SQLSERVER_2017_STANDARD":        eaS("public"),
			"absent":                         eaS("public"),
			"access":                         eaS("Allow"),
			"acl":                            eaS("public"),
			"admin":                          eaB(true),
			"allauthenticatedusers":          eaS("public"),
			"allusers":                       eaS("public"),
			"attribute_condition":            eaS("public"),
			"authorized_networks":            eaS("public"),
			"backup_configuration":           eaB(false),
			"binary_authorization":           eaS("public"),
			"cors":                           eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))),
			"database_flags":                 eaS("public"),
			"database_version":               eaS(">= 1.0"),
			"dataeditor":                     eaS("public"),
			"dataviewer":                     eaS("public"),
			"default_kms_key_name":           eaS("my_password"),
			"default_table_expiration_ms":    eaS("public"),
			"deletion_protection":            eaB(false),
			"domain":                         eaS("public"),
			"encryption":                     eaB(false),
			"encryption_configuration":       eaB(false),
			"enforced":                       eaB(false),
			"force_destroy":                  eaS("public"),
			"group_by_email":                 eaS("alice@example.com"),
			"host":                           eaS("public"),
			"ip_configuration":               eaS("public"),
			"lifecycle_rule":                 eaS("public"),
			"local_infile":                   eaS("public"),
			"log_disconnections":             eaB(false),
			"logging":                        eaB(false),
			"maintenance_window":             eaS("public"),
			"management":                     eaS("public"),
			"member":                         eaS("allUsers"),
			"members":                        eaL(eaS("allUsers")),
			"name":                           eaS("my_password"),
			"off":                            eaS("public"),
			"on":                             eaS("public"),
			"origin":                         eaS("public"),
			"point_in_time_recovery_enabled": eaB(false),
			"predefined_acl":                 eaS("public"),
			"public_access_prevention":       eaS("Allow"),
			"publicread":                     eaB(true),
			"publicreadwrite":                eaB(true),
			"role":                           eaS("roles/storage.objectViewer"),
			"role_entity":                    eaS("roles/owner"),
			"settings":                       eaS("public"),
			"special_group":                  eaS("public"),
			"user_by_email":                  eaS("alice@example.com"),
			"value":                          eaS("public"),
			"website":                        eaS("public"),
			"workload_identity_config":       eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-080: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_iam_workload_identity_pool_provider", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"attribute_condition":            eaU(),
		"authorized_networks":            eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"management":                     eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-080: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_084(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-084")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_kms_crypto_key", "probe", map[string]ir.Value{
			"version_template": eaL(eaM("MYSQL_5_6", eaS("public"), "MYSQL_5_7", eaS("public"), "POSTGRES_10", eaS("public"), "POSTGRES_11", eaS("public"), "POSTGRES_9_6", eaS("public"), "SHA1", eaS("public"), "SQLSERVER_2017_ENTERPRISE", eaS("public"), "SQLSERVER_2017_STANDARD", eaS("public"), "absent", eaS("public"), "access", eaS("Allow"), "acl", eaS("public"), "admin", eaB(true), "algorithm", eaS("SHA1"), "allauthenticatedusers", eaS("public"), "allusers", eaS("public"), "authorized_networks", eaS("public"), "backup_configuration", eaB(false), "cors", eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))), "database_flags", eaS("public"), "database_version", eaS(">= 1.0"), "dataeditor", eaS("public"), "dataviewer", eaS("public"), "default_kms_key_name", eaS("my_password"), "default_table_expiration_ms", eaS("public"), "deletion_protection", eaB(false), "domain", eaS("public"), "encryption", eaB(false), "encryption_configuration", eaB(false), "enforced", eaB(false), "force_destroy", eaS("public"), "group_by_email", eaS("alice@example.com"), "host", eaS("public"), "ip_configuration", eaS("public"), "lifecycle_rule", eaS("public"), "local_infile", eaS("public"), "log_disconnections", eaB(false), "logging", eaB(false), "maintenance_window", eaS("public"), "member", eaS("allUsers"), "members", eaL(eaS("allUsers")), "name", eaS("my_password"), "off", eaS("public"), "on", eaS("public"), "origin", eaS("public"), "point_in_time_recovery_enabled", eaB(false), "predefined_acl", eaS("public"), "public_access_prevention", eaS("Allow"), "publicread", eaB(true), "publicreadwrite", eaB(true), "role", eaS("roles/storage.objectViewer"), "role_entity", eaS("roles/owner"), "settings", eaS("public"), "special_group", eaS("public"), "user_by_email", eaS("alice@example.com"), "value", eaS("public"), "version_template", eaS(">= 1.0"), "website", eaS("public"), "workload_identity_config", eaS("public"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-084: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-084: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-084: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_kms_crypto_key", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-084: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_kms_crypto_key", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SHA1":                           eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"algorithm":                      eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"backup_configuration":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"version_template":               eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-084: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_085(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-085")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_logging_folder_sink", "probe", map[string]ir.Value{
			"MYSQL_5_6":                      eaB(false),
			"MYSQL_5_7":                      eaB(false),
			"POSTGRES_10":                    eaB(false),
			"POSTGRES_11":                    eaB(false),
			"POSTGRES_9_6":                   eaB(false),
			"SQLSERVER_2017_ENTERPRISE":      eaB(false),
			"SQLSERVER_2017_STANDARD":        eaB(false),
			"absent":                         eaB(false),
			"access":                         eaB(false),
			"acl":                            eaB(false),
			"admin":                          eaB(false),
			"allauthenticatedusers":          eaB(false),
			"allusers":                       eaB(false),
			"authorized_networks":            eaB(false),
			"backup_configuration":           eaB(false),
			"binary_authorization":           eaB(false),
			"cors":                           eaB(false),
			"database_flags":                 eaB(false),
			"database_version":               eaB(false),
			"dataeditor":                     eaB(false),
			"dataviewer":                     eaB(false),
			"default_kms_key_name":           eaB(false),
			"default_table_expiration_ms":    eaB(false),
			"deletion_protection":            eaB(false),
			"domain":                         eaB(false),
			"encryption":                     eaB(false),
			"encryption_configuration":       eaB(false),
			"enforced":                       eaB(false),
			"force_destroy":                  eaB(false),
			"group_by_email":                 eaB(false),
			"host":                           eaB(false),
			"ip_configuration":               eaB(false),
			"lifecycle_rule":                 eaB(false),
			"local_infile":                   eaB(false),
			"log_disconnections":             eaB(false),
			"logging":                        eaB(false),
			"maintenance_window":             eaB(false),
			"management":                     eaB(false),
			"member":                         eaB(false),
			"members":                        eaB(false),
			"name":                           eaB(false),
			"off":                            eaB(false),
			"on":                             eaB(false),
			"origin":                         eaB(false),
			"point_in_time_recovery_enabled": eaB(false),
			"predefined_acl":                 eaB(false),
			"public_access_prevention":       eaB(false),
			"publicread":                     eaB(false),
			"publicreadwrite":                eaB(false),
			"role":                           eaB(false),
			"role_entity":                    eaB(false),
			"settings":                       eaB(false),
			"special_group":                  eaB(false),
			"unique_writer_identity":         eaB(false),
			"user_by_email":                  eaB(false),
			"value":                          eaB(false),
			"website":                        eaB(false),
			"workload_identity_config":       eaB(false),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-085: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-085: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-085: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_logging_folder_sink", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-085: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_logging_folder_sink", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"management":                     eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"unique_writer_identity":         eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-085: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_087(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-087")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_project_iam_policy", "probe", map[string]ir.Value{
			"audit_config": eaL(eaM("DATA_READ", eaS("public"), "MYSQL_5_6", eaS("public"), "MYSQL_5_7", eaS("public"), "POSTGRES_10", eaS("public"), "POSTGRES_11", eaS("public"), "POSTGRES_9_6", eaS("public"), "SQLSERVER_2017_ENTERPRISE", eaS("public"), "SQLSERVER_2017_STANDARD", eaS("public"), "absent", eaS("public"), "access", eaS("Allow"), "acl", eaS("public"), "admin", eaB(true), "allauthenticatedusers", eaS("public"), "allusers", eaS("public"), "audit_config", eaB(false), "audit_log_configs", eaB(false), "authorized_networks", eaS("public"), "backup_configuration", eaB(false), "cors", eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))), "database_flags", eaS("public"), "database_version", eaS(">= 1.0"), "dataeditor", eaS("public"), "dataviewer", eaS("public"), "default_kms_key_name", eaS("my_password"), "default_table_expiration_ms", eaS("public"), "deletion_protection", eaB(false), "domain", eaS("public"), "encryption", eaB(false), "encryption_configuration", eaB(false), "enforced", eaB(false), "force_destroy", eaS("public"), "group_by_email", eaS("alice@example.com"), "host", eaS("public"), "ip_configuration", eaS("public"), "lifecycle_rule", eaS("public"), "local_infile", eaS("public"), "log_disconnections", eaB(false), "log_type", eaS("String"), "logging", eaB(false), "maintenance_window", eaS("public"), "member", eaS("allUsers"), "members", eaL(eaS("allUsers")), "name", eaS("my_password"), "off", eaS("public"), "on", eaS("public"), "origin", eaS("public"), "point_in_time_recovery_enabled", eaB(false), "predefined_acl", eaS("public"), "public_access_prevention", eaS("Allow"), "publicread", eaB(true), "publicreadwrite", eaB(true), "role", eaS("roles/storage.objectViewer"), "role_entity", eaS("roles/owner"), "settings", eaS("public"), "special_group", eaS("public"), "user_by_email", eaS("alice@example.com"), "value", eaS("public"), "website", eaS("public"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-087: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-087: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-087: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_project_iam_policy", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-087: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_project_iam_policy", "probe", map[string]ir.Value{
		"DATA_READ":                      eaU(),
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"audit_config":                   eaU(),
		"audit_log_configs":              eaU(),
		"authorized_networks":            eaU(),
		"backup_configuration":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"log_type":                       eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-087: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_090(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-090")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_logging_project_sink", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-090: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-090: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-090: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_logging_project_sink", "probe", map[string]ir.Value{
			"MYSQL_5_6":                      eaS("public"),
			"MYSQL_5_7":                      eaS("public"),
			"POSTGRES_10":                    eaS("public"),
			"POSTGRES_11":                    eaS("public"),
			"POSTGRES_9_6":                   eaS("public"),
			"SQLSERVER_2017_ENTERPRISE":      eaS("public"),
			"SQLSERVER_2017_STANDARD":        eaS("public"),
			"absent":                         eaS("public"),
			"access":                         eaS("Allow"),
			"acl":                            eaS("public"),
			"admin":                          eaB(true),
			"allauthenticatedusers":          eaS("public"),
			"allusers":                       eaS("public"),
			"authorized_networks":            eaS("public"),
			"backup_configuration":           eaB(false),
			"binary_authorization":           eaS("public"),
			"cors":                           eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))),
			"database_flags":                 eaS("public"),
			"database_version":               eaS(">= 1.0"),
			"dataeditor":                     eaS("public"),
			"dataviewer":                     eaS("public"),
			"default_kms_key_name":           eaS("my_password"),
			"default_table_expiration_ms":    eaS("public"),
			"deletion_protection":            eaB(false),
			"domain":                         eaS("public"),
			"encryption":                     eaB(false),
			"encryption_configuration":       eaB(false),
			"enforced":                       eaB(false),
			"filter":                         eaS("public"),
			"force_destroy":                  eaS("public"),
			"group_by_email":                 eaS("alice@example.com"),
			"host":                           eaS("public"),
			"ip_configuration":               eaS("public"),
			"lifecycle_rule":                 eaS("public"),
			"local_infile":                   eaS("public"),
			"log_disconnections":             eaB(false),
			"logging":                        eaB(false),
			"maintenance_window":             eaS("public"),
			"management":                     eaS("public"),
			"member":                         eaS("allUsers"),
			"members":                        eaL(eaS("allUsers")),
			"name":                           eaS("my_password"),
			"off":                            eaS("public"),
			"on":                             eaS("public"),
			"origin":                         eaS("public"),
			"point_in_time_recovery_enabled": eaB(false),
			"predefined_acl":                 eaS("public"),
			"public_access_prevention":       eaS("Allow"),
			"publicread":                     eaB(true),
			"publicreadwrite":                eaB(true),
			"role":                           eaS("roles/storage.objectViewer"),
			"role_entity":                    eaS("roles/owner"),
			"settings":                       eaS("public"),
			"special_group":                  eaS("public"),
			"user_by_email":                  eaS("alice@example.com"),
			"value":                          eaS("public"),
			"website":                        eaS("public"),
			"workload_identity_config":       eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-090: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_logging_project_sink", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"filter":                         eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"management":                     eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-090: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_091(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-091")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_dns_policy", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-091: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-091: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-091: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_dns_policy", "probe", map[string]ir.Value{
			"MYSQL_5_6":                      eaS("private"),
			"MYSQL_5_7":                      eaS("private"),
			"POSTGRES_10":                    eaS("private"),
			"POSTGRES_11":                    eaS("private"),
			"POSTGRES_9_6":                   eaS("private"),
			"SQLSERVER_2017_ENTERPRISE":      eaS("private"),
			"SQLSERVER_2017_STANDARD":        eaS("private"),
			"absent":                         eaS("private"),
			"access":                         eaS("Deny"),
			"acl":                            eaS("private"),
			"admin":                          eaB(false),
			"allauthenticatedusers":          eaS("private"),
			"allusers":                       eaS("private"),
			"authorized_networks":            eaS("private"),
			"backup_configuration":           eaB(true),
			"binary_authorization":           eaS("private"),
			"cors":                           eaL(eaM("allow_origins", eaL(eaS("https://example.com")))),
			"database_flags":                 eaS("private"),
			"database_version":               eaS("~> 5.0"),
			"dataeditor":                     eaS("private"),
			"dataviewer":                     eaS("private"),
			"default_kms_key_name":           eaS("app"),
			"default_table_expiration_ms":    eaS("private"),
			"deletion_protection":            eaB(true),
			"domain":                         eaS("private"),
			"enable_logging":                 eaB(true),
			"encryption":                     eaB(true),
			"encryption_configuration":       eaB(true),
			"enforced":                       eaB(true),
			"force_destroy":                  eaS("private"),
			"group_by_email":                 eaS("alice@example.com"),
			"host":                           eaS("private"),
			"ip_configuration":               eaS("private"),
			"lifecycle_rule":                 eaS("private"),
			"local_infile":                   eaS("private"),
			"log_disconnections":             eaB(true),
			"logging":                        eaB(true),
			"maintenance_window":             eaS("private"),
			"management":                     eaS("private"),
			"member":                         eaS("user:alice@example.com"),
			"members":                        eaL(eaS("user:alice@example.com")),
			"name":                           eaS("app"),
			"off":                            eaS("private"),
			"on":                             eaS("private"),
			"origin":                         eaS("private"),
			"point_in_time_recovery_enabled": eaB(true),
			"predefined_acl":                 eaS("private"),
			"public_access_prevention":       eaS("Deny"),
			"publicread":                     eaB(false),
			"publicreadwrite":                eaB(false),
			"role":                           eaS("roles/viewer"),
			"role_entity":                    eaS("roles/viewer"),
			"settings":                       eaS("private"),
			"special_group":                  eaS("private"),
			"user_by_email":                  eaS("alice@example.com"),
			"value":                          eaS("private"),
			"website":                        eaS("private"),
			"workload_identity_config":       eaS("private"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-091: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_092(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-092")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_dns_record_set", "probe", map[string]ir.Value{
			"MYSQL_5_6":                      eaS("*"),
			"MYSQL_5_7":                      eaS("*"),
			"POSTGRES_10":                    eaS("*"),
			"POSTGRES_11":                    eaS("*"),
			"POSTGRES_9_6":                   eaS("*"),
			"SQLSERVER_2017_ENTERPRISE":      eaS("*"),
			"SQLSERVER_2017_STANDARD":        eaS("*"),
			"absent":                         eaS("*"),
			"access":                         eaS("*"),
			"acl":                            eaS("*"),
			"admin":                          eaS("*"),
			"allauthenticatedusers":          eaS("*"),
			"allusers":                       eaS("*"),
			"authorized_networks":            eaS("*"),
			"auto_upgrade":                   eaS("*"),
			"backup_configuration":           eaS("*"),
			"binary_authorization":           eaS("*"),
			"cors":                           eaS("*"),
			"database_flags":                 eaS("*"),
			"database_version":               eaS("*"),
			"dataeditor":                     eaS("*"),
			"dataviewer":                     eaS("*"),
			"default_kms_key_name":           eaS("*"),
			"default_table_expiration_ms":    eaS("*"),
			"deletion_protection":            eaS("*"),
			"domain":                         eaS("*"),
			"encryption":                     eaS("*"),
			"encryption_configuration":       eaS("*"),
			"enforced":                       eaS("*"),
			"force_destroy":                  eaS("*"),
			"group_by_email":                 eaS("*"),
			"host":                           eaS("*"),
			"ip_configuration":               eaS("*"),
			"lifecycle_rule":                 eaS("*"),
			"local_infile":                   eaS("*"),
			"log_disconnections":             eaS("*"),
			"logging":                        eaS("*"),
			"maintenance_window":             eaS("*"),
			"management":                     eaS("*"),
			"member":                         eaS("*"),
			"members":                        eaS("*"),
			"name":                           eaS("*"),
			"off":                            eaS("*"),
			"on":                             eaS("*"),
			"origin":                         eaS("*"),
			"point_in_time_recovery_enabled": eaS("*"),
			"predefined_acl":                 eaS("*"),
			"public_access_prevention":       eaS("*"),
			"publicread":                     eaS("*"),
			"publicreadwrite":                eaS("*"),
			"role":                           eaS("*"),
			"role_entity":                    eaS("*"),
			"settings":                       eaS("*"),
			"special_group":                  eaS("*"),
			"user_by_email":                  eaS("*"),
			"value":                          eaS("*"),
			"website":                        eaS("*"),
			"workload_identity_config":       eaS("*"),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-092: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-092: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-092: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_dns_record_set", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-092: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_dns_record_set", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"auto_upgrade":                   eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"management":                     eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-092: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_094(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-094")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_pubsub_topic", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-094: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-094: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-094: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_pubsub_topic", "probe", map[string]ir.Value{
			"MYSQL_5_6":                      eaS("public"),
			"MYSQL_5_7":                      eaS("public"),
			"POSTGRES_10":                    eaS("public"),
			"POSTGRES_11":                    eaS("public"),
			"POSTGRES_9_6":                   eaS("public"),
			"SQLSERVER_2017_ENTERPRISE":      eaS("public"),
			"SQLSERVER_2017_STANDARD":        eaS("public"),
			"absent":                         eaS("public"),
			"access":                         eaS("Allow"),
			"acl":                            eaS("public"),
			"admin":                          eaB(true),
			"allauthenticatedusers":          eaS("public"),
			"allusers":                       eaS("public"),
			"authorized_networks":            eaS("public"),
			"backup_configuration":           eaB(false),
			"binary_authorization":           eaS("public"),
			"cors":                           eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))),
			"database_flags":                 eaS("public"),
			"database_version":               eaS(">= 1.0"),
			"dataeditor":                     eaS("public"),
			"dataviewer":                     eaS("public"),
			"default_kms_key_name":           eaS("my_password"),
			"default_table_expiration_ms":    eaS("public"),
			"deletion_protection":            eaB(false),
			"domain":                         eaS("public"),
			"encryption":                     eaB(false),
			"encryption_configuration":       eaB(false),
			"enforced":                       eaB(false),
			"force_destroy":                  eaS("public"),
			"group_by_email":                 eaS("alice@example.com"),
			"host":                           eaS("public"),
			"ip_configuration":               eaS("public"),
			"lifecycle_rule":                 eaS("public"),
			"local_infile":                   eaS("public"),
			"log_disconnections":             eaB(false),
			"logging":                        eaB(false),
			"maintenance_window":             eaS("public"),
			"management":                     eaS("public"),
			"member":                         eaS("allUsers"),
			"members":                        eaL(eaS("allUsers")),
			"message_retention_duration":     eaN(1.0),
			"name":                           eaS("my_password"),
			"off":                            eaS("public"),
			"on":                             eaS("public"),
			"origin":                         eaS("public"),
			"point_in_time_recovery_enabled": eaB(false),
			"predefined_acl":                 eaS("public"),
			"public_access_prevention":       eaS("Allow"),
			"publicread":                     eaB(true),
			"publicreadwrite":                eaB(true),
			"role":                           eaS("roles/storage.objectViewer"),
			"role_entity":                    eaS("roles/owner"),
			"settings":                       eaS("public"),
			"special_group":                  eaS("public"),
			"user_by_email":                  eaS("alice@example.com"),
			"value":                          eaS("public"),
			"website":                        eaS("public"),
			"workload_identity_config":       eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-094: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_pubsub_topic", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"management":                     eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"message_retention_duration":     eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-094: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_095(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-095")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_pubsub_subscription", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-095: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-095: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-095: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_pubsub_subscription", "probe", map[string]ir.Value{
			"MYSQL_5_6":                      eaS("public"),
			"MYSQL_5_7":                      eaS("public"),
			"POSTGRES_10":                    eaS("public"),
			"POSTGRES_11":                    eaS("public"),
			"POSTGRES_9_6":                   eaS("public"),
			"SQLSERVER_2017_ENTERPRISE":      eaS("public"),
			"SQLSERVER_2017_STANDARD":        eaS("public"),
			"absent":                         eaS("public"),
			"access":                         eaS("Allow"),
			"acl":                            eaS("public"),
			"admin":                          eaB(true),
			"allauthenticatedusers":          eaS("public"),
			"allusers":                       eaS("public"),
			"authorized_networks":            eaS("public"),
			"backup_configuration":           eaB(false),
			"binary_authorization":           eaS("public"),
			"cors":                           eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))),
			"database_flags":                 eaS("public"),
			"database_version":               eaS(">= 1.0"),
			"dataeditor":                     eaS("public"),
			"dataviewer":                     eaS("public"),
			"dead_letter_policy":             eaS("{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":\"*\",\"Action\":\"*\",\"Resource\":\"*\"}]}"),
			"default_kms_key_name":           eaS("my_password"),
			"default_table_expiration_ms":    eaS("public"),
			"deletion_protection":            eaB(false),
			"domain":                         eaS("public"),
			"encryption":                     eaB(false),
			"encryption_configuration":       eaB(false),
			"enforced":                       eaB(false),
			"force_destroy":                  eaS("public"),
			"group_by_email":                 eaS("alice@example.com"),
			"host":                           eaS("public"),
			"ip_configuration":               eaS("public"),
			"lifecycle_rule":                 eaS("public"),
			"local_infile":                   eaS("public"),
			"log_disconnections":             eaB(false),
			"logging":                        eaB(false),
			"maintenance_window":             eaS("public"),
			"management":                     eaS("public"),
			"member":                         eaS("allUsers"),
			"members":                        eaL(eaS("allUsers")),
			"name":                           eaS("my_password"),
			"off":                            eaS("public"),
			"on":                             eaS("public"),
			"origin":                         eaS("public"),
			"point_in_time_recovery_enabled": eaB(false),
			"predefined_acl":                 eaS("public"),
			"public_access_prevention":       eaS("Allow"),
			"publicread":                     eaB(true),
			"publicreadwrite":                eaB(true),
			"role":                           eaS("roles/storage.objectViewer"),
			"role_entity":                    eaS("roles/owner"),
			"settings":                       eaS("public"),
			"special_group":                  eaS("public"),
			"user_by_email":                  eaS("alice@example.com"),
			"value":                          eaS("public"),
			"website":                        eaS("public"),
			"workload_identity_config":       eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-095: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_pubsub_subscription", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"dead_letter_policy":             eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"management":                     eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-095: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_098(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-098")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_cloudfunctions2_function", "probe", map[string]ir.Value{}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-098: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-098: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-098: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_cloudfunctions2_function", "probe", map[string]ir.Value{
			"MYSQL_5_6":                      eaS("public"),
			"MYSQL_5_7":                      eaS("public"),
			"POSTGRES_10":                    eaS("public"),
			"POSTGRES_11":                    eaS("public"),
			"POSTGRES_9_6":                   eaS("public"),
			"SQLSERVER_2017_ENTERPRISE":      eaS("public"),
			"SQLSERVER_2017_STANDARD":        eaS("public"),
			"absent":                         eaS("public"),
			"access":                         eaS("Allow"),
			"acl":                            eaS("public"),
			"admin":                          eaB(true),
			"allauthenticatedusers":          eaS("public"),
			"allusers":                       eaS("public"),
			"authorized_networks":            eaS("public"),
			"backup_configuration":           eaB(false),
			"binary_authorization":           eaS("public"),
			"cors":                           eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))),
			"database_flags":                 eaS("public"),
			"database_version":               eaS(">= 1.0"),
			"dataeditor":                     eaS("public"),
			"dataviewer":                     eaS("public"),
			"default_kms_key_name":           eaS("my_password"),
			"default_table_expiration_ms":    eaS("public"),
			"deletion_protection":            eaB(false),
			"domain":                         eaS("public"),
			"encryption":                     eaB(false),
			"encryption_configuration":       eaB(false),
			"enforced":                       eaB(false),
			"force_destroy":                  eaS("public"),
			"group_by_email":                 eaS("alice@example.com"),
			"host":                           eaS("public"),
			"ip_configuration":               eaS("public"),
			"lifecycle_rule":                 eaS("public"),
			"local_infile":                   eaS("public"),
			"log_disconnections":             eaB(false),
			"logging":                        eaB(false),
			"maintenance_window":             eaS("public"),
			"management":                     eaS("public"),
			"max_instances":                  eaS("public"),
			"member":                         eaS("allUsers"),
			"members":                        eaL(eaS("allUsers")),
			"name":                           eaS("my_password"),
			"off":                            eaS("public"),
			"on":                             eaS("public"),
			"origin":                         eaS("public"),
			"point_in_time_recovery_enabled": eaB(false),
			"predefined_acl":                 eaS("public"),
			"public_access_prevention":       eaS("Allow"),
			"publicread":                     eaB(true),
			"publicreadwrite":                eaB(true),
			"role":                           eaS("roles/storage.objectViewer"),
			"role_entity":                    eaS("roles/owner"),
			"settings":                       eaS("public"),
			"special_group":                  eaS("public"),
			"user_by_email":                  eaS("alice@example.com"),
			"value":                          eaS("public"),
			"website":                        eaS("public"),
			"workload_identity_config":       eaS("public"),
		}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-098: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_cloudfunctions2_function", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"backup_configuration":           eaU(),
		"binary_authorization":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"management":                     eaU(),
		"max_instances":                  eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"settings":                       eaU(),
		"special_group":                  eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
		"workload_identity_config":       eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-098: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}
func TestEffectivenessReplay_GCP_099(t *testing.T) {
	rule := eaRuleFor(t, "AEGIS-GCP-099")
	// Positive: black-box probe witness (must fire).
	pos := []ir.Resource{
		eaRes("google_cloud_run_service", "probe", map[string]ir.Value{
			"template": eaL(eaM("MYSQL_5_6", eaS("public"), "MYSQL_5_7", eaS("public"), "POSTGRES_10", eaS("public"), "POSTGRES_11", eaS("public"), "POSTGRES_9_6", eaS("public"), "SQLSERVER_2017_ENTERPRISE", eaS("public"), "SQLSERVER_2017_STANDARD", eaS("public"), "absent", eaS("public"), "access", eaS("Allow"), "acl", eaS("public"), "admin", eaB(true), "allauthenticatedusers", eaS("public"), "allusers", eaS("public"), "authorized_networks", eaS("public"), "backup_configuration", eaB(false), "cors", eaL(eaM("allow_origins", eaL(eaS("*")), "origin", eaL(eaS("*")))), "database_flags", eaS("public"), "database_version", eaS(">= 1.0"), "dataeditor", eaS("public"), "dataviewer", eaS("public"), "default_kms_key_name", eaS("my_password"), "default_table_expiration_ms", eaS("public"), "deletion_protection", eaB(false), "domain", eaS("public"), "encryption", eaB(false), "encryption_configuration", eaB(false), "enforced", eaB(false), "force_destroy", eaS("public"), "group_by_email", eaS("alice@example.com"), "host", eaS("public"), "ip_configuration", eaS("public"), "lifecycle_rule", eaS("public"), "local_infile", eaS("public"), "log_disconnections", eaB(false), "logging", eaB(false), "maintenance_window", eaS("public"), "member", eaS("allUsers"), "members", eaL(eaS("allUsers")), "name", eaS("my_password"), "off", eaS("public"), "on", eaS("public"), "origin", eaS("public"), "point_in_time_recovery_enabled", eaB(false), "predefined_acl", eaS("public"), "public_access_prevention", eaS("Allow"), "publicread", eaB(true), "publicreadwrite", eaB(true), "role", eaS("roles/storage.objectViewer"), "role_entity", eaS("roles/owner"), "service_account", eaN(0.0), "service_account_name", eaS("my_password"), "settings", eaS("public"), "spec", eaS("public"), "special_group", eaS("public"), "template", eaS("public"), "user_by_email", eaS("alice@example.com"), "value", eaS("public"), "website", eaS("public"))),
		}),
	}
	f := eaRun(rule, pos...)
	if len(f) == 0 {
		t.Fatalf("AEGIS-GCP-099: expected >=1 finding on positive witness, got 0")
	}
	if f[0].Severity != rule.Severity() {
		t.Fatalf("AEGIS-GCP-099: severity = %s, want %s", f[0].Severity, rule.Severity())
	}
	if f[0].Evidence.Attribute == "" || f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatalf("AEGIS-GCP-099: evidence must be non-empty, got %v", f[0].Evidence)
	}
	// Negative: black-box probe witness (must stay quiet).
	neg := []ir.Resource{
		eaRes("google_cloud_run_service", "probe", map[string]ir.Value{}),
	}
	if got := eaRun(rule, neg...); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-099: expected 0 findings on negative witness, got %d: %v", len(got), got)
	}
	// Unknown: all-unknown kitchen-sink input must stay quiet.
	unk := eaRes("google_cloud_run_service", "probe", map[string]ir.Value{
		"MYSQL_5_6":                      eaU(),
		"MYSQL_5_7":                      eaU(),
		"POSTGRES_10":                    eaU(),
		"POSTGRES_11":                    eaU(),
		"POSTGRES_9_6":                   eaU(),
		"SQLSERVER_2017_ENTERPRISE":      eaU(),
		"SQLSERVER_2017_STANDARD":        eaU(),
		"absent":                         eaU(),
		"access":                         eaU(),
		"acl":                            eaU(),
		"admin":                          eaU(),
		"allauthenticatedusers":          eaU(),
		"allusers":                       eaU(),
		"authorized_networks":            eaU(),
		"backup_configuration":           eaU(),
		"cors":                           eaU(),
		"database_flags":                 eaU(),
		"database_version":               eaU(),
		"dataeditor":                     eaU(),
		"dataviewer":                     eaU(),
		"default_kms_key_name":           eaU(),
		"default_table_expiration_ms":    eaU(),
		"deletion_protection":            eaU(),
		"domain":                         eaU(),
		"encryption":                     eaU(),
		"encryption_configuration":       eaU(),
		"enforced":                       eaU(),
		"false":                          eaU(),
		"force_destroy":                  eaU(),
		"group_by_email":                 eaU(),
		"host":                           eaU(),
		"ip_configuration":               eaU(),
		"lifecycle_rule":                 eaU(),
		"local_infile":                   eaU(),
		"log_disconnections":             eaU(),
		"logging":                        eaU(),
		"maintenance_window":             eaU(),
		"member":                         eaU(),
		"members":                        eaU(),
		"name":                           eaU(),
		"off":                            eaU(),
		"on":                             eaU(),
		"origin":                         eaU(),
		"point_in_time_recovery_enabled": eaU(),
		"predefined_acl":                 eaU(),
		"public_access_prevention":       eaU(),
		"publicread":                     eaU(),
		"publicreadwrite":                eaU(),
		"role":                           eaU(),
		"role_entity":                    eaU(),
		"service_account":                eaU(),
		"service_account_name":           eaU(),
		"settings":                       eaU(),
		"spec":                           eaU(),
		"special_group":                  eaU(),
		"template":                       eaU(),
		"true":                           eaU(),
		"user_by_email":                  eaU(),
		"value":                          eaU(),
		"website":                        eaU(),
	})
	if got := eaRun(rule, unk); len(got) != 0 {
		t.Fatalf("AEGIS-GCP-099: expected 0 findings on unknown input, got %d: %v", len(got), got)
	}
}

// AEGIS-GCP-164 (FIXED: unknown node_config used to fire via the
// nodeConfigMetaString helper conflating unknown with absent): GKE cluster
// nodes with legacy metadata endpoints enabled.
func TestEffectiveness_GCP164_GKELegacyMetadata_UnknownQuiet(t *testing.T) {
	pos := res("google_container_cluster", "c", map[string]ir.Value{
		"node_config": blks(2, blk("metadata", eaMapVal(map[string]ir.Value{}, 3))),
	})
	if got := runRule(gkeLegacyMetadataEndpoints{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding for absent disable-legacy-endpoints, got %d", len(got))
	}
	neg := res("google_container_cluster", "c", map[string]ir.Value{
		"node_config": blks(2, blk("metadata", eaMapVal(map[string]ir.Value{
			"disable-legacy-endpoints": ks("true", 4),
		}, 3))),
	})
	if got := runRule(gkeLegacyMetadataEndpoints{}, neg); len(got) != 0 {
		t.Fatalf("disable-legacy-endpoints=true must be quiet, got %d", len(got))
	}
	unk := res("google_container_cluster", "c", map[string]ir.Value{"node_config": ku(2)})
	if got := runRule(gkeLegacyMetadataEndpoints{}, unk); len(got) != 0 {
		t.Fatalf("unknown node_config must be quiet, got %d", len(got))
	}
	unkMeta := res("google_container_cluster", "c", map[string]ir.Value{
		"node_config": blks(2, blk("metadata", ku(3))),
	})
	if got := runRule(gkeLegacyMetadataEndpoints{}, unkMeta); len(got) != 0 {
		t.Fatalf("unknown metadata must be quiet, got %d", len(got))
	}
}

// AEGIS-GCP-171 (FIXED: same helper as 164): GKE node pool with legacy
// metadata endpoints enabled.
func TestEffectiveness_GCP171_GKENodePoolLegacyMetadata_UnknownQuiet(t *testing.T) {
	pos := res("google_container_node_pool", "p", map[string]ir.Value{
		"node_config": blks(2, blk("metadata", eaMapVal(map[string]ir.Value{}, 3))),
	})
	if got := runRule(gkeNodePoolLegacyMetadata{}, pos); len(got) != 1 {
		t.Fatalf("expected 1 finding for absent disable-legacy-endpoints, got %d", len(got))
	}
	neg := res("google_container_node_pool", "p", map[string]ir.Value{
		"node_config": blks(2, blk("metadata", eaMapVal(map[string]ir.Value{
			"disable-legacy-endpoints": ks("true", 4),
		}, 3))),
	})
	if got := runRule(gkeNodePoolLegacyMetadata{}, neg); len(got) != 0 {
		t.Fatalf("disable-legacy-endpoints=true must be quiet, got %d", len(got))
	}
	unk := res("google_container_node_pool", "p", map[string]ir.Value{"node_config": ku(2)})
	if got := runRule(gkeNodePoolLegacyMetadata{}, unk); len(got) != 0 {
		t.Fatalf("unknown node_config must be quiet, got %d", len(got))
	}
}

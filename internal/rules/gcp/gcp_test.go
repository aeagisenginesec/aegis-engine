package gcp

import (
	"testing"

	"aegis/internal/ir"
)

// Shared test fixtures for the GCP rule pack.

func spanAt(line int) ir.Span {
	return ir.Span{File: "test.tf", StartLine: line, StartCol: 1, EndLine: line, EndCol: 20}
}

func kv(b bool, line int) ir.Value { return ir.Value{Raw: b, Known: true, Span: spanAt(line)} }
func ks(s string, line int) ir.Value {
	return ir.Value{Raw: s, Known: true, Span: spanAt(line)}
}
func ku(line int) ir.Value { return ir.Value{Known: false, Span: spanAt(line)} }

func strList(line int, items ...string) ir.Value {
	vals := make([]ir.Value, len(items))
	for i, s := range items {
		vals[i] = ks(s, line)
	}
	return ir.Value{Raw: vals, Known: true, Span: spanAt(line)}
}

func blk(pairs ...any) map[string]ir.Value {
	m := map[string]ir.Value{}
	for i := 0; i+1 < len(pairs); i += 2 {
		m[pairs[i].(string)] = pairs[i+1].(ir.Value)
	}
	return m
}

func blks(line int, maps ...map[string]ir.Value) ir.Value {
	vals := make([]ir.Value, len(maps))
	for i, m := range maps {
		vals[i] = ir.Value{Raw: m, Known: true, Span: spanAt(line)}
	}
	return ir.Value{Raw: vals, Known: true, Span: spanAt(line)}
}

func res(typ, name string, attrs map[string]ir.Value) ir.Resource {
	return ir.Resource{
		Type:       typ,
		Name:       name,
		Provider:   "google",
		Attributes: attrs,
		Span:       spanAt(1),
	}
}

func runRule(rule ir.Rule, resources ...ir.Resource) []ir.Finding {
	var out []ir.Finding
	for _, r := range resources {
		if rule.AppliesTo(r.Type) {
			out = append(out, rule.Check(r)...)
		}
	}
	return out
}

func mustFinding(t *testing.T, f []ir.Finding, ruleID string) ir.Finding {
	t.Helper()
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(f), f)
	}
	if f[0].RuleID != ruleID {
		t.Fatalf("wrong rule ID: %s", f[0].RuleID)
	}
	if f[0].Resource == "" || f[0].Evidence.Attribute == "" {
		t.Fatal("finding must carry resource and evidence attribute")
	}
	if f[0].Evidence.Actual == "" || f[0].Evidence.Expected == "" {
		t.Fatal("evidence must carry actual and expected")
	}
	if f[0].Evidence.Span.File == "" {
		t.Fatal("evidence must carry a span")
	}
	return f[0]
}

// ---------------------------------------------------------------------------
// Pack registration
// ---------------------------------------------------------------------------

func TestRulesInIDOrder(t *testing.T) {
	rules := Rules()
	want := []string{
		"AEGIS-GCP-001", "AEGIS-GCP-002", "AEGIS-GCP-003", "AEGIS-GCP-004",
		"AEGIS-GCP-005", "AEGIS-GCP-006", "AEGIS-GCP-007", "AEGIS-GCP-008",
		"AEGIS-GCP-009", "AEGIS-GCP-011", "AEGIS-GCP-012",
		"AEGIS-GCP-013", "AEGIS-GCP-014", "AEGIS-GCP-015", "AEGIS-GCP-016",
		"AEGIS-GCP-017", "AEGIS-GCP-018", "AEGIS-GCP-019", "AEGIS-GCP-020",
		"AEGIS-GCP-021", "AEGIS-GCP-022", "AEGIS-GCP-023", "AEGIS-GCP-024",
		"AEGIS-GCP-025", "AEGIS-GCP-026", "AEGIS-GCP-027", "AEGIS-GCP-028",
		"AEGIS-GCP-029", "AEGIS-GCP-030", "AEGIS-GCP-031", "AEGIS-GCP-032",
		"AEGIS-GCP-033", "AEGIS-GCP-034", "AEGIS-GCP-035", "AEGIS-GCP-036",
		"AEGIS-GCP-037", "AEGIS-GCP-038", "AEGIS-GCP-039", "AEGIS-GCP-040",
		"AEGIS-GCP-041", "AEGIS-GCP-042", "AEGIS-GCP-043", "AEGIS-GCP-044",
		"AEGIS-GCP-045", "AEGIS-GCP-046", "AEGIS-GCP-047",
		"AEGIS-GCP-049", "AEGIS-GCP-050", "AEGIS-GCP-051", "AEGIS-GCP-052",
		"AEGIS-GCP-053", "AEGIS-GCP-054", "AEGIS-GCP-055", "AEGIS-GCP-056",
		"AEGIS-GCP-057", "AEGIS-GCP-058", "AEGIS-GCP-059", "AEGIS-GCP-060",
		"AEGIS-GCP-061", "AEGIS-GCP-062", "AEGIS-GCP-064",
		"AEGIS-GCP-065", "AEGIS-GCP-066", "AEGIS-GCP-067", "AEGIS-GCP-068",
		"AEGIS-GCP-069", "AEGIS-GCP-070", "AEGIS-GCP-071", "AEGIS-GCP-072",
		"AEGIS-GCP-073", "AEGIS-GCP-074", "AEGIS-GCP-075", "AEGIS-GCP-076",
		"AEGIS-GCP-077", "AEGIS-GCP-078", "AEGIS-GCP-079", "AEGIS-GCP-080",
		"AEGIS-GCP-081", "AEGIS-GCP-082", "AEGIS-GCP-083", "AEGIS-GCP-084",
		"AEGIS-GCP-085", "AEGIS-GCP-086", "AEGIS-GCP-087", "AEGIS-GCP-088",
		"AEGIS-GCP-089", "AEGIS-GCP-090", "AEGIS-GCP-091", "AEGIS-GCP-092",
		"AEGIS-GCP-093", "AEGIS-GCP-094", "AEGIS-GCP-095", "AEGIS-GCP-096",
		"AEGIS-GCP-097", "AEGIS-GCP-098", "AEGIS-GCP-099", "AEGIS-GCP-100",
		"AEGIS-GCP-101", "AEGIS-GCP-102", "AEGIS-GCP-103", "AEGIS-GCP-104",
		"AEGIS-GCP-105", "AEGIS-GCP-106", "AEGIS-GCP-107", "AEGIS-GCP-108",
		"AEGIS-GCP-109", "AEGIS-GCP-111",
		"AEGIS-GCP-113", "AEGIS-GCP-114", "AEGIS-GCP-115", "AEGIS-GCP-116",
		"AEGIS-GCP-117", "AEGIS-GCP-120",
		"AEGIS-GCP-123", "AEGIS-GCP-124", "AEGIS-GCP-125", "AEGIS-GCP-126",
		"AEGIS-GCP-127", "AEGIS-GCP-128", "AEGIS-GCP-129", "AEGIS-GCP-130",
		"AEGIS-GCP-131", "AEGIS-GCP-132", "AEGIS-GCP-133", "AEGIS-GCP-134",
		"AEGIS-GCP-135", "AEGIS-GCP-136", "AEGIS-GCP-137", "AEGIS-GCP-138",
		"AEGIS-GCP-139", "AEGIS-GCP-140", "AEGIS-GCP-141", "AEGIS-GCP-142",
		"AEGIS-GCP-143", "AEGIS-GCP-144", "AEGIS-GCP-145", "AEGIS-GCP-146",
		"AEGIS-GCP-147", "AEGIS-GCP-148", "AEGIS-GCP-149", "AEGIS-GCP-150",
		"AEGIS-GCP-151", "AEGIS-GCP-152", "AEGIS-GCP-153", "AEGIS-GCP-154",
		"AEGIS-GCP-155", "AEGIS-GCP-156", "AEGIS-GCP-157", "AEGIS-GCP-158",
		"AEGIS-GCP-159", "AEGIS-GCP-160", "AEGIS-GCP-161", "AEGIS-GCP-162",
		"AEGIS-GCP-163", "AEGIS-GCP-164", "AEGIS-GCP-165", "AEGIS-GCP-166",
		"AEGIS-GCP-167", "AEGIS-GCP-168", "AEGIS-GCP-169", "AEGIS-GCP-170",
		"AEGIS-GCP-171", "AEGIS-GCP-172", "AEGIS-GCP-173", "AEGIS-GCP-174",
		"AEGIS-GCP-175", "AEGIS-GCP-176", "AEGIS-GCP-177", "AEGIS-GCP-178",
		"AEGIS-GCP-179", "AEGIS-GCP-180", "AEGIS-GCP-181", "AEGIS-GCP-182",
		"AEGIS-GCP-183", "AEGIS-GCP-184", "AEGIS-GCP-185", "AEGIS-GCP-186",
		"AEGIS-GCP-187", "AEGIS-GCP-188", "AEGIS-GCP-189", "AEGIS-GCP-190",
		"AEGIS-GCP-191", "AEGIS-GCP-192", "AEGIS-GCP-193", "AEGIS-GCP-194",
		"AEGIS-GCP-196", "AEGIS-GCP-197", "AEGIS-GCP-198", "AEGIS-GCP-199",
		"AEGIS-GCP-200", "AEGIS-GCP-201", "AEGIS-GCP-202", "AEGIS-GCP-203",
		"AEGIS-GCP-204", "AEGIS-GCP-205", "AEGIS-GCP-206", "AEGIS-GCP-207",
		"AEGIS-GCP-208", "AEGIS-GCP-209", "AEGIS-GCP-210", "AEGIS-GCP-211",
		"AEGIS-GCP-212", "AEGIS-GCP-213", "AEGIS-GCP-214", "AEGIS-GCP-215",
		"AEGIS-GCP-216", "AEGIS-GCP-217", "AEGIS-GCP-218", "AEGIS-GCP-219",
		"AEGIS-GCP-220", "AEGIS-GCP-221", "AEGIS-GCP-222", "AEGIS-GCP-223",
		"AEGIS-GCP-224", "AEGIS-GCP-225", "AEGIS-GCP-226", "AEGIS-GCP-227",
		"AEGIS-GCP-228", "AEGIS-GCP-229", "AEGIS-GCP-230", "AEGIS-GCP-231",
		"AEGIS-GCP-232", "AEGIS-GCP-233", "AEGIS-GCP-234", "AEGIS-GCP-235",
		"AEGIS-GCP-236", "AEGIS-GCP-237", "AEGIS-GCP-238", "AEGIS-GCP-239",
		"AEGIS-GCP-240", "AEGIS-GCP-241", "AEGIS-GCP-242", "AEGIS-GCP-243",
		"AEGIS-GCP-244", "AEGIS-GCP-245", "AEGIS-GCP-246", "AEGIS-GCP-247",
		"AEGIS-GCP-248", "AEGIS-GCP-249", "AEGIS-GCP-250", "AEGIS-GCP-251",
		"AEGIS-GCP-252", "AEGIS-GCP-253", "AEGIS-GCP-254", "AEGIS-GCP-255",
		"AEGIS-GCP-256", "AEGIS-GCP-257", "AEGIS-GCP-258", "AEGIS-GCP-259",
		"AEGIS-GCP-260", "AEGIS-GCP-261", "AEGIS-GCP-262", "AEGIS-GCP-263",
		"AEGIS-GCP-264", "AEGIS-GCP-265", "AEGIS-GCP-266", "AEGIS-GCP-267",
		"AEGIS-GCP-268", "AEGIS-GCP-270", "AEGIS-GCP-271", "AEGIS-GCP-273",
		"AEGIS-GCP-274", "AEGIS-GCP-275", "AEGIS-GCP-276", "AEGIS-GCP-277",
		"AEGIS-GCP-278", "AEGIS-GCP-279", "AEGIS-GCP-282", "AEGIS-GCP-284",
		"AEGIS-GCP-285", "AEGIS-GCP-286", "AEGIS-GCP-288", "AEGIS-GCP-289",
		"AEGIS-GCP-290", "AEGIS-GCP-291", "AEGIS-GCP-292",
		"AEGIS-GCP-293", "AEGIS-GCP-294",
	}
	if len(rules) != len(want) {
		t.Fatalf("expected %d rules, got %d", len(want), len(rules))
	}
	for i, w := range want {
		if rules[i].ID() != w {
			t.Fatalf("rule %d: want %s, got %s", i, w, rules[i].ID())
		}
		if rules[i].Title() == "" || rules[i].Description() == "" {
			t.Fatalf("rule %s missing title/description", w)
		}
	}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-001
// ---------------------------------------------------------------------------

func TestBucketPublicIAM_BindingFires(t *testing.T) {
	r := res("google_storage_bucket_iam_binding", "public", map[string]ir.Value{
		"role":    ks("roles/storage.objectViewer", 3),
		"members": strList(4, "user:alice@example.com", "allUsers"),
	})
	f := mustFinding(t, runRule(bucketPublicIAM{}, r), "AEGIS-GCP-001")
	if f.Severity != ir.SeverityCritical {
		t.Fatalf("wrong severity: %s", f.Severity)
	}
}

func TestBucketPublicIAM_MemberFires(t *testing.T) {
	r := res("google_storage_bucket_iam_member", "public", map[string]ir.Value{
		"role":   ks("roles/storage.admin", 3),
		"member": ks("allAuthenticatedUsers", 4),
	})
	mustFinding(t, runRule(bucketPublicIAM{}, r), "AEGIS-GCP-001")
}

func TestBucketPublicIAM_PrivateRoleOK(t *testing.T) {
	r := res("google_storage_bucket_iam_binding", "private", map[string]ir.Value{
		"role":    ks("roles/storage.objectCreator", 3),
		"members": strList(4, "allUsers"),
	})
	if f := runRule(bucketPublicIAM{}, r); len(f) != 0 {
		t.Fatalf("non-read role must not fire, got %d", len(f))
	}
}

func TestBucketPublicIAM_NoPublicMembersOK(t *testing.T) {
	r := res("google_storage_bucket_iam_binding", "team", map[string]ir.Value{
		"role":    ks("roles/storage.objectViewer", 3),
		"members": strList(4, "group:eng@example.com"),
	})
	if f := runRule(bucketPublicIAM{}, r); len(f) != 0 {
		t.Fatalf("no public members must not fire, got %d", len(f))
	}
}

func TestBucketPublicIAM_UnknownRoleNoFinding(t *testing.T) {
	r := res("google_storage_bucket_iam_binding", "public", map[string]ir.Value{
		"role":    ku(3),
		"members": strList(4, "allUsers"),
	})
	if f := runRule(bucketPublicIAM{}, r); len(f) != 0 {
		t.Fatalf("unknown role must not fire, got %d", len(f))
	}
}

func TestBucketPublicIAM_UnknownMembersNoFinding(t *testing.T) {
	r := res("google_storage_bucket_iam_binding", "public", map[string]ir.Value{
		"role":    ks("roles/storage.objectViewer", 3),
		"members": ku(4),
	})
	if f := runRule(bucketPublicIAM{}, r); len(f) != 0 {
		t.Fatalf("unknown members must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-002
// ---------------------------------------------------------------------------

func TestFirewallOpenToWorld_Fires(t *testing.T) {
	r := res("google_compute_firewall", "open", map[string]ir.Value{
		"source_ranges": strList(3, "0.0.0.0/0"),
		"allow":         blks(4, blk("protocol", ks("tcp", 5), "ports", strList(6, "22"))),
	})
	f := mustFinding(t, runRule(firewallOpenToWorld{}, r), "AEGIS-GCP-002")
	if f.Severity != ir.SeverityHigh {
		t.Fatalf("wrong severity: %s", f.Severity)
	}
}

func TestFirewallOpenToWorld_RestrictedOK(t *testing.T) {
	r := res("google_compute_firewall", "internal", map[string]ir.Value{
		"source_ranges": strList(3, "10.0.0.0/8"),
		"allow":         blks(4, blk("protocol", ks("tcp", 5))),
	})
	if f := runRule(firewallOpenToWorld{}, r); len(f) != 0 {
		t.Fatalf("restricted ranges must not fire, got %d", len(f))
	}
}

func TestFirewallOpenToWorld_DenyOnlyOK(t *testing.T) {
	r := res("google_compute_firewall", "deny", map[string]ir.Value{
		"source_ranges": strList(3, "0.0.0.0/0"),
		"deny":          blks(4, blk("protocol", ks("tcp", 5))),
	})
	if f := runRule(firewallOpenToWorld{}, r); len(f) != 0 {
		t.Fatalf("deny-only firewall must not fire, got %d", len(f))
	}
}

func TestFirewallOpenToWorld_UnknownRangesNoFinding(t *testing.T) {
	r := res("google_compute_firewall", "open", map[string]ir.Value{
		"source_ranges": ku(3),
		"allow":         blks(4, blk("protocol", ks("tcp", 5))),
	})
	if f := runRule(firewallOpenToWorld{}, r); len(f) != 0 {
		t.Fatalf("unknown ranges must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-003
// ---------------------------------------------------------------------------

func sqlInstance(backupEnabled ir.Value) ir.Resource {
	return res("google_sql_database_instance", "db", map[string]ir.Value{
		"settings": blks(2, blk(
			"backup_configuration", blks(3, blk("enabled", backupEnabled)),
		)),
	})
}

func TestSQLNoAutomatedBackups_Fires(t *testing.T) {
	f := mustFinding(t, runRule(sqlNoAutomatedBackups{}, sqlInstance(kv(false, 4))), "AEGIS-GCP-003")
	if f.Severity != ir.SeverityMedium {
		t.Fatalf("wrong severity: %s", f.Severity)
	}
}

func TestSQLNoAutomatedBackups_EnabledOK(t *testing.T) {
	if f := runRule(sqlNoAutomatedBackups{}, sqlInstance(kv(true, 4))); len(f) != 0 {
		t.Fatalf("enabled backups must not fire, got %d", len(f))
	}
}

func TestSQLNoAutomatedBackups_UnknownNoFinding(t *testing.T) {
	if f := runRule(sqlNoAutomatedBackups{}, sqlInstance(ku(4))); len(f) != 0 {
		t.Fatalf("unknown enabled must not fire, got %d", len(f))
	}
}

func TestSQLNoAutomatedBackups_NoSettingsNoFinding(t *testing.T) {
	r := res("google_sql_database_instance", "db", nil)
	if f := runRule(sqlNoAutomatedBackups{}, r); len(f) != 0 {
		t.Fatalf("absent settings must not fire, got %d", len(f))
	}
}

// ---------------------------------------------------------------------------
// AEGIS-GCP-004
// ---------------------------------------------------------------------------

func TestGKENoAuthorizedNetworks_Fires(t *testing.T) {
	r := res("google_container_cluster", "prod", map[string]ir.Value{
		"location": ks("us-central1", 2),
	})
	f := mustFinding(t, runRule(gkeNoAuthorizedNetworks{}, r), "AEGIS-GCP-004")
	if f.Severity != ir.SeverityMedium {
		t.Fatalf("wrong severity: %s", f.Severity)
	}
}

func TestGKENoAuthorizedNetworks_ConfiguredOK(t *testing.T) {
	r := res("google_container_cluster", "prod", map[string]ir.Value{
		"master_authorized_networks_config": blks(2, blk(
			"cidr_blocks", blks(3, blk("cidr_block", ks("10.0.0.0/8", 4))),
		)),
	})
	if f := runRule(gkeNoAuthorizedNetworks{}, r); len(f) != 0 {
		t.Fatalf("configured networks must not fire, got %d", len(f))
	}
}

func TestGKENoAuthorizedNetworks_UnknownNoFinding(t *testing.T) {
	r := res("google_container_cluster", "prod", map[string]ir.Value{
		"master_authorized_networks_config": ku(2),
	})
	if f := runRule(gkeNoAuthorizedNetworks{}, r); len(f) != 0 {
		t.Fatalf("unknown config must not fire, got %d", len(f))
	}
}

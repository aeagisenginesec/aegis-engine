package aws

import (
	"testing"

	"aegis/internal/ir"
)

// refVal builds an unresolved reference value.
func refVal(ref string, line int) ir.Value {
	return ir.Value{Known: false, Span: spanAt(line), Ref: ref}
}

// sgRefList builds a known list of SG references.
func sgRefList(line int, refs ...string) ir.Value {
	vals := make([]ir.Value, len(refs))
	for i, r := range refs {
		vals[i] = refVal(r, line)
	}
	return ir.Value{Raw: vals, Known: false, Span: spanAt(line)}
}

func openSG(name string, line int) ir.Resource {
	return res("aws_security_group", name, map[string]ir.Value{
		"ingress": blks(line, blk(
			"cidr_blocks", strList(line, "0.0.0.0/0"),
		)),
	})
}

func chainedSG(name, sourceSG string, line int) ir.Resource {
	return res("aws_security_group", name, map[string]ir.Value{
		"ingress": blks(line, blk(
			"source_security_group_id", refVal("aws_security_group."+sourceSG+".id", line),
		)),
	})
}

func rdsWithSGs(name string, line int, sgs ...string) ir.Resource {
	attrs := map[string]ir.Value{
		"publicly_accessible": kv(false, line),
	}
	if len(sgs) > 0 {
		refs := make([]string, len(sgs))
		for i, s := range sgs {
			refs[i] = "aws_security_group." + s + ".id"
		}
		attrs["vpc_security_group_ids"] = sgRefList(line, refs...)
	}
	return res("aws_db_instance", name, attrs)
}

func ec2WithSGs(name string, line int, sgs ...string) ir.Resource {
	attrs := map[string]ir.Value{}
	if len(sgs) > 0 {
		refs := make([]string, len(sgs))
		for i, s := range sgs {
			refs[i] = "aws_security_group." + s + ".id"
		}
		attrs["vpc_security_group_ids"] = sgRefList(line, refs...)
	}
	return res("aws_instance", name, attrs)
}

func run105(resources ...ir.Resource) []ir.Finding {
	return (multiHopPath{}).CheckAll(resources)
}

func pathNodes(f ir.Finding) []string {
	out := make([]string, len(f.Path))
	for i, s := range f.Path {
		out[i] = s.Resource
	}
	return out
}

func Test105_SGChain2Hop(t *testing.T) {
	sgA := openSG("a", 2)
	sgB := chainedSG("b", "a", 5)
	rds := rdsWithSGs("main", 8, "b")
	out := run105(sgA, sgB, rds)
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	f := out[0]
	if f.RuleID != "AEGIS-AWS-105" {
		t.Fatalf("wrong rule: %s", f.RuleID)
	}
	want := []string{"internet", "aws_security_group.a", "aws_security_group.b", "aws_db_instance.main"}
	got := pathNodes(f)
	if len(got) != len(want) {
		t.Fatalf("want path %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("step %d: want %s, got %s", i, want[i], got[i])
		}
		if f.Path[i].Detail == "" {
			t.Fatalf("step %d has empty detail", i)
		}
	}
}

func Test105_EC2SteppingStone(t *testing.T) {
	// SG-A world-open -> EC2. SG-B (private) allows SG-A -> RDS.
	// Shortest path: internet -> SG-A -> EC2 -> RDS (EC2 sorts before SG-B).
	sgA := openSG("a", 2)
	ec2 := ec2WithSGs("jump", 5, "a")
	sgB := chainedSG("b", "a", 6)
	rds := rdsWithSGs("main", 8, "b")
	out := run105(sgA, ec2, sgB, rds)
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	want := []string{"internet", "aws_security_group.a", "aws_instance.jump", "aws_db_instance.main"}
	got := pathNodes(out[0])
	if len(got) != len(want) {
		t.Fatalf("want path %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("step %d: want %s, got %s", i, want[i], got[i])
		}
	}
}

func Test105_DirectPathStaysSilent(t *testing.T) {
	// internet -> SG -> RDS (3 nodes) is 103's territory, not 105's.
	sg := openSG("web", 2)
	rds := rdsWithSGs("main", 5, "web")
	out := run105(sg, rds)
	if len(out) != 0 {
		t.Fatalf("direct path should not fire 105, got %+v", out)
	}
}

func Test105_NoPathSilent(t *testing.T) {
	sg := res("aws_security_group", "closed", map[string]ir.Value{
		"ingress": blks(2, blk("cidr_blocks", strList(2, "10.0.0.0/8"))),
	})
	rds := rdsWithSGs("main", 5, "closed")
	out := run105(sg, rds)
	if len(out) != 0 {
		t.Fatalf("expected no finding, got %+v", out)
	}
}

func Test105_DeduplicatesOneFindingPerRDS(t *testing.T) {
	// Two open SGs both leading directly to the same RDS: 105 stays
	// silent (3-node paths belong to 103). Only the chained RDS fires.
	sgA := openSG("a", 2)
	sgB := openSG("b", 3)
	rds := rdsWithSGs("main", 5, "a", "b")
	out := run105(sgA, sgB, rds)
	if len(out) != 0 {
		t.Fatalf("direct paths should not fire 105, got %d", len(out))
	}
	// Add a chain: internet -> a -> c -> other (4 nodes) fires once.
	sgC := chainedSG("c", "a", 6)
	rds2 := rdsWithSGs("other", 8, "c")
	out2 := run105(sgA, sgB, sgC, rds, rds2)
	if len(out2) != 1 {
		t.Fatalf("expected 1 finding (other), got %d", len(out2))
	}
	if out2[0].Resource != "aws_db_instance.other" {
		t.Fatalf("wrong target: %s", out2[0].Resource)
	}
}

func Test105_DepthCap(t *testing.T) {
	// Chain of 6 SGs: internet -> s1 -> s2 -> s3 -> s4 -> s5 -> s6 -> rds
	// is 8 nodes / 7 edges; depth cap 4 means no path found.
	var resources []ir.Resource
	resources = append(resources, openSG("s1", 2))
	for i := 2; i <= 6; i++ {
		resources = append(resources, chainedSG(
			"s"+itoa(i), "s"+itoa(i-1), i+1))
	}
	resources = append(resources, rdsWithSGs("main", 10, "s6"))
	out := run105(resources...)
	if len(out) != 0 {
		t.Fatalf("chain beyond depth cap should not fire, got %+v", out)
	}
}

func Test105_ThreeHopChain(t *testing.T) {
	// internet -> s1 -> s2 -> s3 -> rds : 5 nodes, 4 edges = at cap.
	sg1 := openSG("s1", 2)
	sg2 := chainedSG("s2", "s1", 3)
	sg3 := chainedSG("s3", "s2", 4)
	rds := rdsWithSGs("main", 5, "s3")
	out := run105(sg1, sg2, sg3, rds)
	if len(out) != 1 {
		t.Fatalf("expected 1 finding at depth cap, got %d", len(out))
	}
	want := []string{"internet", "aws_security_group.s1", "aws_security_group.s2",
		"aws_security_group.s3", "aws_db_instance.main"}
	got := pathNodes(out[0])
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("step %d: want %s, got %s", i, want[i], got[i])
		}
	}
}

func Test105_Deterministic(t *testing.T) {
	sgA := openSG("a", 2)
	sgB := chainedSG("b", "a", 5)
	rds := rdsWithSGs("main", 8, "b")
	a := run105(sgA, sgB, rds)
	b := run105(rds, sgB, sgA) // shuffled input
	if len(a) != 1 || len(b) != 1 {
		t.Fatalf("expected 1 finding each, got %d/%d", len(a), len(b))
	}
	pa, pb := pathNodes(a[0]), pathNodes(b[0])
	for i := range pa {
		if pa[i] != pb[i] {
			t.Fatalf("non-deterministic path: %v vs %v", pa, pb)
		}
	}
}

func itoa(i int) string {
	return string(rune('0' + i))
}

// ---------------------------------------------------------------------------
// Taint tracking tests (rule 339)
// ---------------------------------------------------------------------------

func taintRes(typ, name, attr, ref string, line int) ir.Resource {
	return res(typ, name, map[string]ir.Value{attr: refVal(ref, line)})
}

func Test339_TaintedVarFires(t *testing.T) {
	r := taintRes("aws_db_instance", "main", "password", "var.db_password", 3)
	out := (hardcodedCredentials{}).CheckAll([]ir.Resource{r})
	if len(out) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(out))
	}
	f := out[0]
	if f.RuleID != "AEGIS-AWS-339" {
		t.Fatalf("wrong rule: %s", f.RuleID)
	}
	if f.Resource != "aws_db_instance.main" {
		t.Fatalf("wrong resource: %s", f.Resource)
	}
	want := "var.db_password -> aws_db_instance.main.password"
	if !contains(f.Evidence.Actual, want) {
		t.Fatalf("evidence should contain taint path %q, got %q", want, f.Evidence.Actual)
	}
	if contains(f.Evidence.Actual, "secret123") {
		t.Fatal("evidence must not leak secret values")
	}
}

func Test339_TaintedLocalFires(t *testing.T) {
	r := taintRes("aws_secretsmanager_secret_version", "v", "secret_string", "local.api_token", 3)
	// secret_string is not in 339's AppliesTo; use a DB type instead.
	r2 := taintRes("aws_docdb_cluster", "c", "password", "local.api_token", 3)
	out := (hardcodedCredentials{}).CheckAll([]ir.Resource{r, r2})
	if len(out) != 1 {
		t.Fatalf("expected 1 finding (docdb only), got %d", len(out))
	}
	if out[0].Resource != "aws_docdb_cluster.c" {
		t.Fatalf("wrong resource: %s", out[0].Resource)
	}
}

func Test339_CleanVarSilent(t *testing.T) {
	r := taintRes("aws_db_instance", "main", "password", "var.instance_class", 3)
	out := (hardcodedCredentials{}).CheckAll([]ir.Resource{r})
	if len(out) != 0 {
		t.Fatalf("clean var name should not fire, got %+v", out)
	}
}

func Test339_UnknownVarSilent(t *testing.T) {
	// Unresolved non-ref value: silent.
	r := res("aws_db_instance", "main", map[string]ir.Value{
		"password": ku(3),
	})
	out := (hardcodedCredentials{}).CheckAll([]ir.Resource{r})
	if len(out) != 0 {
		t.Fatalf("unknown value should not fire, got %+v", out)
	}
}

func Test339_NonVarRefSilent(t *testing.T) {
	// data source refs are not tainted, even with secret-like suffixes.
	r := taintRes("aws_db_instance", "main", "password", "data.aws_secretsmanager_secret_version.db.secret_string", 3)
	out := (hardcodedCredentials{}).CheckAll([]ir.Resource{r})
	if len(out) != 0 {
		t.Fatalf("data ref should not fire taint, got %+v", out)
	}
}

func Test339_LiteralStillFires(t *testing.T) {
	r := res("aws_db_instance", "main", map[string]ir.Value{
		"password": ks("Sup3rSecret!", 3),
	})
	out := (hardcodedCredentials{}).CheckAll([]ir.Resource{r})
	if len(out) != 1 {
		t.Fatalf("literal should still fire, got %d", len(out))
	}
	if out[0].Evidence.Actual != "[REDACTED]" {
		t.Fatalf("literal evidence must be [REDACTED], got %q", out[0].Evidence.Actual)
	}
}

func Test339_NoDoubleCount(t *testing.T) {
	// A literal fires once (Check), not twice (Check + taint).
	r := res("aws_db_instance", "main", map[string]ir.Value{
		"password": ks("Sup3rSecret!", 3),
	})
	out := (hardcodedCredentials{}).CheckAll([]ir.Resource{r})
	if len(out) != 1 {
		t.Fatalf("expected exactly 1 finding, got %d", len(out))
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}())
}

package graph

import (
	"reflect"
	"testing"

	"aegis/internal/ir"
)

var zspan = ir.Span{}

func str(s string) ir.Value   { return ir.Value{Raw: s, Known: true, Span: zspan} }
func boolean(b bool) ir.Value { return ir.Value{Raw: b, Known: true, Span: zspan} }
func ref(r string) ir.Value   { return ir.Value{Known: false, Span: zspan, Ref: r} }
func unknown() ir.Value       { return ir.UnknownValue(zspan) }

func list(vals ...ir.Value) ir.Value {
	return ir.Value{Raw: vals, Known: true, Span: zspan}
}

func obj(pairs map[string]ir.Value) ir.Value {
	return ir.Value{Raw: pairs, Known: true, Span: zspan}
}

func res(typ, name string, attrs map[string]ir.Value) ir.Resource {
	if attrs == nil {
		attrs = map[string]ir.Value{}
	}
	return ir.Resource{
		Type: typ, Name: name, Provider: "aws",
		Attributes: attrs, Span: zspan,
	}
}

func openIngressBlock(cidr string) ir.Value {
	return obj(map[string]ir.Value{
		"from_port":   {Raw: float64(443), Known: true, Span: zspan},
		"to_port":     {Raw: float64(443), Known: true, Span: zspan},
		"protocol":    str("tcp"),
		"cidr_blocks": list(str(cidr)),
	})
}

func TestEdgesFromDirectRefs(t *testing.T) {
	bucket := res("aws_s3_bucket", "assets", nil)
	policy := res("aws_s3_bucket_policy", "assets", map[string]ir.Value{
		"bucket": ref("aws_s3_bucket.assets.id"),
	})
	g := Build([]ir.Resource{bucket, policy})

	out := g.OutEdges("aws_s3_bucket_policy.assets")
	want := []Edge{{From: "aws_s3_bucket_policy.assets", To: "aws_s3_bucket.assets", Via: "aws_s3_bucket.assets.id"}}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("OutEdges = %v, want %v", out, want)
	}
	in := g.InEdges("aws_s3_bucket.assets")
	if !reflect.DeepEqual(in, want) {
		t.Fatalf("InEdges = %v, want %v", in, want)
	}
	if got := g.InEdges("aws_s3_bucket_policy.assets"); len(got) != 0 {
		t.Fatalf("expected no in-edges, got %v", got)
	}
}

func TestEdgesInsideNestedBlocksAndLists(t *testing.T) {
	sg := res("aws_security_group", "web", nil)
	inst := res("aws_instance", "web", map[string]ir.Value{
		"vpc_security_group_ids": list(ref("aws_security_group.web.id")),
		"ebs_block_device": list(obj(map[string]ir.Value{
			"snapshot_ref": ref("aws_ebs_snapshot.base.id"),
		})),
	})
	snap := res("aws_ebs_snapshot", "base", nil)
	g := Build([]ir.Resource{sg, inst, snap})

	out := g.OutEdges("aws_instance.web")
	want := []Edge{
		{From: "aws_instance.web", To: "aws_ebs_snapshot.base", Via: "aws_ebs_snapshot.base.id"},
		{From: "aws_instance.web", To: "aws_security_group.web", Via: "aws_security_group.web.id"},
	}
	if !reflect.DeepEqual(out, want) {
		t.Fatalf("OutEdges = %v, want %v (sorted by To)", out, want)
	}
}

func TestRefsToNonexistentResourcesHaveNoEdge(t *testing.T) {
	lonely := res("aws_s3_bucket_policy", "x", map[string]ir.Value{
		"bucket": ref("aws_s3_bucket.ghost.id"),
	})
	g := Build([]ir.Resource{lonely})
	if got := g.OutEdges("aws_s3_bucket_policy.x"); len(got) != 0 {
		t.Fatalf("expected no edges, got %v", got)
	}
	if got := g.Nodes(); len(got) != 1 {
		t.Fatalf("expected 1 node, got %v", got)
	}
}

func TestSelfRefHasNoEdge(t *testing.T) {
	self := res("aws_security_group", "web", map[string]ir.Value{
		"description": ref("aws_security_group.web.arn"),
	})
	g := Build([]ir.Resource{self})
	if got := g.OutEdges("aws_security_group.web"); len(got) != 0 {
		t.Fatalf("self-ref must not create an edge, got %v", got)
	}
}

func TestNonResourceRefsHaveNoEdges(t *testing.T) {
	r := res("aws_instance", "app", map[string]ir.Value{
		"ami":           ref("var.ami_id"),
		"instance_type": ref("local.instance_type"),
		"key_name":      ref("data.aws_key_pair.main.key_name"),
		"subnet_id":     ref("each.value"),
		"user_data":     ref("count.index"),
		"tags":          ref("self.id"),
		"vpc_id":        ref("module.vpc.vpc_id"),
	})
	other := res("aws_vpc", "main", nil)
	g := Build([]ir.Resource{r, other})
	if got := g.OutEdges("aws_instance.app"); len(got) != 0 {
		t.Fatalf("config refs must not create edges, got %v", got)
	}
}

func TestDuplicateAddressesKeepFirst(t *testing.T) {
	a := res("aws_s3_bucket", "x", map[string]ir.Value{"tags": obj(map[string]ir.Value{"a": str("1")})})
	b := res("aws_s3_bucket", "x", map[string]ir.Value{"tags": obj(map[string]ir.Value{"b": str("2")})})
	g := Build([]ir.Resource{a, b})
	r, ok := g.Resource("aws_s3_bucket.x")
	if !ok {
		t.Fatal("node missing")
	}
	v, _ := r.Attr("tags")
	m, _ := v.AsMap()
	if _, ok := m["a"]; !ok {
		t.Fatalf("expected first resource to win, got %+v", r.Attributes)
	}
	if got := g.Nodes(); len(got) != 1 {
		t.Fatalf("expected 1 node, got %v", got)
	}
}

func TestNodesSorted(t *testing.T) {
	g := Build([]ir.Resource{
		res("aws_vpc", "z", nil),
		res("aws_s3_bucket", "a", nil),
		res("aws_instance", "m", nil),
	})
	want := []string{"aws_instance.m", "aws_s3_bucket.a", "aws_vpc.z"}
	if got := g.Nodes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Nodes = %v, want %v", got, want)
	}
}

func TestInEdgesSortedByFrom(t *testing.T) {
	bucket := res("aws_s3_bucket", "data", nil)
	p1 := res("aws_s3_bucket_policy", "a", map[string]ir.Value{"bucket": ref("aws_s3_bucket.data.id")})
	p2 := res("aws_s3_bucket_acl", "b", map[string]ir.Value{"bucket": ref("aws_s3_bucket.data.arn")})
	g := Build([]ir.Resource{bucket, p1, p2})
	in := g.InEdges("aws_s3_bucket.data")
	want := []Edge{
		{From: "aws_s3_bucket_acl.b", To: "aws_s3_bucket.data", Via: "aws_s3_bucket.data.arn"},
		{From: "aws_s3_bucket_policy.a", To: "aws_s3_bucket.data", Via: "aws_s3_bucket.data.id"},
	}
	if !reflect.DeepEqual(in, want) {
		t.Fatalf("InEdges = %v, want %v", in, want)
	}
}

func TestPubliclyExposedOpenSG(t *testing.T) {
	sg := res("aws_security_group", "open", map[string]ir.Value{
		"ingress": list(openIngressBlock("0.0.0.0/0")),
	})
	g := Build([]ir.Resource{sg})
	if !g.PubliclyExposed("aws_security_group.open") {
		t.Fatal("open SG should be publicly exposed")
	}
}

func TestPubliclyExposedIPv6(t *testing.T) {
	sg := res("aws_security_group", "v6", map[string]ir.Value{
		"ingress": list(openIngressBlock("::/0")),
	})
	g := Build([]ir.Resource{sg})
	if !g.PubliclyExposed("aws_security_group.v6") {
		t.Fatal("::/0 ingress should be publicly exposed")
	}
}

func TestPubliclyExposedRestrictedSG(t *testing.T) {
	sg := res("aws_security_group", "closed", map[string]ir.Value{
		"ingress": list(openIngressBlock("10.0.0.0/8")),
	})
	g := Build([]ir.Resource{sg})
	if g.PubliclyExposed("aws_security_group.closed") {
		t.Fatal("restricted SG must not be publicly exposed")
	}
}

func TestPubliclyExposedNoIngress(t *testing.T) {
	sg := res("aws_security_group", "bare", nil)
	g := Build([]ir.Resource{sg})
	if g.PubliclyExposed("aws_security_group.bare") {
		t.Fatal("SG with no ingress must not be publicly exposed")
	}
}

func TestPubliclyExposedUnknownCIDR(t *testing.T) {
	sg := res("aws_security_group", "mystery", map[string]ir.Value{
		"ingress": list(obj(map[string]ir.Value{
			"cidr_blocks": unknown(),
		})),
	})
	g := Build([]ir.Resource{sg})
	if g.PubliclyExposed("aws_security_group.mystery") {
		t.Fatal("unknown CIDR must not be treated as open")
	}
}

func TestPubliclyExposedEgressOnly(t *testing.T) {
	sg := res("aws_security_group", "eg", map[string]ir.Value{
		"egress": list(openIngressBlock("0.0.0.0/0")),
	})
	g := Build([]ir.Resource{sg})
	if g.PubliclyExposed("aws_security_group.eg") {
		t.Fatal("egress-only SG must not count as inbound exposure")
	}
}

func TestPubliclyExposedViaAttachedSG(t *testing.T) {
	open := res("aws_security_group", "open", map[string]ir.Value{
		"ingress": list(openIngressBlock("0.0.0.0/0")),
	})
	closed := res("aws_security_group", "closed", map[string]ir.Value{
		"ingress": list(openIngressBlock("10.0.0.0/8")),
	})
	exposed := res("aws_instance", "web", map[string]ir.Value{
		"vpc_security_group_ids": list(ref("aws_security_group.open.id")),
	})
	safe := res("aws_instance", "db", map[string]ir.Value{
		"vpc_security_group_ids": list(ref("aws_security_group.closed.id")),
	})
	unknownSG := res("aws_instance", "ghost", map[string]ir.Value{
		"vpc_security_group_ids": list(ref("aws_security_group.missing.id")),
	})
	legacy := res("aws_instance", "old", map[string]ir.Value{
		"security_groups": list(ref("aws_security_group.open.name")),
	})
	g := Build([]ir.Resource{open, closed, exposed, safe, unknownSG, legacy})

	if !g.PubliclyExposed("aws_instance.web") {
		t.Fatal("instance attached to open SG should be exposed")
	}
	if g.PubliclyExposed("aws_instance.db") {
		t.Fatal("instance attached to closed SG must not be exposed")
	}
	if g.PubliclyExposed("aws_instance.ghost") {
		t.Fatal("instance attached to unknown SG must not be exposed")
	}
	if !g.PubliclyExposed("aws_instance.old") {
		t.Fatal("instance with open SG in security_groups should be exposed")
	}
}

func TestPubliclyExposedPublicRDS(t *testing.T) {
	db := res("aws_db_instance", "main", map[string]ir.Value{
		"publicly_accessible": boolean(true),
	})
	g := Build([]ir.Resource{db})
	if !g.PubliclyExposed("aws_db_instance.main") {
		t.Fatal("publicly_accessible RDS should be exposed")
	}
}

func TestPubliclyExposedPrivateRDS(t *testing.T) {
	db := res("aws_db_instance", "main", map[string]ir.Value{
		"publicly_accessible": boolean(false),
	})
	g := Build([]ir.Resource{db})
	if g.PubliclyExposed("aws_db_instance.main") {
		t.Fatal("private RDS must not be exposed")
	}
}

func TestPubliclyExposedUnknownResource(t *testing.T) {
	g := Build([]ir.Resource{res("aws_s3_bucket", "b", nil)})
	if g.PubliclyExposed("aws_instance.nope") {
		t.Fatal("unknown address must not be exposed")
	}
}

func TestSecurityGroupRuleIngress(t *testing.T) {
	open := res("aws_security_group_rule", "ssh", map[string]ir.Value{
		"type":        str("ingress"),
		"cidr_blocks": list(str("0.0.0.0/0")),
	})
	egress := res("aws_security_group_rule", "out", map[string]ir.Value{
		"type":        str("egress"),
		"cidr_blocks": list(str("0.0.0.0/0")),
	})
	vpcRule := res("aws_vpc_security_group_ingress_rule", "http", map[string]ir.Value{
		"cidr_ipv4": str("0.0.0.0/0"),
	})
	g := Build([]ir.Resource{open, egress, vpcRule})
	if !g.PubliclyExposed("aws_security_group_rule.ssh") {
		t.Fatal("open ingress rule should be exposed")
	}
	if g.PubliclyExposed("aws_security_group_rule.out") {
		t.Fatal("egress rule must not count as inbound exposure")
	}
	if !g.PubliclyExposed("aws_vpc_security_group_ingress_rule.http") {
		t.Fatal("open cidr_ipv4 rule should be exposed")
	}
}

func TestDeterminism(t *testing.T) {
	resources := []ir.Resource{
		res("aws_instance", "web", map[string]ir.Value{
			"vpc_security_group_ids": list(ref("aws_security_group.web.id")),
			"tags":                   obj(map[string]ir.Value{"z": str("1"), "a": str("2")}),
		}),
		res("aws_security_group", "web", map[string]ir.Value{
			"ingress": list(openIngressBlock("0.0.0.0/0")),
		}),
		res("aws_s3_bucket_policy", "p", map[string]ir.Value{
			"bucket": ref("aws_s3_bucket.web.arn"),
		}),
		res("aws_s3_bucket", "web", nil),
	}
	g1 := Build(resources)
	g2 := Build(resources)
	if !reflect.DeepEqual(g1.Nodes(), g2.Nodes()) {
		t.Fatal("Nodes not deterministic")
	}
	for _, n := range g1.Nodes() {
		if !reflect.DeepEqual(g1.OutEdges(n), g2.OutEdges(n)) {
			t.Fatalf("OutEdges(%s) not deterministic", n)
		}
		if !reflect.DeepEqual(g1.InEdges(n), g2.InEdges(n)) {
			t.Fatalf("InEdges(%s) not deterministic", n)
		}
	}
}

func TestBuildNeverPanics(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Build panicked: %v", r)
		}
	}()
	Build(nil)
	Build([]ir.Resource{{}})
	Build([]ir.Resource{res("x", "", nil)})
	Build([]ir.Resource{res("", "", map[string]ir.Value{
		"a": ref(""),
		"b": ref("."),
		"c": ref("a."),
		"d": ref("aws_x.y"),
	})})
}

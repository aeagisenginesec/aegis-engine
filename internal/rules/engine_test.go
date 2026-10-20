package rules

import (
	"reflect"
	"strings"
	"testing"

	"aegis/internal/ir"
)

// stubRule is a minimal ir.Rule for engine tests.
type stubRule struct {
	id      string
	applies map[string]bool
	check   func(ir.Resource) []ir.Finding
}

func (s stubRule) ID() string          { return s.id }
func (s stubRule) Title() string       { return "stub " + s.id }
func (s stubRule) Description() string { return "test stub" }
func (s stubRule) Severity() ir.Severity {
	return ir.SeverityLow
}
func (s stubRule) AppliesTo(t string) bool { return s.applies[t] }
func (s stubRule) Check(r ir.Resource) []ir.Finding {
	if s.check != nil {
		return s.check(r)
	}
	return []ir.Finding{{
		RuleID:   s.id,
		Resource: r.Address(),
		Severity: ir.SeverityLow,
		Evidence: ir.Evidence{Attribute: "x"},
	}}
}

func TestRegistry_DuplicateIDIgnored(t *testing.T) {
	reg := NewRegistry()
	reg.Register(stubRule{id: "B", applies: map[string]bool{"t": true}})
	reg.Register(stubRule{id: "A", applies: map[string]bool{"t": true}})
	reg.Register(stubRule{id: "A", applies: map[string]bool{"t": true}}) // dup
	all := reg.All()
	if len(all) != 2 || all[0].ID() != "A" || all[1].ID() != "B" {
		t.Fatalf("All() should dedupe and sort by ID, got %v", all)
	}
}

func TestRun_DeterministicOrder(t *testing.T) {
	reg := NewRegistry()
	reg.Register(stubRule{id: "Z-2", applies: map[string]bool{"aws_x": true}})
	reg.Register(stubRule{id: "A-1", applies: map[string]bool{"aws_x": true}})
	mkRes := func(name string) ir.Resource {
		return ir.Resource{Type: "aws_x", Name: name, Attributes: map[string]ir.Value{}}
	}
	// Deliberately scrambled input order, twice.
	in1 := []ir.Resource{mkRes("c"), mkRes("a"), mkRes("b")}
	in2 := []ir.Resource{mkRes("b"), mkRes("c"), mkRes("a")}
	out1 := reg.Run(in1)
	out2 := reg.Run(in2)
	if !reflect.DeepEqual(out1, out2) {
		t.Fatal("Run output must not depend on input order")
	}
	// Expected order: A-1/a, A-1/b, A-1/c, Z-2/a, Z-2/b, Z-2/c
	want := []string{
		"A-1:aws_x.a", "A-1:aws_x.b", "A-1:aws_x.c",
		"Z-2:aws_x.a", "Z-2:aws_x.b", "Z-2:aws_x.c",
	}
	if len(out1) != len(want) {
		t.Fatalf("expected %d findings, got %d", len(want), len(out1))
	}
	for i, w := range want {
		if got := out1[i].RuleID + ":" + out1[i].Resource; got != w {
			t.Fatalf("position %d: want %s, got %s", i, w, got)
		}
	}
}

func TestRun_AppliesToFilters(t *testing.T) {
	reg := NewRegistry()
	reg.Register(stubRule{id: "R", applies: map[string]bool{"aws_a": true}})
	r := ir.Resource{Type: "aws_b", Name: "x", Attributes: map[string]ir.Value{}}
	if out := reg.Run([]ir.Resource{r}); len(out) != 0 {
		t.Fatalf("rule must not run on non-matching type, got %d findings", len(out))
	}
}

func TestRun_PanickingRuleCannotKillScan(t *testing.T) {
	reg := NewRegistry()
	reg.Register(stubRule{
		id:      "PANIC",
		applies: map[string]bool{"aws_x": true},
		check: func(ir.Resource) []ir.Finding {
			panic("boom")
		},
	})
	reg.Register(stubRule{id: "OK", applies: map[string]bool{"aws_x": true}})
	r := ir.Resource{Type: "aws_x", Name: "x", Attributes: map[string]ir.Value{}}
	out := reg.Run([]ir.Resource{r})
	if len(out) != 1 || out[0].RuleID != "OK" {
		t.Fatalf("panicking rule should be skipped, healthy rule kept: %+v", out)
	}
}

func TestDefaultRegistry_HasAllPacks(t *testing.T) {
	reg := DefaultRegistry()
	all := reg.All()
	// 171 AWS + 25 Azure + 24 GCP + 3 K8s + 1 supplychain + 10 docker + 1 multihop
	// + 5 IAM privilege (501-505) + 8 network exposure (506-513) + 7 encryption gap (514-520)
	// + 7 auth supply (521-527) + 6 hardening (528-533) + 8 terraform (TF-001-008)
	// + 6 deep secrets (534-539) + hygiene expansion + 7 final gap part 2 (545-551)
	// + 76 GCP expansion (GCP-025-100) + 70 Azure expansion
	// + 6 aurora coverage gaps (AWS 631-636) + 8 sibling-pack additions
	// + 22 GCP Checkov gap-closure (GCP-101-122)
	// + 23 Azure gap-closure (127-149: AKS, App Service, Storage)
	// + 13 AWS gap-closure (637-644 search, 645-649 lambda).
	// + 12 Alibaba Cloud pack (ALI-001..012) + 8 OCI pack (OCI-001..008)
	// + 20 Azure new-service coverage (150-169) + 20 GCP expansion (123-142)
	// + 22 K8s hardening (004-025).
	// + 25 Docker expansion (DOCKER-011-035) + 8 Compose pack (COMPOSE-001-008).
	// - 4 AWS rules removed by the concurrent Phase-4 refactor (incl. AEGIS-AWS-558).
	// + 144 Azure expansion (AEGIS-AZURE-170..313) + concurrent AWS/GCP deep packs.
	// + 200 AWS deep expansion (AEGIS-AWS-650..849).
	// - 39 duplicate rules removed by post-audit dedup (46 pairs consolidated).
	// + 5 accuracy-100 rules (AEGIS-AZURE-314, AEGIS-AWS-850,
	//   AEGIS-DOCKER-036, AEGIS-K8S-026, AEGIS-K8S-027).
	// + 6 outperform-mission rules (AEGIS-AWS-851..855, AEGIS-DOCKER-037).
	// − 3 removed as factually wrong / duplicates (684, 692, 702).
	// + 5 K8s hardening gap-closure (AEGIS-K8S-028..032).
	// − 9 duplicate / FP-prone rules removed by the multi-cloud quality
	//   audit (AZR-004, AZURE-008/009/025/045/047/048/225, GCP-063).
	// + 2 multi-cloud quality audit rules (AEGIS-GCP-293, AEGIS-GCP-294).
	// + 1 AWS-856 EC2 EOL image (concurrent addition, kept after audit review).
	// + 1 AWS-857 CFN parameter secret default (R4 recall gap closure).
	// + 2 R4 Sprint-1 FN closures (AEGIS-AWS-858 SG database-port exposure,
	//   AEGIS-COMPOSE-009 host network split out of COMPOSE-003).
	if len(all) != 1145 {
		t.Fatalf("default registry should wire 1145 rules, got %d", len(all))
	}
	ids := map[string]bool{}
	for _, r := range all {
		ids[r.ID()] = true
	}
	for _, want := range []string{"AEGIS-AWS-001", "AEGIS-AWS-104", "AEGIS-AZR-001", "AEGIS-GCP-001", "AEGIS-K8S-001", "AEGIS-SC-001", "AEGIS-TF-001", "AEGIS-ALI-001", "AEGIS-OCI-001"} {
		if !ids[want] {
			t.Errorf("default registry missing %s", want)
		}
	}
}

func TestRegistryFor_SelectsPacks(t *testing.T) {
	reg := RegistryFor("azure")
	for _, r := range reg.All() {
		if !strings.HasPrefix(r.ID(), "AEGIS-AZR") && !strings.HasPrefix(r.ID(), "AEGIS-AZURE") {
			t.Fatalf("azure-only registry leaked %s", r.ID())
		}
	}
	if unknown := UnknownPacks([]string{"aws", "nope"}); len(unknown) != 1 || unknown[0] != "nope" {
		t.Fatalf("UnknownPacks = %v", unknown)
	}
}

func TestDefaultRegistry_EndToEndSmoke(t *testing.T) {
	reg := DefaultRegistry()
	span := ir.Span{File: "main.tf", StartLine: 1, StartCol: 1, EndLine: 5, EndCol: 1}
	resources := []ir.Resource{
		{Type: "aws_s3_bucket", Name: "pub", Attributes: map[string]ir.Value{
			"acl": ir.Value{Raw: "public-read", Known: true, Span: span},
		}, Span: span},
		// bare: private, no SSE -> 001 fires here (pub is
		// intentionally public, so 001 is suppressed on it).
		{Type: "aws_s3_bucket", Name: "bare", Attributes: map[string]ir.Value{}, Span: span},
		{Type: "aws_s3_bucket", Name: "priv", Attributes: map[string]ir.Value{
			"acl": ir.Value{Raw: "private", Known: true, Span: span},
			"logging": ir.Value{Raw: []ir.Value{
				{Raw: map[string]ir.Value{
					"target_bucket": ir.Value{Raw: "log-bucket", Known: true, Span: span},
				}, Known: true, Span: span},
			}, Known: true, Span: span},
			"versioning": ir.Value{Raw: []ir.Value{
				{Raw: map[string]ir.Value{
					"enabled": ir.Value{Raw: true, Known: true, Span: span},
				}, Known: true, Span: span},
			}, Known: true, Span: span},
			"server_side_encryption_configuration": ir.Value{Raw: []ir.Value{
				{Raw: map[string]ir.Value{
					"rule": ir.Value{Raw: []ir.Value{
						{Raw: map[string]ir.Value{
							"apply_server_side_encryption_by_default": ir.Value{Raw: []ir.Value{
								{Raw: map[string]ir.Value{
									// CMK (not AES256): the smoke bucket is fully
									// compliant, so 852 must stay quiet on it.
									"sse_algorithm":     ir.Value{Raw: "aws:kms", Known: true, Span: span},
									"kms_master_key_id": ir.Value{Raw: "arn:aws:kms:us-east-1:123456789012:key/abc-123", Known: true, Span: span},
								}, Known: true, Span: span},
							}, Known: true, Span: span},
						}, Known: true, Span: span},
					}, Known: true, Span: span},
				}, Known: true, Span: span},
			}, Known: true, Span: span},
			// hygiene: lifecycle + replication configured
			"lifecycle_rule": ir.Value{Raw: []ir.Value{
				{Raw: map[string]ir.Value{}, Known: true, Span: span},
			}, Known: true, Span: span},
			"replication_configuration": ir.Value{Raw: []ir.Value{
				{Raw: map[string]ir.Value{}, Known: true, Span: span},
			}, Known: true, Span: span},
		}, Span: span},
		{Type: "aws_s3_bucket_notification", Name: "priv", Attributes: map[string]ir.Value{
			"bucket": ir.Value{Raw: "", Known: false, Span: span, Ref: "aws_s3_bucket.priv.id"},
		}, Span: span},
		{Type: "aws_s3_bucket_public_access_block", Name: "priv", Attributes: map[string]ir.Value{
			"bucket":                  ir.Value{Raw: "", Known: false, Span: span, Ref: "aws_s3_bucket.priv.id"},
			"block_public_acls":       ir.Value{Raw: true, Known: true, Span: span},
			"block_public_policy":     ir.Value{Raw: true, Known: true, Span: span},
			"ignore_public_acls":      ir.Value{Raw: true, Known: true, Span: span},
			"restrict_public_buckets": ir.Value{Raw: true, Known: true, Span: span},
		}, Span: span},
		{Type: "aws_s3_bucket_policy", Name: "priv", Attributes: map[string]ir.Value{
			"bucket": ir.Value{Raw: "", Known: false, Span: span, Ref: "aws_s3_bucket.priv.id"},
			"policy": ir.Value{Raw: `{"Statement":[{"Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`, Known: true, Span: span},
		}, Span: span},
		{Type: "aws_s3_bucket_object_lock_configuration", Name: "priv", Attributes: map[string]ir.Value{
			"bucket": ir.Value{Raw: "", Known: false, Span: span, Ref: "aws_s3_bucket.priv.id"},
		}, Span: span},
		{Type: "aws_s3_bucket_inventory", Name: "priv", Attributes: map[string]ir.Value{
			"bucket": ir.Value{Raw: "", Known: false, Span: span, Ref: "aws_s3_bucket.priv.id"},
		}, Span: span},
	}
	out := reg.Run(resources)
	ids := map[string]int{}
	for _, f := range out {
		ids[f.RuleID+":"+f.Resource]++
	}
	// pub bucket: public ACL (002), no versioning (012). 001 (no SSE)
	// is suppressed on it: the bucket is intentionally public.
	// bare bucket: private, no SSE -> 001 fires.
	for _, want := range []string{
		"AEGIS-AWS-001:aws_s3_bucket.bare",
		"AEGIS-AWS-002:aws_s3_bucket.pub",
		"AEGIS-AWS-012:aws_s3_bucket.pub",
	} {
		if ids[want] != 1 {
			t.Fatalf("expected exactly one %s, got %d (all: %v)", want, ids[want], ids)
		}
	}
	// priv bucket: fully configured -> nothing
	for k := range ids {
		if len(k) > len("aws_s3_bucket.priv") && k[len(k)-len("aws_s3_bucket.priv"):] == "aws_s3_bucket.priv" {
			t.Fatalf("compliant bucket must not fire: %s", k)
		}
	}
}

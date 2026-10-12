package aws

import (
	"testing"

	"aegis/internal/ir"
)

func lambdaRes(attrs map[string]ir.Value) ir.Resource {
	return res("aws_lambda_function", "f", attrs)
}

func wantOneLambda(t *testing.T, rule ir.Rule, r ir.Resource, id string) {
	t.Helper()
	got := runRule(rule, r)
	if len(got) != 1 {
		t.Fatalf("%s: want 1 finding, got %d", id, len(got))
	}
	if got[0].RuleID != id {
		t.Fatalf("%s: wrong rule ID %s", id, got[0].RuleID)
	}
}

func wantZeroLambda(t *testing.T, rule ir.Rule, r ir.Resource, id string) {
	t.Helper()
	if got := runRule(rule, r); len(got) != 0 {
		t.Fatalf("%s: want 0 findings, got %d", id, len(got))
	}
}

// AEGIS-AWS-645: code signing
func Test645_AbsentFires(t *testing.T) {
	wantOneLambda(t, lambdaNoCodeSigning{}, lambdaRes(nil), "AEGIS-AWS-645")
}

func Test645_PresentQuiet(t *testing.T) {
	r := lambdaRes(map[string]ir.Value{
		"code_signing_config": blks(2, blk("description", ks("signed", 3))),
	})
	wantZeroLambda(t, lambdaNoCodeSigning{}, r, "AEGIS-AWS-645")
}

// AEGIS-AWS-646: SnapStart (java only)
func Test646_JavaAbsentFires(t *testing.T) {
	r := lambdaRes(map[string]ir.Value{"runtime": ks("java17", 2)})
	wantOneLambda(t, lambdaNoSnapStart{}, r, "AEGIS-AWS-646")
}

func Test646_JavaEnabledQuiet(t *testing.T) {
	r := lambdaRes(map[string]ir.Value{
		"runtime":    ks("java17", 2),
		"snap_start": blks(2, blk("apply_on", ks("PublishedVersions", 3))),
	})
	wantZeroLambda(t, lambdaNoSnapStart{}, r, "AEGIS-AWS-646")
}

func Test646_NonJavaQuiet(t *testing.T) {
	r := lambdaRes(map[string]ir.Value{"runtime": ks("python3.13", 2)})
	wantZeroLambda(t, lambdaNoSnapStart{}, r, "AEGIS-AWS-646")
}

// AEGIS-AWS-647: dead-letter queue
func Test647_AbsentFires(t *testing.T) {
	wantOneLambda(t, lambdaNoDeadLetter{}, lambdaRes(nil), "AEGIS-AWS-647")
}

func Test647_PresentQuiet(t *testing.T) {
	r := lambdaRes(map[string]ir.Value{
		"dead_letter_config": blks(2, blk("target_arn", ks("arn:aws:sqs:x", 3))),
	})
	wantZeroLambda(t, lambdaNoDeadLetter{}, r, "AEGIS-AWS-647")
}

// AEGIS-AWS-648: EOL runtime
func Test648_OldRuntimeFires(t *testing.T) {
	r := lambdaRes(map[string]ir.Value{"runtime": ks("nodejs12.x", 2)})
	wantOneLambda(t, lambdaDeprecatedRuntime{}, r, "AEGIS-AWS-648")
}

func Test648_ModernQuiet(t *testing.T) {
	r := lambdaRes(map[string]ir.Value{"runtime": ks("python3.13", 2)})
	wantZeroLambda(t, lambdaDeprecatedRuntime{}, r, "AEGIS-AWS-648")
}

func Test648_AbsentQuiet(t *testing.T) {
	wantZeroLambda(t, lambdaDeprecatedRuntime{}, lambdaRes(nil), "AEGIS-AWS-648")
}

// AEGIS-AWS-649: plaintext secret in environment
func Test649_SecretKeyFires(t *testing.T) {
	vars := map[string]ir.Value{
		"secret_key": ks("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", 4),
	}
	varsVal := ir.Value{Raw: vars, Known: true, Span: spanAt(3)}
	r := lambdaRes(map[string]ir.Value{
		"environment": blks(2, blk("variables", varsVal)),
	})
	wantOneLambda(t, lambdaEnvPlaintextSecret{}, r, "AEGIS-AWS-649")
}

func Test649_AccessKeyIDFires(t *testing.T) {
	vars := map[string]ir.Value{
		"access_key": ks("AKIAIOSFODNN7EXAMPLE", 4),
	}
	varsVal := ir.Value{Raw: vars, Known: true, Span: spanAt(3)}
	r := lambdaRes(map[string]ir.Value{
		"environment": blks(2, blk("variables", varsVal)),
	})
	wantOneLambda(t, lambdaEnvPlaintextSecret{}, r, "AEGIS-AWS-649")
}

func Test649_BenignQuiet(t *testing.T) {
	vars := map[string]ir.Value{
		"access_key": ks("<redacted>", 4),
		"log_level":  ks("info", 5),
	}
	varsVal := ir.Value{Raw: vars, Known: true, Span: spanAt(3)}
	r := lambdaRes(map[string]ir.Value{
		"environment": blks(2, blk("variables", varsVal)),
	})
	wantZeroLambda(t, lambdaEnvPlaintextSecret{}, r, "AEGIS-AWS-649")
}

func Test649_NoEnvQuiet(t *testing.T) {
	wantZeroLambda(t, lambdaEnvPlaintextSecret{}, lambdaRes(nil), "AEGIS-AWS-649")
}

func Test649_UnknownValueQuiet(t *testing.T) {
	vars := map[string]ir.Value{
		"secret_key": ku(4),
	}
	varsVal := ir.Value{Raw: vars, Known: true, Span: spanAt(3)}
	r := lambdaRes(map[string]ir.Value{
		"environment": blks(2, blk("variables", varsVal)),
	})
	wantZeroLambda(t, lambdaEnvPlaintextSecret{}, r, "AEGIS-AWS-649")
}

func TestLambda2RulesInIDOrder(t *testing.T) {
	rules := Lambda2Rules()
	if len(rules) != 5 {
		t.Fatalf("expected 5 rules, got %d", len(rules))
	}
	if rules[0].ID() != "AEGIS-AWS-645" || rules[4].ID() != "AEGIS-AWS-649" {
		t.Fatalf("ID order broken: %s .. %s", rules[0].ID(), rules[4].ID())
	}
}

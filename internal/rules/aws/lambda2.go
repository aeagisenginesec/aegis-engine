package aws

// Lambda hardening, round 2 (AEGIS-AWS-645..649).
//
// Gaps not covered by AEGIS-AWS-307/308 (environment KMS, X-Ray tracing),
// 542 (VPC), 547/548 (tracing, reserved concurrency) or 564 (unlimited
// concurrency): code signing, SnapStart for Java runtimes, dead-letter
// queues, end-of-life runtimes, and plaintext secrets in environment
// variables.
//
// Unknown-value contract: a present-but-unresolved attribute yields NO
// finding. Absent attributes are judged against the provider default,
// documented per rule. Rules never panic on unexpected shapes.

import (
	"regexp"
	"strings"

	"aegis/internal/ir"
)

// Lambda2Rules returns the Lambda hardening rules, AEGIS-AWS-645..649, in
// ID order.
func Lambda2Rules() []ir.Rule {
	return []ir.Rule{
		lambdaNoCodeSigning{},      // AEGIS-AWS-645
		lambdaNoSnapStart{},        // AEGIS-AWS-646
		lambdaNoDeadLetter{},       // AEGIS-AWS-647
		lambdaDeprecatedRuntime{},  // AEGIS-AWS-648
		lambdaEnvPlaintextSecret{}, // AEGIS-AWS-649
	}
}

func lambdaFinding(rule ir.Rule, r ir.Resource, attr string, span ir.Span, actual, expected string) ir.Finding {
	return ir.Finding{
		RuleID:      rule.ID(),
		Title:       rule.Title(),
		Description: rule.Description(),
		Severity:    rule.Severity(),
		Resource:    r.Address(),
		Evidence: ir.Evidence{
			Attribute: attr,
			Span:      evidenceSpan(span, r.Span),
			Actual:    actual,
			Expected:  expected,
		},
	}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-645: Lambda function without code signing
// ---------------------------------------------------------------------------

type lambdaNoCodeSigning struct{}

func (lambdaNoCodeSigning) ID() string { return "AEGIS-AWS-645" }
func (lambdaNoCodeSigning) Title() string {
	return "Lambda function without code signing"
}
func (lambdaNoCodeSigning) Description() string {
	return "An aws_lambda_function without a code_signing_config block " +
		"deploys code without signature validation, so tampered deployment " +
		"packages run unchecked. Enforce code signing with AWS Signer."
}
func (lambdaNoCodeSigning) Severity() ir.Severity { return ir.SeverityMedium }
func (lambdaNoCodeSigning) AppliesTo(resType string) bool {
	return resType == "aws_lambda_function"
}

func (s lambdaNoCodeSigning) Check(r ir.Resource) []ir.Finding {
	if _, _, present, _ := getBlocks(r, "code_signing_config"); present {
		return nil
	}
	return []ir.Finding{lambdaFinding(s, r, "code_signing_config",
		ir.Span{}, "absent",
		"code_signing_config { ... } with AWS Signer")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-646: Lambda Java function without SnapStart
// ---------------------------------------------------------------------------

type lambdaNoSnapStart struct{}

func (lambdaNoSnapStart) ID() string { return "AEGIS-AWS-646" }
func (lambdaNoSnapStart) Title() string {
	return "Lambda Java function without SnapStart"
}
func (lambdaNoSnapStart) Description() string {
	return "Hygiene: a Java-based aws_lambda_function without snap_start " +
		"{ apply_on = \"PublishedVersions\" } pays full JVM cold-start " +
		"latency on every scale-out. Enable SnapStart for Java runtimes."
}
func (lambdaNoSnapStart) Severity() ir.Severity { return ir.SeverityLow }
func (lambdaNoSnapStart) AppliesTo(resType string) bool {
	return resType == "aws_lambda_function"
}

func (s lambdaNoSnapStart) Check(r ir.Resource) []ir.Finding {
	runtime, _, present, known := getString(r, "runtime")
	if !present || !known {
		return nil // runtime unknown: SnapStart applicability undecidable
	}
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(runtime)), "java") {
		return nil // SnapStart only supports Java runtimes
	}
	blks, _, spresent, sknown := getBlocks(r, "snap_start")
	if spresent && !sknown {
		return nil
	}
	for _, b := range blks {
		apply, _, apresent, aknown := blockString(b, "apply_on")
		if apresent && !aknown {
			return nil
		}
		if apresent && strings.EqualFold(strings.TrimSpace(apply), "PublishedVersions") {
			return nil
		}
	}
	return []ir.Finding{lambdaFinding(s, r, "snap_start",
		ir.Span{}, "absent",
		"snap_start { apply_on = \"PublishedVersions\" }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-647: Lambda function without dead-letter queue
// ---------------------------------------------------------------------------

type lambdaNoDeadLetter struct{}

func (lambdaNoDeadLetter) ID() string { return "AEGIS-AWS-647" }
func (lambdaNoDeadLetter) Title() string {
	return "Lambda function without dead-letter queue"
}
func (lambdaNoDeadLetter) Description() string {
	return "Hygiene: an aws_lambda_function without a dead_letter_config " +
		"block silently drops asynchronously-invoked events that fail all " +
		"retries. Route failed events to an SQS queue or SNS topic."
}
func (lambdaNoDeadLetter) Severity() ir.Severity { return ir.SeverityLow }
func (lambdaNoDeadLetter) AppliesTo(resType string) bool {
	return resType == "aws_lambda_function"
}

func (s lambdaNoDeadLetter) Check(r ir.Resource) []ir.Finding {
	if _, _, present, _ := getBlocks(r, "dead_letter_config"); present {
		return nil
	}
	return []ir.Finding{lambdaFinding(s, r, "dead_letter_config",
		ir.Span{}, "absent",
		"dead_letter_config { target_arn = aws_sqs_queue.dlq.arn }")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-648: Lambda function on an end-of-life runtime
// ---------------------------------------------------------------------------

type lambdaDeprecatedRuntime struct{}

// lambdaEOLRuntimes lists runtimes that are unambiguously end-of-life: AWS
// has ended support and they receive no security patches.
var lambdaEOLRuntimes = map[string]bool{
	"nodejs8.10": true, "nodejs10.x": true, "nodejs12.x": true,
	"python2.7": true, "python3.6": true,
	"ruby2.5": true, "ruby2.7": true,
	"dotnetcore2.1": true, "dotnetcore3.1": true,
	"go1.x": true,
	"java8": true,
}

func (lambdaDeprecatedRuntime) ID() string { return "AEGIS-AWS-648" }
func (lambdaDeprecatedRuntime) Title() string {
	return "Lambda function on an end-of-life runtime"
}
func (lambdaDeprecatedRuntime) Description() string {
	return "An aws_lambda_function pinned to an end-of-life runtime runs " +
		"on an unpatched language version with known vulnerabilities. " +
		"Migrate to a supported runtime."
}
func (lambdaDeprecatedRuntime) Severity() ir.Severity { return ir.SeverityMedium }
func (lambdaDeprecatedRuntime) AppliesTo(resType string) bool {
	return resType == "aws_lambda_function"
}

func (s lambdaDeprecatedRuntime) Check(r ir.Resource) []ir.Finding {
	runtime, span, present, known := getString(r, "runtime")
	if !present || !known {
		return nil
	}
	rt := strings.ToLower(strings.TrimSpace(runtime))
	if !lambdaEOLRuntimes[rt] {
		return nil
	}
	return []ir.Finding{lambdaFinding(s, r, "runtime", span,
		runtime, "a supported runtime (e.g. nodejs22.x, python3.13)")}
}

// ---------------------------------------------------------------------------
// AEGIS-AWS-649: Lambda function with plaintext secret in environment
// ---------------------------------------------------------------------------

type lambdaEnvPlaintextSecret struct{}

var (
	awsAccessKeyPattern = regexp.MustCompile(`^(AKIA|ASIA)[0-9A-Z]{16}$`)
	awsSecretKeyPattern = regexp.MustCompile(`^[A-Za-z0-9/+=]{40}$`)
)

func secretVarName(name string) bool {
	n := strings.ToLower(name)
	for _, hint := range []string{"secret", "passwd", "password", "token",
		"api_key", "apikey", "access_key", "private_key", "client_secret",
		"auth_key"} {
		if strings.Contains(n, hint) {
			return true
		}
	}
	return false
}

func secretVarValue(v string) bool {
	if awsAccessKeyPattern.MatchString(v) {
		return true
	}
	if awsSecretKeyPattern.MatchString(v) {
		return true
	}
	if len(v) >= 32 {
		var hasUpper, hasLower, hasDigit bool
		for _, c := range v {
			switch {
			case c >= 'A' && c <= 'Z':
				hasUpper = true
			case c >= 'a' && c <= 'z':
				hasLower = true
			case c >= '0' && c <= '9':
				hasDigit = true
			}
		}
		// Long mixed-case alphanumeric token: very likely a real secret.
		if hasUpper && hasLower && hasDigit {
			return true
		}
	}
	return false
}

func (lambdaEnvPlaintextSecret) ID() string { return "AEGIS-AWS-649" }
func (lambdaEnvPlaintextSecret) Title() string {
	return "Lambda function with plaintext secret in environment variables"
}
func (lambdaEnvPlaintextSecret) Description() string {
	return "An aws_lambda_function environment variable holding a value " +
		"that looks like a live credential (AWS key, 40-char secret, or " +
		"long mixed token) exposes the secret to anyone with read access " +
		"to the function configuration. Reference secrets from AWS Secrets " +
		"Manager or SSM Parameter Store instead."
}
func (lambdaEnvPlaintextSecret) Severity() ir.Severity { return ir.SeverityHigh }
func (lambdaEnvPlaintextSecret) AppliesTo(resType string) bool {
	return resType == "aws_lambda_function"
}

func (s lambdaEnvPlaintextSecret) Check(r ir.Resource) []ir.Finding {
	blks, _, present, known := getBlocks(r, "environment")
	if !present || !known {
		return nil
	}
	for _, b := range blks {
		vv, ok := b["variables"]
		if !ok || !vv.Known {
			continue // unresolved variables map: cannot decide
		}
		vars, ok := vv.AsMap()
		if !ok {
			continue // unexpected shape: cannot decide
		}
		for name, val := range vars {
			str, ok := val.AsString()
			if !ok {
				continue // unresolved value: cannot decide
			}
			if secretVarName(name) && secretVarValue(str) {
				return []ir.Finding{lambdaFinding(s, r,
					"environment.variables."+name, val.Span,
					"plaintext credential value",
					"reference from Secrets Manager / SSM Parameter Store")}
			}
		}
	}
	return nil
}

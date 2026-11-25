package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// secretTF is a fixture that trips AEGIS-AWS-538 (plaintext variable
// default) with a live secret value. It proves end to end that the
// secret never reaches the webhook receiver.
const secretTF = `variable "db_password" {
  default = "hunter2-VERY-SECRET-VALUE-9f3a"
}
`

// captureServer records every request body it receives. It is plain
// HTTP, so tests pass --webhook-allow-http (the loopback/lab opt-in).
type captureServer struct {
	srv    *httptest.Server
	calls  int32
	bodies [][]byte
	status int
}

func newCaptureServer(t *testing.T, status int) *captureServer {
	t.Helper()
	c := &captureServer{status: status}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&c.calls, 1)
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r.Body)
		c.bodies = append(c.bodies, buf.Bytes())
		w.WriteHeader(status)
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *captureServer) url() string { return c.srv.URL + "/hook" }

func TestScanWebhookDelivers(t *testing.T) {
	dir := writeFixtures(t)
	srv := newCaptureServer(t, http.StatusOK)

	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", dir, "--format=json", "--webhook", srv.url(), "--webhook-allow-http"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1 (findings), got %d; stderr: %s", code, stderr.String())
	}
	if srv.calls != 1 {
		t.Fatalf("expected 1 webhook delivery, got %d", srv.calls)
	}
	// The local report is intact and valid JSON.
	var env map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("stdout is not valid JSON: %v", err)
	}
	// The delivered payload is the same JSON envelope as the local
	// --format=json output.
	var delivered map[string]any
	if err := json.Unmarshal(srv.bodies[0], &delivered); err != nil {
		t.Fatalf("webhook body is not valid JSON: %v", err)
	}
	if delivered["aegis_version"] != env["aegis_version"] {
		t.Errorf("webhook payload version %v != local report %v", delivered["aegis_version"], env["aegis_version"])
	}
	findings, _ := delivered["findings"].([]any)
	if len(findings) == 0 {
		t.Errorf("webhook payload carries no findings")
	}
	if !strings.Contains(stderr.String(), "webhook delivered") {
		t.Errorf("expected delivery confirmation on stderr, got: %s", stderr.String())
	}
}

func TestScanWebhookSecretRedactedEndToEnd(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secret.tf"), []byte(secretTF), 0o644); err != nil {
		t.Fatal(err)
	}
	srv := newCaptureServer(t, http.StatusOK)

	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", dir, "--format=json", "--webhook", srv.url(), "--webhook-allow-http"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1 (findings), got %d; stderr: %s", code, stderr.String())
	}
	if srv.calls != 1 {
		t.Fatalf("expected 1 webhook delivery, got %d", srv.calls)
	}
	const secret = "hunter2-VERY-SECRET-VALUE-9f3a"
	if bytes.Contains(srv.bodies[0], []byte(secret)) {
		t.Fatalf("webhook payload contains the raw secret:\n%s", srv.bodies[0])
	}
	if bytes.Contains(stdout.Bytes(), []byte(secret)) {
		t.Fatalf("local JSON report contains the raw secret")
	}
	// The secret finding itself must still be delivered (redacted).
	var delivered map[string]any
	if err := json.Unmarshal(srv.bodies[0], &delivered); err != nil {
		t.Fatal(err)
	}
	seen538 := false
	for _, f := range delivered["findings"].([]any) {
		if f.(map[string]any)["rule_id"] == "AEGIS-AWS-538" {
			seen538 = true
			if !strings.Contains(f.(map[string]any)["evidence"].(string), "[REDACTED") {
				t.Errorf("538 evidence not redacted: %q", f.(map[string]any)["evidence"])
			}
		}
	}
	if !seen538 {
		t.Errorf("expected AEGIS-AWS-538 in the webhook payload")
	}
}

func TestScanWebhookUnreachableKeepsLocalResult(t *testing.T) {
	dir := writeFixtures(t)
	// Start a server, then close it: the endpoint exists in form but
	// refuses connections — the delivery-failure path.
	srv := newCaptureServer(t, http.StatusOK)
	deadURL := srv.url()
	srv.srv.Close()

	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", dir, "--format=json", "--webhook", deadURL, "--webhook-allow-http"}, &stdout, &stderr)
	// Delivery failure must NOT lose the local result: exit code still
	// reflects the findings (1), stdout still carries the full report.
	if code != 1 {
		t.Fatalf("expected exit 1 (findings, delivery failure must not change it), got %d; stderr: %s", code, stderr.String())
	}
	var env map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &env); err != nil {
		t.Fatalf("stdout is not valid JSON after failed delivery: %v", err)
	}
	if len(env["findings"].([]any)) == 0 {
		t.Errorf("local report lost its findings after failed delivery")
	}
	if !strings.Contains(stderr.String(), "webhook delivery failed") {
		t.Errorf("expected a delivery-failure warning on stderr, got: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "local results unaffected") {
		t.Errorf("warning should say local results are unaffected, got: %s", stderr.String())
	}
}

func TestScanWebhookFailOnError(t *testing.T) {
	dir := writeFixtures(t)
	srv := newCaptureServer(t, http.StatusOK)
	deadURL := srv.url()
	srv.srv.Close()

	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", dir, "--webhook", deadURL, "--webhook-allow-http", "--webhook-fail-on-error"}, &stdout, &stderr)
	if code != 2 {
		t.Fatalf("expected exit 2 with --webhook-fail-on-error, got %d; stderr: %s", code, stderr.String())
	}
	// The local report is still printed even when delivery is fatal.
	if len(stdout.Bytes()) == 0 {
		t.Errorf("local report missing even with --webhook-fail-on-error")
	}
}

func TestScanWebhookDryRunSendsNothing(t *testing.T) {
	dir := writeFixtures(t)
	srv := newCaptureServer(t, http.StatusOK)

	var stdout, stderr bytes.Buffer
	code := run([]string{"scan", dir, "--webhook", srv.url(), "--webhook-allow-http", "--webhook-dry-run"}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("expected exit 1 (findings), got %d; stderr: %s", code, stderr.String())
	}
	if srv.calls != 0 {
		t.Fatalf("dry-run must not send anything, got %d requests", srv.calls)
	}
	if !strings.Contains(stderr.String(), "webhook dry-run") {
		t.Errorf("expected dry-run notice on stderr, got: %s", stderr.String())
	}
}

func TestScanWebhookInvalidURLFailsFast(t *testing.T) {
	dir := writeFixtures(t)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"http refused", []string{"scan", dir, "--webhook", "http://siem.example.com/hook"}, "plain-http"},
		{"bad url", []string{"scan", dir, "--webhook", "://not-a-url"}, "invalid URL"},
		{"secret without endpoint", []string{"scan", dir, "--webhook-secret", "tok123"}, "require --webhook"},
		{"auth header rejected", []string{"scan", dir, "--webhook", "https://siem.example.com/hook", "--webhook-header", "Authorization: Bearer x"}, "--webhook-secret"},
		{"malformed header", []string{"scan", dir, "--webhook", "https://siem.example.com/hook", "--webhook-header", "NoColonHere"}, "must be \"Name: value\""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := run(tc.args, &stdout, &stderr)
			if code != 2 {
				t.Fatalf("expected exit 2 (usage error), got %d; stderr: %s", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.want) {
				t.Errorf("stderr %q should mention %q", stderr.String(), tc.want)
			}
			if len(stdout.Bytes()) != 0 {
				t.Errorf("failed-fast scan should print no report, got stdout: %s", stdout.String())
			}
		})
	}
}

package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"aegis/internal/ir"
	"aegis/internal/report"
)

// secretFinding is a finding whose evidence carries a live secret value
// in a secret-looking attribute: exactly the shape a rule must never
// emit, and the shape Payload must redact even if one ever does.
func secretFinding() ir.Finding {
	return ir.Finding{
		RuleID:   "AEGIS-AWS-538",
		Title:    "Secret in plaintext variable default",
		Severity: ir.SeverityHigh,
		Resource: "var.db_password",
		Evidence: ir.Evidence{
			Attribute: "password",
			Actual:    "hunter2-VERY-SECRET-VALUE-9f3a",
			Span:      ir.Span{File: "main.tf", StartLine: 3},
		},
	}
}

func scanResultWith(fs ...ir.Finding) ir.ScanResult {
	return ir.ScanResult{
		Target:   "testdata",
		Findings: fs,
	}
}

// --- payload shape & redaction ---

func TestPayloadMatchesJSONReport(t *testing.T) {
	res := scanResultWith(secretFinding())
	payload, err := Payload(res)
	if err != nil {
		t.Fatalf("Payload: %v", err)
	}
	// The webhook payload must be the same document the CLI prints for
	// --format=json: same envelope, same findings, same redaction.
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, res); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if !bytes.Equal(payload, buf.Bytes()) {
		t.Fatalf("webhook payload differs from --format=json output:\nwebhook: %s\njson:    %s", payload, buf.Bytes())
	}
}

func TestPayloadRedactsSecrets(t *testing.T) {
	const secret = "hunter2-VERY-SECRET-VALUE-9f3a"
	payload, err := Payload(scanResultWith(secretFinding()))
	if err != nil {
		t.Fatalf("Payload: %v", err)
	}
	if bytes.Contains(payload, []byte(secret)) {
		t.Fatalf("payload contains the raw secret value:\n%s", payload)
	}
	if !bytes.Contains(payload, []byte("[REDACTED]")) {
		t.Fatalf("payload has no [REDACTED] placeholder:\n%s", payload)
	}
	// The finding itself must still be delivered — redaction removes
	// the value, never the finding.
	var env map[string]any
	if err := json.Unmarshal(payload, &env); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	findings, _ := env["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding in payload, got %d", len(findings))
	}
}

// --- URL validation (fail fast, before scanning) ---

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr string // substring; "" = no error
	}{
		{"https ok", NewConfig("https://siem.example.com/hook"), ""},
		{"https with port and path", NewConfig("https://siem.example.com:8443/aegis/hook"), ""},
		{"empty url", NewConfig(""), "requires a URL"},
		{"no scheme", NewConfig("siem.example.com/hook"), "missing host"},
		{"no host", NewConfig("https://"), "missing host"},
		{"http refused", NewConfig("http://siem.example.com/hook"), "refusing plain-http"},
		{"ftp refused", NewConfig("ftp://siem.example.com/hook"), "unsupported URL scheme"},
		{"userinfo refused", NewConfig("https://token123@siem.example.com/hook"), "must not embed credentials"},
		{"bad url", NewConfig("https://%zz"), "invalid URL"},
		{"zero timeout", func() Config { c := NewConfig("https://x.example.com"); c.Timeout = 0; return c }(), "must be positive"},
		{"zero attempts", func() Config { c := NewConfig("https://x.example.com"); c.MaxAttempts = 0; return c }(), "between 1 and"},
		{"too many attempts", func() Config { c := NewConfig("https://x.example.com"); c.MaxAttempts = 99; return c }(), "between 1 and"},
		{"auth via header refused", func() Config {
			c := NewConfig("https://x.example.com")
			c.Headers = map[string]string{"Authorization": "Bearer x"}
			return c
		}(), "--webhook-secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not contain %q", err, tc.wantErr)
				}
			}
		})
	}
}

func TestValidateAllowsHTTPWithOptIn(t *testing.T) {
	cfg := NewConfig("http://127.0.0.1:9000/hook")
	cfg.AllowHTTP = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("http with --webhook-allow-http should validate: %v", err)
	}
}

// --- delivery: success, auth, headers ---

func TestDeliverSuccess(t *testing.T) {
	var gotBody []byte
	var gotCT, gotUA, gotAuth, gotCustom string
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		body, _ := io.ReadAll(r.Body)
		gotBody = body
		gotCT = r.Header.Get("Content-Type")
		gotUA = r.Header.Get("User-Agent")
		gotAuth = r.Header.Get("Authorization")
		gotCustom = r.Header.Get("X-Aegis-Source")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := NewConfig(srv.URL)
	cfg.AllowHTTP = true
	cfg.Secret = "s3cr3t-token-do-not-log"
	cfg.Headers = map[string]string{"X-Aegis-Source": "ci"}
	payload, err := Payload(scanResultWith(secretFinding()))
	if err != nil {
		t.Fatal(err)
	}
	if err := Deliver(context.Background(), cfg, payload); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if calls != 1 {
		t.Errorf("expected 1 request, got %d", calls)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", gotCT)
	}
	if !strings.HasPrefix(gotUA, "aegis/") {
		t.Errorf("User-Agent = %q, want aegis/<version>", gotUA)
	}
	if !AuthHeaderEqual(gotAuth, "s3cr3t-token-do-not-log") {
		t.Errorf("Authorization header missing or wrong")
	}
	if gotCustom != "ci" {
		t.Errorf("custom header = %q, want ci", gotCustom)
	}
	if !bytes.Equal(gotBody, payload) {
		t.Errorf("server received a different body than the payload")
	}
}

// --- delivery: failure modes ---

func TestDeliver4xxNotRetried(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	cfg := NewConfig(srv.URL)
	cfg.AllowHTTP = true
	cfg.Secret = "s3cr3t-token-do-not-log"
	err := Deliver(context.Background(), cfg, []byte(`{}`))
	if err == nil {
		t.Fatal("expected error on 401, got nil")
	}
	if calls != 1 {
		t.Errorf("4xx must not be retried: got %d calls, want 1", calls)
	}
	if !strings.Contains(err.Error(), "401") {
		t.Errorf("error should name the status: %v", err)
	}
	// The token must never appear in the error text.
	if strings.Contains(err.Error(), "s3cr3t-token-do-not-log") {
		t.Errorf("error leaks the token: %v", err)
	}
}

func TestDeliver5xxRetriesThenSucceeds(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	cfg := NewConfig(srv.URL)
	cfg.AllowHTTP = true
	if err := Deliver(context.Background(), cfg, []byte(`{}`)); err != nil {
		t.Fatalf("Deliver after transient 5xx: %v", err)
	}
	if calls != 3 {
		t.Errorf("expected 3 attempts, got %d", calls)
	}
}

func TestDeliver5xxExhaustsAttempts(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	cfg := NewConfig(srv.URL)
	cfg.AllowHTTP = true
	cfg.MaxAttempts = 3
	err := Deliver(context.Background(), cfg, []byte(`{}`))
	if err == nil {
		t.Fatal("expected error after 5xx exhaustion, got nil")
	}
	if calls != 3 {
		t.Errorf("expected exactly MaxAttempts=3 calls, got %d", calls)
	}
	if !strings.Contains(err.Error(), "503") {
		t.Errorf("error should name the status: %v", err)
	}
}

func TestDeliverTimeoutBounded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // far past the client timeout
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := NewConfig(srv.URL)
	cfg.AllowHTTP = true
	cfg.Timeout = 200 * time.Millisecond
	cfg.MaxAttempts = 1 // one attempt: the timeout itself is the bound
	start := time.Now()
	err := Deliver(context.Background(), cfg, []byte(`{}`))
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if elapsed > 2*time.Second {
		t.Errorf("delivery took %v with a 200ms timeout — a scan must never hang on a webhook", elapsed)
	}
}

func TestDeliverUnreachable(t *testing.T) {
	// Port 1 on loopback: nothing listens, connection refused fast.
	cfg := NewConfig("https://127.0.0.1:1/hook")
	cfg.Timeout = 2 * time.Second
	cfg.MaxAttempts = 1
	err := Deliver(context.Background(), cfg, []byte(`{}`))
	if err == nil {
		t.Fatal("expected error for unreachable endpoint, got nil")
	}
}

func TestDeliverInvalidURLFailsFast(t *testing.T) {
	cfg := NewConfig("http://127.0.0.1:1/hook") // http, no opt-in
	err := Deliver(context.Background(), cfg, []byte(`{}`))
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), "plain-http") {
		t.Errorf("expected http-refusal error, got: %v", err)
	}
}

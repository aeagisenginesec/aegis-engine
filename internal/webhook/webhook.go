// Package webhook POSTs a scan result to a SIEM/SOAR webhook endpoint.
//
// The payload is byte-identical in shape to the normal JSON report
// (report.WriteJSON): the same envelope, the same findings, and the same
// secret redaction. A SIEM parser that already consumes `aegis scan
// --format=json` needs no change to consume a webhook delivery.
//
// Security properties, by design:
//   - HTTPS only. Plain HTTP is refused unless AllowHTTP is set, because
//     scan findings (file paths, resource names, rule IDs) would cross
//     the wire in cleartext. The opt-out exists for loopback/lab
//     receivers only and must be an explicit flag, never a default.
//   - The Bearer token is never logged, never included in an error
//     message, and never placed in the URL. Validate rejects URLs with
//     embedded userinfo for the same reason.
//   - Delivery failure never loses the local result: the CLI writes the
//     local report first and treats a failed delivery as a warning
//     (or, with FailOnError, as exit 2) — the scan exit code for
//     findings is unchanged.
//   - Retries are bounded: MaxAttempts total attempts with exponential
//     backoff, then a final error. A webhook can never hang a scan:
//     every attempt is bounded by the per-attempt Timeout.
package webhook

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"aegis/internal/ir"
	"aegis/internal/report"
	"aegis/internal/version"
)

// Defaults.
const (
	// DefaultTimeout bounds one delivery attempt end to end.
	DefaultTimeout = 10 * time.Second
	// DefaultMaxAttempts is the total number of POST attempts (first
	// try + retries). 3 attempts with backoff is enough to ride out a
	// transient 5xx without turning a scan into a long wait.
	DefaultMaxAttempts = 3
	// DefaultMaxAttemptsCap bounds --webhook-attempts: more than 10
	// attempts is a misconfiguration, not resilience.
	DefaultMaxAttemptsCap = 10
	// maxResponseBody caps how much of an error response body is read.
	// The body is discarded; the cap only stops a hostile endpoint
	// from making the client buffer an unbounded response.
	maxResponseBody = 1 << 20 // 1 MiB
	// backoffBase is the sleep before the first retry; it doubles per
	// retry (500ms, 1s, 2s, ...). Total worst-case wait for the default
	// 3 attempts is ~1.5s of backoff plus 3 timeouts.
	backoffBase = 500 * time.Millisecond
)

// Config carries everything Deliver needs. Use NewConfig to get the
// defaults, then set fields; Validate must pass before any delivery.
type Config struct {
	// URL is the webhook endpoint. HTTPS is required unless AllowHTTP.
	URL string
	// Secret, when non-empty, is sent as `Authorization: Bearer <secret>`.
	// It is never logged or included in error text.
	Secret string
	// Headers are extra request headers (e.g. X-Api-Key). "Authorization"
	// is rejected here: use Secret instead, so the token has exactly
	// one code path and cannot leak through a header list.
	Headers map[string]string
	// Timeout bounds one attempt (connect + send + read headers/body).
	Timeout time.Duration
	// MaxAttempts is the total number of POST attempts (>= 1).
	MaxAttempts int
	// AllowHTTP permits a plain-http:// URL. Only for loopback/lab
	// receivers; never the default.
	AllowHTTP bool
	// DryRun prints what would be sent (to the caller's writer) without
	// sending anything. Handled by the CLI, not by Deliver.
	DryRun bool
	// FailOnError makes the CLI exit 2 when delivery fails. The
	// default (false) only warns: a dead SIEM must not turn a clean
	// scan into a failed one, and must never lose the local report.
	FailOnError bool
}

// NewConfig returns a Config with the documented defaults for url.
func NewConfig(url string) Config {
	return Config{
		URL:         url,
		Timeout:     DefaultTimeout,
		MaxAttempts: DefaultMaxAttempts,
	}
}

// Validate checks cfg before any scan work starts, so a bad endpoint
// fails fast (exit 2) instead of after a full scan. It never includes
// the secret in an error, and it strips any query string from the URL
// it reports, in case a token was pasted there.
func (c Config) Validate() error {
	if strings.TrimSpace(c.URL) == "" {
		return fmt.Errorf("webhook: --webhook requires a URL")
	}
	u, err := url.Parse(c.URL)
	if err != nil {
		return fmt.Errorf("webhook: invalid URL %q: %v", c.URL, err)
	}
	if u.Host == "" {
		return fmt.Errorf("webhook: invalid URL %q: missing host", c.URL)
	}
	if u.User != nil {
		return fmt.Errorf("webhook: URL must not embed credentials (userinfo); pass the token with --webhook-secret")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !c.AllowHTTP {
			return fmt.Errorf("webhook: refusing plain-http URL %s (findings would cross the wire in cleartext); use https:// or pass --webhook-allow-http for a loopback/lab receiver", safeURL(u))
		}
	default:
		return fmt.Errorf("webhook: unsupported URL scheme %q (want https://)", u.Scheme)
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("webhook: --webhook-timeout must be positive (got %s)", c.Timeout)
	}
	if c.MaxAttempts < 1 || c.MaxAttempts > DefaultMaxAttemptsCap {
		return fmt.Errorf("webhook: --webhook-attempts must be between 1 and %d (got %d)", DefaultMaxAttemptsCap, c.MaxAttempts)
	}
	for name := range c.Headers {
		if strings.EqualFold(name, "Authorization") {
			return fmt.Errorf("webhook: pass the token with --webhook-secret (or AEGIS_WEBHOOK_SECRET), not --webhook-header Authorization")
		}
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("webhook: empty header name in --webhook-header")
		}
	}
	return nil
}

// safeURL renders u without userinfo and without the query string, so a
// token pasted into either can never reach a log line or an error.
func safeURL(u *url.URL) string {
	c := *u
	c.User = nil
	c.RawQuery = ""
	c.ForceQuery = false
	return c.String()
}

// Payload renders res exactly as the normal JSON report does: the same
// envelope, and the same secret redaction (report.WriteJSON redacts
// secret-looking evidence before encoding). Keeping this one code path
// means a SIEM parser written against --format=json output works
// unchanged against webhook deliveries, and a secret can never leak
// through a second, divergent serializer.
func Payload(res ir.ScanResult) ([]byte, error) {
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, res); err != nil {
		return nil, fmt.Errorf("webhook: rendering payload: %w", err)
	}
	return buf.Bytes(), nil
}

// Deliver POSTs payload to cfg.URL with cfg's auth, headers, timeout and
// retry policy. It returns nil on any 2xx response. 4xx responses are
// not retried (the request itself was rejected); 5xx, 429 and transport
// errors are retried up to MaxAttempts with exponential backoff, then
// the last error is returned. Error text carries the endpoint (host and
// path only, no query) and the status, never the secret and never a
// response body.
func Deliver(ctx context.Context, cfg Config, payload []byte) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	u, _ := url.Parse(cfg.URL) // Validate already parsed it
	target := safeURL(u)
	client := &http.Client{Timeout: cfg.Timeout}

	var lastErr error
	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("webhook: delivery to %s cancelled: %v", target, err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(payload))
		if err != nil {
			return fmt.Errorf("webhook: building request to %s: %v", target, err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "aegis/"+version.Version)
		if cfg.Secret != "" {
			req.Header.Set("Authorization", "Bearer "+cfg.Secret)
		}
		for name, value := range cfg.Headers {
			req.Header.Set(name, value)
		}

		resp, err := client.Do(req)
		if err != nil {
			// Transport error (DNS, refused, timeout): retryable.
			lastErr = fmt.Errorf("webhook: delivery to %s failed (attempt %d/%d): %v", target, attempt, cfg.MaxAttempts, err)
			if !sleepBeforeRetry(ctx, attempt, cfg.MaxAttempts) {
				break
			}
			continue
		}
		// Drain (capped) and close so the connection can be reused;
		// the body itself is never logged or returned.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBody))
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			// 4xx (other than 429): the endpoint rejected the request
			// itself; retrying the same payload will not help.
			return fmt.Errorf("webhook: delivery to %s rejected with HTTP %d (not retried)", target, resp.StatusCode)
		}
		// 5xx / 429: retryable.
		lastErr = fmt.Errorf("webhook: delivery to %s failed with HTTP %d (attempt %d/%d)", target, resp.StatusCode, attempt, cfg.MaxAttempts)
		if !sleepBeforeRetry(ctx, attempt, cfg.MaxAttempts) {
			break
		}
	}
	return lastErr
}

// sleepBeforeRetry waits the exponential backoff before the next
// attempt. It returns false when this was the last attempt (no sleep
// needed) or the context was cancelled.
func sleepBeforeRetry(ctx context.Context, attempt, maxAttempts int) bool {
	if attempt >= maxAttempts {
		return false
	}
	backoff := backoffBase * time.Duration(1<<(attempt-1))
	select {
	case <-ctx.Done():
		return false
	case <-time.After(backoff):
		return true
	}
}

// AuthHeaderEqual is a test helper: it reports whether got is the exact
// Bearer header for secret, using constant-time comparison. It exists
// so tests can assert the token arrived without ever printing it.
func AuthHeaderEqual(got, secret string) bool {
	want := "Bearer " + secret
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

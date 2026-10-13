// Command surface for `aegis serve`: a small HTTP API over the scan
// pipeline, stdlib net/http only.
//
// Endpoints:
//
//	GET  /v1/health -> {"status":"ok","version":"1.0.0"}
//	POST /v1/scan   -> {"files":[{"path":"main.tf","content":"..."}],"rules":"aws"}
//	                   runs the full in-memory pipeline (no disk writes) and
//	                   returns {"resources":n,"findings":[...],"diagnostics":[...]}
//
// Bounds: request bodies capped at 32 MiB, at most 1000 files per request,
// per-request timeout of 60s, at most 16 concurrent scans. Module expansion
// (which needs a directory on disk) is skipped for in-memory scans;
// variable/local resolution still applies. Findings are secret-redacted
// exactly like the CLI reports.
//
// Authentication: none by default (the default bind is loopback-only).
// Pass --auth-token (or AEGIS_SERVE_TOKEN) to require
// `Authorization: Bearer <token>` on POST /v1/scan; do this whenever the
// API binds a non-loopback address. The health endpoint stays open so
// liveness probes keep working.
package main

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"aegis/internal/adapter/terraform"
	"aegis/internal/ir"
	"aegis/internal/report"
	"aegis/internal/rules"
	"aegis/internal/semantics"
)

const (
	// defaultServeAddr is used when runServe gets an empty address.
	// Loopback-only by default: the API exposes scan results, so it
	// must not bind to all interfaces without an explicit choice.
	defaultServeAddr = "127.0.0.1:8734"
	// maxScanBody caps POST /v1/scan request bodies.
	maxScanBody = 32 << 20 // 32 MiB
	// maxScanFiles caps the number of files per scan request.
	maxScanFiles = 1000
	// requestTimeout bounds each request end to end.
	requestTimeout = 60 * time.Second
	// maxConcurrentScans bounds simultaneous scan handlers. Without a
	// cap, an unauthenticated client could run N × 32 MiB scans in
	// parallel and exhaust memory; excess scans fail fast with 503
	// instead of queueing (a queue would itself be a DoS vector).
	maxConcurrentScans = 16
	// maxServeDiagChars caps any single diagnostic message in API
	// responses. A parser diagnostic must never amplify a small input
	// into a giant response (the old manifests YAML path turned 12 KiB
	// into a 120 MB diagnostic; see Item 5).
	maxServeDiagChars = 2048
)

// scanSemaphore gates concurrent POST /v1/scan handlers.
var scanSemaphore = make(chan struct{}, maxConcurrentScans)

// serveHandler carries per-server options for the API handlers.
type serveHandler struct {
	authToken string
}

// newServeMux builds the API routes. Factored out for httptest.
// authToken is "" for no authentication; when non-empty, POST /v1/scan
// requires `Authorization: Bearer <token>`.
func newServeMux(authToken string) *http.ServeMux {
	h := &serveHandler{authToken: authToken}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/health", handleHealth)
	mux.HandleFunc("/v1/scan", h.handleScan)
	// JSON 404 for everything else (Go's default is a plain-text page).
	mux.HandleFunc("/", handleNotFound)
	return mux
}

// isNonLoopbackAddr reports whether addr binds something other than
// loopback. An empty host (":8734") binds all interfaces: non-loopback.
func isNonLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return true
	}
	if host == "" || host == "localhost" {
		return host == ""
	}
	ip := net.ParseIP(host)
	return ip == nil || !ip.IsLoopback()
}

// runServe starts the HTTP API on addr (default 127.0.0.1:8734 when empty)
// and blocks until the server stops. Returns 0 on clean shutdown, 1 when
// the listener fails. Logs go to stderr via the standard log package.
// authToken, when non-empty, is required as a Bearer token on /v1/scan.
func runServe(addr, authToken string) int {
	if addr == "" {
		addr = defaultServeAddr
	}
	if isNonLoopbackAddr(addr) {
		if authToken == "" {
			log.Printf("aegis serve: WARNING: listening on non-loopback %s with NO authentication — anyone who can reach this port can run scans. Bind loopback or pass --auth-token.", addr)
		} else {
			log.Printf("aegis serve: listening on %s (Bearer-token authentication required for /v1/scan)", addr)
		}
	} else {
		log.Printf("aegis serve: listening on %s", addr)
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           http.TimeoutHandler(newServeMux(authToken), requestTimeout, `{"error":"request timed out"}`),
		ReadHeaderTimeout: 10 * time.Second,
		// ReadTimeout bounds slow-trickle bodies: without it a client
		// could hold a handler goroutine open indefinitely past the
		// 60 s handler timeout (TimeoutHandler cannot kill a handler
		// blocked reading the body).
		ReadTimeout: 70 * time.Second,
		IdleTimeout: 120 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("aegis serve: %v", err)
		return 1
	}
	return 0
}

// handleNotFound answers unmatched routes with a JSON 404.
func handleNotFound(w http.ResponseWriter, r *http.Request) {
	writeServeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
}

// handleHealth answers GET /v1/health.
func handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	writeServeJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": report.Version})
}

// scanFile is one in-memory source file in a scan request.
type scanFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// scanRequest is the POST /v1/scan body.
type scanRequest struct {
	Files []scanFile `json:"files"`
	Rules string     `json:"rules"` // "aws" (default when empty)
}

// scanResponse is the POST /v1/scan result.
type scanResponse struct {
	Resources   int             `json:"resources"`
	Findings    []ir.Finding    `json:"findings"`
	Diagnostics []ir.Diagnostic `json:"diagnostics"`
}

// handleScan answers POST /v1/scan by running the full pipeline in memory.
func (h *serveHandler) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	// Authentication first: unauthenticated clients must not occupy a
	// scan slot (or any other resource).
	if h.authToken != "" {
		want := "Bearer " + h.authToken
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte(want)) != 1 {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
	}
	// Concurrency cap: fail fast, never queue.
	select {
	case scanSemaphore <- struct{}{}:
		defer func() { <-scanSemaphore }()
	default:
		http.Error(w, `{"error":"server busy"}`, http.StatusServiceUnavailable)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxScanBody)
	dec := json.NewDecoder(r.Body)
	var req scanRequest
	if err := dec.Decode(&req); err != nil {
		if strings.Contains(err.Error(), "request body too large") {
			http.Error(w, `{"error":"request body exceeds 32 MiB"}`, http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, `{"error":"invalid JSON body"}`, http.StatusBadRequest)
		return
	}
	// Strict JSON: trailing data after the first value is rejected.
	// (The old decoder silently accepted `{"files":[]} garbage`.)
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		http.Error(w, `{"error":"invalid JSON body (trailing data)"}`, http.StatusBadRequest)
		return
	}
	if len(req.Files) > maxScanFiles {
		http.Error(w, `{"error":"too many files (max 1000)"}`, http.StatusBadRequest)
		return
	}
	rulesParam := req.Rules
	if rulesParam == "" {
		rulesParam = "all"
	}
	packs := strings.Split(rulesParam, ",")
	if unknown := rules.UnknownPacks(packs); len(unknown) > 0 {
		http.Error(w, `{"error":"unknown ruleset"}`, http.StatusBadRequest)
		return
	}
	resp := scanFilesInMemory(req.Files, rules.RegistryFor(packs...))
	resp.Findings = redactServeFindings(resp.Findings)
	resp.Diagnostics = truncateServeDiagnostics(resp.Diagnostics)
	writeServeJSON(w, http.StatusOK, resp)
}

// sanitizeServeParseErr strips internal panic text from a parse error
// before it reaches an API client. Panic values name internal code
// paths; the client only needs to know the file failed to parse.
func sanitizeServeParseErr(err error) string {
	if err == nil {
		return ""
	}
	if strings.Contains(err.Error(), "panicked") {
		return "internal parser error (details withheld)"
	}
	return err.Error()
}

// truncateServeDiag caps one diagnostic message so a parser diagnostic
// can never amplify a small input into a giant response.
func truncateServeDiag(msg string) string {
	if len(msg) <= maxServeDiagChars {
		return msg
	}
	cut := msg[:maxServeDiagChars]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut + "… [truncated]"
}

// truncateServeDiagnostics caps every diagnostic message in a response.
func truncateServeDiagnostics(diags []ir.Diagnostic) []ir.Diagnostic {
	for i := range diags {
		diags[i].Message = truncateServeDiag(diags[i].Message)
	}
	return diags
}

// scanFilesInMemory runs discover-less scan pipeline over in-memory files:
// adapter selection by Handles, ParseModule for .tf (+ semantics
// variable/local resolution), planjson for .plan.json, then the default
// rule registry. Module expansion is skipped: it needs a directory on disk.
func scanFilesInMemory(files []scanFile, registry *rules.Registry) scanResponse {
	adapters := defaultAdapters()
	var resources []ir.Resource
	var mods []terraform.Module
	diags := []ir.Diagnostic{}
	for _, f := range files {
		var ad ir.Adapter
		for _, a := range adapters {
			if a.Handles(f.Path) {
				ad = a
				break
			}
		}
		if ad == nil {
			diags = append(diags, ir.Diagnostic{
				Level:   "warning",
				Message: fmt.Sprintf("no adapter handles %s; skipped", f.Path),
				Span:    ir.Span{File: f.Path},
			})
			continue
		}
		src := []byte(f.Content)
		if ta, ok := ad.(*terraform.Adapter); ok {
			mod, d, err := safeParseModule(ta, f.Path, src)
			diags = append(diags, d...)
			if err != nil {
				diags = append(diags, ir.Diagnostic{
					Level:   "error",
					Message: fmt.Sprintf("parse failed for %s: %s", f.Path, sanitizeServeParseErr(err)),
					Span:    ir.Span{File: f.Path},
				})
				continue
			}
			mods = append(mods, mod)
			resources = append(resources, mod.Resources...)
			// Synthetic terraform_* pseudo-resources (for secret-detection
			// rules 536/538/539). They carry no resolvable refs; semantic
			// resolution is a no-op for them.
			resources = append(resources, mod.SyntheticResources...)
			continue
		}
		// Non-terraform adapters (plan JSON today) go through plain Parse.
		rs, d, err := safeParse(ad, f.Path, src)
		diags = append(diags, d...)
		if err != nil {
			diags = append(diags, ir.Diagnostic{
				Level:   "error",
				Message: fmt.Sprintf("parse failed for %s: %s", f.Path, sanitizeServeParseErr(err)),
				Span:    ir.Span{File: f.Path},
			})
			continue
		}
		resources = append(resources, rs...)
	}
	if len(mods) > 0 {
		scope := semantics.MergeModules(mods)
		resources = scope.ResolveResources(resources)
		expandedDyn, dynDiags := scope.ExpandDynamicBlocks(resources)
		diags = append(diags, dynDiags...)
		resources = expandedDyn
	}
	findings := registry.Run(resources)
	if findings == nil {
		findings = []ir.Finding{}
	}
	return scanResponse{
		Resources:   len(resources),
		Findings:    findings,
		Diagnostics: diags,
	}
}

// secretSubstrings mirrors report's secret-key heuristic. Duplicated here
// because report.redactFindings is unexported and serve must not change
// report's API; keep the two in sync.
var secretSubstrings = []string{"password", "passwd", "secret", "token", "apikey", "api_key", "key"}

// redactServeFindings redacts secret-looking evidence values, mirroring
// report.redactFindings.
func redactServeFindings(fs []ir.Finding) []ir.Finding {
	out := make([]ir.Finding, 0, len(fs))
	for _, f := range fs {
		k := strings.ToLower(f.Evidence.Attribute)
		for _, sub := range secretSubstrings {
			if strings.Contains(k, sub) {
				f.Evidence.Actual = "[REDACTED]"
				break
			}
		}
		out = append(out, f)
	}
	return out
}

// writeServeJSON writes v as JSON with the given status code.
func writeServeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

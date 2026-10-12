# Follow-up Fixes: Detection Correctness Audit

**Date:** 2026-10-12
**Source:** Recommendations from `docs/DETECTION_CORRECTNESS.md` audit

Three defects identified and fixed. All verification green.

---

## Fix 1: Module Expansion Reference Rewriting (HIGHEST PRIORITY)

### Problem
When expanding Terraform modules, resources were renamed (e.g., `aws_s3_bucket.data`
→ `module.s3mod.aws_s3_bucket.data`) but intra-module references were NOT rewritten.
A reference like `bucket = aws_s3_bucket.data.id` inside the module stayed pointing
to the old (non-existent) address, breaking `CheckAll` companion correlation.

**Impact:** 5 rules flagged <80% precision (012, 206, 443, 445, 558) + 1 false positive.
All shared this single root cause.

### Fix
**File:** `internal/semantics/semantics.go`

1. In `expandCall()`: collect all resources first, build old-address → new-address map,
   then rename AND rewrite refs in a single pass.

2. New `rewriteRefs()` / `rewriteValueRefs()` / `rewriteRefString()`: recursively walk
   resource attributes (including nested `[]Value` and `map[string]Value`), rewriting
   any `Ref` string matching an old address prefix. Longest-prefix match ensures
   `aws_s3_bucket.data` doesn't accidentally match `aws_s3_bucket.data2`.

3. Fixed `refAddrOf()` in `internal/rules/aws/attack_paths.go`: the helper that reduces
   `aws_s3_bucket.data.id` → `aws_s3_bucket.data` couldn't parse module-prefixed refs
   like `aws_s3_bucket.module.s3mod.data.id`. Now handles `type.(module.<name>.)*name`
   format.

### Verification
- Module test fixture: `aws_s3_bucket_versioning` with `bucket = aws_s3_bucket.data.id`
  inside a module → rule 012 correctly suppressed (was false positive)
- Labeled corpus: precision 0.986 → **1.000**, FP-rate 0.033 → **0.000**

---

## Fix 2: Resolve jsonencode() with Variables

### Problem
IAM rules (003, 006, 101, 102, 501, 502, 343, 344, 415) stayed silent when policies
used `jsonencode({...})` with non-static arguments (e.g., `var.actions`). The adapter
only handled static jsonencode; anything with variables became a plain Unknown.

### Fix
**Files:** `internal/ir/ir.go`, `internal/adapter/terraform/terraform.go`,
`internal/semantics/semantics.go`

1. Added `EncodeJSON bool` field to `ir.Value` (marked `json:"-"` to exclude from output).

2. In adapter: when `jsonencode()` has non-static args, use `refOrPartial()` on the inner
   argument to preserve structure with refs intact, set `EncodeJSON=true`.

3. In semantics `resolveValue()`: after resolving containers, call `maybeEncodeJSON()`.
   If `EncodeJSON` is set and all children resolved to Known, JSON-encode the structure
   to a string. New `valueToGo()` helper converts `ir.Value` trees to Go natives.

### Verification
- Test: `policy = jsonencode({Version="2012-10-17", Statement=[{Effect="Allow", Action=var.actions, Resource="*"}]})`
  with `var.actions = ["*"]` → rules 006, 102, 501, 502, 503, 504 all fire (was 0 findings)
- Static jsonencode still works (existing behavior preserved)

---

## Fix 3: Tighten Rule 629 Severity

### Problem
Rule 629 (kill chain) emitted UNCERTAIN-entry chains as High severity without a proven
internet entry point. A speculative chain should not be High.

### Fix
**File:** `internal/rules/aws/attack_paths_killchain.go`

In the severity assignment: if `c.Uncertain` is true (any hop uncertain), downgrade to
`ir.SeverityMedium` regardless of IAM involvement. Certain chains keep High/Critical.

### Verification
- `TestKillChain629` and `TestKillChain629NoExposure` still pass
- Certain chains: unchanged severity
- Uncertain chains: now Medium

---

## Overall Verification

| Check | Result |
|-------|--------|
| `go build ./...` | ✅ clean |
| `go vet ./...` | ✅ clean |
| `gofmt` (changed files) | ✅ clean |
| `go test -count=1 ./...` | ✅ all packages green |
| `aegis quality-gate` | ✅ PASS (5/5) |
| Labeled corpus precision | 0.986 → **1.000** |
| Labeled corpus recall | 1.000 → **1.000** |
| Labeled corpus F1 | 0.993 → **1.000** |
| FP-rate | 0.033 → **0.000** |

**Rule count:** 587 (unchanged — no rules added or removed)
**Binary:** rebuilt at `~/workspace/aegis-engine/aegis`

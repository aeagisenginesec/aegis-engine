// Package rules — suppression support.
//
// Two mechanisms, both applied AFTER all rules run so rule logic stays pure:
//
//  1. Inline suppressions: `# aegis:skip=RULE-ID` (or comma-separated IDs,
//     or `all`) comments attached to a resource by the adapter. Only the
//     exact resource+rule pair is suppressed — never global.
//  2. Baselines: a JSON file of finding fingerprints (rule_id + resource +
//     attribute). `aegis scan --baseline=file` drops matching findings;
//     `--baseline-out=file` writes the current findings as a baseline.
package rules

import (
	"encoding/json"
	"os"
	"sort"
	"time"

	"aegis/internal/ir"
)

// suppressAll is the magic rule ID that suppresses every finding for a resource.
const suppressAll = "all"

// ApplyInlineSuppressions drops findings suppressed by resource-level
// aegis:skip comments. It never panics; a nil/empty input yields nil/empty
// output. Deterministic: output preserves input order.
func ApplyInlineSuppressions(resources []ir.Resource, findings []ir.Finding) []ir.Finding {
	if len(findings) == 0 {
		return findings
	}
	// Index suppressed rule IDs by resource address.
	suppressed := make(map[string]map[string]bool, len(resources))
	for _, r := range resources {
		if len(r.SuppressedRules) == 0 {
			continue
		}
		set, ok := suppressed[r.Address()]
		if !ok {
			set = map[string]bool{}
			suppressed[r.Address()] = set
		}
		for _, id := range r.SuppressedRules {
			set[id] = true
		}
	}
	if len(suppressed) == 0 {
		return findings
	}
	out := make([]ir.Finding, 0, len(findings))
	for _, f := range findings {
		set, ok := suppressed[f.Resource]
		if !ok {
			out = append(out, f)
			continue
		}
		if set[suppressAll] || set[f.RuleID] {
			continue // suppressed: exact resource+rule match (or all)
		}
		out = append(out, f)
	}
	return out
}

// Fingerprint identifies a finding stably across runs: rule, resource,
// and evidence attribute. Deliberately excludes values, spans, and
// descriptions so cosmetic edits don't resurrect baselined findings.
type Fingerprint struct {
	RuleID    string `json:"rule_id"`
	Resource  string `json:"resource"`
	Attribute string `json:"attribute"`
}

// BaselineEntry is a baselined finding fingerprint plus optional human
// metadata: why it was baselined, who owns the decision, and when the
// baseline entry expires (RFC3339 date, e.g. "2027-01-01"). Expired
// entries no longer suppress findings.
type BaselineEntry struct {
	Fingerprint
	Reason  string `json:"reason,omitempty"`
	Owner   string `json:"owner,omitempty"`
	Expires string `json:"expires,omitempty"`
}

// Baseline is a set of baselined finding fingerprints.
type Baseline struct {
	Version int `json:"version"`
	// Fingerprints is the legacy flat list (v1 files). Entries is the
	// enriched form (v2). LoadBaseline merges both; WriteBaseline emits
	// Entries when any entry carries metadata, else the flat form.
	Fingerprints []Fingerprint   `json:"fingerprints,omitempty"`
	Entries      []BaselineEntry `json:"entries,omitempty"`
	// index is built on load for O(1) matching; not serialized.
	index map[Fingerprint]bool
	// expired and invalidExpiry record the waiver-governance state found
	// at load: entries whose Expires date has passed (they no longer
	// suppress) and entries whose Expires value could not be parsed
	// (they still suppress — but callers should surface them, because a
	// mistyped expiry silently becomes a permanent waiver otherwise).
	expired       []BaselineEntry
	invalidExpiry []BaselineEntry
}

// FingerprintOf builds the stable fingerprint for a finding.
func FingerprintOf(f ir.Finding) Fingerprint {
	return Fingerprint{
		RuleID:    f.RuleID,
		Resource:  f.Resource,
		Attribute: f.Evidence.Attribute,
	}
}

// LoadBaseline reads a baseline JSON file. Missing index is rebuilt;
// a nil baseline (empty path) is not an error — callers treat nil as
// "no baseline". Never panics on malformed input: returns an error.
// Both v1 (flat fingerprints) and v2 (entries with metadata) are
// accepted; expired entries (Expires < now) are dropped on load.
func LoadBaseline(path string) (*Baseline, error) {
	if path == "" {
		return nil, nil
	}
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b Baseline
	if err := json.Unmarshal(src, &b); err != nil {
		return nil, err
	}
	b.buildIndex()
	return &b, nil
}

// buildIndex (re)builds the fingerprint lookup set, merging the legacy
// flat list and the enriched entries. Expired entries are skipped: an
// entry with Expires set to a past RFC3339 date no longer suppresses.
// Skipped entries are remembered (see ExpiredEntries) so the lapse is
// visible to the user instead of silent. An entry whose Expires cannot
// be parsed keeps suppressing but is remembered too (InvalidExpiryEntries):
// a typo must never quietly mint a permanent waiver.
func (b *Baseline) buildIndex() {
	n := len(b.Fingerprints) + len(b.Entries)
	b.index = make(map[Fingerprint]bool, n)
	for _, fp := range b.Fingerprints {
		b.index[fp] = true
	}
	b.expired = nil
	b.invalidExpiry = nil
	now := time.Now()
	for _, e := range b.Entries {
		if e.Expires != "" {
			t, err := time.Parse(time.RFC3339, e.Expires)
			switch {
			case err != nil:
				b.invalidExpiry = append(b.invalidExpiry, e)
			case t.Before(now):
				b.expired = append(b.expired, e)
				continue // expired: no longer suppresses
			}
		}
		b.index[e.Fingerprint] = true
	}
}

// ExpiredEntries returns the baseline entries whose Expires date has
// passed as of load time. Those entries did NOT suppress their
// findings in this run — the waiver lapsed and the finding is back.
func (b *Baseline) ExpiredEntries() []BaselineEntry {
	if b == nil {
		return nil
	}
	out := make([]BaselineEntry, len(b.expired))
	copy(out, b.expired)
	return out
}

// InvalidExpiryEntries returns the baseline entries whose Expires
// value is not a valid RFC3339 date. They still suppress (fail-open
// on content, by design), but they represent a governance defect the
// user should fix: as written, the waiver never expires.
func (b *Baseline) InvalidExpiryEntries() []BaselineEntry {
	if b == nil {
		return nil
	}
	out := make([]BaselineEntry, len(b.invalidExpiry))
	copy(out, b.invalidExpiry)
	return out
}

// Matches reports whether the finding's fingerprint is baselined.
func (b *Baseline) Matches(f ir.Finding) bool {
	if b == nil {
		return false
	}
	return b.index[FingerprintOf(f)]
}

// ApplyBaseline drops findings whose fingerprint appears in the baseline.
// A nil baseline returns findings unchanged. Deterministic: order preserved.
func ApplyBaseline(b *Baseline, findings []ir.Finding) []ir.Finding {
	if b == nil || len(findings) == 0 {
		return findings
	}
	out := make([]ir.Finding, 0, len(findings))
	for _, f := range findings {
		if !b.Matches(f) {
			out = append(out, f)
		}
	}
	return out
}

// WriteBaseline serializes findings as a stable, sorted fingerprint list.
// The output is deterministic: fingerprints sort by (rule_id, resource,
// attribute), so repeated runs over unchanged findings produce identical
// bytes.
func WriteBaseline(path string, findings []ir.Finding) error {
	fps := make([]Fingerprint, 0, len(findings))
	seen := map[Fingerprint]bool{}
	for _, f := range findings {
		fp := FingerprintOf(f)
		if !seen[fp] {
			seen[fp] = true
			fps = append(fps, fp)
		}
	}
	sort.Slice(fps, func(i, j int) bool {
		if fps[i].RuleID != fps[j].RuleID {
			return fps[i].RuleID < fps[j].RuleID
		}
		if fps[i].Resource != fps[j].Resource {
			return fps[i].Resource < fps[j].Resource
		}
		return fps[i].Attribute < fps[j].Attribute
	})
	b := Baseline{Version: 1, Fingerprints: fps}
	src, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	src = append(src, '\n')
	return os.WriteFile(path, src, 0o644)
}

// BaselineAnnotation carries human metadata for one baselined finding.
type BaselineAnnotation struct {
	Reason  string
	Owner   string
	Expires string // RFC3339 date; empty = no expiry
}

// WriteBaselineWithMetadata serializes findings as baseline entries with
// per-finding metadata. annotations maps FingerprintOf(finding) to its
// metadata; findings without an annotation get an entry with empty
// metadata. The output always uses the v2 "entries" form and is
// deterministic (sorted by rule_id, resource, attribute).
func WriteBaselineWithMetadata(path string, findings []ir.Finding, annotations map[Fingerprint]BaselineAnnotation) error {
	entries := make([]BaselineEntry, 0, len(findings))
	seen := map[Fingerprint]bool{}
	for _, f := range findings {
		fp := FingerprintOf(f)
		if seen[fp] {
			continue
		}
		seen[fp] = true
		e := BaselineEntry{Fingerprint: fp}
		if a, ok := annotations[fp]; ok {
			e.Reason = a.Reason
			e.Owner = a.Owner
			e.Expires = a.Expires
		}
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].RuleID != entries[j].RuleID {
			return entries[i].RuleID < entries[j].RuleID
		}
		if entries[i].Resource != entries[j].Resource {
			return entries[i].Resource < entries[j].Resource
		}
		return entries[i].Attribute < entries[j].Attribute
	})
	b := Baseline{Version: 2, Entries: entries}
	src, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	src = append(src, '\n')
	return os.WriteFile(path, src, 0o644)
}

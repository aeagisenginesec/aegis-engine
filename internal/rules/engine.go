// Package rules hosts the Aegis rule engine: a registry of ir.Rule
// implementations and a deterministic runner.
//
// Determinism contract: Run always emits findings sorted by (rule ID,
// resource address, evidence attribute), regardless of registration or
// input order. The same resources must always produce the same findings.
package rules

import (
	"runtime"
	"sort"
	"sync"

	"aegis/internal/ir"
)

// Registry holds a set of rules keyed by rule ID.
type Registry struct {
	byID   map[string]ir.Rule
	sorted []ir.Rule // cached sorted list, invalidated on Register
	mu     sync.RWMutex
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byID: make(map[string]ir.Rule)}
}

// Register adds a rule. A rule with a duplicate ID is ignored so that
// registration order can never change the rule set.
func (r *Registry) Register(rule ir.Rule) {
	if rule == nil || rule.ID() == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.byID[rule.ID()]; exists {
		return
	}
	r.byID[rule.ID()] = rule
	r.sorted = nil // invalidate cached sort
}

// All returns every registered rule, sorted by ID.
func (r *Registry) All() []ir.Rule {
	r.mu.RLock()
	if r.sorted != nil {
		defer r.mu.RUnlock()
		return r.sorted
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()
	// Double-check after acquiring write lock
	if r.sorted != nil {
		return r.sorted
	}
	out := make([]ir.Rule, 0, len(r.byID))
	for _, rule := range r.byID {
		out = append(out, rule)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	r.sorted = out
	return out
}

// Run evaluates every applicable rule against every resource and returns
// findings in deterministic order: rule ID, then resource address, then
// evidence attribute. Rules implementing ir.CrossResourceRule are evaluated
// once against the full resource set instead of per resource.
//
// Rules are independent of each other, so they run concurrently in a bounded
// worker pool (runtime.NumCPU). Each rule writes only its own findings slice;
// the shared resource list is read-only. Results are concatenated in rule
// order and passed through the same deterministic sort, so output is
// identical to the sequential run.
func (r *Registry) Run(resources []ir.Resource) []ir.Finding {
	rules := r.All()
	perRule := make([][]ir.Finding, len(rules))
	workers := runtime.NumCPU()
	if workers > len(rules) {
		workers = len(rules)
	}
	if workers < 1 {
		workers = 1
	}
	jobs := make(chan int, len(rules))
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				perRule[i] = runOneRule(rules[i], resources)
			}
		}()
	}
	for i := range rules {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	out := []ir.Finding{}
	for _, f := range perRule {
		out = append(out, f...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		if out[i].Resource != out[j].Resource {
			return out[i].Resource < out[j].Resource
		}
		return out[i].Evidence.Attribute < out[j].Evidence.Attribute
	})
	// Inline suppressions (aegis:skip comments) apply after every rule has
	// run, so rule logic stays pure and suppression is purely subtractive.
	return ApplyInlineSuppressions(resources, out)
}

// runOneRule evaluates a single rule. Check must never panic; recover
// defensively so one bad rule cannot take down a scan. The skipped rule is
// still deterministic (it simply yields nothing).
func runOneRule(rule ir.Rule, resources []ir.Resource) (out []ir.Finding) {
	if cr, ok := rule.(ir.CrossResourceRule); ok {
		return safeCheckAll(cr, resources)
	}
	for _, res := range resources {
		if !rule.AppliesTo(res.Type) {
			continue
		}
		out = append(out, safeCheck(rule, res)...)
	}
	return out
}

func safeCheckAll(rule ir.CrossResourceRule, resources []ir.Resource) (findings []ir.Finding) {
	defer func() {
		//nolint:staticcheck // intentional: rules must never panic a scan
		_ = recover()
	}()
	return rule.CheckAll(resources)
}

func safeCheck(rule ir.Rule, res ir.Resource) (findings []ir.Finding) {
	defer func() {
		//nolint:staticcheck // intentional: rules must never panic a scan
		_ = recover()
	}()
	return rule.Check(res)
}

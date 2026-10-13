package arm

import (
	"encoding/json"
	"fmt"
	"testing"
)

func item6Template(t *testing.T, variables map[string]any, resources []any) []byte {
	t.Helper()
	tmpl := map[string]any{
		"$schema":        "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
		"contentVersion": "1.0.0.0",
		"variables":      variables,
		"resources":      resources,
	}
	b, err := json.Marshal(tmpl)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func item6Storage(nameExpr any) map[string]any {
	return map[string]any{
		"type":       "Microsoft.Storage/storageAccounts",
		"apiVersion": "2023-01-01",
		"name":       nameExpr,
		"location":   "eastus",
		"sku":        map[string]any{"name": "Standard_LRS"},
		"kind":       "StorageV2",
		"properties": map[string]any{"allowBlobPublicAccess": true},
	}
}

// Item 6: variable chains that double per level (vN = concat(vN-1, vN-1))
// used to re-evaluate exponentially (v22 ~18 s from a 2 KB file).
// Memoization must make v16 evaluate once, to its exact full value.
func TestItem6MemoizedChain(t *testing.T) {
	vars := map[string]any{"v0": "xxxxxxxx"}
	for i := 1; i <= 16; i++ {
		vars[fmt.Sprintf("v%d", i)] = fmt.Sprintf("[concat(variables('v%d'), variables('v%d'))]", i-1, i-1)
	}
	src := item6Template(t, vars, []any{item6Storage("[variables('v16')]")})
	res, _, err := Adapter{}.Parse("t.json", src)
	if err != nil {
		t.Fatalf("Parse returned hard error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(res))
	}
	// 8 * 2^16 = 524288 chars. Exact length proves the value was fully
	// computed (not capped) and memoized (not re-evaluated per use).
	if len(res[0].Name) != 8*(1<<16) {
		t.Fatalf("expected memoized chain length %d, got %d", 8*(1<<16), len(res[0].Name))
	}
}

// Item 6: a 30-level doubling chain would build an 8 GiB string. The
// constructed-string cap must turn it Unknown (fast) instead of OOM.
func TestItem6ChainCap(t *testing.T) {
	vars := map[string]any{"v0": "xxxxxxxx"}
	for i := 1; i <= 30; i++ {
		vars[fmt.Sprintf("v%d", i)] = fmt.Sprintf("[concat(variables('v%d'), variables('v%d'))]", i-1, i-1)
	}
	src := item6Template(t, vars, []any{item6Storage("[variables('v30')]")})
	res, _, err := Adapter{}.Parse("t.json", src)
	if err != nil {
		t.Fatalf("Parse returned hard error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(res))
	}
	// Name falls back to the raw expression when the value is Unknown:
	// the 8 GiB chain must NOT have been materialized.
	if res[0].Name != "[variables('v30')]" {
		t.Fatalf("expected name to fall back to the raw expression (chain capped to Unknown), got %d-char name", len(res[0].Name))
	}
}

// Item 6: the variable cache must not store values computed while a
// dependency was in-progress. Cyclic variables have no unique value —
// the cycle guard makes the result evaluation-order-dependent — so the
// cache must reproduce the pre-cache (no-cache) behavior exactly, not
// freeze the first order's result.
//
// Here x = coalesce(y, 'X-fb'), y = coalesce(x, 'fb'). Evaluated from
// x first: y sees x in-progress (Unknown) and falls back to 'fb', so
// x = 'fb'. Evaluated from y second (fresh): x sees y in-progress and
// falls back to 'X-fb', so y = 'X-fb'. A naive cache would freeze
// y = 'fb' from the first evaluation and return it for the second
// resource; the cycle-hit guard must not cache either poisoned value.
func TestItem6CacheCyclePoisoning(t *testing.T) {
	vars := map[string]any{
		"x": "[coalesce(variables('y'), 'X-fb')]",
		"y": "[coalesce(variables('x'), 'fb')]",
	}
	src := item6Template(t, vars, []any{
		item6Storage("[variables('x')]"),
		item6Storage("[variables('y')]"),
	})
	res, _, err := Adapter{}.Parse("t.json", src)
	if err != nil {
		t.Fatalf("Parse returned hard error: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("expected 2 resources, got %d", len(res))
	}
	// Resources sort by raw name: "[variables('x')]" before "[variables('y')]".
	if res[0].Name != "fb" {
		t.Fatalf("expected x-resource name 'fb', got %q", res[0].Name)
	}
	if res[1].Name != "X-fb" {
		t.Fatalf("expected y-resource name 'X-fb' (recomputed, not cached 'fb'), got %q", res[1].Name)
	}
}

// Item 6: a direct variable cycle still yields Unknown, never a hang.
func TestItem6VarCycle(t *testing.T) {
	vars := map[string]any{
		"a": "[variables('b')]",
		"b": "[variables('a')]",
	}
	src := item6Template(t, vars, []any{item6Storage("[variables('a')]")})
	res, _, err := Adapter{}.Parse("t.json", src)
	if err != nil {
		t.Fatalf("Parse returned hard error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(res))
	}
}

package bicep

import (
	"strings"
	"testing"
	"time"
)

// Item 6b: fuzzer-found hang — `var x =[[[[ ~[[[[[` looped forever in
// parseArray: a failed parseExpr returns unknown WITHOUT consuming input,
// and the array loop only stopped on `]` or EOF, so an unparseable
// element spun the whole scan. parseArray must fail the array when an
// element parse makes no progress. Each case runs in a goroutine with a
// watchdog so a regression fails the test instead of hanging CI.
func TestItem6bArrayNoProgressHang(t *testing.T) {
	inputs := []string{
		"var x =[[[[ ~[[[[[\n",
		"var x = [~]\n",
		"var x = [1, ~, 2]\n",
		"var x = [[[[[[[[[[ ~ ]]]]]]]]]]\n",
	}
	for _, src := range inputs {
		done := make(chan struct{})
		go func(src string) {
			defer close(done)
			_, _, _ = Adapter{}.Parse("hang.bicep", []byte(src))
		}(src)
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("Parse hung on %q", src)
		}
	}
}

// Item 6b: fuzzer-found panic — `var A=A[` indexed p.src past EOF in
// parseNumber (the `[n]` suffix path calls it without a bounds check).
// Must return false, never panic.
func TestItem6bNumberAtEOF(t *testing.T) {
	for _, src := range []string{"var A=A[\n", "var A=A[1\n", "var x = -\n"} {
		done := make(chan struct{})
		go func(src string) {
			defer close(done)
			_, _, _ = Adapter{}.Parse("eof.bicep", []byte(src))
		}(src)
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatalf("Parse hung on %q", src)
		}
	}
}
// diagnostic, silently suppressing rules that need a known value
// (AEGIS-AZR-001 stops firing when allowBlobPublicAccess is unknown).
// Syntax failures must warn; legitimate unknowns (undeclared identifiers,
// forward references) must NOT warn.
func TestItem6bFailedExprWarns(t *testing.T) {
	src := "var open = [~]\nresource st 'Microsoft.Storage/storageAccounts@2023-01-01' = { name: 'x' location: 'eastus' properties: { allowBlobPublicAccess: open } }\n"
	_, diags, err := Adapter{}.Parse("warn.bicep", []byte(src))
	if err != nil {
		t.Fatalf("Parse returned hard error: %v", err)
	}
	found := false
	for _, d := range diags {
		if strings.Contains(d.Message, `var "open"`) && strings.Contains(d.Message, "failed to parse") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected failed-to-parse warning for var open, got %v", diags)
	}
}

func TestItem6bForwardRefDoesNotWarn(t *testing.T) {
	src := "var a = b\nvar b = true\nresource st 'Microsoft.Storage/storageAccounts@2023-01-01' = { name: 'x' location: 'eastus' }\n"
	_, diags, _ := Adapter{}.Parse("fwd.bicep", []byte(src))
	for _, d := range diags {
		if strings.Contains(d.Message, "failed to parse") {
			t.Fatalf("forward reference must not warn as a parse failure: %v", diags)
		}
	}
}

// Item 6b: a malformed inline property value warns with the property name.
func TestItem6bFailedPropertyWarns(t *testing.T) {
	src := "resource st 'Microsoft.Storage/storageAccounts@2023-01-01' = { name: 'x' location: 'eastus' properties: { allowBlobPublicAccess: [~] } }\n"
	_, diags, err := Adapter{}.Parse("prop.bicep", []byte(src))
	if err != nil {
		t.Fatalf("Parse returned hard error: %v", err)
	}
	found := false
	for _, d := range diags {
		if strings.Contains(d.Message, "allowBlobPublicAccess") && strings.Contains(d.Message, "failed to parse") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected failed-to-parse warning for property, got %v", diags)
	}
}
func TestItem6bValidArrayStillParses(t *testing.T) {
	src := "var x = [1, 2, [3, 4]]\nresource st 'Microsoft.Storage/storageAccounts@2023-01-01' = { name: 'x' location: 'eastus' }\n"
	res, _, err := Adapter{}.Parse("ok.bicep", []byte(src))
	if err != nil {
		t.Fatalf("Parse returned hard error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(res))
	}
}

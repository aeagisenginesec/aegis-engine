package manifests

import (
	"strings"
	"testing"
)

// Item 6: a malformed second document used to discard the valid first
// document's findings (decode returned nil on any error). Valid documents
// decoded before the failure must survive, with an error diagnostic for
// the failing document.
func TestItem6ValidDocBeforeBadDoc(t *testing.T) {
	src := `apiVersion: v1
kind: Pod
metadata:
  name: priv
spec:
  hostNetwork: true
  containers:
  - name: c
    image: nginx
    securityContext:
      privileged: true
---
: this is [not valid yaml
`
	res, diags, err := Adapter{}.Parse("m.yaml", []byte(src))
	if err != nil {
		t.Fatalf("Parse returned hard error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected valid Pod to survive bad second doc, got %d resources", len(res))
	}
	if res[0].Type != "k8s_Pod" || res[0].Name != "priv" {
		t.Fatalf("unexpected surviving resource: %+v", res[0])
	}
	found := false
	for _, d := range diags {
		if d.Level == "error" && strings.Contains(d.Message, "invalid YAML") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected error diagnostic for the malformed document, got %v", diags)
	}
}

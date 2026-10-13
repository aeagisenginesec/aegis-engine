package terraform

import (
	"strings"
	"testing"
)

// Item 6b: JSON-style (colon-separated, quoted-key) objects inside
// jsonencode() silently degraded to Unknown, so IAM policy rules stopped
// firing with no diagnostic — while HCL-style ({ Effect = "Allow" })
// worked. Root cause: quoted keys arrive as ObjectConsKeyExpr wrapping a
// TemplateExpr, and ExprAsKeyword returns "" for those; neither
// staticKeyString nor staticObjectKey unwrapped them. This is the form
// AWS policy documents are pasted in as, so it is the common case, not
// an edge case.
func TestItem6bColonStyleJsonencodePolicy(t *testing.T) {
	src := "resource \"aws_iam_policy\" \"p\" {\n  policy = jsonencode({\n    Version = \"2012-10-17\"\n    Statement = [{ \"Effect\": \"Allow\", \"Action\": \"s3:*\", \"Resource\": \"*\" }]\n  })\n}\n"
	mod, diags, err := Adapter{}.ParseModule("p.tf", []byte(src))
	if err != nil {
		t.Fatalf("ParseModule returned hard error: %v", err)
	}
	for _, d := range diags {
		if d.Level == "error" {
			t.Fatalf("unexpected error diagnostic: %v", d)
		}
	}
	if len(mod.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(mod.Resources))
	}
	pol, ok := mod.Resources[0].Attributes["policy"]
	if !ok || !pol.Known {
		t.Fatalf("expected policy attribute Known, got %+v (present=%v)", pol, ok)
	}
	raw, _ := pol.Raw.(string)
	if !strings.Contains(raw, `"Resource":"*"`) {
		t.Fatalf("expected encoded policy to contain the wildcard resource, got %q", raw)
	}
}

// Item 6b: colon-style objects also work in plain (non-jsonencode)
// attributes and in merge(), which share the key helpers.
func TestItem6bColonStylePlainObject(t *testing.T) {
	src := "resource \"aws_s3_bucket\" \"b\" {\n  bucket = \"x\"\n  tags = { \"Name\": \"n\", \"Env\": \"prod\" }\n  other = merge({ \"a\": \"1\" }, { \"b\": \"2\" })\n}\n"
	mod, _, err := Adapter{}.ParseModule("p.tf", []byte(src))
	if err != nil {
		t.Fatalf("ParseModule returned hard error: %v", err)
	}
	if len(mod.Resources) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(mod.Resources))
	}
	tags, ok := mod.Resources[0].Attributes["tags"]
	if !ok || !tags.Known {
		t.Fatalf("expected tags Known, got %+v (present=%v)", tags, ok)
	}
	other, ok := mod.Resources[0].Attributes["other"]
	if !ok || !other.Known {
		t.Fatalf("expected merge() result Known, got %+v (present=%v)", other, ok)
	}
}

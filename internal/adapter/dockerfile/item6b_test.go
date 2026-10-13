package dockerfile

import (
	"strings"
	"testing"
)

// Item 6b: a NUL byte in a Dockerfile used to silently suppress findings:
// `USER \x00root` tokenized to user "\x00root", which no longer matches
// "root", so the run-as-root finding vanished with no diagnostic. NULs
// are stripped with a warning, and the finding survives.
func TestItem6bNullBytesStrippedWithWarning(t *testing.T) {
	src := "FROM ubuntu:latest\nUSER \x00root\n"
	res, diags, err := Adapter{}.Parse("Dockerfile", []byte(src))
	if err != nil {
		t.Fatalf("Parse returned hard error: %v", err)
	}
	if len(res) != 1 {
		t.Fatalf("expected 1 stage, got %d", len(res))
	}
	u, ok := res[0].Attributes["user"]
	if !ok || !u.Known || u.Raw != "root" {
		t.Fatalf("expected user=root after NUL strip, got %+v (present=%v)", u, ok)
	}
	found := false
	for _, d := range diags {
		if strings.Contains(d.Message, "null bytes") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected null-bytes warning diagnostic, got %v", diags)
	}
}

// Item 6b: a clean Dockerfile gets no NUL warning.
func TestItem6bNoNullBytesNoWarning(t *testing.T) {
	_, diags, _ := Adapter{}.Parse("Dockerfile", []byte("FROM ubuntu:latest\nUSER root\n"))
	for _, d := range diags {
		if strings.Contains(d.Message, "null bytes") {
			t.Fatalf("unexpected null-bytes warning on clean input: %v", diags)
		}
	}
}

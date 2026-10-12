package terraform

import (
	"bytes"
	"strings"
	"testing"
)

func TestPreValidate(t *testing.T) {
	cases := []struct {
		name    string
		src     []byte
		wantErr []string // substrings; nil means no error expected
	}{
		{"empty file is valid", []byte{}, nil},
		{"comments only", []byte("# hi\n// yo\n"), nil},
		{"valid minimal", []byte("resource \"a\" \"b\" {}\n"), nil},
		{
			"null bytes",
			[]byte("a\x00b"),
			[]string{"terraform:", "t.tf", "null bytes"},
		},
		{
			"utf16 le bom",
			[]byte("\xff\xfer\x00e\x00s\x00"),
			[]string{"terraform:", "t.tf", "UTF-16"},
		},
		{
			"utf16 be bom",
			[]byte("\xfe\xff\x00r\x00e"),
			[]string{"terraform:", "t.tf", "UTF-16"},
		},
		{
			"utf16 bom wins over null bytes",
			[]byte("\xff\xfe\x00\x00"),
			[]string{"UTF-16"},
		},
		{
			"oversize",
			bytes.Repeat([]byte("x"), 10<<20+1),
			[]string{"terraform:", "t.tf", "10 MiB"},
		},
		{
			"truncated block",
			[]byte("resource \"a\" \"b\" {\n  x = 1\n"),
			[]string{"terraform:", "t.tf", "unbalanced braces", "1 open, 0 close"},
		},
		{
			"stray close braces",
			[]byte("} } }"),
			[]string{"unbalanced braces", "0 open, 3 close"},
		},
		{
			"braces in strings ignored",
			[]byte("resource \"a\" \"b\" { x = \"}{\" }\n"),
			nil,
		},
		{
			"braces in comments ignored",
			[]byte("# { \n// } \nresource \"a\" \"b\" {}\n"),
			nil,
		},
		{
			"braces in block comments ignored",
			[]byte("/* { } */\nresource \"a\" \"b\" {}\n"),
			nil,
		},
		{
			"braces in heredoc ignored",
			[]byte("resource \"a\" \"b\" {\n  p = <<EOT\n{\n}\nEOT\n}\n"),
			nil,
		},
		{
			"indented heredoc",
			[]byte("resource \"a\" \"b\" {\n  p = <<-EOT\n  {\n  EOT\n}\n"),
			nil,
		},
		{
			"deep nesting rejected",
			deepNesting(60),
			[]string{"terraform:", "t.tf", "nesting depth exceeds 50"},
		},
		{
			"50 levels allowed",
			deepNesting(50),
			nil,
		},
		{
			"interpolation braces in strings ignored",
			[]byte("resource \"a\" \"b\" { x = \"${{a=1}}\" }\n"),
			nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := PreValidate("t.tf", c.src)
			if c.wantErr == nil {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.wantErr)
			}
			for _, want := range c.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q missing %q", err.Error(), want)
				}
			}
		})
	}
}

func TestParseTruncatedBlockIsHardError(t *testing.T) {
	truncated := "resource \"aws_s3_bucket\" \"broken\" {\n  bucket = \"oops\"\n"
	_, _, err := (Adapter{}).Parse("broken.tf", []byte(truncated))
	if err == nil {
		t.Fatal("expected hard error for truncated block, got nil")
	}
	for _, want := range []string{"terraform:", "broken.tf", "unbalanced braces", "1 open, 0 close"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err.Error(), want)
		}
	}
}

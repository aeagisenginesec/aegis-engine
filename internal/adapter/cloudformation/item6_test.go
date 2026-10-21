package cloudformation

import (
	"strings"
	"testing"
)

// Item 6: a self-referential YAML anchor (&a [*a]) used to recurse
// resolveValue until the goroutine stack overflowed and killed the whole
// scanner process. It must now yield a warning diagnostic and an
// Unknown value, with the valid sibling resource still parsed.
func TestItem6AliasCycle(t *testing.T) {
	src := `AWSTemplateFormatVersion: '2010-09-09'
Resources:
  GoodBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: good
  CycBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: &a [*a]
`
	res, diags, err := Adapter{}.Parse("t.yaml", []byte(src))
	if err != nil {
		t.Fatalf("Parse returned hard error: %v", err)
	}
	if len(res) != 2 {
		t.Fatalf("expected 2 resources (valid sibling must survive), got %d", len(res))
	}
	foundCycle := false
	for _, d := range diags {
		if strings.Contains(d.Message, "alias cycle") {
			foundCycle = true
		}
	}
	if !foundCycle {
		t.Fatalf("expected alias-cycle diagnostic, got %v", diags)
	}
}

// Item 6: nested aliases amplify exponentially (billion laughs). The
// alias budget must stop expansion quickly with a warning, not hang.
func TestItem6AliasBudget(t *testing.T) {
	var sb strings.Builder
	sb.WriteString("AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Bucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: lol\n      Tags:\n")
	sb.WriteString("        - &a0 ['x','x','x','x','x','x','x','x']\n")
	for i := 1; i <= 8; i++ {
		sb.WriteString("        - &a" + string(rune('0'+i)) + " [")
		for j := 0; j < 8; j++ {
			if j > 0 {
				sb.WriteString(", ")
			}
			sb.WriteString("*a" + string(rune('0'+i-1)))
		}
		sb.WriteString("]\n")
	}
	sb.WriteString("        - *a8\n")
	res, diags, err := Adapter{}.Parse("t.yaml", []byte(sb.String()))
	if err != nil {
		t.Fatalf("Parse returned hard error: %v", err)
	}
	if len(res) == 0 {
		t.Fatalf("expected the bucket resource to survive budget exhaustion")
	}
	found := false
	for _, d := range diags {
		if strings.Contains(d.Message, "alias") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected alias-budget diagnostic, got %v", diags)
	}
}

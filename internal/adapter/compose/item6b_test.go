package compose

import (
	"strings"
	"testing"
)

// Item 6b: a Compose service entry that is not a mapping (e.g.
// `web: justastring`) used to be dropped silently — indistinguishable
// from a clean service. It must warn, while valid sibling services
// still parse.
func TestItem6bNonMappingServiceWarns(t *testing.T) {
	src := `services:
  web: justastring
  db:
    image: postgres
    privileged: true
`
	res, diags, err := Adapter{}.Parse("compose.yaml", []byte(src))
	if err != nil {
		t.Fatalf("Parse returned hard error: %v", err)
	}
	if len(res) != 1 || res[0].Name != "db" {
		t.Fatalf("expected only the valid db service, got %+v", res)
	}
	found := false
	for _, d := range diags {
		if strings.Contains(d.Message, "not a mapping") && strings.Contains(d.Message, "web") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected non-mapping warning for web, got %v", diags)
	}
}

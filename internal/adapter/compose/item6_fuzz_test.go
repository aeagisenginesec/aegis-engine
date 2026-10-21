package compose

import "testing"

// Item 6: coverage-guided fuzzing for the Compose parser. Invariant: no
// panic; a hard error never accompanies resources.
func FuzzItem6Parse(f *testing.F) {
	f.Add([]byte("services:\n  web:\n    image: nginx:latest\n    privileged: true\n"))
	f.Add([]byte("services:\n  web:\n    image: nginx:latest\n    environment: &a [*a]\n"))
	f.Add([]byte("services: {}\n"))
	f.Add([]byte("\x00\x01\x02\xff\xfe"))
	f.Add([]byte(""))
	f.Add([]byte("services:\n  web: [unclosed\n"))
	f.Fuzz(func(t *testing.T, src []byte) {
		res, _, err := Adapter{}.Parse("compose.yaml", src)
		if err != nil && len(res) != 0 {
			t.Fatalf("hard error %q with %d resources", err, len(res))
		}
	})
}

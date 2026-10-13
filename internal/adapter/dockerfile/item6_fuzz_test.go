package dockerfile

import "testing"

// Item 6: coverage-guided fuzzing for the Dockerfile parser. Invariant:
// no panic; a hard error never accompanies resources.
func FuzzItem6Parse(f *testing.F) {
	f.Add([]byte("FROM ubuntu:latest\nUSER root\n"))
	f.Add([]byte("FROM a AS b\nFROM b\nCOPY --from=a /x /y\n"))
	f.Add([]byte("FROM ubuntu:latest\nRUN echo \\\n  continued\n"))
	f.Add([]byte("\x00\x01\x02\xff\xfe"))
	f.Add([]byte(""))
	f.Add([]byte("FROM\n"))
	f.Fuzz(func(t *testing.T, src []byte) {
		res, _, err := Adapter{}.Parse("Dockerfile", src)
		if err != nil && len(res) != 0 {
			t.Fatalf("hard error %q with %d resources", err, len(res))
		}
	})
}

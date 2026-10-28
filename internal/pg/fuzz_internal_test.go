package pg

import "testing"

func FuzzQualifiedIdentifier(f *testing.F) {
	for _, seed := range []string{"app.documents", "public.tenants", "", "a.b.c", "x; DROP TABLE y"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		got, err := qualifiedIdentifier(input)
		if err != nil {
			return
		}
		if got == "" {
			t.Fatalf("qualifiedIdentifier(%q) returned an empty identifier", input)
		}
		if got[0] == '.' {
			t.Fatalf("qualifiedIdentifier(%q) returned %q with a leading dot", input, got)
		}
	})
}

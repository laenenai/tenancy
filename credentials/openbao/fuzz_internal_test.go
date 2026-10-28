package openbao

import (
	"strings"
	"testing"
)

func FuzzMountPath(f *testing.F) {
	for _, seed := range []string{"", "database", "/database", "database/", "a//b", "a b", "a;b"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		got, err := mountPath(input)
		if err != nil {
			return
		}
		if strings.HasPrefix(got, "/") || strings.HasSuffix(got, "/") || strings.Contains(got, "//") {
			t.Fatalf("mountPath(%q) returned %q with an empty path segment", input, got)
		}
	})
}

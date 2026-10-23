package tenancy_test

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// negativeCompileFile is the program the compiler must reject. See its own
// header comment for what each case in it means.
const negativeCompileFile = "testdata/control_plane_is_not_a_data_plane_handle.go"

// TestControlPlaneIsNotADataPlaneHandle is the compile-time half of the
// charter's requirement that the type system make it impossible to run a
// data-plane query on a control-plane handle.
//
// A runtime test cannot express this. The whole point of making the
// distinction a type-system fact is that the mistake is unwriteable, so the
// only way to test it is to write it somewhere the compiler can see it and
// the build cannot — which is what testdata/ is for. The companion runtime
// assertions, for the shapes Go cannot forbid, are the conformance suite's
// ZeroHandleDeniesRatherThanPanicking subtest and the row-level-security
// subtests.
//
// It needs no database and runs in the inner loop.
func TestControlPlaneIsNotADataPlaneHandle(t *testing.T) {
	t.Parallel()

	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skipf("no go toolchain on PATH, cannot run a compile-failure test: %v", err)
	}

	root := moduleRoot(t)
	out, err := runGoBuild(t, goTool, root)
	if err == nil {
		t.Fatalf("%s compiled successfully; it must not.\n"+
			"The control-plane/data-plane separation has been lost: a registry handle can now run\n"+
			"caller-supplied SQL, or stand where a tenant-scoped handle is expected, or a TenantTx can\n"+
			"be forged. The registry tables carry no row-level-security policy by necessity, so there is\n"+
			"nothing behind that path to catch the mistake. See CHARTER.md and the header comment of %s.",
			negativeCompileFile, negativeCompileFile)
	}

	// Require *type* errors, not just any failure: a missing import, a
	// typo, or a renamed identifier would also make the build fail and
	// would make this test pass for the wrong reason.
	//
	// Every case in the file is checked for individually rather than
	// counting them, because a case that silently stopped being rejected —
	// while the others still were — is exactly the regression this test
	// exists to catch, and a count would hide it behind the others.
	text := string(out)
	required := []struct {
		what     string
		fragment string
	}{
		{"the control plane has no Query method", "control.Query undefined"},
		{"the control plane has no Exec method", "control.Exec undefined"},
		{"the control plane has no QueryRow method", "control.QueryRow undefined"},
		{"the control plane has no Begin method", "control.Begin undefined"},
		{"a control handle cannot be passed as a Scoped", "cannot use control"},
		{"a control handle cannot be converted to a Scoped", "cannot convert control"},
		{"a Scoped cannot be passed as a control handle", "cannot use scoped"},
		{"Scoped's fields are unexported", "unexported field"},
		{"a TenantTx cannot be forged from another handle", "cannot convert raw"},
		{"TenantTx's fields are unexported", "unexported field tx in struct literal of type tenancy.TenantTx"},
		{"a TenantTx exposes no Commit", "tx.Commit undefined"},
	}

	var missing []string
	for _, r := range required {
		if !strings.Contains(text, r.fragment) {
			missing = append(missing, r.what+" (expected the compiler to say something containing "+r.fragment+")")
		}
	}
	if len(missing) > 0 {
		t.Fatalf("%s failed to compile, but not for every reason it must.\nNot rejected:\n  - %s\n\ngo build said:\n%s",
			negativeCompileFile, strings.Join(missing, "\n  - "), text)
	}

	t.Logf("the compiler rejected every case as required:\n%s", text)
}

// runGoBuild compiles the negative file from the module root, discarding
// any output binary, and returns the combined compiler output.
func runGoBuild(t *testing.T, goTool, root string) ([]byte, error) {
	t.Helper()
	// -gcflags=-e is load-bearing: the compiler stops after ten errors by
	// default, and this file deliberately contains more than ten. Without
	// it the last cases would be elided as "too many errors" and this test
	// could not tell "still rejected" from "no longer checked".
	cmd := exec.CommandContext(t.Context(), goTool, "build", "-gcflags=-e", //nolint:gosec // goTool is exec.LookPath's own answer and the file path is this package's own constant
		"-o", filepath.Join(t.TempDir(), "unwanted"), negativeCompileFile)
	cmd.Dir = root
	return cmd.CombinedOutput()
}

// moduleRoot returns the directory holding this module's go.mod, asked of
// the go tool rather than assumed from this test file's location.
func moduleRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), "go", "env", "GOMOD").Output() //nolint:gosec // a fixed, argument-free query to the go tool on PATH
	if err != nil {
		t.Skipf("cannot locate the module root: %v", err)
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == "/dev/null" {
		t.Skip("not running inside a module; cannot compile the negative test file")
	}
	return filepath.Dir(gomod)
}

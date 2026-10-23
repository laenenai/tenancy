package tenancytest

// The self-test for NoSecretLeaksInAnyRendering, copied alongside
// redaction.go into every module that holds material. It exists because the
// helper is duplicated rather than imported: a copy that quietly drops an
// encoding from leakNeedles, or a verb from leakVerbs, would keep passing
// against every real type while no longer being able to fail. These tests
// assert against the detector, not against the module's own types.

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// selfTestMaterial deliberately contains a NUL and a double quote, so that
// Go quoted-string escaping actually changes it and the escaped-form needle
// is exercised rather than collapsing onto the raw one.
var selfTestMaterial = []byte("material-7f3a9c\x00\"must-not-appear")

const selfTestPlaceholder = "selftest(redacted)"

// safeValue is what the convention asks for: all four interfaces, each
// writing one fixed placeholder that names the type and nothing else.
type safeValue struct{ b []byte }

func (v safeValue) String() string               { return selfTestPlaceholder }
func (v safeValue) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, selfTestPlaceholder) }
func (v safeValue) MarshalJSON() ([]byte, error) { return json.Marshal(selfTestPlaceholder) }
func (v safeValue) LogValue() slog.Value         { return slog.StringValue(selfTestPlaceholder) }

// stringerOnlyValue is the most common wrong answer: a named string type with
// a String method, which looks redacted under %v and discloses itself through
// json.Marshal, slog's JSONHandler and every verb fmt does not route through
// Stringer.
type stringerOnlyValue string

func (v stringerOnlyValue) String() string { return selfTestPlaceholder }

// fourInterfacesNoFormatter is the shape keyring's DEK shipped with:
// Stringer, GoStringer, MarshalJSON and LogValuer — four interfaces, and
// still no Formatter, so %d, %c, %U, %b and %o reflect the bytes.
type fourInterfacesNoFormatter struct{ b []byte }

func (v fourInterfacesNoFormatter) String() string   { return selfTestPlaceholder }
func (v fourInterfacesNoFormatter) GoString() string { return selfTestPlaceholder }
func (v fourInterfacesNoFormatter) MarshalJSON() ([]byte, error) {
	return json.Marshal(selfTestPlaceholder)
}

func (v fourInterfacesNoFormatter) LogValue() slog.Value {
	return slog.StringValue(selfTestPlaceholder)
}

// lengthDisclosingValue redacts the material and then reports how long it
// was, which is the mistake that looks like diligence.
type lengthDisclosingValue struct{ b []byte }

func (v lengthDisclosingValue) placeholder() string {
	return "selftest(redacted, " + strconv.Itoa(len(v.b)) + " bytes)"
}

func (v lengthDisclosingValue) String() string               { return v.placeholder() }
func (v lengthDisclosingValue) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, v.placeholder()) }
func (v lengthDisclosingValue) MarshalJSON() ([]byte, error) { return json.Marshal(v.placeholder()) }
func (v lengthDisclosingValue) LogValue() slog.Value         { return slog.StringValue(v.placeholder()) }

func TestSafeValueHasNoMissingInterfacesAndNoLeaks(t *testing.T) {
	t.Parallel()

	v := safeValue{b: selfTestMaterial}
	if missing := missingRedactionInterfaces(v); len(missing) != 0 {
		t.Errorf("missingRedactionInterfaces(safeValue) = %v, want none", missing)
	}
	if leaks := renderingLeaks(v, selfTestMaterial); len(leaks) != 0 {
		t.Errorf("renderingLeaks(safeValue) reported %d leaks, want none:\n%s", len(leaks), formatLeaks(leaks))
	}
}

func TestMissingInterfacesAreReportedByName(t *testing.T) {
	t.Parallel()

	got := missingRedactionInterfaces(stringerOnlyValue(selfTestMaterial))
	var names []string
	for _, m := range got {
		names = append(names, m.iface)
		if m.controls == "" {
			t.Errorf("%s was reported without naming the rendering it controls", m.iface)
		}
	}
	want := []string{"fmt.Formatter", "json.Marshaler", "slog.LogValuer"}
	if !slices.Equal(names, want) {
		t.Errorf("missing interfaces = %v, want %v", names, want)
	}
}

// TestStringerAloneIsNotEnough pins the three renderings that a String method
// does not reach, so that a copy of this helper which stopped exercising
// json.Marshal or slog could not pass.
func TestStringerAloneIsNotEnough(t *testing.T) {
	t.Parallel()

	leaks := renderingLeaks(stringerOnlyValue(selfTestMaterial), selfTestMaterial)
	if len(leaks) == 0 {
		t.Fatal("a Stringer-only named string type was reported as leaking nothing")
	}
	for _, want := range []string{"json.Marshal", "slog JSONHandler", "fmt %d"} {
		if !slices.ContainsFunc(leaks, func(l renderingLeak) bool {
			return strings.HasPrefix(l.rendering, want)
		}) {
			t.Errorf("no leak reported for %s; the detector no longer covers it", want)
		}
	}
}

// TestFormatterIsRequiredEvenWithFourOtherInterfaces is the keyring DEK
// regression. Stringer, GoStringer, MarshalJSON and LogValuer all redact, and
// %d still prints every byte.
func TestFormatterIsRequiredEvenWithFourOtherInterfaces(t *testing.T) {
	t.Parallel()

	v := fourInterfacesNoFormatter{b: selfTestMaterial}

	missing := missingRedactionInterfaces(v)
	if len(missing) != 1 || missing[0].iface != "fmt.Formatter" {
		t.Errorf("missing interfaces = %v, want exactly fmt.Formatter", missing)
	}

	leaks := renderingLeaks(v, selfTestMaterial)
	if len(leaks) == 0 {
		t.Fatal("a type with no Formatter was reported as leaking nothing, yet the decimal verb reflects the bytes")
	}
	if !slices.ContainsFunc(leaks, func(l renderingLeak) bool {
		return strings.HasPrefix(l.encoding, "byte-wise")
	}) {
		t.Errorf("no byte-wise encoding was detected, so the %%d/%%c/%%o/%%b needles are not working:\n%s", formatLeaks(leaks))
	}
}

func TestLengthIsTreatedAsDisclosure(t *testing.T) {
	t.Parallel()

	leaks := renderingLeaks(lengthDisclosingValue{b: selfTestMaterial}, selfTestMaterial)
	if !slices.ContainsFunc(leaks, func(l renderingLeak) bool {
		return l.encoding == "its length in decimal"
	}) {
		t.Errorf("a value that reports the material's length was not flagged:\n%s", formatLeaks(leaks))
	}
}

// TestLengthNeedleFiresOnlyOnAQualifiedLength pins both halves of the length
// needle's rule: the number must be its own token, and a length word must be
// near it.
//
// The second half is here because of a real failure, not a hypothetical one.
// A credential rendering its expiry as 2026-10-23T15:20:08Z contains a
// standalone 20 between two colons, so a 20-byte secret — OpenBao's default
// password length — failed this subtest at 15:20 and passed at 15:21. The
// clock is not allowed to decide whether a security test passes.
// TestTheClockCannotFailThisSubtest is the regression for the 15:20 failure:
// the real needle set for a 20-byte secret, against a rendering that carries a
// timestamp, must be clean.
func TestTheClockCannotFailThisSubtest(t *testing.T) {
	t.Parallel()

	material := []byte("twenty-bytes-exactly")
	if len(material) != 20 {
		t.Fatalf("fixture is %d bytes, the point of it is 20", len(material))
	}
	const rendered = "tenancy.Credential([REDACTED] expires 2026-10-23T15:20:08Z)"
	for _, n := range leakNeedles(material) {
		if n.contained(rendered) {
			t.Errorf("needle %q (%s) matched a rendering that discloses nothing: %q", n.text, n.what, rendered)
		}
	}
}

func TestLengthNeedleFiresOnlyOnAQualifiedLength(t *testing.T) {
	t.Parallel()

	n := needle{what: "length", text: "32", qualified: true}
	// A ULID is in this list because every id in these modules is one, and a
	// two-digit number appearing somewhere inside twenty-six alphanumerics is
	// near certain.
	for _, s := range []string{"ciphertext=320 bytes", "v1320", "4321", "01M5KMCWMH32VJ5W4ZMG3Y1JX93"} {
		if n.contained(s) {
			t.Errorf("the length needle matched inside a longer token: %q", s)
		}
	}
	// Standalone but unqualified: nothing says these numbers measure anything,
	// and this is the flake the nearby-word rule exists to stop.
	for _, s := range []string{"32", "(32)", "15:32:08", "WorkerCapacity:32", "2026-10-23T15:32:08Z"} {
		if n.contained(s) {
			t.Errorf("the length needle fired on a bare number with no length word near it: %q", s)
		}
	}
	for _, s := range []string{"len=32", "32 bytes", "[]uint8(len=32)", "DEK(redacted, 32 bytes)", "Length: 32", "size=32"} {
		if !n.contained(s) {
			t.Errorf("the length needle failed to match a qualified length: %q", s)
		}
	}
}

// TestLeakNeedlesCoverEveryEncodingTheConventionNames is the test that makes
// this file worth copying: it pins the exact set of encodings, so a copy that
// drops one fails here rather than silently stopping being able to fail.
func TestLeakNeedlesCoverEveryEncodingTheConventionNames(t *testing.T) {
	t.Parallel()

	var got []string
	for _, n := range leakNeedles(selfTestMaterial) {
		got = append(got, n.what)
	}
	want := []string{
		"the material itself",
		"lowercase hex",
		"uppercase hex",
		"base64 (std)",
		"base64 (std, unpadded)",
		"base64 (url)",
		"base64 (url, unpadded)",
		"its length in decimal",
		"Go quoted-string escaping",
		"JSON string escaping",
		"byte-wise decimal, as %d prints it",
		"byte-wise octal, as %o prints it",
		"byte-wise binary, as %b prints it",
		"Go syntax for a byte slice, as %#v prints it",
		"byte-wise code points, as %U prints it",
		"byte-wise characters, as %c prints it",
	}
	if !slices.Equal(got, want) {
		t.Errorf("leakNeedles covers %v,\nwant %v", got, want)
	}
}

// TestLeakVerbsExcludeOnlyWhatCannotBeFixed pins the verb list, including the
// deliberate absence of %T and %p.
func TestLeakVerbsExcludeOnlyWhatCannotBeFixed(t *testing.T) {
	t.Parallel()

	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%c", "%U", "%b", "%o"} {
		if !slices.Contains(leakVerbs, verb) {
			t.Errorf("leakVerbs no longer covers %s", verb)
		}
	}
	for _, verb := range []string{"%T", "%p"} {
		if slices.Contains(leakVerbs, verb) {
			t.Errorf("leakVerbs covers %s, which no implementation can control; see the doc comment", verb)
		}
	}
}

func formatLeaks(leaks []renderingLeak) string {
	var b strings.Builder
	for _, l := range leaks {
		fmt.Fprintf(&b, "  %s (%s): %s\n", l.rendering, l.encoding, l.out)
	}
	return b.String()
}

package tenancytest

// This file is a deliberate copy. The same function, with the same self-test
// beside it, lives in every module that holds security-relevant material —
// keyringtest, tenancytest, iamtest — and it is copied rather than imported.
//
// CONVENTIONS.md records the reasoning under "Rendering a secret", and it is
// the CanonicalTime rule applied again. This package is a *non-test* package:
// it imports testing so that a consumer in another module can run the suite
// against its own adapter, which also means it is in the production import
// graph of everyone who imports it. Importing a shared helper module from
// here would put that module — and its own dependency graph — into every
// consumer's go.sum, and couple this module's release cadence to it, in
// exchange for an assertion about string containment. The copy is the cheaper
// trade, and redaction_test.go is copied with it so a copy that drops an
// encoding fails where it was dropped.

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"testing"
)

// minMaterialLen is the shortest material this subtest will accept. Something
// shorter is so likely to occur by chance in an unrelated rendering that the
// subtest would be a coin toss rather than an assertion, and a caller that
// passes two bytes has almost certainly passed the wrong thing.
const minMaterialLen = 8

// NoSecretLeaksInAnyRendering asserts that v cannot be made to disclose
// material by any rendering Go offers, and is the executable half of
// CONVENTIONS.md's "Rendering a secret" convention. It registers itself as a
// subtest under that exact name, so a security invariant appears in test
// output by name rather than being folded into a general-purpose test.
//
// It checks two different things, because they fail in different ways.
//
// First, that v implements all four of fmt.Stringer, fmt.Formatter,
// json.Marshaler and slog.LogValuer, reporting each one that is missing and
// which rendering that one controls. This matters even when nothing leaks
// today: a struct whose material is unexported marshals to "{}" and a struct
// whose fields happen to be printable-safe survives %+v, so a type can pass a
// containment check for reasons that evaporate the moment someone exports a
// field.
//
// Second, that none of the renderings contains material, any encoding of it a
// rendering actually produces (hex in both cases, base64 in all four
// alphabets, Go quoted-string escaping, and the byte-wise decimal, octal,
// binary, rune and Go-syntax forms that %d, %o, %b, %c and %#v emit), or its
// length in decimal. Length is checked because it is a side channel: knowing a
// secret is 6 bytes rather than 64 removes most of a search space.
//
// The renderings covered are String(), every fmt verb except %T and %p,
// json.Marshal, and slog under both standard handlers — each of those also
// applied to a struct that merely contains v, which is how material reaches a
// log line in practice.
//
// %p is excluded, and it is excluded because no implementation can fix it:
// fmt's bad-verb path sets its internal erroring flag before describing the
// operand, so handleMethods returns without consulting any interface and the
// operand is reflected. CONVENTIONS.md records that hole and its mitigation.
// %T is excluded because a type name is the part that should survive.
func NoSecretLeaksInAnyRendering(t *testing.T, v any, material []byte) {
	t.Helper()

	t.Run("NoSecretLeaksInAnyRendering", func(t *testing.T) {
		if len(material) < minMaterialLen {
			t.Fatalf("material is %d bytes, want at least %d: a shorter sentinel makes this subtest a coin toss", len(material), minMaterialLen)
		}

		for _, missing := range missingRedactionInterfaces(v) {
			t.Errorf("%T does not implement %s, so %s is not redacted", v, missing.iface, missing.controls)
		}
		for _, leak := range renderingLeaks(v, material) {
			t.Errorf("%s disclosed the material (as %s): %s", leak.rendering, leak.encoding, leak.out)
		}
	})
}

// missingInterface names one unimplemented redaction interface and the
// rendering it would have controlled.
type missingInterface struct {
	iface    string
	controls string
}

// missingRedactionInterfaces reports which of the four required interfaces v
// does not implement. The mapping from interface to rendering is measured
// behaviour on go1.25.6, not the godoc summary: fmt consults Stringer for %v,
// %s, %q, %x and %X and for no other verb, which is why Formatter is required
// rather than merely nice.
func missingRedactionInterfaces(v any) []missingInterface {
	var missing []missingInterface
	if _, ok := v.(fmt.Stringer); !ok {
		missing = append(missing, missingInterface{"fmt.Stringer", "%v, %s, %q, %x, %X, print and string concatenation"})
	}
	if _, ok := v.(fmt.Formatter); !ok {
		missing = append(missing, missingInterface{"fmt.Formatter", "every other verb, including %d, %c, %U, %b and %o, which consult no other interface"})
	}
	if _, ok := v.(json.Marshaler); !ok {
		missing = append(missing, missingInterface{"json.Marshaler", "json.Marshal, and slog's JSONHandler, which is built on it"})
	}
	if _, ok := v.(slog.LogValuer); !ok {
		missing = append(missing, missingInterface{"slog.LogValuer", "structured log attributes under every handler"})
	}
	return missing
}

// renderingLeak is one rendering that disclosed the material, and the
// encoding it disclosed it in.
type renderingLeak struct {
	rendering string
	encoding  string
	out       string
}

// rendering is one way of turning a value into text, named as a reader would
// name it in a bug report.
type rendering struct {
	name string
	out  string
}

// leakVerbs is every fmt verb this subtest exercises. %T and %p are absent on
// purpose; see NoSecretLeaksInAnyRendering. The width, precision and flag
// forms are here because a Formatter that honours fmt.State's width by
// re-rendering the underlying value is a real way to get this wrong.
var leakVerbs = []string{
	"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%c", "%U",
	"%b", "%o", "%e", "%f", "%t", "%8v", "%-24s", "%+d", "% x", "%.4f",
}

// renderingLeaks renders v every way Go offers and reports every rendering
// that discloses material in any encoding.
//
// The verb list is a variable rather than a sequence of literal format
// strings deliberately: go vet's printf analyzer only inspects constant
// formats, and a literal fmt.Sprintf("%d", aStruct) here would be a vet
// failure in CI for code whose entire purpose is to provoke that case.
func renderingLeaks(v any, material []byte) []renderingLeak {
	var leaks []renderingLeak
	for _, r := range renderings(v) {
		for _, n := range leakNeedles(material) {
			if n.contained(r.out) {
				leaks = append(leaks, renderingLeak{rendering: r.name, encoding: n.what, out: r.out})
			}
		}
	}
	return leaks
}

// renderings produces every rendering of v this subtest asserts on. Each verb
// is applied both to v and to a struct that merely contains v, because that
// second shape — a config, a handle, a request context that happens to carry
// the material — is how material actually reaches a log line.
func renderings(v any) []rendering {
	// container has an exported field so that fmt consults the field's own
	// methods. Material behind an *unexported* field is unreachable by fmt's
	// method path entirely (reflect.Value.CanInterface is false), which is
	// why CONVENTIONS.md requires the four interfaces on every type that
	// transitively holds material rather than only on the innermost one.
	type container struct {
		Value any
	}
	held := container{Value: v}

	out := make([]rendering, 0, 2*len(leakVerbs)+10)
	if s, ok := v.(fmt.Stringer); ok {
		out = append(out, rendering{"String()", s.String()})
	}
	for _, verb := range leakVerbs {
		out = append(out,
			rendering{"fmt " + verb, fmt.Sprintf(verb, v)},
			rendering{"fmt " + verb + " of a struct holding it", fmt.Sprintf(verb, held)},
		)
	}

	out = append(out, marshalRendering("json.Marshal", v), marshalRendering("json.Marshal of a struct holding it", held))

	// The timestamp is dropped from both handlers. It is not part of what is
	// being asserted, and a time of day is a long run of digits that the
	// length needle below could collide with — a rendering must fail this
	// subtest because of the value, never because of the clock.
	opts := &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	}
	for _, h := range []struct {
		name string
		make func(*strings.Builder) slog.Handler
	}{
		{"slog TextHandler", func(w *strings.Builder) slog.Handler { return slog.NewTextHandler(w, opts) }},
		{"slog JSONHandler", func(w *strings.Builder) slog.Handler { return slog.NewJSONHandler(w, opts) }},
	} {
		for _, form := range []struct {
			name string
			attr func() slog.Attr
		}{
			{"slog.Any", func() slog.Attr { return slog.Any("value", v) }},
			{"slog.Attr of a struct holding it", func() slog.Attr { return slog.Any("value", held) }},
			{"a slog group", func() slog.Attr { return slog.Group("g", slog.Any("value", v)) }},
		} {
			var buf strings.Builder
			slog.New(h.make(&buf)).Info("rendering", form.attr())
			out = append(out, rendering{h.name + " " + form.name, buf.String()})
		}
		// The variadic "key", value form takes a different path through
		// slog than slog.Any does, so it gets its own rendering.
		var buf strings.Builder
		slog.New(h.make(&buf)).Info("rendering", "value", v)
		out = append(out, rendering{h.name + " key/value pair", buf.String()})
	}

	return out
}

// marshalRendering renders v as JSON, keeping the error text as the rendering
// when marshalling fails: a MarshalJSON that refuses by returning an error
// built from the material would otherwise hide the leak in the error.
func marshalRendering(name string, v any) rendering {
	b, err := json.Marshal(v)
	if err != nil {
		return rendering{name + " (error)", err.Error()}
	}
	return rendering{name, string(b)}
}

// needle is one encoding of the material, as it would appear in a rendering.
type needle struct {
	what string
	text string
	// standalone is set for the length needle, where a bare number must be
	// matched only as its own token. Two false positives it rules out, both
	// real: a ciphertext byte count of 320 does not disclose a 32-byte key,
	// and a ULID — which every id in these modules is — is a long run of
	// letters and digits in which any two-digit number is near certain to
	// appear.
	standalone bool
}

func (n needle) contained(s string) bool {
	if n.text == "" {
		return false
	}
	if !n.standalone {
		return strings.Contains(s, n.text)
	}
	for i := 0; ; {
		j := strings.Index(s[i:], n.text)
		if j < 0 {
			return false
		}
		start, end := i+j, i+j+len(n.text)
		beforeOK := start == 0 || !isAlphanumeric(s[start-1])
		afterOK := end == len(s) || !isAlphanumeric(s[end])
		if beforeOK && afterOK {
			return true
		}
		i = start + 1
	}
}

func isAlphanumeric(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// leakNeedles is every form the material can appear in that a rendering
// actually produces. Each one was observed in a real rendering rather than
// imagined: the byte-wise forms are what %d, %o, %b, %c, %U and %#v print for
// a []byte field that no interface intercepted, and they are the forms that
// caught keyring's DEK.
func leakNeedles(material []byte) []needle {
	s := string(material)
	needles := []needle{
		{what: "the material itself", text: s},
		{what: "lowercase hex", text: hex.EncodeToString(material)},
		{what: "uppercase hex", text: strings.ToUpper(hex.EncodeToString(material))},
		{what: "base64 (std)", text: base64.StdEncoding.EncodeToString(material)},
		{what: "base64 (std, unpadded)", text: base64.RawStdEncoding.EncodeToString(material)},
		{what: "base64 (url)", text: base64.URLEncoding.EncodeToString(material)},
		{what: "base64 (url, unpadded)", text: base64.RawURLEncoding.EncodeToString(material)},
		{what: "its length in decimal", text: strconv.Itoa(len(material)), standalone: true},
	}

	// Go quoted-string escaping, as %q and encoding/json produce it. Only
	// interesting when escaping actually changed something, otherwise it is
	// the raw needle twice.
	if quoted := strconv.Quote(s); quoted != `"`+s+`"` {
		needles = append(needles, needle{what: "Go quoted-string escaping", text: strings.Trim(quoted, `"`)})
	}

	// encoding/json's own string escaping, which is not strconv.Quote's: a
	// NUL becomes a \u escape rather than a \x one, so a leak through
	// json.Marshal or slog's JSONHandler matches neither the raw needle nor
	// the Go-quoted one.
	if jb, err := json.Marshal(s); err == nil {
		if inner := strings.Trim(string(jb), `"`); inner != s {
			needles = append(needles, needle{what: "JSON string escaping", text: inner})
		}
	}

	// The byte-wise forms. They are what reflection prints for a []byte the
	// method path never reached, and they are per-byte, so a one-byte
	// material would make them meaningless.
	if len(material) >= 2 {
		dec := make([]string, len(material))
		oct := make([]string, len(material))
		bin := make([]string, len(material))
		gos := make([]string, len(material))
		run := make([]string, len(material))
		chr := make([]string, len(material))
		for i, b := range material {
			dec[i] = strconv.FormatUint(uint64(b), 10)
			oct[i] = strconv.FormatUint(uint64(b), 8)
			bin[i] = strconv.FormatUint(uint64(b), 2)
			gos[i] = fmt.Sprintf("%#x", b)
			run[i] = fmt.Sprintf("%U", rune(b))
			chr[i] = string(rune(b))
		}
		needles = append(needles,
			needle{what: "byte-wise decimal, as %d prints it", text: strings.Join(dec, " ")},
			needle{what: "byte-wise octal, as %o prints it", text: strings.Join(oct, " ")},
			needle{what: "byte-wise binary, as %b prints it", text: strings.Join(bin, " ")},
			needle{what: "Go syntax for a byte slice, as %#v prints it", text: strings.Join(gos, ", ")},
			needle{what: "byte-wise code points, as %U prints it", text: strings.Join(run, " ")},
			needle{what: "byte-wise characters, as %c prints it", text: strings.Join(chr, " ")},
		)
	}

	return needles
}

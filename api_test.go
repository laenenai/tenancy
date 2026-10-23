package tenancy_test

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// updateAPI regenerates api.txt instead of checking it:
//
//	go test . -run TestAPIGolden -update-api
var updateAPI = flag.Bool("update-api", false, "rewrite api.txt from the current source")

// apiPackages are the directories api.txt covers, in the order they appear
// in the file. The two importable packages come first; the internal ones
// follow because the facade re-exports them as aliases, so a change to an
// internal signature is a change to the public surface even though Go's
// internal rule keeps the import path private.
//
// Every internal package here is aliased by the facade, so its signatures
// are public surface: internal/domain (the typed ids, the records, the
// enums, the sentinels), internal/pg (the data-plane handle, the pool
// configuration, the row-level-security constants and the enforcement
// report), internal/pool (the cache options and the opener seam),
// internal/registry (the control-plane handle and its inputs),
// internal/scope (Tenancy and Config) and internal/migrate (the migration
// configuration and the schema and identity constants).
//
// testdb is listed as an importable package rather than skipped, which is
// where this module differs from audit's and pgmigrate's golden files. Its
// harness is not this module's private scaffolding: CONVENTIONS.md makes
// `tenancy` the home of the shared container harness, so other modules
// import tenancy/testdb directly and a change to Start's signature breaks
// their test suites. That makes it reviewable surface.
var apiPackages = []string{
	".",
	"tenancytest",
	"testdb",
	"internal/domain",
	"internal/migrate",
	"internal/pg",
	"internal/pool",
	"internal/registry",
	"internal/scope",
}

const apiHeader = `# Public API of github.com/laenenai/tenancy, as a golden file.
#
# Regenerate with: go test . -run TestAPIGolden -update-api
#
# "package tenancy" is the facade a consumer imports; "package tenancytest"
# is the conformance suite it runs against its own wiring; "package testdb"
# is the shared container harness other modules import. The internal
# packages are listed too, because the facade re-exports their types as
# aliases: a change to one of those signatures changes what a consumer
# sees, even though the import path itself is private. Growing this file is
# a reviewed diff — see CHARTER.md.
`

// TestAPIGolden keeps api.txt in step with the source. CHARTER.md makes the
// file one of the two mechanisms that enforce the module's boundary, which
// only works if it is generated rather than maintained by hand.
func TestAPIGolden(t *testing.T) {
	t.Parallel()

	got, err := renderAPI()
	if err != nil {
		t.Fatalf("render api: %v", err)
	}

	if *updateAPI {
		if err := os.WriteFile("api.txt", got, 0o600); err != nil {
			t.Fatalf("write api.txt: %v", err)
		}
		t.Log("api.txt rewritten")
		return
	}

	want, err := os.ReadFile("api.txt")
	if err != nil {
		t.Fatalf("read api.txt: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("api.txt is stale: the public surface has changed.\n"+
			"Regenerate with: go test . -run TestAPIGolden -update-api\n\n"+
			"--- api.txt\n%s\n--- source\n%s", want, got)
	}
}

// renderAPI renders every exported declaration in apiPackages.
func renderAPI() ([]byte, error) {
	var out bytes.Buffer
	out.WriteString(apiHeader)

	for _, dir := range apiPackages {
		section, err := renderPackage(dir)
		if err != nil {
			return nil, fmt.Errorf("render %s: %w", dir, err)
		}
		out.WriteString("\n")
		out.WriteString(section)
	}
	return out.Bytes(), nil
}

// renderPackage renders one directory's exported declarations, sorted so
// the output depends on the declarations and not on the order of the files
// they happen to live in.
func renderPackage(dir string) (string, error) {
	fset := token.NewFileSet()

	names, err := goFiles(dir)
	if err != nil {
		return "", err
	}

	var pkgName string
	var entries []apiEntry
	for _, name := range names {
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			return "", fmt.Errorf("parse %s: %w", name, err)
		}
		pkgName = file.Name.Name
		entries = append(entries, exportedDecls(fset, file)...)
	}
	if pkgName == "" {
		return "", errors.New("no non-test Go files")
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].key < entries[j].key })

	var out strings.Builder
	fmt.Fprintf(&out, "package %s // %s\n", pkgName, dir)
	for _, e := range entries {
		out.WriteString("\n")
		out.WriteString(e.text)
		out.WriteString("\n")
	}
	return out.String(), nil
}

// goFiles lists the non-test .go files in dir, sorted.
func goFiles(dir string) ([]string, error) {
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read dir: %w", err)
	}

	var names []string
	for _, entry := range dirEntries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, fs.ErrNotExist
	}
	sort.Strings(names)
	return names, nil
}

// apiEntry is one rendered declaration plus the key it sorts under.
// Methods sort directly after their receiver type.
type apiEntry struct {
	key  string
	text string
}

// exportedDecls renders the exported declarations in one file. Doc comments
// are deliberately omitted: api.txt is a signature diff, and including the
// prose would make every wording change look like an API change.
func exportedDecls(fset *token.FileSet, file *ast.File) []apiEntry {
	var entries []apiEntry

	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if !d.Name.IsExported() {
				continue
			}
			recv, text, ok := renderFunc(fset, d)
			if !ok {
				continue
			}
			entries = append(entries, apiEntry{key: recv + d.Name.Name, text: text})

		case *ast.GenDecl:
			keyword := map[token.Token]string{
				token.TYPE:  "type",
				token.VAR:   "var",
				token.CONST: "const",
			}[d.Tok]
			if keyword == "" {
				continue
			}
			for _, spec := range d.Specs {
				name, rendered, ok := renderSpec(fset, keyword, spec)
				if !ok {
					continue
				}
				entries = append(entries, apiEntry{key: name, text: rendered})
			}
		}
	}
	return entries
}

// renderFunc renders a function or method signature. The receiver's type
// name is returned separately so a method sorts under its type. A method
// on an unexported type is not part of the surface, however exported its
// own name is, so it reports ok == false.
func renderFunc(fset *token.FileSet, d *ast.FuncDecl) (recvType, text string, ok bool) {
	sig := strings.TrimPrefix(render(fset, d.Type), "func")

	if d.Recv == nil || len(d.Recv.List) == 0 {
		return "", "func " + d.Name.Name + sig, true
	}

	recv := render(fset, d.Recv.List[0].Type)
	bare := strings.TrimLeft(recv, "*")
	if !token.IsExported(bare) {
		return "", "", false
	}
	return bare + ".", fmt.Sprintf("func (%s) %s%s", recv, d.Name.Name, sig), true
}

// renderSpec renders one type, var or const spec, or reports ok == false if
// nothing in it is exported.
func renderSpec(fset *token.FileSet, keyword string, spec ast.Spec) (name, text string, ok bool) {
	switch s := spec.(type) {
	case *ast.TypeSpec:
		if !s.Name.IsExported() {
			return "", "", false
		}
		if st, isStruct := s.Type.(*ast.StructType); isStruct {
			return s.Name.Name, keyword + " " + s.Name.Name + " " + renderStruct(fset, st), true
		}
		return s.Name.Name, keyword + " " + render(fset, s), true

	case *ast.ValueSpec:
		exported := false
		for _, id := range s.Names {
			if id.IsExported() {
				exported = true
				break
			}
		}
		if !exported {
			return "", "", false
		}
		return s.Names[0].Name, keyword + " " + render(fset, s), true
	}
	return "", "", false
}

// renderStruct renders a struct type listing its exported fields only.
// Unexported state is not part of the surface, but its presence is worth
// recording, so a struct that has any says so the way godoc does.
func renderStruct(fset *token.FileSet, st *ast.StructType) string {
	var fields []string
	hidden := false

	for _, field := range st.Fields.List {
		typ := render(fset, field.Type)
		if len(field.Names) == 0 {
			// An embedded field is exported if its type name is.
			if token.IsExported(strings.TrimLeft(typ, "*")) {
				fields = append(fields, typ)
			} else {
				hidden = true
			}
			continue
		}
		var names []string
		for _, name := range field.Names {
			if name.IsExported() {
				names = append(names, name.Name)
			} else {
				hidden = true
			}
		}
		if len(names) > 0 {
			fields = append(fields, strings.Join(names, ", ")+" "+typ)
		}
	}

	if hidden {
		fields = append(fields, "// has unexported fields")
	}
	if len(fields) == 0 {
		return "struct{}"
	}
	return "struct {\n\t" + strings.Join(fields, "\n\t") + "\n}"
}

// collapseBlankLines removes empty lines from a rendered declaration. They
// are artefacts of the doc comments this file strips, not structure.
func collapseBlankLines(s string) string {
	lines := strings.Split(s, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

// render prints one AST node with go/printer, which is the same formatter
// gofmt uses, so the output is stable across runs and across Go releases
// that do not change formatting.
func render(fset *token.FileSet, node ast.Node) string {
	var buf bytes.Buffer
	if err := (&printer.Config{Mode: printer.UseSpaces | printer.TabIndent, Tabwidth: 4}).Fprint(&buf, fset, node); err != nil {
		return fmt.Sprintf("<unprintable: %v>", err)
	}
	return collapseBlankLines(buf.String())
}

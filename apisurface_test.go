package plat

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestPublicAPISurface pins every exported identifier in this package.
// A public API cannot be un-exported later without breaking consumers, so
// growth must be deliberate: this test fails on an ADDITION as loudly as
// on a removal. When a change is intended, update testdata/api-surface.txt
// in the same commit and the diff shows a reviewer exactly what was
// committed to.
func TestPublicAPISurface(t *testing.T) {
	names := exportedNames(t)

	wantBytes, err := os.ReadFile(filepath.Join("testdata", "api-surface.txt"))
	if err != nil {
		t.Fatalf("reading golden: %v", err)
	}
	var want []string
	for _, line := range strings.Split(string(wantBytes), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			want = append(want, line)
		}
	}
	sort.Strings(want)

	if strings.Join(names, "\n") != strings.Join(want, "\n") {
		t.Errorf("public API surface changed.\n got:\n%s\nwant:\n%s\n\n"+
			"If this change is intended, update testdata/api-surface.txt.",
			strings.Join(names, "\n"), strings.Join(want, "\n"))
	}
}

func exportedNames(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	fset := token.NewFileSet()
	var names []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, n, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", n, err)
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Recv != nil {
					if d.Name.IsExported() && recvExported(d.Recv) {
						names = append(names, "method "+recvName(d.Recv)+"."+d.Name.Name)
					}
					continue
				}
				if d.Name.IsExported() {
					names = append(names, "func "+d.Name.Name)
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						if s.Name.IsExported() {
							names = append(names, "type "+s.Name.Name)
						}
					case *ast.ValueSpec:
						for _, id := range s.Names {
							if id.IsExported() {
								names = append(names, "value "+id.Name)
							}
						}
					}
				}
			}
		}
	}
	sort.Strings(names)
	return names
}

func recvName(fl *ast.FieldList) string {
	switch t := fl.List[0].Type.(type) {
	case *ast.StarExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return id.Name
		}
	case *ast.Ident:
		return t.Name
	}
	return ""
}

func recvExported(fl *ast.FieldList) bool {
	return ast.IsExported(recvName(fl))
}

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

// TestPublicAPISurface pins every exported identifier in both public
// packages. A public API cannot be un-exported later without breaking
// consumers, so growth must be deliberate: this test fails on an ADDITION
// as loudly as on a removal. When a change is intended, update the matching
// golden in the same commit and the diff shows a reviewer exactly what was
// committed to.
//
// model/ is listed here rather than carrying its own copy of this test:
// the scanner parses files off disk and never imports the package, so one
// test covers both surfaces without a second copy to drift.
func TestPublicAPISurface(t *testing.T) {
	for _, pkg := range []struct{ dir, golden string }{
		{".", filepath.Join("testdata", "api-surface.txt")},
		{"model", filepath.Join("model", "testdata", "api-surface.txt")},
	} {
		t.Run(pkg.dir, func(t *testing.T) {
			names := exportedNames(t, pkg.dir)

			wantBytes, err := os.ReadFile(pkg.golden)
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
				t.Errorf("public API surface of %s changed.\n got:\n%s\nwant:\n%s\n\n"+
					"If this change is intended, update %s.",
					pkg.dir, strings.Join(names, "\n"), strings.Join(want, "\n"), pkg.golden)
			}
		})
	}
}

func exportedNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	var names []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, 0)
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
	return recvBaseName(fl.List[0].Type)
}

// recvBaseName unwraps a receiver type expression down to its base
// identifier. A plain or pointer receiver on a non-generic type is just
// *ast.Ident or *ast.StarExpr around one, but a receiver on a generic
// type -- e.g. Field[T] or, if a future type parameterizes on more than
// one type, Field[K, V] -- parses as *ast.IndexExpr or *ast.IndexListExpr
// wrapping the base identifier instead. Recursing through all of these
// (and StarExpr around a generic receiver) keeps a method on a generic
// type from being silently dropped from the API surface.
func recvBaseName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return recvBaseName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.IndexExpr:
		return recvBaseName(t.X)
	case *ast.IndexListExpr:
		return recvBaseName(t.X)
	}
	return ""
}

func recvExported(fl *ast.FieldList) bool {
	return ast.IsExported(recvName(fl))
}

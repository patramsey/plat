package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadNameList(t *testing.T) {
	for _, tt := range []struct {
		name string
		in   string
		want []string
	}{
		{"one per line", "a.com\nb.com\nc.com\n", []string{"a.com", "b.com", "c.com"}},
		{"blank lines skipped", "a.com\n\n\nb.com\n", []string{"a.com", "b.com"}},
		{"comments skipped", "# a list\na.com\n  # indented comment\nb.com\n", []string{"a.com", "b.com"}},
		{"surrounding whitespace trimmed", "  a.com  \n\tb.com\t\n", []string{"a.com", "b.com"}},
		{"no trailing newline", "a.com\nb.com", []string{"a.com", "b.com"}},
		{"crlf line endings", "a.com\r\nb.com\r\n", []string{"a.com", "b.com"}},
		{"empty input", "", nil},
		{"only comments and blanks", "# nothing\n\n   \n", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readNameList(strings.NewReader(tt.in))
			if err != nil {
				t.Fatalf("readNameList: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("entry %d = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// TestReadNameList_DoesNotTreatHashInsideANameAsAComment pins that only a
// leading # starts a comment. A name is never valid with a # in it, but
// silently truncating one would turn a bad input into a wrong lookup
// rather than an error the normalizer can report.
func TestReadNameList_DoesNotTreatHashInsideANameAsAComment(t *testing.T) {
	got, err := readNameList(strings.NewReader("a#b.com\n"))
	if err != nil {
		t.Fatalf("readNameList: %v", err)
	}
	if len(got) != 1 || got[0] != "a#b.com" {
		t.Errorf("got %q, want [a#b.com] -- only a leading # starts a comment", got)
	}
}

func TestFile_RejectsPositionalNamesToo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "names.txt")
	if err := os.WriteFile(path, []byte("a.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := run([]string{"--file", path, "b.com"}, &out, &errBuf, uiConfig{})
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "mutually exclusive") {
		t.Errorf("stderr missing the message:\n%s", errBuf.String())
	}
}

func TestFile_MissingFileIsUsageError(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--file", "/nonexistent/nope.txt"}, &out, &errBuf, uiConfig{})
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
}

func TestFile_EmptyListIsUsageError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(path, []byte("# only a comment\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := run([]string{"--file", path}, &out, &errBuf, uiConfig{})
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "no names found") {
		t.Errorf("stderr missing the message:\n%s", errBuf.String())
	}
}

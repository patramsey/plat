package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenDocs_GeneratesManPagesAndCompletionsExcludingHiddenCommands(t *testing.T) {
	dir := t.TempDir()
	var stdout, stderr bytes.Buffer

	// Invoking run() itself (not a hand-built command tree) guarantees
	// this test exercises the real, live command tree — the same one
	// goreleaser's before.hooks will invoke at release build time.
	got := run([]string{"gendocs", dir}, &stdout, &stderr, uiConfig{})
	if got != 0 {
		t.Fatalf("run([gendocs %s]) exit code = %d, stderr=%s", dir, got, stderr.String())
	}

	manEntries, err := os.ReadDir(filepath.Join(dir, "man"))
	if err != nil {
		t.Fatalf("reading man dir: %v", err)
	}
	if len(manEntries) == 0 {
		t.Fatal("expected at least one generated man page")
	}
	for _, e := range manEntries {
		lower := strings.ToLower(e.Name())
		if strings.Contains(lower, "whois") || strings.Contains(lower, "merge") || strings.Contains(lower, "gendocs") {
			t.Errorf("hidden command leaked into a man page filename: %s", e.Name())
		}
		content, err := os.ReadFile(filepath.Join(dir, "man", e.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", e.Name(), err)
		}
		if strings.Contains(string(content), "WHOIS (debug") {
			t.Errorf("hidden whois command's help text leaked into %s", e.Name())
		}
	}

	for _, name := range []string{"plat.bash", "plat.zsh", "plat.fish", "plat.ps1"} {
		content, err := os.ReadFile(filepath.Join(dir, "completions", name))
		if err != nil {
			t.Fatalf("reading completions/%s: %v", name, err)
		}
		if len(content) == 0 {
			t.Errorf("completions/%s is empty", name)
		}
		if strings.Contains(string(content), "gendocs") {
			t.Errorf("hidden gendocs command leaked into completions/%s", name)
		}
	}
}

func TestGenDocs_RequiresExactlyOneArg(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"gendocs"}, &stdout, &stderr, uiConfig{})
	if got == 0 {
		t.Error("run([gendocs]) with no output-dir arg should fail, got exit 0")
	}
}

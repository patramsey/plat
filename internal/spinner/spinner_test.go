package spinner

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun_ExecutesWorkAndReturns(t *testing.T) {
	var buf bytes.Buffer
	var workDone bool

	Run(&buf, "testing", func() {
		workDone = true
	})

	if !workDone {
		t.Error("work function was not called before Run returned")
	}
}

func TestRun_DoesNotRequireARealTerminal(t *testing.T) {
	// This test's mere ability to complete (not hang, not error) is the
	// assertion: Run must work when w is a plain *bytes.Buffer, not a
	// real terminal — this is what makes callers of Run (and their own
	// tests) safe to run in CI/sandboxed environments with no /dev/tty.
	var buf bytes.Buffer
	Run(&buf, "no terminal here", func() {})
}

func TestRun_NeverWritesEscapeSequences(t *testing.T) {
	// Regression test: the bubbletea-based implementation this package
	// used to have wrote terminal capability queries (a DECRQM query for
	// synchronized-output/unicode-core mode, and separately a Kitty
	// keyboard protocol query on every program's first frame) that
	// expect a reply on stdin — but Run disables input entirely, so
	// those replies were never read and leaked onto the user's next
	// shell prompt as literal garbage once the process exited. Rather
	// than assert against the two specific queries that were found this
	// way (see git history), assert the stronger invariant that made
	// them impossible to reintroduce: Run must never write an ESC byte
	// at all — an animated dot has no legitimate reason to negotiate
	// terminal capabilities.
	var buf bytes.Buffer
	Run(&buf, "probing", func() {})
	if strings.ContainsRune(buf.String(), 0x1b) {
		t.Errorf("Run wrote an ESC byte; want plain carriage-return-driven output only, got:\n%q", buf.String())
	}
}

func TestRun_ClearsItsLineOnCompletion(t *testing.T) {
	var buf bytes.Buffer
	Run(&buf, "clearing", func() {})
	out := buf.String()
	if !strings.HasSuffix(out, "\r") {
		t.Errorf("expected output to end with a bare carriage return after clearing, got: %q", out)
	}
	lastCR := strings.LastIndex(out[:len(out)-1], "\r")
	if lastCR < 0 {
		t.Fatalf("expected at least two carriage returns (draw, then clear), got: %q", out)
	}
	cleared := out[lastCR+1 : len(out)-1]
	if strings.TrimSpace(cleared) != "" {
		t.Errorf("expected only blank padding between the last draw and the final clear, got: %q", cleared)
	}
}

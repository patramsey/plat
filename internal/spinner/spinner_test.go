package spinner

import (
	"bytes"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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

// TestRunFunc_ReevaluatesMessage pins that the message function is called
// per frame rather than once. Without this, a counter would render its
// starting value for the whole run and look frozen.
func TestRunFunc_ReevaluatesMessage(t *testing.T) {
	var n atomic.Int64
	var buf bytes.Buffer

	RunFunc(&buf, func() string {
		return fmt.Sprintf("%d/10", n.Load())
	}, func() {
		for i := range 10 {
			n.Store(int64(i + 1))
			time.Sleep(interval + interval/2)
		}
	})

	out := buf.String()
	for _, want := range []string{"1/10", "10/10"} {
		if !strings.Contains(out, want) {
			t.Errorf("output never showed %q -- the message func is not being re-evaluated:\n%q", want, out)
		}
	}
}

// TestRunFunc_RepaintsFullWidthWhenTheMessageShrinks covers draw's
// shrink-padding, which had no test at all: reverting
// `lineLen = len(line) + len(pad)` to `lineLen = len(line)` left the whole
// suite green.
//
// The property is that every frame repaints at least as many columns as
// the widest frame drawn so far, and that the final clear blanks that
// full width. Tracking only the current line's own length instead looks
// harmless -- each draw still pads to the width of the draw before it, so
// in a terminal nobody else is writing to, the columns beyond have
// already been blanked by an earlier frame. That reasoning is exactly
// what does not hold here: runLookupPool drives this spinner on the same
// stderr row that every worker's error diagnostics write to, so a frame
// that repaints only part of the row can leave another writer's tail
// standing next to the counter.
//
// The message shrinks after the first frame, which is what makes the two
// versions diverge: the first frame is wide, and every frame after it
// must still be padded out to that width rather than settling down to
// the short message's own.
func TestRunFunc_RepaintsFullWidthWhenTheMessageShrinks(t *testing.T) {
	const long = "looking up... 1/10 (resolving a rather long name)"
	const short = "9/10"

	var calls atomic.Int64
	var buf bytes.Buffer
	RunFunc(&buf, func() string {
		if calls.Add(1) == 1 {
			return long
		}
		return short
	}, func() {
		// Long enough for the initial draw plus at least two ticks --
		// the divergence only shows from the second shortened frame on.
		time.Sleep(3*interval + interval/2)
	})

	out := buf.String()
	if !strings.HasSuffix(out, "\r") {
		t.Fatalf("expected output to end with a bare carriage return, got: %q", out)
	}
	// "\r" + line1 + "\r" + line2 ... + "\r" + clear + "\r" splits into a
	// leading empty element, one element per drawn line, the clear, and a
	// trailing empty element.
	parts := strings.Split(out[:len(out)-1], "\r")
	if len(parts) < 5 {
		t.Fatalf("expected at least three draws plus a clear, got %d segments: %q", len(parts)-1, out)
	}
	lines, cleared := parts[1:len(parts)-1], parts[len(parts)-1]

	widest := 0
	for i, line := range lines {
		if len(line) < widest {
			t.Errorf("frame %d repainted %d columns after an earlier frame drew %d -- a shrinking message must stay padded to the widest line drawn so far, got %q", i, len(line), widest, line)
		}
		if len(line) > widest {
			widest = len(line)
		}
	}
	if strings.TrimSpace(cleared) != "" {
		t.Errorf("final clear wrote non-blank text: %q", cleared)
	}
	if len(cleared) < widest {
		t.Errorf("final clear blanked %d columns, want at least %d (the widest line drawn)", len(cleared), widest)
	}
}

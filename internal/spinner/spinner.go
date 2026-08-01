// Package spinner shows an animated progress indicator on an io.Writer
// (intended to be stderr) while a caller-supplied function runs, then
// clears it. It writes nothing but a carriage return, spinner frame,
// message text, and (on completion) blanks-plus-carriage-return to erase
// its own line — no ANSI escapes, no raw-mode terminal access, no
// capability negotiation of any kind. plat is a render-and-exit tool, not
// an interactive TUI, and this package never reads input.
//
// This used to wrap charm.land/bubbletea/v2's Program machinery for the
// animation. That was dropped after two separate, real leaks: bubbletea's
// renderer writes terminal capability queries (DECRQM for synchronized-
// output/unicode-core mode, and separately a Kitty keyboard protocol
// query on every program's first frame) that expect a reply on stdin —
// but this package never reads input, so the terminal's replies sat
// unread and got echoed as literal garbage on the user's next shell
// prompt once the process exited. The first leak could be suppressed with
// an environment override; the second had no such gate and always fired.
// Since nothing about an animated dot needs a terminal capability
// negotiation, writing the handful of bytes directly removes the entire
// bug class rather than chasing each query bubbletea might add.
package spinner

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// frames and interval match charm.land/bubbles/v2's spinner.Dot, which
// this package used to render via bubbletea, to keep the same look.
var frames = []string{"⣾ ", "⣽ ", "⣻ ", "⢿ ", "⡿ ", "⣟ ", "⣯ ", "⣷ "}

const interval = time.Second / 10

// Run displays an animated spinner with message on w while work executes
// in the background, then clears the spinner line once work returns.
// work is always fully executed before Run returns, regardless of how
// long it takes relative to the animation.
func Run(w io.Writer, message string, work func()) {
	done := make(chan struct{})
	go func() {
		work()
		close(done)
	}()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lineLen int
	draw := func(frame string) {
		line := frame + message
		lineLen = len(line)
		_, _ = fmt.Fprint(w, "\r"+line)
	}

	draw(frames[0])
	for i := 1; ; i++ {
		select {
		case <-done:
			_, _ = fmt.Fprint(w, "\r"+strings.Repeat(" ", lineLen)+"\r")
			return
		case <-ticker.C:
			draw(frames[i%len(frames)])
		}
	}
}

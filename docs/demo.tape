# Demo recording script for plat. To record it: install vhs
# (https://github.com/charmbracelet/vhs) plus its ffmpeg/ttyd runtime
# deps, make sure `plat` is on your $PATH (e.g. `go install ./cmd/plat`),
# then run:
#
#   vhs docs/demo.tape
#
# This regenerates docs/demo.gif, which README.md already references.
# Keep it in sync: re-run this whenever a change touches what the
# commands below print (flags, output formatting, sample field values),
# not just at release time.
#
# CHECK WHICH plat YOU ARE RECORDING -- run `which -a plat` first. A
# Homebrew-installed plat shadows a freshly `go install`ed one on a
# default macOS $PATH, and recording against a stale binary produces a
# GIF that silently misrepresents the tool. This is not hypothetical: the
# v0.4.0 Homebrew build rendered human output with no colour at all (a
# regression fixed in v0.5.0), so recording against it would have
# published a monochrome GIF of a bug. Put the build you mean first:
#
#   go build -o /tmp/platdemo/plat ./cmd/plat
#   PATH=/tmp/platdemo:$PATH vhs docs/demo.tape
#
# The first three lookups are deliberately all Google (a domain, one of
# its nameserver IPs, and its AS) so the demo reads as one story about
# the same operator seen through three object types, rather than as a
# list of features. All three are ARIN-held, which keeps recording fast
# and the output stable. The last three commands then show what you do
# with that: many names at once into machine output, and diffing a
# lookup against a snapshot taken moments earlier.

Output docs/demo.gif

Require plat

Set Shell "bash"
Set FontSize 20
Set Width 1200
Set Height 900
Set Theme "Dracula"
Set TypingSpeed 60ms

Type "plat google.com"
Sleep 500ms
Enter
Sleep 4s

Type "plat 8.8.8.8"
Sleep 500ms
Enter
Sleep 4s

Type "plat AS15169"
Sleep 500ms
Enter
Sleep 4s

# Several names in one invocation: looked up concurrently, but emitted in
# input order, so the output is stable enough to pipe into jq.
#
# The jq filter uses bare object keys on purpose: vhs's Type cannot
# contain a double quote, escaped or not, so a filter written with string
# literals will not parse.
Type "plat google.com github.com -o ndjson | jq -c '{name: .domain.value, expires: .expires.value}'"
Sleep 500ms
Enter
Sleep 5s

# Save a snapshot, then diff a fresh lookup against it. Seconds apart,
# so the honest answer is "no changes" -- which is exactly the signal a
# monitoring cron wants, and it exits 0 to say so.
Type "plat -o json google.com > /tmp/plat-demo.json"
Sleep 300ms
Enter
Sleep 3s

Type "plat --diff /tmp/plat-demo.json google.com"
Sleep 500ms
Enter
Sleep 4s

Sleep 2s

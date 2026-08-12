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
# Check which plat you are actually recording -- `which plat` -- before
# running this. A Homebrew-installed plat can shadow a freshly
# `go install`ed one, and recording against a stale binary produces a
# GIF that silently misrepresents the tool.
#
# The three lookups are deliberately all Google (a domain, one of its
# nameserver IPs, and its AS) so the demo reads as one story about the
# same operator seen through three object types, rather than as a list
# of features. All three are ARIN-held, which keeps recording fast and
# the output stable.

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

Type "plat -o json google.com | jq '.expires.value'"
Sleep 500ms
Enter
Sleep 3s

Sleep 2s

# Demo recording script for plat. To record it: install vhs
# (https://github.com/charmbracelet/vhs) plus its ffmpeg/ttyd runtime
# deps, make sure `plat` is on your $PATH (e.g. `go install ./cmd/plat`),
# then run:
#
#   vhs docs/demo.tape
#
# This regenerates docs/demo.gif, which README.md already references.
# Keep it in sync: re-run this whenever a change touches what the three
# commands below print (flags, output formatting, sample field values),
# not just at release time.

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

Type "plat -o json google.com | jq '.expires.value'"
Sleep 500ms
Enter
Sleep 3s

Type "plat --source rdap example.com"
Sleep 500ms
Enter
Sleep 3s

Sleep 2s

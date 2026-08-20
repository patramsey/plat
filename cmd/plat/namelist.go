package main

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// readNameList reads one name per line. Blank lines and lines whose first
// non-space character is "#" are skipped, so a list can carry comments and
// stay grep-friendly. Only a *leading* # starts a comment: a name is never
// legitimately spelled with one, and truncating mid-token would turn a bad
// input into a wrong lookup instead of an error the normalizer reports.
//
// Names are returned verbatim apart from surrounding whitespace; every one
// goes through the same normalization a positional argument does, so bulk
// mode introduces no second parsing path.
func readNameList(r io.Reader) ([]string, error) {
	var names []string
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		names = append(names, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading name list: %w", err)
	}
	return names, nil
}

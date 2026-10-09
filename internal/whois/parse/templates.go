package parse

import (
	_ "embed"
	"fmt"
	"strings"
	"time"
	_ "time/tzdata" // template time zones must not depend on the machine's tz database

	"gopkg.in/yaml.v3"
)

//go:embed templates.yaml
var templatesYAML []byte

// Template describes per-TLD overrides to the generic parsing engine: an
// alternate line-tokenizer dialect and/or extra synonym-table entries.
// The zero Template (empty Format, nil Synonyms) means "use the generic
// kv dialect with no overrides."
type Template struct {
	Format   string            `yaml:"format"`
	Synonyms map[string]string `yaml:"synonyms"`
	// CommentOnlyIsNotFound marks a registry that answers a name with no
	// record by sending its comment block (terms of use) and nothing else,
	// with no not-found wording to match. An answer with no content line
	// outside comments then means NotFound.
	CommentOnlyIsNotFound bool `yaml:"commentOnlyIsNotFound"`
	// DateLayouts are Go time layouts tried before the global ones, for a
	// registry whose date format is ambiguous anywhere else: ISOC-IL's
	// day-first "11-01-2029" would misread as November 1 if a
	// month-first registry ever needed the same shape.
	DateLayouts []string `yaml:"dateLayouts"`
	// ContinuationLines makes the kv tokenizer read an indented line as
	// another value for the key above it (see tokenizeKV).
	ContinuationLines bool `yaml:"continuationLines"`
	// Timezone is the IANA zone a registry writes its times of day in
	// when it gives no offset: NASK's "2002.09.19 13:00:00" is 11:00 UTC.
	// Unset means UTC. A bare date is never shifted (see parseDateIn).
	Timezone string `yaml:"timezone"`

	location *time.Location
}

var templates map[string]Template

func init() {
	if err := yaml.Unmarshal(templatesYAML, &templates); err != nil {
		panic("parse: embedded templates.yaml is invalid: " + err.Error())
	}
	if err := loadTimezones(templates); err != nil {
		panic("parse: embedded templates.yaml: " + err.Error())
	}
}

// loadTimezones resolves each template's Timezone into its location.
func loadTimezones(ts map[string]Template) error {
	for tld, tmpl := range ts {
		if tmpl.Timezone == "" {
			continue
		}
		loc, err := time.LoadLocation(tmpl.Timezone)
		if err != nil {
			return fmt.Errorf("%s: %w", tld, err)
		}
		tmpl.location = loc
		ts[tld] = tmpl
	}
	return nil
}

// templateFor returns the template registered for tld, or the zero
// Template if none is registered. This only fails (panics, at init time)
// if the embedded templates.yaml itself is malformed — a build-time
// asset, not runtime input, so a panic on invalid embedded data is
// deliberate rather than plumbing an error through every caller.
func templateFor(tld string) Template {
	return templates[strings.ToLower(tld)]
}

package parse

import (
	_ "embed"
	"strings"

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
}

var templates map[string]Template

func init() {
	if err := yaml.Unmarshal(templatesYAML, &templates); err != nil {
		panic("parse: embedded templates.yaml is invalid: " + err.Error())
	}
}

// templateFor returns the template registered for tld, or the zero
// Template if none is registered. This only fails (panics, at init time)
// if the embedded templates.yaml itself is malformed — a build-time
// asset, not runtime input, so a panic on invalid embedded data is
// deliberate rather than plumbing an error through every caller.
func templateFor(tld string) Template {
	return templates[strings.ToLower(tld)]
}

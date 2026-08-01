package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

// newGendocsCommand returns a hidden subcommand that generates man pages
// and shell completion scripts for root's full (non-hidden) command tree
// into <output-dir>/man and <output-dir>/completions. It is invoked by
// goreleaser's before.hooks at release build time (`go run ./cmd/plat
// gendocs <dir>`), never by an end user — operating on the SAME live
// root command that Execute() runs means generated docs can never drift
// from the real CLI surface, and cobra's man/completion generators
// already skip any command marked Hidden (the whois/merge debug
// subcommands never appear in generated output).
func newGendocsCommand(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:    "gendocs <output-dir>",
		Short:  "Generate man pages and shell completions (internal, used by goreleaser)",
		Hidden: true,
		Args:   cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return genDocs(root, args[0])
		},
	}
}

func genDocs(root *cobra.Command, outputDir string) error {
	manDir := filepath.Join(outputDir, "man")
	compDir := filepath.Join(outputDir, "completions")
	if err := os.MkdirAll(manDir, 0o755); err != nil {
		return fmt.Errorf("gendocs: creating %s: %w", manDir, err)
	}
	if err := os.MkdirAll(compDir, 0o755); err != nil {
		return fmt.Errorf("gendocs: creating %s: %w", compDir, err)
	}

	if err := doc.GenManTree(root, &doc.GenManHeader{
		Title:   "PLAT",
		Section: "1",
		Source:  "plat " + version,
		Manual:  "plat Manual",
	}, manDir); err != nil {
		return fmt.Errorf("gendocs: generating man pages: %w", err)
	}

	completions := []struct {
		filename string
		gen      func(f *os.File) error
	}{
		{"plat.bash", func(f *os.File) error { return root.GenBashCompletionV2(f, true) }},
		{"plat.zsh", func(f *os.File) error { return root.GenZshCompletion(f) }},
		{"plat.fish", func(f *os.File) error { return root.GenFishCompletion(f, true) }},
		{"plat.ps1", func(f *os.File) error { return root.GenPowerShellCompletionWithDesc(f) }},
	}
	for _, c := range completions {
		f, err := os.Create(filepath.Join(compDir, c.filename))
		if err != nil {
			return fmt.Errorf("gendocs: creating %s: %w", c.filename, err)
		}
		genErr := c.gen(f)
		closeErr := f.Close()
		if genErr != nil {
			return fmt.Errorf("gendocs: generating %s: %w", c.filename, genErr)
		}
		if closeErr != nil {
			return fmt.Errorf("gendocs: closing %s: %w", c.filename, closeErr)
		}
	}
	return nil
}

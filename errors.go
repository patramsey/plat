package plat

import "errors"

var (
	// ErrInvalidInput means the input is not a name plat can look up --
	// a single label, a reserved or private IP, and so on. It wraps the
	// specific cause, so errors.Is against it succeeds while the
	// underlying error stays inspectable.
	ErrInvalidInput = errors.New("plat: invalid input")

	// ErrNotFound means every source reported that the object does not
	// exist. It corresponds to the CLI's exit code 1.
	ErrNotFound = errors.New("plat: not found")

	// ErrLookupFailed means no source returned data and at least one
	// failed for a reason other than not-found. It corresponds to the
	// CLI's exit code 3. Inspect Result's per-source details for why.
	ErrLookupFailed = errors.New("plat: lookup failed")
)

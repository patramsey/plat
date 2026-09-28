package source

// RestrictedReason is the error a WHOIS source carries when the registry
// answers that the name is reserved or restricted (see #111). collect
// sets it and the CLI recognises it, so the lookup's headline can say why
// it is inconclusive rather than reporting a generic source failure.
const RestrictedReason = "registry restricts this name (reserved or not available for registration)"

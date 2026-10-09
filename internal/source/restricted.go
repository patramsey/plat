package source

// RestrictedReason is the error a WHOIS source carries when the registry
// answers that the name is reserved or restricted (see #111). collect
// sets it and the CLI recognises it, so the lookup's headline can say why
// it is inconclusive rather than reporting a generic source failure.
const RestrictedReason = "registry restricts this name (reserved or not available for registration)"

// UnrecognisedReason is the error a WHOIS source carries when its answer
// yielded no fields and matched no not-found, refusal, rate-limit or
// restricted wording: an answer plat could not read, rather than a
// registered domain with no data (see #120).
const UnrecognisedReason = "unrecognised answer: no fields could be read, and no known not-found, refusal or rate-limit wording matched"

// EmptyReason replaces UnrecognisedReason when the answer was empty or
// only whitespace: there was no wording to match, and nothing for -v or
// --raw to show, so the problem is the server's rather than a gap in the
// parser (#148).
const EmptyReason = "empty answer: the WHOIS server replied with nothing"

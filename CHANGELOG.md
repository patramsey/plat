# Changelog

All notable changes to `plat` are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project
follows [Semantic Versioning](https://semver.org/).

## [0.11.0] - 2026-09-29

A second sweep, of RDAP, registrar WHOIS servers, RIR edge cases and
gTLD registry backends, plus a structural fix for the class of bug the
first sweep kept finding: a WHOIS answer plat could not read counted as
a registered domain. Exit-code changes are treated as breaking, which is
why this is a minor release.

### Added
- `model.SourceResult.Unavailable` (JSON `"unavailable": true`, omitted
  when false) marks a source with no service for the name.
  `model.Classify` leaves such sources out.

### Changed
- **Breaking:** A WHOIS answer that plat cannot read -- no field parsed,
  and no known not-found, refusal, rate-limit or restricted wording --
  is a failed source instead of a successful one with no data. A lookup
  with no other source now exits `3` ("the registry's answer could not
  be read; -v or --raw shows it") instead of `0` with an empty record.
  This was the root of the ccTLD sweep's bugs: an unknown not-found
  wording read as a registered domain. Replaying every recorded sweep
  answer changes none today; it catches wording not yet seen.
- **Breaking:** Documentation and reserved IP ranges -- `192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`, `3fff::/20`,
  `240.0.0.0/4` and `0.0.0.0/8` -- exit `2` with the reason, like other
  reserved addresses. They were answered as "not registered" (exit `1`),
  "no server listed" (exit `3`) or with IANA's TEST-NET record (exit
  `0`), depending on the range.
- **Breaking:** A free name in a gTLD whose registry has retired WHOIS
  (GMO Registry: `.shop`, `.tokyo`, ...) exits `1` (not registered)
  instead of `0`. The retirement notice read as a registered WHOIS
  answer, which outranked RDAP's "not found". A WHOIS server with no
  service for a name -- retired, TLD unsupported, or refusing every
  query (`.ch`) -- is now *unavailable* rather than failed, and is left
  out of the outcome; `-v` shows it as "unavailable" with the reason.
- **Breaking:** A free `.africa` name exits `1` instead of `0`; ZACR's
  "No information was found matching that query" matched no marker.

### Fixed
- Registrar URLs and abuse phone numbers that differ only in formatting
  -- `https://www.godaddy.com` vs `http://www.godaddy.com`, a trailing
  slash or missing scheme, `+1.4806242505` vs `480-624-2505` -- no
  longer raise a conflict. A different host or number still does.
- The Web.com-family registrar WHOIS rate limit ("IP Address Has Reached
  Rate Limit", register.com, domain.com) is recognised as a rate limit
  rather than an empty answer.
- AFRINIC IP and ASN lookups show the network or AS name. AFRINIC's RDAP
  puts the registrant organisation's handle (`ORG-AFNC1-AFRINIC`) in the
  name field, which outranked WHOIS's real name.
- RDAP works for registries that only offer RSA key exchange over TLS
  (`.cat`, `.eus`). plat retries once with those cipher suites after a
  TLS handshake failure -- only with its own default HTTP client, so a
  server that can do better never sees them and a library caller's
  client keeps its TLS policy.
- A registrar WHOIS referral that is a URL rather than a host (ZACR's
  `http://www.dns.net.za/whois`) is no longer dialled.
- RDAP abuse contacts are read where registries put them: nested inside
  the registrar entity (the gTLD RDAP profile) or, for ARIN, inside the
  registrant. plat read only top-level entities, so gTLD RDAP never
  supplied an abuse contact -- it came only from WHOIS, which registries
  are retiring. A `tel:` URI value is unwrapped to the bare number.

## [0.10.0] - 2026-09-27

Follow-ups from v0.9.0's ccTLD sweep: reserved names, WHOIS formats that
parsed to an empty record, and a v0.9.0 regression in `.bo`. Exit-code
changes are treated as breaking, as in v0.9.0, which is why this is a
minor release rather than a patch.

### Changed
- **Breaking:** A name the registry reports as reserved or restricted --
  `.ug`, `.dm`, `.bw` and `.qa` policy rejections, and registry-held
  names such as `nic.om`, `nic.ca`, `nic.nz`, `nic.cn`, `nic.hk` and
  `nic.kr` -- exits `3` with "the registry reports this name as reserved
  or restricted" instead of `0` as an empty registered record. It is not
  reported as "not registered" either, since the name cannot be
  registered. A name another source does have a record for (e.g.
  `nic.ke` via RDAP) still exits `0`.
- **Breaking:** A free `.il` name exits `1` (not registered) instead of
  `0`. ISOC-IL answers a name with no record with its terms of use and
  nothing else, which plat read as a registered domain.
- **Breaking:** `.bo` exit codes change back from v0.9.0's. A registered
  `.bo` domain exits `0` again instead of `3`, and a free one exits `1`
  instead of `3`. v0.9.0 mistook the footer on every `.bo` answer
  ("whois.nic.bo solo acepta consultas con dominios .bo") for a refusal,
  and `.bo` has no RDAP to fall back on. The footer now means "no
  record" only when it is the entire answer.
- **Breaking:** A rate-limited `.lu` lookup is a failed source (exit `3`
  when it is the only one) instead of an empty successful answer (exit
  `0`). `.lu`'s "Maximum query rate reached" matched no marker.

### Fixed
- WHOIS-only ccTLDs whose answers parsed to an empty record now show
  their domain, registrar, dates and nameservers: `.gg` and `.je`
  (indented sections), `.bo` (Spanish labels), `.lu` (`domainname`,
  `registrar-name`), and `.it`'s registrar, which shares an
  `Organization:` sub-key with the contact sections.
- WHOIS "Registrar Name" is read as the registrar, so `.il`, `.au`,
  `.ae` and `.cl` answers show one.

## [0.9.0] - 2026-09-27

Fixes from a live sweep of TLDs, RIRs and CLI paths: wrong data shown as
fact, lookups reported as succeeding when they had not, parsers that had
never worked on real registry output, and conflicts between sources that
agreed.

### Changed
- **Breaking:** plat requires **Go 1.26** or newer to build or to use as a
  library (previously 1.25). `golang.org/x/net`, `x/sync` and `x/term`
  dropped Go 1.25, which is past its support window now that Go 1.27 is
  current. Release binaries are unaffected.
- **Breaking:** An unregistered name in `.be` and about 40 other
  country-code TLDs exits `1` (not registered) instead of `0`. Their
  registries' not-found wordings -- DNS Belgium's "Status: AVAILABLE",
  CoCCA's "No Object Found", Tucows's "is available for registration",
  JWhoisServer's "NO OBJECT FOUND!" and a dozen one-offs -- matched no
  marker, so plat rendered a free name as a registered domain with no
  fields. Found by a sweep of every ccTLD; each new marker was checked
  against the sweep's registered answers and matched none.
- **Breaking:** A WHOIS server that refuses the query is a failed source.
  SWITCH (`.ch`, `.li`) refuses port-43 queries, and `plat nic.ch` exited
  `0` with an empty record; it now exits `3` and says why under `-v`.
  `.gq`'s "This TLD has no whois server" and `.bo`'s query refusal are
  treated the same way.
- **Breaking:** Reserved ASNs -- `AS0`, `AS23456`, documentation,
  private-use and IANA-reserved ranges -- exit `2` with the reason, and
  `plat.Client.Lookup` returns `ErrInvalidInput`, instead of exit `3`
  claiming no sources could be reached. An `AS` number beyond 32 bits is
  reported as out of range rather than as an invalid single-label domain.
- **Breaking:** A domain's RDAP status `active` is reported as `ok`, its
  EPP equivalent (RFC 8056), so it no longer appears alongside WHOIS's
  `ok` as a second status. Scripts matching `"active"` in `status.value`
  need updating.

### Fixed
- `.uk` domains get WHOIS data again. IANA's record for `.uk` has listed
  no WHOIS server since 2026-08-04, so plat queried RDAP alone and one
  slow RDAP response failed the whole lookup with exit `3`. plat now falls
  back to `whois.nic.uk` when IANA names no server, and never overrides
  one IANA does name. Nominet has announced that this service ends on
  9 February 2027; after that the fallback fails like any unreachable
  source.
- `.uk` WHOIS responses are parsed. Real Nominet output indents every
  line, headers included, and the parser recognized a header only at
  column zero -- so it had never extracted a field from a live `.uk`
  response. Its test fixture had been written in the shape the parser
  expected rather than recorded, and is replaced by real recordings.
  Nominet's `[Tag = X]` registrar suffix and its "No registrar listed"
  sentence no longer produce false registrar conflicts.
- RIPE-region IP and ASN lookups report the owning organization rather
  than a maintainer. RIPE gives its `mnt-by` maintainers the registrant
  role too, so `80.128.0.1` showed "DTAG-NIC" instead of Deutsche Telekom
  AG, and the wrong value won the merge.
- WHOIS responses that list contact, nsset or keyset objects after the
  domain keep the domain's own registrar and dates. `seznam.cz` reported
  the registry's own contact as its registrar, and `google.it` its tech
  contact's creation date. `.cz` and `.br` creation and update dates now
  parse, as does registro.br's `#ticket` date suffix.
- `.mx` no longer shows a contact's state as the domain status
  ("nuevoLeon"), and its nameservers are read.
- An RDAP abuse phone is the contact's voice number. The last `tel` in
  the vCard used to win, so `AS3333` reported RIPE's fax number.
- GDPR redaction is reported for domain and IP lookups. A redacted
  source was dropped before the merge checked for redaction, so no
  notice ever appeared.
- ARIN IP lookups inside nested networks -- most ISP space -- get a WHOIS
  record. A bare query returned only a summary, which counted as an
  empty success. plat now asks ARIN for full records and keeps the most
  specific network, matching RDAP; ARIN's "Reassigned" and RDAP's
  "ASSIGNMENT" no longer conflict.
- `.nl`, `.be`, `.it`, `.cn` and `.at` WHOIS yield the registrars,
  nameservers and dates their responses carry.
- A nameserver spelled in Unicode by one source and punycode by another
  counts once, with no conflict.
- A registry that names itself as the registrar WHOIS server (`.au`,
  `nic.xyz`, `nic.co`) is not queried twice and counted as a second
  source.
- A date-only WHOIS value no longer conflicts with an RDAP timestamp from
  the same local day (`google.com.br`).
- "Error: ratelimit exceeded" is recognised as a rate limit rather than
  an empty successful answer.
- A WHOIS failure on an IP or ASN lookup reports why. A timeout or
  refused connection at the RIR showed as `no data` under `-v`, with no
  `error` in `-o json`; domain lookups already reported the reason.
- A name with no RDAP service or WHOIS server listed anywhere (e.g.
  `.gr`) now says so, instead of "no sources could be reached" -- nothing
  had been queried, so nothing had failed to answer. When `--source`
  excluded the only source a name has, the message points at the filter.
- An RDAP 429 whose `Retry-After` outlasts the timeout is reported as a
  rate limit at once, rather than waiting out the budget and reporting a
  timeout.
- `--diff` accepts its own snapshot for an IDN domain; it compared the
  snapshot's Unicode name against the punycode query and exited `2`.
- `--no-color` removes colour with an explicit `-o human`, as `NO_COLOR`
  does.
- A failed name in a human/plain bulk run no longer leaves a stray blank
  line on stdout.

## [0.8.0] - 2026-08-28

### Added
- The data model is now a public package, `github.com/patramsey/plat/model`.
  `plat.Record` and its siblings remain aliases, so existing code compiles
  unchanged, but their fields -- previously hidden in `internal/` -- are now
  documented and visible via `go doc github.com/patramsey/plat/model.Record`.

### Changed
- **Breaking:** A cancelled or expired context now returns the context's own
  error from `Lookup`, not `ErrLookupFailed`. `errors.Is(err,
  context.Canceled)` and `errors.Is(err, context.DeadlineExceeded)` now
  report true, and `errors.Is(err, ErrLookupFailed)` is correspondingly
  false for these cases. Code retrying on `ErrLookupFailed` no longer
  retries a cancellation.
- **Breaking:** `New` now returns an error for an unknown `SourceID` in
  `Options.Sources`, naming the offending value. It previously accepted any
  string, then `Lookup` consulted zero sources and reported a generic
  lookup failure -- a typo in the caller's config surfaced as an
  infrastructure error instead of a config error.

## [0.7.0] - 2026-08-25

### Added
- `--help` now explains what plat does, decodes the `RR`/`GR`/`RW`/`GW`
  source tags that appear in its own output, and shows runnable examples.

### Changed
- **Breaking:** A name containing an empty label -- `a..com`, `xn--.com`,
  `.com` -- now exits `2` (usage error) instead of `1` (not found), and
  `plat.Client.Lookup` returns `ErrInvalidInput` for the same inputs
  instead of a nil error wrapping a not-found `Result`. Exit `1` claimed
  every source agreed the name did not exist, about a name plat never
  actually looked up. `xn--.com` was the clearest case:
  `idna.Lookup.ToASCII("xn--.com")` returns `.com` with a nil error, so
  plat queried `.com` -- a different name than the one it was given --
  got a not-found answer for it, and reported that as the result for
  `xn--.com`. Scripts and library callers keying on the old behavior for
  these inputs need updating.

### Fixed
- The source legend now lists only the tags a record actually carries.
  A `.de` domain answered by registry WHOIS alone no longer gets a key
  explaining three sources that appear nowhere in its output. Both the
  human and plain renderers.
- `-v` now names the sources `--source` and `--no-follow` excluded,
  instead of silently omitting them from a block documented as showing
  every source attempted. A flag is only named when it genuinely
  excluded something -- `--no-follow` gates just the registrar RDAP
  hop, so it's not listed for an IP or ASN lookup, which has no
  registrar to begin with.
- `-o plain` caps its value column to the terminal width. Previously one
  long `Status` value padded every row past 80 columns, and the
  terminal's own wrap orphaned the source tags onto their own line.
  Values wrap at whitespace, so a long registrar name wraps while an
  unbreakable token like a URL stays intact on one line and may still
  exceed the width. Piped output is unchanged -- wrapping only applies
  when stdout is a terminal, so `grep` and `awk` still see whole
  nameserver lists.
- `-q` no longer double-spaces its one-line summaries in multi-name runs.
- A conflict-carrying record's box no longer overflows a narrow
  terminal. `writeConflictsHint` was the only writer inside the box not
  given the requested width, so its 51-rune hint string -- plus 4
  columns of border and padding -- pinned the box at 55 display columns
  regardless of how narrow it was asked to be; a record with no conflict
  tracked the requested width correctly.

## [0.6.0] - 2026-08-23

### Fixed
- Nameservers no longer carry glue addresses. `.de`, `.cz`, `.pl`, `.ru`,
  `.lt`, and `.eu` each append the nameserver's IP address onto the same
  WHOIS line, in a different dialect per registry (space-separated,
  parenthesised, bracketed). plat stored the whole line as the hostname,
  so `nic.cz` showed three nameservers as six, invented a `nameservers`
  conflict between sources that actually agreed, and left the field
  with no provenance at all -- plat reporting its own parsing gap as a
  disagreement in the data, on the exact signal this tool exists to
  provide. Indent-format registries separately dropped a nameserver
  outright when its glue was IPv6-only (`ns1.example.eu
  (2a05:d018::1)`): the line tokenizer split on the first colon, which
  sits inside the address, so the whole line fell into `Unmapped` under
  a garbage key instead of `Nameservers`. `.lt` had lost its
  nameservers entirely to a missing `Nameserver:` (singular) synonym.
  Glue is stripped correctly for every dialect listed, `.pl` included --
  but `.pl` also splits its nameserver list across continuation lines
  that plat's generic key/value tokenizer does not yet follow, so `.pl`
  lookups still return only the first of typically four nameservers;
  fixing that tokenizer gap is tracked as a follow-up, not shipped here.
- EPP statuses are now matched case-insensitively. A registrar whose
  WHOIS output lowercases them -- Cloudflare's does -- had every
  restriction listed twice, once per casing, read by plat as two
  different statuses rather than one spelled two ways.
- A ccTLD status written as an English phrase, not an EPP token, is
  kept whole instead of being truncated to its first word. CZ.NIC's
  `Sponsoring registrar change forbidden` had been shortened to
  `sponsoring`.
- IDN domains no longer report a conflict with themselves. RDAP
  publishes the Unicode form (`bücher.com`) and WHOIS publishes the
  A-label (`xn--bcher-kva.com`) for the same domain; plat now folds
  both to punycode before comparing values, so all four sources are
  credited and the displayed spelling is unchanged. This was the same
  failure as the nameserver conflicts above: two true spellings of one
  fact, read as a disagreement.
- `.eu` returns its nameservers; its WHOIS format had been misread as
  the generic `kv` dialect and now routes to Nominet's indent
  tokenizer, which its section-header layout actually matches. Note
  honestly: EURid publishes no status and no dates at all for any
  `.eu` domain -- those fields stay empty because the registry does
  not emit them, not because plat fails to parse them.
- Third-level `.jp` records (`.ad.jp`, `.co.jp`) now return domain,
  status, and nameservers. JPRS prefixes third-level lines with a
  lettered ordinal the bracket tokenizer couldn't match. Second-level
  `.jp` (`example.jp`) was never affected.
- Three more date formats parse instead of falling back unparsed:
  ISO-8601 with a basic (non-colon) UTC offset, as `.io` emits it;
  JPRS's `(JST)`-suffixed timestamps; and `.kr`'s dotted `1996. 07.
  20.` form.
- `--diff` accepts IP snapshots from RIPE, APNIC, and AFRINIC. Their
  WHOIS records carry neither a CIDR nor a handle, which the diff
  matcher needed to identify a snapshot's record; those comparisons
  previously failed with `--diff snapshot is for , but the query is
  ...` and exited 2 instead of reporting what changed.

## [0.5.0] - 2026-08-20

### Added
- `EncodeJSON` and `EncodeNDJSON` produce the plat CLI's exact
  `schemaVersion: 1` JSON from a `Result` -- byte-identical to `-o json`
  for the same lookup, with `EncodeOptions{Raw}` to include embedded
  source payloads. `EncodeNDJSON` writes the same document as a single
  newline-delimited record; for one `Result` it emits the same bytes as
  `EncodeJSON`. NDJSON's value is streaming many `Result`s into one
  stream, mirroring the CLI's `-o ndjson` across multiple names -- not
  a different encoding of a single record. The schema version is
  exposed as the `SchemaVersion` constant.
- `Options.HTTPClient` now also covers the IANA bootstrap fetch that
  `New` performs, not just RDAP queries. Previously, a caller who set
  `HTTPClient` to route requests through a proxy still had `New` reach
  `data.iana.org` directly; a hung or blocked direct request fell back
  silently to the bootstrap snapshot embedded in the binary.

### Changed
- **Breaking:** `NewIPResolver` and `NewASNResolver` are removed.
  `NewResolver` now takes a single `ResolverConfig{Domains, Prefixes,
  ASNs}`, each field optional, in place of one constructor per object
  kind: `NewResolver(m)` becomes
  `NewResolver(ResolverConfig{Domains: m})`. The previous per-kind
  constructors made it easy to point plat at a private RDAP deployment
  for domains and, without noticing, lose RDAP coverage for every IP
  and ASN lookup -- a `Resolver` built from `NewResolver` alone reports
  no coverage for those kinds, so lookups of them fall back to
  WHOIS-only, silently. Nothing in this repo's CI catches a break like
  this automatically, so a consumer finds out at their own `go build`.
  The API remains v0 and may still change before 1.0.

### Fixed
- Human output is coloured again. Since v0.4.0 every `plat <name>` lookup
  rendered monochrome in a terminal: bulk mode buffers each name's output
  so results can be flushed in input order, and the renderer decides how
  much colour to emit from the writer in front of it -- which is what
  keeps piped output clean. A buffer is not a terminal, so every escape
  was stripped, and the stripped bytes were then copied to a terminal that
  did want colour. Correct behaviour, applied to the wrong writer. The
  buffers now carry the real stdout's colour profile, so the renderer
  downsamples to what the terminal actually supports instead of to the
  buffer. Bulk (`--file`, multiple names) is coloured too, which it never
  was. Piped output, `NO_COLOR`, `--no-color`, and every machine format
  are unchanged, and `plat` still emits zero ANSI in all of them.

## [0.4.0] - 2026-08-19

### Added
- `--file <path>` reads names from a file, one per line, with blank lines
  and `#` comments skipped; `--file -` reads stdin. `--concurrency N`
  (default 4) controls how many names are looked up in parallel, and
  applies to names given on the command line too. Results are emitted in
  input order regardless of which lookups finish first, so two runs of the
  same list produce identical output. WHOIS queries are paced per server
  -- including referral hops to registrar servers -- so a large single-TLD
  list cannot hammer one server; the pace is a fixed conservative interval
  that no CLI flag changes (the Go library added below can tune it).
  `--timeout` bounds the time a lookup spends
  talking to servers, so a name waiting its turn for a paced server is
  never timed out before it gets to ask -- pacing costs wall time, never
  a source. A single name is unaffected: no pacing, no pool, no progress
  output.
- `--diff <snapshot.json>` compares a fresh lookup against a previously
  saved `-o json` snapshot and reports what changed -- expiry,
  nameservers, status, and every other merged field. Exits 4 when
  anything changed, 0 when nothing did; exit codes 1, 2, and 3 keep
  their existing meanings. Works for domains, IPs, and ASNs. Compares
  values only: source provenance and conflicts are ignored, so a source
  simply dropping out of one run does not by itself register as a
  change. It can still surface one if the remaining sources disagree on
  a field's precision, or if the dropped source was the only one
  supplying a field -- e.g. an ASN lookup losing registry-rdap falls
  back to registry-whois's date-only `Registered`/`Updated` timestamps
  (`2000-03-30T05:00:00Z` -> `2000-03-30T00:00:00Z`) and loses `Status`
  entirely, since only RDAP supplies it; both are real differences
  between the two merged records, not noise.
  Snapshots saved before v0.3.1 (whose nameserver and status lists were
  unsorted) compare correctly, since lists are compared as sets.
- The lookup engine is now importable as a Go library, at
  `github.com/patramsey/plat` (`go get github.com/patramsey/plat`), with
  no need to shell out to the `plat` binary. `plat.New` builds a
  `Client`; `Client.Lookup` runs one domain, IP, or ASN lookup and
  returns a merged, provenance-annotated record. A `Client` should be
  built once and reused across lookups -- it holds the IANA bootstrap
  data and a per-server WHOIS pacing limiter, and constructing a fresh
  one per name throws both away. Per-field provenance, the CLI's core
  idea, comes through unchanged: every field is a `Field[T]` carrying
  its merged value and the sources that supplied it. A failing source
  is not an error -- `Lookup` returns successfully as long as one
  source answers, with per-source detail in the record's `Sources`
  field. The record types (`Record`, `IPRecord`, `ASNRecord`, and their
  component types) are aliases to internal types, so `internal/` stays
  private and free to change underneath the public API. The JSON,
  human, and plain renderers are not exposed by this package, so a
  library consumer cannot currently produce plat's documented
  `schemaVersion: 1` output from a `Result` -- that remains CLI-only.
  Per-server WHOIS pacing is on by default and is tunable here, unlike
  from the CLI: `Options.WHOISInterval` sets the interval and
  `Options.DisableWHOISPacing` turns it off. Pacing is not free for
  every single lookup -- when one lookup's referral chain queries the
  same WHOIS host twice, which happens when a registry refers the
  registrar query back to that host, the second query waits the full
  interval. That is why the option exists, and why plat's own CLI
  disables pacing for single-name runs, leaving single lookups exactly
  as fast as before. This API is v0 and may change before 1.0.

### Changed
- Internal maintenance: the RDAP fetch path and two merge helpers each
  existed as separate near-identical copies per object type -- three
  copies of the fetch-and-parse core, three of the source-record filter,
  and two of the status union. Each is now a single generic. No behavior
  change: output for a domain, an IP, and an ASN is byte-identical to the
  previous build across `-o json`. Domain status merging deliberately
  keeps its own EPP-specific step and is not shared with IP/ASN status,
  since RIR status strings use no `client`/`server` prefix convention;
  a test pins that asymmetry in both directions.

## [0.3.2] - 2026-08-12

### Fixed
- IP and ASN lookups no longer advertise source codes that cannot apply
  to them. Both renderers printed the same fixed four-source legend
  (`RR registrar-rdap  GR registry-rdap  RW registrar-whois  GW
  registry-whois`) for every object type, but an IP allocation or an
  autonomous system is registered directly with an RIR and has no
  registrar at all -- so `RR`/`RW` explained badges that could never
  appear, reading as "plat failed to reach the registrar" rather than
  "no such source exists". IP and ASN records now show only
  `GR registry-rdap  GW registry-whois`. Domain output is unchanged, and
  all four codes remain correct there. Affects the human and plain
  renderers; JSON/NDJSON carry full source names and were never
  affected.

## [0.3.1] - 2026-08-12

### Fixed
- LACNIC-held IP lookups (`plat 200.3.12.1`, etc.) no longer silently
  drop registry-WHOIS data. `internal/whois/parse/ip.go` was missing
  LACNIC's RPSL vocabulary for org name (`owner`), org ID (`ownerid`),
  and last-modified (`changed`) -- the identical gap already fixed for
  ASN lookups in `internal/whois/parse/asn.go`, but never ported to the
  IP parser. Organization and Updated now correctly show both
  `registry-rdap` and `registry-whois` provenance instead of appearing
  RDAP-only with no conflict to reveal the missing source.
- `-o json` and `-o ndjson` are now byte-reproducible across runs. The
  `nameservers` and `status` arrays are sorted, so repeated lookups of an
  unchanged domain, IP, or ASN produce identical output. Previously the
  order tracked whatever the highest-precedence source returned, and at
  least one registrar's RDAP server returns nameservers in a different
  order on every request -- so diffing two runs, or hashing the output,
  saw spurious changes. Values and source attribution are unaffected;
  only ordering changed, so `schemaVersion` stays 1.

### Changed
- Internal maintenance: `internal/whois/parse`'s IP and ASN WHOIS parsers
  shared the same vocabulary (org name, org ID, country, dates, abuse
  contacts) in two separately maintained lookup tables that had already
  drifted out of sync twice -- once for `status`, once for LACNIC's
  `owner`/`ownerid`/`changed` keys (see above). The shared vocabulary is
  now declared once (`commonFields`) and lifted into both parsers' tables,
  and `TestCommonVocabularyReachesBothParsers` fails if a future shared
  key is ever added for only one of them. No behavior change: outputs for
  `example.com`, `8.8.8.8`, `193.0.6.139`, `200.3.12.1`, `AS15169`,
  `AS3333`, and `AS28573` are byte-identical to the pre-refactor build.
  One latent difference: `ParseASN` now also recognizes `ownerid` (the
  pre-refactor `asnSynonyms` lacked it, unlike its IP counterpart). No
  ASN golden response carries that key today, so nothing observable
  changes; it's noted here because a future LACNIC ASN response that
  does carry it will now be parsed correctly instead of silently
  dropped.

## [0.3.0] - 2026-08-11

### Added
- ASN lookups. `plat AS15169` (the `AS` prefix is required) now finds the
  RIR holding the autonomous system and queries its RDAP and WHOIS,
  merging the result with the same per-field provenance as a domain or IP
  lookup. There's no registrar leg -- only `registry-rdap`/
  `registry-whois` ever appear as sources -- and the record's fields are
  an autonomous system's own (handle, AS name, start/end autnum range,
  holding organization) rather than a domain's or netblock's. `-o json`
  sets `"objectType": "asn"` to distinguish the shape from a domain or IP
  record's, an additive change that leaves `schemaVersion` at 1 and
  existing output otherwise unchanged. A bare number (`plat 15169`) is
  not treated as an ASN lookup, since it's likelier a typo'd domain.

## [0.2.0] - 2026-08-10

### Added
- IP-address lookups. `plat 8.8.8.8` (or any IPv4/IPv6 address) now
  finds the RIR holding the containing netblock and queries its RDAP
  and WHOIS, merging the result with the same per-field provenance as
  a domain lookup. There's no registrar leg -- only `registry-rdap`/
  `registry-whois` ever appear as sources -- and the record's fields are
  a netblock's own (handle, CIDR, start/end address, parent handle,
  holding organization) rather than a domain's. `-o json` sets
  `"objectType": "ip"` to distinguish the shape from a domain record's
  `"objectType": "domain"`, an additive change that leaves
  `schemaVersion` at 1 and domain output otherwise unchanged.
  Reserved/private addresses (`10.0.0.1`, `127.0.0.1`, `::1`, ...) exit
  2 with a friendly error, since no RIR allocates them to an
  organization.

### Removed
- The hidden `plat whois` and `plat merge` debug subcommands, dev-only
  scaffolding used to prove the WHOIS engine and merge engine end to end
  before `--source`/`-o` existed. Both were `Hidden: true` (never in
  `--help`) and strictly inferior to `--source whois -o plain -v`, which
  supersedes them with full parsed output and provenance. No documented
  interface changes. See #45.

### Fixed
- Lifecycle stage text misattributed two of its three timeline durations
  to ICANN policy. Only the 30-day Redemption Grace Period is actually
  ICANN-mandated (Expired Registration Recovery Policy §3.1); the 45-day
  Auto-Renew Grace and 5-day Pending Delete figures are common registry
  conventions. The Auto-Renew Grace description now also states plainly
  that ICANN leaves the timing of that stage entirely to the registrar's
  discretion.

## [0.1.4] - 2026-08-04

### Added
- Lifecycle interpretation for expired gTLD domains: a plain-language
  explanation of where a domain sits in ICANN's Expired Domain Deletion
  Policy timeline (Auto-Renew Grace / Redemption Grace / Pending Restore
  / Pending Delete), with a clearly-labeled, estimated end date where one
  can be computed. Shown in JSON (`lifecycle`), the human view, and the
  plain view. Not shown for ccTLDs or internationalized (IDN) TLDs, which
  set or can't be reliably classified against ICANN's gTLD policy.

### Fixed
- Some registrar RDAP servers (e.g. GoDaddy's) report a bare, ambiguous
  status alongside the properly client/server-prefixed EPP status for the
  same restriction (e.g. both `transferProhibited` and
  `clientTransferProhibited`) — `status` now drops the redundant bare
  form when a prefixed variant is already present.

## [0.1.3] - 2026-08-02

### Changed
- Release archive filenames no longer include the version number (e.g.
  `plat_darwin_arm64.tar.gz` instead of `plat_0.1.2_darwin_arm64.tar.gz`),
  so the Releases page's "latest" download links stay valid across
  releases.

## [0.1.2] - 2026-08-02

### Added
- `--no-color` flag, equivalent to the existing `NO_COLOR` environment
  variable.
- `-q`/`--quiet` flag: a one-line summary per domain (lock status,
  expiry, conflict count) instead of the full view. Ignored for `-o
  json`/`-o ndjson`.

### Fixed
- `.eu` domains: the registrar name wasn't parsed out of EURid's nested
  WHOIS structure (`Registrar:` header with the name on an indented
  `Name:` line beneath it).

## [0.1.1] - 2026-08-01

### Fixed
- `plat version` (and the release binaries generally) embedded the full
  40-character git commit SHA instead of the short form.
- The Homebrew tap push now uses its own cross-repo token — the default
  Actions token can't push to a separate repository.
- The Homebrew formula now publishes into the tap's `Formula/` directory
  instead of the repo root, where `brew` couldn't find it.

### Added
- `--version` flag on the root command, equivalent to `plat version`.
- `plat version -o json` for machine-readable version output.
- `plat version --full` to include the Go compiler version and target
  platform.

## [0.1.0] - 2026-08-01

Initial public release.

### Added
- Domain lookup via RDAP and WHOIS, queried concurrently from both
  registry and registrar, merged into one record with per-field source
  provenance.
- Styled human terminal view, plain-text output, and a versioned
  JSON/NDJSON schema.
- GDPR-aware redaction handling and explicit conflict detection.
- `goreleaser`-based release pipeline: binaries, checksums, and a
  Homebrew tap.
- Man pages and shell completions generated at build time.

[Unreleased]: https://github.com/patramsey/plat/compare/v0.11.0...HEAD
[0.11.0]: https://github.com/patramsey/plat/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/patramsey/plat/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/patramsey/plat/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/patramsey/plat/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/patramsey/plat/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/patramsey/plat/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/patramsey/plat/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/patramsey/plat/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/patramsey/plat/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/patramsey/plat/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/patramsey/plat/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/patramsey/plat/compare/v0.1.4...v0.2.0
[0.1.4]: https://github.com/patramsey/plat/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/patramsey/plat/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/patramsey/plat/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/patramsey/plat/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/patramsey/plat/releases/tag/v0.1.0

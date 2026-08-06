# plat JSON output schema

`plat <domain> -o json` and `plat <domain> -o ndjson` emit the unified
domain record as JSON; `plat <ip>` does the same for an IP network lookup.
This schema is a public API: a breaking change to any field's shape bumps
`schemaVersion`. The current version is **1**.

## Top-level shape

```json
{
  "schemaVersion": 1,
  "objectType": "domain",
  "domain": { "value": "example.com", "sources": ["registry-rdap"] },
  "handle": { "value": "2336799_DOMAIN_COM-VRSN", "sources": ["registry-rdap"] },
  "registrar": {
    "name": { "value": "Example Registrar, Inc.", "sources": ["registrar-rdap"] },
    "abuseEmail": { "value": "abuse@example-registrar.example", "sources": ["registrar-rdap"] }
  },
  "status": { "value": ["clientTransferProhibited"], "sources": ["registry-rdap"] },
  "created": { "value": "1995-08-14T04:00:00Z", "raw": "1995-08-14T04:00:00Z", "parsed": true, "sources": ["registry-rdap"] },
  "expires": { "value": "2026-08-13T04:00:00Z", "raw": "2026-08-13T04:00:00Z", "parsed": true, "sources": ["registry-rdap"] },
  "nameservers": { "value": ["a.iana-servers.net", "b.iana-servers.net"], "sources": ["registry-rdap"] },
  "conflicts": [],
  "redacted": [],
  "sources": [
    { "source": "registry-rdap", "ok": true, "notFound": false, "latencyMs": 89 },
    { "source": "registrar-rdap", "ok": true, "notFound": false, "latencyMs": 145 }
  ]
}
```

`objectType` is `"domain" | "ip"` — always present, immediately after
`schemaVersion`. It's the discriminator telling consumers which field set
to expect in the rest of the record: a `"domain"` record follows the
domain shape below (`registrar`, `nameservers`, `expires`, `dnssec`,
`lifecycle`, ...); an `"ip"` record follows the [IP records](#ip-records)
shape instead (`startAddress`/`endAddress`, `cidr`, `org`, ...). Adding
`objectType` was a purely additive change — `schemaVersion` stayed **1**.

## Field shapes

Every optional field (`domain`, `handle`, `registrar.*`, `status`,
`created`, `updated`, `expires`, `nameservers`, `dnssec`, `lifecycle`) is
**omitted entirely** from the output when no source contributed a value, or
— for `lifecycle`, a field plat derives rather than any source reporting
directly — when it isn't computable or doesn't apply. Never `null`, never
an empty object, simply absent. `jq '.expires.value'` on a record with no
expires data returns `null` (jq's normal behavior for a missing path), so
pipelines don't need to special-case absence.

- **String field** (`domain`, `handle`, `registrar.name`, `registrar.ianaId`, `registrar.url`, `registrar.abuseEmail`, `registrar.abusePhone`):
  ```json
  { "value": "<string>", "sources": ["<source-id>", ...] }
  ```
- **List field** (`status`, `nameservers`):
  ```json
  { "value": ["<string>", ...], "sources": ["<source-id>", ...] }
  ```
- **Bool field** (`dnssec`):
  ```json
  { "value": true, "sources": ["<source-id>", ...] }
  ```
- **Time field** (`created`, `updated`, `expires`):
  ```json
  { "value": "<RFC3339 string or null>", "raw": "<original string>", "parsed": true, "sources": [...] }
  ```
  `value` is `null` when the source's date string couldn't be parsed — `raw`/`parsed` always reflect the underlying source data so nothing is silently dropped. `created`/`updated` keep the highest-precedence source's value even when sources disagree (see `conflicts[]`). `expires` is the one exception: on a genuine conflict, `value` is the *earliest* disputed date rather than the highest-precedence one — showing more runway than actually exists is the riskier failure mode for an expiration date, so a conflicted `expires` conservatively assumes the sooner date. `sources` always reflects whichever sources actually agree with the returned `value`, not merely every source that reported something.
- **`registrar`** is an object of up to 5 string fields (`name`, `ianaId`, `url`, `abuseEmail`, `abusePhone`), each following the string-field shape above and each independently omittable. The whole `registrar` key is omitted only if every one of its sub-fields is absent.
- **`lifecycle`** — plat's own interpretation of where an expired gTLD domain sits in ICANN's Expired Registration Recovery Policy (ERRP) timeline, derived from `status`/`updated`/`expires` rather than reported directly by any source. Omitted for ccTLDs (which set independent policies this schema doesn't model), for all internationalized (IDN) TLDs in either Unicode or punycode form (since ccTLD/gTLD type can't be reliably distinguished without a TLD list), and for domains with no recognized lifecycle-relevant status:
  ```json
  {
    "stage": "redemptionGrace",
    "label": "Redemption Grace Period",
    "description": "This domain has expired and is no longer eligible for normal renewal. The registrant can still recover it by asking the registrar for a restore, typically for an added fee. If it isn't restored, the domain moves to Pending Delete and is later released for new registration.",
    "estimatedEndsBy": "2026-09-02T00:00:00Z",
    "estimateBasis": "Estimate based on ICANN's fixed 30-day Redemption Grace Period policy for gTLDs, calculated from this record's last-updated time. Actual timing is set by the registry/registrar and may be earlier."
  }
  ```
  `stage` is one of `autoRenewGrace`, `redemptionGrace`, `pendingRestore`, `pendingDelete`. `estimatedEndsBy`/`estimateBasis` are omitted together when no estimate could be computed (missing/unparsed anchor timestamp, or `pendingRestore`, which has no fixed or conventional duration to estimate from) — `estimatedEndsBy` is always explicitly an *estimate*, never a confirmed date; `estimateBasis` always states which policy or convention and anchor it was derived from, and whether that duration is ICANN-mandated (only Redemption Grace's 30 days actually is) or a common registry convention (Auto-Renew Grace's 45 days, Pending Delete's 5 days).
- **`conflicts[]`** — one entry per field where present sources disagreed:
  ```json
  { "field": "expires", "values": { "registry-rdap": "2026-08-13T04:00:00Z", "registry-whois": "2026-08-10" } }
  ```
  Always fully populated regardless of the CLI's `--conflicts` flag, which only affects whether the human/plain renderers print this detail inline — it has no effect on machine output.
- **`redacted[]`** — one entry per field where a higher-precedence source's value was withheld:
  ```json
  { "field": "registrar.name", "source": "registrar-rdap", "reason": "redacted" }
  ```
- **`sources[]`** — one entry per source actually attempted, always present (an empty array if literally nothing was attempted):
  ```json
  { "source": "registry-rdap", "ok": true, "notFound": false, "latencyMs": 89, "error": "timeout" }
  ```
  `error` is omitted when empty. `source` is one of `registry-rdap`, `registrar-rdap`, `registry-whois`, `registrar-whois` — these full names are what every `sources` array uses throughout this schema, in JSON/NDJSON, always. The human/plain terminal views abbreviate them to 2-letter codes (`GR`/`RR`/`GW`/`RW`) purely for display, with a legend printed once per lookup; that abbreviation is a rendering choice, not part of this schema.

## IP records

`plat <ip-or-cidr>` emits an IP network record instead of a domain record
— same envelope, `"objectType": "ip"`, a disjoint field set. An IP
allocation is queried from the registry only (RDAP and WHOIS at the RIR
that holds the block); there is no registrar leg, so `sources[]` only ever
contains `registry-rdap`/`registry-whois` entries. `registrar`, `expires`,
`nameservers`, `dnssec`, and `lifecycle` never appear on an IP record —
those are domain-only concepts (a netblock has no registrar, no
expiration, no nameservers, no DNSSEC, and no ICANN expired-domain
lifecycle to interpret).

```json
{
  "schemaVersion": 1,
  "objectType": "ip",
  "handle": { "value": "NET-8-8-8-0-2", "sources": ["registry-rdap"] },
  "name": { "value": "GOGL", "sources": ["registry-rdap"] },
  "startAddress": { "value": "8.8.8.0", "sources": ["registry-rdap"] },
  "endAddress": { "value": "8.8.8.255", "sources": ["registry-rdap"] },
  "cidr": { "value": "8.8.8.0/24", "sources": ["registry-rdap"] },
  "ipVersion": { "value": "v4", "sources": ["registry-rdap"] },
  "country": { "value": "US", "sources": ["registry-whois"] },
  "org": {
    "name": { "value": "Google LLC", "sources": ["registry-whois"] }
  },
  "status": { "value": ["active"], "sources": ["registry-rdap"] },
  "registered": { "value": "2023-12-28T22:24:33Z", "raw": "2023-12-28T17:24:33-05:00", "parsed": true, "sources": ["registry-rdap"] },
  "conflicts": [],
  "redacted": [],
  "sources": [
    { "source": "registry-rdap", "ok": true, "notFound": false, "latencyMs": 120 }
  ]
}
```

- **String fields** (`handle`, `name`, `startAddress`, `endAddress`, `cidr`, `ipVersion`, `parentHandle`, `country`, `org.name`, `org.id`, `org.abuseEmail`, `org.abusePhone`): same string-field shape as the domain schema. `startAddress`/`endAddress` are the netblock's first/last address, each independently omittable — the human/plain renderers combine them into a single `start - end` row, but the JSON schema keeps them as two separate fields.
- **List field** (`status`): same list-field shape as the domain schema — EPP-normalized where a status vocabulary applies, otherwise the source's own status strings.
- **Time fields** (`registered`, `updated`): same time-field shape as the domain schema (`value`/`raw`/`parsed`/`sources`). There is no `expires` — IP allocations don't expire the way domain registrations do.
- **`org`** is an object of up to 4 string fields (`name`, `id`, `abuseEmail`, `abusePhone`), each following the string-field shape above and each independently omittable — the IP-record analog of `registrar`. The whole `org` key is omitted only if every one of its sub-fields is absent.
- **`conflicts[]`**, **`redacted[]`**, **`sources[]`** — identical shapes and semantics to the domain schema above, just scoped to IP field names (e.g. `{"field": "org.name", ...}`) and, for `sources[]`, restricted to `registry-rdap`/`registry-whois` since there's no registrar leg to query.

## `--raw`

Adding `--raw` includes each source's raw response payload as `sources[].raw`:

```json
{ "source": "registry-rdap", "ok": true, "raw": { "objectClassName": "domain", "ldhName": "EXAMPLE.COM", ... } }
```

For RDAP sources, `raw` is the actual response JSON embedded as-is (a JSON
object, not a string). For WHOIS sources, `raw` is the plaintext response
encoded as a JSON string, since WHOIS has no native JSON structure:

```json
{ "source": "registry-whois", "ok": true, "raw": "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar\n..." }
```

Without `--raw`, the `raw` key is omitted entirely from every source entry.

## NDJSON (`-o ndjson`)

For multiple domain arguments, each domain's record is written as one
compact JSON object per line (no pretty-printing, no blank lines between
records) — standard [NDJSON](http://ndjson.org/). `-o json` (the
single-object form) only accepts exactly one domain argument; use
`-o ndjson` for multiple.

## Errors in machine mode

If a domain can't be looked up at all (bad input, or no source returned
usable data), the error goes to **stderr**, not stdout, as:

```json
{ "error": "is not registered (checked: registry-rdap)", "domain": "example-nonexistent-xyz.com" }
```

The message text itself isn't part of the stability guarantee below — only
the `{error, domain}` shape is. A confirmed-unregistered domain (every
attempted source agrees it doesn't exist) reads as "is not registered"; a
genuine lookup failure (sources errored, so non-existence can't be
confirmed) reads as "lookup inconclusive" or "lookup failed" instead.

stdout only ever contains successfully-rendered records in machine mode —
scripts consuming stdout never need to distinguish a partial/error object
from a real record.

## Stability policy

This schema is versioned via the top-level `schemaVersion` field (currently
`1`). Any backward-incompatible change — a field renamed, removed, or its
type changed — bumps `schemaVersion`. Purely additive changes (a new
optional field) do not require a version bump.

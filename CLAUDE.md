# tldextract

Go library (`github.com/DNSFilter/tldextract`, forked from `joeguo/tldextract`) that
extracts the eTLD (gTLD/ccTLD/public suffix), registered root domain, and subdomain
from a URL/FQDN, based on the Public Suffix List (PSL).

## Layout

- `tldextract.go` — all core logic (see below).
- `tldextract_test.go` — table-driven tests, run against a live-downloaded PSL cache
  at `/tmp/tld.cache` (see `init()`). Covers V1 vs V2 behavioral differences side by
  side, plus `TestIsValidSuffix`.
- `cmd/main.go` — tiny CLI: `go run ./cmd <fqdn>`, prints the V1 `Extract` result.
- `doc.go` — package doc comment/example (still references the old `joeguo` import
  path — stale, matches `README.md`).
- `./tld` — a compiled binary left in the working tree (build artifact from
  `cmd/main.go`, untracked). Not source; ignore/regenerate as needed.

## Core types

```go
type Result struct {
    Flag int    // Malformed | Domain | Ip4 | Ip6 | ETld
    Sub  string
    Root string
    Tld  string
}
```

Suffix rules are stored in a reverse-label **Trie** (`Trie.matches map[string]*Trie`),
built once in `New`/`NewFromStaticList` from the raw PSL text. Each node tracks
`ValidTld` (this label sequence is a real suffix) and `ExceptRule` (PSL `!exception`
lines, e.g. `!city.kobe.jp`) and wildcard matches (`*.s5y.io`) are handled via a
literal `"*"` key in `matches`.

## V1 vs V2

The package carries two parallel extraction pipelines, kept side by side rather than
replacing V1 outright (tests exercise both):

- **V1**: `Extract` → `extract` → `extractTld` → `getTldIndex`. Legacy behavior —
  does not strip a trailing path (`http://x.com/path` misparses), and does not
  recognize a bare suffix as anything other than `Malformed` (e.g. `"google.com"`
  alone doesn't resolve to `ETld`).
- **V2**: `ExtractV2` → `extractV2` → `extractTldV2` → `getTldIndexV2`. Strips
  anything after the first `/` before parsing, and introduces the `ETld` flag: if the
  whole input is exactly a PSL suffix (e.g. `"google.com"`, `"co.uk"`, `"s5y.io"`),
  it returns `Flag: ETld` instead of `Malformed`.
- `IsValidSuffix(url)` is V2-based: true iff `url` is *exactly* an eTLD/suffix entry.

Both pipelines share `subdomain()` (splits root from sub by the last label) and the
same `domainregex`/`ip4regex`/`schemaregex` validators.

## Where the PSL data comes from

`download()` in `tldextract.go` fetches the suffix list from:

```
https://static.dnsfilter.com/effective_tld_names.dat
```

(NOTE: upstream `joeguo/tldextract` instead pulls from
`https://publicsuffix.org/list/public_suffix_list.dat` — this fork points at a
DNSFilter-hosted copy instead, see comment at `tldextract.go:225-227`.)

`New()` caches this download to `CacheFile` on disk and reuses it on subsequent runs;
`NewFromStaticList()` skips the network/cache entirely and takes the list as a string
(used for tests or when the caller already has the data).

### `static.dnsfilter.com` repo (`~/dev/static.dnsfilter.com`)

This is a plain static-file-hosting repo (Dokku-style `.static` buildpack +
`nginx.conf.sigil` template, provisioned via Terraform under
`terraform/environment/{dev,stg,prod}`) — whatever is committed to the repo root is
served as-is at `static.dnsfilter.com/<filename>`. There is **no build/generation
step or CI automation** for `effective_tld_names.dat`; it's a manually maintained
flat file:

- The bulk of the file (~12,880 lines) is the standard Mozilla Public Suffix List,
  copied in wholesale (ICANN + private domains sections), terminated by the
  `// ===END PRIVATE DOMAINS===` marker.
- After that marker, DNSFilter appends its **own custom entries** — domains treated
  as their own eTLD/suffix purely for DNSFilter's filtering/categorization needs
  (e.g. `amazon.com`, `amazon.ca`, `taboola.com`, advertising subdomains like
  `r.msn.com`, `mobile.events.data.trafficmanager.net`, and a batch of smart-device
  vendor domains added by Peter Lowe in Oct 2020 — `ring.com`, `roku.com`,
  `sonos.com`, etc.). These are unrelated to real PSL semantics; they exist so that
  `tldextract` treats e.g. `foo.amazon.com` and `bar.amazon.com` as distinct
  "domains" under a shared suffix rather than collapsing them under `amazon.com`.
- History (`git log -- effective_tld_names.dat`, 34 commits, 2017–2020) is entirely
  manual, human-authored additions/tweaks (no bot/automation commits) — the file is
  updated by editing and committing directly to this repo, then whatever infra
  redeploys the static site.
- `public_suffix_list.dat` in the same repo appears to be a more recent/unmodified
  mirror of the upstream PSL (larger, no custom section) — not the file `tldextract`
  actually downloads.

Do **not** confuse this with `~/dev/tld-maintainer` — that's an unrelated Go service
that syncs IANA TLD (`tlds-alpha-by-domain.txt`) and root-zone NS data into a Postgres
`tlds` table; it has nothing to do with `effective_tld_names.dat` or the PSL used
here.

## Testing

```sh
go test ./...
```

`tldextract_test.go`'s `init()` calls `New(cache, false)`, which downloads the live
PSL from `static.dnsfilter.com` on first run and caches it at `/tmp/tld.cache` — tests
require network access unless that cache file already exists.

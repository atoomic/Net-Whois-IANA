# CLAUDE.md — Net::Whois::IANA

## What this is

A Perl module for querying IANA regional whois registries (RIPE, APNIC, ARIN,
LACNIC, AFRINIC) and National Internet Registries (JPNIC, KRNIC, IDNIC) to
extract descriptive information about IP addresses.

Repository: `atoomic/Net-Whois-IANA`

## Build system

This project uses **Dist::Zilla** (`dist.ini`) to manage releases, but
development uses the checked-in `Makefile.PL` directly:

```bash
perl Makefile.PL
make
make test
```

`$VERSION` is injected by dzil at build/release time — it is **not** present in
the source checkout. This means `t/00-load.t` (version check) and
`t/boilerplate.t` (expects README without `.md`) fail in dev. These are known
and expected.

## Dependencies

Runtime: `IO::Socket`, `Net::CIDR` (>= 0.22).
Test: `Test2::Suite`, `Test::MockModule`, `Test::More`, `Test::CPAN::Meta`, `Test::Builder`.

Install test deps: `cpm install -g --cpanfile cpanfile`

## CI

GitHub Actions workflow in `.github/workflows/ci.yml`:
1. Quick test on system perl (ubuntu-latest)
2. Matrix test across all Perl versions from v5.8+ using `perldocker/perl-tester`

All PRs must pass CI. The two known dev-checkout failures (00-load, boilerplate)
are not in the matrix path.

## Code architecture

Everything lives in a single file: `lib/Net/Whois/IANA.pm` (~900 lines).

### Structure

- **Constants & accessors** (lines 1-58): `%IANA` server map, `@DEFAULT_SOURCE_ORDER`,
  compile-time accessor generation for query fields.
- **Connection** (`whois_connect`): TCP connect with retry loop.
- **IP validation** (`is_valid_ipv4`, `is_valid_ipv6`, `is_valid_ip`): Pure functions.
- **Query pipeline** (`init_query` → `source_connect` → `whois_query`): Iterates
  sources round-robin until a valid response is found.
- **Per-registry functions**: Each registry has a triplet:
  - `*_read_query`: Socket I/O + line parsing
  - `*_process_query`: Field normalization + validation (pure hash→hash)
  - `*_query`: Composes read + process
- **Post-processing** (`post_process_query`): Abuse email extraction, CIDR normalization.
- **`is_mine`**: CIDR lookup helper.

Some read functions are aliased: `*afrinic_read_query = *apnic_read_query`,
`*krnic_read_query = *apnic_read_query`, `*idnic_read_query = *apnic_read_query`.

### Key patterns

- JPNIC uses bracket-style fields (`[Field Name] value`), others use `key: value`.
- ARIN uses `+ $ip` query prefix, RIPE/APNIC use `-r $ip`, LACNIC sends bare IP,
  JPNIC appends `/e` for English output.
- `init_query` returns `{}` (truthy) on error, `undef` (implicit) on success.
  This is a legacy convention — callers must check for truthiness as failure.

## Tests

Tests live in `t/`:

| File | What it tests | Network? |
|------|--------------|----------|
| `t/00-load.t` | Module loads, version check | No (fails in dev) |
| `t/01-connect-query.t` | Live whois query | **Yes** |
| `t/05-ip-validation.t` | `is_valid_ipv4/ipv6/ip` | No |
| `t/06-source-and-accessors.t` | `set_source`, accessors | No |
| `t/07-query-processing.t` | All `*_process_query` + `post_process_query` | No |
| `t/08-whois-query-flow.t` | `whois_query`, `source_connect`, `is_mine` | No (mocked) |
| `t/09-read-query.t` | `*_read_query` functions | No (tied handles) |
| `t/10-t/50` | Live per-registry queries | **Yes** |
| `t/60-cidrvalidate.t` | CIDR validation | No |
| `t/90-misc.t` | Miscellaneous | No |

### Testing conventions

- Use **Test2::V0** for new tests (`use Test2::V0;`).
- Network-dependent tests (`t/01`, `t/10`-`t/50`) hit real whois servers — they
  are slow and may fail due to rate limiting. Unit tests (`t/05`-`t/09`, `t/60`)
  are fast and deterministic.
- **FakeSocket pattern** (t/08): Overloaded object with `<>` operator for
  higher-level mocks (source_connect, whois_query).
- **Tied filehandle pattern** (t/09): `Tie::Handle` with TIEHANDLE/PRINT/READLINE/CLOSE
  for testing `_read_query` functions that use `print $sock` and `while (<$sock>)`.
  Overloaded objects fail with "Not a GLOB reference" for print.
- `*_process_query` functions are pure hash→hash — test them directly without
  any socket mocking.

## Conventions

- Perl 5.6+ compatibility (`use 5.006`), CI tests down to 5.8.
- Prototypes on subs (legacy style, e.g., `sub new ($)`) — follow existing pattern.
- POD is the source of truth for README (auto-generated via `ReadmeAnyFromPod`).
  Edit POD in `IANA.pm`, not `README.md`.
- Default branch is `master` (not `main`).

## Known issues

See [issue #46](https://github.com/atoomic/Net-Whois-IANA/issues/46) for
tracked audit findings.

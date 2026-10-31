# Changelog — `armature-validation`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](https://github.com/quinnjr/armature/blob/main/CHANGELOG.md).

## [Unreleased]

Breaking: the next release is 0.8.0. Validators reject more input (see the
entries marked breaking), error output no longer carries submitted values, and
dependency features this crate used to enable for its consumers are gone.

### Security

- **Submitted values no longer reach clients or error output (breaking).** Every
  built-in validator copied the rejected input into `ValidationError::value`,
  and `ValidationPipe::parse` and `validate!` put `format!("{:?}", errors)` into
  an `Error::BadRequest`, which `armature-core` passes to the client verbatim.
  A password that failed `length(min = 8)` — the README's own example — came
  back in the 400 body and was logged by the request logger.
  - The built-in validators no longer set `value`; `with_value` remains for
    callers who opt in on a non-sensitive field.
  - `ValidationErrors::to_json` (and so `ValidationPipe::error_response`)
    omits `value`; `to_json_with_values` opts in.
  - `ValidationError`'s `Debug` output redacts `value`.
  - `ValidationPipe::parse` and `validate!` return `Error::Validation` with
    `ValidationErrors::client_message()` (`field: message` pairs) instead of
    `Debug` text.
- **`ValidationPipe::parse` no longer exposes serde's error text (breaking).**
  A body that does not deserialize maps to `Error::Deserialization` instead of
  `BadRequest("Invalid JSON: …")`, which quoted the input and named the target
  type's fields and enum variants. `armature-core` sends the client a generic
  message for that variant, and the variant itself carries only serde's error
  category and position, so the value does not reach core's debug log either.
  Code matching on `Error::BadRequest` from `parse` or `validate!` must now
  match `Error::Validation` / `Error::Deserialization`.
- **`Min`, `Max`, `InRange` and `IsPositive` reject NaN and infinities
  (breaking).**
  `Min(0.0)` and `Max(100.0)` both accepted `f64::NAN` (every comparison with
  NaN is false), and `"NaN".parse::<f64>()` is how a query parameter becomes
  one. A NaN *bound* now rejects every value instead of accepting every value.
- **`IsUrl` accepts only URLs the parser reads exactly as written
  (breaking).** Beyond the
  control-character check, it accepted strings the WHATWG parser rewrites, so
  the caller kept a different URL from the one examined: `https:\\evil.com`,
  `https:evil.com`, `https://ex%61mple.com`, zero-width and fullwidth
  characters in the host, IPv4 shorthands (`http://0x7f.1/`), and
  `https://trusted.example@evil.example/`. It now requires RFC 3986
  characters only, well-formed `%XX` escapes, a literal `http://`/`https://`,
  no userinfo, a host within DNS length limits, and a host, port and remainder
  the parser left unchanged; port 0 and a path beginning with `//` (a
  protocol-relative open redirect when the path is used on its own) are also
  rejected, as are a second `#` (RFC 3986 allows none inside a fragment) and
  `[`/`]` in the path or fragment (they remain allowed in the query, as in
  `?page[size]=10`).
  Documented as a syntax check, not an SSRF filter.
  Previously-accepted inputs that are now **rejected** (breaking): non-ASCII
  hosts or paths (give hosts in `xn--` form and percent-encode paths);
  characters the parser encodes, such as `'` in a query or `` ` ``, `{`, `|`,
  `^`; non-canonical IPv6 (`[0:0::1]`, `[::ffff:127.0.0.1]`); ports with
  leading zeros (`:0443`); dot segments (`/a/../b`); malformed `%` escapes;
  `[`/`]` in a path or fragment; a second `#`; a path starting with `//`;
  port 0; userinfo.
- **`validate_parallel` no longer copies a validator's panic message into the
  returned error.** A panicking validator now fails its own field closed
  (`validationFailed`) without discarding other fields' errors, and the call
  falls back to the synchronous path outside a Tokio runtime instead of
  panicking.
- **`NotEmpty` rejects invisible-only values (breaking)**: zero-width
  spaces, bidi controls, Hangul fillers, the braille blank, combining marks
  with nothing to combine with in the common scripts, and similar, which
  displayed as blank while passing a `trim()` check. Control-only values such
  as `"\0"` are rejected too.
- **`IsEmail` enforces RFC 5321 lengths and dot-atom rules (breaking)**: at
  most 64 octets before the `@` and 254 in total, and no leading, trailing or
  consecutive dots in the local part.

### Fixed

- **Breaking:** `validate!` referred to `armature_core::Error` and called
  `.validate()` through whatever trait was in scope, so it did not compile
  for a crate that depended only on `armature-validation`. It now uses
  `$crate` paths and calls `armature_validation::Validate::validate`, so the
  DTO must implement this crate's `Validate` (a type with only an inherent
  `validate` method no longer works with the macro).
- `validate_parallel` returns errors in rule order, matching `validate`.
- README: the install line named `0.1`, the license was given as
  `MIT OR Apache-2.0` (the crate is `Apache-2.0`), and it advertised
  customizable error messages the derive does not support. Its examples are
  now compiled as doc tests.

### Added

- The sealed `Numeric` trait. `Min`, `Max`, `InRange` and the new
  `IsPositive::validate` are generic over every primitive integer and float
  type; they were limited to `i32` (and `f64` for `Min`/`Max`).
- `Matches::full`, which anchors the pattern to the whole value (and rejects
  a pattern that is not valid on its own, so it cannot close the anchoring
  group early). `Matches` itself matches anywhere in the value, which is now
  documented.
- `ValidationErrors::to_json_with_values` and `client_message`.
- `ValidationErrors::to_json` lists at most 100 errors, adding a `truncated`
  count of the rest, so a body failing one check per array element cannot
  produce a response many times its size.
- `IsNumeric` and `IsUuid` in the prelude.
- `ValidationPipe::parse_strict`, which also requires a single JSON
  `Content-Type` (`application/json` or `application/<token>+json`; 415
  otherwise), for cookie-authenticated endpoints that a cross-site
  `text/plain` form post could otherwise reach.

### Changed

- `Matches::new` and `Matches::full` cache compiled patterns, and compile
  errors, so the derive's `regex` rule, which builds a `Matches` on every
  `validate()` call, no longer recompiles per request. The cache is bounded at
  512 entries and a 256 MiB weight budget: each entry is weighed by the
  256 KiB / 1 / 2 / 4 MiB class its program fits (10 MiB beyond that) plus
  three times its source length, so 64–128 typical Unicode rules such as
  `[\w.-]{3,32}` fit.
  Weights are approximate (up to ~1.25x for unanchored patterns), and
  resident memory for a full cache measures about 350 MiB. Eviction is CLOCK;
  sources over 64 KiB are not cached. Concurrent misses on one pattern compile
  it once and share the result. An application cycling through more large
  patterns than fit recompiles on each call, as without a cache. Each use
  clones the cached `Regex`, which starts an empty search cache (microseconds
  to warm) rather than retaining one per pattern.
- `ValidationErrors::client_message` does not repeat the field name when the
  message already names it, lists at most 20 errors of at most 200 characters
  each, and replaces control, line/paragraph-separator and bidi formatting
  characters with spaces so a caller-written field or message cannot break
  the line.
- `ValidationContext`'s `Debug` lists keys only, not the request data.
- `Display` for `ValidationError` and `ValidationErrors` (what logs print)
  replaces control, line-separator and bidi characters with spaces, and
  `ValidationErrors` lists at most 100 errors of at most 200 characters each.
  `to_json` applies the same replacement and 200-character bound to `field`,
  `message`, `constraint` and the opt-in `value`.
- `MaxLength` stops counting once the limit is exceeded.
- **Breaking — dependency features:** `tokio` is trimmed to the `rt` feature
  (`rt-multi-thread`, `sync` and `time` dropped, `macros` moved to
  dev-dependencies), `serde`'s `derive` feature moved to dev-dependencies, and
  `armature-core` is required with `default-features = false` (its
  `h1-backend` default selects the server implementation, which a dependency
  must not override). A downstream crate that relied on this crate enabling
  those features through feature unification must now enable them itself.
- Dependencies: `once_cell` replaced by `std::sync::LazyLock`; `regex-syntax`
  0.8 is a direct dependency (used by `Matches::full`).
- The published package is limited to the library, tests, benches and docs
  (no CI, fuzz or hook configuration).

## [0.7.0] - 2026-10-29

### Changed

- Requires `armature-core` 0.12 (was `0.11`).
- Requires `armature-proc-macro` 0.6 (was `0.5`).

## [0.6.0] - 2026-10-17

### Changed

- **Sibling requirements follow the security-hardening release train (breaking).**
  `armature-core` 0.10 → 0.11, `armature-proc-macro` 0.4 → 0.5. Those releases change public APIs and secure-by-default behaviour
  (see each crate's CHANGELOG); this crate's minor moves with them so a
  downstream build can't mix it with the previous sibling releases. No code
  changes in this crate.

## [0.5.0] - 2026-09-15

### Changed

- **Breaking:** requires `armature-core` 0.10 (was `0.9`); its types appear in this crate's API, so the requirement change is breaking here and the minor moves. Part of the `armature-core` 0.10 release train.
- Dependencies bumped to their latest releases: `regex` 1.12 → 1.13, `tokio` 1.52 → 1.53.

## [0.4.0] - 2026-08-05

### Changed

- **Requires `armature-core` 0.9 (breaking).** The requirement moved `0.8` →
  `0.9`. `armature-core 0.9.0` itself moves `armature-h1` across a breaking
  0.x boundary; because `armature-core` types appear in this crate's own
  public API, the requirement change is breaking here too and the minor moves
  with it. Under Cargo's 0.x caret rules the 0.8 and 0.9 types are distinct
  and do not unify, so a consumer holding an `armature-core 0.8` type cannot
  pass it to this crate. Part of the `armature-core 0.9.0` release train; see
  `armature-core`'s CHANGELOG for the publish order.
- Requires `armature-proc-macro` 0.4 (was `0.3`); it moved its minor in the same train for the same reason.

## [0.3.1] - 2026-08-04

### Fixed

- Requirements on sibling armature crates name a minor instead of `0`. Under
  Cargo's 0.x rules `version = "0"` matches any release ever made, and edition
  2024 selects the MSRV-aware resolver, so a consumer declaring an older
  `rust-version` was handed the oldest version satisfying it — resolving
  `armature-core = "0"` on Rust 1.89 produced `armature-core 0.2.3` while an
  explicit `armature-core = "0.8"` elsewhere in the same graph pulled 0.8.2.
  Two copies of core, and a build failing on symbols the older one lacks. Each
  0.x minor in this family is a breaking change, so the requirement now names
  one. No API change.

## [0.3.0] - 2026-08-04

### Fixed

- **Security — `IsUrl` rejects embedded control characters and spaces.** The
  WHATWG URL parser trims `c0_control_or_space` — every code point at or below
  `U+0020`, tab, CR and LF among them — *before* parsing, so
  `https://a.example/\r\nX-Injected: 1` parsed cleanly and was accepted. The
  caller keeps the original string, so the validator was approving text it had
  never actually examined, and that text still carried a CRLF into wherever it
  was used next — a `Location` header being the obvious route to response
  splitting. The check now uses the parser's own predicate rather than
  `char::is_control()`, which misses `U+0020`.
- **Breaking:** a field with rules but **absent** from the input was silently skipped, so a form that simply omitted `email` passed `NotEmpty` and `IsEmail`. A missing required field is now validated as `""`; mark genuinely optional fields with the new `ValidationRules::optional()`. Applies to both `validate` and `validate_parallel`.
- `IsUuid` accepted only lowercase and checked neither version nor variant. It is now case-insensitive per RFC 9562 §4, constrains the version to 1–8 and the variant to 8/9/a/b, and permits the nil and max UUIDs.
- `IsUrl` parses with the `url` crate instead of pattern matching. It previously rejected valid URLs with a single-label host (`https://a`) and accepted invalid ones (`https://!!`).

### Added

- Adopted the `validation` criterion benchmark from the root package's `benches/`. Run it with `cargo bench -p armature-validation --bench validation`. The crate now sets `autobenches = false`, so a new file under `benches/` needs an explicit `[[bench]]` entry.
- `ValidationRules::optional()`, `is_optional()` and `field_name()`.

### Changed

- (0.1.4) Migrated onto `armature-core` `0.8`'s `Bytes`-backed request and response types. No behavior change beyond what that migration implies; see the [`armature-core` changelog](https://github.com/quinnjr/armature-core/blob/main/CHANGELOG.md).

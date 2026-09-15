# Changelog — `armature-validation`

All notable changes to this crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this crate adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Earlier changes are recorded in the workspace [`CHANGELOG.md`](../CHANGELOG.md).

## [Unreleased]

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

### Added

- Adopted the `validation` criterion benchmark from the root package's `benches/`. Run it with `cargo bench -p armature-validation --bench validation`. The crate now sets `autobenches = false`, so a new file under `benches/` needs an explicit `[[bench]]` entry.

### Fixed

- **Breaking:** a field with rules that is absent from the input now fails validation. It was silently skipped, so a form missing `email` entirely passed `NotEmpty` and `IsEmail`; `ValidationRules::optional()` opts out.
- `IsUuid` accepts uppercase and checks version/variant; `IsUrl` parses with the `url` crate instead of a regex that rejected `https://a` and accepted `https://!!`.

### Fixed

- A field with rules but **absent** from the input was silently skipped, so a form that simply omitted `email` passed `NotEmpty` and `IsEmail`. A missing required field is now validated as `""`; mark genuinely optional fields with the new `ValidationRules::optional()`. Applies to both `validate` and `validate_parallel`.
- `IsUuid` accepted only lowercase and checked neither version nor variant. It is now case-insensitive per RFC 9562 §4, constrains the version to 1–8 and the variant to 8/9/a/b, and permits the nil and max UUIDs.
- `IsUrl` parses with the `url` crate instead of pattern matching. It previously rejected valid URLs with a single-label host (`https://a`) and accepted invalid ones (`https://!!`).

### Added

- `ValidationRules::optional()`, `is_optional()` and `field_name()`.

### Changed — `0.1.3` → `0.1.4`

- Migrated onto `armature-core` `0.8`'s `Bytes`-backed request and response types. No behavior change beyond what that migration implies; see [`armature-core/CHANGELOG.md`](../armature-core/CHANGELOG.md).

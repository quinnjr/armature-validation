// Built-in validators
//
// None of these attach the submitted value to the error they return: the value
// is client input, an error is routinely serialised into a response or a log,
// and a password that fails `MinLength` must not come back out that way. A
// caller that wants the value on a known-safe field adds it with
// `ValidationError::with_value`.

use crate::ValidationError;
use regex::Regex;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Condvar, LazyLock, Mutex, RwLock};

/// RFC 5322 `dot-atom` local part, `@`, then a hostname.
///
/// The local part is one or more runs of `atext` separated by single dots, so
/// a leading, trailing or doubled dot is rejected (`.a@x.io`, `a..b@x.io`).
/// Lengths are checked separately, see [`IsEmail`].
static EMAIL_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~-]+)*@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$").unwrap()
});

/// RFC 9562 UUID string form.
///
/// Case-insensitive: §4 defines the hex digits as case-insensitive on input,
/// so an uppercase UUID is valid and must not be rejected. The version nibble
/// is constrained to 1-8 and the variant nibble to the RFC 9562 variant
/// (`8`/`9`/`a`/`b`); the nil and max UUIDs are permitted explicitly, since
/// neither carries a valid version/variant.
static UUID_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$",
    )
    .unwrap()
});

/// A hostname (dot-separated non-empty labels, optional trailing dot) or a
/// bracketed IP-literal.
///
/// `url` accepts some hosts that no DNS resolver or web client will (`https://!!`
/// parses, with `!!` as the host), so the parsed host is checked against this
/// afterwards.
static HOST_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)^(?:\[[0-9a-f:.]+\]|[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9_-]*[a-z0-9])?)*\.?)$",
    )
    .unwrap()
});

static ALPHA_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-zA-Z]+$").unwrap());

static ALPHANUMERIC_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9]+$").unwrap());

static NUMERIC_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9]+$").unwrap());

/// Characters that render as nothing: Unicode format characters (`Cf`, e.g.
/// zero-width space, bidi overrides, the BOM) and the default-ignorable or
/// "filler" code points that fonts draw as blank (Hangul fillers, the braille
/// blank, variation selectors).
///
/// Not covered by `char::is_whitespace` or `char::is_control`, so a value made
/// of them passes a `trim().is_empty()` check while looking empty, and inside
/// a URL they make the string a user sees differ from the one that is parsed.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{2800}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF0}'..='\u{FFFC}'
            | '\u{13430}'..='\u{1343F}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{16FE4}'
            | '\u{1D159}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

/// Combining marks from the common blocks (generic diacritics, Cyrillic,
/// Hebrew, Arabic, Devanagari, Thai, kana voicing): they attach to a
/// preceding character, and a value made of nothing else renders as blank or
/// as a stray accent. A best-effort list, not the full `Mn`/`Me` categories.
fn is_combining_mark(c: char) -> bool {
    matches!(
        c,
        '\u{0300}'..='\u{036F}'
            | '\u{0483}'..='\u{0489}'
            | '\u{0591}'..='\u{05BD}'
            | '\u{05BF}'
            | '\u{05C1}'..='\u{05C2}'
            | '\u{05C4}'..='\u{05C5}'
            | '\u{05C7}'
            | '\u{0610}'..='\u{061A}'
            | '\u{064B}'..='\u{065F}'
            | '\u{0900}'..='\u{0903}'
            | '\u{093A}'..='\u{093C}'
            | '\u{093E}'..='\u{094F}'
            | '\u{0E31}'
            | '\u{0E34}'..='\u{0E3A}'
            | '\u{0E47}'..='\u{0E4E}'
            | '\u{1AB0}'..='\u{1AFF}'
            | '\u{1DC0}'..='\u{1DFF}'
            | '\u{20D0}'..='\u{20FF}'
            | '\u{3099}'..='\u{309A}'
            | '\u{FE20}'..='\u{FE2F}'
            | '\u{1D165}'..='\u{1D169}'
            | '\u{1D16D}'..='\u{1D172}'
            | '\u{1D17B}'..='\u{1D182}'
            // Emoji skin-tone modifiers, which modify a preceding emoji.
            | '\u{1F3FB}'..='\u{1F3FF}'
    )
}

// String validators

/// Validates that a string has visible content.
///
/// Rejects a value made only of whitespace, control characters, invisible
/// characters (zero-width spaces, bidi controls, Hangul fillers and similar)
/// and combining marks, all of which would otherwise pass for a non-empty name
/// while displaying as blank. The invisible set is a best-effort denylist of
/// the common cases, not every code point a font may draw as nothing.
pub struct NotEmpty;

impl NotEmpty {
    pub fn validate(value: &str, field: &str) -> Result<(), ValidationError> {
        if value
            .chars()
            .all(|c| c.is_whitespace() || c.is_control() || is_invisible(c) || is_combining_mark(c))
        {
            Err(
                ValidationError::new(field, format!("{} should not be empty", field))
                    .with_constraint("notEmpty"),
            )
        } else {
            Ok(())
        }
    }
}

/// Validates minimum string length, counted in `char`s.
pub struct MinLength(pub usize);

impl MinLength {
    pub fn validate(&self, value: &str, field: &str) -> Result<(), ValidationError> {
        if value.chars().count() < self.0 {
            Err(ValidationError::new(
                field,
                format!("{} must be at least {} characters", field, self.0),
            )
            .with_constraint("minLength"))
        } else {
            Ok(())
        }
    }
}

/// Validates maximum string length, counted in `char`s.
pub struct MaxLength(pub usize);

impl MaxLength {
    pub fn validate(&self, value: &str, field: &str) -> Result<(), ValidationError> {
        // `take` bounds the walk: a multi-megabyte value is rejected after
        // `max + 1` characters rather than counted to the end.
        if value.chars().take(self.0.saturating_add(1)).count() > self.0 {
            Err(ValidationError::new(
                field,
                format!("{} must be at most {} characters", field, self.0),
            )
            .with_constraint("maxLength"))
        } else {
            Ok(())
        }
    }
}

/// Validates email format.
///
/// Accepts an RFC 5322 `dot-atom` local part (ASCII; no leading, trailing or
/// consecutive dots) and a hostname domain, within the RFC 5321 limits of 64
/// octets for the local part and 254 for the whole address. A single-label
/// domain such as `user@localhost` is accepted.
///
/// This is a format check. The characters RFC 5322 permits in a local part
/// include `'`, `` ` ``, `{`, `|` and others, so a valid address is still not
/// safe to interpolate into HTML, SQL or a shell without escaping.
pub struct IsEmail;

impl IsEmail {
    /// RFC 5321 §4.5.3.1.1.
    const MAX_LOCAL: usize = 64;
    /// RFC 5321 §4.5.3.1.3: a 256-octet path less the angle brackets.
    const MAX_TOTAL: usize = 254;

    pub fn validate(value: &str, field: &str) -> Result<(), ValidationError> {
        let is_valid = value.len() <= Self::MAX_TOTAL
            && value
                .split_once('@')
                .is_some_and(|(local, _)| local.len() <= Self::MAX_LOCAL)
            && EMAIL_REGEX.is_match(value);

        if is_valid {
            Ok(())
        } else {
            Err(
                ValidationError::new(field, format!("{} must be a valid email", field))
                    .with_constraint("isEmail"),
            )
        }
    }
}

/// Validates URL format
pub struct IsUrl;

impl IsUrl {
    /// Accept an absolute `http`/`https` URL that the URL parser reads exactly
    /// as written.
    ///
    /// The value is *parsed* (via the `url` crate), not pattern-matched, and
    /// accepted only if:
    ///
    /// - it consists solely of RFC 3986 URI characters (ASCII letters, digits,
    ///   `-._~:/?#[]@!$&'()*+,;=` and well-formed `%`-escapes), with `[`/`]`
    ///   only in an IP-literal host or the query and at most one `#`.
    ///   Anything else, from a CR or a space to a backslash, a zero-width
    ///   space or a fullwidth letter, is something the WHATWG parser strips,
    ///   rewrites or percent-encodes;
    /// - it begins with `http://` or `https://` literally (case-insensitive).
    ///   The parser also accepts `https:host`, `https:/host` and
    ///   `https:\\host`, which other consumers read differently;
    /// - it has no userinfo. `https://trusted.example@evil.example/` is a
    ///   valid URL whose host is `evil.example`, and the reason to reject it
    ///   is that people and prefix checks read it as `trusted.example`;
    /// - the host and port as written are the ones the parser produced, up to
    ///   ASCII case and an explicit default port. This rejects hosts the
    ///   parser *normalised*: percent-escapes (`ex%61mple.com`), IDNA mapping
    ///   (non-ASCII hosts, which must be submitted in their `xn--` form) and
    ///   IPv4 shorthands (`0x7f.1`, `2130706433`, both `127.0.0.1`);
    /// - everything after the host is exactly what the parser kept, so it did
    ///   not resolve dot segments or encode anything along the way;
    /// - the host is a plausible hostname or IP literal. `url` will happily
    ///   parse `https://!!` with `!!` as the host.
    ///
    /// The point of each rule is the same: the string a caller keeps and
    /// later uses (in a `Location` header, an allowlist prefix check, another
    /// HTTP client) must be the string that was examined. Approving the
    /// parser's normalised form while the caller holds the original is how
    /// `"https://a.example/\r\nX-Injected: 1"` becomes response splitting.
    ///
    /// Single-label hosts are accepted: `https://a`, `http://localhost` and
    /// `http://intranet` are all real, resolvable URLs. So are `xn--` hosts,
    /// which may decode to lookalikes of other domains (`xn--pple-43d.com` is
    /// `аpple.com` with a Cyrillic `а`); this validator does not judge which
    /// domains are trustworthy.
    ///
    /// It also rejects port 0 and a path beginning with `//`, which is a
    /// protocol-relative reference to another host when the path is used on
    /// its own. It does not normalise: `HTTPS://EXAMPLE.COM/` and the
    /// trailing-dot `https://example.com./` pass as written, so compare hosts
    /// case-insensitively and without a trailing dot when allowlisting.
    ///
    /// Percent-escapes are accepted as written, including escaped controls
    /// (`%0d%0a`): the string holds no CR or LF, but code that percent-decodes
    /// the URL before writing it into a header gets them back.
    ///
    /// This is a syntax check, **not** an SSRF filter: loopback, private and
    /// link-local addresses (`http://127.0.0.1/`, `http://169.254.169.254/`)
    /// are valid URLs and pass. Resolve and vet the destination before
    /// fetching a user-supplied URL server-side.
    pub fn validate(value: &str, field: &str) -> Result<(), ValidationError> {
        if Self::is_valid(value) {
            Ok(())
        } else {
            Err(
                ValidationError::new(field, format!("{} must be a valid URL", field))
                    .with_constraint("isUrl"),
            )
        }
    }

    fn is_uri_char(c: char) -> bool {
        c.is_ascii_alphanumeric() || "-._~:/?#[]@!$&'()*+,;=%".contains(c)
    }

    fn strip_scheme(value: &str) -> Option<&str> {
        ["http://", "https://"].iter().find_map(|prefix| {
            value
                .get(..prefix.len())
                .filter(|head| head.eq_ignore_ascii_case(prefix))
                .map(|_| &value[prefix.len()..])
        })
    }

    /// Every `%` starts a two-hex-digit escape (RFC 3986 §2.1). The parser
    /// leaves a malformed one alone, but decoders downstream disagree on it.
    fn has_well_formed_escapes(value: &str) -> bool {
        let bytes = value.as_bytes();
        bytes.iter().enumerate().all(|(i, &b)| {
            b != b'%'
                || bytes
                    .get(i + 1..i + 3)
                    .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
        })
    }

    /// DNS limits (RFC 1035 §2.3.4): labels of at most 63 octets, a name of
    /// at most 253 not counting a trailing dot. IP-literals are exempt.
    fn host_within_dns_limits(host: &str) -> bool {
        if host.starts_with('[') {
            return true;
        }
        let name = host.strip_suffix('.').unwrap_or(host);
        name.len() <= 253 && name.split('.').all(|label| label.len() <= 63)
    }

    fn is_valid(value: &str) -> bool {
        if !value.chars().all(Self::is_uri_char)
            || !Self::has_well_formed_escapes(value)
            || value.matches('#').count() > 1
        {
            return false;
        }
        let Some(rest) = Self::strip_scheme(value) else {
            return false;
        };
        let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(authority_end);
        // `[` and `]` belong to an IP-literal host (RFC 3986 §3.2.2), so not
        // in the path or fragment. A query keeps them: `?page[size]=10` is
        // JSON:API's and many frameworks' convention, and the parser leaves
        // it as written.
        let query_start = tail.find('?').unwrap_or(tail.len());
        let fragment_start = tail.find('#').unwrap_or(tail.len());
        let (path, fragment) = (
            &tail[..query_start.min(fragment_start)],
            &tail[fragment_start..],
        );
        if authority.contains('@') || path.contains(['[', ']']) || fragment.contains(['[', ']']) {
            return false;
        }

        let Ok(parsed) = url::Url::parse(value) else {
            return false;
        };
        if !matches!(parsed.scheme(), "http" | "https") {
            return false;
        }
        let Some(host) = parsed.host_str() else {
            return false;
        };
        if !HOST_REGEX.is_match(host) || !Self::host_within_dns_limits(host) {
            return false;
        }

        // Split the written authority into host and port. An IP-literal is
        // bracketed and contains colons of its own.
        let (raw_host, raw_port) = match authority.strip_prefix('[') {
            Some(after) => match after.split_once(']') {
                Some((inner, port)) => (&authority[..inner.len() + 2], port),
                None => return false,
            },
            None => match authority.split_once(':') {
                Some((h, _)) => (h, &authority[h.len()..]),
                None => (authority, ""),
            },
        };
        if !raw_host.eq_ignore_ascii_case(host) {
            return false;
        }
        if let Some(port) = raw_port.strip_prefix(':') {
            // `url` drops an explicit default port, accepts an empty one and
            // strips leading zeros, so the port must be written canonically
            // (`443`, not `0443`) and be the one the parser kept.
            let written = port
                .parse::<u16>()
                .ok()
                .filter(|&n| n != 0 && n.to_string() == port);
            if written.is_none() || written != parsed.port_or_known_default() {
                return false;
            }
        } else if !raw_port.is_empty() {
            return false;
        }

        // `https://a//evil.example`: a path that starts with `//` is a
        // protocol-relative URL to a different host once it is used on its
        // own, as in a redirect to "the path of the validated URL".
        if tail.starts_with("//") {
            return false;
        }

        // An empty path is the one thing the parser legitimately adds: a `/`
        // on its own, or before a query or fragment that follows the host.
        let parsed_tail = &parsed[url::Position::BeforePath..];
        match parsed_tail.strip_prefix('/') {
            Some(rest) if !tail.starts_with('/') => tail == rest,
            _ => tail == parsed_tail,
        }
    }
}

/// Validates UUID format
pub struct IsUuid;

impl IsUuid {
    pub fn validate(value: &str, field: &str) -> Result<(), ValidationError> {
        if UUID_REGEX.is_match(value) {
            Ok(())
        } else {
            Err(
                ValidationError::new(field, format!("{} must be a valid UUID", field))
                    .with_constraint("isUuid"),
            )
        }
    }
}

/// Validates that a string is one or more ASCII letters (`a-z`, `A-Z`).
///
/// Non-ASCII letters such as `é` are rejected.
pub struct IsAlpha;

impl IsAlpha {
    pub fn validate(value: &str, field: &str) -> Result<(), ValidationError> {
        if ALPHA_REGEX.is_match(value) {
            Ok(())
        } else {
            Err(
                ValidationError::new(field, format!("{} must contain only letters", field))
                    .with_constraint("isAlpha"),
            )
        }
    }
}

/// Validates that a string is one or more ASCII letters or digits.
///
/// Non-ASCII letters and digits are rejected.
pub struct IsAlphanumeric;

impl IsAlphanumeric {
    pub fn validate(value: &str, field: &str) -> Result<(), ValidationError> {
        if ALPHANUMERIC_REGEX.is_match(value) {
            Ok(())
        } else {
            Err(ValidationError::new(
                field,
                format!("{} must contain only letters and numbers", field),
            )
            .with_constraint("isAlphanumeric"))
        }
    }
}

/// Validates that a string is one or more ASCII digits (`0-9`).
///
/// There is no sign, decimal point or length limit: combine with
/// [`MaxLength`] before parsing into a fixed-width integer.
pub struct IsNumeric;

impl IsNumeric {
    pub fn validate(value: &str, field: &str) -> Result<(), ValidationError> {
        if NUMERIC_REGEX.is_match(value) {
            Ok(())
        } else {
            Err(
                ValidationError::new(field, format!("{} must contain only numbers", field))
                    .with_constraint("isNumeric"),
            )
        }
    }
}

// Number validators

mod sealed {
    pub trait Sealed {}
}

/// Primitive numbers accepted by [`Min`], [`Max`], [`InRange`] and
/// [`IsPositive`].
///
/// Sealed: implemented for every built-in integer and float type.
pub trait Numeric: sealed::Sealed + PartialOrd + fmt::Display + Copy {
    #[doc(hidden)]
    const ZERO: Self;

    /// Whether the value is a finite number. Always true for integers; false
    /// for a float NaN or infinity, which every numeric validator rejects.
    #[doc(hidden)]
    fn is_finite_number(self) -> bool {
        true
    }
}

macro_rules! numeric_int {
    ($($t:ty),*) => {$(
        impl sealed::Sealed for $t {}
        impl Numeric for $t {
            const ZERO: Self = 0;
        }
    )*};
}
numeric_int!(
    i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize
);

macro_rules! numeric_float {
    ($($t:ty),*) => {$(
        impl sealed::Sealed for $t {}
        impl Numeric for $t {
            const ZERO: Self = 0.0;
            fn is_finite_number(self) -> bool {
                self.is_finite()
            }
        }
    )*};
}
numeric_float!(f32, f64);

fn non_finite(field: &str, constraint: &str) -> ValidationError {
    ValidationError::new(field, format!("{} must be a finite number", field))
        .with_constraint(constraint)
}

/// Validates minimum value.
///
/// A float NaN or infinity is rejected: NaN compares false against every
/// bound, so a plain `value < min` check would let it through, and `"NaN"`
/// is what `str::parse::<f64>` makes of a query parameter. A NaN *bound*
/// rejects every value, rather than accepting every value.
pub struct Min<T>(pub T);

impl<T: Numeric> Min<T> {
    pub fn validate(&self, value: T, field: &str) -> Result<(), ValidationError> {
        if !value.is_finite_number() {
            Err(non_finite(field, "min"))
        } else if !matches!(
            value.partial_cmp(&self.0),
            Some(Ordering::Greater | Ordering::Equal)
        ) {
            Err(
                ValidationError::new(field, format!("{} must be at least {}", field, self.0))
                    .with_constraint("min"),
            )
        } else {
            Ok(())
        }
    }
}

/// Validates maximum value. A float NaN or infinity is rejected, and a NaN
/// bound rejects every value, as for [`Min`].
pub struct Max<T>(pub T);

impl<T: Numeric> Max<T> {
    pub fn validate(&self, value: T, field: &str) -> Result<(), ValidationError> {
        if !value.is_finite_number() {
            Err(non_finite(field, "max"))
        } else if !matches!(
            value.partial_cmp(&self.0),
            Some(Ordering::Less | Ordering::Equal)
        ) {
            Err(
                ValidationError::new(field, format!("{} must be at most {}", field, self.0))
                    .with_constraint("max"),
            )
        } else {
            Ok(())
        }
    }
}

/// Validates value is strictly greater than zero (and, for floats, finite).
pub struct IsPositive;

impl IsPositive {
    pub fn validate<T: Numeric>(value: T, field: &str) -> Result<(), ValidationError> {
        if value.is_finite_number() && value > T::ZERO {
            Ok(())
        } else {
            Err(
                ValidationError::new(field, format!("{} must be a positive number", field))
                    .with_constraint("isPositive"),
            )
        }
    }

    pub fn validate_i32(value: i32, field: &str) -> Result<(), ValidationError> {
        Self::validate(value, field)
    }

    pub fn validate_f64(value: f64, field: &str) -> Result<(), ValidationError> {
        Self::validate(value, field)
    }
}

/// Validates value is in the inclusive range `min..=max`.
///
/// A float NaN or infinity is rejected. If `min > max` no value is in range,
/// so every value is rejected.
pub struct InRange<T> {
    pub min: T,
    pub max: T,
}

impl<T: Numeric> InRange<T> {
    pub fn validate(&self, value: T, field: &str) -> Result<(), ValidationError> {
        if !value.is_finite_number() {
            Err(non_finite(field, "inRange"))
        } else if value >= self.min && value <= self.max {
            Ok(())
        } else {
            Err(ValidationError::new(
                field,
                format!("{} must be between {} and {}", field, self.min, self.max),
            )
            .with_constraint("inRange"))
        }
    }
}

/// Compiled patterns, keyed by `(anchored, source)`, so that a pattern built
/// per call (as `#[derive(Validate)]`'s `regex` rule does on every
/// `validate()`) is compiled once rather than on every request.
///
/// Bounded by a byte budget, [`CACHE_BUDGET`], and an entry count,
/// [`CACHE_ENTRIES`]. Each entry is weighed at 1.25 × the smallest of
/// [`SIZE_CLASSES`] its compiled program fits under: the class limits the
/// NFAs, and the one-pass DFA and prefilters add up to about another tenth,
/// so the budget is approximate. A pattern over the largest class is
/// compiled under the `regex` crate's default limit and weighed at that. Unicode classes make large
/// programs common: `^[\w.-]{3,32}$` compiles to about 2 MiB. Every entry's
/// lazy-DFA cache (one per thread using it) is capped at [`CACHE_DFA`], so
/// the worst case is about [`CACHE_BUDGET`] plus `threads × CACHE_ENTRIES ×
/// CACHE_DFA` of search caches, reached only by an application compiling
/// hundreds of distinct large patterns.
///
/// Eviction is CLOCK (second chance): a lookup marks its entry referenced,
/// and the eviction hand skips, and clears, referenced entries. A working
/// set that fits stays cached while a burst of one-off patterns (e.g. ones
/// built from request data) cycles through the unreferenced slots.
///
/// A source longer than [`MAX_PATTERN`] is never cached.
static MATCHES_CACHE: LazyLock<RwLock<PatternCache>> = LazyLock::new(Default::default);
const MAX_PATTERN: usize = 1024;
const CACHE_ENTRIES: usize = 512;
const CACHE_BUDGET: usize = 256 * 1024 * 1024;
const CACHE_DFA: usize = 256 * 1024;
const SIZE_CLASSES: [usize; 3] = [256 * 1024, 2 * 1024 * 1024, 8 * 1024 * 1024];
/// `regex`'s default `size_limit`, the weight of a pattern over every class.
const DEFAULT_COMPILED: usize = 10 * 1024 * 1024;

/// Patterns being compiled for the cache. A caller that misses on a pattern
/// already here waits on [`MATCHES_INFLIGHT_DONE`] and then finds it cached.
static MATCHES_INFLIGHT: LazyLock<Mutex<HashSet<PatternKey>>> = LazyLock::new(Default::default);
static MATCHES_INFLIGHT_DONE: Condvar = Condvar::new();

/// Marks a pattern as being compiled; dropping it, on any path, unmarks it
/// and wakes waiters.
struct InFlight(PatternKey);

impl InFlight {
    fn enter(key: &PatternKey) -> Self {
        let mut inflight = MATCHES_INFLIGHT.lock().unwrap_or_else(|e| e.into_inner());
        while inflight.contains(key) {
            inflight = MATCHES_INFLIGHT_DONE
                .wait(inflight)
                .unwrap_or_else(|e| e.into_inner());
        }
        inflight.insert(key.clone());
        Self(key.clone())
    }
}

impl Drop for InFlight {
    fn drop(&mut self) {
        MATCHES_INFLIGHT
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.0);
        MATCHES_INFLIGHT_DONE.notify_all();
    }
}

/// An entry's budget weight for a program within `limit`; see
/// [`MATCHES_CACHE`].
const fn weigh(limit: usize) -> usize {
    limit + limit / 4
}

type PatternKey = (bool, String);

struct CacheEntry {
    regex: Regex,
    weight: usize,
    referenced: AtomicBool,
}

#[derive(Default)]
struct PatternCache {
    entries: HashMap<PatternKey, CacheEntry>,
    /// Insertion ring the CLOCK hand walks.
    ring: Vec<PatternKey>,
    hand: usize,
    weight: usize,
}

impl PatternCache {
    fn get(&self, key: &PatternKey) -> Option<Regex> {
        self.entries.get(key).map(|entry| {
            entry.referenced.store(true, AtomicOrdering::Relaxed);
            entry.regex.clone()
        })
    }

    fn insert(&mut self, key: PatternKey, regex: Regex, weight: usize) {
        if let Some(old) = self.entries.remove(&key) {
            self.weight -= old.weight;
            self.ring.retain(|k| k != &key);
        }
        while !self.ring.is_empty()
            && (self.entries.len() >= CACHE_ENTRIES || self.weight + weight > CACHE_BUDGET)
        {
            self.hand %= self.ring.len();
            let entry = &self.entries[&self.ring[self.hand]];
            if entry.referenced.swap(false, AtomicOrdering::Relaxed) {
                self.hand += 1;
            } else {
                // `remove`, not `swap_remove`: the ring's order is the
                // CLOCK's, and swapping would bring the newest entry under
                // the hand to be evicted next.
                let victim = self.ring.remove(self.hand);
                if let Some(old) = self.entries.remove(&victim) {
                    self.weight -= old.weight;
                }
            }
        }
        self.weight += weight;
        // Behind the hand, so a new entry gets a full sweep before it is
        // considered for eviction.
        let at = self.hand.min(self.ring.len());
        self.ring.insert(at, key.clone());
        self.hand = at + 1;
        self.entries.insert(
            key,
            CacheEntry {
                regex,
                weight,
                referenced: AtomicBool::new(false),
            },
        );
    }
}

/// Custom regex validator.
///
/// The value passes if the pattern matches **anywhere** in it, as with
/// [`Regex::is_match`]: `Matches::new("[a-z]+")` accepts `"1<script>a"`. For
/// an allowlist, anchor the pattern (`^…$`) or use [`Matches::full`].
///
/// Patterns should come from the application, not from requests: the `regex`
/// engine matches in linear time, but compiling a pattern can be expensive.
///
/// With the `(?m)` flag, `^` and `$` match at line boundaries, so
/// `Matches::new("(?m)^[a-z]+$")` accepts `"abc\n<x>"`; [`Matches::full`]
/// anchors with `\A`/`\z`, which always mean the ends of the value.
pub struct Matches(pub Regex);

impl Matches {
    /// Compile `pattern`, reusing an earlier compilation of the same pattern.
    pub fn new(pattern: &str) -> Result<Self, regex::Error> {
        Self::cached_compile(false, pattern)
    }

    /// Like [`Matches::new`], but the pattern must match the whole value.
    ///
    /// The pattern is parsed on its own first, so one with an unbalanced `)`
    /// is an error rather than a way to close the anchoring group early
    /// (`a)|(?:b` would otherwise become `^(?:a)|(?:b)$`).
    ///
    /// The pattern is wrapped as `\A(?:pattern)\z`, so a verbose-mode
    /// (`(?x)`) pattern ending in a `#` comment is rejected: the comment
    /// would swallow the closing `)`. End such a pattern with a newline.
    pub fn full(pattern: &str) -> Result<Self, regex::Error> {
        Self::cached_compile(true, pattern)
    }

    /// Compile `pattern` (anchored to the whole value if `full`), through the
    /// cache. Anchored entries are keyed separately from plain ones, so an
    /// anchored form only ever comes out of the cache via [`Matches::full`],
    /// which checked the bare pattern before inserting it.
    fn cached_compile(full: bool, pattern: &str) -> Result<Self, regex::Error> {
        let key = (full, pattern.to_owned());
        if let Some(regex) = MATCHES_CACHE
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
        {
            return Ok(Self(regex));
        }
        // Single flight: concurrent misses on one pattern wait for the first
        // compile instead of each repeating it.
        let _flight = (pattern.len() <= MAX_PATTERN).then(|| InFlight::enter(&key));
        if let Some(regex) = MATCHES_CACHE
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
        {
            return Ok(Self(regex));
        }
        let source = if full {
            // Parsing is enough to reject an unbalanced pattern, and far
            // cheaper than compiling it.
            regex_syntax::Parser::new()
                .parse(pattern)
                .map_err(|e| regex::Error::Syntax(e.to_string()))?;
            format!(r"\A(?:{pattern})\z")
        } else {
            pattern.to_owned()
        };
        if pattern.len() > MAX_PATTERN {
            return Ok(Self(Regex::new(&source)?));
        }
        // The smallest size class the program fits sets its cache weight. A
        // failed attempt stops once it exceeds its limit, but still costs up
        // to that limit's worth of compiling: with three classes a miss on a
        // large pattern costs about twice to two and a half times a plain
        // compile.
        let mut compiled = None;
        for limit in SIZE_CLASSES {
            match regex::RegexBuilder::new(&source)
                .size_limit(limit)
                .dfa_size_limit(CACHE_DFA)
                .build()
            {
                Ok(regex) => {
                    compiled = Some((regex, weigh(limit)));
                    break;
                }
                Err(regex::Error::CompiledTooBig(_)) => continue,
                Err(e) => return Err(e),
            }
        }
        let (regex, weight) = match compiled {
            Some(found) => found,
            None => (
                regex::RegexBuilder::new(&source)
                    .dfa_size_limit(CACHE_DFA)
                    .build()?,
                weigh(DEFAULT_COMPILED),
            ),
        };
        MATCHES_CACHE
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, regex.clone(), weight);
        Ok(Self(regex))
    }

    #[cfg(test)]
    fn cached(full: bool, pattern: &str) -> bool {
        MATCHES_CACHE
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&(full, pattern.to_owned()))
            .is_some()
    }

    pub fn validate(&self, value: &str, field: &str) -> Result<(), ValidationError> {
        if self.0.is_match(value) {
            Ok(())
        } else {
            Err(
                ValidationError::new(field, format!("{} does not match required pattern", field))
                    .with_constraint("matches"),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_not_empty() {
        assert!(NotEmpty::validate("test", "field").is_ok());
        assert!(NotEmpty::validate("", "field").is_err());
        assert!(NotEmpty::validate("   ", "field").is_err());
    }

    #[test]
    fn test_min_length() {
        let validator = MinLength(5);
        assert!(validator.validate("hello", "field").is_ok());
        assert!(validator.validate("hi", "field").is_err());
    }

    #[test]
    fn test_is_email() {
        assert!(IsEmail::validate("test@example.com", "email").is_ok());
        assert!(IsEmail::validate("invalid", "email").is_err());
    }

    #[test]
    fn test_min_value() {
        let validator = Min(10);
        assert!(validator.validate(15, "age").is_ok());
        assert!(validator.validate(5, "age").is_err());
    }

    #[test]
    fn test_max_length() {
        let validator = MaxLength(10);
        assert!(validator.validate("short", "field").is_ok());
        assert!(validator.validate("this is too long", "field").is_err());
    }

    #[test]
    fn test_max_value() {
        let validator = Max(100i32);
        assert!(validator.validate(50i32, "value").is_ok());
        assert!(validator.validate(150i32, "value").is_err());
    }

    #[test]
    fn test_in_range() {
        let validator = InRange {
            min: 10i32,
            max: 20i32,
        };
        assert!(validator.validate(15i32, "value").is_ok());
        assert!(validator.validate(5i32, "value").is_err());
        assert!(validator.validate(25i32, "value").is_err());
    }

    #[test]
    fn test_is_url() {
        assert!(IsUrl::validate("https://example.com", "url").is_ok());
        assert!(IsUrl::validate("http://test.org/path", "url").is_ok());
        assert!(IsUrl::validate("not a url", "url").is_err());

        // A single-label host is a real URL. The old regex required at least
        // two characters after the scheme and rejected this.
        assert!(IsUrl::validate("https://a", "url").is_ok());
        assert!(IsUrl::validate("http://localhost:8080/health", "url").is_ok());
        assert!(IsUrl::validate("https://[::1]:8443/", "url").is_ok());

        // The old regex accepted anything non-whitespace after the scheme.
        assert!(IsUrl::validate("https://!!", "url").is_err());
        assert!(IsUrl::validate("https://", "url").is_err());
        // Only http(s); other schemes parse but are not web URLs.
        assert!(IsUrl::validate("ftp://example.com", "url").is_err());
        assert!(IsUrl::validate("javascript:alert(1)", "url").is_err());
        // Relative references are not absolute URLs.
        assert!(IsUrl::validate("/path/only", "url").is_err());
    }

    /// The WHATWG parser strips C0 controls *and spaces* before parsing, so a
    /// value carrying a CRLF or a stray space parses cleanly while the caller
    /// keeps the original — validating a string that was never examined. The
    /// caller then holds a CRLF to carry into whatever it does next, a
    /// `Location` header being the obvious route to response splitting, or an
    /// un-encoded space where the parser silently supplied `%20`.
    #[test]
    fn is_url_rejects_embedded_controls_and_spaces() {
        // Each of these parses successfully once the parser has stripped or
        // percent-encoded the offending characters, which is exactly why they
        // must be caught first.
        for value in [
            "https://a.example/\r\nX-Injected: 1",
            "http\n://evil.example/",
            "\u{11}http\n:L/x",
            "https://example.com/\tpath",
            "https://example.com/\u{0}",
            // Trimmed from both ends: not control characters, still normalised
            // away from what the caller kept.
            " https://example.com ",
            "https://example.com ",
            // Interior space: rewritten to `a%20b`, so again the parser
            // examined a different string than the one being approved.
            "https://example.com/a b",
        ] {
            assert!(
                url::Url::parse(value).is_ok(),
                "test case {value:?} no longer exercises the stripping behaviour"
            );
            assert!(
                IsUrl::validate(value, "url").is_err(),
                "IsUrl accepted {value:?}, which carries a control character or space"
            );
        }
    }

    /// RFC 9562 §4: the hex digits are case-insensitive on input, so an
    /// uppercase UUID is valid. The old regex was lowercase-only and also
    /// checked neither the version nor the variant nibble.
    #[test]
    fn test_is_uuid_case_and_version_variant() {
        let lower = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
        assert!(IsUuid::validate(lower, "id").is_ok());
        assert!(IsUuid::validate(&lower.to_uppercase(), "id").is_ok());
        assert!(IsUuid::validate("F47AC10B-58cc-4372-A567-0e02b2c3d479", "id").is_ok());

        // Nil and max UUIDs are valid despite carrying no version/variant.
        assert!(IsUuid::validate("00000000-0000-0000-0000-000000000000", "id").is_ok());
        assert!(IsUuid::validate("ffffffff-ffff-ffff-ffff-ffffffffffff", "id").is_ok());

        // Version 0 and version 9 do not exist.
        assert!(IsUuid::validate("f47ac10b-58cc-0372-a567-0e02b2c3d479", "id").is_err());
        assert!(IsUuid::validate("f47ac10b-58cc-9372-a567-0e02b2c3d479", "id").is_err());
        // Variant nibble must be 8/9/a/b.
        assert!(IsUuid::validate("f47ac10b-58cc-4372-c567-0e02b2c3d479", "id").is_err());

        assert!(IsUuid::validate("not-a-uuid", "id").is_err());
        assert!(IsUuid::validate("f47ac10b58cc4372a5670e02b2c3d479", "id").is_err());
    }

    #[test]
    fn test_is_alpha() {
        assert!(IsAlpha::validate("abcXYZ", "field").is_ok());
        assert!(IsAlpha::validate("abc123", "field").is_err());
        assert!(IsAlpha::validate("abc xyz", "field").is_err());
    }

    #[test]
    fn test_is_alphanumeric() {
        assert!(IsAlphanumeric::validate("abc123", "field").is_ok());
        assert!(IsAlphanumeric::validate("abc@123", "field").is_err());
        assert!(IsAlphanumeric::validate("test", "field").is_ok());
    }

    #[test]
    fn test_is_numeric() {
        assert!(IsNumeric::validate("12345", "field").is_ok());
        assert!(IsNumeric::validate("123.45", "field").is_err());
        assert!(IsNumeric::validate("abc", "field").is_err());
    }

    #[test]
    fn test_is_uuid() {
        assert!(IsUuid::validate("550e8400-e29b-41d4-a716-446655440000", "id").is_ok());
        assert!(IsUuid::validate("not-a-uuid", "id").is_err());
        assert!(IsUuid::validate("", "id").is_err());
    }

    #[test]
    fn test_not_empty_with_whitespace_only() {
        assert!(NotEmpty::validate("\t\n  \r", "field").is_err());
    }

    #[test]
    fn test_min_length_exact() {
        let validator = MinLength(5);
        assert!(validator.validate("exact", "field").is_ok());
        assert!(validator.validate("four", "field").is_err());
    }

    #[test]
    fn test_max_length_exact() {
        let validator = MaxLength(5);
        assert!(validator.validate("exact", "field").is_ok());
        assert!(validator.validate("sixsix", "field").is_err());
    }

    #[test]
    fn test_in_range_boundaries() {
        let validator = InRange {
            min: 0i32,
            max: 10i32,
        };
        assert!(validator.validate(0i32, "value").is_ok());
        assert!(validator.validate(10i32, "value").is_ok());
        assert!(validator.validate(-1i32, "value").is_err());
        assert!(validator.validate(11i32, "value").is_err());
    }

    #[test]
    fn test_email_variations() {
        assert!(IsEmail::validate("user+tag@example.com", "email").is_ok());
        assert!(IsEmail::validate("user.name@example.co.uk", "email").is_ok());
        assert!(IsEmail::validate("@example.com", "email").is_err());
        assert!(IsEmail::validate("user@", "email").is_err());
    }

    #[test]
    fn test_url_variations() {
        assert!(IsUrl::validate("https://example.com", "url").is_ok());
        assert!(IsUrl::validate("http://test.com/path", "url").is_ok());
        assert!(IsUrl::validate("//example.com", "url").is_err());
    }

    #[test]
    fn test_uuid_formats() {
        // UUID v4 format
        assert!(IsUuid::validate("123e4567-e89b-12d3-a456-426614174000", "id").is_ok());
        // Without hyphens should fail
        assert!(IsUuid::validate("123e4567e89b12d3a456426614174000", "id").is_err());
    }

    #[test]
    fn test_max_length_counts_characters_not_bytes() {
        // Three emoji = 3 characters but 12 bytes. Under a 5-char cap it must pass.
        let three_emoji = "😀😀😀";
        assert_eq!(three_emoji.chars().count(), 3);
        assert_eq!(three_emoji.len(), 12);
        assert!(MaxLength(5).validate(three_emoji, "field").is_ok());
        // A 2-char cap must still reject the 3 characters.
        assert!(MaxLength(2).validate(three_emoji, "field").is_err());
    }

    #[test]
    fn test_min_length_counts_characters_not_bytes() {
        // "café" is 4 characters but 5 bytes. MinLength(4) must accept it.
        let cafe = "café";
        assert_eq!(cafe.chars().count(), 4);
        assert_eq!(cafe.len(), 5);
        assert!(MinLength(4).validate(cafe, "field").is_ok());
        assert!(MinLength(5).validate(cafe, "field").is_err());
    }

    #[test]
    fn test_empty_string_validators() {
        // Empty strings fail because regex requires at least one character
        assert!(IsAlpha::validate("", "field").is_err());
        assert!(IsNumeric::validate("", "field").is_err());
        assert!(IsAlphanumeric::validate("", "field").is_err());
    }

    /// No validator may copy the client's input into its error: the error is
    /// what gets serialised into responses and logs.
    #[test]
    fn errors_never_carry_the_submitted_value() {
        let secret = "hunter2-SECRET";
        let errors = [
            MinLength(64).validate(secret, "f").unwrap_err(),
            MaxLength(2).validate(secret, "f").unwrap_err(),
            IsEmail::validate(secret, "f").unwrap_err(),
            IsUrl::validate(secret, "f").unwrap_err(),
            IsUuid::validate(secret, "f").unwrap_err(),
            IsAlpha::validate(secret, "f").unwrap_err(),
            IsAlphanumeric::validate(secret, "f").unwrap_err(),
            IsNumeric::validate(secret, "f").unwrap_err(),
            Matches::new("^x$")
                .unwrap()
                .validate(secret, "f")
                .unwrap_err(),
        ];
        for e in errors {
            assert!(e.value.is_none(), "{} attached the value", e.constraint);
            assert!(!e.message.contains(secret), "{}", e.message);
        }
        for e in [
            Min(10).validate(1, "f").unwrap_err(),
            Max(1.0).validate(9.5, "f").unwrap_err(),
            InRange { min: 1, max: 2 }.validate(3, "f").unwrap_err(),
            IsPositive::validate(-7, "f").unwrap_err(),
        ] {
            assert!(e.value.is_none(), "{} attached the value", e.constraint);
        }
    }

    /// NaN compares false against any bound, so `value < min` alone lets it
    /// through; `"NaN".parse::<f64>()` is how it arrives from a query string.
    #[test]
    fn numeric_validators_reject_non_finite_floats() {
        for v in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(Min(0.0).validate(v, "x").is_err(), "Min accepted {v}");
            assert!(Max(100.0).validate(v, "x").is_err(), "Max accepted {v}");
            assert!(
                InRange { min: 0.0, max: 1.0 }.validate(v, "x").is_err(),
                "InRange accepted {v}"
            );
            assert!(
                IsPositive::validate_f64(v, "x").is_err(),
                "IsPositive accepted {v}"
            );
        }
        assert!(Min(f32::MIN).validate(f32::NAN, "x").is_err());
        assert!(Min(0.5).validate(0.5, "x").is_ok());
        // A NaN bound admits nothing rather than everything.
        assert!(Min(f64::NAN).validate(-1e300, "x").is_err());
        assert!(Max(f64::NAN).validate(1e300, "x").is_err());
        assert!(
            InRange {
                min: f64::NAN,
                max: 1.0
            }
            .validate(0.5, "x")
            .is_err()
        );
        assert!(Max(0.5).validate(0.5, "x").is_ok());
    }

    #[test]
    fn numeric_validators_cover_all_primitive_types() {
        assert!(Min(18u32).validate(17, "age").is_err());
        assert!(Max(10i64).validate(10, "n").is_ok());
        assert!(
            InRange {
                min: 1usize,
                max: 3
            }
            .validate(2, "n")
            .is_ok()
        );
        assert!(IsPositive::validate(0u8, "n").is_err());
        assert!(IsPositive::validate(1i128, "n").is_ok());
        // Inverted bounds admit nothing.
        assert!(InRange { min: 10, max: 1 }.validate(5, "n").is_err());
    }

    #[test]
    fn not_empty_rejects_invisible_only_values() {
        for value in [
            "\u{200B}",
            "\u{200D}\u{200C}",
            "\u{FEFF}",
            "\u{2800}",
            "\u{3164}",
            "\u{115F}",
            "\u{00AD}",
            "\u{180E}",
            "\u{0301}",
            "\u{20E3}",
            "\u{1D159}",
            "\u{1F3FB}",
            "\u{FFFC}",
            "\u{05B0}",
            "\u{0483}",
            "\u{093C}",
            "\u{0E31}",
            "\u{3099}",
            "\u{202E}",
            "\0",
            " \u{200B}\t",
        ] {
            assert!(
                NotEmpty::validate(value, "name").is_err(),
                "accepted {value:?}"
            );
        }
        assert!(NotEmpty::validate("a\u{200B}", "name").is_ok());
        assert!(NotEmpty::validate("é", "name").is_ok());
        // Visible punctuation and letters inside the mark blocks.
        for visible in ["\u{05C0}", "\u{05C3}", "\u{093D}", "\u{0600}1"] {
            assert!(
                NotEmpty::validate(visible, "name").is_ok(),
                "rejected {visible:?}"
            );
        }
    }

    #[test]
    fn email_enforces_dot_atom_and_rfc5321_lengths() {
        for bad in [".a@x.io", "a.@x.io", "a..b@x.io", "a@b@c.io", "a b@x.io"] {
            assert!(IsEmail::validate(bad, "email").is_err(), "accepted {bad:?}");
        }
        let local_64 = "a".repeat(64);
        assert!(IsEmail::validate(&format!("{local_64}@x.io"), "email").is_ok());
        assert!(IsEmail::validate(&format!("a{local_64}@x.io"), "email").is_err());

        let domain = format!(
            "{}.{}.{}.io",
            "d".repeat(63),
            "d".repeat(63),
            "d".repeat(63)
        );
        let at_limit = format!("{}@{domain}", "a".repeat(254 - 1 - domain.len()));
        assert_eq!(at_limit.len(), 254);
        assert!(IsEmail::validate(&at_limit, "email").is_ok());
        assert!(IsEmail::validate(&format!("a{at_limit}"), "email").is_err());
    }

    /// Each of these parses, but the parser reads a different URL than the one
    /// written: the host is rewritten, or something the caller keeps is not
    /// what was examined.
    #[test]
    fn is_url_rejects_inputs_the_parser_rewrites() {
        for value in [
            // Missing or altered `//`.
            "https:evil.example",
            "https:/evil.example",
            "https:\\\\evil.example",
            "https:/\\evil.example",
            "https://evil.example\\x",
            // Userinfo.
            "https://trusted.example@evil.example/",
            "https://user:pass@evil.example/",
            // Host normalisation: percent-escapes, IDNA, IPv4 shorthand.
            "https://ex%61mple.com/",
            "https://exa\u{200B}mple.com/",
            "https://ex\u{AD}ample.com",
            "https://\u{FF45}xample.com",
            "https://ex\u{3002}ample.com/",
            "https://m\u{FC}nchen.de/",
            "http://0x7f.1/",
            "http://2130706433/",
            "http://127.1/",
            "http://[0:0::1]/",
            // Path or query the parser encodes or resolves.
            "https://example.com/<script>\"",
            "https://example.com/\u{202E}gnp.exe",
            "https://example.com/caf\u{E9}",
            "https://example.com/a/../admin",
            // Empty labels and ports.
            "https://a..b/",
            "https://.a/",
            "https://example.com:/",
            "https://example.com:99999/",
            "https://example.com:+80/",
            "https://example.com:0443/",
            "http://example.com:080/",
            "http://example.com:0/",
            "https://example.com//evil.example/x",
            "https://example.com/#a#b",
            "https://example.com/[x]",
            "https://example.com/#[x]",
            // Malformed percent-escapes.
            "https://example.com/%zz",
            "https://example.com/%",
            "https://example.com/a%2",
            "https://example.com/?a=%G1",
            // Over DNS length limits.
            "https://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example/",
        ] {
            assert!(
                IsUrl::validate(value, "url").is_err(),
                "IsUrl accepted {value:?}"
            );
        }
    }

    #[test]
    fn is_url_enforces_dns_length_limits() {
        let label = |n| "a".repeat(n);
        assert!(IsUrl::validate(&format!("https://{}.io/", label(63)), "url").is_ok());
        assert!(IsUrl::validate(&format!("https://{}.io/", label(64)), "url").is_err());
        // Four labels of 63 plus separators = 255 > 253.
        let long = [label(63), label(63), label(63), label(63)].join(".");
        assert!(IsUrl::validate(&format!("https://{long}/"), "url").is_err());
        let ok = [label(63), label(63), label(63), label(61)].join(".");
        assert_eq!(ok.len(), 253);
        assert!(IsUrl::validate(&format!("https://{ok}/"), "url").is_ok());
        assert!(IsUrl::validate(&format!("https://{ok}./"), "url").is_ok());
    }

    #[test]
    fn is_url_accepts_canonical_forms() {
        for value in [
            "https://example.com",
            "https://example.com/",
            "HTTPS://Example.COM/Path?q=1#frag",
            "http://example.com:80/",
            "https://example.com:8443/x",
            "https://[::1]:8443/",
            "http://127.0.0.1:6379/",
            "https://xn--mnchen-3ya.de/",
            "https://example.com/caf%C3%A9?a=b&c=d",
            "https://example.com.",
            "https://under_score.example/",
            // Query or fragment directly after the host: the parser inserts
            // the empty path's `/`, and that alone is not a rewrite.
            "https://example.com?x=1",
            "https://example.com#frag",
            "https://example.com:8443?x",
            "https://example.com/%2F",
            "https://api.example/items?page[size]=10&filter[name]=x",
        ] {
            assert!(
                IsUrl::validate(value, "url").is_ok(),
                "IsUrl rejected {value:?}"
            );
        }
    }

    #[test]
    fn matches_is_unanchored_and_full_is_anchored() {
        assert!(
            Matches::new("[a-z]+")
                .unwrap()
                .validate("1<x>a", "f")
                .is_ok()
        );
        let full = Matches::full("[a-z]+").unwrap();
        assert!(full.validate("abc", "f").is_ok());
        assert!(full.validate("1<x>a", "f").is_err());
        // Alternation must stay inside the anchors.
        // An unbalanced pattern must not escape the anchors.
        assert!(Matches::full("a)|(?:b").is_err());
        assert!(Matches::full("[a-z]+)|(?:x").is_err());
        // Nor when its anchored form was cached through `new`.
        Matches::new(r"\A(?:a)|(?:b)\z").unwrap();
        assert!(Matches::full("a)|(?:b").is_err());
        let alt = Matches::full("a|b").unwrap();
        assert!(alt.validate("ab", "f").is_err());
        assert!(alt.validate("b", "f").is_ok());
    }

    /// On a private cache, so other tests' entries in the global one are not
    /// evicted mid-assertion.
    #[test]
    fn matches_cache_stays_within_entry_and_byte_bounds() {
        let regex = Regex::new("x").unwrap();
        let mut cache = PatternCache::default();
        for i in 0..(CACHE_ENTRIES + 50) {
            cache.insert((false, format!("s{i}")), regex.clone(), SIZE_CLASSES[0]);
        }
        assert_eq!(cache.entries.len(), CACHE_ENTRIES);
        for i in 0..100 {
            cache.insert(
                (false, format!("l{i}")),
                regex.clone(),
                weigh(DEFAULT_COMPILED),
            );
        }
        assert!(cache.weight <= CACHE_BUDGET, "weight {}", cache.weight);
        let summed: usize = cache.entries.values().map(|e| e.weight).sum();
        assert_eq!(summed, cache.weight);
        assert_eq!(cache.ring.len(), cache.entries.len());
    }

    /// A pattern first inserted while the cache is full and churning must
    /// survive until its next use: new entries go behind the CLOCK hand.
    #[test]
    fn matches_cache_keeps_entries_inserted_during_churn() {
        let regex = Regex::new("x").unwrap();
        let mut cache = PatternCache::default();
        for i in 0..CACHE_ENTRIES {
            cache.insert((false, format!("fill{i}")), regex.clone(), SIZE_CLASSES[0]);
        }
        let late = (false, "late".to_string());
        let mut misses = 0;
        for round in 0..50 {
            if cache.get(&late).is_none() {
                misses += 1;
                cache.insert(late.clone(), regex.clone(), SIZE_CLASSES[0]);
            }
            for k in 0..10 {
                cache.insert(
                    (false, format!("cold{round}-{k}")),
                    regex.clone(),
                    SIZE_CLASSES[0],
                );
            }
        }
        assert_eq!(misses, 1, "late entry was evicted before reuse");
    }

    /// Concurrent misses on one pattern compile it once: the rest wait for
    /// the first and are served from the cache.
    #[test]
    fn matches_cache_single_flight() {
        let pattern = r"^single-flight-[\w.-]{3,32}$";
        let threads: Vec<_> = (0..8)
            .map(|_| std::thread::spawn(move || Matches::new(pattern).unwrap()))
            .collect();
        for t in threads {
            assert!(t.join().unwrap().validate("single-flight-abc", "f").is_ok());
        }
        assert!(Matches::cached(false, pattern));
        let key = (false, pattern.to_owned());
        assert!(!MATCHES_INFLIGHT.lock().unwrap().contains(&key));
    }

    /// A working set that fits survives a stream of one-off patterns: CLOCK
    /// gives referenced entries a second chance.
    #[test]
    fn matches_cache_keeps_hot_entries() {
        let regex = Regex::new("x").unwrap();
        let mut cache = PatternCache::default();
        let hot: Vec<PatternKey> = (0..20).map(|i| (false, format!("hot{i}"))).collect();
        for key in &hot {
            cache.insert(key.clone(), regex.clone(), 4 * 1024 * 1024);
        }
        for i in 0..1000 {
            for key in &hot {
                assert!(cache.get(key).is_some(), "hot entry {key:?} evicted at {i}");
            }
            cache.insert((false, format!("cold{i}")), regex.clone(), 4 * 1024 * 1024);
        }
    }

    /// Unicode classes with a bounded repeat compile to megabytes; they are
    /// the common shape of a derive `regex` rule and must still be cached.
    #[test]
    fn matches_caches_large_unicode_patterns() {
        let pattern = r"^[\w.-]{3,32}$";
        assert!(
            Matches::new(pattern)
                .unwrap()
                .validate("user.name", "f")
                .is_ok()
        );
        assert!(Matches::cached(false, pattern));
        assert!(Matches::full(r"[\w.-]{3,32}").is_ok());
        assert!(Matches::cached(true, r"[\w.-]{3,32}"));
    }

    #[test]
    fn matches_full_supports_verbose_mode_ending_in_newline() {
        assert!(Matches::full("(?x) [a-z]+ # letters").is_err());
        let m = Matches::full("(?x) [a-z]+ # letters\n").unwrap();
        assert!(m.validate("abc", "f").is_ok());
        assert!(m.validate("abc1", "f").is_err());
    }

    #[test]
    fn matches_new_reuses_compiled_patterns_and_reports_bad_ones() {
        let pattern = "^cache-me-[0-9]+$";
        let a = Matches::new(pattern).unwrap();
        assert!(Matches::cached(false, pattern));
        assert!(a.validate("cache-me-42", "f").is_ok());
        let long = format!("^{}$", "x".repeat(MAX_PATTERN));
        assert!(Matches::new(&long).is_ok());
        assert!(
            !Matches::cached(false, &long),
            "oversized pattern was cached"
        );
        assert!(Matches::new("(unclosed").is_err());
        // A failed compile is not cached as a success.
        assert!(Matches::new("(unclosed").is_err());
    }
}

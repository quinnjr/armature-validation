//! Fuzz the string validators.
//!
//! These run on request bodies and query parameters, so every one of them sees
//! attacker-chosen text. Several are regex-backed and one (`IsUrl`) delegates
//! to a real URL parser, which is where the interesting behaviour is: a
//! validator that *accepts* something the rest of the system then treats as
//! trusted is the failure that matters, not one that rejects too much.
//!
//! Beyond absence of panics, the checks here are cross-validations — places
//! where two independent implementations must agree about the same string:
//!
//! * anything `IsUuid` accepts must parse as a UUID;
//! * anything `IsUrl` accepts must parse as an absolute `http`/`https` URL,
//!   which is the property its doc claims and the reason it exists rather than
//!   a bare regex — and must be a string the parser did not have to rewrite:
//!   ASCII, free of spaces and backslashes, without userinfo, and naming the
//!   parsed host verbatim;
//! * `IsEmail` must respect the RFC 5321 length limits and dot rules;
//! * the numeric validators must never accept a NaN or an infinity, read here
//!   from the input's leading bytes as both an `f64` and an `f32`;
//! * `Matches::full` must anchor to the whole value;
//! * `ValidationPipe::parse_strict` must not panic on any `Content-Type`
//!   bytes, must refuse a repeated header, and must accept exactly the JSON
//!   media types;
//! * `IsAlpha`, `IsAlphanumeric` and `IsNumeric` must agree with Rust's own
//!   character classification, and must not disagree with each other;
//! * `MinLength` and `MaxLength` must bound `char`s rather than bytes, which
//!   only text outside ASCII can tell apart.
//!
//! Nothing here re-derives a bound with the same expression the validator uses
//! — an assertion that restates the implementation cannot fail, so it would
//! cost fuzzing time without covering anything.

#![no_main]

use armature_validation::{
    InRange, IsAlpha, IsAlphanumeric, IsEmail, IsNumeric, IsPositive, IsUrl, IsUuid, Matches, Max,
    MaxLength, Min, MinLength, NotEmpty,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Every bit pattern is a float, NaNs and infinities included; none of the
    // bounds may let a non-finite one through.
    if let Some(bytes) = data.get(..4) {
        let x = f32::from_le_bytes(bytes.try_into().unwrap());
        let accepted = [
            Min(f32::MIN).validate(x, "n").is_ok(),
            Max(f32::MAX).validate(x, "n").is_ok(),
            InRange {
                min: f32::MIN,
                max: f32::MAX,
            }
            .validate(x, "n")
            .is_ok(),
            IsPositive::validate(x, "n").is_ok(),
        ];
        assert!(
            x.is_finite() || !accepted.contains(&true),
            "a numeric validator accepted non-finite f32 {x}: {accepted:?}",
        );
    }
    if let Some(bytes) = data.get(..8) {
        let x = f64::from_le_bytes(bytes.try_into().unwrap());
        let accepted = [
            Min(f64::MIN).validate(x, "n").is_ok(),
            Max(f64::MAX).validate(x, "n").is_ok(),
            InRange {
                min: f64::MIN,
                max: f64::MAX,
            }
            .validate(x, "n")
            .is_ok(),
            IsPositive::validate(x, "n").is_ok(),
        ];
        assert!(
            x.is_finite() || !accepted.contains(&true),
            "a numeric validator accepted non-finite {x}: {accepted:?}",
        );
    }

    // `parse_strict` reads a client-supplied header: arbitrary bytes there
    // must be a 415 or a parse result, never a panic, and the verdict must
    // match an independent statement of "a single JSON media type".
    {
        struct Dto;
        impl<'de> serde::Deserialize<'de> for Dto {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                serde::de::IgnoredAny::deserialize(d).map(|_| Dto)
            }
        }
        impl armature_validation::Validate for Dto {
            fn validate(&self) -> Result<(), Vec<armature_validation::ValidationError>> {
                Ok(())
            }
        }
        // A newline splits the input into two header lines, as a client
        // sending the field twice would.
        let lines: Vec<&[u8]> = data.splitn(2, |&b| b == b'\n').collect();
        let mut req = armature_core::HttpRequest::new("POST", "/".to_string());
        for line in &lines {
            req.headers.append("content-type", *line);
        }
        req.body = armature_core::Bytes::from_static(b"{}");
        let accepted = armature_validation::ValidationPipe::parse_strict::<Dto>(&req).is_ok();
        let expected = lines.len() == 1 && is_json_media_type(lines[0]);
        assert_eq!(
            accepted, expected,
            "parse_strict on Content-Type {lines:?}: accepted {accepted}, expected {expected}",
        );
    }

    let Ok(value) = std::str::from_utf8(data) else {
        return;
    };
    if value.len() > 4096 {
        return;
    }

    const FIELD: &str = "field";

    // None of these may panic on arbitrary text.
    let is_email = IsEmail::validate(value, FIELD).is_ok();
    let is_url = IsUrl::validate(value, FIELD).is_ok();
    let is_uuid = IsUuid::validate(value, FIELD).is_ok();
    let is_alpha = IsAlpha::validate(value, FIELD).is_ok();
    let is_alnum = IsAlphanumeric::validate(value, FIELD).is_ok();
    let is_numeric = IsNumeric::validate(value, FIELD).is_ok();

    // A UUID this validator accepts must be one the UUID parser accepts.
    // Downstream code calls `Uuid::parse_str` on validated input, so a
    // disagreement means a value passes validation and then fails to parse.
    if is_uuid {
        assert!(
            uuid::Uuid::parse_str(value).is_ok(),
            "IsUuid accepted {value:?}, which does not parse as a UUID",
        );
    }

    // `IsUrl` documents that it accepts only absolute http/https URLs, and
    // that it rejects control characters. The second half matters more than it
    // looks: the WHATWG parser strips C0 controls *before* parsing, so a value
    // carrying a CRLF parses cleanly while the caller keeps the original —
    // approving a string that was never examined, and handing on a CRLF that
    // becomes response splitting in a `Location` header.
    if is_url {
        assert!(
            !value.chars().any(|c| c.is_control()),
            "IsUrl accepted {value:?}, which carries a control character",
        );
        // Re-parsed here rather than compared against a hand-rolled split:
        // matching `://` textually is not what the parser does, and asserting
        // it would report the difference between the two as a validator bug.
        let parsed = url::Url::parse(value).ok();
        let scheme = parsed.as_ref().map(|u| u.scheme().to_owned());
        assert!(
            matches!(scheme.as_deref(), Some("http") | Some("https")),
            "IsUrl accepted {value:?}, whose parsed scheme is {scheme:?}",
        );
        let parsed = parsed.unwrap();
        // The parser rewrites non-ASCII text, spaces and backslashes, and a
        // userinfo makes people read the wrong host, so none may survive.
        assert!(
            value.is_ascii() && !value.contains([' ', '\\']),
            "IsUrl accepted {value:?}, which the parser would rewrite",
        );
        assert!(
            parsed.username().is_empty() && parsed.password().is_none(),
            "IsUrl accepted {value:?}, which carries userinfo",
        );
        // The host the parser settled on must be the one written, so a
        // percent-escaped, IDNA-mapped or shorthand host cannot pass.
        let host = parsed.host_str().unwrap_or_default().to_ascii_lowercase();
        assert!(
            value.to_ascii_lowercase().contains(&format!("//{host}")),
            "IsUrl accepted {value:?}, whose parsed host {host:?} is not written in it",
        );
        // The whole-string form of the contract: the serialisation is the
        // input with only the changes the parser may make without changing
        // meaning (lower-case scheme and host, an elided default port, the
        // empty path's `/`).
        assert_eq!(
            parsed.as_str(),
            canonical_url(value),
            "IsUrl accepted {value:?}, which the parser rewrote",
        );
        // Every `%` starts a two-hex-digit escape.
        let bytes = value.as_bytes();
        assert!(
            bytes.iter().enumerate().all(|(i, &b)| b != b'%'
                || bytes
                    .get(i + 1..i + 3)
                    .is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit))),
            "IsUrl accepted {value:?}, which has a malformed percent-escape",
        );
    }

    // `Matches::full` anchors to the whole value: the escaped value matches
    // itself and nothing longer. Kept short, since each input compiles a regex.
    if value.len() <= 32 {
        let full = Matches::full(&regex::escape(value)).expect("an escaped literal compiles");
        assert!(
            full.validate(value, FIELD).is_ok(),
            "full({value:?}) rejected itself"
        );
        let longer = format!("{value}x");
        assert!(
            full.validate(&longer, FIELD).is_err(),
            "full({value:?}) accepted {longer:?}",
        );
    }

    // Character-class validators must agree with the standard library, and are
    // documented as requiring a non-empty run of the relevant class.
    if is_alpha {
        assert!(
            !value.is_empty() && value.chars().all(|c| c.is_alphabetic()),
            "IsAlpha accepted {value:?}",
        );
        assert!(
            is_alnum,
            "IsAlpha accepted {value:?} but IsAlphanumeric did not"
        );
    }
    if is_numeric {
        assert!(
            !value.is_empty() && value.chars().all(|c| c.is_numeric()),
            "IsNumeric accepted {value:?}",
        );
    }
    if is_alnum {
        assert!(
            !value.is_empty() && value.chars().all(|c| c.is_alphanumeric()),
            "IsAlphanumeric accepted {value:?}",
        );
    }

    // An email must at least be non-empty; the regex is the definition of the
    // rest, so asserting a second pattern here would only restate it.
    // RFC 5321 limits and the dot-atom shape of the local part.
    if is_email {
        let (local, _) = value
            .rsplit_once('@')
            .unwrap_or_else(|| panic!("IsEmail accepted {value:?}, which has no `@`"));
        assert!(
            value.len() <= 254 && !local.is_empty() && local.len() <= 64,
            "IsEmail accepted {value:?}, which exceeds the RFC 5321 limits",
        );
        assert!(
            !local.starts_with('.') && !local.ends_with('.') && !local.contains(".."),
            "IsEmail accepted {value:?}, whose local part has a stray dot",
        );
    }

    // `NotEmpty` is documented as rejecting input that is empty or whitespace
    // only. Stated as a property of the characters rather than as a second call
    // to `trim`, so that a validator narrowed to a plain emptiness check — which
    // would still agree with `trim` on every ASCII-space-free input — is caught.
    if NotEmpty::validate(value, FIELD).is_ok() {
        assert!(
            value.chars().any(|c| !c.is_whitespace()),
            "NotEmpty accepted {value:?}, which holds no non-whitespace character",
        );
    }

    // Length bounds count `char`s, not bytes, and the plausible regression is a
    // slip to `value.len()`. That is invisible on ASCII and shows up only where
    // `bytes > chars`, so both bounds are asserted at the point where the two
    // measures disagree: the fuzzer supplies the multi-byte text that separates
    // them. Comparing the validator against a bound recomputed with its own
    // `chars().count()` expression would be true by construction instead.
    let chars = value.chars().count();
    let bytes = value.len();
    // A byte-counting `MaxLength` rejects here as soon as any character needs
    // more than one byte, since it sees `bytes > chars`.
    assert!(
        MaxLength(chars).validate(value, FIELD).is_ok(),
        "MaxLength({chars}) rejected a {chars}-char value of {bytes} bytes: {value:?}",
    );
    // The same divergence from below: no value can satisfy a minimum one
    // character longer than itself, but a byte-counting check is satisfied
    // whenever `bytes >= chars + 1`.
    assert!(
        MinLength(chars + 1).validate(value, FIELD).is_err(),
        "MinLength({}) accepted a {chars}-char value of {bytes} bytes: {value:?}",
        chars + 1,
    );
});

/// `value` (an ASCII `scheme://authority[tail]` string) with the only rewrites
/// a WHATWG parser may apply to a URL `IsUrl` accepts.
fn canonical_url(value: &str) -> String {
    let (scheme, rest) = value.split_once("://").expect("IsUrl requires `://`");
    let scheme = scheme.to_ascii_lowercase();
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let mut authority = authority.to_ascii_lowercase();
    let default = if scheme == "https" { ":443" } else { ":80" };
    if authority.ends_with(default) {
        authority.truncate(authority.len() - default.len());
    }
    let tail = if tail.starts_with('/') {
        tail.to_owned()
    } else {
        format!("/{tail}")
    };
    format!("{scheme}://{authority}{tail}")
}

/// RFC 9110 `media-type` naming JSON: `application/json` or
/// `application/<token>+json`, ignoring parameters and surrounding SP/HTAB.
/// Written with `str` operations rather than the validator's byte loops.
fn is_json_media_type(value: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(value) else {
        // Non-UTF-8 bytes in the parameters are allowed; the media type
        // itself must be ASCII, which the token check below enforces.
        let media = value.split(|&b| b == b';').next().unwrap_or_default();
        return std::str::from_utf8(media).is_ok_and(|m| is_json_media_type(m.as_bytes()));
    };
    let media = text
        .split(';')
        .next()
        .unwrap_or("")
        .trim_matches([' ', '\t']);
    let lower = media.to_ascii_lowercase();
    let Some(sub) = lower.strip_prefix("application/") else {
        return false;
    };
    let token = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c))
    };
    token(sub) && (sub == "json" || sub.strip_suffix("+json").is_some_and(|p| !p.is_empty()))
}

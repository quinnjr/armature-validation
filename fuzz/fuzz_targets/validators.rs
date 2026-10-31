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
//!   from the input's leading bytes;
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
    InRange, IsAlpha, IsAlphanumeric, IsEmail, IsNumeric, IsPositive, IsUrl, IsUuid, Max,
    MaxLength, Min, MinLength, NotEmpty,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Every bit pattern is a float, NaNs and infinities included; none of the
    // bounds may let a non-finite one through.
    if let Some(bytes) = data.get(..8) {
        let x = f64::from_le_bytes(bytes.try_into().unwrap());
        let accepted = [
            Min(f64::MIN).validate(x, "n").is_ok(),
            Max(f64::MAX).validate(x, "n").is_ok(),
            InRange { min: f64::MIN, max: f64::MAX }.validate(x, "n").is_ok(),
            IsPositive::validate(x, "n").is_ok(),
        ];
        assert!(
            x.is_finite() || !accepted.contains(&true),
            "a numeric validator accepted non-finite {x}: {accepted:?}",
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
    }

    // Character-class validators must agree with the standard library, and are
    // documented as requiring a non-empty run of the relevant class.
    if is_alpha {
        assert!(
            !value.is_empty() && value.chars().all(|c| c.is_alphabetic()),
            "IsAlpha accepted {value:?}",
        );
        assert!(is_alnum, "IsAlpha accepted {value:?} but IsAlphanumeric did not");
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

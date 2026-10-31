// Validation pipe for automatic request validation

use crate::{Validate, ValidationErrors};
use armature_core::{Error, HttpRequest, HttpResponse};
use serde::de::DeserializeOwned;

/// Validation pipe that validates request bodies
pub struct ValidationPipe;

impl ValidationPipe {
    /// Validate and parse request body.
    ///
    /// Both failure paths produce a 400 whose client-facing text carries no
    /// submitted value:
    ///
    /// - a body that does not deserialize maps to [`Error::Deserialization`],
    ///   which `armature-core` replaces with a generic message for the client.
    ///   The error carries only serde's error category and position, not its
    ///   message: that quotes the offending input and names fields and enum
    ///   variants of the target type, and core logs the detail;
    /// - a body that fails validation maps to [`Error::Validation`] with
    ///   [`ValidationErrors::client_message`], i.e. `field: message` pairs only.
    pub fn parse<T>(req: &HttpRequest) -> Result<T, Error>
    where
        T: DeserializeOwned + Validate,
    {
        let parsed: T =
            // Only the error's category and position: serde's message quotes the
            // offending input, and `armature-core` logs `Deserialization` detail.
            serde_json::from_slice(&req.body).map_err(|e| {
                Error::Deserialization(format!(
                    "{:?} error at line {} column {}",
                    e.classify(),
                    e.line(),
                    e.column()
                ))
            })?;

        parsed.validate().map_err(validation_error)?;

        Ok(parsed)
    }

    /// Like [`parse`](Self::parse), but first requires a JSON `Content-Type`
    /// (`application/json` or any `application/*+json`), failing with
    /// [`Error::UnsupportedMediaType`] (415) otherwise.
    ///
    /// `parse` reads any body as JSON. A cross-site HTML form can send a JSON
    /// body as `text/plain` without a CORS preflight, so an endpoint that
    /// authenticates by cookie and uses `parse` accepts forged requests. Use
    /// this method for such endpoints.
    pub fn parse_strict<T>(req: &HttpRequest) -> Result<T, Error>
    where
        T: DeserializeOwned + Validate,
    {
        let is_json = req.headers.get("content-type").is_some_and(|ct| {
            let media = ct.split(';').next().unwrap_or("").trim();
            media.eq_ignore_ascii_case("application/json")
                || media
                    .get(..12)
                    .is_some_and(|p| p.eq_ignore_ascii_case("application/"))
                    && media.len() > 17
                    && media[media.len() - 5..].eq_ignore_ascii_case("+json")
        });
        if !is_json {
            return Err(Error::UnsupportedMediaType(
                "expected a JSON Content-Type".to_string(),
            ));
        }
        Self::parse(req)
    }

    /// Transform validation errors to an HTTP 400 response.
    ///
    /// The body is [`ValidationErrors::to_json`], which never includes the
    /// submitted values.
    pub fn error_response(errors: ValidationErrors) -> HttpResponse {
        HttpResponse::from_parts(
            400,
            std::collections::HashMap::from([(
                "Content-Type".to_string(),
                "application/json".to_string(),
            )]),
            errors.to_json().to_string().into_bytes(),
        )
    }
}

/// The client-safe `Error` for a failed validation; shared with [`validate!`].
#[doc(hidden)]
pub fn validation_error(errors: Vec<crate::ValidationError>) -> Error {
    Error::Validation(ValidationErrors::from(errors).client_message())
}

/// Validate a DTO in a handler, returning early with a 400 on failure.
///
/// Expands to a `?` on the DTO's [`Validate::validate`], so it must be used in
/// a function returning `Result<_, armature_core::Error>`. The error carries
/// `field: message` pairs only, never the submitted values.
///
/// ```
/// use armature_validation::{validate, Validate, ValidationError};
///
/// struct Dto { name: String }
///
/// impl Validate for Dto {
///     fn validate(&self) -> Result<(), Vec<ValidationError>> {
///         if self.name.is_empty() {
///             Err(vec![ValidationError::new("name", "name is required")])
///         } else {
///             Ok(())
///         }
///     }
/// }
///
/// fn handler(dto: Dto) -> Result<(), armature_core::Error> {
///     validate!(dto);
///     Ok(())
/// }
///
/// assert!(handler(Dto { name: "x".into() }).is_ok());
/// assert!(handler(Dto { name: String::new() }).is_err());
/// ```
#[macro_export]
macro_rules! validate {
    ($dto:expr) => {{ $crate::Validate::validate(&$dto).map_err($crate::validation_error)? }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Validate, ValidationError};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    struct TestDto {
        name: String,
        age: i32,
    }

    impl Validate for TestDto {
        fn validate(&self) -> Result<(), Vec<ValidationError>> {
            let mut errors = Vec::new();

            if self.name.is_empty() {
                errors.push(ValidationError::new("name", "Name is required"));
            }

            if self.age < 0 {
                errors.push(ValidationError::new("age", "Age must be positive"));
            }

            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors)
            }
        }
    }

    #[test]
    fn test_validation_pipe() {
        let valid_dto = TestDto {
            name: "John".to_string(),
            age: 30,
        };

        let json = serde_json::to_vec(&valid_dto).unwrap();
        let mut req = HttpRequest::new("POST", "/test".to_string());
        req.body = armature_core::Bytes::from(json);

        let result: Result<TestDto, Error> = ValidationPipe::parse(&req);
        assert!(result.is_ok());
    }

    fn request(body: &str) -> HttpRequest {
        let mut req = HttpRequest::new("POST", "/test".to_string());
        req.body = armature_core::Bytes::from(body.to_owned());
        req
    }

    /// A rejected value must not come back to the client, even when the
    /// validator attached it to the error.
    #[test]
    fn validation_failure_does_not_echo_submitted_values() {
        #[derive(Debug, Deserialize)]
        struct Login {
            password: String,
        }
        impl Validate for Login {
            fn validate(&self) -> Result<(), Vec<ValidationError>> {
                Err(vec![
                    ValidationError::new("password", "password is too short")
                        .with_value(self.password.clone()),
                ])
            }
        }

        let err = ValidationPipe::parse::<Login>(&request(r#"{"password":"hunter2"}"#))
            .expect_err("validation must fail");
        assert!(matches!(err, Error::Validation(_)));
        let client = err.client_message();
        assert!(!client.contains("hunter2"), "{client}");
        assert!(client.contains("password is too short"), "{client}");
    }

    /// serde's error text quotes the input and names the target type's fields;
    /// the pipe must hand it to `Error::Deserialization`, which core redacts.
    #[test]
    fn invalid_json_is_redacted_for_the_client() {
        let err = ValidationPipe::parse::<TestDto>(&request(r#"{"name":"x","age":"SECRET-123"}"#))
            .expect_err("type mismatch must fail");
        assert!(matches!(err, Error::Deserialization(_)));
        let client = err.client_message();
        assert!(!client.contains("SECRET-123"), "{client}");
        assert!(!client.contains("age"), "{client}");
        // Nor in the detail core logs.
        let logged = err.to_string();
        assert!(!logged.contains("SECRET-123"), "{logged}");
    }

    #[test]
    fn parse_strict_requires_json_content_type() {
        let body = r#"{"name":"x","age":1}"#;
        for (ct, ok) in [
            (None, false),
            (Some("text/plain"), false),
            (Some("application/x-www-form-urlencoded"), false),
            (Some("multipart/form-data; boundary=x"), false),
            (Some("application/json"), true),
            (Some("Application/JSON; charset=utf-8"), true),
            (Some("application/problem+json"), true),
            (Some("application/+json"), false),
            (Some("text/+json"), false),
        ] {
            let mut req = request(body);
            if let Some(ct) = ct {
                req.headers.insert("content-type", ct);
            }
            let result = ValidationPipe::parse_strict::<TestDto>(&req);
            assert_eq!(result.is_ok(), ok, "{ct:?}");
            if !ok {
                assert!(matches!(result, Err(Error::UnsupportedMediaType(_))));
            }
        }
    }

    #[test]
    fn error_response_omits_values() {
        let errors = ValidationErrors::new(vec![
            ValidationError::new("password", "too short").with_value("hunter2"),
        ]);
        let response = ValidationPipe::error_response(errors);
        assert_eq!(response.status, 400);
        let body = String::from_utf8(response.body.to_vec()).unwrap();
        assert!(!body.contains("hunter2"), "{body}");
        assert!(body.contains("too short"), "{body}");
    }

    #[test]
    fn validate_macro_returns_client_safe_error() {
        fn handler(dto: TestDto) -> Result<TestDto, Error> {
            validate!(dto);
            Ok(dto)
        }
        let err = handler(TestDto {
            name: String::new(),
            age: 1,
        })
        .expect_err("empty name must fail");
        assert!(matches!(err, Error::Validation(_)));
        assert!(err.client_message().contains("Name is required"));
    }
}

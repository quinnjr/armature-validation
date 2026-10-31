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
    ///   serde's own text quotes the offending input and names fields and enum
    ///   variants of the target type, so it must not be passed through;
    /// - a body that fails validation maps to [`Error::Validation`] with
    ///   [`ValidationErrors::client_message`], i.e. `field: message` pairs only.
    pub fn parse<T>(req: &HttpRequest) -> Result<T, Error>
    where
        T: DeserializeOwned + Validate,
    {
        let parsed: T =
            serde_json::from_slice(&req.body).map_err(|e| Error::Deserialization(e.to_string()))?;

        parsed.validate().map_err(validation_error)?;

        Ok(parsed)
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

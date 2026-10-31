// Validation errors

use std::fmt;

/// Validation error for a single field
///
/// `Debug` redacts [`value`](Self::value): an error list is routinely logged or
/// formatted with `{:?}`, and the value is whatever the client submitted, a
/// password or token included.
#[derive(Clone)]
pub struct ValidationError {
    /// Field name that failed validation
    pub field: String,

    /// Error message
    pub message: String,

    /// Validation constraint that failed
    pub constraint: String,

    /// Value that failed validation (optional).
    ///
    /// The built-in validators never set this: the value is client input, and
    /// copying it into an error that may be serialised into a response or a log
    /// reflects passwords and tokens back out. Attach it with
    /// [`with_value`](Self::with_value) only for fields known to be
    /// non-sensitive. Even then it is left out of [`ValidationErrors::to_json`]
    /// unless [`ValidationErrors::to_json_with_values`] is used.
    pub value: Option<String>,
}

impl ValidationError {
    /// Create a new validation error.
    ///
    /// `field` and `message` are sent to clients as written, so do not build
    /// either from the submitted value (`format!("{v} is invalid")` reflects
    /// it back); use [`with_value`](Self::with_value), which is redacted.
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        let field = field.into();
        Self {
            constraint: "custom".to_string(),
            message: message.into(),
            field,
            value: None,
        }
    }

    /// Set the constraint name
    pub fn with_constraint(mut self, constraint: impl Into<String>) -> Self {
        self.constraint = constraint.into();
        self
    }

    /// Set the invalid value
    pub fn with_value(mut self, value: impl Into<String>) -> Self {
        self.value = Some(value.into());
        self
    }
}

impl fmt::Debug for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ValidationError")
            .field("field", &self.field)
            .field("message", &self.message)
            .field("constraint", &self.constraint)
            .field("value", &self.value.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

impl std::error::Error for ValidationError {}

/// Collection of validation errors
#[derive(Debug, Clone)]
pub struct ValidationErrors {
    pub errors: Vec<ValidationError>,
}

impl ValidationErrors {
    /// Create a new validation errors collection
    pub fn new(errors: Vec<ValidationError>) -> Self {
        Self { errors }
    }

    /// Check if there are any errors
    pub fn is_empty(&self) -> bool {
        self.errors.is_empty()
    }

    /// Get the number of errors
    pub fn len(&self) -> usize {
        self.errors.len()
    }

    /// Add an error
    pub fn add(&mut self, error: ValidationError) {
        self.errors.push(error);
    }

    /// Get errors for a specific field
    pub fn get_field_errors(&self, field: &str) -> Vec<&ValidationError> {
        self.errors.iter().filter(|e| e.field == field).collect()
    }

    /// Convert to a JSON representation that is safe to send to a client.
    ///
    /// Each error carries `field`, `message` and `constraint`. The submitted
    /// [`value`](ValidationError::value) is never included, since it is the
    /// client's own input (possibly a password) and echoing it also lets one
    /// large rejected field inflate the response. Use
    /// [`to_json_with_values`](Self::to_json_with_values) to opt in.
    pub fn to_json(&self) -> serde_json::Value {
        self.json(false)
    }

    /// Like [`to_json`](Self::to_json), but also includes each error's
    /// [`value`](ValidationError::value) where one was attached.
    ///
    /// Only use this when every field that may carry a value is known to be
    /// non-sensitive.
    pub fn to_json_with_values(&self) -> serde_json::Value {
        self.json(true)
    }

    fn json(&self, with_values: bool) -> serde_json::Value {
        serde_json::json!({
            "errors": self.errors.iter().map(|e| {
                let mut entry = serde_json::json!({
                    "field": e.field,
                    "message": e.message,
                    "constraint": e.constraint,
                });
                if with_values && let Some(value) = &e.value {
                    entry["value"] = serde_json::Value::String(value.clone());
                }
                entry
            }).collect::<Vec<_>>()
        })
    }

    /// A one-line summary that is safe to send to a client: each error's
    /// message, prefixed with `field: ` unless the message already names the
    /// field (as the built-in validators' do), joined with `"; "`. Never
    /// includes the submitted [`value`](ValidationError::value).
    ///
    /// At most [`CLIENT_MESSAGE_MAX_ERRORS`](Self::CLIENT_MESSAGE_MAX_ERRORS)
    /// errors are listed, followed by a count of the rest, so a body that
    /// fails thousands of nested checks does not produce a message of the
    /// same size.
    pub fn client_message(&self) -> String {
        let shown = self.errors.len().min(Self::CLIENT_MESSAGE_MAX_ERRORS);
        let mut message = self.errors[..shown]
            .iter()
            .map(|e| {
                // "email must be…" already names the field; "emails…" or an
                // empty field name does not.
                let names_field = !e.field.is_empty()
                    && e.message.strip_prefix(&e.field).is_some_and(|rest| {
                        rest.chars().next().is_none_or(|c| !c.is_alphanumeric() && c != '_')
                    });
                if names_field {
                    e.message.clone()
                } else {
                    e.to_string()
                }
            })
            .collect::<Vec<_>>()
            .join("; ")
            // One line: a control character in a caller-written field or
            // message must not start a new log line or header.
            .replace(
                |c: char| c.is_control() || matches!(c, '\u{2028}' | '\u{2029}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'),
                " ",
            );
        if self.errors.len() > shown {
            message.push_str(&format!(" (and {} more)", self.errors.len() - shown));
        }
        message
    }

    /// The most errors [`client_message`](Self::client_message) lists.
    pub const CLIENT_MESSAGE_MAX_ERRORS: usize = 20;
}

impl fmt::Display for ValidationErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for error in &self.errors {
            writeln!(f, "{}", error)?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationErrors {}

impl From<Vec<ValidationError>> for ValidationErrors {
    fn from(errors: Vec<ValidationError>) -> Self {
        Self::new(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn errors() -> ValidationErrors {
        ValidationErrors::new(vec![
            ValidationError::new("password", "password is too short").with_value("hunter2"),
            ValidationError::new("age", "must be positive"),
        ])
    }

    #[test]
    fn debug_redacts_value() {
        let debug = format!("{:?}", errors());
        assert!(!debug.contains("hunter2"), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");
    }

    #[test]
    fn to_json_omits_values_unless_asked() {
        let json = errors().to_json().to_string();
        assert!(
            !json.contains("hunter2") && !json.contains("\"value\""),
            "{json}"
        );
        let with = errors().to_json_with_values();
        assert_eq!(with["errors"][0]["value"], "hunter2");
        assert!(with["errors"][1].get("value").is_none());
    }

    #[test]
    fn client_message_is_one_line() {
        let errors = ValidationErrors::new(vec![ValidationError::new(
            "a\r\nb",
            "x\ny\u{2028}z\u{202E}",
        )]);
        assert_eq!(errors.client_message(), "a  b: x y z ");
    }

    #[test]
    fn client_message_field_prefix_needs_a_word_boundary() {
        let errors = ValidationErrors::new(vec![
            ValidationError::new("a", "age is invalid"),
            ValidationError::new("", "anything"),
            ValidationError::new("age", "age is invalid"),
        ]);
        assert_eq!(
            errors.client_message(),
            "a: age is invalid; : anything; age is invalid"
        );
    }

    #[test]
    fn client_message_is_capped() {
        let many = ValidationErrors::new(
            (0..100)
                .map(|i| ValidationError::new(format!("f{i}"), "bad"))
                .collect(),
        );
        let message = many.client_message();
        assert!(message.ends_with("f19: bad (and 80 more)"), "{message}");
    }

    #[test]
    fn client_message_names_each_field_once() {
        assert_eq!(
            errors().client_message(),
            "password is too short; age: must be positive"
        );
    }
}

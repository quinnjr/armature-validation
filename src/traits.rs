// Validation traits

use crate::ValidationError;
use async_trait::async_trait;

/// Trait for validatable types
pub trait Validate {
    /// Validate the value and return errors if any
    fn validate(&self) -> Result<(), Vec<ValidationError>>;
}

/// Trait for async validatable types
#[async_trait]
pub trait AsyncValidate {
    /// Async validation (e.g., database checks)
    async fn validate_async(&self) -> Result<(), Vec<ValidationError>>;
}

/// Trait for custom validators
pub trait Validator: Send + Sync {
    /// Validate a value
    fn validate(&self, value: &dyn std::any::Any, field: &str) -> Result<(), ValidationError>;

    /// Get validator name
    fn name(&self) -> &'static str;
}

/// Trait for async validators
#[async_trait]
pub trait AsyncValidator: Send + Sync {
    /// Async validate a value
    async fn validate_async(
        &self,
        value: &dyn std::any::Any,
        field: &str,
    ) -> Result<(), ValidationError>;

    /// Get validator name
    fn name(&self) -> &'static str;
}

/// Validation context for additional data
///
/// `Debug` lists the keys only: the values are request data.
#[derive(Clone)]
pub struct ValidationContext {
    /// Request data or additional context
    pub data: std::collections::HashMap<String, String>,
}

impl ValidationContext {
    /// Create a new validation context
    pub fn new() -> Self {
        Self {
            data: std::collections::HashMap::new(),
        }
    }

    /// Add context data
    pub fn with_data(mut self, key: String, value: String) -> Self {
        self.data.insert(key, value);
        self
    }

    /// Get context data
    pub fn get(&self, key: &str) -> Option<&String> {
        self.data.get(key)
    }
}

impl std::fmt::Debug for ValidationContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut keys: Vec<&String> = self.data.keys().collect();
        keys.sort();
        f.debug_struct("ValidationContext")
            .field("keys", &keys)
            .finish_non_exhaustive()
    }
}

impl Default for ValidationContext {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_debug_hides_values() {
        let ctx = ValidationContext::new().with_data("password".into(), "hunter2".into());
        let debug = format!("{ctx:?}");
        assert!(
            debug.contains("password") && !debug.contains("hunter2"),
            "{debug}"
        );
    }
}

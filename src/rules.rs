// Validation rules builder

use crate::ValidationError;
use std::sync::Arc;

type ValidatorFn = Arc<dyn Fn(&str, &str) -> Result<(), ValidationError> + Send + Sync>;

/// Builder for creating validation rules
#[derive(Clone)]
pub struct ValidationRules {
    validators: Vec<ValidatorFn>,
    field: String,
    optional: bool,
}

impl ValidationRules {
    /// Create new validation rules for a field.
    ///
    /// The field is **required** by default: if the input has no entry for it,
    /// [`ValidationBuilder::validate`] runs the validators against `""` rather
    /// than skipping them, so a form that simply omits `email` fails
    /// `NotEmpty`/`IsEmail` instead of passing. Call
    /// [`ValidationRules::optional`] for a field that may legitimately be
    /// absent.
    pub fn for_field(field: impl Into<String>) -> Self {
        Self {
            validators: Vec::new(),
            field: field.into(),
            optional: false,
        }
    }

    /// Skip these rules entirely when the field is absent from the input.
    ///
    /// A present-but-empty value is still validated - absence and emptiness
    /// are different things, and only absence is exempted here.
    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }

    /// Whether these rules are skipped when the field is absent.
    pub fn is_optional(&self) -> bool {
        self.optional
    }

    /// The field these rules apply to.
    pub fn field_name(&self) -> &str {
        &self.field
    }

    /// Add a custom validator function
    #[allow(clippy::should_implement_trait)]
    pub fn add<F>(mut self, validator: F) -> Self
    where
        F: Fn(&str, &str) -> Result<(), ValidationError> + Send + Sync + 'static,
    {
        self.validators.push(Arc::new(validator));
        self
    }

    /// Validate a value against all rules
    pub fn validate(&self, value: &str) -> Result<(), Vec<ValidationError>> {
        let mut errors = Vec::new();

        for validator in &self.validators {
            if let Err(error) = validator(value, &self.field) {
                errors.push(error);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Validation rules builder for complex validation scenarios
pub struct ValidationBuilder {
    rules: Vec<ValidationRules>,
}

impl ValidationBuilder {
    /// Create a new validation builder
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add rules for a field
    pub fn field(mut self, rules: ValidationRules) -> Self {
        self.rules.push(rules);
        self
    }

    /// The value a rule should be run against, or `None` to skip the rule.
    ///
    /// Shared by the sync and parallel paths so the two cannot drift on how
    /// they treat a missing field.
    fn value_for<'a>(
        rule: &ValidationRules,
        data: &'a std::collections::HashMap<String, String>,
    ) -> Option<&'a str> {
        match data.get(rule.field_name()) {
            Some(value) => Some(value.as_str()),
            None if rule.is_optional() => None,
            // Absent and required: validate as empty so `NotEmpty` and friends
            // reject it rather than never running.
            None => Some(""),
        }
    }

    /// Validate all fields.
    ///
    /// A field with rules but no entry in `data` is validated as `""`, not
    /// skipped: skipping it meant a submission that simply omitted `email`
    /// passed `NotEmpty` and `IsEmail`, so the easiest way to defeat validation
    /// was to leave the field out. Mark genuinely optional fields with
    /// [`ValidationRules::optional`].
    pub fn validate(
        &self,
        data: &std::collections::HashMap<String, String>,
    ) -> Result<(), Vec<ValidationError>> {
        let mut all_errors = Vec::new();

        for rule in &self.rules {
            let Some(value) = Self::value_for(rule, data) else {
                continue;
            };
            if let Err(mut errors) = rule.validate(value) {
                all_errors.append(&mut errors);
            }
        }

        if all_errors.is_empty() {
            Ok(())
        } else {
            Err(all_errors)
        }
    }

    /// Validate all fields concurrently using async tasks.
    ///
    /// Each field's validators run in a separate [`tokio`] task via a
    /// [`JoinSet`](tokio::task::JoinSet), so independent fields are scheduled
    /// concurrently rather than strictly in sequence.
    ///
    /// # Performance
    ///
    /// The built-in validators are synchronous and CPU-cheap, so for typical
    /// forms the task-spawn overhead dominates and this offers no measurable
    /// speedup over [`ValidationBuilder::validate`] — it is not benchmarked to
    /// be faster. Reach for it only when your validators do genuinely
    /// independent, latency-bound work (for example custom async checks wrapped
    /// in blocking validators); otherwise prefer the synchronous method.
    ///
    /// # Runtime
    ///
    /// Tasks are spawned on the current [`tokio`] runtime. Called outside one,
    /// this falls back to [`ValidationBuilder::validate`] rather than panicking.
    ///
    /// # Panics in validators
    ///
    /// Inside a runtime, a validator that panics fails validation closed: the
    /// field gets a generic `validationFailed` error. The panic payload is not
    /// copied into the error, since it may name internals or carry data, and
    /// errors are sent to clients. The process's panic hook still runs, so the
    /// default hook prints the payload to stderr. Outside a runtime the
    /// synchronous fallback, like [`ValidationBuilder::validate`], lets the
    /// panic propagate.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use armature_validation::*;
    /// # use std::collections::HashMap;
    /// # async fn example() -> Result<(), Vec<ValidationError>> {
    /// let validator = ValidationBuilder::new()
    ///     .field(ValidationRules::for_field("email").add(IsEmail::validate))
    ///     .field(ValidationRules::for_field("username").add(NotEmpty::validate))
    ///     .field(ValidationRules::for_field("age").add(NotEmpty::validate));
    ///
    /// let mut data = HashMap::new();
    /// data.insert("email".to_string(), "user@example.com".to_string());
    /// data.insert("username".to_string(), "john_doe".to_string());
    /// data.insert("age".to_string(), "25".to_string());
    ///
    /// validator.validate_parallel(&data).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn validate_parallel(
        &self,
        data: &std::collections::HashMap<String, String>,
    ) -> Result<(), Vec<ValidationError>> {
        use tokio::task::JoinSet;

        if tokio::runtime::Handle::try_current().is_err() {
            return self.validate(data);
        }

        let mut set = JoinSet::new();
        // Field of each spawned rule, by spawn order.
        let mut order_of: Vec<String> = Vec::new();

        // Spawn validation tasks for each field. Missing-field handling goes
        // through the same `value_for` as the synchronous path, so the two
        // cannot disagree about whether an absent field passes.
        for rule in &self.rules {
            let Some(value) = Self::value_for(rule, data) else {
                continue;
            };
            let value = value.to_owned();
            let field = rule.field.clone();
            let validators = rule.validators.clone();

            let order = order_of.len();
            order_of.push(field.clone());
            set.spawn(async move {
                let mut errors = Vec::new();
                for validator in &validators {
                    if let Err(error) = validator(&value, &field) {
                        errors.push(error);
                    }
                }
                (order, errors)
            });
        }

        // Collect per rule, then flatten in rule order so the result matches
        // the synchronous path regardless of which task finished first. A rule
        // whose task did not complete (it panicked) fails closed.
        let mut per_rule: Vec<Option<Vec<ValidationError>>> = vec![None; order_of.len()];
        while let Some(result) = set.join_next().await {
            if let Ok((order, errors)) = result {
                per_rule[order] = Some(errors);
            }
        }
        let all_errors: Vec<ValidationError> = per_rule
            .into_iter()
            .zip(order_of)
            .flat_map(|(errors, field)| {
                errors.unwrap_or_else(|| {
                    vec![
                        ValidationError::new(&field, format!("{} could not be validated", field))
                            .with_constraint("validationFailed"),
                    ]
                })
            })
            .collect();

        if all_errors.is_empty() {
            Ok(())
        } else {
            Err(all_errors)
        }
    }
}

impl Default for ValidationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validators::*;

    #[test]
    fn test_validation_rules() {
        let rules = ValidationRules::for_field("email")
            .add(NotEmpty::validate)
            .add(IsEmail::validate);

        assert!(rules.validate("test@example.com").is_ok());
        assert!(rules.validate("invalid").is_err());
        assert!(rules.validate("").is_err());
    }

    #[test]
    fn test_validation_builder() {
        let mut data = std::collections::HashMap::new();
        data.insert("name".to_string(), "John".to_string());
        data.insert("email".to_string(), "john@example.com".to_string());

        let builder = ValidationBuilder::new()
            .field(ValidationRules::for_field("name").add(NotEmpty::validate))
            .field(ValidationRules::for_field("email").add(IsEmail::validate));

        assert!(builder.validate(&data).is_ok());
    }

    fn signup_validator() -> ValidationBuilder {
        ValidationBuilder::new()
            .field(
                ValidationRules::for_field("email")
                    .add(NotEmpty::validate)
                    .add(IsEmail::validate),
            )
            .field(ValidationRules::for_field("name").add(NotEmpty::validate))
    }

    /// Regression: a field with rules but absent from the input used to be
    /// skipped outright, so omitting `email` passed both `NotEmpty` and
    /// `IsEmail`.
    #[test]
    fn test_missing_required_field_fails() {
        let mut data = std::collections::HashMap::new();
        data.insert("name".to_string(), "John".to_string());

        let errors = signup_validator()
            .validate(&data)
            .expect_err("an omitted required field must not pass validation");
        assert!(errors.iter().any(|e| e.field == "email"));
    }

    #[tokio::test]
    async fn test_missing_required_field_fails_in_parallel_path_too() {
        let mut data = std::collections::HashMap::new();
        data.insert("name".to_string(), "John".to_string());

        let errors = signup_validator()
            .validate_parallel(&data)
            .await
            .expect_err("the parallel path must agree with the sync path");
        assert!(errors.iter().any(|e| e.field == "email"));
    }

    /// An explicitly optional field may be absent, but is still validated when
    /// present.
    #[test]
    fn test_optional_field_may_be_absent() {
        let validator = ValidationBuilder::new().field(
            ValidationRules::for_field("website")
                .optional()
                .add(IsUrl::validate),
        );

        let empty = std::collections::HashMap::new();
        assert!(validator.validate(&empty).is_ok());

        let mut present = std::collections::HashMap::new();
        present.insert("website".to_string(), "not a url".to_string());
        assert!(validator.validate(&present).is_err());
    }

    /// A panicking validator fails its field closed, without leaking the panic
    /// payload, and without discarding other fields' errors.
    #[tokio::test]
    async fn parallel_panic_fails_closed_without_leaking_payload() {
        let validator = ValidationBuilder::new()
            .field(ValidationRules::for_field("a").add(NotEmpty::validate))
            .field(ValidationRules::for_field("b").add(
                |_: &str, _: &str| -> Result<(), ValidationError> { panic!("db password=s3cr3t") },
            ));
        let errors = validator
            .validate_parallel(&std::collections::HashMap::new())
            .await
            .expect_err("both fields must fail");
        let fields: Vec<_> = errors.iter().map(|e| e.field.as_str()).collect();
        assert_eq!(fields, ["a", "b"]);
        assert!(errors.iter().all(|e| !e.message.contains("s3cr3t")));
        assert_eq!(errors[1].constraint, "validationFailed");
    }

    /// Outside a runtime the parallel path degrades to the synchronous one.
    #[test]
    fn parallel_without_runtime_falls_back_to_sync() {
        let validator = signup_validator();
        let data = std::collections::HashMap::new();
        let errors = block_on_ready(validator.validate_parallel(&data))
            .expect_err("missing fields must fail");
        assert!(errors.iter().any(|e| e.field == "email"));
    }

    /// Minimal executor: polls a future that never actually waits.
    fn block_on_ready<F: std::future::Future>(fut: F) -> F::Output {
        use std::task::{Context, Poll, Waker};
        let mut fut = std::pin::pin!(fut);
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
                return out;
            }
        }
    }
}

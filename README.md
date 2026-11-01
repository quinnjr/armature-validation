# armature-validation

Request validation for the Armature framework.

## Features

- **Derive Macro** - `#[derive(Validate)]` for structs
- **Built-in Rules** - Email, URL, length, range, regex, etc.
- **Custom Validators** - Create your own validation rules
- **Nested Validation** - Validate nested structs
- **Client-safe errors** - Error responses never echo the submitted values

## Installation

```toml
[dependencies]
armature-validation = "0.8"
```

## Quick Start

```rust
use armature_validation::{Validate, ValidationError};

#[derive(Validate)]
struct CreateUser {
    #[validate(length(min = 3, max = 50))]
    username: String,

    #[validate(email)]
    email: String,

    #[validate(length(min = 8))]
    password: String,

    #[validate(range(min = 13, max = 120))]
    age: u8,
}

fn create_user(data: CreateUser) -> Result<(), Vec<ValidationError>> {
    data.validate()?;
    // Process valid data
    Ok(())
}

let short_password = CreateUser {
    username: "alice".into(),
    email: "alice@example.com".into(),
    password: "hunter2".into(),
    age: 30,
};
assert!(create_user(short_password).is_err());
```

## Available Validators

| Validator | Description |
|-----------|-------------|
| `email` | Valid email address (RFC 5321 lengths, dot-atom local part) |
| `url` | Absolute `http`/`https` URL, exactly as the URL parser reads it |
| `length(min, max)` | String length bounds, in characters |
| `range(min, max)` | Numeric range |
| `regex(pattern)` | Regex match **anywhere** in the value; anchor with `^…$` for a full match |
| `required` | Has visible content (not empty, whitespace or invisible characters) |
| `custom(fn)` | Custom function |

`url` is a syntax check, not an SSRF filter: `http://127.0.0.1/` is a valid URL.
Vet the destination before fetching a user-supplied URL from the server.

## Custom Validators

A custom function receives the field's value only, so the error names the
field itself:

```rust
use armature_validation::{Validate, ValidationError};

fn validate_username(username: &str) -> Result<(), ValidationError> {
    if username.contains(' ') {
        return Err(ValidationError::new("username", "No spaces allowed"));
    }
    Ok(())
}

#[derive(Validate)]
struct User {
    #[validate(custom = "validate_username")]
    username: String,
}

assert!(User { username: "a b".into() }.validate().is_err());
```

## Error Output

Validation errors are sent to clients, so the submitted value is kept out of
everything client-facing: the built-in validators do not record it (the
derive's `range` rule does, and a custom validator may), and whatever is
recorded is left out of `ValidationErrors::to_json` and `client_message` and
redacted from `Debug` output. `ValidationPipe::parse` and the
`validate!` macro return `armature_core::Error::Validation` with `field: message`
pairs, and a body that fails to deserialize returns
`armature_core::Error::Deserialization`, whose detail the framework does not
send to the client.

`ValidationPipe::parse` reads any body as JSON. For an endpoint authenticated
by cookie, use `ValidationPipe::parse_strict`, which also requires a JSON
`Content-Type`: a cross-site HTML form can post a JSON-shaped `text/plain`
body without a CORS preflight. To refuse unknown fields, add
`#[serde(deny_unknown_fields)]` to the DTO.

## License

Apache-2.0

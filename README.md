
# ntex-basicauth

A Basic Authentication middleware designed for the [ntex](https://github.com/ntex-rs/ntex) web framework.

[![Crates.io](https://img.shields.io/crates/v/ntex-basicauth.svg)](https://crates.io/crates/ntex-basicauth)
[![Documentation](https://docs.rs/ntex-basicauth/badge.svg)](https://docs.rs/ntex-basicauth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Features

- 🔐 **Basic Authentication** - Standard HTTP Basic Authentication support
- 🏗️ **Builder** - Simple API design
- ⚡ **Cache** - Built-in authentication result cache to reduce validation overhead
- 🔧 **Flexible Configuration** - Supports multiple user validation methods
- 🛣️ **Path Filtering** - Supports skipping authentication for specific paths
- 🔒 **BCrypt Support** - Optional BCrypt password hashing (requires `bcrypt` feature)
- 📄 **JSON Response** - Optional JSON error response (requires `json` feature)
- 🎯 **Custom Validator** - Support for custom user validation logic

## Installation

Add the dependency in your `Cargo.toml`:

```toml
[dependencies]
ntex-basicauth = "0.1"
```

```toml
[dependencies]
ntex-basicauth = { version = "0.1", features = ["bcrypt"] }
```

## Quick Start

### Basic Usage

```rust
use ntex::web;
use ntex_basicauth::BasicAuth;
use std::collections::HashMap;

#[ntex::main]
async fn main() -> std::io::Result<()> {
    // Create user list
    let mut users = HashMap::new();
    users.insert("admin".to_string(), "secret".to_string());
    users.insert("user".to_string(), "password".to_string());

    web::HttpServer::new(move || {
        web::App::new()
            .wrap(BasicAuth::with_users(users.clone()))
            .route("/protected", web::get().to(protected_handler))
            .route("/public", web::get().to(public_handler))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

async fn protected_handler() -> &'static str {
    "This is protected content!"
}
-
async fn public_handler() -> &'static str {
    "This is public content"
}
```

### Using the Builder Pattern

```rust
use ntex_basicauth::{BasicAuthBuilder, PathFilter};

let auth = BasicAuthBuilder::new()
    .user("admin", "secret")
    .user("user", "password")
    .realm("My Application")
    .cache_size_limit(500)
    .path_filter(
        PathFilter::new()
            .skip_prefix("/public/")
            .skip_exact("/health")
            .skip_suffix(".css")
    )
    .build()
    .unwrap();

web::App::new()
    .wrap(auth)
    .service(web::resource("/api/data").to(handler))
```

### BCrypt Password Support

After enabling the `bcrypt` feature:

```rust
use ntex_basicauth::{BasicAuthConfig, BcryptUserValidator};
use std::sync::Arc;

let mut validator = BcryptUserValidator::new();
validator.add_user_with_password("admin".to_string(), "secret").unwrap();

let config = BasicAuthConfig::new(Arc::new(validator))
    .realm("Secure Area".to_string());

let auth = BasicAuth::new(config);
```

### Custom Validator

```rust
use ntex_basicauth::{UserValidator, Credentials, AuthResult, BasicAuthConfig, BasicAuth};
use std::sync::Arc;
use std::pin::Pin;
use std::future::Future;

struct DatabaseValidator {
    // Database connection, etc.
}

impl UserValidator for DatabaseValidator {
    fn validate<'a>(
        &'a self,
        credentials: &'a Credentials,
    ) -> Pin<Box<dyn Future<Output = AuthResult<bool>> + Send + 'a>> {
        Box::pin(async move {
            // Implement database query logic here
            // For example: check if username and password match in the database
            let user_exists = check_user_in_database(&credentials.username, &credentials.password).await;
            Ok(user_exists)
        })
    }
}

async fn check_user_in_database(username: &str, password: &str) -> bool {
    // Actual database query logic
    true // Example return value
}

// Using custom validator
let config = BasicAuthConfig::new(Arc::new(DatabaseValidator {}));
let auth = BasicAuth::new(config);
```

## Getting User Information

Get authenticated user information in the request handler:

```rust
use ntex::web;
use ntex_basicauth::{extract_credentials, get_username, is_user};

async fn handler(req: web::HttpRequest) -> web::Result<String> {
    // Get full authentication info
    if let Some(credentials) = extract_credentials(&req) {
        return Ok(format!("User: {}", credentials.username));
    }

    // Get only the username
    if let Some(username) = get_username(&req) {
        return Ok(format!("Welcome, {}!", username));
    }

    // Check if specific user
    if is_user(&req, "admin") {
        return Ok("Admin user".to_string());
    }

    Ok("Unknown user".to_string())
}
```

## Configuration Options

### BasicAuthConfig

```rust
let config = BasicAuthConfig::new(validator)
    .realm("My Application".to_string())           // Set authentication realm
    .disable_cache()                               // Disable cache
    .cache_size_limit(1000)                        // Set cache size limit
    .path_filter(filter);                          // Set path filter
```

### PathFilter

```rust
let filter = PathFilter::new()
    .skip_exact("/health")          // Skip exact path
    .skip_prefix("/public/")        // Skip prefix match
    .skip_suffix(".css");           // Skip suffix match
```

## Error Handling

When authentication fails, the middleware returns HTTP 401 status code and corresponding error information:

```json
{
    "code": 401,
    "message": "Authentication required",
    "error": "Invalid credentials"
}
```

Error types:

- `MissingHeader` - Missing Authorization header
- `InvalidFormat` - Invalid Authorization header format
- `InvalidBase64` - Invalid Base64 encoding
- `InvalidCredentials` - Invalid user credentials
- `ValidationFailed` - User validation failed

## Performance Optimization

### Cache

Authentication cache is enabled by default, which can significantly reduce repeated validation overhead:

```rust
let config = BasicAuthConfig::new(validator)
    .cache_size_limit(500)  // Set cache entry limit
    .disable_cache();       // Or completely disable cache
```

### Path Filtering

For paths that do not require authentication, use path filter to skip authentication check:

```rust
let filter = PathFilter::new()
    .skip_prefix("/static/")    // Static resources
    .skip_exact("/health")      // Health check
    .skip_suffix(".ico");       // Icon files
```

## License

This project is licensed under the MIT License.

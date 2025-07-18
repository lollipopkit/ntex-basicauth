# ntex-basicauth

A Basic Authentication middleware designed for the [ntex](https://github.com/ntex-rs/ntex) web framework.

[![Crates.io](https://img.shields.io/crates/v/ntex-basicauth.svg)](https://crates.io/crates/ntex-basicauth)
[![Documentation](https://docs.rs/ntex-basicauth/badge.svg)](https://docs.rs/ntex-basicauth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Features

- **Cache** - Built-in authentication result cache to reduce validation overhead
- **Flexible Configuration** - Supports multiple user validation methods
- **Path Filtering** - Supports skipping authentication for specific paths
- **BCrypt Support** - Optional BCrypt password hashing (requires `bcrypt` feature)
- **JSON Response** - Optional JSON error response (requires `json` feature)
- **Custom Validator** - Support for custom user validation logic
- **Regex Paths** - Regular expression path matching (requires `regex` feature)
- **Safety** - Timing-safe password comparison (`timing-safe`, enabled by default). Automatic password memory cleanup using `zeroize` crate (`secure-memory`, enabled by default)

## Installation

Add the dependency in your `Cargo.toml`:

```toml
[dependencies]
ntex-basicauth = "^0"
```

Enable optional features if needed:

```toml
[dependencies]
ntex-basicauth = { version = "^0", features = ["bcrypt", "regex"] }
```

## Quick Start

### Basic Usage

```rust
use ntex::web;
use ntex_basicauth::BasicAuthBuilder;
use std::collections::HashMap;

#[ntex::main]
async fn main() -> std::io::Result<()> {

    web::HttpServer::new(move || {
        let mut users = HashMap::new();
        users.insert("admin".to_string(), "secret".to_string());
        users.insert("user".to_string(), "password".to_string());

        let auth = BasicAuthBuilder::new()
            .users(users)
            .realm("My Application")
            .build()
            .expect("Failed to configure authentication");

        web::App::new()
            .wrap(auth)
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

async fn public_handler() -> &'static str {
    "This is public content"
}
```

### Using the Builder Pattern

```rust
use ntex_basicauth::{BasicAuthBuilder, PathFilter};
use std::collections::HashMap;

let mut users = HashMap::new();
users.insert("admin".to_string(), "secret".to_string());

let filter = PathFilter::new()
    .skip_prefix("/public/")
    .skip_exact("/health")
    .skip_suffix(".css");

let auth = BasicAuthBuilder::new()
    .users(users)
    .realm("My Application")
    .path_filter(filter)
    .log_failures(true)
    .max_header_size(4096)
    .build()
    .unwrap();
```

### Regex Path Filtering

Enable the `regex` feature in Cargo.toml:

```toml
[dependencies]
ntex-basicauth = { version = "^0", features = ["regex"] }
```

```rust
use ntex_basicauth::{BasicAuthBuilder, PathFilter};

let filter = PathFilter::new()
    .skip_regex(r"^/assets/.*\.(js|css|png|jpg)$").unwrap();

let auth = BasicAuthBuilder::new()
    .user("admin", "secret")
    .path_filter(filter)
    .build()
    .unwrap();
```

### BCrypt Password Support

Enable the `bcrypt` feature in Cargo.toml:

```toml
[dependencies]
ntex-basicauth = { version = "^0", features = ["bcrypt"] }
```

```rust
use ntex_basicauth::{BasicAuthBuilder, BcryptUserValidator};
use std::sync::Arc;

let mut validator = BcryptUserValidator::new();
validator.add_user_with_password("admin".to_string(), "secret").unwrap();

let auth = BasicAuthBuilder::new()
    .validator(Arc::new(validator))
    .realm("My Application")
    .build()
    .unwrap();
```

### Custom Validator

```rust
use ntex_basicauth::{UserValidator, Credentials, AuthResult, BasicAuthBuilder};
use std::sync::Arc;
use std::future::Future;
use std::pin::Pin;

struct DatabaseValidator;

impl UserValidator for DatabaseValidator {
    fn validate<'a>(
        &'a self,
        credentials: &'a Credentials,
    ) -> Pin<Box<dyn Future<Output = AuthResult<bool>> + Send + 'a>> {
        Box::pin(async move {
            // Replace with your DB logic
            Ok(credentials.username == "admin" && credentials.password == "secret")
        })
    }
}

let auth = BasicAuthBuilder::new()
    .validator(Arc::new(DatabaseValidator))
    .realm("Custom Realm")
    .build()
    .unwrap();
```

## Getting User Information

Get authenticated user information in the request handler:

```rust
use ntex::web;
use ntex_basicauth::{extract_credentials, get_username, is_user};

async fn handler(req: web::HttpRequest) -> web::Result<String> {
    if let Some(credentials) = extract_credentials(&req) {
        return Ok(format!("User: {}", credentials.username));
    }

    if let Some(username) = get_username(&req) {
        return Ok(format!("Welcome, {}!", username));
    }

    if is_user(&req, "admin") {
        return Ok("Admin access granted".to_string());
    }

    Ok("Unknown user".to_string())
}
```

## PathFilter Macro

You can use the `path_filter!` macro for convenient filter creation:

```rust
use ntex_basicauth::path_filter;

let filter = path_filter!(
    exact: ["/health", "/metrics"],
    prefix: ["/public/"],
    suffix: [".css", ".js"]
);
```

## Common Skip Paths

Use built-in common skip paths:

```rust
use ntex_basicauth::{BasicAuthBuilder, common_skip_paths};

let auth = BasicAuthBuilder::new()
    .user("admin", "secret")
    .path_filter(common_skip_paths())
    .build()
    .unwrap();
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

Error types include:

- `MissingHeader` - Missing Authorization header
- `InvalidFormat` - Invalid Authorization header format
- `InvalidBase64` - Invalid Base64 encoding
- `InvalidCredentials` - Invalid user credentials
- `ValidationFailed` - User validation failed

## Configuration

### Advanced Security Configuration

```rust
use ntex_basicauth::{BasicAuthBuilder, CacheConfig};
use std::time::Duration;

let cache_config = CacheConfig::new()
    .max_size(1000)
    .ttl_minutes(10)
    .cleanup_interval_seconds(300);

let auth = BasicAuthBuilder::new()
    .user("admin", "secret")
    .with_cache(cache_config)
    .max_concurrent_validations(100)        // Limit concurrent validations
    .validation_timeout(Duration::from_secs(30))  // Set validation timeout
    .rate_limit_per_ip(10, Duration::from_secs(60))  // 10 requests per minute per IP
    .log_usernames_in_production(false)     // Don't log usernames in production
    .build()
    .unwrap();
```

### Security Best Practices

- **Memory Security**: The `secure-memory` feature (enabled by default) automatically clears password data from memory after use
- **Cache Security**: Cache keys are SHA256-hashed with application-specific salt to prevent rainbow table attacks
- **Production Logging**: Set `log_usernames_in_production(false)` to prevent username leakage in production logs
- **DoS Protection**: Configure rate limiting and concurrent validation limits to prevent resource exhaustion

## Cache Configuration

Cache is enabled by default (unless disabled via builder/config):

```rust
use ntex_basicauth::{BasicAuthBuilder, CacheConfig};

let cache_config = CacheConfig::new()
    .max_size(1000)
    .ttl_minutes(10)
    .cleanup_interval_seconds(300);

let auth = BasicAuthBuilder::new()
    .user("admin", "secret")
    .with_cache(cache_config)
    .build()
    .unwrap();
```

## License

This project is licensed under the MIT License.

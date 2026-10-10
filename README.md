# ntex-basicauth

Basic Authentication (RFC 7617) middleware for the [ntex](https://github.com/ntex-rs/ntex) web framework.

[![Crates.io](https://img.shields.io/crates/v/ntex-basicauth.svg)](https://crates.io/crates/ntex-basicauth)
[![Documentation](https://docs.rs/ntex-basicauth/badge.svg)](https://docs.rs/ntex-basicauth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Features

- Static user list (stored as SHA-256 digests, constant-time comparison), BCrypt, or a custom async validator
- Per-IP limit of failed attempts, validation timeout and concurrency limit
- Optional cache of successful authentications
- Path filter to skip authentication (exact / prefix / suffix / regex)
- `AuthenticatedUser` extractor for handlers
- Passwords are zeroized after use and redacted from `Debug`; error responses never expose internal details

| Feature  | Default | Description                                  |
| -------- | ------- | -------------------------------------------- |
| `cache`  | yes     | Cache of successful authentications          |
| `regex`  | yes     | `PathFilter::skip_regex`                     |
| `bcrypt` | yes     | `BcryptUserValidator`                        |

## Quick Start

```rust,no_run
use ntex::web;
use ntex_basicauth::{AuthenticatedUser, BasicAuth, common_skip_paths};

#[ntex::main]
async fn main() -> std::io::Result<()> {
    // Build once and clone into each worker so that the failure limiter,
    // cache and metrics are shared.
    let auth = BasicAuth::builder()
        .user("admin", "secret")
        .realm("My Application")
        .path_filter(common_skip_paths())
        .build()
        .expect("invalid auth config");

    web::HttpServer::new(async move || {
        web::App::new()
            .middleware(auth.clone())
            .route("/", web::get().to(index))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

// Use `Option<AuthenticatedUser>` on routes that may skip authentication.
async fn index(user: AuthenticatedUser) -> String {
    format!("Hello, {}!", user.username())
}
```

## Configuration

```rust,no_run
use ntex_basicauth::{AuthResult, BasicAuth, CacheConfig, PathFilter};
use std::time::Duration;

fn auth() -> AuthResult<BasicAuth> {
    BasicAuth::builder()
        .users_from_file("users.txt")?              // `username:password` per line
        .realm("Production API")
        .cache(CacheConfig::new().max_size(1000).ttl(Duration::from_secs(300)))
        .max_failures_per_ip(10, Duration::from_secs(60)) // 429 after 10 failures/min
        .trusted_proxies(["10.0.0.0/8".parse().unwrap()]) // read X-Forwarded-For from these
        .max_concurrent_validations(100)
        .validation_timeout(Duration::from_secs(5)) // 503 on timeout
        .log_failures(true)
        .path_filter(PathFilter::new().skip_exact("/health").skip_prefix("/static/"))
        .build()
}
```

Notes:

- `max_failures_per_ip` only counts failed attempts (wrong credentials or a malformed header); successful requests are never throttled. Blocked clients get 429 with `Retry-After`. IPv6 clients are grouped by /64.
- The client IP is the peer address. `X-Forwarded-For` is read only when the peer is in `trusted_proxies`, taking the rightmost hop that is not a trusted proxy (hops a client prepends are ignored). Behind an unlisted proxy, all clients share the proxy's failure budget.
- Requests without a peer address (Unix sockets) share one failure budget by default. Behind a local reverse proxy on a Unix socket, enable `trust_peerless_proxy(true)` to key them by `X-Forwarded-For` instead.
- At most 65536 clients are tracked; beyond that, new clients share the same overflow entry.
- The cache only stores successful authentications. Call `BasicAuth::clear_cache()` after changing passwords in a custom backend.
- `skip_suffix` matches any route ending with the suffix (including dynamic segments such as `/api/users/x.js`); prefer prefixes. Paths with dot-segments (`..`, `%2e%2e`) never skip authentication.

## Validators

### BCrypt

```rust
use ntex_basicauth::{AuthResult, BasicAuth, BcryptUserValidator};

fn auth() -> AuthResult<BasicAuth> {
    let mut validator = BcryptUserValidator::new();
    validator.add_user("admin", "$2b$12$...");
    BasicAuth::builder().validator(validator).build()
}
```

### Custom

```rust
use ntex_basicauth::{AuthResult, BasicAuth, BoxFuture, Credentials, UserValidator};

struct DbValidator;

impl UserValidator for DbValidator {
    fn validate<'a>(&'a self, credentials: &'a Credentials) -> BoxFuture<'a, AuthResult<bool>> {
        Box::pin(async move {
            // Ok(false) for wrong credentials (401), Err for backend failures (500).
            Ok(credentials.username == "admin" && credentials.verify_password("secret"))
        })
    }
}

fn auth() -> AuthResult<BasicAuth> {
    BasicAuth::builder().validator(DbValidator).build()
}
```

## Errors

| Error                | Status | Body message               |
| -------------------- | ------ | -------------------------- |
| `MissingHeader`      | 401    | `Authentication required`  |
| `InvalidHeader`      | 401    | `Authentication required`  |
| `InvalidCredentials` | 401    | `Invalid credentials`      |
| `RateLimited`        | 429    | `Too many failed attempts` |
| `Timeout`            | 503    | `Authentication timed out` |
| `Validator`/`Config` | 500    | `Internal server error`    |

Body format: `{"code":401,"message":"Invalid credentials"}`. Use `BasicAuthBuilder::error_handler` to customize the response.

## License

MIT

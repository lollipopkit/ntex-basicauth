//! # ntex-basicauth
//!
//! Basic Authentication (RFC 7617) middleware for the [ntex](https://github.com/ntex-rs/ntex) web framework.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use ntex::web;
//! use ntex_basicauth::{AuthenticatedUser, BasicAuth, common_skip_paths};
//!
//! #[ntex::main]
//! async fn main() -> std::io::Result<()> {
//!     // Build once and clone into each worker so that the failure limiter,
//!     // cache and metrics are shared.
//!     let auth = BasicAuth::builder()
//!         .user("admin", "secret")
//!         .realm("My Application")
//!         .path_filter(common_skip_paths())
//!         .build()
//!         .expect("invalid auth config");
//!
//!     web::HttpServer::new(async move || {
//!         web::App::new()
//!             .middleware(auth.clone())
//!             .route("/", web::get().to(index))
//!     })
//!     .bind("127.0.0.1:8080")?
//!     .run()
//!     .await
//! }
//!
//! async fn index(user: AuthenticatedUser) -> String {
//!     format!("Hello, {}!", user.username())
//! }
//! ```
//!
//! ## Feature Flags
//!
//! - `cache` (default): cache of successful authentications
//! - `regex` (default): regex path matching in [`PathFilter`]
//! - `bcrypt` (default): [`BcryptUserValidator`]

#![doc(html_root_url = "https://docs.rs/ntex-basicauth/")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

#[cfg(feature = "cache")]
mod cache;
mod error;
mod filter;
mod limiter;
mod middleware;
mod validator;

#[cfg(feature = "cache")]
pub use cache::CacheConfig;
pub use error::{AuthError, AuthResult};
pub use filter::{PathFilter, common_skip_paths};
pub use ipnet::IpNet;
pub use middleware::{
    AuthMetrics, AuthenticatedUser, BasicAuth, BasicAuthBuilder, BasicAuthService,
};
#[cfg(feature = "bcrypt")]
pub use validator::BcryptUserValidator;
pub use validator::{
    BoxFuture, Credentials, StaticUserValidator, UserValidator, is_valid_username,
};

#[cfg(all(doctest, feature = "cache", feature = "bcrypt"))]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

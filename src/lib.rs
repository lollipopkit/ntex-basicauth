pub mod auth;
pub mod error;

pub use auth::{BasicAuth, BasicAuthConfig, Credentials, UserValidator};
pub use error::{AuthError, AuthResult};
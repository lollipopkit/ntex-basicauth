//! Authentication error types and response handling

use ntex::http::{StatusCode, header, header::HeaderValue};
use ntex::web;
use thiserror::Error;

/// Authentication error type
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthError {
    /// Missing `Authorization` header
    #[error("missing Authorization header")]
    MissingHeader,

    /// Malformed `Authorization` header (wrong scheme, bad Base64, non UTF-8, ...)
    #[error("invalid Authorization header")]
    InvalidHeader,

    /// Unknown user or wrong password
    #[error("invalid credentials")]
    InvalidCredentials,

    /// Too many failed attempts from the client IP
    #[error("too many failed authentication attempts, retry after {retry_after}s")]
    RateLimited {
        /// Seconds until the client may retry, sent as `Retry-After`
        retry_after: u64,
    },

    /// The validator did not finish within the configured timeout
    #[error("validation timed out")]
    Timeout,

    /// The validator backend failed (database down, malformed stored hash, ...)
    #[error("validator error: {0}")]
    Validator(String),

    /// Invalid middleware configuration
    #[error("configuration error: {0}")]
    Config(String),
}

/// Authentication result type
pub type AuthResult<T> = Result<T, AuthError>;

impl AuthError {
    /// HTTP status code for this error
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::MissingHeader | Self::InvalidHeader | Self::InvalidCredentials => {
                StatusCode::UNAUTHORIZED
            }
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::Timeout => StatusCode::SERVICE_UNAVAILABLE,
            Self::Validator(_) | Self::Config(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Whether this error is caused by the client
    pub fn is_client_error(&self) -> bool {
        self.status_code().is_client_error()
    }

    /// Message exposed to the client. Never contains internal details.
    fn public_message(&self) -> &'static str {
        match self {
            Self::MissingHeader | Self::InvalidHeader => "Authentication required",
            Self::InvalidCredentials => "Invalid credentials",
            Self::RateLimited { .. } => "Too many failed attempts",
            Self::Timeout => "Authentication timed out",
            Self::Validator(_) | Self::Config(_) => "Internal server error",
        }
    }

    /// Build the error response, adding a `WWW-Authenticate` challenge for 401s.
    pub fn to_response(&self, realm: &str) -> web::HttpResponse {
        self.response(challenge(realm).ok().as_ref())
    }

    pub(crate) fn response(&self, challenge: Option<&HeaderValue>) -> web::HttpResponse {
        let status = self.status_code();
        let mut builder = web::HttpResponse::build(status);
        builder
            .set_header(header::CONTENT_TYPE, "application/json")
            .set_header(header::CACHE_CONTROL, "no-store");
        match self {
            Self::RateLimited { retry_after } => {
                builder.set_header(header::RETRY_AFTER, *retry_after);
            }
            _ if status == StatusCode::UNAUTHORIZED => {
                if let Some(challenge) = challenge {
                    builder.set_header(header::WWW_AUTHENTICATE, challenge.clone());
                }
            }
            _ => {}
        }
        // Both fields are static and JSON-safe, so no serializer is needed.
        builder.body(format!(
            r#"{{"code":{},"message":"{}"}}"#,
            status.as_u16(),
            self.public_message()
        ))
    }
}

/// Realm used when none is configured
pub(crate) const DEFAULT_REALM: &str = "Restricted Area";

/// Build the `WWW-Authenticate` value for `realm`, escaping it as a quoted-string.
pub(crate) fn challenge(realm: &str) -> AuthResult<HeaderValue> {
    if realm.is_empty() || realm.chars().any(char::is_control) {
        return Err(AuthError::Config(
            "realm must be non-empty and contain no control characters".into(),
        ));
    }
    let escaped = realm.replace('\\', "\\\\").replace('"', "\\\"");
    HeaderValue::from_str(&format!("Basic realm=\"{escaped}\", charset=\"UTF-8\""))
        .map_err(|_| AuthError::Config("realm is not a valid header value".into()))
}

impl web::error::WebResponseError for AuthError {
    fn status_code(&self) -> StatusCode {
        AuthError::status_code(self)
    }

    fn error_response(&self, _: &web::HttpRequest) -> web::HttpResponse {
        self.to_response(DEFAULT_REALM)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_codes() {
        assert_eq!(
            AuthError::MissingHeader.status_code(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            AuthError::RateLimited { retry_after: 1 }.status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            AuthError::Timeout.status_code(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(AuthError::InvalidCredentials.is_client_error());
        assert!(!AuthError::Validator("db".into()).is_client_error());
    }

    #[test]
    fn challenge_rejects_crlf_and_escapes_quotes() {
        assert!(challenge("safe\r\nX-Injected: evil").is_err());
        assert!(challenge("").is_err());
        let value = challenge(r#"a "b" \c"#).unwrap();
        assert_eq!(
            value.to_str().unwrap(),
            r#"Basic realm="a \"b\" \\c", charset="UTF-8""#
        );
    }

    #[test]
    fn response_hides_internal_details() {
        let resp = AuthError::Validator("secret db dsn".into()).to_response("x");
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(resp.headers().get(header::WWW_AUTHENTICATE).is_none());
        let resp = AuthError::InvalidCredentials.to_response("x");
        assert!(resp.headers().get(header::WWW_AUTHENTICATE).is_some());
        let req = ntex::web::test::TestRequest::default().to_http_request();
        let resp = web::WebResponseError::error_response(&AuthError::MissingHeader, &req);
        assert_eq!(
            resp.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            r#"Basic realm="Restricted Area", charset="UTF-8""#
        );
        let resp = AuthError::RateLimited { retry_after: 42 }.to_response("x");
        assert_eq!(resp.headers().get(header::RETRY_AFTER).unwrap(), "42");
    }
}

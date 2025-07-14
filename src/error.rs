use ntex::{http::StatusCode, web};
use thiserror::Error;

#[cfg(feature = "json")]
use serde::{Deserialize, Serialize};

/// Authentication errors
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Missing Authorization header")]
    MissingHeader,
    #[error("Invalid Authorization header format")]
    InvalidFormat,
    #[error("Invalid Base64 encoding")]
    InvalidBase64,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("User validation failed: {0}")]
    ValidationFailed(String),
    #[error("Cache operation failed: {0}")]
    CacheError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

pub type AuthResult<T> = Result<T, AuthError>;

#[derive(Debug)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
struct AuthErrorResponse {
    code: u32,
    message: String,
    error: String,
    #[cfg_attr(feature = "json", serde(skip_serializing_if = "Option::is_none"))]
    details: Option<String>,
}

impl AuthError {
    /// Create HTTP 401 response with proper WWW-Authenticate header
    pub fn to_response(&self, realm: &str) -> web::HttpResponse {
        self.to_response_with_details(realm, None)
    }

    /// Create HTTP 401 response with custom details
    pub fn to_response_with_details(&self, realm: &str, details: Option<String>) -> web::HttpResponse {
        let error_response = AuthErrorResponse {
            code: 401,
            message: "Authentication required".to_string(),
            error: self.to_string(),
            details,
        };

        #[cfg(feature = "json")]
        let body = serde_json::to_string(&error_response)
            .unwrap_or_else(|_| r#"{"code":401,"message":"Authentication required"}"#.to_string());

        #[cfg(not(feature = "json"))]
        let body = format!(
            r#"{{"code":401,"message":"Authentication required","error":"{}"}}"#,
            self
        );

        let www_authenticate = format!("Basic realm=\"{}\"", realm);

        web::HttpResponse::build(StatusCode::UNAUTHORIZED)
            .set_header("content-type", "application/json")
            .set_header("www-authenticate", www_authenticate)
            .body(body)
    }
}

impl web::error::WebResponseError for AuthError {
    fn status_code(&self) -> StatusCode {
        StatusCode::UNAUTHORIZED
    }

    fn error_response(&self, _req: &ntex::web::HttpRequest) -> web::HttpResponse {
        self.to_response("Restricted Area")
    }
}
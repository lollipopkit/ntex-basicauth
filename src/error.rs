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
}

pub type AuthResult<T> = Result<T, AuthError>;

#[derive(Debug)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
struct AuthErrorResponse {
    code: u32,
    message: String,
    error: String,
}

impl web::error::WebResponseError for AuthError {
    fn status_code(&self) -> StatusCode {
        StatusCode::UNAUTHORIZED
    }

    fn error_response(&self, _req: &ntex::web::HttpRequest) -> web::HttpResponse {
        let error_response = AuthErrorResponse {
            code: 401,
            message: "Authentication required".to_string(),
            error: self.to_string(),
        };

        #[cfg(feature = "json")]
        let body = serde_json::to_string(&error_response)
            .unwrap_or_else(|_| r#"{"code":401,"message":"Authentication required"}"#.to_string());

        #[cfg(not(feature = "json"))]
        let body = format!(
            r#"{{"code":401,"message":"Authentication required","error":"{}"}}"#,
            self
        );

        web::HttpResponse::build(self.status_code())
            .set_header("content-type", "application/json")
            .set_header("www-authenticate", "Basic realm=\"Restricted Area\"")
            .body(body)
    }
}
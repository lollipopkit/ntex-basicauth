//! Authentication error types and response handling

use ntex::{http::StatusCode, web};
use thiserror::Error;

#[cfg(feature = "json")]
use serde::{Deserialize, Serialize};

/// Authentication error type
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Missing Authorization header")]
    /// Missing Authorization header
    MissingHeader,

    #[error("Invalid Authorization header format")]
    /// Invalid format of Authorization header
    InvalidFormat,

    #[error("Invalid Base64 encoding")]
    /// Invalid Base64 encoding
    InvalidBase64,

    #[error("Invalid user credentials")]
    /// Invalid user credentials
    InvalidCredentials,

    #[error("User validation failed: {0}")]
    /// User validation failed with a message
    ValidationFailed(String),

    #[error("Cache operation failed: {0}")]
    /// Cache operation failed with a message
    CacheError(String),

    #[error("Configuration error: {0}")]
    /// Configuration error with a message
    ConfigError(String),

    #[error("Internal server error: {0}")]
    /// Internal server error with a message
    InternalError(String),
}

/// Authentication result type
pub type AuthResult<T> = Result<T, AuthError>;

/// Error response structure
#[derive(Debug)]
#[cfg_attr(feature = "json", derive(Serialize, Deserialize))]
struct AuthErrorResponse {
    code: u16,
    message: &'static str,
    error: String,
    #[cfg_attr(feature = "json", serde(skip_serializing_if = "Option::is_none"))]
    details: Option<String>,
    #[cfg_attr(feature = "json", serde(skip_serializing_if = "Option::is_none"))]
    error_id: Option<String>,
}

impl AuthError {
    /// Create HTTP 401 response with appropriate WWW-Authenticate header
    pub fn to_response(&self, realm: &str) -> web::HttpResponse {
        self.to_response_with_details(realm, None)
    }

    /// Create HTTP 401 response with custom details
    pub fn to_response_with_details(
        &self,
        realm: &str,
        details: Option<String>,
    ) -> web::HttpResponse {
        let (status_code, message) = match self {
            AuthError::MissingHeader | AuthError::InvalidFormat | AuthError::InvalidBase64 => {
                (StatusCode::UNAUTHORIZED, "Authentication required")
            }
            AuthError::InvalidCredentials => (StatusCode::UNAUTHORIZED, "Invalid credentials"),
            AuthError::ValidationFailed(_) => (StatusCode::UNAUTHORIZED, "Validation failed"),
            AuthError::ConfigError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Configuration error"),
            AuthError::CacheError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Cache error"),
            AuthError::InternalError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal error"),
        };

        let error_response = AuthErrorResponse {
            code: status_code.as_u16(),
            message,
            error: self.to_string(),
            details,
            error_id: Some(self.error_id()),
        };

        #[cfg(feature = "json")]
        let body = serde_json::to_string(&error_response)
            .unwrap_or_else(|_| self.fallback_json_response());

        #[cfg(not(feature = "json"))]
        let body = format!(
            r#"{{"code":{},"message":"{}","error":"{}"}}"#,
            error_response.code,
            error_response.message,
            self.escape_json(&error_response.error)
        );

        let mut binding = web::HttpResponse::build(status_code);
        let mut response = binding
            .set_header("content-type", "application/json")
            .set_header("cache-control", "no-store");

        // Only add WWW-Authenticate header for authentication errors
        if status_code == StatusCode::UNAUTHORIZED {
            let www_authenticate = format!("Basic realm=\"{}\", charset=\"UTF-8\"", self.escape_header_value(realm));
            response = response.set_header("www-authenticate", www_authenticate);
        }

        response.body(body)
    }

    /// Generate error ID for log tracing
    fn error_id(&self) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        std::mem::discriminant(self).hash(&mut hasher);
        format!("AUTH_{:x}", hasher.finish())
    }

    #[cfg(not(feature = "json"))]
    /// Escape JSON string
    fn escape_json(&self, s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
            .replace('\r', "\\r")
            .replace('\t', "\\t")
    }

    /// Escape HTTP header value
    fn escape_header_value(&self, s: &str) -> String {
        s.replace('"', "\\\"")
    }

    /// Fallback JSON response (when serialization fails)
    fn fallback_json_response(&self) -> String {
        r#"{"code":500,"message":"Internal error","error":"Response serialization failed"}"#
            .to_string()
    }

    /// Check if this is a client error
    pub fn is_client_error(&self) -> bool {
        matches!(
            self,
            AuthError::MissingHeader
                | AuthError::InvalidFormat
                | AuthError::InvalidBase64
                | AuthError::InvalidCredentials
        )
    }

    /// Check if this is a server error
    pub fn is_server_error(&self) -> bool {
        !self.is_client_error()
    }

    /// Get suggested log level
    pub fn log_level(&self) -> &'static str {
        match self {
            AuthError::MissingHeader | AuthError::InvalidCredentials => "info",
            AuthError::InvalidFormat | AuthError::InvalidBase64 => "warn",
            AuthError::ValidationFailed(_) => "warn",
            AuthError::ConfigError(_) | AuthError::InternalError(_) => "error",
            AuthError::CacheError(_) => "warn",
        }
    }
}

impl web::error::WebResponseError for AuthError {
    fn status_code(&self) -> StatusCode {
        match self {
            AuthError::MissingHeader
            | AuthError::InvalidFormat
            | AuthError::InvalidBase64
            | AuthError::InvalidCredentials
            | AuthError::ValidationFailed(_) => StatusCode::UNAUTHORIZED,

            AuthError::ConfigError(_) | AuthError::CacheError(_) | AuthError::InternalError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    fn error_response(&self, _req: &ntex::web::HttpRequest) -> web::HttpResponse {
        self.to_response("Restricted Area")
    }
}

/// Convenience macro for creating errors
#[macro_export]
macro_rules! auth_error {
    (missing_header) => {
        $crate::AuthError::MissingHeader
    };
    (invalid_format) => {
        $crate::AuthError::InvalidFormat
    };
    (invalid_base64) => {
        $crate::AuthError::InvalidBase64
    };
    (invalid_credentials) => {
        $crate::AuthError::InvalidCredentials
    };
    (validation_failed, $msg:expr) => {
        $crate::AuthError::ValidationFailed($msg.to_string())
    };
    (cache_error, $msg:expr) => {
        $crate::AuthError::CacheError($msg.to_string())
    };
    (config_error, $msg:expr) => {
        $crate::AuthError::ConfigError($msg.to_string())
    };
    (internal_error, $msg:expr) => {
        $crate::AuthError::InternalError($msg.to_string())
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_classification() {
        assert!(AuthError::MissingHeader.is_client_error());
        assert!(AuthError::InvalidCredentials.is_client_error());
        assert!(AuthError::ConfigError("test".to_string()).is_server_error());
        assert!(AuthError::InternalError("test".to_string()).is_server_error());
    }

    #[test]
    fn test_error_id_consistency() {
        let error1 = AuthError::MissingHeader;
        let error2 = AuthError::MissingHeader;
        assert_eq!(error1.error_id(), error2.error_id());

        let error3 = AuthError::InvalidCredentials;
        assert_ne!(error1.error_id(), error3.error_id());
    }

    #[cfg(not(feature = "json"))]
    #[test]
    fn test_json_escaping() {
        let error =
            AuthError::ValidationFailed("Message with \"quotes\" and\nnew line".to_string());
        let escaped = error.escape_json(&error.to_string());
        assert!(!escaped.contains('\n'));
        assert!(escaped.contains("\\\""));
    }

    #[test]
    fn test_macro_usage() {
        let _error1 = auth_error!(missing_header);
        let _error2 = auth_error!(validation_failed, "Custom message");
        let _error3 = auth_error!(config_error, "Configuration issue");
    }
}

//! Credentials and user validators

#[cfg(feature = "bcrypt")]
use crate::error::AuthError;
use crate::error::AuthResult;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Boxed `Send` future returned by [`UserValidator::validate`]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Credentials decoded from a Basic `Authorization` header.
///
/// The password is wiped from memory on drop and redacted in `Debug` output.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Credentials {
    /// Username
    #[zeroize(skip)]
    pub username: String,
    /// Password
    pub password: String,
}

impl Credentials {
    /// Create new credentials
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }

    /// Constant-time comparison of the password against `expected`.
    ///
    /// Both sides are hashed first so the comparison does not leak length.
    pub fn verify_password(&self, expected: &str) -> bool {
        digest(&self.password).ct_eq(&digest(expected)).into()
    }

    /// Whether both fields satisfy RFC 7617 (no colon in the username, no
    /// control characters anywhere).
    pub fn is_valid_format(&self) -> bool {
        is_valid_username(&self.username) && !self.password.chars().any(char::is_control)
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

/// Whether `username` is acceptable for Basic auth: at most 255 bytes, no
/// colon and no control characters. Non-ASCII (UTF-8) usernames are allowed.
pub fn is_valid_username(username: &str) -> bool {
    username.len() <= 255 && !username.chars().any(|c| c == ':' || c.is_control())
}

fn digest(s: &str) -> [u8; 32] {
    Sha256::digest(s.as_bytes()).into()
}

/// Custom authentication backend.
///
/// Return `Ok(false)` for unknown users or wrong passwords and `Err` only for
/// backend failures; errors are answered with 500 instead of 401.
pub trait UserValidator: Send + Sync {
    /// Validate user credentials
    fn validate<'a>(&'a self, credentials: &'a Credentials) -> BoxFuture<'a, AuthResult<bool>>;
}

impl<T: UserValidator + ?Sized> UserValidator for Arc<T> {
    fn validate<'a>(&'a self, credentials: &'a Credentials) -> BoxFuture<'a, AuthResult<bool>> {
        (**self).validate(credentials)
    }
}

/// In-memory user list.
///
/// Only SHA-256 digests of the passwords are kept, and unknown users go
/// through the same comparison as known ones to avoid username enumeration
/// through response timing.
#[derive(Default)]
pub struct StaticUserValidator {
    users: HashMap<String, [u8; 32]>,
    case_insensitive: bool,
}

impl StaticUserValidator {
    /// Create an empty validator
    pub fn new() -> Self {
        Self::default()
    }

    /// Match usernames case-insensitively. Existing usernames are normalized;
    /// on collision the last inserted entry wins.
    pub fn case_insensitive(mut self) -> Self {
        self.case_insensitive = true;
        self.users = std::mem::take(&mut self.users)
            .into_iter()
            .map(|(k, v)| (k.to_lowercase(), v))
            .collect();
        self
    }

    /// Add or replace a user
    pub fn add_user(
        &mut self,
        username: impl Into<String>,
        password: impl AsRef<str>,
    ) -> &mut Self {
        let mut username = username.into();
        if self.case_insensitive {
            username = username.to_lowercase();
        }
        self.users.insert(username, digest(password.as_ref()));
        self
    }

    /// Check if user exists
    pub fn contains_user(&self, username: &str) -> bool {
        self.users.contains_key(self.key(username).as_ref())
    }

    /// Number of users
    pub fn len(&self) -> usize {
        self.users.len()
    }

    /// Whether there are no users
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    fn key<'a>(&self, username: &'a str) -> Cow<'a, str> {
        if self.case_insensitive {
            Cow::Owned(username.to_lowercase())
        } else {
            Cow::Borrowed(username)
        }
    }
}

impl<U: Into<String>, P: AsRef<str>> FromIterator<(U, P)> for StaticUserValidator {
    fn from_iter<I: IntoIterator<Item = (U, P)>>(iter: I) -> Self {
        let mut v = Self::new();
        v.extend(iter);
        v
    }
}

impl<U: Into<String>, P: AsRef<str>> Extend<(U, P)> for StaticUserValidator {
    fn extend<I: IntoIterator<Item = (U, P)>>(&mut self, iter: I) {
        for (u, p) in iter {
            self.add_user(u, p);
        }
    }
}

impl UserValidator for StaticUserValidator {
    fn validate<'a>(&'a self, credentials: &'a Credentials) -> BoxFuture<'a, AuthResult<bool>> {
        let stored = self.users.get(self.key(&credentials.username).as_ref());
        // No SHA-256 output equals all zeros in practice, so the dummy never matches.
        let expected = stored.unwrap_or(&[0; 32]);
        let matches: bool = digest(&credentials.password).ct_eq(expected).into();
        Box::pin(std::future::ready(Ok(matches && stored.is_some())))
    }
}

/// BCrypt validator. Verification runs on the blocking thread pool.
#[cfg(feature = "bcrypt")]
pub struct BcryptUserValidator {
    users: HashMap<String, String>,
    cost: u32,
    /// Cost of the dummy hash used for unknown users, so they take as long as
    /// known ones. Tracks the highest cost among the stored hashes.
    dummy_cost: u32,
    dummy_hash: Arc<std::sync::OnceLock<String>>,
}

#[cfg(feature = "bcrypt")]
impl Default for BcryptUserValidator {
    fn default() -> Self {
        Self {
            users: HashMap::new(),
            cost: bcrypt::DEFAULT_COST,
            dummy_cost: bcrypt::DEFAULT_COST,
            dummy_hash: Default::default(),
        }
    }
}

#[cfg(feature = "bcrypt")]
impl BcryptUserValidator {
    /// Create an empty validator
    pub fn new() -> Self {
        Self::default()
    }

    /// Cost factor used by [`add_user_with_password`](Self::add_user_with_password)
    pub fn with_cost(mut self, cost: u32) -> Self {
        self.cost = cost;
        self
    }

    /// Add a user with a precomputed BCrypt hash
    pub fn add_user(&mut self, username: impl Into<String>, hash: impl Into<String>) -> &mut Self {
        let hash = hash.into();
        if let Some(cost) = hash.split('$').nth(2).and_then(|c| c.parse().ok()) {
            self.dummy_cost = self.dummy_cost.max(cost);
        }
        self.users.insert(username.into(), hash);
        self
    }

    /// Hash `password` with the configured cost and add the user
    pub fn add_user_with_password(
        &mut self,
        username: impl Into<String>,
        password: &str,
    ) -> AuthResult<&mut Self> {
        let hash = bcrypt::hash(password, self.cost)
            .map_err(|e| AuthError::Config(format!("bcrypt hash failed: {e}")))?;
        Ok(self.add_user(username, hash))
    }

    /// Number of users
    pub fn len(&self) -> usize {
        self.users.len()
    }

    /// Whether there are no users
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }
}

#[cfg(feature = "bcrypt")]
impl<U: Into<String>, H: Into<String>> FromIterator<(U, H)> for BcryptUserValidator {
    fn from_iter<I: IntoIterator<Item = (U, H)>>(iter: I) -> Self {
        let mut v = Self::new();
        for (u, h) in iter {
            v.add_user(u, h);
        }
        v
    }
}

#[cfg(feature = "bcrypt")]
impl UserValidator for BcryptUserValidator {
    fn validate<'a>(&'a self, credentials: &'a Credentials) -> BoxFuture<'a, AuthResult<bool>> {
        let hash = self.users.get(&credentials.username).cloned();
        let password = zeroize::Zeroizing::new(credentials.password.clone());
        let dummy_hash = Arc::clone(&self.dummy_hash);
        let dummy_cost = self.dummy_cost;

        Box::pin(async move {
            ntex::rt::spawn_blocking(move || match hash {
                Some(hash) => bcrypt::verify(password.as_str(), &hash)
                    .map_err(|e| AuthError::Validator(format!("bcrypt verify failed: {e}"))),
                None => {
                    let dummy =
                        dummy_hash.get_or_init(|| bcrypt::hash("", dummy_cost).unwrap_or_default());
                    let _ = bcrypt::verify(password.as_str(), dummy);
                    Ok(false)
                }
            })
            .await
            .map_err(|_| AuthError::Validator("bcrypt task failed".into()))?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[ntex::test]
    async fn static_validator() {
        let v: StaticUserValidator = [("admin", "secret"), ("user", "pass:with:colons")]
            .into_iter()
            .collect();
        assert!(
            v.validate(&Credentials::new("admin", "secret"))
                .await
                .unwrap()
        );
        assert!(
            v.validate(&Credentials::new("user", "pass:with:colons"))
                .await
                .unwrap()
        );
        assert!(
            !v.validate(&Credentials::new("admin", "wrong"))
                .await
                .unwrap()
        );
        assert!(!v.validate(&Credentials::new("nobody", "")).await.unwrap());
        assert!(
            !v.validate(&Credentials::new("ADMIN", "secret"))
                .await
                .unwrap()
        );
    }

    #[ntex::test]
    async fn case_insensitive_applies_to_existing_users() {
        let mut v = StaticUserValidator::new();
        v.add_user("Admin", "secret");
        let v = v.case_insensitive();
        assert!(v.contains_user("ADMIN"));
        assert!(
            v.validate(&Credentials::new("admin", "secret"))
                .await
                .unwrap()
        );
    }

    #[test]
    fn credentials_format() {
        assert!(Credentials::new("user", "pass").is_valid_format());
        assert!(Credentials::new("", "pass").is_valid_format());
        assert!(Credentials::new("用户", "pass").is_valid_format());
        assert!(!Credentials::new("user:name", "pass").is_valid_format());
        assert!(!Credentials::new("user", "pass\nword").is_valid_format());
        assert!(!Credentials::new("user", "pass\tword").is_valid_format());
        assert!(!Credentials::new("a".repeat(256), "").is_valid_format());
    }

    #[test]
    fn debug_redacts_password() {
        let s = format!("{:?}", Credentials::new("admin", "hunter2"));
        assert!(s.contains("admin"));
        assert!(!s.contains("hunter2"));
    }

    #[cfg(feature = "bcrypt")]
    #[ntex::test]
    async fn bcrypt_validator() {
        let mut v = BcryptUserValidator::new().with_cost(4);
        v.add_user_with_password("admin", "secret").unwrap();
        assert!(
            v.validate(&Credentials::new("admin", "secret"))
                .await
                .unwrap()
        );
        assert!(
            !v.validate(&Credentials::new("admin", "wrong"))
                .await
                .unwrap()
        );
        assert!(
            !v.validate(&Credentials::new("nobody", "secret"))
                .await
                .unwrap()
        );
    }
}

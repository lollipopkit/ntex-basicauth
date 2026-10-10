//! Middleware, builder and metrics

use crate::error::{AuthError, AuthResult, challenge};
use crate::filter::PathFilter;
use crate::limiter::{ConcurrencyLimiter, FailureLimiter, ProxyTrust};
use crate::validator::{Credentials, StaticUserValidator, UserValidator};
use base64::{Engine, engine::general_purpose::STANDARD};
use ipnet::IpNet;
use ntex::http::Payload;
use ntex::http::header::{self, HeaderMap, HeaderValue};
use ntex::time::timeout;
use ntex::{Middleware, Service, ServiceCtx, web};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

#[cfg(feature = "cache")]
use crate::cache::{AuthCache, CacheConfig};

/// Identity of the authenticated user, stored in the request extensions.
///
/// Use it directly as a handler argument (or `Option<AuthenticatedUser>` on
/// routes that may bypass authentication):
///
/// ```rust
/// use ntex_basicauth::AuthenticatedUser;
///
/// async fn handler(user: AuthenticatedUser) -> String {
///     format!("Hello, {}!", user.username())
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedUser {
    username: String,
}

impl AuthenticatedUser {
    /// Username
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Authenticated user of `req`, if any
    pub fn get(req: &web::HttpRequest) -> Option<Self> {
        req.extensions().get::<Self>().cloned()
    }
}

impl<Err: web::ErrorRenderer> web::FromRequest<Err> for AuthenticatedUser {
    type Error = AuthError;

    async fn from_request(req: &web::HttpRequest, _: &mut Payload) -> Result<Self, AuthError> {
        Self::get(req).ok_or_else(|| {
            log::error!("AuthenticatedUser extracted on a route without BasicAuth");
            AuthError::Config("BasicAuth middleware is not applied to this route".into())
        })
    }
}

/// Authentication counters. Shared by all workers using the same [`BasicAuth`].
#[derive(Debug, Default)]
pub struct AuthMetrics {
    requests: AtomicU64,
    successes: AtomicU64,
    failures: AtomicU64,
    cache_hits: AtomicU64,
    validations: AtomicU64,
    validation_micros: AtomicU64,
}

impl AuthMetrics {
    /// Requests that went through authentication (skipped paths excluded)
    pub fn requests(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }

    /// Successful authentications
    pub fn successes(&self) -> u64 {
        self.successes.load(Ordering::Relaxed)
    }

    /// Failed authentications, including missing headers and rate limiting
    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    /// Successful authentications answered from the cache
    pub fn cache_hits(&self) -> u64 {
        self.cache_hits.load(Ordering::Relaxed)
    }

    /// Calls to the validator
    pub fn validations(&self) -> u64 {
        self.validations.load(Ordering::Relaxed)
    }

    /// Average validator latency
    pub fn avg_validation_time(&self) -> Duration {
        let micros = self.validation_micros.load(Ordering::Relaxed);
        Duration::from_micros(micros.checked_div(self.validations()).unwrap_or(0))
    }

    /// Reset all counters
    pub fn reset(&self) {
        for counter in [
            &self.requests,
            &self.successes,
            &self.failures,
            &self.cache_hits,
            &self.validations,
            &self.validation_micros,
        ] {
            counter.store(0, Ordering::Relaxed);
        }
    }

    fn incr(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    fn record_validation(&self, elapsed: Duration) {
        Self::incr(&self.validations);
        let micros = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        self.validation_micros.fetch_add(micros, Ordering::Relaxed);
    }
}

type ErrorHandler = Box<dyn Fn(&AuthError, &str) -> web::HttpResponse + Send + Sync>;

/// Basic authentication middleware.
///
/// Cloning is cheap and clones share the cache, the failure limiter and the
/// metrics. Build it once outside `HttpServer::new` and clone it into the app
/// factory, otherwise every worker gets its own limiter and counters.
#[derive(Clone)]
pub struct BasicAuth(Arc<Inner>);

struct Inner {
    realm: String,
    challenge: HeaderValue,
    validator: Arc<dyn UserValidator>,
    #[cfg(feature = "cache")]
    cache: Option<AuthCache>,
    path_filter: Option<PathFilter>,
    max_header_size: usize,
    log_failures: bool,
    log_usernames: bool,
    error_handler: Option<ErrorHandler>,
    validation_timeout: Option<Duration>,
    concurrency: Option<Arc<ConcurrencyLimiter>>,
    failure_limiter: Option<FailureLimiter>,
    proxy_trust: ProxyTrust,
    metrics: AuthMetrics,
}

impl BasicAuth {
    /// Start building a middleware
    pub fn builder() -> BasicAuthBuilder {
        BasicAuthBuilder::new()
    }

    /// Authentication counters
    pub fn metrics(&self) -> &AuthMetrics {
        &self.0.metrics
    }

    /// Realm sent in the `WWW-Authenticate` challenge
    pub fn realm(&self) -> &str {
        &self.0.realm
    }

    /// Drop all cached authentications, e.g. after a password change
    #[cfg(feature = "cache")]
    pub fn clear_cache(&self) {
        if let Some(cache) = &self.0.cache {
            cache.clear();
        }
    }
}

impl Inner {
    async fn authenticate(
        &self,
        headers: &HeaderMap,
        peer: Option<IpAddr>,
    ) -> AuthResult<AuthenticatedUser> {
        AuthMetrics::incr(&self.metrics.requests);

        let ip = self.proxy_trust.client_ip(peer, headers);
        if let Some(retry) = self
            .failure_limiter
            .as_ref()
            .and_then(|l| l.blocked_for(ip))
        {
            let retry_after = retry.as_secs() + u64::from(retry.subsec_nanos() > 0);
            return Err(self.fail(AuthError::RateLimited { retry_after }, ip, None));
        }

        let credentials = match parse_credentials(headers, self.max_header_size) {
            Ok(credentials) => credentials,
            Err(err) => return Err(self.fail(err, ip, None)),
        };

        match self.check(&credentials).await {
            Ok(true) => {
                AuthMetrics::incr(&self.metrics.successes);
                Ok(AuthenticatedUser {
                    username: credentials.username.clone(),
                })
            }
            Ok(false) => Err(self.fail(AuthError::InvalidCredentials, ip, Some(&credentials))),
            Err(err) => Err(self.fail(err, ip, Some(&credentials))),
        }
    }

    /// Record and log a failure, then hand the error back.
    fn fail(
        &self,
        err: AuthError,
        ip: Option<IpAddr>,
        credentials: Option<&Credentials>,
    ) -> AuthError {
        AuthMetrics::incr(&self.metrics.failures);

        if matches!(
            err,
            AuthError::InvalidHeader | AuthError::InvalidCredentials
        ) && let Some(limiter) = &self.failure_limiter
        {
            limiter.record_failure(ip);
        }

        let user = credentials
            .filter(|_| self.log_usernames)
            .map(|c| c.username.as_str());
        if !err.is_client_error() {
            log::error!("basic auth failed: {err}, ip: {ip:?}, user: {user:?}");
        } else if self.log_failures && !matches!(err, AuthError::MissingHeader) {
            log::warn!("basic auth failed: {err}, ip: {ip:?}, user: {user:?}");
        }
        err
    }

    async fn check(&self, credentials: &Credentials) -> AuthResult<bool> {
        #[cfg(feature = "cache")]
        let cache_key = self.cache.as_ref().map(|cache| cache.key(credentials));
        #[cfg(feature = "cache")]
        if let (Some(cache), Some(key)) = (&self.cache, &cache_key)
            && cache.contains(key)
        {
            AuthMetrics::incr(&self.metrics.cache_hits);
            return Ok(true);
        }

        let start = Instant::now();
        let valid = self.validate(credentials).await;
        self.metrics.record_validation(start.elapsed());

        #[cfg(feature = "cache")]
        if let (Ok(true), Some(cache), Some(key)) = (&valid, &self.cache, cache_key) {
            cache.insert(key);
        }
        valid
    }

    /// Run the validator under the optional concurrency limit and timeout.
    ///
    /// With a concurrency limit, validation runs in a spawned task holding the
    /// permit until the validator really finishes, even if this request times
    /// out. Validators that cannot be cancelled (bcrypt on a blocking thread)
    /// therefore cannot pile up past the limit. Waiting for a permit counts
    /// towards the timeout.
    async fn validate(&self, credentials: &Credentials) -> AuthResult<bool> {
        match &self.concurrency {
            None => {
                self.with_timeout(self.validator.validate(credentials))
                    .await
            }
            Some(limiter) => {
                let validator = Arc::clone(&self.validator);
                let limiter = Arc::clone(limiter);
                let credentials = credentials.clone();
                let task = ntex::rt::spawn(async move {
                    let _permit = limiter.acquire().await;
                    validator.validate(&credentials).await
                });
                self.with_timeout(async {
                    task.await
                        .map_err(|_| AuthError::Validator("validation task failed".into()))?
                })
                .await
            }
        }
    }

    async fn with_timeout(&self, fut: impl Future<Output = AuthResult<bool>>) -> AuthResult<bool> {
        match self.validation_timeout {
            Some(dur) => timeout(dur, fut).await.map_err(|_| AuthError::Timeout)?,
            None => fut.await,
        }
    }

    fn error_response(&self, err: &AuthError) -> web::HttpResponse {
        match &self.error_handler {
            Some(handler) => handler(err, &self.realm),
            None => err.response(Some(&self.challenge)),
        }
    }
}

/// Decode a Basic `Authorization` header (RFC 7617).
fn parse_credentials(headers: &HeaderMap, max_size: usize) -> AuthResult<Credentials> {
    let value = headers
        .get(header::AUTHORIZATION)
        .ok_or(AuthError::MissingHeader)?;
    if value.len() > max_size {
        return Err(AuthError::InvalidHeader);
    }
    let (scheme, token) = value
        .to_str()
        .ok()
        .and_then(|v| v.split_once(' '))
        .ok_or(AuthError::InvalidHeader)?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return Err(AuthError::InvalidHeader);
    }

    let decoded = Zeroizing::new(
        STANDARD
            .decode(token.trim_matches(' '))
            .map_err(|_| AuthError::InvalidHeader)?,
    );
    let (username, password) = std::str::from_utf8(&decoded)
        .ok()
        .and_then(|s| s.split_once(':'))
        .ok_or(AuthError::InvalidHeader)?;

    let credentials = Credentials::new(username, password);
    if !credentials.is_valid_format() {
        return Err(AuthError::InvalidCredentials);
    }
    Ok(credentials)
}

impl<S, Cfg> Middleware<S, Cfg> for BasicAuth {
    type Service = BasicAuthService<S>;

    fn create(&self, service: S, _: Cfg) -> Self::Service {
        BasicAuthService {
            service,
            auth: self.clone(),
        }
    }
}

/// Service created by the [`BasicAuth`] middleware
pub struct BasicAuthService<S> {
    service: S,
    auth: BasicAuth,
}

impl<S, Err> Service<web::WebRequest<Err>> for BasicAuthService<S>
where
    S: Service<web::WebRequest<Err>, Response = web::WebResponse, Error = web::Error>,
    Err: web::ErrorRenderer,
{
    type Response = web::WebResponse;
    type Error = web::Error;

    ntex::forward_ready!(service);
    ntex::forward_poll!(service);
    ntex::forward_shutdown!(service);

    async fn call(
        &self,
        req: web::WebRequest<Err>,
        ctx: ServiceCtx<'_, Self>,
    ) -> Result<Self::Response, Self::Error> {
        let auth = &*self.auth.0;
        if auth
            .path_filter
            .as_ref()
            .is_some_and(|filter| filter.should_skip(req.path()))
        {
            return ctx.call(&self.service, req).await;
        }

        match auth
            .authenticate(req.headers(), req.peer_addr().map(|addr| addr.ip()))
            .await
        {
            Ok(user) => {
                req.extensions_mut().insert(user);
                ctx.call(&self.service, req).await
            }
            Err(err) => Ok(req.into_response(auth.error_response(&err))),
        }
    }
}

/// Builder for [`BasicAuth`]
pub struct BasicAuthBuilder {
    users: StaticUserValidator,
    validator: Option<Arc<dyn UserValidator>>,
    case_sensitive: bool,
    realm: String,
    #[cfg(feature = "cache")]
    cache: Option<CacheConfig>,
    path_filter: Option<PathFilter>,
    max_header_size: usize,
    log_failures: bool,
    log_usernames: bool,
    error_handler: Option<ErrorHandler>,
    validation_timeout: Option<Duration>,
    max_concurrent_validations: Option<usize>,
    max_failures_per_ip: Option<(u32, Duration)>,
    proxy_trust: ProxyTrust,
}

impl Default for BasicAuthBuilder {
    fn default() -> Self {
        Self {
            users: StaticUserValidator::new(),
            validator: None,
            case_sensitive: true,
            realm: "Restricted Area".into(),
            #[cfg(feature = "cache")]
            cache: None,
            path_filter: None,
            max_header_size: 8192,
            log_failures: false,
            log_usernames: false,
            error_handler: None,
            validation_timeout: Some(Duration::from_secs(30)),
            max_concurrent_validations: None,
            max_failures_per_ip: None,
            proxy_trust: ProxyTrust::default(),
        }
    }
}

impl BasicAuthBuilder {
    /// Create a builder with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a user with a plaintext password
    pub fn user(mut self, username: impl Into<String>, password: impl AsRef<str>) -> Self {
        self.users.add_user(username, password);
        self
    }

    /// Add users with plaintext passwords
    pub fn users<U: Into<String>, P: AsRef<str>>(
        mut self,
        users: impl IntoIterator<Item = (U, P)>,
    ) -> Self {
        self.users.extend(users);
        self
    }

    /// Load users from a file with one `username:password` per line. Empty
    /// lines and lines starting with `#` are ignored; passwords are taken
    /// verbatim (not trimmed).
    pub fn users_from_file(mut self, path: impl AsRef<std::path::Path>) -> AuthResult<Self> {
        let content = Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|e| AuthError::Config(format!("failed to read user file: {e}")))?,
        );
        for (i, line) in content.lines().enumerate() {
            let line = line.strip_suffix('\r').unwrap_or(line);
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            let (username, password) = line
                .split_once(':')
                .filter(|(u, p)| Credentials::new(*u, *p).is_valid_format())
                .ok_or_else(|| {
                    AuthError::Config(format!("user file line {}: invalid entry", i + 1))
                })?;
            self.users.add_user(username, password);
        }
        Ok(self)
    }

    /// Use a custom validator instead of a user list
    pub fn validator(mut self, validator: impl UserValidator + 'static) -> Self {
        self.validator = Some(Arc::new(validator));
        self
    }

    /// Username case sensitivity for the built-in user list (default: sensitive)
    pub fn case_sensitive(mut self, sensitive: bool) -> Self {
        self.case_sensitive = sensitive;
        self
    }

    /// Realm sent in the `WWW-Authenticate` challenge
    pub fn realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = realm.into();
        self
    }

    /// Cache successful authentications (disabled by default)
    #[cfg(feature = "cache")]
    pub fn cache(mut self, config: CacheConfig) -> Self {
        self.cache = Some(config);
        self
    }

    /// Paths that skip authentication
    pub fn path_filter(mut self, filter: PathFilter) -> Self {
        self.path_filter = Some(filter);
        self
    }

    /// Add exact paths that skip authentication
    pub fn skip_paths<P: Into<String>>(mut self, paths: impl IntoIterator<Item = P>) -> Self {
        self.path_filter = Some(
            self.path_filter
                .take()
                .unwrap_or_default()
                .skip_paths(paths),
        );
        self
    }

    /// Maximum `Authorization` header size in bytes (default: 8192)
    pub fn max_header_size(mut self, size: usize) -> Self {
        self.max_header_size = size;
        self
    }

    /// Log client-side failures at `warn` level (server-side errors are always
    /// logged at `error` level)
    pub fn log_failures(mut self, enabled: bool) -> Self {
        self.log_failures = enabled;
        self
    }

    /// Include usernames in failure logs (default: off)
    pub fn log_usernames(mut self, enabled: bool) -> Self {
        self.log_usernames = enabled;
        self
    }

    /// Custom response for failures. Receives the error and the realm; it is
    /// responsible for the `WWW-Authenticate` header on 401 responses.
    pub fn error_handler<F>(mut self, handler: F) -> Self
    where
        F: Fn(&AuthError, &str) -> web::HttpResponse + Send + Sync + 'static,
    {
        self.error_handler = Some(Box::new(handler));
        self
    }

    /// Validation timeout, `None` to disable (default: 30s). Timeouts are
    /// answered with 503.
    pub fn validation_timeout(mut self, timeout: impl Into<Option<Duration>>) -> Self {
        self.validation_timeout = timeout.into();
        self
    }

    /// Maximum number of validations running at the same time
    pub fn max_concurrent_validations(mut self, max: usize) -> Self {
        self.max_concurrent_validations = Some(max);
        self
    }

    /// Answer 429 to a client IP after `max` failed attempts within `window`.
    /// Successful requests are not counted.
    pub fn max_failures_per_ip(mut self, max: u32, window: Duration) -> Self {
        self.max_failures_per_ip = Some((max, window));
        self
    }

    /// Networks of reverse proxies whose `X-Forwarded-For` is trusted for
    /// [`max_failures_per_ip`](Self::max_failures_per_ip) (default: none).
    ///
    /// When the peer is in one of these networks, the client IP is the
    /// rightmost hop that is not a trusted proxy, so hops a client prepends are
    /// ignored. Behind a proxy that is not listed, all clients share the
    /// proxy's address and therefore its failure budget.
    pub fn trusted_proxies(mut self, proxies: impl IntoIterator<Item = IpNet>) -> Self {
        self.proxy_trust.networks.extend(proxies);
        self
    }

    /// Trust `X-Forwarded-For` on connections without a peer address, such as
    /// a Unix socket that only a local reverse proxy connects to (default:
    /// off). The proxy must set or append the header.
    ///
    /// When off, or when the header is absent or malformed, these requests
    /// share one failure budget: failures from one client then block all
    /// clients without a peer address.
    pub fn trust_peerless_proxy(mut self, trust: bool) -> Self {
        self.proxy_trust.peerless = trust;
        self
    }

    /// Validate the configuration and build the middleware
    pub fn build(self) -> AuthResult<BasicAuth> {
        let validator: Arc<dyn UserValidator> = match self.validator {
            Some(_) if !self.users.is_empty() => {
                return Err(config_err("set either a validator or users, not both"));
            }
            Some(validator) => validator,
            None if self.users.is_empty() => {
                return Err(config_err("a validator or at least one user is required"));
            }
            None if self.case_sensitive => Arc::new(self.users),
            None => Arc::new(self.users.case_insensitive()),
        };

        if self.max_header_size == 0 {
            return Err(config_err("max_header_size must be greater than 0"));
        }
        if self.validation_timeout.is_some_and(|t| t.is_zero()) {
            return Err(config_err("validation_timeout must be greater than 0"));
        }
        if self.max_concurrent_validations == Some(0) {
            return Err(config_err(
                "max_concurrent_validations must be greater than 0",
            ));
        }
        if let Some((max, window)) = self.max_failures_per_ip
            && (max == 0 || window.is_zero())
        {
            return Err(config_err(
                "max_failures_per_ip needs a non-zero limit and window",
            ));
        }
        Ok(BasicAuth(Arc::new(Inner {
            challenge: challenge(&self.realm)?,
            realm: self.realm,
            validator,
            #[cfg(feature = "cache")]
            cache: self.cache.map(AuthCache::new).transpose()?,
            path_filter: self.path_filter,
            max_header_size: self.max_header_size,
            log_failures: self.log_failures,
            log_usernames: self.log_usernames,
            error_handler: self.error_handler,
            validation_timeout: self.validation_timeout,
            concurrency: self
                .max_concurrent_validations
                .map(|max| Arc::new(ConcurrencyLimiter::new(max))),
            failure_limiter: self
                .max_failures_per_ip
                .map(|(max, window)| FailureLimiter::new(max, window)),
            proxy_trust: self.proxy_trust,
            metrics: AuthMetrics::default(),
        })))
    }
}

fn config_err(msg: &str) -> AuthError {
    AuthError::Config(msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::BoxFuture;
    use ntex::Pipeline;
    use ntex::http::StatusCode;
    use ntex::web::{App, test};

    fn basic(creds: &str) -> String {
        format!("Basic {}", STANDARD.encode(creds))
    }

    fn headers(value: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(header::AUTHORIZATION, HeaderValue::from_str(value).unwrap());
        map
    }

    async fn app(
        auth: BasicAuth,
    ) -> Pipeline<impl Service<ntex::http::Request, Response = web::WebResponse, Error = web::Error>>
    {
        test::init_service(App::new().middleware(auth).route(
            "/{tail}*",
            web::get().to(|user: Option<AuthenticatedUser>| async move {
                user.map(|u| u.username).unwrap_or_default()
            }),
        ))
        .await
    }

    async fn get(
        app: &Pipeline<
            impl Service<ntex::http::Request, Response = web::WebResponse, Error = web::Error>,
        >,
        path: &str,
        auth: Option<&str>,
    ) -> web::WebResponse {
        let mut req = test::TestRequest::with_uri(path);
        if let Some(auth) = auth {
            req = req.header(header::AUTHORIZATION, basic(auth));
        }
        test::call_service(app, req.to_request()).await
    }

    #[test]
    fn parse() {
        let c = parse_credentials(&headers(&basic("admin:pa:ss")), 8192).unwrap();
        assert_eq!(
            (c.username.as_str(), c.password.as_str()),
            ("admin", "pa:ss")
        );
        let c = parse_credentials(
            &headers(&format!("bAsIc   {}", STANDARD.encode("a:b"))),
            8192,
        );
        assert!(c.is_ok());

        let err = |v: &str| parse_credentials(&headers(v), 8192).unwrap_err();
        assert!(matches!(err("Bearer abc"), AuthError::InvalidHeader));
        assert!(matches!(err("Basic !!!"), AuthError::InvalidHeader));
        assert!(matches!(err(&basic("nocolon")), AuthError::InvalidHeader));
        assert!(matches!(
            err(&basic("a:b\nc")),
            AuthError::InvalidCredentials
        ));
        assert!(matches!(
            parse_credentials(&HeaderMap::new(), 8192),
            Err(AuthError::MissingHeader)
        ));
        assert!(matches!(
            parse_credentials(&headers(&basic("a:b")), 4),
            Err(AuthError::InvalidHeader)
        ));
    }

    #[ntex::test]
    async fn end_to_end() {
        let auth = BasicAuth::builder()
            .user("admin", "secret")
            .realm("Test")
            .skip_paths(["/health"])
            .build()
            .unwrap();
        let app = app(auth.clone()).await;

        let resp = get(&app, "/", Some("admin:secret")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(test::read_body(resp).await, "admin");

        let resp = get(&app, "/", None).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            resp.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            r#"Basic realm="Test", charset="UTF-8""#
        );

        let resp = get(&app, "/", Some("admin:wrong")).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = get(&app, "/health", None).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let m = auth.metrics();
        assert_eq!((m.requests(), m.successes(), m.failures()), (3, 1, 2));
        assert_eq!(m.validations(), 2);
    }

    #[ntex::test]
    async fn failure_limit_counts_only_failures() {
        // Test requests carry no peer address, so they share the overflow entry.
        let auth = BasicAuth::builder()
            .user("admin", "secret")
            .max_failures_per_ip(2, Duration::from_secs(60))
            .build()
            .unwrap();
        let app = app(auth).await;

        // Successful requests and the initial challenge are not counted.
        for _ in 0..5 {
            let resp = get(&app, "/", Some("admin:secret")).await;
            assert_eq!(resp.status(), StatusCode::OK);
        }
        let resp = get(&app, "/", None).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        for _ in 0..2 {
            let resp = get(&app, "/", Some("admin:wrong")).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }
        let resp = get(&app, "/", Some("admin:secret")).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(resp.headers().get(header::RETRY_AFTER).unwrap(), "60");
    }

    #[ntex::test]
    async fn peerless_proxy_keys_by_forwarded_for() {
        let auth = BasicAuth::builder()
            .user("admin", "secret")
            .max_failures_per_ip(1, Duration::from_secs(60))
            .trust_peerless_proxy(true)
            .build()
            .unwrap();
        let app = app(auth).await;
        let status = async |creds: &str, forwarded: Option<&str>| {
            let mut req = test::TestRequest::default().header(header::AUTHORIZATION, basic(creds));
            if let Some(forwarded) = forwarded {
                req = req.header("x-forwarded-for", forwarded);
            }
            test::call_service(&app, req.to_request()).await.status()
        };

        assert_eq!(
            status("admin:wrong", Some("6.6.6.6, 1.1.1.1")).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            status("admin:secret", Some("7.7.7.7, 1.1.1.1")).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        // Other clients behind the proxy are unaffected.
        assert_eq!(
            status("admin:secret", Some("2.2.2.2")).await,
            StatusCode::OK
        );
        // Without a usable header, requests fall back to the shared entry.
        assert_eq!(status("admin:wrong", None).await, StatusCode::UNAUTHORIZED);
        assert_eq!(
            status("admin:secret", Some("junk")).await,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            status("admin:secret", Some("3.3.3.3")).await,
            StatusCode::OK
        );
    }

    struct SlowValidator;

    impl UserValidator for SlowValidator {
        fn validate<'a>(&'a self, _: &'a Credentials) -> BoxFuture<'a, AuthResult<bool>> {
            Box::pin(async {
                ntex::time::sleep(Duration::from_secs(5)).await;
                Ok(true)
            })
        }
    }

    #[ntex::test]
    async fn validation_timeout() {
        for concurrency in [None, Some(1)] {
            let mut builder = BasicAuth::builder()
                .validator(SlowValidator)
                .validation_timeout(Duration::from_millis(50));
            if let Some(max) = concurrency {
                builder = builder.max_concurrent_validations(max);
            }
            let app = app(builder.build().unwrap()).await;
            let resp = get(&app, "/", Some("a:b")).await;
            assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
    }

    #[ntex::test]
    async fn concurrency_limited_auth_succeeds() {
        let auth = BasicAuth::builder()
            .user("admin", "secret")
            .max_concurrent_validations(2)
            .build()
            .unwrap();
        let app = app(auth).await;
        let resp = get(&app, "/", Some("admin:secret")).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[cfg(feature = "cache")]
    #[ntex::test]
    async fn cache_only_successes() {
        let auth = BasicAuth::builder()
            .user("admin", "secret")
            .cache(CacheConfig::new())
            .build()
            .unwrap();
        let app = app(auth.clone()).await;
        for creds in ["admin:secret", "admin:secret", "admin:wrong", "admin:wrong"] {
            get(&app, "/", Some(creds)).await;
        }
        assert_eq!(auth.metrics().cache_hits(), 1);
        assert_eq!(auth.metrics().validations(), 3);
        assert_eq!(auth.0.cache.as_ref().unwrap().len(), 1);
        auth.clear_cache();
        assert_eq!(auth.0.cache.as_ref().unwrap().len(), 0);
    }

    #[ntex::test]
    async fn custom_error_handler() {
        let auth = BasicAuth::builder()
            .user("admin", "secret")
            .error_handler(|err, _| web::HttpResponse::build(err.status_code()).body("nope"))
            .build()
            .unwrap();
        let app = app(auth).await;
        let resp = get(&app, "/", None).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(test::read_body(resp).await, "nope");
    }

    #[test]
    fn builder_validation() {
        assert!(BasicAuth::builder().build().is_err());
        assert!(
            BasicAuth::builder()
                .user("a", "b")
                .realm("")
                .build()
                .is_err()
        );
        assert!(
            BasicAuth::builder()
                .user("a", "b")
                .validator(SlowValidator)
                .build()
                .is_err()
        );
        assert!(
            BasicAuth::builder()
                .user("a", "b")
                .max_header_size(0)
                .build()
                .is_err()
        );
        let auth = BasicAuth::builder()
            .user("a", "b")
            .realm("App")
            .build()
            .unwrap();
        assert_eq!(auth.realm(), "App");
    }

    #[ntex::test]
    async fn users_from_file() -> std::io::Result<()> {
        use std::io::Write;
        let mut file = tempfile::NamedTempFile::new()?;
        writeln!(
            file,
            "# comment\nadmin:secret\nuser:pass:with:colons\n\nspace: padded \r"
        )?;
        let auth = BasicAuth::builder()
            .users_from_file(file.path())
            .unwrap()
            .build()
            .unwrap();
        let validator = &auth.0.validator;
        let ok = async |u: &str, p: &str| validator.validate(&Credentials::new(u, p)).await;
        assert!(ok("admin", "secret").await.unwrap());
        assert!(ok("user", "pass:with:colons").await.unwrap());
        assert!(ok("space", " padded ").await.unwrap());
        assert!(!ok("space", "padded").await.unwrap());

        let mut bad = tempfile::NamedTempFile::new()?;
        writeln!(bad, "no-colon")?;
        assert!(BasicAuth::builder().users_from_file(bad.path()).is_err());
        Ok(())
    }
}

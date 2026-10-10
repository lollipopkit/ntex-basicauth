# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Breaking

- `BasicAuth::builder()` / `BasicAuthBuilder` is the only way to configure the
  middleware. `BasicAuthConfig`, `BasicAuth::new`, the `single_user_auth` /
  `multi_user_auth` / `auth_with_common_skips` / `bcrypt_auth` helpers,
  `prelude`, `LibInfo`, `version()`, the `BasicAuthMiddleware` alias and the
  `auth_error!` / `path_filter!` macros are removed.
- `BasicAuth` is `Clone` and shares its state between clones. Build it once
  outside `HttpServer::new` and clone it into the app factory; otherwise every
  worker gets its own limiter, cache and metrics.
- The request extensions hold `AuthenticatedUser` (username only) instead of
  `Credentials`. Use it as a handler argument. `extract_credentials`,
  `extract_credentials_web`, `get_username` and `is_user` are removed.
- `rate_limit_per_ip` is replaced by `max_failures_per_ip`, which counts only
  failed attempts (wrong credentials or a malformed header).
- `client_ip_header` is replaced by `trusted_proxies(IpNet...)`.
  `X-Forwarded-For` is read only when the peer is a trusted proxy, and the
  client IP is the rightmost untrusted hop. `IpNet` is re-exported.
- `AuthError` variants: `InvalidFormat` / `InvalidBase64` are merged into
  `InvalidHeader`; `ValidationFailed` / `InternalError` / `CacheError` /
  `ConfigError` become `Validator` / `Config`; `RateLimited` carries
  `retry_after`; `Timeout` is new. The enum is `#[non_exhaustive]`.
- Validator errors respond with 500 and timeouts with 503 (previously 401 and
  500). Response bodies are `{"code":..,"message":..}` without internal error
  text or `error_id`.
- `UserValidator` only has `validate`, returns `BoxFuture`, and no longer
  requires `Debug`. `pre_validate`, `name` and `user_count` are removed.
- `CacheConfig` only has `max_size` and `ttl`; `AuthCache`, `CacheStats` and
  the background cleanup task are removed. `BasicAuth::clear_cache` is new.
- The cache is enabled by default (`CacheConfig::default()`); `with_cache` /
  `disable_cache` are replaced by `cache(impl Into<Option<CacheConfig>>)`,
  `cache(None)` disables it.
- `AuthMetrics` fields are private; validation time is measured in
  microseconds and averaged over validator calls (`avg_validation_time`).
- `ConcurrencyLimiter` and `RateLimiter` are no longer public.
- The `json`, `timing-safe` and `secure-memory` features are removed;
  constant-time comparison and zeroization are always on.
- `common_skip_paths` no longer skips file suffixes (`.js`, `.css`, ...), and
  `observability_skip_paths` is removed.
- `log_usernames_in_production` is renamed to `log_usernames`;
  `enable_metrics` is removed. Logging uses the `log` crate.
- MSRV is 1.88.

### Fixed

- Failed authentications were cached, so every wrong guess was stored and a
  full cache was swept on every request.
- Cache keys used a fixed salt; they now use a per-instance random secret.
- The cache cleanup task was never stopped and kept the cache alive.
- Unknown users returned faster than known ones (notably with bcrypt),
  allowing username enumeration.
- The client IP was taken from the leftmost `X-Forwarded-For` entry of any
  peer, which a client can forge to evade the limiter.
- Once the limiter's map was full, new IPs evicted tracked ones, so rotating
  addresses could clear a block. Unseen IPs now share an overflow entry, as do
  requests without a peer address.
- Suffix rules in `common_skip_paths` exempted dynamic routes such as
  `/api/users/x.js` from authentication. Paths with dot-segments, encoded
  separators (`%2f`, `%5c`), backslashes or double encoding never skip.
- Concurrent requests could exceed the failure budget while their
  validations were in flight; attempts in flight now count against it.
- Out-of-range bcrypt costs in stored hashes no longer break the dummy hash
  used for unknown users.
- Bumped `event-listener` to 5.4.2 (RUSTSEC-2026-0221).
- `Credentials`' `Debug` output contained the password.
- `AuthError`'s `WebResponseError` impl sent 401 without `WWW-Authenticate`.
- Non-ASCII usernames were rejected although the challenge announces UTF-8.
- `users_from_file` trimmed passwords.
- The `regex` feature did not compile without `cache`.
- Readiness, polling and shutdown were not forwarded to the inner service.

### Added

- `AuthenticatedUser` extractor.
- `Retry-After` header on 429 responses.
- `trust_peerless_proxy`: key requests without a peer address (Unix sockets)
  by `X-Forwarded-For` instead of a shared failure budget.
- Client IP and username (with `log_usernames`) in failure logs.
- `StaticUserValidator` stores SHA-256 digests instead of plaintext passwords.
- `LICENSE`, CI.

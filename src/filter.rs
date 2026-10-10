//! Paths that bypass authentication

#[cfg(feature = "regex")]
use regex::Regex;

/// Set of path patterns that skip authentication.
///
/// Paths that a later component could resolve differently never match:
/// dot-segments (`..`, `%2e%2e`), encoded separators (`%2f`, `%5c`),
/// backslashes and double encoding (`%25`). So neither `/static/../admin` nor
/// `/static/%2e%2e%2fadmin` can be used to bypass authentication.
#[derive(Debug, Clone, Default)]
pub struct PathFilter {
    patterns: Vec<PathPattern>,
}

#[derive(Debug, Clone)]
enum PathPattern {
    Exact(String),
    Prefix(String),
    Suffix(String),
    #[cfg(feature = "regex")]
    Regex(Regex),
}

impl PathFilter {
    /// Create an empty filter
    pub fn new() -> Self {
        Self::default()
    }

    /// Skip authentication for an exact path
    pub fn skip_exact(mut self, path: impl Into<String>) -> Self {
        self.patterns.push(PathPattern::Exact(path.into()));
        self
    }

    /// Skip authentication for paths starting with `prefix`
    pub fn skip_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.patterns.push(PathPattern::Prefix(prefix.into()));
        self
    }

    /// Skip authentication for paths ending with `suffix`.
    ///
    /// Use with care: a suffix such as `.js` also matches dynamic routes like
    /// `/api/users/{id}` when the id ends with `.js`.
    pub fn skip_suffix(mut self, suffix: impl Into<String>) -> Self {
        self.patterns.push(PathPattern::Suffix(suffix.into()));
        self
    }

    /// Skip authentication for paths matching a regular expression
    #[cfg(feature = "regex")]
    pub fn skip_regex(mut self, pattern: &str) -> Result<Self, regex::Error> {
        self.patterns.push(PathPattern::Regex(Regex::new(pattern)?));
        Ok(self)
    }

    /// Skip authentication for multiple exact paths
    pub fn skip_paths<P: Into<String>>(self, paths: impl IntoIterator<Item = P>) -> Self {
        paths.into_iter().fold(self, Self::skip_exact)
    }

    /// Skip authentication for multiple prefixes
    pub fn skip_prefixes<P: Into<String>>(self, prefixes: impl IntoIterator<Item = P>) -> Self {
        prefixes.into_iter().fold(self, Self::skip_prefix)
    }

    /// Skip authentication for multiple suffixes
    pub fn skip_suffixes<P: Into<String>>(self, suffixes: impl IntoIterator<Item = P>) -> Self {
        suffixes.into_iter().fold(self, Self::skip_suffix)
    }

    /// Whether `path` skips authentication
    pub fn should_skip(&self, path: &str) -> bool {
        !is_ambiguous(path)
            && self.patterns.iter().any(|pattern| match pattern {
                PathPattern::Exact(exact) => path == exact,
                PathPattern::Prefix(prefix) => path.starts_with(prefix.as_str()),
                PathPattern::Suffix(suffix) => path.ends_with(suffix.as_str()),
                #[cfg(feature = "regex")]
                PathPattern::Regex(regex) => regex.is_match(path),
            })
    }

    /// Number of patterns
    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// Whether the filter has no patterns
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

fn is_ambiguous(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    ["%2f", "%5c", "%25", "\\"].iter().any(|p| path.contains(p))
        || path.split('/').any(|seg| {
            let seg = seg.replace("%2e", ".");
            seg == "." || seg == ".."
        })
}

/// Filter for health probes and static asset directories: `/health`,
/// `/healthz`, `/healthcheck`, `/ping`, `/favicon.ico` and everything under
/// `/static/`, `/assets/`, `/public/` and `/.well-known/`.
///
/// Observability endpoints such as `/metrics` stay protected; add them
/// explicitly with [`PathFilter::skip_paths`] if they must be public.
pub fn common_skip_paths() -> PathFilter {
    PathFilter::new()
        .skip_paths([
            "/health",
            "/healthz",
            "/healthcheck",
            "/ping",
            "/favicon.ico",
        ])
        .skip_prefixes(["/static/", "/assets/", "/public/", "/.well-known/"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching() {
        let filter = PathFilter::new()
            .skip_exact("/health")
            .skip_prefix("/public/")
            .skip_suffix(".css")
            .skip_paths(["/api/status", "/metrics"]);

        assert!(filter.should_skip("/health"));
        assert!(filter.should_skip("/public/images/logo.png"));
        assert!(filter.should_skip("/assets/style.css"));
        assert!(filter.should_skip("/api/status"));
        assert!(!filter.should_skip("/api/users"));
        assert!(!filter.should_skip("/healthcheck"));
        assert_eq!(filter.len(), 5);
    }

    #[test]
    fn dot_segments_never_skip() {
        let filter = PathFilter::new().skip_prefix("/public/");
        assert!(!filter.should_skip("/public/../admin"));
        assert!(!filter.should_skip("/public/%2e%2e/admin"));
        assert!(!filter.should_skip("/public/.%2E/admin"));
        assert!(!filter.should_skip("/public/./x"));
        assert!(!filter.should_skip("/public/%2e%2e%2fadmin"));
        assert!(!filter.should_skip("/public/..%2Fadmin"));
        assert!(!filter.should_skip("/public/..%5cadmin"));
        assert!(!filter.should_skip("/public/..\\admin"));
        assert!(!filter.should_skip("/public/%252e%252e/admin"));
        assert!(filter.should_skip("/public/..hidden"));
        assert!(filter.should_skip("/public/a%20b.png"));
    }

    #[cfg(feature = "regex")]
    #[test]
    fn regex() {
        let filter = PathFilter::new().skip_regex(r"^/api/v\d+/public/").unwrap();
        assert!(filter.should_skip("/api/v1/public/data"));
        assert!(!filter.should_skip("/api/v1/private/data"));
        assert!(PathFilter::new().skip_regex("(").is_err());
    }

    #[test]
    fn common() {
        let filter = common_skip_paths();
        assert!(filter.should_skip("/health"));
        assert!(filter.should_skip("/static/css/main.css"));
        assert!(filter.should_skip("/.well-known/acme-challenge/x"));
        assert!(!filter.should_skip("/metrics"));
        assert!(!filter.should_skip("/api/users/x.js"));
        assert!(!filter.should_skip("/health/live"));
    }
}

//! End-to-end tests over a real socket, where requests carry a peer address.

use base64::{Engine, engine::general_purpose::STANDARD};
use ntex::http::StatusCode;
use ntex::web::{self, App, test};
use ntex_basicauth::{AuthenticatedUser, BasicAuth, IpNet};
use std::time::Duration;

async fn status(srv: &test::TestServer, creds: &str, forwarded: &str) -> StatusCode {
    srv.get("/")
        .header("authorization", format!("Basic {}", STANDARD.encode(creds)))
        .header("x-forwarded-for", forwarded)
        .send()
        .await
        .unwrap()
        .status()
}

async fn server(trusted: Option<IpNet>) -> test::TestServer {
    let auth = BasicAuth::builder()
        .user("admin", "secret")
        .max_failures_per_ip(1, Duration::from_secs(60))
        .trusted_proxies(trusted)
        .build()
        .unwrap();
    test::server(async move || {
        App::new().middleware(auth.clone()).route(
            "/",
            web::get().to(async |u: AuthenticatedUser| u.username().to_owned()),
        )
    })
    .await
}

#[ntex::test]
async fn untrusted_peer_ignores_forwarded_for() {
    let srv = server(None).await;
    assert_eq!(
        status(&srv, "admin:wrong", "1.1.1.1").await,
        StatusCode::UNAUTHORIZED
    );
    // A different forged header does not give the peer a fresh budget.
    assert_eq!(
        status(&srv, "admin:secret", "2.2.2.2").await,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[ntex::test]
async fn trusted_proxy_uses_rightmost_untrusted_hop() {
    let srv = server(Some("127.0.0.0/8".parse().unwrap())).await;
    assert_eq!(
        status(&srv, "admin:wrong", "6.6.6.6, 1.1.1.1").await,
        StatusCode::UNAUTHORIZED
    );
    // Rotating the client-controlled leftmost hop does not escape the limit.
    assert_eq!(
        status(&srv, "admin:secret", "7.7.7.7, 1.1.1.1").await,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Another client behind the same proxy has its own budget.
    assert_eq!(
        status(&srv, "admin:secret", "2.2.2.2").await,
        StatusCode::OK
    );
}

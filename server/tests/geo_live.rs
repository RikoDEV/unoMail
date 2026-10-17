//! Reverse DNS and country lookups against the real DNS. Ignored by default because it needs
//! Internet access; run with `cargo test --test geo_live -- --ignored`.

use mail_auth::MessageAuthenticator;
use unomail::{activity, app::App, config::Config};

#[tokio::test]
#[ignore = "needs Internet access"]
async fn public_addresses_are_described_from_dns() {
    let dir = tempfile::tempdir().unwrap();
    let resolver = MessageAuthenticator::new_cloudflare_tls().unwrap();
    let app = App::new(Config::for_tests(dir.path().to_path_buf()), Some(resolver)).await.unwrap();

    let cloudflare = activity::describe(&app, "1.1.1.1".parse().unwrap()).await;
    assert_eq!(cloudflare.rdns.as_deref(), Some("one.one.one.one"), "{cloudflare:?}");
    assert!(cloudflare.country.is_some(), "{cloudflare:?}");
    let google = activity::describe(&app, "2001:4860:4860::8888".parse().unwrap()).await;
    assert_eq!((google.rdns.as_deref(), google.country.as_deref()), (Some("dns.google"), Some("US")), "{google:?}");

    // Private addresses are never sent to anyone.
    assert_eq!(activity::describe(&app, "10.0.0.1".parse().unwrap()).await, activity::Described::default());
}

//! Browser login with `oidc.application-type=web-app`.
//!
//! Web-app mode uses the authorization-code flow and stores redirect and
//! authentication state in encrypted cookies. Build it through provider
//! discovery or explicit provider endpoints so the middleware knows the
//! authorization and token URLs.

use axum::{Extension, Router, routing::get};
use oidc_middleware::{ApplicationType, Oidc, OidcConfig, Principal};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _app = app().await?;
    Ok(())
}

async fn app() -> Result<Router, Box<dyn std::error::Error + Send + Sync>> {
    let oidc = Oidc::builder(OidcConfig {
        application_type: ApplicationType::WebApp,
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        client_id: Some("orders-web".to_owned()),
        ..OidcConfig::default()
    })
    .discover()
    .await?;

    let protected = Router::new()
        .route("/", get(home))
        .layer(oidc.clone().layer());

    Ok(Router::new()
        .route("/health", get(health))
        // OIDC-owned callback and logout routes must stay outside the OIDC
        // layer so they can complete login and logout flows directly.
        .merge(oidc.routes())
        .merge(protected))
}

async fn health() -> &'static str {
    "ok"
}

async fn home(Extension(principal): Extension<Principal>) -> String {
    format!("signed in as {}", principal.subject())
}

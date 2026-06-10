//! Provider discovery and JWKS-backed JWT validation.
//!
//! Use this when the application can reach the OIDC provider at startup. The
//! middleware fetches discovery metadata, loads JWKS keys, and validates bearer
//! JWTs locally.

use axum::{Extension, Router, routing::get};
use oidc_middleware::{Oidc, OidcConfig, Principal};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _app = app().await?;
    Ok(())
}

async fn app() -> Result<Router, Box<dyn std::error::Error + Send + Sync>> {
    let oidc = Oidc::builder(OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        client_id: Some("orders-api".to_owned()),
        ..OidcConfig::default()
    })
    .discover()
    .await?;

    Ok(Router::new().route("/me", get(me)).layer(oidc.layer()))
}

async fn me(Extension(principal): Extension<Principal>) -> String {
    format!("subject={}", principal.subject())
}

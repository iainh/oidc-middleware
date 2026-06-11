//! Browser login with `oidc.application-type=web-app`.
//!
//! Web-app mode uses the authorization-code flow, stores authentication state
//! in an encrypted cookie, and keeps redirect state in `tower-sessions`. Build
//! it through provider discovery or explicit provider endpoints so the
//! middleware knows the authorization and token URLs.

use axum::{Extension, Router, routing::get};
use oidc_middleware::{ApplicationType, Oidc, OidcConfig, Principal};
use tower_sessions::{MemoryStore, SessionManagerLayer};

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
        // The OIDC layer intercepts the configured callback path before this
        // handler runs. Keeping a route here makes Axum routing explicit.
        .route("/q/oidc/callback", get(callback_placeholder))
        .layer(oidc.layer());

    Ok(Router::new()
        .route("/health", get(health))
        .merge(protected)
        .layer(SessionManagerLayer::new(MemoryStore::default())))
}

async fn health() -> &'static str {
    "ok"
}

async fn home(Extension(principal): Extension<Principal>) -> String {
    format!("signed in as {}", principal.subject())
}

async fn callback_placeholder() -> &'static str {
    "callback handled by OIDC middleware"
}

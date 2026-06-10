//! Bearer-service authentication for an Axum API.
//!
//! This is the smallest useful server-side shape: public routes stay outside
//! the OIDC layer, protected routes are wrapped by `Oidc::layer`, and handlers
//! read the authenticated identity from Axum extensions.

use axum::{Extension, Router, routing::get};
use oidc_middleware::{Oidc, OidcConfig, Principal, StaticTokenValidator};

fn main() {
    let _app = app();
}

fn app() -> Router {
    let oidc = Oidc::builder(OidcConfig::default())
        // Use `JwtValidator`, provider discovery, introspection, or UserInfo in
        // production. `StaticTokenValidator` keeps this example self-contained.
        .validator(StaticTokenValidator::bearer("dev-token", "alice"))
        .build();

    let api = Router::new()
        .route("/me", get(me))
        .route("/orders", get(list_orders))
        .layer(oidc.layer());

    Router::new().route("/health", get(health)).merge(api)
}

async fn health() -> &'static str {
    "ok"
}

async fn me(Extension(principal): Extension<Principal>) -> String {
    format!("subject={}", principal.subject())
}

async fn list_orders(Extension(principal): Extension<Principal>) -> String {
    format!("orders visible to {}", principal.subject())
}

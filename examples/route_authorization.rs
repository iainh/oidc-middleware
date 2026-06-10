//! Route-local authorization with Axum/Tower layers.
//!
//! Keep OIDC provider configuration centralized, then express authorization at
//! the route that needs it. This is the recommended replacement for path-policy
//! configuration because it follows normal Axum composition.

use axum::{Extension, Router, routing::get};
use oidc_middleware::{
    Oidc, OidcConfig, Principal, RequireAuthenticatedLayer, RequireRolesLayer, StaticTokenValidator,
};

fn main() {
    let _app = app();
}

fn app() -> Router {
    let oidc = Oidc::builder(OidcConfig::default())
        .validator(StaticTokenValidator::principal(
            "dev-token",
            Principal::with_groups("alice", ["orders-user", "orders-admin"]),
        ))
        .build();

    let protected = Router::new()
        .route(
            "/account",
            get(account).route_layer(RequireAuthenticatedLayer::new()),
        )
        .route(
            "/orders",
            get(orders).route_layer(RequireRolesLayer::any(["orders-user", "orders-admin"])),
        )
        .route(
            "/admin/reindex",
            get(reindex).route_layer(RequireRolesLayer::all(["orders-admin", "operator"])),
        )
        .layer(oidc.layer());

    Router::new().route("/health", get(health)).merge(protected)
}

async fn health() -> &'static str {
    "ok"
}

async fn account(Extension(principal): Extension<Principal>) -> String {
    format!("account for {}", principal.subject())
}

async fn orders() -> &'static str {
    "orders"
}

async fn reindex() -> &'static str {
    "reindex scheduled"
}

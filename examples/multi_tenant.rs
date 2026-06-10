//! Multi-tenant OIDC routing.
//!
//! Tenants can be selected by path, header, or token issuer. This example uses
//! path selection and keeps each tenant's validator separate.

use axum::{Extension, Router, routing::get};
use oidc_middleware::{Oidc, OidcConfig, Principal, StaticTokenValidator, Tenants};

fn main() {
    let _app = app();
}

fn app() -> Router {
    let orders = Oidc::builder(OidcConfig {
        tenant_paths: Some("/orders/*".to_owned()),
        tenant_id: Some("orders".to_owned()),
        ..OidcConfig::default()
    })
    .validator(StaticTokenValidator::bearer("orders-token", "alice"))
    .build();

    let billing = Oidc::builder(OidcConfig {
        tenant_paths: Some("/billing/*".to_owned()),
        tenant_id: Some("billing".to_owned()),
        ..OidcConfig::default()
    })
    .validator(StaticTokenValidator::bearer("billing-token", "bob"))
    .build();

    let tenants = Tenants::builder()
        .tenant("orders", orders)
        .tenant("billing", billing)
        .build();

    Router::new()
        .route("/orders/me", get(whoami))
        .route("/billing/me", get(whoami))
        .layer(tenants.layer())
}

async fn whoami(Extension(principal): Extension<Principal>) -> String {
    format!("subject={}", principal.subject())
}

//! Loading `oidc.*` settings from MicroProfile-style configuration.
//!
//! This mirrors Quarkus' configuration ergonomics while keeping runtime wiring
//! explicit. Authorization remains route-local; `Oidc::from_config` only loads
//! OIDC authentication/provider settings.

use axum::{Extension, Router, routing::get};
use mp_config::{Config, MapSource};
use oidc_middleware::{Oidc, Principal, RequireRolesLayer, StaticTokenValidator};

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _app = app()?;
    Ok(())
}

fn app() -> Result<Router, Box<dyn std::error::Error + Send + Sync>> {
    let config = Config::builder()
        .add_source(
            MapSource::new("example", 100)
                .with("oidc.auth-server-url", "https://issuer.example/realms/app")
                .with("oidc.client-id", "orders-api")
                .with("oidc.token.audience", "orders-api")
                .with("oidc.roles.role-claim-path", "groups,realm_access.roles"),
        )
        .build();

    let oidc = Oidc::from_config(&config)?
        // Keep the example runnable without a provider. Replace this with
        // `.discover().await?`, `.public_key(...)`, or introspection in real apps.
        .validator(StaticTokenValidator::principal(
            "dev-token",
            Principal::with_groups("alice", ["orders-reader"]),
        ))
        .build();

    let protected = Router::new()
        .route(
            "/orders",
            get(orders).route_layer(RequireRolesLayer::any(["orders-reader"])),
        )
        .layer(oidc.layer());

    Ok(Router::new().route("/health", get(health)).merge(protected))
}

async fn health() -> &'static str {
    "ok"
}

async fn orders(Extension(principal): Extension<Principal>) -> String {
    format!("orders for {}", principal.subject())
}

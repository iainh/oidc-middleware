//! Opaque-token validation with OAuth2 token introspection.
//!
//! The example uses an in-process introspector so the file is self-contained.
//! In production, use `introspection_endpoint(...)` or call your own provider
//! from the `TokenIntrospector` implementation.

use axum::{Extension, Router, routing::get};
use oidc_middleware::{IntrospectionResponse, Oidc, OidcConfig, Principal};
use std::sync::Arc;

fn main() {
    let _app = app();
}

fn app() -> Router {
    let introspector = |token: Arc<str>| async move {
        if token.as_ref() == "opaque-token" {
            return IntrospectionResponse::from_json(
                r#"{
                    "active": true,
                    "sub": "alice",
                    "groups": ["orders-reader"]
                }"#,
            )
            .map_err(Into::into);
        }

        Ok(IntrospectionResponse {
            active: false,
            ..IntrospectionResponse::default()
        })
    };

    let oidc = Oidc::builder(OidcConfig::default())
        .token_introspector(introspector)
        .build();

    Router::new()
        .route("/me", get(me))
        .route("/orders", get(orders))
        .layer(oidc.layer())
}

async fn me(Extension(principal): Extension<Principal>) -> String {
    format!("subject={}", principal.subject())
}

async fn orders(Extension(principal): Extension<Principal>) -> String {
    let groups = principal.groups().collect::<Vec<_>>().join(",");
    format!("groups={groups}")
}

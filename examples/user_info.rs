//! UserInfo-backed bearer-token validation.
//!
//! Use this shape when access tokens are opaque to the application and the
//! provider's UserInfo endpoint is the source of identity and roles.

use axum::{Extension, Router, routing::get};
use oidc_middleware::{Oidc, OidcConfig, Principal, UserInfoResponse};
use std::sync::Arc;

fn main() {
    let _app = app();
}

fn app() -> Router {
    let provider = |token: Arc<str>| async move {
        if token.as_ref() != "userinfo-token" {
            return Err("token was not accepted by UserInfo".into());
        }

        UserInfoResponse::from_json(
            r#"{
                "sub": "alice",
                "groups": ["profile-reader", "orders-reader"]
            }"#,
        )
        .map_err(Into::into)
    };

    let oidc = Oidc::builder(OidcConfig::default())
        .user_info_provider(provider)
        .build();

    Router::new()
        .route("/profile", get(profile))
        .layer(oidc.layer())
}

async fn profile(Extension(principal): Extension<Principal>) -> String {
    let groups = principal.groups().collect::<Vec<_>>().join(",");
    format!("subject={}, groups={groups}", principal.subject())
}

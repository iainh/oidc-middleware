//! Handler-level authorization with macros.
//!
//! Route layers are usually the best fit for Axum apps. The macros are useful
//! when a permission belongs directly to a handler and you want Quarkus-style
//! annotations near the function body.

use axum::{Router, routing::get};
use oidc_middleware::{
    Error, FromOidcPrincipal, Oidc, OidcAuthorize, OidcConfig, OidcPrincipal, Principal,
    StaticTokenValidator, authenticated, roles_allowed,
};

fn main() {
    let _app = app();
}

fn app() -> Router {
    let oidc = Oidc::builder(OidcConfig::default())
        .validator(StaticTokenValidator::principal(
            "dev-token",
            Principal::with_groups("alice", ["admin"]),
        ))
        .build();

    Router::new()
        .route("/profile", get(profile))
        .route("/admin", get(admin))
        .route("/account", get(account))
        .layer(oidc.layer())
}

#[authenticated]
async fn profile(principal: OidcPrincipal) -> Result<String, Error> {
    Ok(format!("profile for {}", principal.subject()))
}

#[roles_allowed("admin")]
async fn admin(principal: OidcPrincipal) -> Result<String, Error> {
    Ok(format!("admin view for {}", principal.subject()))
}

#[derive(Clone, OidcAuthorize, FromOidcPrincipal)]
struct User {
    #[oidc(principal)]
    principal: Principal,
    #[oidc(subject)]
    account_id: String,
}

#[roles_allowed("admin", principal = user)]
async fn account(user: User) -> Result<String, Error> {
    Ok(format!("account {}", user.account_id))
}

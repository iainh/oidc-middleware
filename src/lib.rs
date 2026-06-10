//! Quarkus-inspired OIDC middleware for [`axum`].
//!
//! `oidc-middleware` keeps the part of Quarkus OIDC that works well for teams:
//! provider configuration is declarative and predictable. It changes the part
//! that does not map cleanly to Rust: authorization is expressed through normal
//! Axum and Tower composition instead of global path-policy strings.
//!
//! # Choosing the right integration
//!
//! - Use [`Oidc::builder`] when application code owns provider configuration.
//! - Use [`Oidc::from_config`] or [`Oidc::discover_from_config`] when you want
//!   Quarkus-style `oidc.*` properties from [`mp_config`].
//! - Use [`RequireRolesLayer`] or [`RequireAuthenticatedLayer`] on routes when
//!   authorization is structural and should be visible in the router.
//! - Use `roles_allowed` or `authenticated` when the authorization decision
//!   belongs directly to a handler.
//! - Use [`Tenants`] when a single Axum app must validate tokens for multiple
//!   issuers, realms, or client populations.
//!
//! # Bearer-service example
//!
//! ```
//! use axum::{Router, routing::get};
//! use oidc_middleware::{Oidc, OidcConfig, RequireRolesLayer, StaticTokenValidator};
//!
//! # fn app() -> Router {
//! let oidc = Oidc::builder(OidcConfig {
//!     auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
//!     client_id: Some("orders-service".to_owned()),
//!     ..OidcConfig::default()
//! })
//! .validator(StaticTokenValidator::bearer("dev-token", "alice"))
//! .build();
//!
//! let protected = Router::new()
//!     .route(
//!         "/orders",
//!         get(|| async { "ok" })
//!             .route_layer(RequireRolesLayer::any(["orders-reader", "orders-admin"])),
//!     )
//!     .layer(oidc.layer());
//!
//! Router::new()
//!     .route("/health", get(|| async { "ok" }))
//!     .merge(protected)
//! # }
//! ```
//!
//! Public routes should usually stay outside [`Oidc::layer`]. The OIDC layer is
//! intentionally closed by default: once it wraps a route, missing or rejected
//! bearer tokens become `401 Unauthorized` responses.
//!
//! # MicroProfile and Quarkus mapping
//!
//! Quarkus OIDC is configured under `oidc.*`. This crate follows that naming
//! model through [`OidcConfig::from_config`], while keeping runtime behaviour
//! explicit and testable:
//!
//! - `oidc.auth-server-url` maps to [`OidcConfig::auth_server_url`].
//! - `oidc.provider` maps to [`OidcConfig::provider`]. Built-in providers are
//!   convenience defaults, not a substitute for issuer validation.
//! - `oidc.client-id` maps to [`OidcConfig::client_id`]. It is used for
//!   provider calls and default Keycloak resource-role extraction.
//! - `oidc.application-type` maps to [`OidcConfig::application_type`]. Use
//!   `service` for APIs and `web-app` for browser login.
//! - `oidc.authentication.*` configures browser redirects for `web-app`
//!   applications. Web-app middleware expects a `tower_sessions::Session`
//!   extension supplied by `tower-sessions`.
//! - `oidc.enabled=false` disables authentication for the layer. This is useful
//!   for local profiles, but it also means protected handlers must not assume a
//!   [`Principal`] extension exists.
//! - `oidc.tenant-enabled=false` returns `404 Not Found` for the selected
//!   tenant so disabled tenants do not advertise protected resources.
//! - `oidc.token.audience=any` and `oidc.token.issuer=any` bypass the
//!   corresponding validation and should be reserved for providers that cannot
//!   emit stable claims.
//!
//! More complete runnable patterns live in the `examples/` directory.

#[cfg(feature = "macros")]
pub use oidc_middleware_macros::{authenticated, roles_allowed};

mod authorization;
mod claims;
mod config;
mod config_helpers;
mod error;
mod introspection;
#[cfg(feature = "jwt")]
mod jwks;
#[cfg(feature = "jwt")]
mod jwt;
mod oidc;
mod path;
mod principal;
mod provider;
mod tenants;
mod token;
mod user_info;
mod validation_claims;
mod validator;
#[cfg(feature = "web-app")]
mod web_app;

pub use authorization::{
    RequireAuthenticatedLayer, RequireAuthenticatedService, RequireRolesLayer, RequireRolesService,
};
pub use config::{
    ApplicationType, ClientSecretMethod, OidcAuthenticationConfig, OidcClientSecretConfig,
    OidcConfig, OidcCredentialsConfig, OidcIntrospectionCredentialsConfig, OidcRolesConfig,
    OidcTokenBindingConfig, OidcTokenConfig, RolesSource, TokenSignatureAlgorithm,
    WellKnownProvider,
};
pub use error::{BuildError, Error};
pub use introspection::{
    IntrospectionFallbackValidator, IntrospectionResponse, IntrospectionValidator,
    TokenIntrospector,
};
#[cfg(feature = "jwt")]
pub use jwks::{JwksProvider, JwksRefreshFuture};
#[cfg(feature = "jwt")]
pub use jwt::JwtValidator;
pub use oidc::{Oidc, OidcBuilder, OidcLayer, OidcService};
pub use principal::{OidcPrincipal, Principal};
pub use provider::ProviderMetadata;
pub use tenants::{Tenants, TenantsBuilder, TenantsLayer, TenantsService};
pub use user_info::{
    UserInfoProvider, UserInfoResponse, UserInfoRolesValidator, UserInfoValidator,
};
pub use validator::{StaticTokenValidator, TokenValidator};

pub(crate) use config::role_claim_paths_for_source;
pub(crate) use oidc::oidc_builder_from_config;
use std::error::Error as StdError;
use std::future::Future;
use std::pin::Pin;
pub(crate) use validator::ValidationFuture;

/// Result type returned by token validators.
pub type Result<T> = std::result::Result<T, Error>;

/// Boxed error type used by extension points.
pub type BoxError = Box<dyn StdError + Send + Sync>;
/// Future returned by [`TokenIntrospector`].
pub type IntrospectionFuture =
    Pin<Box<dyn Future<Output = std::result::Result<IntrospectionResponse, BoxError>> + Send>>;
/// Future returned by [`UserInfoProvider`].
pub type UserInfoFuture =
    Pin<Box<dyn Future<Output = std::result::Result<UserInfoResponse, BoxError>> + Send>>;
/// Result type returned while building OIDC middleware.
pub type BuildResult<T> = std::result::Result<T, BuildError>;

#[cfg(test)]
mod tests;

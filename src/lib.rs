//! Quarkus-inspired OIDC middleware for [`axum`].
//!
//! `oidc-middleware` maps the pieces that make Quarkus OIDC productive onto
//! explicit Rust types: MicroProfile-style configuration via [`mp-config`], a
//! cloneable axum layer, bearer-token challenge responses, and request
//! extensions for the authenticated identity.
//!
//! ## Example
//!
//! ```
//! use axum::{Router, routing::get};
//! use oidc_middleware::{Oidc, OidcConfig, StaticTokenValidator};
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
//! Router::new()
//!     .route("/orders", get(|| async { "ok" }))
//!     .layer(oidc.layer())
//! # }
//! ```
//!
//! ## MicroProfile and Quarkus mapping
//!
//! Quarkus OIDC is configured under `oidc.*`. This crate follows that
//! naming model through [`OidcConfig::from_config`], while keeping runtime
//! behaviour explicit and testable:
//!
//! - `oidc.auth-server-url` maps to [`OidcConfig::auth_server_url`].
//! - `oidc.provider` maps to [`OidcConfig::provider`].
//! - `oidc.client-id` maps to [`OidcConfig::client_id`].
//! - `oidc.application-type` maps to [`OidcConfig::application_type`].
//! - `oidc.authentication.*` configures browser redirects for
//!   `web-app` applications. `web-app` middleware expects a
//!   [`tower_sessions::Session`] extension supplied by `tower-sessions`.
//! - `oidc.enabled=false` disables authentication for the layer.
//! - `oidc.tenant-enabled=false` rejects requests as tenant-disabled.

pub use oidc_middleware_macros::{authenticated, roles_allowed};

mod authorization;
mod claims;
mod config;
mod config_helpers;
mod error;
mod introspection;
mod jwks;
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
mod web_app;

pub use authorization::Authorization;
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
pub use jwks::{JwksProvider, JwksRefreshFuture};
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

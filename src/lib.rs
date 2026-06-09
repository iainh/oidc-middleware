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
//! Quarkus OIDC is configured under `quarkus.oidc.*`. This crate follows that
//! naming model through [`OidcConfig::from_config`], while keeping runtime
//! behaviour explicit and testable:
//!
//! - `quarkus.oidc.auth-server-url` maps to [`OidcConfig::auth_server_url`].
//! - `quarkus.oidc.client-id` maps to [`OidcConfig::client_id`].
//! - `quarkus.oidc.application-type` maps to [`OidcConfig::application_type`].
//! - `quarkus.oidc.enabled=false` disables authentication for the layer.
//! - `quarkus.oidc.tenant-enabled=false` rejects requests as tenant-disabled.

use axum::body::Body;
use axum::response::{IntoResponse, Response};
use http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use http::{HeaderValue, Request, StatusCode};
use mp_config::{Config, ConfigProperties};
use std::convert::Infallible;
use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower_layer::Layer;
use tower_service::Service;

/// Result type returned by token validators.
pub type Result<T> = std::result::Result<T, Error>;

type BoxError = Box<dyn StdError + Send + Sync>;
type ValidationFuture = Pin<Box<dyn Future<Output = Result<Principal>> + Send>>;

/// OIDC configuration loaded from the MicroProfile-style config model.
#[derive(Clone, Debug, ConfigProperties, Eq, PartialEq)]
#[config(prefix = "quarkus.oidc", rename_all = "kebab-case")]
pub struct OidcConfig {
    /// Enables or disables the OIDC middleware.
    #[config(default = "true")]
    pub enabled: bool,
    /// Enables or disables the selected tenant.
    #[config(default = "true")]
    pub tenant_enabled: bool,
    /// Base URL of the OpenID Connect provider or realm.
    pub auth_server_url: Option<String>,
    /// Client identifier expected by the provider.
    pub client_id: Option<String>,
    /// Quarkus-style application type.
    #[config(default)]
    pub application_type: ApplicationType,
}

impl OidcConfig {
    /// Loads `quarkus.oidc.*` properties from an [`mp_config::Config`].
    pub fn from_config(config: &Config) -> mp_config::Result<Self> {
        <Self as ConfigProperties>::from_config(config)
    }
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            tenant_enabled: true,
            auth_server_url: None,
            client_id: None,
            application_type: ApplicationType::Service,
        }
    }
}

/// Quarkus-compatible OIDC application type.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ApplicationType {
    /// Service applications authenticate bearer tokens.
    #[default]
    Service,
    /// Web applications authenticate users through authorization-code flow.
    WebApp,
    /// Hybrid applications support service and web-app behaviour.
    Hybrid,
}

impl mp_config::FromConfigValue for ApplicationType {
    fn from_config_value(value: &str) -> std::result::Result<Self, String> {
        match value {
            "service" => Ok(Self::Service),
            "web-app" => Ok(Self::WebApp),
            "hybrid" => Ok(Self::Hybrid),
            other => Err(format!(
                "expected one of `service`, `web-app`, or `hybrid`, got `{other}`"
            )),
        }
    }
}

/// Authenticated identity stored in request extensions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Principal {
    subject: Arc<str>,
}

impl Principal {
    /// Creates a principal with the supplied subject.
    pub fn new(subject: impl Into<String>) -> Self {
        Self {
            subject: Arc::from(subject.into()),
        }
    }

    /// Returns the token subject.
    pub fn subject(&self) -> &str {
        &self.subject
    }
}

/// Error type returned while authenticating a request.
#[derive(Debug)]
pub enum Error {
    /// The request did not include an `Authorization: Bearer` token.
    MissingBearerToken,
    /// The `Authorization` header was not valid UTF-8 or not in bearer format.
    InvalidAuthorizationHeader,
    /// The selected tenant is disabled.
    TenantDisabled,
    /// The validator rejected the token.
    TokenRejected(BoxError),
}

impl Error {
    fn status(&self) -> StatusCode {
        match self {
            Self::TenantDisabled => StatusCode::NOT_FOUND,
            Self::MissingBearerToken
            | Self::InvalidAuthorizationHeader
            | Self::TokenRejected(_) => StatusCode::UNAUTHORIZED,
        }
    }

    fn challenge(&self) -> HeaderValue {
        match self {
            Self::MissingBearerToken => HeaderValue::from_static("Bearer"),
            Self::InvalidAuthorizationHeader => {
                HeaderValue::from_static(r#"Bearer error="invalid_request""#)
            }
            Self::TokenRejected(_) => HeaderValue::from_static(r#"Bearer error="invalid_token""#),
            Self::TenantDisabled => HeaderValue::from_static("Bearer"),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingBearerToken => write!(f, "missing bearer token"),
            Self::InvalidAuthorizationHeader => write!(f, "invalid authorization header"),
            Self::TenantDisabled => write!(f, "OIDC tenant is disabled"),
            Self::TokenRejected(source) => write!(f, "token rejected: {source}"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::TokenRejected(source) => Some(source.as_ref()),
            _ => None,
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = self.status();
        let challenge = self.challenge();
        let mut response = status.into_response();
        response.headers_mut().insert(WWW_AUTHENTICATE, challenge);
        response
    }
}

/// Validates a bearer token and returns the authenticated principal.
pub trait TokenValidator: Send + Sync + 'static {
    /// Validates a raw bearer token.
    fn validate(&self, token: Arc<str>) -> ValidationFuture;
}

impl<F, Fut> TokenValidator for F
where
    F: Fn(Arc<str>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Principal>> + Send + 'static,
{
    fn validate(&self, token: Arc<str>) -> ValidationFuture {
        Box::pin(self(token))
    }
}

/// Development/test token validator that accepts exactly one bearer token.
#[derive(Clone, Debug)]
pub struct StaticTokenValidator {
    token: Arc<str>,
    principal: Principal,
}

impl StaticTokenValidator {
    /// Creates a validator that accepts `token` and maps it to `subject`.
    pub fn bearer(token: impl Into<String>, subject: impl Into<String>) -> Self {
        Self {
            token: Arc::from(token.into()),
            principal: Principal::new(subject),
        }
    }
}

impl TokenValidator for StaticTokenValidator {
    fn validate(&self, token: Arc<str>) -> ValidationFuture {
        let principal = self.principal.clone();
        let expected = self.token.clone();
        Box::pin(async move {
            if token == expected {
                Ok(principal)
            } else {
                Err(Error::TokenRejected("bearer token did not match".into()))
            }
        })
    }
}

/// OIDC middleware entry point.
#[derive(Clone)]
pub struct Oidc {
    config: OidcConfig,
    validator: Arc<dyn TokenValidator>,
}

impl Oidc {
    /// Starts building OIDC middleware from configuration.
    pub fn builder(config: OidcConfig) -> OidcBuilder {
        OidcBuilder {
            config,
            validator: None,
        }
    }

    /// Loads configuration from `quarkus.oidc.*` and starts building.
    pub fn from_config(config: &Config) -> mp_config::Result<OidcBuilder> {
        Ok(Self::builder(OidcConfig::from_config(config)?))
    }

    /// Returns a tower layer suitable for `Router::layer`.
    pub fn layer(self) -> OidcLayer {
        OidcLayer { oidc: self }
    }

    async fn authenticate(&self, request: &mut Request<Body>) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        if !self.config.tenant_enabled {
            return Err(Error::TenantDisabled);
        }

        let token = bearer_token(request)?;
        let principal = self.validator.validate(token).await?;
        request.extensions_mut().insert(principal);
        Ok(())
    }
}

/// Builder for [`Oidc`].
pub struct OidcBuilder {
    config: OidcConfig,
    validator: Option<Arc<dyn TokenValidator>>,
}

impl OidcBuilder {
    /// Sets the bearer token validator.
    pub fn validator<V>(mut self, validator: V) -> Self
    where
        V: TokenValidator,
    {
        self.validator = Some(Arc::new(validator));
        self
    }

    /// Finishes the OIDC middleware.
    ///
    /// If no validator is supplied, all bearer tokens are rejected. This keeps
    /// protected routes closed while allowing configuration and routing to be
    /// wired before a JWT/JWKS backend is added.
    pub fn build(self) -> Oidc {
        Oidc {
            config: self.config,
            validator: self.validator.unwrap_or_else(|| Arc::new(RejectAllTokens)),
        }
    }
}

#[derive(Clone)]
struct RejectAllTokens;

impl TokenValidator for RejectAllTokens {
    fn validate(&self, _token: Arc<str>) -> ValidationFuture {
        Box::pin(async { Err(Error::TokenRejected("no token validator configured".into())) })
    }
}

/// Tower layer produced by [`Oidc::layer`].
#[derive(Clone)]
pub struct OidcLayer {
    oidc: Oidc,
}

impl<S> Layer<S> for OidcLayer {
    type Service = OidcService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        OidcService {
            inner,
            oidc: self.oidc.clone(),
        }
    }
}

/// Tower service that authenticates requests before passing them to the inner service.
#[derive(Clone)]
pub struct OidcService<S> {
    inner: S,
    oidc: Oidc,
}

impl<S> Service<Request<Body>> for OidcService<S>
where
    S: Service<Request<Body>, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = std::result::Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let oidc = self.oidc.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            match oidc.authenticate(&mut request).await {
                Ok(()) => inner.call(request).await,
                Err(error) => Ok(error.into_response()),
            }
        })
    }
}

fn bearer_token(request: &Request<Body>) -> Result<Arc<str>> {
    let Some(header) = request.headers().get(AUTHORIZATION) else {
        return Err(Error::MissingBearerToken);
    };

    let value = header
        .to_str()
        .map_err(|_| Error::InvalidAuthorizationHeader)?;
    let token = value
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
        .ok_or(Error::InvalidAuthorizationHeader)?;

    Ok(Arc::from(token))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::extract::Extension;
    use axum::routing::get;
    use mp_config::MapSource;
    use tower::ServiceExt;

    #[test]
    fn config_loads_quarkus_oidc_properties() {
        let config = Config::builder()
            .add_source(
                MapSource::new("test", 100)
                    .with(
                        "quarkus.oidc.auth-server-url",
                        "https://issuer.example/realms/app",
                    )
                    .with("quarkus.oidc.client-id", "orders-service")
                    .with("quarkus.oidc.application-type", "hybrid"),
            )
            .build();

        let oidc = OidcConfig::from_config(&config).expect("config should load");

        assert_eq!(
            oidc,
            OidcConfig {
                enabled: true,
                tenant_enabled: true,
                auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
                client_id: Some("orders-service".to_owned()),
                application_type: ApplicationType::Hybrid,
            }
        );
    }

    #[tokio::test]
    async fn disabled_oidc_allows_request_without_bearer_token() {
        let response = public_app(
            Oidc::builder(OidcConfig {
                enabled: false,
                ..OidcConfig::default()
            })
            .build(),
        )
        .oneshot(request("/protected", None))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_bearer_token_is_challenged() {
        let response = app(oidc())
            .oneshot(request("/protected", None))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(WWW_AUTHENTICATE).unwrap(),
            HeaderValue::from_static("Bearer")
        );
    }

    #[tokio::test]
    async fn invalid_bearer_token_is_challenged() {
        let response = app(oidc())
            .oneshot(request("/protected", Some("Bearer wrong-token")))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(WWW_AUTHENTICATE).unwrap(),
            HeaderValue::from_static(r#"Bearer error="invalid_token""#)
        );
    }

    #[tokio::test]
    async fn valid_bearer_token_adds_principal_extension() {
        let response = app(oidc())
            .oneshot(request("/protected", Some("Bearer test-token")))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn tenant_disabled_returns_not_found() {
        let response = app(Oidc::builder(OidcConfig {
            tenant_enabled: false,
            ..OidcConfig::default()
        })
        .validator(StaticTokenValidator::bearer("test-token", "alice"))
        .build())
        .oneshot(request("/protected", Some("Bearer test-token")))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    fn oidc() -> Oidc {
        Oidc::builder(OidcConfig::default())
            .validator(StaticTokenValidator::bearer("test-token", "alice"))
            .build()
    }

    fn app(oidc: Oidc) -> Router {
        Router::new()
            .route(
                "/protected",
                get(|Extension(principal): Extension<Principal>| async move {
                    principal.subject().to_owned()
                }),
            )
            .layer(oidc.layer())
    }

    fn public_app(oidc: Oidc) -> Router {
        Router::new()
            .route("/protected", get(|| async { "ok" }))
            .layer(oidc.layer())
    }

    fn request(uri: &str, authorization: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().uri(uri);
        if let Some(authorization) = authorization {
            builder = builder.header(AUTHORIZATION, authorization);
        }
        builder
            .body(Body::empty())
            .expect("request should be valid")
    }
}

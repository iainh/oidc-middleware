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
use jsonwebtoken::jwk::{JwkSet, KeyAlgorithm};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use mp_config::{Config, ConfigProperties};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashSet;
use std::convert::Infallible;
use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower_layer::Layer;
use tower_service::Service;

/// Result type returned by token validators.
pub type Result<T> = std::result::Result<T, Error>;

type BoxError = Box<dyn StdError + Send + Sync>;
type ValidationFuture = Pin<Box<dyn Future<Output = Result<Principal>> + Send>>;

/// Result type returned while building OIDC middleware.
pub type BuildResult<T> = std::result::Result<T, BuildError>;

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
    /// Token validation settings.
    #[config(nested)]
    pub token: OidcTokenConfig,
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
            token: OidcTokenConfig::default(),
        }
    }
}

/// Token validation configuration loaded from `quarkus.oidc.token.*`.
#[derive(Clone, Debug, ConfigProperties, Default, Eq, PartialEq)]
#[config(rename_all = "kebab-case")]
pub struct OidcTokenConfig {
    /// Expected token issuer. Defaults to `auth-server-url` when unset.
    pub issuer: Option<String>,
    /// Expected token audience.
    pub audience: Option<String>,
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
    issuer: Option<Arc<str>>,
    audience: Vec<Arc<str>>,
    groups: Vec<Arc<str>>,
}

impl Principal {
    /// Creates a principal with the supplied subject.
    pub fn new(subject: impl Into<String>) -> Self {
        Self {
            subject: Arc::from(subject.into()),
            issuer: None,
            audience: Vec::new(),
            groups: Vec::new(),
        }
    }

    /// Returns the token subject.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the token issuer when present.
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// Returns token audiences.
    pub fn audience(&self) -> impl Iterator<Item = &str> {
        self.audience.iter().map(AsRef::as_ref)
    }

    /// Returns group or role names carried by the token.
    pub fn groups(&self) -> impl Iterator<Item = &str> {
        self.groups.iter().map(AsRef::as_ref)
    }

    fn from_claims(claims: TokenClaims) -> Self {
        Self {
            subject: Arc::from(claims.sub),
            issuer: claims.iss.map(Arc::from),
            audience: claims.aud.into_iter().map(Arc::from).collect(),
            groups: claims.groups.into_iter().map(Arc::from).collect(),
        }
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

/// Error type returned while building provider-backed middleware.
#[derive(Debug)]
pub enum BuildError {
    /// Provider discovery requires `quarkus.oidc.auth-server-url`.
    MissingAuthServerUrl,
    /// A configured provider or metadata URL could not be parsed.
    InvalidUrl { url: String, message: String },
    /// Fetching provider metadata or keys failed.
    Http(reqwest::Error),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingAuthServerUrl => write!(
                f,
                "OIDC provider discovery requires `quarkus.oidc.auth-server-url`"
            ),
            Self::InvalidUrl { url, message } => write!(f, "invalid URL `{url}`: {message}"),
            Self::Http(source) => write!(f, "OIDC provider request failed: {source}"),
        }
    }
}

impl StdError for BuildError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Http(source) => Some(source),
            _ => None,
        }
    }
}

impl From<reqwest::Error> for BuildError {
    fn from(source: reqwest::Error) -> Self {
        Self::Http(source)
    }
}

/// OpenID Provider metadata used by discovery.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ProviderMetadata {
    /// Canonical issuer returned by the provider.
    pub issuer: Option<String>,
    /// JSON Web Key Set URL returned by the provider.
    pub jwks_uri: String,
}

impl ProviderMetadata {
    /// Parses provider metadata from JSON.
    pub fn from_json(json: &str) -> std::result::Result<Self, serde_json::Error> {
        serde_json::from_str(json)
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

/// JWT bearer token validator.
#[derive(Clone)]
pub struct JwtValidator {
    keys: JwtKeys,
    validation: Validation,
}

impl JwtValidator {
    /// Builds an HS256 JWT validator.
    ///
    /// This is useful for tests and development providers. Production OIDC
    /// deployments should normally use asymmetric keys from provider metadata,
    /// which will be added as the discovery/JWKS support grows.
    pub fn hs256(secret: impl AsRef<[u8]>, config: &OidcConfig) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        apply_validation_config(&mut validation, config);

        Self {
            keys: JwtKeys::Single(Arc::new(DecodingKey::from_secret(secret.as_ref()))),
            validation,
        }
    }

    /// Builds a JWT validator backed by a JSON Web Key Set.
    ///
    /// The token header `kid` is matched against the supplied key set. If the
    /// header has no `kid` and the set contains exactly one key, that key is
    /// used. Supported key algorithms are inferred from JWK `alg` fields when
    /// present.
    pub fn jwks(jwks: JwkSet, config: &OidcConfig) -> Self {
        let mut validation = Validation::new(Algorithm::RS256);
        apply_validation_config(&mut validation, config);

        let algorithms = supported_algorithms(&jwks);
        if !algorithms.is_empty() {
            validation.algorithms = algorithms;
        }

        Self {
            keys: JwtKeys::Set(Arc::new(jwks)),
            validation,
        }
    }
}

impl TokenValidator for JwtValidator {
    fn validate(&self, token: Arc<str>) -> ValidationFuture {
        let keys = self.keys.clone();
        let validation = self.validation.clone();

        Box::pin(async move {
            let key = keys.decoding_key(&token)?;
            decode::<TokenClaims>(&token, &key, &validation)
                .map(|data| Principal::from_claims(data.claims))
                .map_err(|error| Error::TokenRejected(Box::new(error)))
        })
    }
}

#[derive(Clone)]
enum JwtKeys {
    Single(Arc<DecodingKey>),
    Set(Arc<JwkSet>),
}

impl JwtKeys {
    fn decoding_key(&self, token: &str) -> Result<DecodingKey> {
        match self {
            Self::Single(key) => Ok((**key).clone()),
            Self::Set(jwks) => {
                let header =
                    decode_header(token).map_err(|error| Error::TokenRejected(Box::new(error)))?;
                let jwk = match header.kid.as_deref() {
                    Some(kid) => jwks.find(kid).ok_or_else(|| {
                        Error::TokenRejected(format!("no JWK matched kid `{kid}`").into())
                    })?,
                    None if jwks.keys.len() == 1 => &jwks.keys[0],
                    None => {
                        return Err(Error::TokenRejected(
                            "JWT header did not include a key id".into(),
                        ));
                    }
                };

                DecodingKey::from_jwk(jwk).map_err(|error| Error::TokenRejected(Box::new(error)))
            }
        }
    }
}

#[derive(Debug)]
struct TokenClaims {
    sub: String,
    iss: Option<String>,
    aud: Vec<String>,
    groups: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RealmAccess {
    #[serde(default)]
    roles: Vec<String>,
}

impl<'de> Deserialize<'de> for TokenClaims {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawClaims {
            sub: String,
            #[serde(default)]
            iss: Option<String>,
            #[serde(default, deserialize_with = "deserialize_audience")]
            aud: Vec<String>,
            #[serde(default)]
            groups: Vec<String>,
            #[serde(default)]
            realm_access: RealmAccess,
        }

        let mut raw = RawClaims::deserialize(deserializer)?;
        raw.groups.extend(raw.realm_access.roles);
        deduplicate(&mut raw.groups);

        Ok(Self {
            sub: raw.sub,
            iss: raw.iss,
            aud: raw.aud,
            groups: raw.groups,
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

    /// Discovers provider metadata and installs a JWKS-backed JWT validator.
    pub async fn discover(self) -> BuildResult<Oidc> {
        self.discover_with_client(reqwest::Client::new()).await
    }

    /// Discovers provider metadata using a caller-supplied HTTP client.
    pub async fn discover_with_client(self, client: reqwest::Client) -> BuildResult<Oidc> {
        if !self.config.enabled {
            return Ok(self.build());
        }

        let auth_server_url = self
            .config
            .auth_server_url
            .clone()
            .ok_or(BuildError::MissingAuthServerUrl)?;
        let metadata_url = discovery_url(&auth_server_url)?;
        let metadata: ProviderMetadata = client
            .get(metadata_url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let jwks: JwkSet = client
            .get(&metadata.jwks_uri)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        Ok(self.provider_metadata(metadata, jwks))
    }

    /// Installs provider metadata and a JWKS-backed JWT validator.
    pub fn provider_metadata(mut self, metadata: ProviderMetadata, jwks: JwkSet) -> Oidc {
        let mut validation_config = self.config.clone();
        if validation_config.token.issuer.is_none() {
            validation_config.token.issuer = metadata.issuer;
        }

        self.validator = Some(Arc::new(JwtValidator::jwks(jwks, &validation_config)));
        self.build()
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

fn discovery_url(auth_server_url: &str) -> BuildResult<reqwest::Url> {
    let url = format!(
        "{}/.well-known/openid-configuration",
        auth_server_url.trim_end_matches('/')
    );
    reqwest::Url::parse(&url).map_err(|error| BuildError::InvalidUrl {
        url,
        message: error.to_string(),
    })
}

fn apply_validation_config(validation: &mut Validation, config: &OidcConfig) {
    let issuer = config
        .token
        .issuer
        .as_deref()
        .or(config.auth_server_url.as_deref());
    if let Some(issuer) = issuer {
        validation.set_issuer(&[issuer]);
    }

    if let Some(audience) = config.token.audience.as_deref() {
        validation.set_audience(&[audience]);
    }
}

fn supported_algorithms(jwks: &JwkSet) -> Vec<Algorithm> {
    let mut algorithms = Vec::new();
    for algorithm in jwks
        .keys
        .iter()
        .filter_map(|jwk| jwk_algorithm(jwk.common.key_algorithm))
    {
        if !algorithms.contains(&algorithm) {
            algorithms.push(algorithm);
        }
    }
    algorithms
}

fn jwk_algorithm(algorithm: Option<KeyAlgorithm>) -> Option<Algorithm> {
    Algorithm::from_str(&algorithm?.to_string()).ok()
}

fn deserialize_audience<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?.unwrap_or(Value::Null);
    match value {
        Value::Null => Ok(Vec::new()),
        Value::String(audience) => Ok(vec![audience]),
        Value::Array(values) => values
            .into_iter()
            .map(|value| match value {
                Value::String(audience) => Ok(audience),
                _ => Err(serde::de::Error::custom("audience entries must be strings")),
            })
            .collect(),
        _ => Err(serde::de::Error::custom(
            "audience must be a string or string array",
        )),
    }
}

fn deduplicate(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::extract::Extension;
    use axum::routing::get;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use mp_config::MapSource;
    use serde::Serialize;
    use serde_json::json;
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
                    .with("quarkus.oidc.application-type", "hybrid")
                    .with("quarkus.oidc.token.audience", "orders-api"),
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
                token: OidcTokenConfig {
                    issuer: None,
                    audience: Some("orders-api".to_owned()),
                },
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

    #[tokio::test]
    async fn jwt_validator_accepts_signed_token_and_extracts_claims() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
            },
            ..OidcConfig::default()
        };
        let token = jwt(TestClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            exp: 4_102_444_800,
            groups: vec!["admin"],
            realm_access: RealmAccessClaims {
                roles: vec!["user"],
            },
        });

        let response = claims_app(
            Oidc::builder(config.clone())
                .validator(JwtValidator::hs256("secret", &config))
                .build(),
        )
        .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn jwt_validator_rejects_wrong_issuer() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            ..OidcConfig::default()
        };
        let token = jwt(TestClaims {
            sub: "alice",
            iss: "https://other-issuer.example/realms/app",
            aud: "orders-api",
            exp: 4_102_444_800,
            groups: Vec::new(),
            realm_access: RealmAccessClaims { roles: Vec::new() },
        });

        let response = app(Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build())
        .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(WWW_AUTHENTICATE).unwrap(),
            HeaderValue::from_static(r#"Bearer error="invalid_token""#)
        );
    }

    #[tokio::test]
    async fn jwks_validator_selects_key_by_kid() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
            },
            ..OidcConfig::default()
        };
        let token = jwt_with_kid(
            "test-key",
            TestClaims {
                sub: "alice",
                iss: "https://issuer.example/realms/app",
                aud: "orders-api",
                exp: 4_102_444_800,
                groups: vec!["admin"],
                realm_access: RealmAccessClaims {
                    roles: vec!["user"],
                },
            },
        );

        let response = claims_app(
            Oidc::builder(config.clone())
                .validator(JwtValidator::jwks(test_jwks(), &config))
                .build(),
        )
        .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn jwks_validator_rejects_unknown_kid() {
        let config = OidcConfig::default();
        let token = jwt_with_kid(
            "other-key",
            TestClaims {
                sub: "alice",
                iss: "https://issuer.example/realms/app",
                aud: "orders-api",
                exp: 4_102_444_800,
                groups: Vec::new(),
                realm_access: RealmAccessClaims { roles: Vec::new() },
            },
        );

        let response = app(Oidc::builder(config.clone())
            .validator(JwtValidator::jwks(test_jwks(), &config))
            .build())
        .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(WWW_AUTHENTICATE).unwrap(),
            HeaderValue::from_static(r#"Bearer error="invalid_token""#)
        );
    }

    #[test]
    fn discovery_url_appends_well_known_path() {
        assert_eq!(
            discovery_url("https://issuer.example/realms/app")
                .expect("discovery URL should parse")
                .as_str(),
            "https://issuer.example/realms/app/.well-known/openid-configuration"
        );
        assert_eq!(
            discovery_url("https://issuer.example/realms/app/")
                .expect("discovery URL should parse")
                .as_str(),
            "https://issuer.example/realms/app/.well-known/openid-configuration"
        );
    }

    #[test]
    fn provider_metadata_parses_oidc_discovery_document() {
        let metadata = ProviderMetadata::from_json(
            r#"{
                "issuer": "https://issuer.example/realms/app",
                "jwks_uri": "https://issuer.example/realms/app/protocol/openid-connect/certs"
            }"#,
        )
        .expect("provider metadata should parse");

        assert_eq!(
            metadata,
            ProviderMetadata {
                issuer: Some("https://issuer.example/realms/app".to_owned()),
                jwks_uri: "https://issuer.example/realms/app/protocol/openid-connect/certs"
                    .to_owned(),
            }
        );
    }

    #[tokio::test]
    async fn provider_metadata_installs_issuer_and_jwks_validator() {
        let token = jwt_with_kid(
            "test-key",
            TestClaims {
                sub: "alice",
                iss: "https://issuer.example/realms/app",
                aud: "orders-api",
                exp: 4_102_444_800,
                groups: vec!["admin"],
                realm_access: RealmAccessClaims {
                    roles: vec!["user"],
                },
            },
        );

        let response = claims_app(
            Oidc::builder(OidcConfig {
                token: OidcTokenConfig {
                    issuer: None,
                    audience: Some("orders-api".to_owned()),
                },
                ..OidcConfig::default()
            })
            .provider_metadata(test_metadata(), test_jwks()),
        )
        .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
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

    fn claims_app(oidc: Oidc) -> Router {
        Router::new()
            .route(
                "/protected",
                get(|Extension(principal): Extension<Principal>| async move {
                    assert_eq!(principal.subject(), "alice");
                    assert_eq!(
                        principal.issuer(),
                        Some("https://issuer.example/realms/app")
                    );
                    assert_eq!(principal.audience().collect::<Vec<_>>(), vec!["orders-api"]);
                    assert_eq!(
                        principal.groups().collect::<Vec<_>>(),
                        vec!["admin", "user"]
                    );
                    "ok"
                }),
            )
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

    fn jwt(claims: TestClaims<'_>) -> String {
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"secret"),
        )
        .expect("test token should encode")
    }

    fn jwt_with_kid(kid: &str, claims: TestClaims<'_>) -> String {
        let mut header = Header::default();
        header.kid = Some(kid.to_owned());

        encode(&header, &claims, &EncodingKey::from_secret(b"secret"))
            .expect("test token should encode")
    }

    fn test_jwks() -> JwkSet {
        serde_json::from_value(json!({
            "keys": [
                {
                    "kty": "oct",
                    "alg": "HS256",
                    "kid": "test-key",
                    "k": "c2VjcmV0"
                }
            ]
        }))
        .expect("test JWKS should parse")
    }

    fn test_metadata() -> ProviderMetadata {
        ProviderMetadata {
            issuer: Some("https://issuer.example/realms/app".to_owned()),
            jwks_uri: "https://issuer.example/realms/app/certs".to_owned(),
        }
    }

    #[derive(Serialize)]
    struct TestClaims<'a> {
        sub: &'a str,
        iss: &'a str,
        aud: &'a str,
        exp: u64,
        groups: Vec<&'a str>,
        realm_access: RealmAccessClaims<'a>,
    }

    #[derive(Serialize)]
    struct RealmAccessClaims<'a> {
        roles: Vec<&'a str>,
    }
}

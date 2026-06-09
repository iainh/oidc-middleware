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

pub use oidc_middleware_macros::roles_allowed;

use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::response::{IntoResponse, Response};
use http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use http::request::Parts;
use http::{HeaderValue, Request, StatusCode};
use jsonwebtoken::jwk::{JwkSet, KeyAlgorithm};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use mp_config::{Config, ConfigProperties};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::convert::Infallible;
use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower_layer::Layer;
use tower_service::Service;

/// Result type returned by token validators.
pub type Result<T> = std::result::Result<T, Error>;

/// Boxed error type used by extension points.
pub type BoxError = Box<dyn StdError + Send + Sync>;
type ValidationFuture = Pin<Box<dyn Future<Output = Result<Principal>> + Send>>;
/// Future returned by [`JwksProvider`].
pub type JwksRefreshFuture =
    Pin<Box<dyn Future<Output = std::result::Result<JwkSet, BoxError>> + Send>>;

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
    /// Paths that should select this tenant.
    pub tenant_paths: Option<String>,
    /// Quarkus-style application type.
    #[config(default)]
    pub application_type: ApplicationType,
    /// Token validation settings.
    #[config(nested)]
    pub token: OidcTokenConfig,
    /// Role extraction settings.
    #[config(nested)]
    pub roles: OidcRolesConfig,
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
            tenant_paths: None,
            application_type: ApplicationType::Service,
            token: OidcTokenConfig::default(),
            roles: OidcRolesConfig::default(),
        }
    }
}

/// Token validation configuration loaded from `quarkus.oidc.token.*`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcTokenConfig {
    /// Expected token issuer. Defaults to `auth-server-url` when unset.
    pub issuer: Option<String>,
    /// Expected token audience.
    pub audience: Option<String>,
    /// Expected JWT `typ` claim value.
    pub token_type: Option<String>,
    /// Required JWT signature algorithm.
    pub signature_algorithm: Option<TokenSignatureAlgorithm>,
    /// Require the token to include a `sub` claim.
    pub subject_required: bool,
    /// Required claims and their expected string values.
    pub required_claims: HashMap<String, Vec<String>>,
    /// Claim used as the authenticated principal name.
    pub principal_claim: Option<String>,
    /// Custom HTTP header that contains the bearer token.
    pub header: Option<String>,
    /// HTTP Authorization header scheme.
    pub authorization_scheme: String,
    /// Grace period applied to token expiry and issued-at checks.
    pub lifespan_grace: Option<u64>,
    /// Maximum age allowed since the token `iat` claim.
    pub age: Option<Duration>,
}

impl Default for OidcTokenConfig {
    fn default() -> Self {
        Self {
            issuer: None,
            audience: None,
            token_type: None,
            signature_algorithm: None,
            subject_required: false,
            required_claims: HashMap::new(),
            principal_claim: None,
            header: None,
            authorization_scheme: "Bearer".to_owned(),
            lifespan_grace: None,
            age: None,
        }
    }
}

impl ConfigProperties for OidcTokenConfig {
    fn from_config(config: &Config) -> mp_config::Result<Self> {
        Self::from_config_prefix(config, "")
    }

    fn from_config_prefix(config: &Config, prefix: &str) -> mp_config::Result<Self> {
        let key = |name: &str| {
            if prefix.is_empty() {
                name.to_owned()
            } else {
                format!("{prefix}.{name}")
            }
        };

        Ok(Self {
            issuer: config.get_optional(&key("issuer"))?,
            audience: config.get_optional(&key("audience"))?,
            token_type: config.get_optional(&key("token-type"))?,
            signature_algorithm: config.get_optional(&key("signature-algorithm"))?,
            subject_required: config
                .get_optional(&key("subject-required"))?
                .unwrap_or_default(),
            required_claims: load_required_claims(config, &key("required-claims"))?,
            principal_claim: config.get_optional(&key("principal-claim"))?,
            header: config.get_optional(&key("header"))?,
            authorization_scheme: config
                .get_optional(&key("authorization-scheme"))?
                .unwrap_or_else(|| "Bearer".to_owned()),
            lifespan_grace: config.get_optional(&key("lifespan-grace"))?,
            age: config.get_optional(&key("age"))?,
        })
    }
}

impl OidcTokenConfig {
    fn audiences(&self) -> Vec<String> {
        self.audience.as_deref().map(split_csv).unwrap_or_default()
    }

    fn accepts_any_audience(&self) -> bool {
        self.audiences().iter().any(|audience| audience == "any")
    }
}

/// Role extraction configuration loaded from `quarkus.oidc.roles.*`.
#[derive(Clone, Debug, ConfigProperties, Eq, PartialEq)]
#[config(rename_all = "kebab-case")]
pub struct OidcRolesConfig {
    /// Token claim paths used to extract role names.
    ///
    /// The default covers standard `groups` claims and Keycloak realm roles.
    #[config(default = "groups,realm_access.roles")]
    pub role_claim_path: String,
    /// Separator used when a role claim is a string containing multiple roles.
    #[config(default = " ")]
    pub role_claim_separator: String,
}

impl Default for OidcRolesConfig {
    fn default() -> Self {
        Self {
            role_claim_path: "groups,realm_access.roles".to_owned(),
            role_claim_separator: " ".to_owned(),
        }
    }
}

impl OidcRolesConfig {
    fn claim_paths(&self) -> Vec<String> {
        split_csv(&self.role_claim_path)
    }
}

/// Quarkus-compatible JWT signature algorithm restriction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenSignatureAlgorithm {
    /// RSA using SHA-256.
    Rs256,
    /// RSA using SHA-384.
    Rs384,
    /// RSA using SHA-512.
    Rs512,
    /// RSASSA-PSS using SHA-256.
    Ps256,
    /// RSASSA-PSS using SHA-384.
    Ps384,
    /// RSASSA-PSS using SHA-512.
    Ps512,
    /// ECDSA using SHA-256.
    Es256,
    /// ECDSA using SHA-384.
    Es384,
    /// EdDSA.
    Eddsa,
}

impl TokenSignatureAlgorithm {
    fn algorithm(self) -> Algorithm {
        match self {
            Self::Rs256 => Algorithm::RS256,
            Self::Rs384 => Algorithm::RS384,
            Self::Rs512 => Algorithm::RS512,
            Self::Ps256 => Algorithm::PS256,
            Self::Ps384 => Algorithm::PS384,
            Self::Ps512 => Algorithm::PS512,
            Self::Es256 => Algorithm::ES256,
            Self::Es384 => Algorithm::ES384,
            Self::Eddsa => Algorithm::EdDSA,
        }
    }
}

impl mp_config::FromConfigValue for TokenSignatureAlgorithm {
    fn from_config_value(value: &str) -> std::result::Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "rs256" => Ok(Self::Rs256),
            "rs384" => Ok(Self::Rs384),
            "rs512" => Ok(Self::Rs512),
            "ps256" => Ok(Self::Ps256),
            "ps384" => Ok(Self::Ps384),
            "ps512" => Ok(Self::Ps512),
            "es256" => Ok(Self::Es256),
            "es384" => Ok(Self::Es384),
            "eddsa" => Ok(Self::Eddsa),
            other => Err(format!(
                "expected one of `rs256`, `rs384`, `rs512`, `ps256`, `ps384`, `ps512`, `es256`, `es384`, or `eddsa`, got `{other}`"
            )),
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

    /// Creates a principal with group memberships.
    pub fn with_groups(
        subject: impl Into<String>,
        groups: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            subject: Arc::from(subject.into()),
            issuer: None,
            audience: Vec::new(),
            groups: groups
                .into_iter()
                .map(|group| Arc::from(group.into()))
                .collect(),
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

    /// Returns true when this principal has `group`.
    pub fn has_group(&self, group: &str) -> bool {
        self.groups
            .iter()
            .any(|candidate| candidate.as_ref() == group)
    }

    /// Returns true when this principal has at least one of `groups`.
    pub fn has_any_group<'a>(&self, groups: impl IntoIterator<Item = &'a str>) -> bool {
        groups.into_iter().any(|group| self.has_group(group))
    }

    fn from_claims(
        claims: TokenClaims,
        role_claim_paths: &[String],
        role_claim_separator: &str,
        principal_claim: Option<&str>,
    ) -> Result<Self> {
        let subject = principal_name(&claims, principal_claim)?;
        Ok(Self {
            subject: Arc::from(subject),
            issuer: claims.iss.map(Arc::from),
            audience: claims.aud.into_iter().map(Arc::from).collect(),
            groups: extract_roles(&claims.extra, role_claim_paths, role_claim_separator)
                .into_iter()
                .map(Arc::from)
                .collect(),
        })
    }
}

/// Axum extractor for the authenticated OIDC principal.
///
/// This is intended for handlers protected by [`Oidc::layer`]. It is also the
/// expected principal argument for [`roles_allowed`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcPrincipal(Principal);

impl OidcPrincipal {
    /// Consumes the extractor wrapper and returns the principal.
    pub fn into_inner(self) -> Principal {
        self.0
    }
}

impl std::ops::Deref for OidcPrincipal {
    type Target = Principal;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for OidcPrincipal
where
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Principal>()
            .cloned()
            .map(Self)
            .ok_or(Error::Forbidden)
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
    /// The authenticated principal is not allowed to access the route.
    Forbidden,
    /// The validator rejected the token.
    TokenRejected(BoxError),
}

impl Error {
    fn status(&self) -> StatusCode {
        match self {
            Self::TenantDisabled => StatusCode::NOT_FOUND,
            Self::Forbidden => StatusCode::FORBIDDEN,
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
            Self::TenantDisabled | Self::Forbidden => HeaderValue::from_static("Bearer"),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingBearerToken => write!(f, "missing bearer token"),
            Self::InvalidAuthorizationHeader => write!(f, "invalid authorization header"),
            Self::TenantDisabled => write!(f, "OIDC tenant is disabled"),
            Self::Forbidden => write!(f, "authenticated principal is not allowed"),
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
        let mut response = status.into_response();
        if status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, self.challenge());
        }
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

/// Quarkus-style HTTP authorization policies.
///
/// Load this from `quarkus.http.auth.permission.*` and
/// `quarkus.http.auth.policy.*` properties with [`Authorization::from_config`],
/// then attach it with [`OidcBuilder::authorization`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Authorization {
    permissions: Arc<[HttpPermission]>,
}

impl Authorization {
    /// Loads Quarkus-style HTTP authorization configuration.
    pub fn from_config(config: &Config) -> mp_config::Result<Self> {
        let role_policies = load_role_policies(config)?;
        let mut permissions = Vec::new();

        for name in permission_names(config) {
            let prefix = format!("quarkus.http.auth.permission.{name}");
            let paths = split_csv(&config.get::<String>(&format!("{prefix}.paths"))?);
            let methods = config
                .get_optional::<String>(&format!("{prefix}.methods"))?
                .map(|methods| {
                    split_csv(&methods)
                        .into_iter()
                        .map(|method| method.to_ascii_uppercase())
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let policy_name = config.get::<String>(&format!("{prefix}.policy"))?;
            let policy = policy_from_config(&policy_name, &role_policies);

            permissions.push(HttpPermission {
                paths,
                methods,
                policy,
            });
        }

        Ok(Self {
            permissions: Arc::from(permissions),
        })
    }

    fn requirement(&self, method: &http::Method, path: &str) -> AuthRequirement {
        let matches = self
            .permissions
            .iter()
            .filter_map(|permission| {
                permission
                    .matches(method, path)
                    .map(|score| (score, permission))
            })
            .collect::<Vec<_>>();

        let Some(max_score) = matches.iter().map(|(score, _)| *score).max() else {
            return AuthRequirement::Permit;
        };

        let policies = matches
            .into_iter()
            .filter(|(score, _)| *score == max_score)
            .map(|(_, permission)| &permission.policy)
            .collect::<Vec<_>>();

        if policies
            .iter()
            .any(|policy| matches!(policy, HttpPolicy::Deny))
        {
            return AuthRequirement::Deny;
        }

        let mut roles = Vec::new();
        let mut authenticated = false;
        for policy in policies {
            match policy {
                HttpPolicy::Authenticated => authenticated = true,
                HttpPolicy::Roles(allowed) => roles.extend(allowed.iter().cloned()),
                HttpPolicy::Permit | HttpPolicy::Deny => {}
            }
        }

        if !roles.is_empty() {
            roles.sort();
            roles.dedup();
            return AuthRequirement::Roles(roles);
        }

        if authenticated {
            AuthRequirement::Authenticated
        } else {
            AuthRequirement::Permit
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HttpPermission {
    paths: Vec<String>,
    methods: Vec<String>,
    policy: HttpPolicy,
}

impl HttpPermission {
    fn matches(&self, method: &http::Method, request_path: &str) -> Option<usize> {
        if !self.methods.is_empty()
            && !self
                .methods
                .iter()
                .any(|configured| configured == method.as_str())
        {
            return None;
        }

        self.paths
            .iter()
            .filter_map(|path| path_match_score(path, request_path))
            .max()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum HttpPolicy {
    Permit,
    Deny,
    Authenticated,
    Roles(Vec<String>),
}

enum AuthRequirement {
    Permit,
    Deny,
    Authenticated,
    Roles(Vec<String>),
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
        Self::principal(token, Principal::new(subject))
    }

    /// Creates a validator that accepts `token` and returns `principal`.
    pub fn principal(token: impl Into<String>, principal: Principal) -> Self {
        Self {
            token: Arc::from(token.into()),
            principal,
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
    role_claim_paths: Arc<[String]>,
    role_claim_separator: Arc<str>,
    token_type: Option<Arc<str>>,
    subject_required: bool,
    required_claims: Arc<HashMap<String, Vec<String>>>,
    principal_claim: Option<Arc<str>>,
    token_age: Option<Duration>,
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
        apply_signature_algorithm_config(&mut validation, config);

        Self {
            keys: JwtKeys::Single(Arc::new(DecodingKey::from_secret(secret.as_ref()))),
            validation,
            role_claim_paths: Arc::from(config.roles.claim_paths()),
            role_claim_separator: Arc::from(config.roles.role_claim_separator.clone()),
            token_type: config.token.token_type.clone().map(Arc::from),
            subject_required: config.token.subject_required,
            required_claims: Arc::new(config.token.required_claims.clone()),
            principal_claim: config.token.principal_claim.clone().map(Arc::from),
            token_age: config.token.age,
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
        apply_jwks_algorithm_config(&mut validation, &jwks, config);

        Self {
            keys: JwtKeys::Set(Arc::new(jwks)),
            validation,
            role_claim_paths: Arc::from(config.roles.claim_paths()),
            role_claim_separator: Arc::from(config.roles.role_claim_separator.clone()),
            token_type: config.token.token_type.clone().map(Arc::from),
            subject_required: config.token.subject_required,
            required_claims: Arc::new(config.token.required_claims.clone()),
            principal_claim: config.token.principal_claim.clone().map(Arc::from),
            token_age: config.token.age,
        }
    }

    /// Builds a JWT validator backed by a refreshable JSON Web Key Set.
    ///
    /// The current key set is used first. If a token contains an unknown `kid`,
    /// the provider is called once to refresh the set before rejecting the
    /// token.
    pub fn refreshable_jwks<P>(jwks: JwkSet, provider: P, config: &OidcConfig) -> Self
    where
        P: JwksProvider,
    {
        let mut validation = Validation::new(Algorithm::RS256);
        apply_validation_config(&mut validation, config);
        apply_jwks_algorithm_config(&mut validation, &jwks, config);

        Self {
            keys: JwtKeys::Refreshing(RefreshingJwks {
                current: Arc::new(Mutex::new(jwks)),
                provider: Arc::new(provider),
            }),
            validation,
            role_claim_paths: Arc::from(config.roles.claim_paths()),
            role_claim_separator: Arc::from(config.roles.role_claim_separator.clone()),
            token_type: config.token.token_type.clone().map(Arc::from),
            subject_required: config.token.subject_required,
            required_claims: Arc::new(config.token.required_claims.clone()),
            principal_claim: config.token.principal_claim.clone().map(Arc::from),
            token_age: config.token.age,
        }
    }
}

impl TokenValidator for JwtValidator {
    fn validate(&self, token: Arc<str>) -> ValidationFuture {
        let keys = self.keys.clone();
        let validation = self.validation.clone();
        let role_claim_paths = self.role_claim_paths.clone();
        let role_claim_separator = self.role_claim_separator.clone();
        let token_type = self.token_type.clone();
        let subject_required = self.subject_required;
        let required_claims = self.required_claims.clone();
        let principal_claim = self.principal_claim.clone();
        let token_age = self.token_age;
        let leeway = validation.leeway;

        Box::pin(async move {
            let key = keys.decoding_key(&token).await?;
            decode::<TokenClaims>(&token, &key, &validation)
                .map_err(|error| Error::TokenRejected(Box::new(error)))
                .and_then(|data| {
                    validate_token_type(&data.claims, token_type.as_deref())?;
                    validate_subject(&data.claims, subject_required)?;
                    validate_required_claims(&data.claims, &required_claims)?;
                    validate_token_age(&data.claims, token_age, leeway)?;
                    Principal::from_claims(
                        data.claims,
                        &role_claim_paths,
                        &role_claim_separator,
                        principal_claim.as_deref(),
                    )
                })
        })
    }
}

/// Source used to refresh a provider JSON Web Key Set.
pub trait JwksProvider: Send + Sync + 'static {
    /// Fetches the current JSON Web Key Set.
    fn fetch(&self) -> JwksRefreshFuture;
}

impl<F, Fut> JwksProvider for F
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = std::result::Result<JwkSet, BoxError>> + Send + 'static,
{
    fn fetch(&self) -> JwksRefreshFuture {
        Box::pin(self())
    }
}

#[derive(Clone)]
struct HttpJwksProvider {
    client: reqwest::Client,
    jwks_uri: String,
}

impl JwksProvider for HttpJwksProvider {
    fn fetch(&self) -> JwksRefreshFuture {
        let client = self.client.clone();
        let jwks_uri = self.jwks_uri.clone();
        Box::pin(async move {
            client
                .get(&jwks_uri)
                .send()
                .await?
                .error_for_status()?
                .json::<JwkSet>()
                .await
                .map_err(|error| Box::new(error) as BoxError)
        })
    }
}

#[derive(Clone)]
enum JwtKeys {
    Single(Arc<DecodingKey>),
    Set(Arc<JwkSet>),
    Refreshing(RefreshingJwks),
}

#[derive(Clone)]
struct RefreshingJwks {
    current: Arc<Mutex<JwkSet>>,
    provider: Arc<dyn JwksProvider>,
}

impl JwtKeys {
    async fn decoding_key(&self, token: &str) -> Result<DecodingKey> {
        match self {
            Self::Single(key) => Ok((**key).clone()),
            Self::Set(jwks) => decoding_key_from_jwks(jwks, token),
            Self::Refreshing(jwks) => {
                let key_result = {
                    let current = jwks
                        .current
                        .lock()
                        .map_err(|_| Error::TokenRejected("JWKS cache lock was poisoned".into()))?;
                    decoding_key_from_jwks(&current, token)
                };

                match key_result {
                    Ok(key) => Ok(key),
                    Err(error) if should_refresh_jwks(&error) => {
                        let refreshed =
                            jwks.provider.fetch().await.map_err(Error::TokenRejected)?;
                        let key = decoding_key_from_jwks(&refreshed, token)?;
                        let mut current = jwks.current.lock().map_err(|_| {
                            Error::TokenRejected("JWKS cache lock was poisoned".into())
                        })?;
                        *current = refreshed;
                        Ok(key)
                    }
                    Err(error) => Err(error),
                }
            }
        }
    }
}

fn decoding_key_from_jwks(jwks: &JwkSet, token: &str) -> Result<DecodingKey> {
    let header = decode_header(token).map_err(|error| Error::TokenRejected(Box::new(error)))?;
    let jwk = match header.kid.as_deref() {
        Some(kid) => jwks
            .find(kid)
            .ok_or_else(|| Error::TokenRejected(UnknownKid(kid.to_owned()).into()))?,
        None if jwks.keys.len() == 1 => &jwks.keys[0],
        None => {
            return Err(Error::TokenRejected(
                "JWT header did not include a key id".into(),
            ));
        }
    };

    DecodingKey::from_jwk(jwk).map_err(|error| Error::TokenRejected(Box::new(error)))
}

fn should_refresh_jwks(error: &Error) -> bool {
    matches!(error, Error::TokenRejected(source) if source.is::<UnknownKid>())
}

fn validate_token_type(claims: &TokenClaims, expected: Option<&str>) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };

    match claims.typ.as_deref() {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(Error::TokenRejected(
            format!("JWT typ claim `{actual}` did not match expected `{expected}`").into(),
        )),
        None => Err(Error::TokenRejected(
            format!("JWT typ claim is required to be `{expected}`").into(),
        )),
    }
}

fn validate_subject(claims: &TokenClaims, subject_required: bool) -> Result<()> {
    if subject_required && claims.sub.is_none() {
        return Err(Error::TokenRejected("JWT sub claim is required".into()));
    }

    Ok(())
}

fn validate_required_claims(
    claims: &TokenClaims,
    required_claims: &HashMap<String, Vec<String>>,
) -> Result<()> {
    for (claim_name, expected_values) in required_claims {
        let actual_values = claim_string_values(claims, claim_name).ok_or_else(|| {
            Error::TokenRejected(format!("JWT claim `{claim_name}` is required").into())
        })?;

        for expected in expected_values {
            if !actual_values.iter().any(|actual| actual == expected) {
                return Err(Error::TokenRejected(
                    format!("JWT claim `{claim_name}` did not include required value `{expected}`")
                        .into(),
                ));
            }
        }
    }

    Ok(())
}

fn validate_token_age(claims: &TokenClaims, max_age: Option<Duration>, leeway: u64) -> Result<()> {
    let Some(max_age) = max_age else {
        return Ok(());
    };
    let issued_at = claims.iat.ok_or_else(|| {
        Error::TokenRejected("JWT iat claim is required for token age validation".into())
    })?;
    let now = unix_timestamp()?;

    if issued_at > now.saturating_add(leeway) {
        return Err(Error::TokenRejected(
            "JWT iat claim is later than the allowed lifespan grace".into(),
        ));
    }

    if now
        > issued_at
            .saturating_add(max_age.as_secs())
            .saturating_add(leeway)
    {
        return Err(Error::TokenRejected(
            "JWT age exceeded the configured token age".into(),
        ));
    }

    Ok(())
}

fn unix_timestamp() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| Error::TokenRejected(Box::new(error)))
}

fn principal_name(claims: &TokenClaims, principal_claim: Option<&str>) -> Result<String> {
    if let Some(claim_name) = principal_claim {
        return claim_string_value(claims, claim_name).ok_or_else(|| {
            Error::TokenRejected(
                format!("JWT principal claim `{claim_name}` is required to be a string").into(),
            )
        });
    }

    claim_string_value(claims, "upn")
        .or_else(|| claim_string_value(claims, "preferred_username"))
        .or_else(|| claims.sub.clone())
        .ok_or_else(|| {
            Error::TokenRejected(
                "JWT must include a principal claim such as `upn`, `preferred_username`, or `sub`"
                    .into(),
            )
        })
}

fn claim_string_value(claims: &TokenClaims, claim_name: &str) -> Option<String> {
    match claim_name {
        "sub" => claims.sub.clone(),
        "iss" => claims.iss.clone(),
        "typ" => claims.typ.clone(),
        _ => claims
            .extra
            .get(claim_name)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    }
}

fn claim_string_values(claims: &TokenClaims, claim_name: &str) -> Option<Vec<String>> {
    match claim_name {
        "sub" => claims.sub.clone().map(|subject| vec![subject]),
        "iss" => claims.iss.clone().map(|issuer| vec![issuer]),
        "aud" => Some(claims.aud.clone()),
        "typ" => claims.typ.clone().map(|token_type| vec![token_type]),
        "iat" => claims.iat.map(|issued_at| vec![issued_at.to_string()]),
        _ => json_string_values(claims.extra.get(claim_name)?),
    }
}

fn json_string_values(value: &Value) -> Option<Vec<String>> {
    match value {
        Value::String(value) => Some(vec![value.clone()]),
        Value::Array(values) => values
            .iter()
            .map(|value| value.as_str().map(ToOwned::to_owned))
            .collect(),
        _ => None,
    }
}

#[derive(Debug)]
struct UnknownKid(String);

impl fmt::Display for UnknownKid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "no JWK matched kid `{}`", self.0)
    }
}

impl StdError for UnknownKid {}

#[derive(Debug)]
struct TokenClaims {
    sub: Option<String>,
    iss: Option<String>,
    aud: Vec<String>,
    typ: Option<String>,
    iat: Option<u64>,
    extra: Value,
}

impl<'de> Deserialize<'de> for TokenClaims {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawClaims {
            #[serde(default)]
            sub: Option<String>,
            #[serde(default)]
            iss: Option<String>,
            #[serde(default, deserialize_with = "deserialize_audience")]
            aud: Vec<String>,
            #[serde(default)]
            typ: Option<String>,
            #[serde(default)]
            iat: Option<u64>,
            #[serde(flatten)]
            extra: serde_json::Map<String, Value>,
        }

        let raw = RawClaims::deserialize(deserializer)?;

        Ok(Self {
            sub: raw.sub,
            iss: raw.iss,
            aud: raw.aud,
            typ: raw.typ,
            iat: raw.iat,
            extra: Value::Object(raw.extra),
        })
    }
}

/// OIDC middleware entry point.
#[derive(Clone)]
pub struct Oidc {
    config: OidcConfig,
    validator: Arc<dyn TokenValidator>,
    authorization: Option<Authorization>,
}

impl Oidc {
    /// Starts building OIDC middleware from configuration.
    pub fn builder(config: OidcConfig) -> OidcBuilder {
        OidcBuilder {
            config,
            validator: None,
            authorization: None,
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

        if let Some(authorization) = &self.authorization {
            match authorization.requirement(request.method(), request.uri().path()) {
                AuthRequirement::Permit => return Ok(()),
                AuthRequirement::Deny => {
                    self.authenticate_principal(request).await?;
                    return Err(Error::Forbidden);
                }
                AuthRequirement::Authenticated => {
                    self.authenticate_principal(request).await?;
                    return Ok(());
                }
                AuthRequirement::Roles(roles) => {
                    let principal = self.authenticate_principal(request).await?;
                    if roles
                        .iter()
                        .any(|role| principal.groups().any(|group| group == role))
                    {
                        return Ok(());
                    }
                    return Err(Error::Forbidden);
                }
            }
        }

        self.authenticate_principal(request).await?;
        Ok(())
    }

    async fn authenticate_principal(&self, request: &mut Request<Body>) -> Result<Principal> {
        let token = bearer_token(request, &self.config.token)?;
        let principal = self.validator.validate(token).await?;
        request.extensions_mut().insert(principal.clone());
        Ok(principal)
    }
}

/// Builder for [`Oidc`].
pub struct OidcBuilder {
    config: OidcConfig,
    validator: Option<Arc<dyn TokenValidator>>,
    authorization: Option<Authorization>,
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

    /// Sets Quarkus-style path authorization policies.
    pub fn authorization(mut self, authorization: Authorization) -> Self {
        self.authorization = Some(authorization);
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

        Ok(self.provider_metadata_refreshing(metadata, jwks, client))
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

    /// Installs provider metadata and a refreshable JWKS-backed JWT validator.
    pub fn provider_metadata_refreshing(
        mut self,
        metadata: ProviderMetadata,
        jwks: JwkSet,
        client: reqwest::Client,
    ) -> Oidc {
        let mut validation_config = self.config.clone();
        if validation_config.token.issuer.is_none() {
            validation_config.token.issuer = metadata.issuer;
        }

        self.validator = Some(Arc::new(JwtValidator::refreshable_jwks(
            jwks,
            HttpJwksProvider {
                client,
                jwks_uri: metadata.jwks_uri,
            },
            &validation_config,
        )));
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
            authorization: self.authorization,
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

/// Multi-tenant OIDC middleware.
#[derive(Clone, Default)]
pub struct Tenants {
    tenants: Arc<[RegisteredTenant]>,
    default_tenant: Option<Oidc>,
    header_name: Option<http::HeaderName>,
}

impl Tenants {
    /// Starts building a multi-tenant OIDC layer.
    pub fn builder() -> TenantsBuilder {
        TenantsBuilder::default()
    }

    /// Loads the default tenant and named tenants from `mp-config`.
    ///
    /// The default tenant uses `quarkus.oidc.*`; named tenants use
    /// `quarkus.oidc.<tenant>.*`. Tenant selection uses each tenant's
    /// `tenant-paths` property.
    pub fn from_config(config: &Config) -> mp_config::Result<TenantsBuilder> {
        let mut builder = Tenants::builder();
        if has_default_tenant_config(config) {
            let default_config = OidcConfig::from_config(config)?;
            builder = builder.default_tenant(Oidc::builder(default_config).build());
        }

        for name in named_tenant_names(config) {
            let tenant_config =
                OidcConfig::from_config_prefix(config, &format!("quarkus.oidc.{name}"))?;
            builder = builder.tenant(name, Oidc::builder(tenant_config).build());
        }

        Ok(builder)
    }

    /// Returns a tower layer suitable for `Router::layer`.
    pub fn layer(self) -> TenantsLayer {
        TenantsLayer { tenants: self }
    }

    fn select(&self, request: &Request<Body>) -> Option<&Oidc> {
        if let Some(header_name) = &self.header_name {
            if let Some(value) = request
                .headers()
                .get(header_name)
                .and_then(|value| value.to_str().ok())
            {
                if let Some(tenant) = self
                    .tenants
                    .iter()
                    .find(|tenant| tenant.name.as_ref() == value)
                {
                    return Some(&tenant.oidc);
                }
            }
        }

        let path = request.uri().path();
        self.tenants
            .iter()
            .filter_map(|tenant| tenant.match_score(path).map(|score| (score, tenant)))
            .max_by_key(|(score, _)| *score)
            .map(|(_, tenant)| &tenant.oidc)
            .or(self.default_tenant.as_ref())
    }
}

/// Builder for [`Tenants`].
#[derive(Default)]
pub struct TenantsBuilder {
    tenants: Vec<RegisteredTenant>,
    default_tenant: Option<Oidc>,
    header_name: Option<http::HeaderName>,
}

impl TenantsBuilder {
    /// Sets the fallback tenant used when no named tenant matches.
    pub fn default_tenant(mut self, oidc: Oidc) -> Self {
        self.default_tenant = Some(oidc);
        self
    }

    /// Adds a named tenant.
    pub fn tenant(mut self, name: impl Into<String>, oidc: Oidc) -> Self {
        let name = Arc::from(name.into());
        let tenant_paths = oidc
            .config
            .tenant_paths
            .as_deref()
            .map(split_csv)
            .unwrap_or_default();
        self.tenants.push(RegisteredTenant {
            name,
            tenant_paths,
            oidc,
        });
        self
    }

    /// Selects tenants from a request header before path matching.
    pub fn tenant_header(mut self, header_name: http::HeaderName) -> Self {
        self.header_name = Some(header_name);
        self
    }

    /// Finishes the tenant registry.
    pub fn build(self) -> Tenants {
        Tenants {
            tenants: Arc::from(self.tenants),
            default_tenant: self.default_tenant,
            header_name: self.header_name,
        }
    }
}

#[derive(Clone)]
struct RegisteredTenant {
    name: Arc<str>,
    tenant_paths: Vec<String>,
    oidc: Oidc,
}

impl RegisteredTenant {
    fn match_score(&self, request_path: &str) -> Option<usize> {
        self.tenant_paths
            .iter()
            .filter_map(|path| path_match_score(path, request_path))
            .max()
    }
}

/// Tower layer produced by [`Tenants::layer`].
#[derive(Clone)]
pub struct TenantsLayer {
    tenants: Tenants,
}

impl<S> Layer<S> for TenantsLayer {
    type Service = TenantsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TenantsService {
            inner,
            tenants: self.tenants.clone(),
        }
    }
}

/// Tower service that selects a tenant and authenticates requests.
#[derive(Clone)]
pub struct TenantsService<S> {
    inner: S,
    tenants: Tenants,
}

impl<S> Service<Request<Body>> for TenantsService<S>
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
        let tenants = self.tenants.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let Some(tenant) = tenants.select(&request) else {
                return inner.call(request).await;
            };

            match tenant.authenticate(&mut request).await {
                Ok(()) => inner.call(request).await,
                Err(error) => Ok(error.into_response()),
            }
        })
    }
}

fn load_role_policies(config: &Config) -> mp_config::Result<HashMap<String, Vec<String>>> {
    let mut policies = HashMap::new();

    for key in config.property_names() {
        let Some(name) = key
            .strip_prefix("quarkus.http.auth.policy.")
            .and_then(|suffix| suffix.strip_suffix(".roles-allowed"))
        else {
            continue;
        };

        policies.insert(name.to_owned(), split_csv(&config.get::<String>(&key)?));
    }

    Ok(policies)
}

fn load_required_claims(
    config: &Config,
    prefix: &str,
) -> mp_config::Result<HashMap<String, Vec<String>>> {
    let mut claims = HashMap::new();
    let property_prefix = format!("{prefix}.");

    for key in config.property_names() {
        let Some(claim_name) = key.strip_prefix(&property_prefix) else {
            continue;
        };
        if claim_name.is_empty() || claim_name.contains('.') {
            continue;
        }

        claims.insert(
            claim_name.to_owned(),
            split_csv(&config.get::<String>(&key)?),
        );
    }

    Ok(claims)
}

fn has_default_tenant_config(config: &Config) -> bool {
    config.property_names().into_iter().any(|key| {
        key == "quarkus.oidc.enabled"
            || key == "quarkus.oidc.tenant-enabled"
            || key == "quarkus.oidc.auth-server-url"
            || key == "quarkus.oidc.client-id"
            || key == "quarkus.oidc.tenant-paths"
            || key == "quarkus.oidc.application-type"
            || key.starts_with("quarkus.oidc.token.")
    })
}

fn named_tenant_names(config: &Config) -> Vec<String> {
    let mut names = BTreeSet::new();
    for key in config.property_names() {
        let Some(rest) = key.strip_prefix("quarkus.oidc.") else {
            continue;
        };
        let Some((name, property)) = rest.split_once('.') else {
            continue;
        };
        if !matches!(name, "token" | "roles")
            && matches!(
                property,
                "enabled"
                    | "tenant-enabled"
                    | "auth-server-url"
                    | "client-id"
                    | "tenant-paths"
                    | "application-type"
            )
            || property.starts_with("token.")
        {
            names.insert(name.to_owned());
        }
    }
    names.into_iter().collect()
}

fn permission_names(config: &Config) -> Vec<String> {
    let mut names = BTreeSet::new();

    for key in config.property_names() {
        if let Some(name) = key
            .strip_prefix("quarkus.http.auth.permission.")
            .and_then(|suffix| suffix.strip_suffix(".paths"))
        {
            names.insert(name.to_owned());
        }
    }

    names.into_iter().collect()
}

fn policy_from_config(name: &str, role_policies: &HashMap<String, Vec<String>>) -> HttpPolicy {
    match name {
        "permit" => HttpPolicy::Permit,
        "deny" => HttpPolicy::Deny,
        "authenticated" => HttpPolicy::Authenticated,
        name => HttpPolicy::Roles(role_policies.get(name).cloned().unwrap_or_default()),
    }
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn path_match_score(pattern: &str, request_path: &str) -> Option<usize> {
    if pattern == request_path {
        return Some(10_000 + pattern.len());
    }

    if pattern == "/*" {
        return Some(1);
    }

    if let Some(prefix) = pattern.strip_suffix("/*") {
        let prefix = format!("{prefix}/");
        return request_path.starts_with(&prefix).then_some(prefix.len());
    }

    if let Some(prefix) = pattern.strip_suffix('*') {
        return request_path.starts_with(prefix).then_some(prefix.len());
    }

    None
}

fn bearer_token(request: &Request<Body>, config: &OidcTokenConfig) -> Result<Arc<str>> {
    if let Some(header_name) = &config.header {
        let header_name = http::HeaderName::from_str(header_name)
            .map_err(|_| Error::InvalidAuthorizationHeader)?;
        let Some(header) = request.headers().get(header_name) else {
            return Err(Error::MissingBearerToken);
        };
        let token = header
            .to_str()
            .map_err(|_| Error::InvalidAuthorizationHeader)?
            .trim();
        if token.is_empty() {
            return Err(Error::InvalidAuthorizationHeader);
        }
        return Ok(Arc::from(token));
    }

    let Some(header) = request.headers().get(AUTHORIZATION) else {
        return Err(Error::MissingBearerToken);
    };

    let value = header
        .to_str()
        .map_err(|_| Error::InvalidAuthorizationHeader)?;
    let prefix = format!("{} ", config.authorization_scheme);
    let token = value
        .strip_prefix(&prefix)
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
    validation.leeway = config.token.lifespan_grace.unwrap_or_default();

    let issuer = config
        .token
        .issuer
        .as_deref()
        .or(config.auth_server_url.as_deref());
    if let Some(issuer) = issuer.filter(|issuer| *issuer != "any") {
        validation.set_issuer(&[issuer]);
    }

    if config.token.accepts_any_audience() {
        validation.validate_aud = false;
        return;
    }

    let audiences = config.token.audiences();
    if audiences.is_empty() {
        if let Some(client_id) = config.client_id.as_deref() {
            validation.set_audience(&[client_id]);
        }
    } else {
        validation.set_audience(&audiences);
    }
}

fn apply_signature_algorithm_config(validation: &mut Validation, config: &OidcConfig) {
    if let Some(algorithm) = config.token.signature_algorithm {
        validation.algorithms = vec![algorithm.algorithm()];
    }
}

fn apply_jwks_algorithm_config(validation: &mut Validation, jwks: &JwkSet, config: &OidcConfig) {
    if config.token.signature_algorithm.is_some() {
        apply_signature_algorithm_config(validation, config);
        return;
    }

    let algorithms = supported_algorithms(jwks);
    if !algorithms.is_empty() {
        validation.algorithms = algorithms;
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

fn extract_roles(claims: &Value, paths: &[String], separator: &str) -> Vec<String> {
    let mut roles = Vec::new();
    for path in paths {
        if let Some(value) = claim_path_value(claims, path) {
            collect_roles(value, &mut roles, separator);
        }
    }
    deduplicate(&mut roles);
    roles
}

fn claim_path_value<'a>(claims: &'a Value, path: &str) -> Option<&'a Value> {
    path.split(['.', '/'])
        .filter(|part| !part.is_empty())
        .try_fold(claims, |value, part| value.get(part))
}

fn collect_roles(value: &Value, roles: &mut Vec<String>, separator: &str) {
    match value {
        Value::String(role) => split_roles(role, separator, roles),
        Value::Array(values) => {
            for value in values {
                collect_roles(value, roles, separator);
            }
        }
        _ => {}
    }
}

fn split_roles(value: &str, separator: &str, roles: &mut Vec<String>) {
    if separator.is_empty() {
        let role = value.trim();
        if !role.is_empty() {
            roles.push(role.to_owned());
        }
        return;
    }

    roles.extend(
        value
            .split(separator)
            .map(str::trim)
            .filter(|role| !role.is_empty())
            .map(ToOwned::to_owned),
    );
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
                    .with("quarkus.oidc.token.audience", "orders-api")
                    .with("quarkus.oidc.token.token-type", "bearer")
                    .with("quarkus.oidc.token.signature-algorithm", "rs256")
                    .with("quarkus.oidc.token.subject-required", "true")
                    .with("quarkus.oidc.token.required-claims.org_id", "org_xyz")
                    .with("quarkus.oidc.token.required-claims.scope", "read,write")
                    .with("quarkus.oidc.token.principal-claim", "email")
                    .with("quarkus.oidc.token.header", "x-access-token")
                    .with("quarkus.oidc.token.authorization-scheme", "Token")
                    .with("quarkus.oidc.token.lifespan-grace", "5")
                    .with("quarkus.oidc.token.age", "60s")
                    .with(
                        "quarkus.oidc.roles.role-claim-path",
                        "resource_access.api.roles",
                    )
                    .with("quarkus.oidc.roles.role-claim-separator", "|"),
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
                tenant_paths: None,
                application_type: ApplicationType::Hybrid,
                token: OidcTokenConfig {
                    issuer: None,
                    audience: Some("orders-api".to_owned()),
                    token_type: Some("bearer".to_owned()),
                    signature_algorithm: Some(TokenSignatureAlgorithm::Rs256),
                    subject_required: true,
                    required_claims: HashMap::from([
                        ("org_id".to_owned(), vec!["org_xyz".to_owned()]),
                        (
                            "scope".to_owned(),
                            vec!["read".to_owned(), "write".to_owned()],
                        ),
                    ]),
                    principal_claim: Some("email".to_owned()),
                    header: Some("x-access-token".to_owned()),
                    authorization_scheme: "Token".to_owned(),
                    lifespan_grace: Some(5),
                    age: Some(Duration::from_secs(60)),
                },
                roles: OidcRolesConfig {
                    role_claim_path: "resource_access.api.roles".to_owned(),
                    role_claim_separator: "|".to_owned(),
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
    async fn configured_authorization_scheme_is_accepted() {
        let response = app(Oidc::builder(OidcConfig {
            token: OidcTokenConfig {
                authorization_scheme: "Token".to_owned(),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        })
        .validator(StaticTokenValidator::bearer("test-token", "alice"))
        .build())
        .oneshot(request("/protected", Some("Token test-token")))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn configured_authorization_scheme_rejects_default_scheme() {
        let response = app(Oidc::builder(OidcConfig {
            token: OidcTokenConfig {
                authorization_scheme: "Token".to_owned(),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        })
        .validator(StaticTokenValidator::bearer("test-token", "alice"))
        .build())
        .oneshot(request("/protected", Some("Bearer test-token")))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn configured_token_header_is_accepted() {
        let response = app(Oidc::builder(OidcConfig {
            token: OidcTokenConfig {
                header: Some("x-access-token".to_owned()),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        })
        .validator(StaticTokenValidator::bearer("test-token", "alice"))
        .build())
        .oneshot(request_with_header(
            "/protected",
            "x-access-token",
            "test-token",
        ))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
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
                token_type: None,
                ..OidcTokenConfig::default()
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
    async fn jwt_validator_extracts_configured_role_claim_path() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                token_type: None,
                ..OidcTokenConfig::default()
            },
            roles: OidcRolesConfig {
                role_claim_path: "resource_access.orders.roles".to_owned(),
                ..OidcRolesConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(CustomRoleClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            exp: 4_102_444_800,
            resource_access: ResourceAccessClaims {
                orders: ResourceRolesClaims {
                    roles: vec!["orders-admin", "orders-user"],
                },
            },
        });

        let response = custom_roles_app(
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
    async fn jwt_validator_extracts_slash_separated_role_claim_path() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                token_type: None,
                ..OidcTokenConfig::default()
            },
            roles: OidcRolesConfig {
                role_claim_path: "resource_access/orders/roles".to_owned(),
                ..OidcRolesConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(CustomRoleClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            exp: 4_102_444_800,
            resource_access: ResourceAccessClaims {
                orders: ResourceRolesClaims {
                    roles: vec!["orders-admin", "orders-user"],
                },
            },
        });

        let response = custom_roles_app(
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
    async fn jwt_validator_splits_string_role_claims_with_configured_separator() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                token_type: None,
                ..OidcTokenConfig::default()
            },
            roles: OidcRolesConfig {
                role_claim_path: "permissions".to_owned(),
                role_claim_separator: "|".to_owned(),
            },
            ..OidcConfig::default()
        };
        let token = jwt(StringRoleClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            exp: 4_102_444_800,
            permissions: "orders-admin|orders-user",
        });

        let response = custom_roles_app(
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
    async fn jwt_validator_uses_default_principal_claim_order() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(PrincipalClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            preferred_username: Some("preferred-alice"),
            upn: Some("alice@example.com"),
            email: Some("alice@orders.example"),
            exp: 4_102_444_800,
        });

        let response = subject_app(
            Oidc::builder(config.clone())
                .validator(JwtValidator::hs256("secret", &config))
                .build(),
            "alice@example.com",
        )
        .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn jwt_validator_uses_configured_principal_claim() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                principal_claim: Some("email".to_owned()),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(PrincipalClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            preferred_username: Some("preferred-alice"),
            upn: Some("alice@example.com"),
            email: Some("alice@orders.example"),
            exp: 4_102_444_800,
        });

        let response = subject_app(
            Oidc::builder(config.clone())
                .validator(JwtValidator::hs256("secret", &config))
                .build(),
            "alice@orders.example",
        )
        .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn jwt_validator_rejects_missing_configured_principal_claim() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                principal_claim: Some("email".to_owned()),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(TestClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
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
    }

    #[tokio::test]
    async fn jwt_validator_accepts_missing_subject_when_not_required() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(NoSubjectClaims {
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            preferred_username: Some("preferred-alice"),
            exp: 4_102_444_800,
        });

        let response = subject_app(
            Oidc::builder(config.clone())
                .validator(JwtValidator::hs256("secret", &config))
                .build(),
            "preferred-alice",
        )
        .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn jwt_validator_rejects_missing_subject_when_required() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                subject_required: true,
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(NoSubjectClaims {
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            preferred_username: Some("preferred-alice"),
            exp: 4_102_444_800,
        });

        let response = app(Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build())
        .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn jwt_validator_rejects_token_without_principal_claims() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(NoSubjectClaims {
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            preferred_username: None,
            exp: 4_102_444_800,
        });

        let response = app(Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build())
        .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn jwt_validator_uses_client_id_as_default_audience() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            client_id: Some("orders-api".to_owned()),
            ..OidcConfig::default()
        };
        let token = jwt(TestClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            exp: 4_102_444_800,
            groups: vec!["admin"],
            realm_access: RealmAccessClaims { roles: Vec::new() },
        });

        let response = claims_subject_app(
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
    async fn jwt_validator_rejects_wrong_client_id_audience() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            client_id: Some("orders-api".to_owned()),
            ..OidcConfig::default()
        };
        let token = jwt(TestClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "other-api",
            exp: 4_102_444_800,
            groups: vec!["admin"],
            realm_access: RealmAccessClaims { roles: Vec::new() },
        });

        let response = app(Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build())
        .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn jwt_validator_accepts_any_configured_audience() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api,billing-api".to_owned()),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(TestClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "billing-api",
            exp: 4_102_444_800,
            groups: vec!["admin"],
            realm_access: RealmAccessClaims { roles: Vec::new() },
        });

        let response = claims_subject_app(
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
    async fn jwt_validator_rejects_unlisted_configured_audience() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api,billing-api".to_owned()),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(TestClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "inventory-api",
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
    }

    #[tokio::test]
    async fn jwt_validator_skips_audience_validation_when_configured_any() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            client_id: Some("orders-api".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("any".to_owned()),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(TestClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "inventory-api",
            exp: 4_102_444_800,
            groups: vec!["admin"],
            realm_access: RealmAccessClaims { roles: Vec::new() },
        });

        let response = claims_subject_app(
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
    async fn jwt_validator_accepts_configured_token_type() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                token_type: Some("bearer".to_owned()),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(TokenTypeClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            typ: "bearer",
            exp: 4_102_444_800,
        });

        let response = claims_subject_app(
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
    async fn jwt_validator_rejects_wrong_token_type() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                token_type: Some("bearer".to_owned()),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(TokenTypeClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            typ: "id_token",
            exp: 4_102_444_800,
        });

        let response = app(Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build())
        .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn jwt_validator_rejects_missing_token_type() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                token_type: Some("bearer".to_owned()),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(TestClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
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
    }

    #[tokio::test]
    async fn jwt_validator_rejects_unexpected_signature_algorithm() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                signature_algorithm: Some(TokenSignatureAlgorithm::Rs256),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(TestClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
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
    }

    #[test]
    fn config_rejects_unknown_signature_algorithm() {
        let config = Config::builder()
            .add_source(
                MapSource::new("test", 100).with("quarkus.oidc.token.signature-algorithm", "hs256"),
            )
            .build();

        let error = OidcConfig::from_config(&config).expect_err("config should reject hs256");

        assert!(
            error
                .to_string()
                .contains("expected one of `rs256`, `rs384`, `rs512`"),
            "unexpected error: {error}"
        );
    }

    #[tokio::test]
    async fn jwt_validator_accepts_required_claim_values() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                required_claims: HashMap::from([
                    ("org_id".to_owned(), vec!["org_xyz".to_owned()]),
                    (
                        "scope".to_owned(),
                        vec!["read".to_owned(), "write".to_owned()],
                    ),
                ]),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(RequiredClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            org_id: "org_xyz",
            scope: vec!["read", "write", "delete"],
            exp: 4_102_444_800,
        });

        let response = claims_subject_app(
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
    async fn jwt_validator_rejects_missing_required_claim() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                required_claims: HashMap::from([("org_id".to_owned(), vec!["org_xyz".to_owned()])]),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(TestClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
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
    }

    #[tokio::test]
    async fn jwt_validator_rejects_missing_required_claim_value() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                required_claims: HashMap::from([(
                    "scope".to_owned(),
                    vec!["read".to_owned(), "write".to_owned()],
                )]),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(RequiredClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            org_id: "org_xyz",
            scope: vec!["read"],
            exp: 4_102_444_800,
        });

        let response = app(Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build())
        .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn jwt_validator_accepts_expiry_within_lifespan_grace() {
        let now = unix_timestamp().expect("system time should be after epoch");
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                lifespan_grace: Some(5),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(TimeClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            exp: now - 2,
            iat: now - 30,
        });

        let response = claims_subject_app(
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
    async fn jwt_validator_rejects_token_older_than_configured_age() {
        let now = unix_timestamp().expect("system time should be after epoch");
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                age: Some(Duration::from_secs(5)),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(TimeClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            exp: now + 60,
            iat: now - 30,
        });

        let response = app(Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build())
        .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn jwt_validator_rejects_missing_iat_when_token_age_is_configured() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                age: Some(Duration::from_secs(60)),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(TestClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
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
    async fn jwt_validator_skips_issuer_validation_when_configured_any() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: Some("any".to_owned()),
                audience: Some("orders-api".to_owned()),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(TestClaims {
            sub: "alice",
            iss: "https://other-issuer.example/realms/app",
            aud: "orders-api",
            exp: 4_102_444_800,
            groups: vec!["admin"],
            realm_access: RealmAccessClaims { roles: Vec::new() },
        });

        let response = claims_subject_app(
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
    async fn jwks_validator_selects_key_by_kid() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                token_type: None,
                ..OidcTokenConfig::default()
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

    #[tokio::test]
    async fn refreshable_jwks_fetches_when_kid_is_missing() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                token_type: None,
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let refreshed = rotated_jwks();
        let token = jwt_with_kid_and_secret(
            "rotated-key",
            b"rotated",
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
                .validator(JwtValidator::refreshable_jwks(
                    test_jwks(),
                    move || {
                        let refreshed = refreshed.clone();
                        async move { Ok(refreshed) }
                    },
                    &config,
                ))
                .build(),
        )
        .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
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
                    token_type: None,
                    ..OidcTokenConfig::default()
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

    #[test]
    fn tenants_load_named_tenant_paths_from_config() {
        let config = Config::builder()
            .add_source(
                MapSource::new("tenants", 100)
                    .with("quarkus.oidc.tenant-paths", "/api/default")
                    .with("quarkus.oidc.tenant-a.tenant-paths", "/api/a/*")
                    .with("quarkus.oidc.tenant-a.client-id", "tenant-a-client")
                    .with("quarkus.oidc.tenant-b.tenant-enabled", "false")
                    .with("quarkus.oidc.tenant-b.tenant-paths", "/api/b/*"),
            )
            .build();

        assert_eq!(
            named_tenant_names(&config),
            vec!["tenant-a".to_owned(), "tenant-b".to_owned()]
        );

        let tenant_a = OidcConfig::from_config_prefix(&config, "quarkus.oidc.tenant-a").unwrap();
        assert_eq!(tenant_a.tenant_paths, Some("/api/a/*".to_owned()));
        assert_eq!(tenant_a.client_id, Some("tenant-a-client".to_owned()));
    }

    #[tokio::test]
    async fn tenants_select_by_most_specific_tenant_path() {
        let response = tenant_app(
            Tenants::builder()
                .default_tenant(static_tenant("default-token", "default"))
                .tenant(
                    "tenant-a",
                    static_tenant_with_paths("a-token", "tenant-a", "/api/a/*"),
                )
                .tenant(
                    "tenant-b",
                    static_tenant_with_paths("b-token", "tenant-b", "/api/a/special"),
                )
                .build(),
        )
        .oneshot(request("/api/a/special", Some("Bearer b-token")))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn tenants_select_by_header_before_path() {
        let response = tenant_app(
            Tenants::builder()
                .tenant_header(http::HeaderName::from_static("x-oidc-tenant"))
                .tenant(
                    "tenant-a",
                    static_tenant_with_paths("a-token", "tenant-a", "/api/a/*"),
                )
                .tenant(
                    "tenant-b",
                    static_tenant_with_paths("b-token", "tenant-b", "/api/b/*"),
                )
                .build(),
        )
        .oneshot(
            Request::builder()
                .uri("/api/a/resource")
                .header(AUTHORIZATION, "Bearer b-token")
                .header("x-oidc-tenant", "tenant-b")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn tenants_preserve_disabled_tenant_behaviour() {
        let response = tenant_app(
            Tenants::builder()
                .tenant(
                    "tenant-a",
                    Oidc::builder(OidcConfig {
                        tenant_enabled: false,
                        tenant_paths: Some("/api/a/*".to_owned()),
                        ..OidcConfig::default()
                    })
                    .validator(StaticTokenValidator::bearer("a-token", "tenant-a"))
                    .build(),
                )
                .build(),
        )
        .oneshot(request("/api/a/resource", Some("Bearer a-token")))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn authorization_matches_quarkus_default_deny_permissions() {
        let authorization = Authorization::from_config(
            &Config::builder()
                .add_source(
                    MapSource::new("quarkus-default-deny", 100)
                        .with("quarkus.http.auth.permission.default-deny.paths", "/*")
                        .with("quarkus.http.auth.permission.default-deny.policy", "deny")
                        .with(
                            "quarkus.http.auth.permission.permit1.paths",
                            "/permit,/combined",
                        )
                        .with("quarkus.http.auth.permission.permit1.policy", "permit")
                        .with("quarkus.http.auth.permission.permit2.paths", "/permit-get")
                        .with("quarkus.http.auth.permission.permit2.methods", "GET")
                        .with("quarkus.http.auth.permission.permit2.policy", "permit")
                        .with(
                            "quarkus.http.auth.permission.deny1.paths",
                            "/deny,/combined",
                        )
                        .with("quarkus.http.auth.permission.deny1.policy", "deny"),
                )
                .build(),
        )
        .expect("authorization config should load");
        let app = authz_app(authorization);

        let response = app
            .clone()
            .oneshot(request("/unmentioned", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(request("/unmentioned", Some("Bearer test-token")))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = app
            .clone()
            .oneshot(request("/permit", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(request_with_method(http::Method::POST, "/permit", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(request("/permit-get", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(request_with_method(http::Method::POST, "/permit-get", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(request("/combined", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(request("/combined", Some("Bearer test-token")))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn authorization_matches_quarkus_role_policy_permissions() {
        let authorization = Authorization::from_config(
            &Config::builder()
                .add_source(
                    MapSource::new("quarkus-roles", 100)
                        .with("quarkus.http.auth.policy.r1.roles-allowed", "test")
                        .with("quarkus.http.auth.policy.r2.roles-allowed", "admin")
                        .with(
                            "quarkus.http.auth.permission.roles1.paths",
                            "/roles1,/deny,/permit,/combined,/wildcard1/*,/wildcard2*",
                        )
                        .with("quarkus.http.auth.permission.roles1.policy", "r1")
                        .with(
                            "quarkus.http.auth.permission.roles2.paths",
                            "/roles2,/deny,/permit/combined,/wildcard3/*",
                        )
                        .with("quarkus.http.auth.permission.roles2.policy", "r2")
                        .with("quarkus.http.auth.permission.permit1.paths", "/permit")
                        .with("quarkus.http.auth.permission.permit1.policy", "permit")
                        .with(
                            "quarkus.http.auth.permission.deny1.paths",
                            "/deny,/combined",
                        )
                        .with("quarkus.http.auth.permission.deny1.policy", "deny"),
                )
                .build(),
        )
        .expect("authorization config should load");
        let app = authz_app(authorization);

        let response = app
            .clone()
            .oneshot(request("/roles1", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(request("/roles1", Some("Bearer test-token")))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(request("/roles2", Some("Bearer test-token")))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = app
            .clone()
            .oneshot(request("/permit", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(request("/permit", Some("Bearer test-token")))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(request("/deny", Some("Bearer test-token")))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = app
            .clone()
            .oneshot(request("/wildcard1/a", Some("Bearer test-token")))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(request("/wildcard1/a", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(request("/wildcard2", Some("Bearer test-token")))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(request("/wildcard3XXX", None))
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

    fn authz_app(authorization: Authorization) -> Router {
        Router::new().fallback(|| async { "ok" }).layer(
            Oidc::builder(OidcConfig::default())
                .validator(StaticTokenValidator::principal(
                    "test-token",
                    Principal::with_groups("test", ["test"]),
                ))
                .authorization(authorization)
                .build()
                .layer(),
        )
    }

    fn tenant_app(tenants: Tenants) -> Router {
        Router::new()
            .fallback(|Extension(principal): Extension<Principal>| async move {
                principal.subject().to_owned()
            })
            .layer(tenants.layer())
    }

    fn static_tenant(token: &str, subject: &str) -> Oidc {
        Oidc::builder(OidcConfig::default())
            .validator(StaticTokenValidator::bearer(token, subject))
            .build()
    }

    fn static_tenant_with_paths(token: &str, subject: &str, paths: &str) -> Oidc {
        Oidc::builder(OidcConfig {
            tenant_paths: Some(paths.to_owned()),
            ..OidcConfig::default()
        })
        .validator(StaticTokenValidator::bearer(token, subject))
        .build()
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

    fn claims_subject_app(oidc: Oidc) -> Router {
        Router::new()
            .route(
                "/protected",
                get(|Extension(principal): Extension<Principal>| async move {
                    assert_eq!(principal.subject(), "alice");
                    "ok"
                }),
            )
            .layer(oidc.layer())
    }

    fn subject_app(oidc: Oidc, expected_subject: &'static str) -> Router {
        Router::new()
            .route(
                "/protected",
                get(
                    move |Extension(principal): Extension<Principal>| async move {
                        assert_eq!(principal.subject(), expected_subject);
                        "ok"
                    },
                ),
            )
            .layer(oidc.layer())
    }

    fn custom_roles_app(oidc: Oidc) -> Router {
        Router::new()
            .route(
                "/protected",
                get(|Extension(principal): Extension<Principal>| async move {
                    assert_eq!(
                        principal.groups().collect::<Vec<_>>(),
                        vec!["orders-admin", "orders-user"]
                    );
                    "ok"
                }),
            )
            .layer(oidc.layer())
    }

    fn request(uri: &str, authorization: Option<&str>) -> Request<Body> {
        request_with_method(http::Method::GET, uri, authorization)
    }

    fn request_with_method(
        method: http::Method,
        uri: &str,
        authorization: Option<&str>,
    ) -> Request<Body> {
        let mut builder = Request::builder().uri(uri);
        builder = builder.method(method);
        if let Some(authorization) = authorization {
            builder = builder.header(AUTHORIZATION, authorization);
        }
        builder
            .body(Body::empty())
            .expect("request should be valid")
    }

    fn request_with_header(uri: &str, header_name: &str, header_value: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .header(header_name, header_value)
            .body(Body::empty())
            .expect("request should be valid")
    }

    fn jwt(claims: impl Serialize) -> String {
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"secret"),
        )
        .expect("test token should encode")
    }

    fn jwt_with_kid(kid: &str, claims: TestClaims<'_>) -> String {
        jwt_with_kid_and_secret(kid, b"secret", claims)
    }

    fn jwt_with_kid_and_secret(kid: &str, secret: &[u8], claims: impl Serialize) -> String {
        let mut header = Header::default();
        header.kid = Some(kid.to_owned());

        encode(&header, &claims, &EncodingKey::from_secret(secret))
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

    fn rotated_jwks() -> JwkSet {
        serde_json::from_value(json!({
            "keys": [
                {
                    "kty": "oct",
                    "alg": "HS256",
                    "kid": "rotated-key",
                    "k": "cm90YXRlZA"
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
    struct PrincipalClaims<'a> {
        sub: &'a str,
        iss: &'a str,
        aud: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        preferred_username: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        upn: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        email: Option<&'a str>,
        exp: u64,
    }

    #[derive(Serialize)]
    struct NoSubjectClaims<'a> {
        iss: &'a str,
        aud: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        preferred_username: Option<&'a str>,
        exp: u64,
    }

    #[derive(Serialize)]
    struct TokenTypeClaims<'a> {
        sub: &'a str,
        iss: &'a str,
        aud: &'a str,
        typ: &'a str,
        exp: u64,
    }

    #[derive(Serialize)]
    struct RequiredClaims<'a> {
        sub: &'a str,
        iss: &'a str,
        aud: &'a str,
        org_id: &'a str,
        scope: Vec<&'a str>,
        exp: u64,
    }

    #[derive(Serialize)]
    struct TimeClaims<'a> {
        sub: &'a str,
        iss: &'a str,
        aud: &'a str,
        exp: u64,
        iat: u64,
    }

    #[derive(Serialize)]
    struct RealmAccessClaims<'a> {
        roles: Vec<&'a str>,
    }

    #[derive(Serialize)]
    struct CustomRoleClaims<'a> {
        sub: &'a str,
        iss: &'a str,
        aud: &'a str,
        exp: u64,
        resource_access: ResourceAccessClaims<'a>,
    }

    #[derive(Serialize)]
    struct StringRoleClaims<'a> {
        sub: &'a str,
        iss: &'a str,
        aud: &'a str,
        exp: u64,
        permissions: &'a str,
    }

    #[derive(Serialize)]
    struct ResourceAccessClaims<'a> {
        orders: ResourceRolesClaims<'a>,
    }

    #[derive(Serialize)]
    struct ResourceRolesClaims<'a> {
        roles: Vec<&'a str>,
    }
}

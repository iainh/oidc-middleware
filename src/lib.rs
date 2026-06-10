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
//! - `quarkus.oidc.provider` maps to [`OidcConfig::provider`].
//! - `quarkus.oidc.client-id` maps to [`OidcConfig::client_id`].
//! - `quarkus.oidc.application-type` maps to [`OidcConfig::application_type`].
//! - `quarkus.oidc.enabled=false` disables authentication for the layer.
//! - `quarkus.oidc.tenant-enabled=false` rejects requests as tenant-disabled.

pub use oidc_middleware_macros::{authenticated, roles_allowed};

mod claims;
mod path;
mod token;

use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::response::{IntoResponse, Response};
use claims::{apply_role_mappings, claim_path_value, deserialize_audience, extract_roles};
use http::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use http::request::Parts;
use http::{HeaderValue, Request, StatusCode};
use jsonwebtoken::jwk::{JwkSet, KeyAlgorithm};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use mp_config::{Config, ConfigProperties};
use path::{normalize_permission_paths, path_match_score};
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
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
use token::{
    bearer_token, unverified_token_from_request, unverified_token_issuer,
    validate_authorization_scheme,
};
use tower_layer::Layer;
use tower_service::Service;

const DEFAULT_ROLE_CLAIM_PATH: &str = "groups,realm_access.roles";

/// Result type returned by token validators.
pub type Result<T> = std::result::Result<T, Error>;

/// Boxed error type used by extension points.
pub type BoxError = Box<dyn StdError + Send + Sync>;
type ValidationFuture = Pin<Box<dyn Future<Output = Result<Principal>> + Send>>;
/// Future returned by [`TokenIntrospector`].
pub type IntrospectionFuture =
    Pin<Box<dyn Future<Output = std::result::Result<IntrospectionResponse, BoxError>> + Send>>;
/// Future returned by [`UserInfoProvider`].
pub type UserInfoFuture =
    Pin<Box<dyn Future<Output = std::result::Result<UserInfoResponse, BoxError>> + Send>>;
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
    /// Resolve tenants by the bearer token issuer claim.
    #[config(default = "false")]
    pub resolve_tenants_with_issuer: bool,
    /// Base URL of the OpenID Connect provider or realm.
    pub auth_server_url: Option<String>,
    /// Well-known OpenID Connect provider identifier.
    pub provider: Option<WellKnownProvider>,
    /// Timeout for establishing HTTP connections to the provider.
    #[config(default = "10s")]
    pub connection_timeout: Duration,
    /// Enables OIDC provider metadata discovery.
    #[config(default = "true")]
    pub discovery_enabled: bool,
    /// Relative or absolute OIDC provider metadata discovery path.
    #[config(default = ".well-known/openid-configuration")]
    pub discovery_path: String,
    /// Relative or absolute JWKS endpoint used when discovery is disabled.
    pub jwks_path: Option<String>,
    /// Relative or absolute authorization endpoint path.
    pub authorization_path: Option<String>,
    /// Relative or absolute token endpoint path.
    pub token_path: Option<String>,
    /// Relative or absolute dynamic client registration endpoint path.
    pub registration_path: Option<String>,
    /// Relative or absolute token revocation endpoint path.
    pub revoke_path: Option<String>,
    /// Relative or absolute token introspection endpoint path.
    pub introspection_path: Option<String>,
    /// Relative or absolute user info endpoint path.
    pub user_info_path: Option<String>,
    /// Relative or absolute end-session endpoint path.
    pub end_session_path: Option<String>,
    /// Client identifier expected by the provider.
    pub client_id: Option<String>,
    /// Human-readable client name.
    pub client_name: Option<String>,
    /// Stable tenant identifier used for tenant selection.
    pub tenant_id: Option<String>,
    /// Paths that should select this tenant.
    pub tenant_paths: Option<String>,
    /// Public key used for local JWT verification without provider discovery.
    pub public_key: Option<String>,
    /// Quarkus-style application type.
    #[config(default)]
    pub application_type: ApplicationType,
    /// Client credential settings used for provider calls.
    #[config(nested)]
    pub credentials: OidcCredentialsConfig,
    /// Token introspection endpoint-specific credentials.
    #[config(nested)]
    pub introspection_credentials: OidcIntrospectionCredentialsConfig,
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
            resolve_tenants_with_issuer: false,
            auth_server_url: None,
            provider: None,
            connection_timeout: Duration::from_secs(10),
            discovery_enabled: true,
            discovery_path: ".well-known/openid-configuration".to_owned(),
            jwks_path: None,
            authorization_path: None,
            token_path: None,
            registration_path: None,
            revoke_path: None,
            introspection_path: None,
            user_info_path: None,
            end_session_path: None,
            client_id: None,
            client_name: None,
            tenant_id: None,
            tenant_paths: None,
            public_key: None,
            application_type: ApplicationType::Service,
            credentials: OidcCredentialsConfig::default(),
            introspection_credentials: OidcIntrospectionCredentialsConfig::default(),
            token: OidcTokenConfig::default(),
            roles: OidcRolesConfig::default(),
        }
    }
}

/// Client credential configuration loaded from `quarkus.oidc.credentials.*`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OidcCredentialsConfig {
    /// Client secret used with `client-id` for provider authentication.
    pub secret: Option<String>,
    /// Client-secret authentication method.
    pub client_secret: OidcClientSecretConfig,
}

impl ConfigProperties for OidcCredentialsConfig {
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
            secret: load_optional_non_empty_string(config, &key("secret"))?,
            client_secret: OidcClientSecretConfig::from_config_prefix(
                config,
                &key("client-secret"),
            )?,
        })
    }
}

impl OidcCredentialsConfig {
    fn effective_client_secret(&self) -> Option<&str> {
        self.secret
            .as_deref()
            .or(self.client_secret.value.as_deref())
    }
}

/// Client-secret authentication settings.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OidcClientSecretConfig {
    /// Client secret value used when `credentials.secret` is not configured.
    pub value: Option<String>,
    /// How the client secret is sent to the provider.
    pub method: ClientSecretMethod,
}

impl ConfigProperties for OidcClientSecretConfig {
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
            value: load_optional_non_empty_string(config, &key("value"))?,
            method: config.get_optional(&key("method"))?.unwrap_or_default(),
        })
    }
}

/// Client-secret authentication method.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ClientSecretMethod {
    /// Send client credentials with HTTP Basic authentication.
    #[default]
    Basic,
    /// Send client credentials as form parameters.
    Post,
    /// Send client credentials as query parameters.
    Query,
}

impl mp_config::FromConfigValue for ClientSecretMethod {
    fn from_config_value(value: &str) -> std::result::Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "basic" => Ok(Self::Basic),
            "post" => Ok(Self::Post),
            "query" => Ok(Self::Query),
            other => Err(format!(
                "expected one of `basic`, `post`, or `query`, got `{other}`"
            )),
        }
    }
}

/// Quarkus-compatible well-known OpenID Connect provider identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WellKnownProvider {
    /// Apple.
    Apple,
    /// Discord.
    Discord,
    /// Facebook.
    Facebook,
    /// GitHub.
    Github,
    /// Google.
    Google,
    /// LinkedIn.
    Linkedin,
    /// Mastodon.
    Mastodon,
    /// Microsoft.
    Microsoft,
    /// Slack.
    Slack,
    /// Spotify.
    Spotify,
    /// Strava.
    Strava,
    /// Twitch.
    Twitch,
    /// Twitter.
    Twitter,
    /// X.
    X,
}

impl mp_config::FromConfigValue for WellKnownProvider {
    fn from_config_value(value: &str) -> std::result::Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "apple" => Ok(Self::Apple),
            "discord" => Ok(Self::Discord),
            "facebook" => Ok(Self::Facebook),
            "github" => Ok(Self::Github),
            "google" => Ok(Self::Google),
            "linkedin" => Ok(Self::Linkedin),
            "mastodon" => Ok(Self::Mastodon),
            "microsoft" => Ok(Self::Microsoft),
            "slack" => Ok(Self::Slack),
            "spotify" => Ok(Self::Spotify),
            "strava" => Ok(Self::Strava),
            "twitch" => Ok(Self::Twitch),
            "twitter" => Ok(Self::Twitter),
            "x" => Ok(Self::X),
            other => Err(format!(
                "expected one of `apple`, `discord`, `facebook`, `github`, `google`, `linkedin`, `mastodon`, `microsoft`, `slack`, `spotify`, `strava`, `twitch`, `twitter`, or `x`, got `{other}`"
            )),
        }
    }
}

impl WellKnownProvider {
    fn auth_server_url(self) -> Option<&'static str> {
        match self {
            Self::Google => Some("https://accounts.google.com"),
            _ => None,
        }
    }

    fn as_config_value(self) -> &'static str {
        match self {
            Self::Apple => "apple",
            Self::Discord => "discord",
            Self::Facebook => "facebook",
            Self::Github => "github",
            Self::Google => "google",
            Self::Linkedin => "linkedin",
            Self::Mastodon => "mastodon",
            Self::Microsoft => "microsoft",
            Self::Slack => "slack",
            Self::Spotify => "spotify",
            Self::Strava => "strava",
            Self::Twitch => "twitch",
            Self::Twitter => "twitter",
            Self::X => "x",
        }
    }
}

/// Introspection endpoint-specific credentials.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcIntrospectionCredentialsConfig {
    /// User name used for introspection endpoint Basic authentication.
    pub name: Option<String>,
    /// Secret used for introspection endpoint Basic authentication.
    pub secret: Option<String>,
    /// Include the configured OIDC client id in the introspection form body.
    pub include_client_id: bool,
}

impl Default for OidcIntrospectionCredentialsConfig {
    fn default() -> Self {
        Self {
            name: None,
            secret: None,
            include_client_id: true,
        }
    }
}

impl ConfigProperties for OidcIntrospectionCredentialsConfig {
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
            name: load_optional_non_empty_string(config, &key("name"))?,
            secret: load_optional_non_empty_string(config, &key("secret"))?,
            include_client_id: config
                .get_optional(&key("include-client-id"))?
                .unwrap_or(true),
        })
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
    /// Private key location used to decrypt encrypted JWT tokens.
    pub decryption_key_location: Option<String>,
    /// Decrypt encrypted ID tokens.
    pub decrypt_id_token: Option<bool>,
    /// Decrypt encrypted access tokens.
    pub decrypt_access_token: bool,
    /// Require the token to include a `sub` claim.
    pub subject_required: bool,
    /// Require the token to include an `iat` claim.
    pub issued_at_required: bool,
    /// Required claims and their expected string values.
    pub required_claims: HashMap<String, Vec<String>>,
    /// Claim used as the authenticated principal name.
    pub principal_claim: Option<String>,
    /// HTTP header that contains the bearer token.
    ///
    /// `Authorization` uses the configured authorization scheme. Other
    /// headers carry the raw token value.
    pub header: String,
    /// HTTP Authorization header scheme.
    pub authorization_scheme: String,
    /// Grace period applied to token expiry and issued-at checks.
    pub lifespan_grace: Option<u64>,
    /// Maximum age allowed since the token `iat` claim.
    pub age: Option<Duration>,
    /// Minimum interval between forced JWKS refreshes after an unknown `kid`.
    pub forced_jwk_refresh_interval: Duration,
    /// Allow remote introspection of JWT tokens when no matching JWK is available.
    pub allow_jwt_introspection: bool,
    /// Require JWT tokens to be validated by remote introspection only.
    pub require_jwt_introspection_only: bool,
    /// Allow remote introspection of opaque bearer tokens.
    pub allow_opaque_token_introspection: bool,
    /// Verify opaque access tokens by calling the UserInfo endpoint.
    pub verify_access_token_with_user_info: bool,
    /// Token binding validation configuration.
    pub binding: OidcTokenBindingConfig,
}

impl Default for OidcTokenConfig {
    fn default() -> Self {
        Self {
            issuer: None,
            audience: None,
            token_type: None,
            signature_algorithm: None,
            decryption_key_location: None,
            decrypt_id_token: None,
            decrypt_access_token: false,
            subject_required: false,
            issued_at_required: true,
            required_claims: HashMap::new(),
            principal_claim: None,
            header: "Authorization".to_owned(),
            authorization_scheme: "Bearer".to_owned(),
            lifespan_grace: None,
            age: None,
            forced_jwk_refresh_interval: Duration::from_secs(600),
            allow_jwt_introspection: true,
            require_jwt_introspection_only: false,
            allow_opaque_token_introspection: true,
            verify_access_token_with_user_info: false,
            binding: OidcTokenBindingConfig::default(),
        }
    }
}

/// Token binding validation configuration loaded from `quarkus.oidc.token.binding.*`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OidcTokenBindingConfig {
    /// Require an access-token `cnf` claim matching the client certificate.
    pub certificate: bool,
}

impl ConfigProperties for OidcTokenBindingConfig {
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
            certificate: config
                .get_optional(&key("certificate"))?
                .unwrap_or_default(),
        })
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

        let token_header_key = key("header");
        let header = config
            .get_optional::<String>(&token_header_key)?
            .unwrap_or_else(|| "Authorization".to_owned());
        http::HeaderName::from_str(&header).map_err(|error| {
            mp_config::ConfigError::Conversion {
                name: token_header_key.clone(),
                value: header.clone(),
                message: error.to_string(),
            }
        })?;
        let authorization_scheme_key = key("authorization-scheme");
        let authorization_scheme = config
            .get_optional(&authorization_scheme_key)?
            .unwrap_or_else(|| "Bearer".to_owned());
        validate_authorization_scheme(&authorization_scheme_key, &authorization_scheme)?;

        let audience_key = key("audience");
        let audience = config.get_optional::<String>(&audience_key)?;
        if let Some(value) = &audience {
            if split_csv(value).is_empty() {
                return Err(mp_config::ConfigError::Conversion {
                    name: audience_key,
                    value: value.clone(),
                    message: "token audience must include at least one audience".to_owned(),
                });
            }
        }

        let token_type = load_optional_non_empty_string(config, &key("token-type"))?;
        let principal_claim = load_optional_non_empty_string(config, &key("principal-claim"))?;

        Ok(Self {
            issuer: config.get_optional(&key("issuer"))?,
            audience,
            token_type,
            signature_algorithm: config.get_optional(&key("signature-algorithm"))?,
            decryption_key_location: load_optional_non_empty_string(
                config,
                &key("decryption-key-location"),
            )?,
            decrypt_id_token: config.get_optional(&key("decrypt-id-token"))?,
            decrypt_access_token: config
                .get_optional(&key("decrypt-access-token"))?
                .unwrap_or_default(),
            subject_required: config
                .get_optional(&key("subject-required"))?
                .unwrap_or_default(),
            issued_at_required: config
                .get_optional(&key("issued-at-required"))?
                .unwrap_or(true),
            required_claims: load_required_claims(config, &key("required-claims"))?,
            principal_claim,
            header,
            authorization_scheme,
            lifespan_grace: config.get_optional(&key("lifespan-grace"))?,
            age: config.get_optional(&key("age"))?,
            forced_jwk_refresh_interval: config
                .get_optional(&key("forced-jwk-refresh-interval"))?
                .unwrap_or_else(|| Duration::from_secs(600)),
            allow_jwt_introspection: config
                .get_optional(&key("allow-jwt-introspection"))?
                .unwrap_or(true),
            require_jwt_introspection_only: config
                .get_optional(&key("require-jwt-introspection-only"))?
                .unwrap_or_default(),
            allow_opaque_token_introspection: config
                .get_optional(&key("allow-opaque-token-introspection"))?
                .unwrap_or(true),
            verify_access_token_with_user_info: config
                .get_optional(&key("verify-access-token-with-user-info"))?
                .unwrap_or_default(),
            binding: OidcTokenBindingConfig::from_config_prefix(config, &key("binding"))?,
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

/// Token source used for role extraction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum RolesSource {
    /// Extract roles from the access token.
    #[default]
    AccessToken,
    /// Extract roles from the ID token.
    IdToken,
    /// Extract roles from the UserInfo response.
    UserInfo,
}

impl mp_config::FromConfigValue for RolesSource {
    fn from_config_value(value: &str) -> std::result::Result<Self, String> {
        match value.to_ascii_lowercase().as_str() {
            "accesstoken" | "access-token" => Ok(Self::AccessToken),
            "idtoken" | "id-token" => Ok(Self::IdToken),
            "userinfo" | "user-info" => Ok(Self::UserInfo),
            other => Err(format!(
                "expected one of `accesstoken`, `idtoken`, or `userinfo`, got `{other}`"
            )),
        }
    }
}

/// Role extraction configuration loaded from `quarkus.oidc.roles.*`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcRolesConfig {
    /// Token or response source used to extract roles.
    pub source: RolesSource,
    /// Token claim paths used to extract role names.
    ///
    /// The default covers standard `groups` claims and Keycloak realm roles.
    pub role_claim_path: String,
    /// Separator used when a role claim is a string containing multiple roles.
    pub role_claim_separator: String,
}

impl Default for OidcRolesConfig {
    fn default() -> Self {
        Self {
            source: RolesSource::AccessToken,
            role_claim_path: DEFAULT_ROLE_CLAIM_PATH.to_owned(),
            role_claim_separator: " ".to_owned(),
        }
    }
}

impl ConfigProperties for OidcRolesConfig {
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

        let role_claim_path_key = key("role-claim-path");
        let role_claim_path = config
            .get_optional::<String>(&role_claim_path_key)?
            .unwrap_or_else(|| DEFAULT_ROLE_CLAIM_PATH.to_owned());
        if split_csv(&role_claim_path).is_empty() {
            return Err(mp_config::ConfigError::Conversion {
                name: role_claim_path_key,
                value: role_claim_path,
                message: "role-claim-path must include at least one claim path".to_owned(),
            });
        }

        Ok(Self {
            source: config.get_optional(&key("source"))?.unwrap_or_default(),
            role_claim_path,
            role_claim_separator: config
                .get_optional(&key("role-claim-separator"))?
                .unwrap_or_else(|| " ".to_owned()),
        })
    }
}

impl OidcRolesConfig {
    fn claim_paths(&self) -> Vec<String> {
        split_csv(&self.role_claim_path)
    }
}

fn role_claim_paths(config: &OidcConfig) -> Vec<String> {
    let mut paths = config.roles.claim_paths();
    if config.roles.role_claim_path == DEFAULT_ROLE_CLAIM_PATH {
        if let Some(client_id) = config
            .client_id
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            paths.push(format!(r#"resource_access."{client_id}".roles"#));
        }
    }
    paths
}

fn role_claim_paths_for_source(config: &OidcConfig, source: RolesSource) -> Vec<String> {
    if config.roles.source == source {
        role_claim_paths(config)
    } else {
        Vec::new()
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
        match value.to_ascii_lowercase().as_str() {
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
        self.challenge_with_scheme("Bearer")
    }

    fn challenge_with_scheme(&self, scheme: &str) -> HeaderValue {
        let value = match self {
            Self::MissingBearerToken | Self::TenantDisabled | Self::Forbidden => scheme.to_owned(),
            Self::InvalidAuthorizationHeader => format!(r#"{scheme} error="invalid_request""#),
            Self::TokenRejected(_) => format!(r#"{scheme} error="invalid_token""#),
        };
        HeaderValue::from_str(&value).unwrap_or_else(|_| self.challenge())
    }

    fn into_response_with_scheme(self, scheme: &str) -> Response {
        let status = self.status();
        let mut response = status.into_response();
        if status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, self.challenge_with_scheme(scheme));
        }
        response
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
    /// Loading `mp-config` backed OIDC configuration failed.
    Config(mp_config::ConfigError),
    /// Provider discovery requires `quarkus.oidc.auth-server-url`.
    MissingAuthServerUrl,
    /// The configured well-known provider has no built-in issuer URL yet.
    UnsupportedWellKnownProvider(WellKnownProvider),
    /// Direct JWKS loading requires `quarkus.oidc.jwks-path`.
    MissingJwksPath,
    /// Remote token introspection requires a configured or discovered endpoint.
    MissingIntrospectionEndpoint,
    /// UserInfo token validation requires a configured or discovered endpoint.
    MissingUserInfoEndpoint,
    /// The configured public key could not be parsed.
    InvalidPublicKey(BoxError),
    /// A configured provider or metadata URL could not be parsed.
    InvalidUrl { url: String, message: String },
    /// Fetching provider metadata or keys failed.
    Http(reqwest::Error),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(source) => write!(f, "OIDC configuration failed: {source}"),
            Self::MissingAuthServerUrl => write!(
                f,
                "OIDC provider discovery requires `quarkus.oidc.auth-server-url`"
            ),
            Self::UnsupportedWellKnownProvider(provider) => write!(
                f,
                "well-known OIDC provider `{}` requires `quarkus.oidc.auth-server-url` until its issuer URL is built in",
                provider.as_config_value()
            ),
            Self::MissingJwksPath => write!(
                f,
                "OIDC JWKS loading requires `quarkus.oidc.jwks-path` when discovery is disabled"
            ),
            Self::MissingIntrospectionEndpoint => write!(
                f,
                "OIDC token introspection requires an introspection endpoint"
            ),
            Self::MissingUserInfoEndpoint => {
                write!(f, "OIDC UserInfo validation requires a UserInfo endpoint")
            }
            Self::InvalidPublicKey(source) => write!(f, "invalid OIDC public key: {source}"),
            Self::InvalidUrl { url, message } => write!(f, "invalid URL `{url}`: {message}"),
            Self::Http(source) => write!(f, "OIDC provider request failed: {source}"),
        }
    }
}

impl StdError for BuildError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Config(source) => Some(source),
            Self::InvalidPublicKey(source) => Some(source.as_ref()),
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

impl From<mp_config::ConfigError> for BuildError {
    fn from(source: mp_config::ConfigError) -> Self {
        Self::Config(source)
    }
}

/// OpenID Provider metadata used by discovery.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ProviderMetadata {
    /// Canonical issuer returned by the provider.
    pub issuer: Option<String>,
    /// JSON Web Key Set URL returned by the provider.
    pub jwks_uri: String,
    /// OAuth2 authorization endpoint returned by the provider.
    pub authorization_endpoint: Option<String>,
    /// OAuth2 token endpoint returned by the provider.
    pub token_endpoint: Option<String>,
    /// Dynamic client registration endpoint returned by the provider.
    pub registration_endpoint: Option<String>,
    /// OAuth2 token revocation endpoint returned by the provider.
    pub revocation_endpoint: Option<String>,
    /// OAuth2 token introspection endpoint returned by the provider.
    pub introspection_endpoint: Option<String>,
    /// OIDC user info endpoint returned by the provider.
    pub userinfo_endpoint: Option<String>,
    /// OIDC end-session endpoint returned by the provider.
    pub end_session_endpoint: Option<String>,
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
    role_mappings: Arc<HashMap<String, Vec<String>>>,
}

impl Authorization {
    /// Loads Quarkus-style HTTP authorization configuration.
    pub fn from_config(config: &Config) -> mp_config::Result<Self> {
        let role_policies = load_role_policies(config)?;
        let role_mappings = load_role_mappings(config, "quarkus.http.auth.roles-mapping")?;
        let root_path = config
            .get_optional::<String>("quarkus.http.root-path")?
            .unwrap_or_else(|| "/".to_owned());
        let mut permissions = Vec::new();

        for name in permission_names(config) {
            let prefix = format!("quarkus.http.auth.permission.{name}");
            if !config
                .get_optional::<bool>(&format!("{prefix}.enabled"))?
                .unwrap_or(true)
            {
                continue;
            }

            let paths_key = format!("{prefix}.paths");
            let paths_value = config.get::<String>(&paths_key)?;
            let paths = split_csv(&paths_value);
            if paths.is_empty() {
                return Err(mp_config::ConfigError::Conversion {
                    name: paths_key,
                    value: paths_value,
                    message: "permission paths must include at least one path".to_owned(),
                });
            }
            let paths = normalize_permission_paths(paths, &root_path);
            let methods_key = format!("{prefix}.methods");
            let methods = config
                .get_optional::<String>(&methods_key)?
                .map(|methods| parse_configured_http_methods(&methods_key, &methods))
                .transpose()?
                .unwrap_or_default();
            let policy_key = format!("{prefix}.policy");
            let policy_name = config.get::<String>(&policy_key)?;
            let policy = policy_from_config(&policy_key, &policy_name, &role_policies)?;
            let shared = config
                .get_optional::<bool>(&format!("{prefix}.shared"))?
                .unwrap_or_default();

            permissions.push(HttpPermission {
                paths,
                methods,
                policy,
                shared,
            });
        }

        Ok(Self {
            permissions: Arc::from(permissions),
            role_mappings: Arc::new(role_mappings),
        })
    }

    fn requirement(&self, method: &http::Method, path: &str) -> AuthRequirement {
        let path_matches = self
            .permissions
            .iter()
            .filter_map(|permission| {
                permission
                    .path_match_score(path)
                    .map(|path_score| PermissionMatch {
                        path_score,
                        method_score: permission.method_match_score(method),
                        permission,
                    })
            })
            .collect::<Vec<_>>();

        if path_matches.is_empty() {
            return AuthRequirement::Permit;
        }

        let shared_policies = path_matches
            .iter()
            .filter(|permission_match| {
                permission_match.permission.shared && permission_match.method_score.is_some()
            })
            .map(|permission_match| &permission_match.permission.policy)
            .collect::<Vec<_>>();
        let unshared_matches = path_matches
            .iter()
            .filter(|permission_match| !permission_match.permission.shared)
            .collect::<Vec<_>>();

        let Some(max_path_score) = unshared_matches
            .iter()
            .map(|permission_match| permission_match.path_score)
            .max()
        else {
            if shared_policies.is_empty() {
                return AuthRequirement::Deny;
            }
            return policies_requirement(shared_policies, &self.role_mappings);
        };

        let unshared_matches = unshared_matches
            .into_iter()
            .filter(|permission_match| permission_match.path_score == max_path_score)
            .collect::<Vec<_>>();
        let Some(max_method_score) = unshared_matches
            .iter()
            .filter_map(|permission_match| permission_match.method_score)
            .max()
        else {
            return AuthRequirement::Deny;
        };

        let mut policies = shared_policies;
        policies.extend(
            unshared_matches
                .into_iter()
                .filter(|permission_match| permission_match.method_score == Some(max_method_score))
                .map(|permission_match| &permission_match.permission.policy),
        );

        policies_requirement(policies, &self.role_mappings)
    }
}

struct PermissionMatch<'a> {
    path_score: usize,
    method_score: Option<usize>,
    permission: &'a HttpPermission,
}

fn policies_requirement(
    policies: Vec<&HttpPolicy>,
    global_role_mappings: &HashMap<String, Vec<String>>,
) -> AuthRequirement {
    if policies.is_empty() {
        return AuthRequirement::Permit;
    }

    if policies
        .iter()
        .any(|policy| matches!(policy, HttpPolicy::Deny))
    {
        return AuthRequirement::Deny;
    }

    let mut role_sets = Vec::new();
    let mut role_mappings = global_role_mappings.clone();
    let mut authenticated = false;
    for policy in policies {
        match policy {
            HttpPolicy::Authenticated => authenticated = true,
            HttpPolicy::Roles(role_policy) => {
                authenticated = true;
                if !role_policy.roles_allowed.is_empty()
                    && !role_policy
                        .roles_allowed
                        .iter()
                        .any(|role| role.as_str() == "**")
                {
                    let mut roles = role_policy.roles_allowed.clone();
                    roles.sort();
                    roles.dedup();
                    role_sets.push(roles);
                }
                merge_role_mappings(&mut role_mappings, &role_policy.role_mappings);
            }
            HttpPolicy::Permit | HttpPolicy::Deny => {}
        }
    }

    if !role_sets.is_empty() {
        return AuthRequirement::Roles {
            role_sets,
            role_mappings,
        };
    }

    if authenticated {
        AuthRequirement::Authenticated(role_mappings)
    } else {
        AuthRequirement::Permit
    }
}

fn merge_role_mappings(
    target: &mut HashMap<String, Vec<String>>,
    source: &HashMap<String, Vec<String>>,
) {
    for (role, mapped_roles) in source {
        target
            .entry(role.clone())
            .or_default()
            .extend(mapped_roles.iter().cloned());
    }
}

fn parse_configured_http_methods(
    property_name: &str,
    value: &str,
) -> mp_config::Result<Vec<String>> {
    let methods = parse_http_methods(property_name, value)?;
    if methods.is_empty() {
        return Err(mp_config::ConfigError::Conversion {
            name: property_name.to_owned(),
            value: value.to_owned(),
            message: "permission methods must include at least one method when configured"
                .to_owned(),
        });
    }

    Ok(methods)
}

fn parse_http_methods(property_name: &str, value: &str) -> mp_config::Result<Vec<String>> {
    split_csv(value)
        .into_iter()
        .map(|method| {
            let method = method.to_ascii_uppercase();
            http::Method::from_bytes(method.as_bytes())
                .map(|_| method.clone())
                .map_err(|error| mp_config::ConfigError::Conversion {
                    name: property_name.to_owned(),
                    value: method,
                    message: error.to_string(),
                })
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HttpPermission {
    paths: Vec<String>,
    methods: Vec<String>,
    policy: HttpPolicy,
    shared: bool,
}

impl HttpPermission {
    fn path_match_score(&self, request_path: &str) -> Option<usize> {
        self.paths
            .iter()
            .filter_map(|path| path_match_score(path, request_path))
            .max()
    }

    fn method_match_score(&self, method: &http::Method) -> Option<usize> {
        if self.methods.is_empty() {
            return Some(0);
        }

        if !self.methods.is_empty()
            && !self
                .methods
                .iter()
                .any(|configured| configured == method.as_str())
        {
            return None;
        }

        Some(1)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum HttpPolicy {
    Permit,
    Deny,
    Authenticated,
    Roles(RolePolicy),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct RolePolicy {
    roles_allowed: Vec<String>,
    role_mappings: HashMap<String, Vec<String>>,
}

enum AuthRequirement {
    Permit,
    Deny,
    Authenticated(HashMap<String, Vec<String>>),
    Roles {
        role_sets: Vec<Vec<String>>,
        role_mappings: HashMap<String, Vec<String>>,
    },
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
    issued_at_required: bool,
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
            role_claim_paths: Arc::from(role_claim_paths_for_source(
                config,
                RolesSource::AccessToken,
            )),
            role_claim_separator: Arc::from(config.roles.role_claim_separator.clone()),
            token_type: config.token.token_type.clone().map(Arc::from),
            subject_required: config.token.subject_required,
            issued_at_required: config.token.issued_at_required,
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
            role_claim_paths: Arc::from(role_claim_paths_for_source(
                config,
                RolesSource::AccessToken,
            )),
            role_claim_separator: Arc::from(config.roles.role_claim_separator.clone()),
            token_type: config.token.token_type.clone().map(Arc::from),
            subject_required: config.token.subject_required,
            issued_at_required: config.token.issued_at_required,
            required_claims: Arc::new(config.token.required_claims.clone()),
            principal_claim: config.token.principal_claim.clone().map(Arc::from),
            token_age: config.token.age,
        }
    }

    /// Builds a JWT validator backed by `quarkus.oidc.public-key`.
    pub fn public_key(public_key: &str, config: &OidcConfig) -> BuildResult<Self> {
        let mut validation = Validation::new(public_key_algorithm(config));
        apply_validation_config(&mut validation, config);
        apply_signature_algorithm_config(&mut validation, config);
        let key = public_decoding_key(public_key, &validation)?;

        Ok(Self {
            keys: JwtKeys::Single(Arc::new(key)),
            validation,
            role_claim_paths: Arc::from(role_claim_paths_for_source(
                config,
                RolesSource::AccessToken,
            )),
            role_claim_separator: Arc::from(config.roles.role_claim_separator.clone()),
            token_type: config.token.token_type.clone().map(Arc::from),
            subject_required: config.token.subject_required,
            issued_at_required: config.token.issued_at_required,
            required_claims: Arc::new(config.token.required_claims.clone()),
            principal_claim: config.token.principal_claim.clone().map(Arc::from),
            token_age: config.token.age,
        })
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
                last_forced_refresh: Arc::new(Mutex::new(None)),
                forced_refresh_interval: config.token.forced_jwk_refresh_interval,
            }),
            validation,
            role_claim_paths: Arc::from(role_claim_paths_for_source(
                config,
                RolesSource::AccessToken,
            )),
            role_claim_separator: Arc::from(config.roles.role_claim_separator.clone()),
            token_type: config.token.token_type.clone().map(Arc::from),
            subject_required: config.token.subject_required,
            issued_at_required: config.token.issued_at_required,
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
        let issued_at_required = self.issued_at_required;
        let required_claims = self.required_claims.clone();
        let principal_claim = self.principal_claim.clone();
        let token_age = self.token_age;
        let leeway = validation.leeway;

        Box::pin(async move {
            let key = keys.decoding_key(&token).await?;
            decode::<TokenClaims>(&token, &key, &validation)
                .map_err(|error| Error::TokenRejected(Box::new(error)))
                .and_then(|data| {
                    validate_token_type(
                        data.header.typ.as_deref(),
                        &data.claims,
                        token_type.as_deref(),
                    )?;
                    validate_subject(&data.claims, subject_required)?;
                    validate_issued_at(&data.claims, issued_at_required, leeway)?;
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

/// Token validator that falls back to introspection after local JWT rejection.
#[derive(Clone)]
pub struct IntrospectionFallbackValidator {
    jwt: Arc<dyn TokenValidator>,
    introspection: Arc<dyn TokenValidator>,
    allow_jwt_introspection: bool,
    allow_opaque_token_introspection: bool,
}

impl IntrospectionFallbackValidator {
    /// Builds a fallback validator from a local JWT validator and introspection validator.
    pub fn new<J, I>(jwt: J, introspection: I, config: &OidcConfig) -> Self
    where
        J: TokenValidator,
        I: TokenValidator,
    {
        Self {
            jwt: Arc::new(jwt),
            introspection: Arc::new(introspection),
            allow_jwt_introspection: config.token.allow_jwt_introspection,
            allow_opaque_token_introspection: config.token.allow_opaque_token_introspection,
        }
    }
}

impl TokenValidator for IntrospectionFallbackValidator {
    fn validate(&self, token: Arc<str>) -> ValidationFuture {
        let jwt = self.jwt.clone();
        let introspection = self.introspection.clone();
        let allow_jwt_introspection = self.allow_jwt_introspection;
        let allow_opaque_token_introspection = self.allow_opaque_token_introspection;

        Box::pin(async move {
            match jwt.validate(token.clone()).await {
                Ok(principal) => Ok(principal),
                Err(error) => {
                    let token_is_jwt = token_looks_like_jwt(&token);
                    if (token_is_jwt && !allow_jwt_introspection)
                        || (!token_is_jwt && !allow_opaque_token_introspection)
                    {
                        return Err(error);
                    }
                    introspection.validate(token).await
                }
            }
        })
    }
}

fn token_looks_like_jwt(token: &str) -> bool {
    token.split('.').count() == 3
}

/// OAuth2 token introspection response.
///
/// The standard `active` member controls whether the token is accepted. Common
/// JWT-style members are modelled directly and remaining claims are preserved
/// for role, principal, and required-claim extraction.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct IntrospectionResponse {
    /// Whether the token is currently active.
    #[serde(default)]
    pub active: bool,
    /// Token subject.
    #[serde(default)]
    pub sub: Option<String>,
    /// Token issuer.
    #[serde(default)]
    pub iss: Option<String>,
    /// Token audience.
    #[serde(default, deserialize_with = "deserialize_audience")]
    pub aud: Vec<String>,
    /// Token type.
    #[serde(default)]
    pub typ: Option<String>,
    /// Issued-at timestamp.
    #[serde(default)]
    pub iat: Option<u64>,
    /// Additional introspection claims.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

impl IntrospectionResponse {
    /// Parses an introspection response from JSON.
    pub fn from_json(json: &str) -> std::result::Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    fn into_claims(self) -> TokenClaims {
        TokenClaims {
            sub: self.sub,
            iss: self.iss,
            aud: self.aud,
            typ: self.typ,
            iat: self.iat,
            extra: Value::Object(self.extra),
        }
    }
}

/// Source used to introspect opaque or remote-validated bearer tokens.
pub trait TokenIntrospector: Send + Sync + 'static {
    /// Introspects a raw bearer token.
    fn introspect(&self, token: Arc<str>) -> IntrospectionFuture;
}

impl<F, Fut> TokenIntrospector for F
where
    F: Fn(Arc<str>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = std::result::Result<IntrospectionResponse, BoxError>> + Send + 'static,
{
    fn introspect(&self, token: Arc<str>) -> IntrospectionFuture {
        Box::pin(self(token))
    }
}

/// Token validator backed by OAuth2 token introspection.
#[derive(Clone)]
pub struct IntrospectionValidator {
    introspector: Arc<dyn TokenIntrospector>,
    expected_issuer: Option<Arc<str>>,
    audiences: Arc<[String]>,
    accepts_any_audience: bool,
    role_claim_paths: Arc<[String]>,
    role_claim_separator: Arc<str>,
    token_type: Option<Arc<str>>,
    subject_required: bool,
    issued_at_required: bool,
    required_claims: Arc<HashMap<String, Vec<String>>>,
    principal_claim: Option<Arc<str>>,
    token_age: Option<Duration>,
    leeway: u64,
}

impl IntrospectionValidator {
    /// Builds a token introspection validator.
    pub fn new<I>(introspector: I, config: &OidcConfig) -> Self
    where
        I: TokenIntrospector,
    {
        let expected_issuer = config
            .token
            .issuer
            .as_deref()
            .or(config.auth_server_url.as_deref())
            .filter(|issuer| *issuer != "any")
            .map(|issuer| Arc::from(issuer.to_owned()));
        let audiences = config.token.audiences();

        Self {
            introspector: Arc::new(introspector),
            expected_issuer,
            audiences: Arc::from(audiences.into_boxed_slice()),
            accepts_any_audience: config.token.accepts_any_audience(),
            role_claim_paths: Arc::from(role_claim_paths_for_source(
                config,
                RolesSource::AccessToken,
            )),
            role_claim_separator: Arc::from(config.roles.role_claim_separator.clone()),
            token_type: config.token.token_type.clone().map(Arc::from),
            subject_required: config.token.subject_required,
            issued_at_required: config.token.issued_at_required,
            required_claims: Arc::new(config.token.required_claims.clone()),
            principal_claim: config.token.principal_claim.clone().map(Arc::from),
            token_age: config.token.age,
            leeway: config.token.lifespan_grace.unwrap_or_default(),
        }
    }
}

impl TokenValidator for IntrospectionValidator {
    fn validate(&self, token: Arc<str>) -> ValidationFuture {
        let introspector = self.introspector.clone();
        let expected_issuer = self.expected_issuer.clone();
        let audiences = self.audiences.clone();
        let accepts_any_audience = self.accepts_any_audience;
        let role_claim_paths = self.role_claim_paths.clone();
        let role_claim_separator = self.role_claim_separator.clone();
        let token_type = self.token_type.clone();
        let subject_required = self.subject_required;
        let issued_at_required = self.issued_at_required;
        let required_claims = self.required_claims.clone();
        let principal_claim = self.principal_claim.clone();
        let token_age = self.token_age;
        let leeway = self.leeway;

        Box::pin(async move {
            let response = introspector
                .introspect(token)
                .await
                .map_err(Error::TokenRejected)?;
            if !response.active {
                return Err(Error::TokenRejected(
                    "token introspection is not active".into(),
                ));
            }

            let claims = response.into_claims();
            validate_introspection_issuer(&claims, expected_issuer.as_deref())?;
            validate_introspection_audience(&claims, &audiences, accepts_any_audience)?;
            validate_token_type(None, &claims, token_type.as_deref())?;
            validate_subject(&claims, subject_required)?;
            validate_issued_at(&claims, issued_at_required, leeway)?;
            validate_required_claims(&claims, &required_claims)?;
            validate_token_age(&claims, token_age, leeway)?;
            Principal::from_claims(
                claims,
                &role_claim_paths,
                &role_claim_separator,
                principal_claim.as_deref(),
            )
        })
    }
}

/// OIDC UserInfo response.
///
/// Standard token-like fields are modelled directly and the remaining claims
/// are available for principal, required-claim, and role extraction.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct UserInfoResponse {
    /// Subject identifier.
    #[serde(default)]
    pub sub: Option<String>,
    /// Issuer, when returned by the provider.
    #[serde(default)]
    pub iss: Option<String>,
    /// Audience, when returned by the provider.
    #[serde(default, deserialize_with = "deserialize_audience")]
    pub aud: Vec<String>,
    /// Token or response type, when returned by the provider.
    #[serde(default)]
    pub typ: Option<String>,
    /// Issued-at timestamp, when returned by the provider.
    #[serde(default)]
    pub iat: Option<u64>,
    /// Additional UserInfo claims.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

impl UserInfoResponse {
    /// Parses a UserInfo response from JSON.
    pub fn from_json(json: &str) -> std::result::Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    fn into_claims(self) -> TokenClaims {
        TokenClaims {
            sub: self.sub,
            iss: self.iss,
            aud: self.aud,
            typ: self.typ,
            iat: self.iat,
            extra: Value::Object(self.extra),
        }
    }
}

/// Source used to fetch OIDC UserInfo for an access token.
pub trait UserInfoProvider: Send + Sync + 'static {
    /// Fetches UserInfo for a raw bearer token.
    fn user_info(&self, token: Arc<str>) -> UserInfoFuture;
}

impl<F, Fut> UserInfoProvider for F
where
    F: Fn(Arc<str>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = std::result::Result<UserInfoResponse, BoxError>> + Send + 'static,
{
    fn user_info(&self, token: Arc<str>) -> UserInfoFuture {
        Box::pin(self(token))
    }
}

/// Token validator backed by the OIDC UserInfo endpoint.
#[derive(Clone)]
pub struct UserInfoValidator {
    provider: Arc<dyn UserInfoProvider>,
    role_claim_paths: Arc<[String]>,
    role_claim_separator: Arc<str>,
    subject_required: bool,
    required_claims: Arc<HashMap<String, Vec<String>>>,
    principal_claim: Option<Arc<str>>,
    token_age: Option<Duration>,
    leeway: u64,
}

impl UserInfoValidator {
    /// Builds a UserInfo-backed token validator.
    pub fn new<P>(provider: P, config: &OidcConfig) -> Self
    where
        P: UserInfoProvider,
    {
        Self {
            provider: Arc::new(provider),
            role_claim_paths: Arc::from(role_claim_paths_for_source(config, RolesSource::UserInfo)),
            role_claim_separator: Arc::from(config.roles.role_claim_separator.clone()),
            subject_required: config.token.subject_required,
            required_claims: Arc::new(config.token.required_claims.clone()),
            principal_claim: config.token.principal_claim.clone().map(Arc::from),
            token_age: config.token.age,
            leeway: config.token.lifespan_grace.unwrap_or_default(),
        }
    }
}

impl TokenValidator for UserInfoValidator {
    fn validate(&self, token: Arc<str>) -> ValidationFuture {
        let provider = self.provider.clone();
        let role_claim_paths = self.role_claim_paths.clone();
        let role_claim_separator = self.role_claim_separator.clone();
        let subject_required = self.subject_required;
        let required_claims = self.required_claims.clone();
        let principal_claim = self.principal_claim.clone();
        let token_age = self.token_age;
        let leeway = self.leeway;

        Box::pin(async move {
            let claims = provider
                .user_info(token)
                .await
                .map_err(Error::TokenRejected)?
                .into_claims();
            validate_subject(&claims, subject_required)?;
            validate_required_claims(&claims, &required_claims)?;
            if claims.iat.is_some() {
                validate_token_age(&claims, token_age, leeway)?;
            }
            Principal::from_claims(
                claims,
                &role_claim_paths,
                &role_claim_separator,
                principal_claim.as_deref(),
            )
        })
    }
}

/// Token validator that validates a bearer token first, then loads roles from UserInfo.
#[derive(Clone)]
pub struct UserInfoRolesValidator {
    token_validator: Arc<dyn TokenValidator>,
    provider: Arc<dyn UserInfoProvider>,
    role_claim_paths: Arc<[String]>,
    role_claim_separator: Arc<str>,
}

impl UserInfoRolesValidator {
    /// Builds a validator that preserves token validation and sources roles from UserInfo.
    pub fn new<V, P>(token_validator: V, provider: P, config: &OidcConfig) -> Self
    where
        V: TokenValidator,
        P: UserInfoProvider,
    {
        Self::from_parts(Arc::new(token_validator), Arc::new(provider), config)
    }

    fn from_parts(
        token_validator: Arc<dyn TokenValidator>,
        provider: Arc<dyn UserInfoProvider>,
        config: &OidcConfig,
    ) -> Self {
        Self {
            token_validator,
            provider,
            role_claim_paths: Arc::from(role_claim_paths_for_source(config, RolesSource::UserInfo)),
            role_claim_separator: Arc::from(config.roles.role_claim_separator.clone()),
        }
    }
}

impl TokenValidator for UserInfoRolesValidator {
    fn validate(&self, token: Arc<str>) -> ValidationFuture {
        let token_validator = self.token_validator.clone();
        let provider = self.provider.clone();
        let role_claim_paths = self.role_claim_paths.clone();
        let role_claim_separator = self.role_claim_separator.clone();

        Box::pin(async move {
            let principal = token_validator.validate(token.clone()).await?;
            let claims = provider
                .user_info(token)
                .await
                .map_err(Error::TokenRejected)?
                .into_claims();

            if let Some(user_info_subject) = claims.sub.as_deref() {
                if user_info_subject != principal.subject() {
                    return Err(Error::TokenRejected(
                        "UserInfo subject did not match access token subject".into(),
                    ));
                }
            }

            Ok(Principal {
                subject: principal.subject,
                issuer: principal.issuer,
                audience: principal.audience,
                groups: extract_roles(&claims.extra, &role_claim_paths, &role_claim_separator)
                    .into_iter()
                    .map(Arc::from)
                    .collect(),
            })
        })
    }
}

#[derive(Clone)]
struct HttpUserInfoProvider {
    client: reqwest::Client,
    endpoint: String,
}

impl UserInfoProvider for HttpUserInfoProvider {
    fn user_info(&self, token: Arc<str>) -> UserInfoFuture {
        let client = self.client.clone();
        let endpoint = self.endpoint.clone();
        Box::pin(async move {
            let authorization = HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|error| Box::new(error) as BoxError)?;
            client
                .get(endpoint)
                .header(AUTHORIZATION, authorization)
                .send()
                .await?
                .error_for_status()?
                .json::<UserInfoResponse>()
                .await
                .map_err(|error| Box::new(error) as BoxError)
        })
    }
}

#[derive(Clone)]
struct HttpTokenIntrospector {
    client: reqwest::Client,
    endpoint: String,
    client_id: Option<String>,
    client_auth_name: Option<String>,
    client_secret: Option<String>,
    client_secret_method: ClientSecretMethod,
    include_client_id: bool,
}

impl TokenIntrospector for HttpTokenIntrospector {
    fn introspect(&self, token: Arc<str>) -> IntrospectionFuture {
        let client = self.client.clone();
        let endpoint = self.endpoint.clone();
        let client_id = self.client_id.clone();
        let client_auth_name = self.client_auth_name.clone();
        let client_secret = self.client_secret.clone();
        let client_secret_method = self.client_secret_method;
        let include_client_id = self.include_client_id;
        Box::pin(async move {
            introspection_request(
                &client,
                &endpoint,
                token.as_ref(),
                IntrospectionRequestAuth {
                    client_id: client_id.as_deref(),
                    client_auth_name: client_auth_name.as_deref(),
                    client_secret: client_secret.as_deref(),
                    client_secret_method,
                    include_client_id,
                },
            )
            .send()
            .await?
            .error_for_status()?
            .json::<IntrospectionResponse>()
            .await
            .map_err(|error| Box::new(error) as BoxError)
        })
    }
}

fn http_token_introspector(
    config: &OidcConfig,
    client: reqwest::Client,
    endpoint: String,
) -> HttpTokenIntrospector {
    let introspection_secret = config.introspection_credentials.secret.clone();
    let has_introspection_credentials = introspection_secret.is_some();
    let client_auth_name = if has_introspection_credentials {
        config
            .introspection_credentials
            .name
            .clone()
            .or_else(|| config.client_id.clone())
    } else {
        config.client_id.clone()
    };
    let client_secret = introspection_secret.or_else(|| {
        config
            .credentials
            .effective_client_secret()
            .map(ToOwned::to_owned)
    });
    let client_secret_method = if has_introspection_credentials {
        ClientSecretMethod::Basic
    } else {
        config.credentials.client_secret.method
    };

    HttpTokenIntrospector {
        client,
        endpoint,
        client_id: config.client_id.clone(),
        client_auth_name,
        client_secret,
        client_secret_method,
        include_client_id: has_introspection_credentials
            && config.introspection_credentials.include_client_id,
    }
}

fn introspection_request<'a>(
    client: &'a reqwest::Client,
    endpoint: &'a str,
    token: &'a str,
    auth: IntrospectionRequestAuth<'a>,
) -> reqwest::RequestBuilder {
    match (
        auth.client_id,
        auth.client_auth_name,
        auth.client_secret,
        auth.client_secret_method,
    ) {
        (client_id, Some(client_auth_name), Some(client_secret), ClientSecretMethod::Basic) => {
            let mut form = vec![("token", token)];
            if auth.include_client_id {
                if let Some(client_id) = client_id {
                    form.push(("client_id", client_id));
                }
            }
            client
                .post(endpoint)
                .form(&form)
                .basic_auth(client_auth_name, Some(client_secret))
        }
        (Some(client_id), _, Some(client_secret), ClientSecretMethod::Post) => {
            client.post(endpoint).form(&[
                ("token", token),
                ("client_id", client_id),
                ("client_secret", client_secret),
            ])
        }
        (Some(client_id), _, Some(client_secret), ClientSecretMethod::Query) => client
            .post(endpoint)
            .query(&[("client_id", client_id), ("client_secret", client_secret)])
            .form(&[("token", token)]),
        _ => client.post(endpoint).form(&[("token", token)]),
    }
}

#[derive(Clone, Copy)]
struct IntrospectionRequestAuth<'a> {
    client_id: Option<&'a str>,
    client_auth_name: Option<&'a str>,
    client_secret: Option<&'a str>,
    client_secret_method: ClientSecretMethod,
    include_client_id: bool,
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
    last_forced_refresh: Arc<Mutex<Option<SystemTime>>>,
    forced_refresh_interval: Duration,
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
                        if !jwks.should_force_refresh()? {
                            return Err(error);
                        }
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

impl RefreshingJwks {
    fn should_force_refresh(&self) -> Result<bool> {
        let mut last_forced_refresh = self
            .last_forced_refresh
            .lock()
            .map_err(|_| Error::TokenRejected("JWKS refresh lock was poisoned".into()))?;
        let now = SystemTime::now();
        if last_forced_refresh
            .and_then(|last| now.duration_since(last).ok())
            .is_some_and(|elapsed| elapsed < self.forced_refresh_interval)
        {
            return Ok(false);
        }

        *last_forced_refresh = Some(now);
        Ok(true)
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

fn validate_introspection_issuer(claims: &TokenClaims, expected: Option<&str>) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };

    match claims.iss.as_deref() {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(Error::TokenRejected(
            format!("introspection issuer `{actual}` did not match expected `{expected}`").into(),
        )),
        None => Err(Error::TokenRejected(
            "introspection issuer claim is required".into(),
        )),
    }
}

fn validate_introspection_audience(
    claims: &TokenClaims,
    audiences: &[String],
    accepts_any_audience: bool,
) -> Result<()> {
    if accepts_any_audience || audiences.is_empty() {
        return Ok(());
    }

    if claims
        .aud
        .iter()
        .any(|actual| audiences.iter().any(|expected| actual == expected))
    {
        return Ok(());
    }

    Err(Error::TokenRejected(
        "introspection audience did not include a configured audience".into(),
    ))
}

fn validate_token_type(
    header_token_type: Option<&str>,
    claims: &TokenClaims,
    expected: Option<&str>,
) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };

    match header_token_type
        .filter(|actual| *actual != "JWT")
        .or(claims.typ.as_deref())
    {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(Error::TokenRejected(
            format!("JWT typ `{actual}` did not match expected `{expected}`").into(),
        )),
        None => Err(Error::TokenRejected(
            format!("JWT typ is required to be `{expected}`").into(),
        )),
    }
}

fn validate_subject(claims: &TokenClaims, subject_required: bool) -> Result<()> {
    if subject_required && claims.sub.is_none() {
        return Err(Error::TokenRejected("JWT sub claim is required".into()));
    }

    Ok(())
}

fn validate_issued_at(claims: &TokenClaims, issued_at_required: bool, leeway: u64) -> Result<()> {
    let Some(issued_at) = claims.iat else {
        if issued_at_required {
            return Err(Error::TokenRejected("JWT iat claim is required".into()));
        }
        return Ok(());
    };
    let now = unix_timestamp()?;

    if issued_at > now.saturating_add(leeway) {
        return Err(Error::TokenRejected(
            "JWT iat claim is later than the allowed lifespan grace".into(),
        ));
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
        _ => claim_path_value(&claims.extra, claim_name)
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
        _ => json_string_values(claim_path_value(&claims.extra, claim_name)?),
    }
}

fn json_string_values(value: &Value) -> Option<Vec<String>> {
    match value {
        Value::String(value) => {
            let mut values = vec![value.clone()];
            values.extend(value.split_whitespace().map(ToOwned::to_owned));
            values.sort();
            values.dedup();
            Some(values)
        }
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

    /// Loads `quarkus.oidc.*` and `quarkus.http.auth.permission.*` configuration.
    pub fn from_config(config: &Config) -> mp_config::Result<OidcBuilder> {
        oidc_builder_from_config(
            OidcConfig::from_config(config)?,
            "quarkus.oidc.public-key",
            "quarkus.oidc.application-type",
            "quarkus.oidc.roles.source",
            "quarkus.oidc.token.binding.certificate",
            "quarkus.oidc.token.decrypt-access-token",
            "quarkus.oidc.token.decrypt-id-token",
        )?
        .authorization_from_config(config)
    }

    /// Loads configuration, discovers the provider, and builds the middleware.
    ///
    /// This is the config-driven path for bearer-service middleware: local
    /// `public-key` validation is installed without network access, while
    /// provider-backed configurations fetch discovery metadata and keys.
    pub async fn discover_from_config(config: &Config) -> BuildResult<Oidc> {
        Self::from_config(config)?.discover().await
    }

    /// Loads configuration, then discovers the provider with a caller-supplied client.
    pub async fn discover_from_config_with_client(
        config: &Config,
        client: reqwest::Client,
    ) -> BuildResult<Oidc> {
        Self::from_config(config)?
            .discover_with_client(client)
            .await
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
                AuthRequirement::Authenticated(role_mappings) => {
                    let mut principal = self.authenticate_principal(request).await?;
                    apply_role_mappings(&mut principal, &role_mappings);
                    request.extensions_mut().insert(principal);
                    return Ok(());
                }
                AuthRequirement::Roles {
                    role_sets,
                    role_mappings,
                } => {
                    let mut principal = self.authenticate_principal(request).await?;
                    apply_role_mappings(&mut principal, &role_mappings);
                    if role_sets
                        .iter()
                        .all(|roles| principal.has_any_group(roles.iter().map(String::as_str)))
                    {
                        request.extensions_mut().insert(principal);
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

fn oidc_builder_from_config(
    config: OidcConfig,
    public_key_property: &str,
    application_type_property: &str,
    roles_source_property: &str,
    token_binding_certificate_property: &str,
    token_decrypt_access_token_property: &str,
    token_decrypt_id_token_property: &str,
) -> mp_config::Result<OidcBuilder> {
    let public_key = config.public_key.clone();
    let mut builder = Oidc::builder(config);
    if !builder.config.enabled {
        return Ok(builder);
    }
    validate_service_application_type(&builder.config, application_type_property)?;
    validate_service_roles_source(&builder.config, roles_source_property)?;
    validate_service_token_binding_certificate(
        &builder.config,
        token_binding_certificate_property,
    )?;
    validate_service_token_decryption(
        &builder.config,
        token_decrypt_access_token_property,
        token_decrypt_id_token_property,
    )?;
    if let Some(public_key) = public_key {
        builder = builder.public_key(&public_key).map_err(|error| {
            mp_config::ConfigError::Conversion {
                name: public_key_property.to_owned(),
                value: public_key,
                message: error.to_string(),
            }
        })?;
    }
    Ok(builder)
}

fn validate_service_application_type(
    config: &OidcConfig,
    property_name: &str,
) -> mp_config::Result<()> {
    if config.application_type == ApplicationType::WebApp {
        return Err(mp_config::ConfigError::Conversion {
            name: property_name.to_owned(),
            value: "web-app".to_owned(),
            message: "`web-app` application type requires authorization-code flow support, which is not implemented for bearer-service middleware".to_owned(),
        });
    }
    Ok(())
}

fn validate_service_roles_source(
    config: &OidcConfig,
    property_name: &str,
) -> mp_config::Result<()> {
    if config.roles.source == RolesSource::IdToken {
        return Err(mp_config::ConfigError::Conversion {
            name: property_name.to_owned(),
            value: "idtoken".to_owned(),
            message: "`idtoken` roles require web-app ID token support, which is not implemented for bearer-service middleware".to_owned(),
        });
    }
    Ok(())
}

fn validate_service_token_binding_certificate(
    config: &OidcConfig,
    property_name: &str,
) -> mp_config::Result<()> {
    if config.token.binding.certificate {
        return Err(mp_config::ConfigError::Conversion {
            name: property_name.to_owned(),
            value: "true".to_owned(),
            message: "`token.binding.certificate` requires client certificate thumbprint extraction, which is not implemented for bearer-service middleware".to_owned(),
        });
    }
    Ok(())
}

fn validate_service_token_decryption(
    config: &OidcConfig,
    decrypt_access_token_property: &str,
    decrypt_id_token_property: &str,
) -> mp_config::Result<()> {
    if config.token.decrypt_access_token {
        return Err(mp_config::ConfigError::Conversion {
            name: decrypt_access_token_property.to_owned(),
            value: "true".to_owned(),
            message: "`token.decrypt-access-token` requires JWE access-token decryption, which is not implemented for bearer-service middleware".to_owned(),
        });
    }

    if config.token.decrypt_id_token == Some(true) {
        return Err(mp_config::ConfigError::Conversion {
            name: decrypt_id_token_property.to_owned(),
            value: "true".to_owned(),
            message: "`token.decrypt-id-token` requires web-app ID token decryption, which is not implemented for bearer-service middleware".to_owned(),
        });
    }

    Ok(())
}

fn oidc_http_client(config: &OidcConfig) -> BuildResult<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .connect_timeout(config.connection_timeout)
        .build()?)
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

    fn authorization_from_config(mut self, config: &Config) -> mp_config::Result<Self> {
        if has_authorization_config(config) {
            self.authorization = Some(Authorization::from_config(config)?);
        }
        Ok(self)
    }

    /// Installs a `quarkus.oidc.public-key` backed JWT validator.
    pub fn public_key(mut self, public_key: &str) -> BuildResult<Self> {
        self.validator = Some(Arc::new(JwtValidator::public_key(
            public_key,
            &self.config,
        )?));
        Ok(self)
    }

    /// Installs a custom token introspection validator.
    pub fn token_introspector<I>(mut self, introspector: I) -> Self
    where
        I: TokenIntrospector,
    {
        self.validator = Some(Arc::new(IntrospectionValidator::new(
            introspector,
            &self.config,
        )));
        self
    }

    /// Installs an HTTP token introspection validator.
    pub fn introspection_endpoint(self, endpoint: &str) -> BuildResult<Self> {
        let client = oidc_http_client(&self.config)?;
        self.introspection_endpoint_with_client(endpoint, client)
    }

    /// Installs an HTTP token introspection validator using a caller-supplied client.
    pub fn introspection_endpoint_with_client(
        mut self,
        endpoint: &str,
        client: reqwest::Client,
    ) -> BuildResult<Self> {
        reqwest::Url::parse(endpoint).map_err(|error| BuildError::InvalidUrl {
            url: endpoint.to_owned(),
            message: error.to_string(),
        })?;
        self.validator = Some(Arc::new(IntrospectionValidator::new(
            http_token_introspector(&self.config, client, endpoint.to_owned()),
            &self.config,
        )));
        Ok(self)
    }

    /// Installs a custom UserInfo-backed token validator.
    pub fn user_info_provider<P>(mut self, provider: P) -> Self
    where
        P: UserInfoProvider,
    {
        self.validator = Some(Arc::new(UserInfoValidator::new(provider, &self.config)));
        self
    }

    /// Installs an HTTP UserInfo-backed token validator.
    pub fn user_info_endpoint(self, endpoint: &str) -> BuildResult<Self> {
        let client = oidc_http_client(&self.config)?;
        self.user_info_endpoint_with_client(endpoint, client)
    }

    /// Installs an HTTP UserInfo-backed token validator using a caller-supplied client.
    pub fn user_info_endpoint_with_client(
        mut self,
        endpoint: &str,
        client: reqwest::Client,
    ) -> BuildResult<Self> {
        reqwest::Url::parse(endpoint).map_err(|error| BuildError::InvalidUrl {
            url: endpoint.to_owned(),
            message: error.to_string(),
        })?;
        self.validator = Some(Arc::new(UserInfoValidator::new(
            HttpUserInfoProvider {
                client,
                endpoint: endpoint.to_owned(),
            },
            &self.config,
        )));
        Ok(self)
    }

    /// Discovers provider metadata and installs a JWKS-backed JWT validator.
    pub async fn discover(self) -> BuildResult<Oidc> {
        let client = oidc_http_client(&self.config)?;
        self.discover_with_client(client).await
    }

    /// Discovers provider metadata using a caller-supplied HTTP client.
    pub async fn discover_with_client(self, client: reqwest::Client) -> BuildResult<Oidc> {
        if !self.config.enabled || self.config.public_key.is_some() {
            return Ok(self.build());
        }

        let auth_server_url = auth_server_url_from_config(&self.config)?;
        if !self.config.discovery_enabled {
            if self.config.token.require_jwt_introspection_only {
                let introspection_path = self
                    .config
                    .introspection_path
                    .clone()
                    .ok_or(BuildError::MissingIntrospectionEndpoint)?;
                let endpoint = provider_endpoint_url(&auth_server_url, &introspection_path)?;
                return self
                    .introspection_endpoint_with_client(endpoint.as_str(), client)
                    .map(OidcBuilder::build);
            }

            if self.config.token.verify_access_token_with_user_info {
                let user_info_path = self
                    .config
                    .user_info_path
                    .clone()
                    .ok_or(BuildError::MissingUserInfoEndpoint)?;
                let endpoint = provider_endpoint_url(&auth_server_url, &user_info_path)?;
                return self
                    .user_info_endpoint_with_client(endpoint.as_str(), client)
                    .map(OidcBuilder::build);
            }

            if self.uses_user_info_roles() {
                self.config
                    .user_info_path
                    .as_ref()
                    .ok_or(BuildError::MissingUserInfoEndpoint)?;
            }

            let jwks_path = self
                .config
                .jwks_path
                .clone()
                .ok_or(BuildError::MissingJwksPath)?;
            let jwks_url = provider_endpoint_url(&auth_server_url, &jwks_path)?;
            let jwks: JwkSet = client
                .get(jwks_url)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            let mut builder = self;
            builder.install_jwks_with_optional_introspection(jwks, client);
            return Ok(builder.build());
        }

        let metadata_url = discovery_url(&auth_server_url, &self.config.discovery_path)?;
        let metadata: ProviderMetadata = client
            .get(metadata_url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        if self.config.token.require_jwt_introspection_only {
            let endpoint = metadata
                .introspection_endpoint
                .as_deref()
                .ok_or(BuildError::MissingIntrospectionEndpoint)?;
            return self
                .introspection_endpoint_with_client(endpoint, client)
                .map(OidcBuilder::build);
        }

        if self.config.token.verify_access_token_with_user_info {
            let endpoint = metadata
                .userinfo_endpoint
                .as_deref()
                .ok_or(BuildError::MissingUserInfoEndpoint)?;
            return self
                .user_info_endpoint_with_client(endpoint, client)
                .map(OidcBuilder::build);
        }

        if self.uses_user_info_roles() {
            metadata
                .userinfo_endpoint
                .as_ref()
                .ok_or(BuildError::MissingUserInfoEndpoint)?;
        }

        let jwks: JwkSet = client
            .get(&metadata.jwks_uri)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        self.provider_metadata_refreshing(metadata, jwks, client)
    }

    /// Installs provider metadata and a JWKS-backed JWT validator.
    pub fn provider_metadata(
        mut self,
        metadata: ProviderMetadata,
        jwks: JwkSet,
    ) -> BuildResult<Oidc> {
        if self.config.token.require_jwt_introspection_only {
            self.install_metadata_introspection(metadata, reqwest::Client::new())?;
            return Ok(self.build());
        }

        if self.config.token.verify_access_token_with_user_info {
            self.install_metadata_user_info(metadata, reqwest::Client::new())?;
            return Ok(self.build());
        }

        if self.uses_user_info_roles() {
            metadata
                .userinfo_endpoint
                .as_ref()
                .ok_or(BuildError::MissingUserInfoEndpoint)?;
        }

        let validation_config = provider_validation_config(&self.config, &metadata);
        let jwt = JwtValidator::jwks(jwks, &validation_config);
        let client = reqwest::Client::new();
        let validator = self.jwt_with_metadata_introspection(jwt, metadata.clone(), client.clone());
        self.validator = Some(self.with_metadata_user_info_roles(validator, metadata, client));
        Ok(self.build())
    }

    /// Installs provider metadata and a refreshable JWKS-backed JWT validator.
    pub fn provider_metadata_refreshing(
        mut self,
        metadata: ProviderMetadata,
        jwks: JwkSet,
        client: reqwest::Client,
    ) -> BuildResult<Oidc> {
        if self.config.token.require_jwt_introspection_only {
            self.install_metadata_introspection(metadata, client)?;
            return Ok(self.build());
        }

        if self.config.token.verify_access_token_with_user_info {
            self.install_metadata_user_info(metadata, client)?;
            return Ok(self.build());
        }

        if self.uses_user_info_roles() {
            metadata
                .userinfo_endpoint
                .as_ref()
                .ok_or(BuildError::MissingUserInfoEndpoint)?;
        }

        let validation_config = provider_validation_config(&self.config, &metadata);
        let jwt = JwtValidator::refreshable_jwks(
            jwks,
            HttpJwksProvider {
                client: client.clone(),
                jwks_uri: metadata.jwks_uri.clone(),
            },
            &validation_config,
        );
        let validator = self.jwt_with_metadata_introspection(jwt, metadata.clone(), client.clone());
        self.validator = Some(self.with_metadata_user_info_roles(validator, metadata, client));
        Ok(self.build())
    }

    fn install_jwks_with_optional_introspection(&mut self, jwks: JwkSet, client: reqwest::Client) {
        let jwt = JwtValidator::jwks(jwks, &self.config);
        let user_info_endpoint = self.user_info_endpoint_from_config();
        let Some(introspection_path) = self.config.introspection_path.as_deref() else {
            self.validator = Some(self.with_user_info_roles_from_config(Arc::new(jwt), client));
            return;
        };
        let Some(auth_server_url) = self.config.auth_server_url.as_deref() else {
            self.validator = Some(self.with_user_info_roles_from_config(Arc::new(jwt), client));
            return;
        };
        let Ok(endpoint) = provider_endpoint_url(auth_server_url, introspection_path) else {
            self.validator = Some(self.with_user_info_roles_from_config(Arc::new(jwt), client));
            return;
        };
        let introspection = IntrospectionValidator::new(
            http_token_introspector(&self.config, client.clone(), endpoint.to_string()),
            &self.config,
        );
        let validator = Arc::new(IntrospectionFallbackValidator::new(
            jwt,
            introspection,
            &self.config,
        ));
        self.validator = Some(match user_info_endpoint {
            Some(endpoint) if self.uses_user_info_roles() => {
                Arc::new(UserInfoRolesValidator::from_parts(
                    validator,
                    Arc::new(HttpUserInfoProvider { client, endpoint }),
                    &self.config,
                ))
            }
            _ => validator,
        });
    }

    fn jwt_with_metadata_introspection<J>(
        &self,
        jwt: J,
        metadata: ProviderMetadata,
        client: reqwest::Client,
    ) -> Arc<dyn TokenValidator>
    where
        J: TokenValidator,
    {
        let Some(endpoint) = metadata.introspection_endpoint.clone() else {
            return Arc::new(jwt);
        };
        let validation_config = provider_validation_config(&self.config, &metadata);
        let introspection = IntrospectionValidator::new(
            http_token_introspector(&validation_config, client, endpoint),
            &validation_config,
        );
        Arc::new(IntrospectionFallbackValidator::new(
            jwt,
            introspection,
            &self.config,
        ))
    }

    fn install_metadata_introspection(
        &mut self,
        metadata: ProviderMetadata,
        client: reqwest::Client,
    ) -> BuildResult<()> {
        let endpoint = metadata
            .introspection_endpoint
            .clone()
            .ok_or(BuildError::MissingIntrospectionEndpoint)?;
        let validation_config = provider_validation_config(&self.config, &metadata);
        self.validator = Some(Arc::new(IntrospectionValidator::new(
            http_token_introspector(&validation_config, client, endpoint),
            &validation_config,
        )));
        Ok(())
    }

    fn install_metadata_user_info(
        &mut self,
        metadata: ProviderMetadata,
        client: reqwest::Client,
    ) -> BuildResult<()> {
        let endpoint = metadata
            .userinfo_endpoint
            .clone()
            .ok_or(BuildError::MissingUserInfoEndpoint)?;
        let validation_config = provider_validation_config(&self.config, &metadata);
        self.validator = Some(Arc::new(UserInfoValidator::new(
            HttpUserInfoProvider { client, endpoint },
            &validation_config,
        )));
        Ok(())
    }

    fn uses_user_info_roles(&self) -> bool {
        self.config.roles.source == RolesSource::UserInfo
            && !self.config.token.verify_access_token_with_user_info
    }

    fn user_info_endpoint_from_config(&self) -> Option<String> {
        let auth_server_url = self.config.auth_server_url.as_deref()?;
        let user_info_path = self.config.user_info_path.as_deref()?;
        provider_endpoint_url(auth_server_url, user_info_path)
            .ok()
            .map(Into::into)
    }

    fn with_user_info_roles_from_config(
        &self,
        validator: Arc<dyn TokenValidator>,
        client: reqwest::Client,
    ) -> Arc<dyn TokenValidator> {
        if !self.uses_user_info_roles() {
            return validator;
        }
        let Some(endpoint) = self.user_info_endpoint_from_config() else {
            return validator;
        };
        Arc::new(UserInfoRolesValidator::from_parts(
            validator,
            Arc::new(HttpUserInfoProvider { client, endpoint }),
            &self.config,
        ))
    }

    fn with_metadata_user_info_roles(
        &self,
        validator: Arc<dyn TokenValidator>,
        metadata: ProviderMetadata,
        client: reqwest::Client,
    ) -> Arc<dyn TokenValidator> {
        if !self.uses_user_info_roles() {
            return validator;
        }
        let Some(endpoint) = metadata.userinfo_endpoint else {
            return validator;
        };
        Arc::new(UserInfoRolesValidator::from_parts(
            validator,
            Arc::new(HttpUserInfoProvider { client, endpoint }),
            &self.config,
        ))
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
        let authorization_scheme = oidc.config.token.authorization_scheme.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            match oidc.authenticate(&mut request).await {
                Ok(()) => inner.call(request).await,
                Err(error) => Ok(error.into_response_with_scheme(&authorization_scheme)),
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
    resolve_with_issuer: bool,
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
    /// `tenant-paths` property, and configured `quarkus.http.auth.permission.*`
    /// policies are applied to each tenant.
    pub fn from_config(config: &Config) -> mp_config::Result<TenantsBuilder> {
        let mut builder = Tenants::builder().resolve_with_issuer(
            config
                .get_optional::<bool>("quarkus.oidc.resolve-tenants-with-issuer")?
                .unwrap_or_default(),
        );
        if let Some(header_name) = config.get_optional::<String>("quarkus.oidc.tenant-id-header")? {
            let parsed = http::HeaderName::from_str(&header_name).map_err(|error| {
                mp_config::ConfigError::Conversion {
                    name: "quarkus.oidc.tenant-id-header".to_owned(),
                    value: header_name,
                    message: error.to_string(),
                }
            })?;
            builder = builder.tenant_header(parsed);
        }
        if has_default_tenant_config(config) {
            let default_config = OidcConfig::from_config(config)?;
            let default_tenant = oidc_builder_from_config(
                default_config,
                "quarkus.oidc.public-key",
                "quarkus.oidc.application-type",
                "quarkus.oidc.roles.source",
                "quarkus.oidc.token.binding.certificate",
                "quarkus.oidc.token.decrypt-access-token",
                "quarkus.oidc.token.decrypt-id-token",
            )?
            .authorization_from_config(config)?
            .build();
            builder = builder.default_tenant(default_tenant);
        }

        for tenant in named_tenant_configs(config) {
            let prefix = format!("quarkus.oidc.{}", tenant.prefix_segment);
            let tenant_config = OidcConfig::from_config_prefix(config, &prefix)?;
            validate_configured_tenant_paths(&tenant_config, &format!("{prefix}.tenant-paths"))?;
            let oidc = oidc_builder_from_config(
                tenant_config,
                &format!("{prefix}.public-key"),
                &format!("{prefix}.application-type"),
                &format!("{prefix}.roles.source"),
                &format!("{prefix}.token.binding.certificate"),
                &format!("{prefix}.token.decrypt-access-token"),
                &format!("{prefix}.token.decrypt-id-token"),
            )?
            .authorization_from_config(config)?
            .build();
            builder = builder.tenant(tenant.name, oidc);
        }

        Ok(builder)
    }

    /// Loads configured tenants, discovers their providers, and builds the registry.
    ///
    /// The default tenant uses `quarkus.oidc.*`; named tenants use
    /// `quarkus.oidc.<tenant>.*`. Local `public-key` tenants are built without
    /// network access, while provider-backed tenants fetch discovery metadata
    /// and keys.
    pub async fn discover_from_config(config: &Config) -> BuildResult<Tenants> {
        discover_tenants_from_config(config, None).await
    }

    /// Loads configured tenants and discovers providers with a caller-supplied client.
    pub async fn discover_from_config_with_client(
        config: &Config,
        client: reqwest::Client,
    ) -> BuildResult<Tenants> {
        discover_tenants_from_config(config, Some(client)).await
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
                if let Some(tenant) = self.tenants.iter().find(|tenant| tenant.matches_id(value)) {
                    return Some(&tenant.oidc);
                }
            }
        }

        if self.resolve_with_issuer {
            if let Some(tenant) = self.tenants.iter().find(|tenant| {
                tenant
                    .unverified_request_issuer(request)
                    .is_some_and(|issuer| tenant.issuer_matches(&issuer))
            }) {
                return Some(&tenant.oidc);
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

fn validate_configured_tenant_paths(
    config: &OidcConfig,
    property_name: &str,
) -> mp_config::Result<()> {
    if let Some(value) = &config.tenant_paths {
        if split_csv(value).is_empty() {
            return Err(mp_config::ConfigError::Conversion {
                name: property_name.to_owned(),
                value: value.clone(),
                message: "tenant-paths must include at least one path".to_owned(),
            });
        }
    }

    Ok(())
}

/// Builder for [`Tenants`].
#[derive(Default)]
pub struct TenantsBuilder {
    tenants: Vec<RegisteredTenant>,
    default_tenant: Option<Oidc>,
    header_name: Option<http::HeaderName>,
    resolve_with_issuer: bool,
}

impl TenantsBuilder {
    /// Sets the fallback tenant used when no named tenant matches.
    pub fn default_tenant(mut self, oidc: Oidc) -> Self {
        self.default_tenant = Some(oidc);
        self
    }

    /// Adds a named tenant.
    pub fn tenant(mut self, name: impl Into<String>, oidc: Oidc) -> Self {
        let name: Arc<str> = Arc::from(name.into());
        let id: Arc<str> = Arc::from(
            oidc.config
                .tenant_id
                .as_deref()
                .unwrap_or(name.as_ref())
                .to_owned(),
        );
        let mut tenant_paths = oidc
            .config
            .tenant_paths
            .as_deref()
            .map(split_csv)
            .unwrap_or_default();
        if tenant_paths.is_empty() {
            tenant_paths.push(default_tenant_path(name.as_ref()));
        }
        self.tenants.push(RegisteredTenant {
            name,
            id,
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

    /// Selects tenants by matching bearer token `iss` claims.
    pub fn resolve_with_issuer(mut self, enabled: bool) -> Self {
        self.resolve_with_issuer = enabled;
        self
    }

    /// Finishes the tenant registry.
    pub fn build(self) -> Tenants {
        Tenants {
            tenants: Arc::from(self.tenants),
            default_tenant: self.default_tenant,
            header_name: self.header_name,
            resolve_with_issuer: self.resolve_with_issuer,
        }
    }
}

async fn discover_tenants_from_config(
    config: &Config,
    client: Option<reqwest::Client>,
) -> BuildResult<Tenants> {
    let mut builder = Tenants::builder().resolve_with_issuer(
        config
            .get_optional::<bool>("quarkus.oidc.resolve-tenants-with-issuer")?
            .unwrap_or_default(),
    );
    if let Some(header_name) = config.get_optional::<String>("quarkus.oidc.tenant-id-header")? {
        let parsed = http::HeaderName::from_str(&header_name).map_err(|error| {
            mp_config::ConfigError::Conversion {
                name: "quarkus.oidc.tenant-id-header".to_owned(),
                value: header_name,
                message: error.to_string(),
            }
        })?;
        builder = builder.tenant_header(parsed);
    }
    if has_default_tenant_config(config) {
        let default_config = OidcConfig::from_config(config)?;
        let default_tenant = oidc_builder_from_config(
            default_config,
            "quarkus.oidc.public-key",
            "quarkus.oidc.application-type",
            "quarkus.oidc.roles.source",
            "quarkus.oidc.token.binding.certificate",
            "quarkus.oidc.token.decrypt-access-token",
            "quarkus.oidc.token.decrypt-id-token",
        )?
        .authorization_from_config(config)?;
        let default_tenant = discover_oidc_builder(default_tenant, client.as_ref()).await?;
        builder = builder.default_tenant(default_tenant);
    }

    for tenant in named_tenant_configs(config) {
        let prefix = format!("quarkus.oidc.{}", tenant.prefix_segment);
        let tenant_config = OidcConfig::from_config_prefix(config, &prefix)?;
        validate_configured_tenant_paths(&tenant_config, &format!("{prefix}.tenant-paths"))?;
        let oidc = oidc_builder_from_config(
            tenant_config,
            &format!("{prefix}.public-key"),
            &format!("{prefix}.application-type"),
            &format!("{prefix}.roles.source"),
            &format!("{prefix}.token.binding.certificate"),
            &format!("{prefix}.token.decrypt-access-token"),
            &format!("{prefix}.token.decrypt-id-token"),
        )?
        .authorization_from_config(config)?;
        let oidc = discover_oidc_builder(oidc, client.as_ref()).await?;
        builder = builder.tenant(tenant.name, oidc);
    }

    Ok(builder.build())
}

async fn discover_oidc_builder(
    builder: OidcBuilder,
    client: Option<&reqwest::Client>,
) -> BuildResult<Oidc> {
    match client {
        Some(client) => builder.discover_with_client(client.clone()).await,
        None => builder.discover().await,
    }
}

#[derive(Clone)]
struct RegisteredTenant {
    name: Arc<str>,
    id: Arc<str>,
    tenant_paths: Vec<String>,
    oidc: Oidc,
}

impl RegisteredTenant {
    fn matches_id(&self, value: &str) -> bool {
        self.id.as_ref() == value || self.name.as_ref() == value
    }

    fn match_score(&self, request_path: &str) -> Option<usize> {
        self.tenant_paths
            .iter()
            .filter_map(|path| path_match_score(path, request_path))
            .max()
    }

    fn issuer_matches(&self, issuer: &str) -> bool {
        self.oidc
            .config
            .token
            .issuer
            .as_deref()
            .filter(|expected| *expected != "any")
            .or(self.oidc.config.auth_server_url.as_deref())
            .is_some_and(|expected| expected == issuer)
    }

    fn unverified_request_issuer(&self, request: &Request<Body>) -> Option<String> {
        unverified_token_from_request(request, &self.oidc.config.token)
            .and_then(unverified_token_issuer)
    }
}

fn default_tenant_path(name: &str) -> String {
    format!("/{name}/*")
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
                Err(error) => {
                    Ok(error.into_response_with_scheme(&tenant.config.token.authorization_scheme))
                }
            }
        })
    }
}

fn load_role_policies(config: &Config) -> mp_config::Result<HashMap<String, RolePolicy>> {
    let mut policies = HashMap::new();

    for key in config.property_names() {
        if let Some(name) = key
            .strip_prefix("quarkus.http.auth.policy.")
            .and_then(|suffix| suffix.strip_suffix(".roles-allowed"))
        {
            let value = config.get::<String>(&key)?;
            let roles_allowed = split_csv(&value);
            if roles_allowed.is_empty() {
                return Err(mp_config::ConfigError::Conversion {
                    name: key,
                    value,
                    message: "roles-allowed must include at least one role".to_owned(),
                });
            }
            policies
                .entry(name.to_owned())
                .or_insert_with(RolePolicy::default)
                .roles_allowed = roles_allowed;
            continue;
        }

        let Some((name, role)) = key
            .strip_prefix("quarkus.http.auth.policy.")
            .and_then(|suffix| suffix.split_once(".roles."))
        else {
            continue;
        };

        let Some(role) = config_map_entry_name(role) else {
            continue;
        };

        policies
            .entry(name.to_owned())
            .or_insert_with(RolePolicy::default)
            .role_mappings
            .insert(role, load_role_mapping(config, &key)?);
    }

    Ok(policies)
}

fn load_role_mappings(
    config: &Config,
    prefix: &str,
) -> mp_config::Result<HashMap<String, Vec<String>>> {
    let mut mappings = HashMap::new();
    let property_prefix = format!("{prefix}.");

    for key in config.property_names() {
        let Some(role) = key.strip_prefix(&property_prefix) else {
            continue;
        };
        let Some(role) = config_map_entry_name(role) else {
            continue;
        };

        mappings.insert(role, load_role_mapping(config, &key)?);
    }

    Ok(mappings)
}

fn load_role_mapping(config: &Config, key: &str) -> mp_config::Result<Vec<String>> {
    let value = config.get::<String>(key)?;
    let mapped_roles = split_csv(&value);
    if mapped_roles.is_empty() {
        return Err(mp_config::ConfigError::Conversion {
            name: key.to_owned(),
            value,
            message: "role mappings must include at least one mapped role".to_owned(),
        });
    }
    Ok(mapped_roles)
}

fn load_optional_non_empty_string(config: &Config, key: &str) -> mp_config::Result<Option<String>> {
    let value = config.get_optional::<String>(key)?;
    if let Some(value) = &value {
        if value.trim().is_empty() {
            return Err(mp_config::ConfigError::Conversion {
                name: key.to_owned(),
                value: value.clone(),
                message: "value must not be empty when configured".to_owned(),
            });
        }
    }
    Ok(value)
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
        let Some(claim_name) = config_map_entry_name(claim_name) else {
            continue;
        };

        let value = config.get::<String>(&key)?;
        let expected_values = split_csv(&value);
        if expected_values.is_empty() {
            return Err(mp_config::ConfigError::Conversion {
                name: key,
                value,
                message: "required claims must include at least one expected value".to_owned(),
            });
        }

        claims.insert(claim_name, expected_values);
    }

    Ok(claims)
}

fn config_map_entry_name(name: &str) -> Option<String> {
    if let Some(quoted) = name
        .strip_prefix('"')
        .and_then(|name| name.strip_suffix('"'))
    {
        return (!quoted.is_empty()).then(|| quoted.to_owned());
    }

    if name.is_empty() || name.contains('.') {
        return None;
    }

    Some(name.to_owned())
}

fn has_default_tenant_config(config: &Config) -> bool {
    config.property_names().into_iter().any(|key| {
        key == "quarkus.oidc.enabled"
            || key == "quarkus.oidc.tenant-enabled"
            || key == "quarkus.oidc.auth-server-url"
            || key == "quarkus.oidc.provider"
            || key == "quarkus.oidc.connection-timeout"
            || key == "quarkus.oidc.discovery-enabled"
            || key == "quarkus.oidc.discovery-path"
            || key == "quarkus.oidc.jwks-path"
            || key == "quarkus.oidc.authorization-path"
            || key == "quarkus.oidc.token-path"
            || key == "quarkus.oidc.registration-path"
            || key == "quarkus.oidc.revoke-path"
            || key == "quarkus.oidc.introspection-path"
            || key == "quarkus.oidc.user-info-path"
            || key == "quarkus.oidc.end-session-path"
            || key == "quarkus.oidc.client-id"
            || key == "quarkus.oidc.client-name"
            || key == "quarkus.oidc.tenant-id"
            || key == "quarkus.oidc.tenant-id-header"
            || key == "quarkus.oidc.tenant-paths"
            || key == "quarkus.oidc.public-key"
            || key == "quarkus.oidc.application-type"
            || key.starts_with("quarkus.oidc.credentials.")
            || key.starts_with("quarkus.oidc.introspection-credentials.")
            || key.starts_with("quarkus.oidc.token.")
            || key.starts_with("quarkus.oidc.roles.")
    })
}

#[cfg(test)]
fn named_tenant_names(config: &Config) -> Vec<String> {
    named_tenant_configs(config)
        .into_iter()
        .map(|tenant| tenant.name)
        .collect()
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
struct NamedTenantConfig {
    name: String,
    prefix_segment: String,
}

fn named_tenant_configs(config: &Config) -> Vec<NamedTenantConfig> {
    let mut names = BTreeSet::new();
    for key in config.property_names() {
        let Some(rest) = key.strip_prefix("quarkus.oidc.") else {
            continue;
        };
        let Some((name, prefix_segment, property)) = named_tenant_key_parts(rest) else {
            continue;
        };
        let tenant_property = matches!(
            property,
            "enabled"
                | "tenant-enabled"
                | "auth-server-url"
                | "provider"
                | "connection-timeout"
                | "discovery-enabled"
                | "discovery-path"
                | "jwks-path"
                | "authorization-path"
                | "token-path"
                | "registration-path"
                | "revoke-path"
                | "introspection-path"
                | "user-info-path"
                | "end-session-path"
                | "client-id"
                | "client-name"
                | "tenant-id"
                | "tenant-paths"
                | "public-key"
                | "application-type"
        ) || property.starts_with("token.")
            || property.starts_with("credentials.")
            || property.starts_with("introspection-credentials.")
            || property.starts_with("roles.");
        if !matches!(
            name.as_str(),
            "credentials" | "introspection-credentials" | "token" | "roles"
        ) && tenant_property
        {
            names.insert(NamedTenantConfig {
                name,
                prefix_segment,
            });
        }
    }
    names.into_iter().collect()
}

fn named_tenant_key_parts(rest: &str) -> Option<(String, String, &str)> {
    if let Some(rest) = rest.strip_prefix('"') {
        let end = rest.find('"')?;
        let name = &rest[..end];
        if name.is_empty() {
            return None;
        }
        let property = rest[end + 1..].strip_prefix('.')?;
        return Some((name.to_owned(), format!(r#""{name}""#), property));
    }

    let (name, property) = rest.split_once('.')?;
    if name.is_empty() {
        return None;
    }
    Some((name.to_owned(), name.to_owned(), property))
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

fn has_authorization_config(config: &Config) -> bool {
    !permission_names(config).is_empty()
}

fn policy_from_config(
    property_name: &str,
    name: &str,
    role_policies: &HashMap<String, RolePolicy>,
) -> mp_config::Result<HttpPolicy> {
    match name {
        "permit" => Ok(HttpPolicy::Permit),
        "deny" => Ok(HttpPolicy::Deny),
        "authenticated" => Ok(HttpPolicy::Authenticated),
        name => role_policies
            .get(name)
            .cloned()
            .map(HttpPolicy::Roles)
            .ok_or_else(|| mp_config::ConfigError::Conversion {
                name: property_name.to_owned(),
                value: name.to_owned(),
                message: format!("authorization policy `{name}` is not defined"),
            }),
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

fn discovery_url(auth_server_url: &str, discovery_path: &str) -> BuildResult<reqwest::Url> {
    provider_endpoint_url(auth_server_url, discovery_path)
}

fn auth_server_url_from_config(config: &OidcConfig) -> BuildResult<String> {
    if let Some(auth_server_url) = &config.auth_server_url {
        return Ok(auth_server_url.clone());
    }

    if let Some(provider) = config.provider {
        return provider
            .auth_server_url()
            .map(ToOwned::to_owned)
            .ok_or(BuildError::UnsupportedWellKnownProvider(provider));
    }

    Err(BuildError::MissingAuthServerUrl)
}

fn provider_endpoint_url(auth_server_url: &str, path: &str) -> BuildResult<reqwest::Url> {
    let url = if path.starts_with("http://") || path.starts_with("https://") {
        path.to_owned()
    } else {
        format!(
            "{}/{}",
            auth_server_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    };
    reqwest::Url::parse(&url).map_err(|error| BuildError::InvalidUrl {
        url,
        message: error.to_string(),
    })
}

fn provider_validation_config(config: &OidcConfig, metadata: &ProviderMetadata) -> OidcConfig {
    let mut validation_config = config.clone();
    if validation_config.token.issuer.is_none() {
        validation_config.token.issuer = metadata.issuer.clone();
    }
    validation_config
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
        validation.validate_aud = false;
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

fn public_key_algorithm(config: &OidcConfig) -> Algorithm {
    config
        .token
        .signature_algorithm
        .map(|algorithm| algorithm.algorithm())
        .unwrap_or(Algorithm::RS256)
}

fn public_decoding_key(public_key: &str, validation: &Validation) -> BuildResult<DecodingKey> {
    let key = public_key.as_bytes();
    let algorithm = validation
        .algorithms
        .first()
        .copied()
        .unwrap_or(Algorithm::RS256);

    match algorithm {
        Algorithm::ES256 | Algorithm::ES384 => DecodingKey::from_ec_pem(key),
        Algorithm::EdDSA => DecodingKey::from_ed_pem(key),
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => DecodingKey::from_rsa_pem(key),
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            return Err(BuildError::InvalidPublicKey(
                "public-key does not support HMAC signature algorithms".into(),
            ));
        }
    }
    .map_err(|error| BuildError::InvalidPublicKey(Box::new(error)))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claims::claim_path_parts;
    use crate::path::{normalize_permission_paths, path_match_score};
    use axum::Router;
    use axum::extract::Extension;
    use axum::routing::get;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use mp_config::MapSource;
    use serde::Serialize;
    use serde_json::json;
    use tower::ServiceExt;

    const TEST_IAT: u64 = 1_700_000_000;

    const PRIVATE_RSA_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJETqse41HRBsc
7cfcq3ak4oZWFCoZlcic525A3FfO4qW9BMtRO/iXiyCCHn8JhiL9y8j5JdVP2Q9Z
IpfElcFd3/guS9w+5RqQGgCR+H56IVUyHZWtTJbKPcwWXQdNUX0rBFcsBzCRESJL
eelOEdHIjG7LRkx5l/FUvlqsyHDVJEQsHwegZ8b8C0fz0EgT2MMEdn10t6Ur1rXz
jMB/wvCg8vG8lvciXmedyo9xJ8oMOh0wUEgxziVDMMovmC+aJctcHUAYubwoGN8T
yzcvnGqL7JSh36Pwy28iPzXZ2RLhAyJFU39vLaHdljwthUaupldlNyCfa6Ofy4qN
ctlUPlN1AgMBAAECggEAdESTQjQ70O8QIp1ZSkCYXeZjuhj081CK7jhhp/4ChK7J
GlFQZMwiBze7d6K84TwAtfQGZhQ7km25E1kOm+3hIDCoKdVSKch/oL54f/BK6sKl
qlIzQEAenho4DuKCm3I4yAw9gEc0DV70DuMTR0LEpYyXcNJY3KNBOTjN5EYQAR9s
2MeurpgK2MdJlIuZaIbzSGd+diiz2E6vkmcufJLtmYUT/k/ddWvEtz+1DnO6bRHh
xuuDMeJA/lGB/EYloSLtdyCF6sII6C6slJJtgfb0bPy7l8VtL5iDyz46IKyzdyzW
tKAn394dm7MYR1RlUBEfqFUyNK7C+pVMVoTwCC2V4QKBgQD64syfiQ2oeUlLYDm4
CcKSP3RnES02bcTyEDFSuGyyS1jldI4A8GXHJ/lG5EYgiYa1RUivge4lJrlNfjyf
dV230xgKms7+JiXqag1FI+3mqjAgg4mYiNjaao8N8O3/PD59wMPeWYImsWXNyeHS
55rUKiHERtCcvdzKl4u35ZtTqQKBgQDNKnX2bVqOJ4WSqCgHRhOm386ugPHfy+8j
m6cicmUR46ND6ggBB03bCnEG9OtGisxTo/TuYVRu3WP4KjoJs2LD5fwdwJqpgtHl
yVsk45Y1Hfo+7M6lAuR8rzCi6kHHNb0HyBmZjysHWZsn79ZM+sQnLpgaYgQGRbKV
DZWlbw7g7QKBgQCl1u+98UGXAP1jFutwbPsx40IVszP4y5ypCe0gqgon3UiY/G+1
zTLp79GGe/SjI2VpQ7AlW7TI2A0bXXvDSDi3/5Dfya9ULnFXv9yfvH1QwWToySpW
Kvd1gYSoiX84/WCtjZOr0e0HmLIb0vw0hqZA4szJSqoxQgvF22EfIWaIaQKBgQCf
34+OmMYw8fEvSCPxDxVvOwW2i7pvV14hFEDYIeZKW2W1HWBhVMzBfFB5SE8yaCQy
pRfOzj9aKOCm2FjjiErVNpkQoi6jGtLvScnhZAt/lr2TXTrl8OwVkPrIaN0bG/AS
aUYxmBPCpXu3UjhfQiWqFq/mFyzlqlgvuCc9g95HPQKBgAscKP8mLxdKwOgX8yFW
GcZ0izY/30012ajdHY+/QK5lsMoxTnn0skdS+spLxaS5ZEO4qvPVb8RAoCkWMMal
2pOhmquJQVDPDLuZHdrIiKiDM20dy9sMfHygWcZjQ4WSxf/J7T9canLZIXFhHAZT
3wc9h4G8BBCtWN2TN/LsGZdB
-----END PRIVATE KEY-----"#;

    const PUBLIC_RSA_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyRE6rHuNR0QbHO3H3Kt2
pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5/CYYi/cvI+SXVT9kPWSKXxJXB
Xd/4LkvcPuUakBoAkfh+eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHR
yIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG/AtH89BIE9jDBHZ9dLelK9a184zAf8Lw
oPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xq
i+yUod+j8MtvIj812dkS4QMiRVN/by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5T
dQIDAQAB
-----END PUBLIC KEY-----"#;

    #[test]
    fn config_loads_quarkus_oidc_properties() {
        let config = Config::builder()
            .add_source(
                MapSource::new("test", 100)
                    .with(
                        "quarkus.oidc.auth-server-url",
                        "https://issuer.example/realms/app",
                    )
                    .with("quarkus.oidc.provider", "github")
                    .with("quarkus.oidc.connection-timeout", "2s")
                    .with("quarkus.oidc.resolve-tenants-with-issuer", "true")
                    .with("quarkus.oidc.discovery-enabled", "false")
                    .with("quarkus.oidc.discovery-path", "custom-discovery")
                    .with("quarkus.oidc.jwks-path", "protocol/openid-connect/certs")
                    .with(
                        "quarkus.oidc.authorization-path",
                        "protocol/openid-connect/auth",
                    )
                    .with("quarkus.oidc.token-path", "protocol/openid-connect/token")
                    .with(
                        "quarkus.oidc.registration-path",
                        "clients-registrations/openid-connect",
                    )
                    .with("quarkus.oidc.revoke-path", "protocol/openid-connect/revoke")
                    .with(
                        "quarkus.oidc.introspection-path",
                        "protocol/openid-connect/token/introspect",
                    )
                    .with(
                        "quarkus.oidc.user-info-path",
                        "protocol/openid-connect/userinfo",
                    )
                    .with(
                        "quarkus.oidc.end-session-path",
                        "protocol/openid-connect/logout",
                    )
                    .with("quarkus.oidc.client-id", "orders-service")
                    .with("quarkus.oidc.client-name", "Orders Service")
                    .with("quarkus.oidc.credentials.secret", "orders-secret")
                    .with("quarkus.oidc.credentials.client-secret.method", "post")
                    .with("quarkus.oidc.introspection-credentials.name", "introspect")
                    .with(
                        "quarkus.oidc.introspection-credentials.secret",
                        "introspect-secret",
                    )
                    .with(
                        "quarkus.oidc.introspection-credentials.include-client-id",
                        "false",
                    )
                    .with("quarkus.oidc.tenant-id", "orders-tenant")
                    .with("quarkus.oidc.public-key", "configured-public-key")
                    .with("quarkus.oidc.application-type", "hybrid")
                    .with("quarkus.oidc.token.audience", "orders-api")
                    .with("quarkus.oidc.token.token-type", "bearer")
                    .with("quarkus.oidc.token.signature-algorithm", "rs256")
                    .with(
                        "quarkus.oidc.token.decryption-key-location",
                        "/etc/oidc/decryption.pem",
                    )
                    .with("quarkus.oidc.token.decrypt-id-token", "false")
                    .with("quarkus.oidc.token.decrypt-access-token", "false")
                    .with("quarkus.oidc.token.subject-required", "true")
                    .with("quarkus.oidc.token.issued-at-required", "false")
                    .with("quarkus.oidc.token.required-claims.org_id", "org_xyz")
                    .with("quarkus.oidc.token.required-claims.scope", "read,write")
                    .with(
                        "quarkus.oidc.token.required-claims.\"resource_access.orders.roles\"",
                        "orders-admin",
                    )
                    .with("quarkus.oidc.token.principal-claim", "email")
                    .with("quarkus.oidc.token.header", "x-access-token")
                    .with("quarkus.oidc.token.authorization-scheme", "Token")
                    .with("quarkus.oidc.token.lifespan-grace", "5")
                    .with("quarkus.oidc.token.age", "60s")
                    .with("quarkus.oidc.token.forced-jwk-refresh-interval", "30s")
                    .with("quarkus.oidc.token.allow-jwt-introspection", "false")
                    .with("quarkus.oidc.token.require-jwt-introspection-only", "true")
                    .with(
                        "quarkus.oidc.token.allow-opaque-token-introspection",
                        "false",
                    )
                    .with(
                        "quarkus.oidc.token.verify-access-token-with-user-info",
                        "true",
                    )
                    .with("quarkus.oidc.token.binding.certificate", "true")
                    .with(
                        "quarkus.oidc.roles.role-claim-path",
                        "resource_access.api.roles",
                    )
                    .with("quarkus.oidc.roles.source", "userinfo")
                    .with("quarkus.oidc.roles.role-claim-separator", "|"),
            )
            .build();

        let oidc = OidcConfig::from_config(&config).expect("config should load");

        assert_eq!(
            oidc,
            OidcConfig {
                enabled: true,
                tenant_enabled: true,
                resolve_tenants_with_issuer: true,
                auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
                provider: Some(WellKnownProvider::Github),
                connection_timeout: Duration::from_secs(2),
                discovery_enabled: false,
                discovery_path: "custom-discovery".to_owned(),
                jwks_path: Some("protocol/openid-connect/certs".to_owned()),
                authorization_path: Some("protocol/openid-connect/auth".to_owned()),
                token_path: Some("protocol/openid-connect/token".to_owned()),
                registration_path: Some("clients-registrations/openid-connect".to_owned()),
                revoke_path: Some("protocol/openid-connect/revoke".to_owned()),
                introspection_path: Some("protocol/openid-connect/token/introspect".to_owned()),
                user_info_path: Some("protocol/openid-connect/userinfo".to_owned()),
                end_session_path: Some("protocol/openid-connect/logout".to_owned()),
                client_id: Some("orders-service".to_owned()),
                client_name: Some("Orders Service".to_owned()),
                tenant_id: Some("orders-tenant".to_owned()),
                tenant_paths: None,
                public_key: Some("configured-public-key".to_owned()),
                application_type: ApplicationType::Hybrid,
                credentials: OidcCredentialsConfig {
                    secret: Some("orders-secret".to_owned()),
                    client_secret: OidcClientSecretConfig {
                        value: None,
                        method: ClientSecretMethod::Post,
                    },
                },
                introspection_credentials: OidcIntrospectionCredentialsConfig {
                    name: Some("introspect".to_owned()),
                    secret: Some("introspect-secret".to_owned()),
                    include_client_id: false,
                },
                token: OidcTokenConfig {
                    issuer: None,
                    audience: Some("orders-api".to_owned()),
                    token_type: Some("bearer".to_owned()),
                    signature_algorithm: Some(TokenSignatureAlgorithm::Rs256),
                    decryption_key_location: Some("/etc/oidc/decryption.pem".to_owned()),
                    decrypt_id_token: Some(false),
                    decrypt_access_token: false,
                    subject_required: true,
                    issued_at_required: false,
                    required_claims: HashMap::from([
                        ("org_id".to_owned(), vec!["org_xyz".to_owned()]),
                        (
                            "scope".to_owned(),
                            vec!["read".to_owned(), "write".to_owned()],
                        ),
                        (
                            "resource_access.orders.roles".to_owned(),
                            vec!["orders-admin".to_owned()],
                        ),
                    ]),
                    principal_claim: Some("email".to_owned()),
                    header: "x-access-token".to_owned(),
                    authorization_scheme: "Token".to_owned(),
                    lifespan_grace: Some(5),
                    age: Some(Duration::from_secs(60)),
                    forced_jwk_refresh_interval: Duration::from_secs(30),
                    allow_jwt_introspection: false,
                    require_jwt_introspection_only: true,
                    allow_opaque_token_introspection: false,
                    verify_access_token_with_user_info: true,
                    binding: OidcTokenBindingConfig { certificate: true },
                },
                roles: OidcRolesConfig {
                    source: RolesSource::UserInfo,
                    role_claim_path: "resource_access.api.roles".to_owned(),
                    role_claim_separator: "|".to_owned(),
                },
            }
        );
    }

    #[test]
    fn config_rejects_unknown_roles_source() {
        let config = Config::builder()
            .add_source(MapSource::new("test", 100).with("quarkus.oidc.roles.source", "session"))
            .build();

        let error = OidcConfig::from_config(&config).expect_err("roles source should be rejected");

        assert!(
            error
                .to_string()
                .contains("expected one of `accesstoken`, `idtoken`, or `userinfo`"),
            "{error}"
        );
    }

    #[test]
    fn config_rejects_empty_role_claim_path() {
        let config = Config::builder()
            .add_source(
                MapSource::new("empty-role-claim-path", 100)
                    .with("quarkus.oidc.roles.role-claim-path", " , "),
            )
            .build();

        let error =
            OidcConfig::from_config(&config).expect_err("empty role claim path should be rejected");

        assert!(
            error
                .to_string()
                .contains("quarkus.oidc.roles.role-claim-path"),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("role-claim-path must include at least one claim path"),
            "{error}"
        );
    }

    #[test]
    fn config_loads_id_token_roles_source() {
        let config = Config::builder()
            .add_source(MapSource::new("test", 100).with("quarkus.oidc.roles.source", "idtoken"))
            .build();

        let oidc = OidcConfig::from_config(&config).expect("config should load");

        assert_eq!(oidc.roles.source, RolesSource::IdToken);
    }

    #[test]
    fn config_defaults_token_binding_certificate_to_false() {
        let config = Config::builder()
            .add_source(MapSource::new("test", 100))
            .build();

        let oidc = OidcConfig::from_config(&config).expect("config should load");

        assert!(!oidc.token.binding.certificate);
    }

    #[test]
    fn config_rejects_unknown_provider() {
        let config = Config::builder()
            .add_source(MapSource::new("test", 100).with("quarkus.oidc.provider", "custom"))
            .build();

        let error = OidcConfig::from_config(&config).expect_err("provider should be rejected");

        assert!(
            error
                .to_string()
                .contains("expected one of `apple`, `discord`, `facebook`"),
            "{error}"
        );
    }

    #[test]
    fn config_loads_client_secret_value() {
        let config = Config::builder()
            .add_source(MapSource::new("test", 100).with(
                "quarkus.oidc.credentials.client-secret.value",
                "orders-secret",
            ))
            .build();

        let oidc = OidcConfig::from_config(&config).expect("config should load");

        assert_eq!(
            oidc.credentials.effective_client_secret(),
            Some("orders-secret")
        );
    }

    #[test]
    fn config_prefers_credentials_secret_over_client_secret_value() {
        let config = Config::builder()
            .add_source(
                MapSource::new("test", 100)
                    .with("quarkus.oidc.credentials.secret", "primary-secret")
                    .with(
                        "quarkus.oidc.credentials.client-secret.value",
                        "fallback-secret",
                    ),
            )
            .build();

        let oidc = OidcConfig::from_config(&config).expect("config should load");

        assert_eq!(
            oidc.credentials.effective_client_secret(),
            Some("primary-secret")
        );
    }

    #[test]
    fn config_rejects_empty_credentials_secret() {
        let config = Config::builder()
            .add_source(
                MapSource::new("empty-credentials-secret", 100)
                    .with("quarkus.oidc.credentials.secret", " "),
            )
            .build();

        let error = OidcConfig::from_config(&config)
            .expect_err("empty credentials secret should be rejected");

        assert!(
            error
                .to_string()
                .contains("quarkus.oidc.credentials.secret"),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("value must not be empty when configured"),
            "{error}"
        );
    }

    #[test]
    fn config_rejects_empty_client_secret_value() {
        let config = Config::builder()
            .add_source(
                MapSource::new("empty-client-secret-value", 100)
                    .with("quarkus.oidc.credentials.client-secret.value", " "),
            )
            .build();

        let error = OidcConfig::from_config(&config)
            .expect_err("empty client secret value should be rejected");

        assert!(
            error
                .to_string()
                .contains("quarkus.oidc.credentials.client-secret.value"),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("value must not be empty when configured"),
            "{error}"
        );
    }

    #[test]
    fn config_loads_introspection_credentials() {
        let config = Config::builder()
            .add_source(
                MapSource::new("test", 100)
                    .with("quarkus.oidc.introspection-credentials.name", "introspect")
                    .with(
                        "quarkus.oidc.introspection-credentials.secret",
                        "introspect-secret",
                    )
                    .with(
                        "quarkus.oidc.introspection-credentials.include-client-id",
                        "false",
                    ),
            )
            .build();

        let oidc = OidcConfig::from_config(&config).expect("config should load");

        assert_eq!(
            oidc.introspection_credentials,
            OidcIntrospectionCredentialsConfig {
                name: Some("introspect".to_owned()),
                secret: Some("introspect-secret".to_owned()),
                include_client_id: false,
            }
        );
    }

    #[test]
    fn config_rejects_empty_introspection_credentials_name() {
        let config = Config::builder()
            .add_source(
                MapSource::new("empty-introspection-name", 100)
                    .with("quarkus.oidc.introspection-credentials.name", " "),
            )
            .build();

        let error = OidcConfig::from_config(&config)
            .expect_err("empty introspection credentials name should be rejected");

        assert!(
            error
                .to_string()
                .contains("quarkus.oidc.introspection-credentials.name"),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("value must not be empty when configured"),
            "{error}"
        );
    }

    #[test]
    fn config_rejects_empty_introspection_credentials_secret() {
        let config = Config::builder()
            .add_source(
                MapSource::new("empty-introspection-secret", 100)
                    .with("quarkus.oidc.introspection-credentials.secret", " "),
            )
            .build();

        let error = OidcConfig::from_config(&config)
            .expect_err("empty introspection credentials secret should be rejected");

        assert!(
            error
                .to_string()
                .contains("quarkus.oidc.introspection-credentials.secret"),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("value must not be empty when configured"),
            "{error}"
        );
    }

    #[test]
    fn config_loads_query_client_secret_method() {
        let config = Config::builder()
            .add_source(
                MapSource::new("test", 100)
                    .with("quarkus.oidc.credentials.client-secret.method", "query"),
            )
            .build();

        let oidc = OidcConfig::from_config(&config).expect("config should load");

        assert_eq!(
            oidc.credentials.client_secret.method,
            ClientSecretMethod::Query
        );
    }

    #[test]
    fn config_rejects_unknown_client_secret_method() {
        let config = Config::builder()
            .add_source(
                MapSource::new("test", 100)
                    .with("quarkus.oidc.credentials.client-secret.method", "post-jwt"),
            )
            .build();

        let error =
            OidcConfig::from_config(&config).expect_err("client secret method should be rejected");

        assert!(
            error
                .to_string()
                .contains("expected one of `basic`, `post`, or `query`"),
            "{error}"
        );
    }

    #[test]
    fn config_loads_application_type_case_insensitively() {
        let config = Config::builder()
            .add_source(
                MapSource::new("test", 100).with("quarkus.oidc.application-type", "WEB-APP"),
            )
            .build();

        let oidc = OidcConfig::from_config(&config).expect("config should load");

        assert_eq!(oidc.application_type, ApplicationType::WebApp);
    }

    #[test]
    fn config_loads_hybrid_application_type() {
        let config = Config::builder()
            .add_source(MapSource::new("test", 100).with("quarkus.oidc.application-type", "hybrid"))
            .build();

        let oidc = OidcConfig::from_config(&config).expect("config should load");

        assert_eq!(oidc.application_type, ApplicationType::Hybrid);
    }

    #[test]
    fn config_rejects_invalid_token_header() {
        let config = Config::builder()
            .add_source(
                MapSource::new("test", 100).with("quarkus.oidc.token.header", "not a header"),
            )
            .build();

        let error = match OidcConfig::from_config(&config) {
            Err(error) => error,
            Ok(_) => panic!("token header should be rejected"),
        };

        assert!(
            error.to_string().contains("quarkus.oidc.token.header"),
            "{error}"
        );
    }

    #[test]
    fn config_loads_valid_authorization_scheme() {
        let config = Config::builder()
            .add_source(
                MapSource::new("test", 100).with("quarkus.oidc.token.authorization-scheme", "DPoP"),
            )
            .build();

        let oidc = OidcConfig::from_config(&config).expect("config should load");

        assert_eq!(oidc.token.authorization_scheme, "DPoP");
    }

    #[test]
    fn config_defaults_token_header_to_authorization() {
        let config = Config::builder()
            .add_source(MapSource::new("test", 100))
            .build();

        let oidc = OidcConfig::from_config(&config).expect("config should load");

        assert_eq!(oidc.token.header, "Authorization");
    }

    #[test]
    fn config_rejects_invalid_authorization_scheme() {
        for scheme in ["Bearer Token", "Bearer/Token"] {
            let config = Config::builder()
                .add_source(
                    MapSource::new("test", 100)
                        .with("quarkus.oidc.token.authorization-scheme", scheme),
                )
                .build();

            let error = OidcConfig::from_config(&config)
                .expect_err("authorization scheme should be rejected");

            assert!(
                error
                    .to_string()
                    .contains("quarkus.oidc.token.authorization-scheme"),
                "{error}"
            );
            assert!(
                error
                    .to_string()
                    .contains("authorization scheme must be a non-empty HTTP token"),
                "{error}"
            );
        }
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
    async fn default_authorization_scheme_is_case_insensitive() {
        let response = app(oidc())
            .oneshot(request("/protected", Some("bearer test-token")))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn configured_authorization_scheme_is_case_insensitive() {
        let response = app(Oidc::builder(OidcConfig {
            token: OidcTokenConfig {
                authorization_scheme: "Token".to_owned(),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        })
        .validator(StaticTokenValidator::bearer("test-token", "alice"))
        .build())
        .oneshot(request("/protected", Some("token test-token")))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn configured_authorization_scheme_is_used_in_missing_token_challenge() {
        let response = app(Oidc::builder(OidcConfig {
            token: OidcTokenConfig {
                authorization_scheme: "Token".to_owned(),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        })
        .validator(StaticTokenValidator::bearer("test-token", "alice"))
        .build())
        .oneshot(request("/protected", None))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(WWW_AUTHENTICATE).unwrap(),
            HeaderValue::from_static("Token")
        );
    }

    #[tokio::test]
    async fn configured_authorization_scheme_is_used_in_invalid_token_challenge() {
        let response = app(Oidc::builder(OidcConfig {
            token: OidcTokenConfig {
                authorization_scheme: "Token".to_owned(),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        })
        .validator(StaticTokenValidator::bearer("test-token", "alice"))
        .build())
        .oneshot(request("/protected", Some("Token wrong-token")))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(WWW_AUTHENTICATE).unwrap(),
            HeaderValue::from_static(r#"Token error="invalid_token""#)
        );
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
                header: "x-access-token".to_owned(),
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
    async fn configured_authorization_token_header_uses_scheme() {
        let response = app(Oidc::builder(OidcConfig {
            token: OidcTokenConfig {
                header: "Authorization".to_owned(),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        })
        .validator(StaticTokenValidator::bearer("test-token", "alice"))
        .build())
        .oneshot(request("/protected", Some("Bearer test-token")))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn configured_authorization_token_header_respects_custom_scheme() {
        let response = app(Oidc::builder(OidcConfig {
            token: OidcTokenConfig {
                header: "Authorization".to_owned(),
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
    async fn introspection_validator_accepts_active_token_and_extracts_roles() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            client_id: Some("orders-service".to_owned()),
            token: OidcTokenConfig {
                audience: Some("orders-api".to_owned()),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let validator = IntrospectionValidator::new(
            |token: Arc<str>| async move {
                assert_eq!(token.as_ref(), "opaque-token");
                Ok(IntrospectionResponse::from_json(
                    r#"{
                        "active": true,
                        "sub": "alice",
                        "iss": "https://issuer.example/realms/app",
                        "aud": ["orders-api"],
                        "iat": 1700000000,
                        "groups": ["orders-user"],
                        "realm_access": {
                            "roles": ["realm-admin"]
                        },
                        "resource_access": {
                            "orders-service": {
                                "roles": ["orders-admin"]
                            }
                        }
                    }"#,
                )
                .expect("introspection response should parse"))
            },
            &config,
        );

        let principal = validator
            .validate(Arc::from("opaque-token"))
            .await
            .expect("active token should validate");

        assert_eq!(principal.subject(), "alice");
        assert_eq!(
            principal.issuer(),
            Some("https://issuer.example/realms/app")
        );
        assert_eq!(principal.audience().collect::<Vec<_>>(), vec!["orders-api"]);
        assert_eq!(
            principal.groups().collect::<Vec<_>>(),
            vec!["orders-user", "realm-admin", "orders-admin"]
        );
    }

    #[tokio::test]
    async fn introspection_validator_rejects_inactive_token() {
        let validator = IntrospectionValidator::new(
            |_token: Arc<str>| async move { Ok(IntrospectionResponse::default()) },
            &OidcConfig::default(),
        );

        let error = validator
            .validate(Arc::from("opaque-token"))
            .await
            .expect_err("inactive token should be rejected");

        assert!(
            error.to_string().contains("introspection is not active"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn introspection_validator_applies_configured_audience() {
        let config = OidcConfig {
            token: OidcTokenConfig {
                audience: Some("orders-api".to_owned()),
                issued_at_required: false,
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let validator = IntrospectionValidator::new(
            |_token: Arc<str>| async move {
                Ok(IntrospectionResponse::from_json(
                    r#"{
                        "active": true,
                        "sub": "alice",
                        "aud": "inventory-api"
                    }"#,
                )
                .expect("introspection response should parse"))
            },
            &config,
        );

        let error = validator
            .validate(Arc::from("opaque-token"))
            .await
            .expect_err("wrong audience should be rejected");

        assert!(
            error
                .to_string()
                .contains("introspection audience did not include"),
            "{error}"
        );
    }

    #[test]
    fn introspection_request_uses_basic_auth_when_client_secret_is_configured() {
        let request = introspection_request(
            &reqwest::Client::new(),
            "https://issuer.example/realms/app/protocol/openid-connect/token/introspect",
            "opaque-token",
            IntrospectionRequestAuth {
                client_id: Some("orders-service"),
                client_auth_name: Some("orders-service"),
                client_secret: Some("orders-secret"),
                client_secret_method: ClientSecretMethod::Basic,
                include_client_id: false,
            },
        )
        .build()
        .expect("request should build");

        assert_eq!(
            request.headers().get(AUTHORIZATION),
            Some(&HeaderValue::from_static(
                "Basic b3JkZXJzLXNlcnZpY2U6b3JkZXJzLXNlY3JldA=="
            ))
        );
    }

    #[test]
    fn introspection_request_can_include_client_id_with_basic_auth() {
        let request = introspection_request(
            &reqwest::Client::new(),
            "https://issuer.example/realms/app/protocol/openid-connect/token/introspect",
            "opaque-token",
            IntrospectionRequestAuth {
                client_id: Some("orders-service"),
                client_auth_name: Some("introspect"),
                client_secret: Some("introspect-secret"),
                client_secret_method: ClientSecretMethod::Basic,
                include_client_id: true,
            },
        )
        .build()
        .expect("request should build");
        let body = request
            .body()
            .and_then(reqwest::Body::as_bytes)
            .and_then(|body| std::str::from_utf8(body).ok())
            .expect("request body should be buffered form data");

        assert_eq!(
            request.headers().get(AUTHORIZATION),
            Some(&HeaderValue::from_static(
                "Basic aW50cm9zcGVjdDppbnRyb3NwZWN0LXNlY3JldA=="
            ))
        );
        assert!(body.contains("token=opaque-token"), "{body}");
        assert!(body.contains("client_id=orders-service"), "{body}");
    }

    #[test]
    fn introspection_request_posts_client_secret_when_configured() {
        let request = introspection_request(
            &reqwest::Client::new(),
            "https://issuer.example/realms/app/protocol/openid-connect/token/introspect",
            "opaque-token",
            IntrospectionRequestAuth {
                client_id: Some("orders-service"),
                client_auth_name: Some("orders-service"),
                client_secret: Some("orders-secret"),
                client_secret_method: ClientSecretMethod::Post,
                include_client_id: false,
            },
        )
        .build()
        .expect("request should build");
        let body = request
            .body()
            .and_then(reqwest::Body::as_bytes)
            .and_then(|body| std::str::from_utf8(body).ok())
            .expect("request body should be buffered form data");

        assert!(!request.headers().contains_key(AUTHORIZATION));
        assert!(body.contains("token=opaque-token"), "{body}");
        assert!(body.contains("client_id=orders-service"), "{body}");
        assert!(body.contains("client_secret=orders-secret"), "{body}");
    }

    #[test]
    fn introspection_request_uses_query_client_secret_when_configured() {
        let request = introspection_request(
            &reqwest::Client::new(),
            "https://issuer.example/realms/app/protocol/openid-connect/token/introspect",
            "opaque-token",
            IntrospectionRequestAuth {
                client_id: Some("orders-service"),
                client_auth_name: Some("orders-service"),
                client_secret: Some("orders-secret"),
                client_secret_method: ClientSecretMethod::Query,
                include_client_id: false,
            },
        )
        .build()
        .expect("request should build");
        let body = request
            .body()
            .and_then(reqwest::Body::as_bytes)
            .and_then(|body| std::str::from_utf8(body).ok())
            .expect("request body should be buffered form data");
        let query = request.url().query().expect("query should be present");

        assert!(!request.headers().contains_key(AUTHORIZATION));
        assert!(body.contains("token=opaque-token"), "{body}");
        assert!(!body.contains("client_id="), "{body}");
        assert!(!body.contains("client_secret="), "{body}");
        assert!(query.contains("client_id=orders-service"), "{query}");
        assert!(query.contains("client_secret=orders-secret"), "{query}");
    }

    #[test]
    fn introspection_request_skips_basic_auth_without_client_secret() {
        let request = introspection_request(
            &reqwest::Client::new(),
            "https://issuer.example/realms/app/protocol/openid-connect/token/introspect",
            "opaque-token",
            IntrospectionRequestAuth {
                client_id: Some("orders-service"),
                client_auth_name: Some("orders-service"),
                client_secret: None,
                client_secret_method: ClientSecretMethod::Basic,
                include_client_id: false,
            },
        )
        .build()
        .expect("request should build");

        assert!(!request.headers().contains_key(AUTHORIZATION));
    }

    #[test]
    fn http_introspector_uses_client_secret_value() {
        let config = OidcConfig {
            client_id: Some("orders-service".to_owned()),
            credentials: OidcCredentialsConfig {
                client_secret: OidcClientSecretConfig {
                    value: Some("orders-secret".to_owned()),
                    ..OidcClientSecretConfig::default()
                },
                ..OidcCredentialsConfig::default()
            },
            ..OidcConfig::default()
        };
        let introspector = http_token_introspector(
            &config,
            reqwest::Client::new(),
            "https://issuer.example/realms/app/protocol/openid-connect/token/introspect".to_owned(),
        );

        assert_eq!(introspector.client_secret.as_deref(), Some("orders-secret"));
    }

    #[test]
    fn http_introspector_uses_introspection_credentials() {
        let config = OidcConfig {
            client_id: Some("orders-service".to_owned()),
            credentials: OidcCredentialsConfig {
                secret: Some("orders-secret".to_owned()),
                client_secret: OidcClientSecretConfig {
                    method: ClientSecretMethod::Query,
                    ..OidcClientSecretConfig::default()
                },
            },
            introspection_credentials: OidcIntrospectionCredentialsConfig {
                name: Some("introspect".to_owned()),
                secret: Some("introspect-secret".to_owned()),
                include_client_id: true,
            },
            ..OidcConfig::default()
        };
        let introspector = http_token_introspector(
            &config,
            reqwest::Client::new(),
            "https://issuer.example/realms/app/protocol/openid-connect/token/introspect".to_owned(),
        );

        assert_eq!(introspector.client_auth_name.as_deref(), Some("introspect"));
        assert_eq!(
            introspector.client_secret.as_deref(),
            Some("introspect-secret")
        );
        assert_eq!(introspector.client_secret_method, ClientSecretMethod::Basic);
        assert!(introspector.include_client_id);
    }

    #[tokio::test]
    async fn introspection_fallback_uses_primary_jwt_validator_first() {
        let validator = IntrospectionFallbackValidator::new(
            StaticTokenValidator::bearer("jwt-token", "alice"),
            StaticTokenValidator::bearer("opaque-token", "bob"),
            &OidcConfig::default(),
        );

        let principal = validator
            .validate(Arc::from("jwt-token"))
            .await
            .expect("primary validator should accept token");

        assert_eq!(principal.subject(), "alice");
    }

    #[tokio::test]
    async fn introspection_fallback_accepts_opaque_token_when_enabled() {
        let validator = IntrospectionFallbackValidator::new(
            StaticTokenValidator::bearer("jwt-token", "alice"),
            StaticTokenValidator::bearer("opaque-token", "bob"),
            &OidcConfig::default(),
        );

        let principal = validator
            .validate(Arc::from("opaque-token"))
            .await
            .expect("opaque token should fall back to introspection");

        assert_eq!(principal.subject(), "bob");
    }

    #[tokio::test]
    async fn introspection_fallback_rejects_opaque_token_when_disabled() {
        let config = OidcConfig {
            token: OidcTokenConfig {
                allow_opaque_token_introspection: false,
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let validator = IntrospectionFallbackValidator::new(
            StaticTokenValidator::bearer("jwt-token", "alice"),
            StaticTokenValidator::bearer("opaque-token", "bob"),
            &config,
        );

        let error = validator
            .validate(Arc::from("opaque-token"))
            .await
            .expect_err("opaque fallback should be disabled");

        assert!(error.to_string().contains("bearer token did not match"));
    }

    #[tokio::test]
    async fn introspection_fallback_rejects_jwt_token_when_jwt_introspection_disabled() {
        let config = OidcConfig {
            token: OidcTokenConfig {
                allow_jwt_introspection: false,
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let validator = IntrospectionFallbackValidator::new(
            StaticTokenValidator::bearer("jwt-token", "alice"),
            StaticTokenValidator::bearer("a.b.c", "bob"),
            &config,
        );

        let error = validator
            .validate(Arc::from("a.b.c"))
            .await
            .expect_err("JWT fallback should be disabled");

        assert!(error.to_string().contains("bearer token did not match"));
    }

    #[tokio::test]
    async fn user_info_validator_accepts_response_and_extracts_roles() {
        let config = OidcConfig {
            client_id: Some("orders-service".to_owned()),
            token: OidcTokenConfig {
                principal_claim: Some("preferred_username".to_owned()),
                ..OidcTokenConfig::default()
            },
            roles: OidcRolesConfig {
                source: RolesSource::UserInfo,
                ..OidcRolesConfig::default()
            },
            ..OidcConfig::default()
        };
        let validator = UserInfoValidator::new(
            |token: Arc<str>| async move {
                assert_eq!(token.as_ref(), "opaque-token");
                Ok(UserInfoResponse::from_json(
                    r#"{
                        "sub": "alice-subject",
                        "preferred_username": "alice",
                        "groups": ["orders-user"],
                        "realm_access": {
                            "roles": ["realm-admin"]
                        },
                        "resource_access": {
                            "orders-service": {
                                "roles": ["orders-admin"]
                            }
                        }
                    }"#,
                )
                .expect("UserInfo response should parse"))
            },
            &config,
        );

        let principal = validator
            .validate(Arc::from("opaque-token"))
            .await
            .expect("UserInfo response should validate");

        assert_eq!(principal.subject(), "alice");
        assert_eq!(
            principal.groups().collect::<Vec<_>>(),
            vec!["orders-user", "realm-admin", "orders-admin"]
        );
    }

    #[tokio::test]
    async fn user_info_validator_skips_roles_when_source_is_access_token() {
        let validator = UserInfoValidator::new(
            |_token: Arc<str>| async move {
                Ok(UserInfoResponse::from_json(
                    r#"{
                        "sub": "alice",
                        "groups": ["orders-admin"]
                    }"#,
                )
                .expect("UserInfo response should parse"))
            },
            &OidcConfig::default(),
        );

        let principal = validator
            .validate(Arc::from("opaque-token"))
            .await
            .expect("UserInfo response should validate");

        assert_eq!(principal.groups().collect::<Vec<_>>(), Vec::<&str>::new());
    }

    #[tokio::test]
    async fn user_info_validator_applies_required_claims() {
        let config = OidcConfig {
            token: OidcTokenConfig {
                required_claims: HashMap::from([(
                    "scope".to_owned(),
                    vec!["orders:read".to_owned()],
                )]),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let validator = UserInfoValidator::new(
            |_token: Arc<str>| async move {
                Ok(UserInfoResponse::from_json(
                    r#"{
                        "sub": "alice",
                        "scope": "orders:write"
                    }"#,
                )
                .expect("UserInfo response should parse"))
            },
            &config,
        );

        let error = validator
            .validate(Arc::from("opaque-token"))
            .await
            .expect_err("missing required claim should be rejected");

        assert!(
            error
                .to_string()
                .contains("claim `scope` did not include required value"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn user_info_roles_validator_preserves_jwt_validation() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                token_type: None,
                ..OidcTokenConfig::default()
            },
            roles: OidcRolesConfig {
                source: RolesSource::UserInfo,
                ..OidcRolesConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(TestClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            exp: 4_102_444_800,
            groups: vec!["token-role"],
            realm_access: RealmAccessClaims { roles: Vec::new() },
        });
        let validator = UserInfoRolesValidator::new(
            JwtValidator::hs256("secret", &config),
            |_token: Arc<str>| async move {
                Ok(UserInfoResponse::from_json(
                    r#"{
                        "sub": "alice",
                        "groups": ["orders-admin", "orders-user"]
                    }"#,
                )
                .expect("UserInfo response should parse"))
            },
            &config,
        );

        let principal = validator
            .validate(Arc::from(token))
            .await
            .expect("JWT and UserInfo roles should validate");

        assert_eq!(principal.subject(), "alice");
        assert_eq!(
            principal.groups().collect::<Vec<_>>(),
            vec!["orders-admin", "orders-user"]
        );
    }

    #[tokio::test]
    async fn user_info_roles_validator_rejects_subject_mismatch() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                token_type: None,
                ..OidcTokenConfig::default()
            },
            roles: OidcRolesConfig {
                source: RolesSource::UserInfo,
                ..OidcRolesConfig::default()
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
        let validator = UserInfoRolesValidator::new(
            JwtValidator::hs256("secret", &config),
            |_token: Arc<str>| async move {
                Ok(UserInfoResponse::from_json(
                    r#"{
                        "sub": "bob",
                        "groups": ["orders-admin"]
                    }"#,
                )
                .expect("UserInfo response should parse"))
            },
            &config,
        );

        let error = validator
            .validate(Arc::from(token))
            .await
            .expect_err("UserInfo subject mismatch should be rejected");

        assert!(
            error
                .to_string()
                .contains("UserInfo subject did not match access token subject"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn oidc_from_config_uses_public_key_for_local_jwt_verification() {
        let config = Config::builder()
            .add_source(
                MapSource::new("public-key", 100)
                    .with("quarkus.oidc.public-key", PUBLIC_RSA_KEY)
                    .with(
                        "quarkus.oidc.auth-server-url",
                        "https://issuer.example/realms/app",
                    )
                    .with("quarkus.oidc.token.audience", "orders-api"),
            )
            .build();
        let token = jwt_rs256(TestClaims {
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
            Oidc::from_config(&config)
                .expect("public key config should load")
                .build(),
        )
        .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn oidc_discover_from_config_builds_public_key_validator() {
        let config = Config::builder()
            .add_source(
                MapSource::new("public-key-discovery", 100)
                    .with("quarkus.oidc.public-key", PUBLIC_RSA_KEY)
                    .with(
                        "quarkus.oidc.auth-server-url",
                        "https://issuer.example/realms/app",
                    )
                    .with("quarkus.oidc.token.audience", "orders-api"),
            )
            .build();
        let token = jwt_rs256(TestClaims {
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
            Oidc::discover_from_config(&config)
                .await
                .expect("public key config should build without provider discovery"),
        )
        .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn oidc_discover_from_config_requires_auth_server_url_for_provider_discovery() {
        let config = Config::builder()
            .add_source(MapSource::new("provider-discovery", 100))
            .build();

        let error = match Oidc::discover_from_config(&config).await {
            Ok(_) => panic!("provider discovery should require an auth-server-url"),
            Err(error) => error,
        };

        assert!(matches!(error, BuildError::MissingAuthServerUrl));
    }

    #[tokio::test]
    async fn oidc_from_config_applies_http_authorization() {
        let config = Config::builder()
            .add_source(
                MapSource::new("authz", 100)
                    .with("quarkus.http.auth.permission.public.paths", "/public")
                    .with("quarkus.http.auth.permission.public.policy", "permit")
                    .with("quarkus.http.auth.permission.private.paths", "/private")
                    .with(
                        "quarkus.http.auth.permission.private.policy",
                        "authenticated",
                    ),
            )
            .build();
        let app = Router::new().fallback(|| async { "ok" }).layer(
            Oidc::from_config(&config)
                .expect("OIDC config should load")
                .validator(StaticTokenValidator::bearer("test-token", "alice"))
                .build()
                .layer(),
        );

        let response = app
            .clone()
            .oneshot(request("/public", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(request("/private", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn oidc_from_config_rejects_invalid_public_key() {
        let config = Config::builder()
            .add_source(
                MapSource::new("public-key", 100)
                    .with("quarkus.oidc.public-key", "not a pem public key"),
            )
            .build();

        let Err(error) = Oidc::from_config(&config) else {
            panic!("invalid public key should fail");
        };
        assert!(matches!(
            error,
            mp_config::ConfigError::Conversion { name, .. }
                if name == "quarkus.oidc.public-key"
        ));
    }

    #[test]
    fn oidc_from_config_ignores_public_key_when_disabled() {
        let config = Config::builder()
            .add_source(
                MapSource::new("disabled-public-key", 100)
                    .with("quarkus.oidc.enabled", "false")
                    .with("quarkus.oidc.public-key", "not a pem public key"),
            )
            .build();

        let _builder = Oidc::from_config(&config).expect("disabled OIDC should not parse key");
    }

    #[test]
    fn oidc_from_config_rejects_id_token_roles_source() {
        let config = Config::builder()
            .add_source(
                MapSource::new("idtoken-roles", 100)
                    .with("quarkus.oidc.public-key", PUBLIC_RSA_KEY)
                    .with("quarkus.oidc.roles.source", "idtoken"),
            )
            .build();

        let Err(error) = Oidc::from_config(&config) else {
            panic!("ID token roles should be rejected for bearer-service middleware");
        };
        assert!(matches!(
            error,
            mp_config::ConfigError::Conversion { ref name, .. }
                if name == "quarkus.oidc.roles.source"
        ));
        assert!(
            error
                .to_string()
                .contains("`idtoken` roles require web-app ID token support"),
            "{error}"
        );
    }

    #[test]
    fn oidc_from_config_rejects_web_app_application_type() {
        let config = Config::builder()
            .add_source(
                MapSource::new("web-app", 100)
                    .with("quarkus.oidc.public-key", PUBLIC_RSA_KEY)
                    .with("quarkus.oidc.application-type", "web-app"),
            )
            .build();

        let Err(error) = Oidc::from_config(&config) else {
            panic!("web-app should be rejected for bearer-service middleware");
        };
        assert!(matches!(
            error,
            mp_config::ConfigError::Conversion { ref name, .. }
                if name == "quarkus.oidc.application-type"
        ));
        assert!(
            error
                .to_string()
                .contains("`web-app` application type requires authorization-code flow support"),
            "{error}"
        );
    }

    #[test]
    fn oidc_from_config_rejects_token_binding_certificate() {
        let config = Config::builder()
            .add_source(
                MapSource::new("token-binding", 100)
                    .with("quarkus.oidc.token.binding.certificate", "true"),
            )
            .build();

        let Err(error) = Oidc::from_config(&config) else {
            panic!("certificate-bound tokens should be rejected for bearer-service middleware");
        };
        assert!(matches!(
            error,
            mp_config::ConfigError::Conversion { ref name, .. }
                if name == "quarkus.oidc.token.binding.certificate"
        ));
        assert!(
            error
                .to_string()
                .contains("requires client certificate thumbprint extraction"),
            "{error}"
        );
    }

    #[test]
    fn oidc_from_config_rejects_decrypt_access_token() {
        let config = Config::builder()
            .add_source(
                MapSource::new("decrypt-access-token", 100)
                    .with("quarkus.oidc.token.decrypt-access-token", "true"),
            )
            .build();

        let Err(error) = Oidc::from_config(&config) else {
            panic!("encrypted access tokens should be rejected until JWE support is implemented");
        };
        assert!(matches!(
            error,
            mp_config::ConfigError::Conversion { ref name, .. }
                if name == "quarkus.oidc.token.decrypt-access-token"
        ));
        assert!(
            error
                .to_string()
                .contains("requires JWE access-token decryption"),
            "{error}"
        );
    }

    #[test]
    fn oidc_from_config_rejects_decrypt_id_token() {
        let config = Config::builder()
            .add_source(
                MapSource::new("decrypt-id-token", 100)
                    .with("quarkus.oidc.token.decrypt-id-token", "true"),
            )
            .build();

        let Err(error) = Oidc::from_config(&config) else {
            panic!("encrypted ID tokens should be rejected until web-app support is implemented");
        };
        assert!(matches!(
            error,
            mp_config::ConfigError::Conversion { ref name, .. }
                if name == "quarkus.oidc.token.decrypt-id-token"
        ));
        assert!(
            error
                .to_string()
                .contains("requires web-app ID token decryption"),
            "{error}"
        );
    }

    #[test]
    fn oidc_from_config_accepts_hybrid_application_type() {
        let config = Config::builder()
            .add_source(
                MapSource::new("hybrid", 100)
                    .with("quarkus.oidc.public-key", PUBLIC_RSA_KEY)
                    .with("quarkus.oidc.application-type", "hybrid"),
            )
            .build();

        let _builder = Oidc::from_config(&config).expect("hybrid should support bearer middleware");
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
    async fn jwt_validator_extracts_default_client_resource_roles() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            client_id: Some("orders-service".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                token_type: None,
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(ClientResourceRoleClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            exp: 4_102_444_800,
            resource_access: ClientResourceAccessClaims {
                orders_service: ResourceRolesClaims {
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
    async fn jwt_validator_extracts_quoted_namespace_role_claim_path() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                token_type: None,
                ..OidcTokenConfig::default()
            },
            roles: OidcRolesConfig {
                role_claim_path: "\"https://claims.example/roles\"".to_owned(),
                ..OidcRolesConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(NamespacedRoleClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            exp: 4_102_444_800,
            namespaced_roles: vec!["orders-admin", "orders-user"],
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
                source: RolesSource::AccessToken,
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
    async fn jwt_validator_skips_roles_when_source_is_user_info() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                token_type: None,
                ..OidcTokenConfig::default()
            },
            roles: OidcRolesConfig {
                source: RolesSource::UserInfo,
                ..OidcRolesConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(TestClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            exp: 4_102_444_800,
            groups: vec!["orders-admin"],
            realm_access: RealmAccessClaims {
                roles: vec!["realm-admin"],
            },
        });

        let principal = JwtValidator::hs256("secret", &config)
            .validate(Arc::from(token))
            .await
            .expect("JWT should validate");

        assert_eq!(principal.groups().collect::<Vec<_>>(), Vec::<&str>::new());
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
    async fn jwt_validator_uses_configured_principal_claim_path() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                principal_claim: Some("profile.email".to_owned()),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt(ProfilePrincipalClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            profile: ProfileClaims {
                email: "alice@orders.example",
            },
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
    async fn jwt_validator_does_not_require_audience_when_unconfigured() {
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
    async fn jwt_validator_does_not_use_client_id_as_default_audience() {
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
    async fn jwt_validator_accepts_configured_header_token_type() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                token_type: Some("at+jwt".to_owned()),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt_with_header_type(
            "at+jwt",
            TestClaims {
                sub: "alice",
                iss: "https://issuer.example/realms/app",
                aud: "orders-api",
                exp: 4_102_444_800,
                groups: Vec::new(),
                realm_access: RealmAccessClaims { roles: Vec::new() },
            },
        );

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
    async fn jwt_validator_accepts_space_separated_required_claim_values() {
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
        let token = jwt(StringScopeClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            scope: "read write delete",
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
    async fn jwt_validator_accepts_nested_required_claim_values() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                required_claims: HashMap::from([(
                    "resource_access.orders.roles".to_owned(),
                    vec!["orders-admin".to_owned()],
                )]),
                ..OidcTokenConfig::default()
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
    async fn jwt_validator_loads_quoted_nested_required_claims_from_config() {
        let config = Config::builder()
            .add_source(
                MapSource::new("quoted-required-claims", 100)
                    .with(
                        "quarkus.oidc.auth-server-url",
                        "https://issuer.example/realms/app",
                    )
                    .with("quarkus.oidc.token.audience", "orders-api")
                    .with(
                        "quarkus.oidc.token.required-claims.\"resource_access.orders.roles\"",
                        "orders-admin",
                    ),
            )
            .build();
        let config = OidcConfig::from_config(&config).expect("OIDC config should load");
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
    async fn jwt_validator_loads_slash_separated_required_claims_from_config() {
        let config = Config::builder()
            .add_source(
                MapSource::new("slash-required-claims", 100)
                    .with(
                        "quarkus.oidc.auth-server-url",
                        "https://issuer.example/realms/app",
                    )
                    .with("quarkus.oidc.token.audience", "orders-api")
                    .with(
                        "quarkus.oidc.token.required-claims.\"resource_access/orders/roles\"",
                        "orders-admin",
                    ),
            )
            .build();
        let config = OidcConfig::from_config(&config).expect("OIDC config should load");
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

    #[test]
    fn config_rejects_empty_required_claim_values() {
        let config = Config::builder()
            .add_source(
                MapSource::new("empty-required-claims", 100)
                    .with("quarkus.oidc.token.required-claims.scope", " , "),
            )
            .build();

        let error = OidcConfig::from_config(&config)
            .expect_err("empty required claim values should be rejected");

        assert!(
            error
                .to_string()
                .contains("quarkus.oidc.token.required-claims.scope"),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("required claims must include at least one expected value"),
            "{error}"
        );
    }

    #[test]
    fn config_rejects_empty_token_audience() {
        let config = Config::builder()
            .add_source(
                MapSource::new("empty-token-audience", 100)
                    .with("quarkus.oidc.token.audience", " , "),
            )
            .build();

        let error =
            OidcConfig::from_config(&config).expect_err("empty token audience should be rejected");

        assert!(
            error.to_string().contains("quarkus.oidc.token.audience"),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("token audience must include at least one audience"),
            "{error}"
        );
    }

    #[test]
    fn config_rejects_empty_token_type() {
        let config = Config::builder()
            .add_source(
                MapSource::new("empty-token-type", 100).with("quarkus.oidc.token.token-type", " "),
            )
            .build();

        let error =
            OidcConfig::from_config(&config).expect_err("empty token type should be rejected");

        assert!(
            error.to_string().contains("quarkus.oidc.token.token-type"),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("value must not be empty when configured"),
            "{error}"
        );
    }

    #[test]
    fn config_rejects_empty_principal_claim() {
        let config = Config::builder()
            .add_source(
                MapSource::new("empty-principal-claim", 100)
                    .with("quarkus.oidc.token.principal-claim", " "),
            )
            .build();

        let error =
            OidcConfig::from_config(&config).expect_err("empty principal claim should be rejected");

        assert!(
            error
                .to_string()
                .contains("quarkus.oidc.token.principal-claim"),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("value must not be empty when configured"),
            "{error}"
        );
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
    async fn jwt_validator_rejects_missing_iat_by_default() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt_without_iat(TestClaims {
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
    async fn jwt_validator_accepts_missing_iat_when_not_required() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                issued_at_required: false,
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let token = jwt_without_iat(TestClaims {
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

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn jwt_validator_rejects_future_iat_beyond_lifespan_grace() {
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
            exp: now + 60,
            iat: now + 10,
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
        let token = jwt_without_iat(TestClaims {
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

    #[tokio::test]
    async fn refreshable_jwks_throttles_forced_refreshes() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                token_type: None,
                forced_jwk_refresh_interval: Duration::from_secs(600),
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        };
        let refreshes = Arc::new(Mutex::new(0usize));
        let refreshed = rotated_jwks();
        let provider_refreshes = refreshes.clone();
        let validator = JwtValidator::refreshable_jwks(
            test_jwks(),
            move || {
                let refreshed = refreshed.clone();
                let provider_refreshes = provider_refreshes.clone();
                async move {
                    let mut refreshes = provider_refreshes
                        .lock()
                        .expect("refresh counter should not be poisoned");
                    *refreshes += 1;
                    Ok(refreshed)
                }
            },
            &config,
        );
        let token = jwt_with_kid(
            "missing-key",
            TestClaims {
                sub: "alice",
                iss: "https://issuer.example/realms/app",
                aud: "orders-api",
                exp: 4_102_444_800,
                groups: Vec::new(),
                realm_access: RealmAccessClaims { roles: Vec::new() },
            },
        );

        for _ in 0..2 {
            let response = app(Oidc::builder(config.clone())
                .validator(validator.clone())
                .build())
            .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
            .await
            .expect("request should complete");
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        assert_eq!(
            *refreshes
                .lock()
                .expect("refresh counter should not be poisoned"),
            1
        );
    }

    #[test]
    fn discovery_url_appends_well_known_path() {
        assert_eq!(
            discovery_url(
                "https://issuer.example/realms/app",
                ".well-known/openid-configuration"
            )
            .expect("discovery URL should parse")
            .as_str(),
            "https://issuer.example/realms/app/.well-known/openid-configuration"
        );
        assert_eq!(
            discovery_url(
                "https://issuer.example/realms/app/",
                ".well-known/openid-configuration"
            )
            .expect("discovery URL should parse")
            .as_str(),
            "https://issuer.example/realms/app/.well-known/openid-configuration"
        );
        assert_eq!(
            discovery_url("https://issuer.example/realms/app", "custom-discovery")
                .expect("discovery URL should parse")
                .as_str(),
            "https://issuer.example/realms/app/custom-discovery"
        );
    }

    #[test]
    fn provider_google_supplies_auth_server_url() {
        let config = OidcConfig {
            provider: Some(WellKnownProvider::Google),
            ..OidcConfig::default()
        };

        assert_eq!(
            auth_server_url_from_config(&config)
                .expect("google provider should supply auth-server-url")
                .as_str(),
            "https://accounts.google.com"
        );
        assert_eq!(
            discovery_url(
                auth_server_url_from_config(&config)
                    .expect("google provider should supply auth-server-url")
                    .as_str(),
                ".well-known/openid-configuration",
            )
            .expect("discovery URL should parse")
            .as_str(),
            "https://accounts.google.com/.well-known/openid-configuration"
        );
    }

    #[test]
    fn explicit_auth_server_url_overrides_provider() {
        let config = OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            provider: Some(WellKnownProvider::Google),
            ..OidcConfig::default()
        };

        assert_eq!(
            auth_server_url_from_config(&config)
                .expect("explicit auth-server-url should be used")
                .as_str(),
            "https://issuer.example/realms/app"
        );
    }

    #[test]
    fn unsupported_provider_requires_auth_server_url() {
        let config = OidcConfig {
            provider: Some(WellKnownProvider::Github),
            ..OidcConfig::default()
        };

        assert!(matches!(
            auth_server_url_from_config(&config),
            Err(BuildError::UnsupportedWellKnownProvider(
                WellKnownProvider::Github
            ))
        ));
        assert!(
            auth_server_url_from_config(&config)
                .expect_err("github provider should require explicit auth-server-url")
                .to_string()
                .contains("well-known OIDC provider `github` requires"),
        );
    }

    #[test]
    fn provider_endpoint_url_supports_relative_and_absolute_paths() {
        assert_eq!(
            provider_endpoint_url(
                "https://issuer.example/realms/app",
                "/protocol/openid-connect/certs"
            )
            .expect("endpoint URL should parse")
            .as_str(),
            "https://issuer.example/realms/app/protocol/openid-connect/certs"
        );
        assert_eq!(
            provider_endpoint_url(
                "https://issuer.example/realms/app",
                "https://keys.example/jwks"
            )
            .expect("endpoint URL should parse")
            .as_str(),
            "https://keys.example/jwks"
        );
    }

    #[tokio::test]
    async fn discovery_disabled_requires_jwks_path() {
        let result = Oidc::builder(OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            discovery_enabled: false,
            ..OidcConfig::default()
        })
        .discover()
        .await;
        let Err(error) = result else {
            panic!("disabled discovery requires jwks-path");
        };

        assert!(matches!(error, BuildError::MissingJwksPath));
    }

    #[tokio::test]
    async fn discovery_disabled_requires_introspection_path_for_introspection_only() {
        let result = Oidc::builder(OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            discovery_enabled: false,
            token: OidcTokenConfig {
                require_jwt_introspection_only: true,
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        })
        .discover()
        .await;
        let Err(error) = result else {
            panic!("introspection-only discovery requires introspection-path");
        };

        assert!(matches!(error, BuildError::MissingIntrospectionEndpoint));
    }

    #[tokio::test]
    async fn discovery_disabled_requires_user_info_path_for_user_info_validation() {
        let result = Oidc::builder(OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            discovery_enabled: false,
            token: OidcTokenConfig {
                verify_access_token_with_user_info: true,
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        })
        .discover()
        .await;
        let Err(error) = result else {
            panic!("UserInfo validation requires user-info-path");
        };

        assert!(matches!(error, BuildError::MissingUserInfoEndpoint));
    }

    #[tokio::test]
    async fn discovery_disabled_requires_user_info_path_for_user_info_roles() {
        let result = Oidc::builder(OidcConfig {
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            discovery_enabled: false,
            jwks_path: Some("certs".to_owned()),
            roles: OidcRolesConfig {
                source: RolesSource::UserInfo,
                ..OidcRolesConfig::default()
            },
            ..OidcConfig::default()
        })
        .discover()
        .await;
        let Err(error) = result else {
            panic!("UserInfo roles require user-info-path");
        };

        assert!(matches!(error, BuildError::MissingUserInfoEndpoint));
    }

    #[test]
    fn provider_metadata_parses_oidc_discovery_document() {
        let metadata = ProviderMetadata::from_json(
            r#"{
                "issuer": "https://issuer.example/realms/app",
                "jwks_uri": "https://issuer.example/realms/app/protocol/openid-connect/certs",
                "authorization_endpoint": "https://issuer.example/realms/app/protocol/openid-connect/auth",
                "token_endpoint": "https://issuer.example/realms/app/protocol/openid-connect/token",
                "registration_endpoint": "https://issuer.example/realms/app/clients-registrations/openid-connect",
                "revocation_endpoint": "https://issuer.example/realms/app/protocol/openid-connect/revoke",
                "introspection_endpoint": "https://issuer.example/realms/app/protocol/openid-connect/token/introspect",
                "userinfo_endpoint": "https://issuer.example/realms/app/protocol/openid-connect/userinfo",
                "end_session_endpoint": "https://issuer.example/realms/app/protocol/openid-connect/logout"
            }"#,
        )
        .expect("provider metadata should parse");

        assert_eq!(
            metadata,
            ProviderMetadata {
                issuer: Some("https://issuer.example/realms/app".to_owned()),
                jwks_uri: "https://issuer.example/realms/app/protocol/openid-connect/certs"
                    .to_owned(),
                authorization_endpoint: Some(
                    "https://issuer.example/realms/app/protocol/openid-connect/auth".to_owned(),
                ),
                token_endpoint: Some(
                    "https://issuer.example/realms/app/protocol/openid-connect/token".to_owned(),
                ),
                registration_endpoint: Some(
                    "https://issuer.example/realms/app/clients-registrations/openid-connect"
                        .to_owned(),
                ),
                revocation_endpoint: Some(
                    "https://issuer.example/realms/app/protocol/openid-connect/revoke".to_owned(),
                ),
                introspection_endpoint: Some(
                    "https://issuer.example/realms/app/protocol/openid-connect/token/introspect"
                        .to_owned(),
                ),
                userinfo_endpoint: Some(
                    "https://issuer.example/realms/app/protocol/openid-connect/userinfo".to_owned(),
                ),
                end_session_endpoint: Some(
                    "https://issuer.example/realms/app/protocol/openid-connect/logout".to_owned(),
                ),
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
            .provider_metadata(test_metadata(), test_jwks())
            .expect("provider metadata should install validator"),
        )
        .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn provider_metadata_uses_introspection_when_required() {
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
                    require_jwt_introspection_only: true,
                    ..OidcTokenConfig::default()
                },
                ..OidcConfig::default()
            })
            .provider_metadata(test_introspection_metadata(), test_jwks())
            .expect("provider metadata should install introspection validator"),
        )
        .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn provider_metadata_uses_user_info_when_configured() {
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
                    verify_access_token_with_user_info: true,
                    ..OidcTokenConfig::default()
                },
                ..OidcConfig::default()
            })
            .provider_metadata(test_user_info_metadata(), test_jwks())
            .expect("provider metadata should install UserInfo validator"),
        )
        .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn provider_metadata_requires_introspection_endpoint() {
        let result = Oidc::builder(OidcConfig {
            token: OidcTokenConfig {
                require_jwt_introspection_only: true,
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        })
        .provider_metadata(test_metadata(), test_jwks());

        assert!(matches!(
            result,
            Err(BuildError::MissingIntrospectionEndpoint)
        ));
    }

    #[test]
    fn provider_metadata_requires_user_info_endpoint_for_validation() {
        let result = Oidc::builder(OidcConfig {
            token: OidcTokenConfig {
                verify_access_token_with_user_info: true,
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        })
        .provider_metadata(test_metadata(), test_jwks());

        assert!(matches!(result, Err(BuildError::MissingUserInfoEndpoint)));
    }

    #[test]
    fn provider_metadata_requires_user_info_endpoint_for_roles() {
        let result = Oidc::builder(OidcConfig {
            roles: OidcRolesConfig {
                source: RolesSource::UserInfo,
                ..OidcRolesConfig::default()
            },
            ..OidcConfig::default()
        })
        .provider_metadata(test_metadata(), test_jwks());

        assert!(matches!(result, Err(BuildError::MissingUserInfoEndpoint)));
    }

    #[test]
    fn tenants_load_named_tenant_paths_from_config() {
        let config = Config::builder()
            .add_source(
                MapSource::new("tenants", 100)
                    .with("quarkus.oidc.tenant-paths", "/api/default")
                    .with("quarkus.oidc.tenant-a.tenant-paths", "/api/a/*")
                    .with("quarkus.oidc.tenant-a.provider", "google")
                    .with("quarkus.oidc.tenant-a.connection-timeout", "3s")
                    .with("quarkus.oidc.tenant-a.client-id", "tenant-a-client")
                    .with("quarkus.oidc.tenant-a.client-name", "Tenant A")
                    .with("quarkus.oidc.tenant-a.tenant-id", "orders")
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
        assert_eq!(tenant_a.provider, Some(WellKnownProvider::Google));
        assert_eq!(tenant_a.connection_timeout, Duration::from_secs(3));
        assert_eq!(tenant_a.client_id, Some("tenant-a-client".to_owned()));
        assert_eq!(tenant_a.client_name, Some("Tenant A".to_owned()));
        assert_eq!(tenant_a.tenant_id, Some("orders".to_owned()));
    }

    #[test]
    fn tenants_from_config_rejects_empty_named_tenant_paths() {
        let config = Config::builder()
            .add_source(
                MapSource::new("empty-tenant-paths", 100)
                    .with("quarkus.oidc.tenant-a.tenant-paths", " , "),
            )
            .build();

        let Err(error) = Tenants::from_config(&config) else {
            panic!("empty named tenant paths should be rejected");
        };

        assert!(
            error
                .to_string()
                .contains("quarkus.oidc.tenant-a.tenant-paths"),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("tenant-paths must include at least one path"),
            "{error}"
        );
    }

    #[test]
    fn tenants_load_quoted_named_tenant_config() {
        let config = Config::builder()
            .add_source(
                MapSource::new("quoted-tenants", 100)
                    .with(
                        r#"quarkus.oidc."tenant.with.dot".tenant-paths"#,
                        "/api/quoted/*",
                    )
                    .with(
                        r#"quarkus.oidc."tenant.with.dot".client-id"#,
                        "quoted-client",
                    )
                    .with(
                        r#"quarkus.oidc."tenant.with.dot".roles.role-claim-path"#,
                        "permissions",
                    ),
            )
            .build();

        assert_eq!(
            named_tenant_names(&config),
            vec!["tenant.with.dot".to_owned()]
        );

        let tenant =
            OidcConfig::from_config_prefix(&config, r#"quarkus.oidc."tenant.with.dot""#).unwrap();
        assert_eq!(tenant.tenant_paths, Some("/api/quoted/*".to_owned()));
        assert_eq!(tenant.client_id, Some("quoted-client".to_owned()));
        assert_eq!(tenant.roles.role_claim_path, "permissions");

        let _tenants = Tenants::from_config(&config)
            .expect("quoted tenant config should load")
            .build();
    }

    #[test]
    fn tenants_from_config_rejects_named_id_token_roles_source() {
        let config = Config::builder()
            .add_source(
                MapSource::new("tenant-idtoken-roles", 100)
                    .with("quarkus.oidc.tenant-a.tenant-paths", "/api/a/*")
                    .with("quarkus.oidc.tenant-a.roles.source", "idtoken"),
            )
            .build();

        let Err(error) = Tenants::from_config(&config) else {
            panic!("ID token roles should be rejected for named bearer-service tenants");
        };
        assert!(matches!(
            error,
            mp_config::ConfigError::Conversion { ref name, .. }
                if name == "quarkus.oidc.tenant-a.roles.source"
        ));
        assert!(
            error
                .to_string()
                .contains("`idtoken` roles require web-app ID token support"),
            "{error}"
        );
    }

    #[test]
    fn tenants_from_config_rejects_named_empty_role_claim_path() {
        let config = Config::builder()
            .add_source(
                MapSource::new("tenant-empty-role-claim-path", 100)
                    .with("quarkus.oidc.tenant-a.tenant-paths", "/api/a/*")
                    .with("quarkus.oidc.tenant-a.roles.role-claim-path", " , "),
            )
            .build();

        let Err(error) = Tenants::from_config(&config) else {
            panic!("empty role claim path should be rejected for named tenants");
        };
        assert!(
            error
                .to_string()
                .contains("quarkus.oidc.tenant-a.roles.role-claim-path"),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("role-claim-path must include at least one claim path"),
            "{error}"
        );
    }

    #[test]
    fn tenants_from_config_rejects_named_web_app_application_type() {
        let config = Config::builder()
            .add_source(
                MapSource::new("tenant-web-app", 100)
                    .with("quarkus.oidc.tenant-a.tenant-paths", "/api/a/*")
                    .with("quarkus.oidc.tenant-a.application-type", "web-app"),
            )
            .build();

        let Err(error) = Tenants::from_config(&config) else {
            panic!("web-app should be rejected for named bearer-service tenants");
        };
        assert!(matches!(
            error,
            mp_config::ConfigError::Conversion { ref name, .. }
                if name == "quarkus.oidc.tenant-a.application-type"
        ));
        assert!(
            error
                .to_string()
                .contains("`web-app` application type requires authorization-code flow support"),
            "{error}"
        );
    }

    #[test]
    fn tenants_from_config_rejects_named_token_binding_certificate() {
        let config = Config::builder()
            .add_source(
                MapSource::new("tenant-token-binding", 100)
                    .with("quarkus.oidc.tenant-a.tenant-paths", "/api/a/*")
                    .with("quarkus.oidc.tenant-a.token.binding.certificate", "true"),
            )
            .build();

        let Err(error) = Tenants::from_config(&config) else {
            panic!("certificate-bound tokens should be rejected for named bearer-service tenants");
        };
        assert!(matches!(
            error,
            mp_config::ConfigError::Conversion { ref name, .. }
                if name == "quarkus.oidc.tenant-a.token.binding.certificate"
        ));
        assert!(
            error
                .to_string()
                .contains("requires client certificate thumbprint extraction"),
            "{error}"
        );
    }

    #[test]
    fn tenants_from_config_rejects_named_decrypt_access_token() {
        let config = Config::builder()
            .add_source(
                MapSource::new("tenant-decrypt-access-token", 100)
                    .with("quarkus.oidc.tenant-a.tenant-paths", "/api/a/*")
                    .with("quarkus.oidc.tenant-a.token.decrypt-access-token", "true"),
            )
            .build();

        let Err(error) = Tenants::from_config(&config) else {
            panic!("encrypted access tokens should be rejected for named bearer-service tenants");
        };
        assert!(matches!(
            error,
            mp_config::ConfigError::Conversion { ref name, .. }
                if name == "quarkus.oidc.tenant-a.token.decrypt-access-token"
        ));
        assert!(
            error
                .to_string()
                .contains("requires JWE access-token decryption"),
            "{error}"
        );
    }

    #[test]
    fn tenants_detect_named_tenant_credentials_config() {
        let config = Config::builder()
            .add_source(
                MapSource::new("tenant-credentials", 100)
                    .with("quarkus.oidc.tenant-a.credentials.secret", "tenant-secret")
                    .with(
                        "quarkus.oidc.tenant-a.credentials.client-secret.method",
                        "post",
                    ),
            )
            .build();

        assert_eq!(named_tenant_names(&config), vec!["tenant-a".to_owned()]);

        let tenant = OidcConfig::from_config_prefix(&config, "quarkus.oidc.tenant-a")
            .expect("tenant credentials should load");
        assert_eq!(
            tenant.credentials,
            OidcCredentialsConfig {
                secret: Some("tenant-secret".to_owned()),
                client_secret: OidcClientSecretConfig {
                    value: None,
                    method: ClientSecretMethod::Post,
                },
            }
        );
    }

    #[test]
    fn tenants_detect_named_tenant_introspection_credentials_config() {
        let config = Config::builder()
            .add_source(
                MapSource::new("tenant-introspection-credentials", 100)
                    .with(
                        "quarkus.oidc.tenant-a.introspection-credentials.name",
                        "introspect",
                    )
                    .with(
                        "quarkus.oidc.tenant-a.introspection-credentials.secret",
                        "introspect-secret",
                    ),
            )
            .build();

        assert_eq!(named_tenant_names(&config), vec!["tenant-a".to_owned()]);

        let tenant = OidcConfig::from_config_prefix(&config, "quarkus.oidc.tenant-a")
            .expect("tenant introspection credentials should load");
        assert_eq!(
            tenant.introspection_credentials,
            OidcIntrospectionCredentialsConfig {
                name: Some("introspect".to_owned()),
                secret: Some("introspect-secret".to_owned()),
                include_client_id: true,
            }
        );
    }

    #[test]
    fn tenants_detect_default_tenant_roles_config() {
        let config = Config::builder()
            .add_source(
                MapSource::new("tenant-roles", 100)
                    .with("quarkus.oidc.roles.role-claim-path", "permissions"),
            )
            .build();

        let tenants = Tenants::from_config(&config)
            .expect("default tenant roles config should load")
            .build();
        let default_tenant = tenants
            .default_tenant
            .expect("roles config should create default tenant");

        assert_eq!(default_tenant.config.roles.role_claim_path, "permissions");
    }

    #[test]
    fn tenants_detect_default_tenant_introspection_credentials_config() {
        let config = Config::builder()
            .add_source(
                MapSource::new("tenant-introspection-credentials", 100).with(
                    "quarkus.oidc.introspection-credentials.secret",
                    "introspect-secret",
                ),
            )
            .build();

        let tenants = Tenants::from_config(&config)
            .expect("default tenant introspection credentials config should load")
            .build();
        let default_tenant = tenants
            .default_tenant
            .expect("introspection credentials config should create default tenant");

        assert_eq!(
            default_tenant
                .config
                .introspection_credentials
                .secret
                .as_deref(),
            Some("introspect-secret")
        );
    }

    #[test]
    fn tenants_load_tenant_id_header_from_config() {
        let config = Config::builder()
            .add_source(
                MapSource::new("tenant-header", 100)
                    .with("quarkus.oidc.tenant-id-header", "x-oidc-tenant")
                    .with("quarkus.oidc.tenant-a.tenant-id", "orders"),
            )
            .build();

        let tenants = Tenants::from_config(&config)
            .expect("tenant header config should load")
            .build();

        assert_eq!(
            tenants.header_name,
            Some(http::HeaderName::from_static("x-oidc-tenant"))
        );
    }

    #[test]
    fn tenants_reject_invalid_tenant_id_header_from_config() {
        let config = Config::builder()
            .add_source(
                MapSource::new("tenant-header", 100)
                    .with("quarkus.oidc.tenant-id-header", "not a header"),
            )
            .build();

        let error = match Tenants::from_config(&config) {
            Ok(_) => panic!("tenant header should be rejected"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            mp_config::ConfigError::Conversion { name, .. }
                if name == "quarkus.oidc.tenant-id-header"
        ));
    }

    #[tokio::test]
    async fn tenants_from_config_apply_http_authorization() {
        let config = Config::builder()
            .add_source(
                MapSource::new("tenant-authz", 100)
                    .with("quarkus.oidc.tenant-a.tenant-paths", "/tenant-a/*")
                    .with(
                        "quarkus.http.auth.permission.public.paths",
                        "/tenant-a/public",
                    )
                    .with("quarkus.http.auth.permission.public.policy", "permit")
                    .with(
                        "quarkus.http.auth.permission.private.paths",
                        "/tenant-a/private",
                    )
                    .with(
                        "quarkus.http.auth.permission.private.policy",
                        "authenticated",
                    ),
            )
            .build();
        let tenants = Tenants::from_config(&config)
            .expect("tenant config should load")
            .build();
        let app = Router::new()
            .fallback(|| async { "ok" })
            .layer(tenants.layer());

        let response = app
            .clone()
            .oneshot(request("/tenant-a/public", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(request("/tenant-a/private", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn tenants_discover_from_config_builds_named_public_key_tenant() {
        let config = Config::builder()
            .add_source(
                MapSource::new("tenant-public-key-discovery", 100)
                    .with("quarkus.oidc.tenant-a.public-key", PUBLIC_RSA_KEY)
                    .with(
                        "quarkus.oidc.tenant-a.auth-server-url",
                        "https://issuer.example/realms/app",
                    )
                    .with("quarkus.oidc.tenant-a.token.audience", "orders-api"),
            )
            .build();
        let token = jwt_rs256(TestClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            exp: 4_102_444_800,
            groups: vec!["admin"],
            realm_access: RealmAccessClaims {
                roles: vec!["user"],
            },
        });

        let response = tenant_app(
            Tenants::discover_from_config(&config)
                .await
                .expect("public key tenant config should build without provider discovery"),
        )
        .oneshot(request(
            "/tenant-a/protected",
            Some(&format!("Bearer {token}")),
        ))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_body(response).await, "alice");
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
    async fn tenants_select_named_tenant_from_first_path_segment() {
        let response = tenant_app(
            Tenants::builder()
                .default_tenant(static_tenant("default-token", "default"))
                .tenant("tenant-a", static_tenant("a-token", "tenant-a"))
                .tenant("tenant-b", static_tenant("b-token", "tenant-b"))
                .build(),
        )
        .oneshot(request("/tenant-b/bearer", Some("Bearer b-token")))
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
    async fn tenants_select_by_configured_tenant_id_header() {
        let response = tenant_app(
            Tenants::builder()
                .tenant_header(http::HeaderName::from_static("x-oidc-tenant"))
                .tenant(
                    "tenant-a",
                    static_tenant_with_id("a-token", "tenant-a", "orders"),
                )
                .tenant(
                    "tenant-b",
                    static_tenant_with_id("b-token", "tenant-b", "billing"),
                )
                .build(),
        )
        .oneshot(
            Request::builder()
                .uri("/unmatched")
                .header(AUTHORIZATION, "Bearer a-token")
                .header("x-oidc-tenant", "orders")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response_body(response).await,
            "tenant-a",
            "tenant-id should select tenant-a"
        );
    }

    #[tokio::test]
    async fn tenants_select_by_token_issuer_when_enabled() {
        let tenant_a_token = jwt(TestClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/a",
            aud: "orders-api",
            exp: 4_102_444_800,
            groups: vec![],
            realm_access: RealmAccessClaims { roles: vec![] },
        });
        let tenant_b_token = jwt(TestClaims {
            sub: "bob",
            iss: "https://issuer.example/realms/b",
            aud: "orders-api",
            exp: 4_102_444_800,
            groups: vec![],
            realm_access: RealmAccessClaims { roles: vec![] },
        });

        let response = tenant_app(
            Tenants::builder()
                .resolve_with_issuer(true)
                .tenant(
                    "tenant-a",
                    static_tenant_with_issuer(
                        &tenant_a_token,
                        "tenant-a",
                        "https://issuer.example/realms/a",
                    ),
                )
                .tenant(
                    "tenant-b",
                    static_tenant_with_issuer(
                        &tenant_b_token,
                        "tenant-b",
                        "https://issuer.example/realms/b",
                    ),
                )
                .build(),
        )
        .oneshot(request(
            "/unmatched",
            Some(&format!("Bearer {tenant_b_token}")),
        ))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response_body(response).await,
            "tenant-b",
            "issuer should select tenant-b"
        );
    }

    #[tokio::test]
    async fn tenants_select_by_token_issuer_with_configured_scheme() {
        let tenant_a_token = jwt(TestClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/a",
            aud: "orders-api",
            exp: 4_102_444_800,
            groups: vec![],
            realm_access: RealmAccessClaims { roles: vec![] },
        });
        let tenant_b_token = jwt(TestClaims {
            sub: "bob",
            iss: "https://issuer.example/realms/b",
            aud: "orders-api",
            exp: 4_102_444_800,
            groups: vec![],
            realm_access: RealmAccessClaims { roles: vec![] },
        });

        let response = tenant_app(
            Tenants::builder()
                .resolve_with_issuer(true)
                .tenant(
                    "tenant-a",
                    static_tenant_with_issuer(
                        &tenant_a_token,
                        "tenant-a",
                        "https://issuer.example/realms/a",
                    ),
                )
                .tenant(
                    "tenant-b",
                    Oidc::builder(OidcConfig {
                        auth_server_url: Some("https://issuer.example/realms/b".to_owned()),
                        token: OidcTokenConfig {
                            authorization_scheme: "Token".to_owned(),
                            ..OidcTokenConfig::default()
                        },
                        ..OidcConfig::default()
                    })
                    .validator(StaticTokenValidator::bearer(&tenant_b_token, "tenant-b"))
                    .build(),
                )
                .build(),
        )
        .oneshot(request(
            "/unmatched",
            Some(&format!("Token {tenant_b_token}")),
        ))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response_body(response).await,
            "tenant-b",
            "configured scheme should select tenant-b by issuer"
        );
    }

    #[tokio::test]
    async fn tenants_select_by_token_issuer_with_configured_header() {
        let token = jwt(TestClaims {
            sub: "bob",
            iss: "https://issuer.example/realms/b",
            aud: "orders-api",
            exp: 4_102_444_800,
            groups: vec![],
            realm_access: RealmAccessClaims { roles: vec![] },
        });

        let response = tenant_app(
            Tenants::builder()
                .resolve_with_issuer(true)
                .tenant(
                    "tenant-b",
                    Oidc::builder(OidcConfig {
                        auth_server_url: Some("https://issuer.example/realms/b".to_owned()),
                        token: OidcTokenConfig {
                            header: "x-access-token".to_owned(),
                            ..OidcTokenConfig::default()
                        },
                        ..OidcConfig::default()
                    })
                    .validator(StaticTokenValidator::bearer(&token, "tenant-b"))
                    .build(),
                )
                .build(),
        )
        .oneshot(request_with_header("/unmatched", "x-access-token", &token))
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response_body(response).await,
            "tenant-b",
            "configured token header should select tenant-b by issuer"
        );
    }

    #[tokio::test]
    async fn tenant_header_takes_precedence_over_token_issuer() {
        let token = jwt(TestClaims {
            sub: "bob",
            iss: "https://issuer.example/realms/b",
            aud: "orders-api",
            exp: 4_102_444_800,
            groups: vec![],
            realm_access: RealmAccessClaims { roles: vec![] },
        });

        let response = tenant_app(
            Tenants::builder()
                .tenant_header(http::HeaderName::from_static("x-oidc-tenant"))
                .resolve_with_issuer(true)
                .tenant(
                    "tenant-a",
                    static_tenant_with_issuer(
                        &token,
                        "tenant-a",
                        "https://issuer.example/realms/a",
                    ),
                )
                .tenant(
                    "tenant-b",
                    static_tenant_with_issuer(
                        &token,
                        "tenant-b",
                        "https://issuer.example/realms/b",
                    ),
                )
                .build(),
        )
        .oneshot(
            Request::builder()
                .uri("/unmatched")
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .header("x-oidc-tenant", "tenant-a")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response_body(response).await,
            "tenant-a",
            "header should select tenant-a"
        );
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
    async fn authorization_ignores_disabled_permissions() {
        let authorization = Authorization::from_config(
            &Config::builder()
                .add_source(
                    MapSource::new("quarkus-disabled-permission", 100)
                        .with("quarkus.http.auth.permission.permit.paths", "/resource")
                        .with("quarkus.http.auth.permission.permit.policy", "permit")
                        .with("quarkus.http.auth.permission.deny.paths", "/resource")
                        .with("quarkus.http.auth.permission.deny.policy", "deny")
                        .with("quarkus.http.auth.permission.deny.enabled", "false"),
                )
                .build(),
        )
        .expect("authorization config should load");
        let app = authz_app(authorization);

        let response = app
            .oneshot(request("/resource", None))
            .await
            .expect("request should complete");

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn authorization_rejects_undefined_named_policy() {
        let error = Authorization::from_config(
            &Config::builder()
                .add_source(
                    MapSource::new("quarkus-undefined-policy", 100)
                        .with("quarkus.http.auth.permission.secured.paths", "/resource")
                        .with("quarkus.http.auth.permission.secured.policy", "missing"),
                )
                .build(),
        )
        .expect_err("undefined named policy should be rejected");

        assert!(
            error.to_string().contains(
                "failed to convert config property `quarkus.http.auth.permission.secured.policy` value `missing`"
            ),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("authorization policy `missing` is not defined"),
            "{error}"
        );
    }

    #[test]
    fn authorization_rejects_empty_roles_allowed_policy() {
        let error = Authorization::from_config(
            &Config::builder()
                .add_source(
                    MapSource::new("quarkus-empty-roles", 100)
                        .with("quarkus.http.auth.policy.empty.roles-allowed", " , ")
                        .with("quarkus.http.auth.permission.secured.paths", "/resource")
                        .with("quarkus.http.auth.permission.secured.policy", "empty"),
                )
                .build(),
        )
        .expect_err("empty roles-allowed should be rejected");

        assert!(
            error.to_string().contains(
                "failed to convert config property `quarkus.http.auth.policy.empty.roles-allowed`"
            ),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("roles-allowed must include at least one role"),
            "{error}"
        );
    }

    #[test]
    fn authorization_rejects_empty_permission_paths() {
        let error = Authorization::from_config(
            &Config::builder()
                .add_source(
                    MapSource::new("quarkus-empty-paths", 100)
                        .with("quarkus.http.auth.permission.secured.paths", " , ")
                        .with(
                            "quarkus.http.auth.permission.secured.policy",
                            "authenticated",
                        ),
                )
                .build(),
        )
        .expect_err("empty permission paths should be rejected");

        assert!(
            error.to_string().contains(
                "failed to convert config property `quarkus.http.auth.permission.secured.paths`"
            ),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("permission paths must include at least one path"),
            "{error}"
        );
    }

    #[test]
    fn authorization_rejects_empty_permission_methods() {
        let error = Authorization::from_config(
            &Config::builder()
                .add_source(
                    MapSource::new("quarkus-empty-methods", 100)
                        .with("quarkus.http.auth.permission.secured.paths", "/resource")
                        .with("quarkus.http.auth.permission.secured.methods", " , ")
                        .with(
                            "quarkus.http.auth.permission.secured.policy",
                            "authenticated",
                        ),
                )
                .build(),
        )
        .expect_err("empty permission methods should be rejected");

        assert!(
            error.to_string().contains(
                "failed to convert config property `quarkus.http.auth.permission.secured.methods`"
            ),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("permission methods must include at least one method when configured"),
            "{error}"
        );
    }

    #[test]
    fn authorization_normalizes_configured_methods() {
        assert_eq!(
            parse_http_methods("quarkus.http.auth.permission.secured.methods", "get,Post")
                .expect("methods should parse"),
            vec!["GET".to_owned(), "POST".to_owned()]
        );
    }

    #[test]
    fn authorization_rejects_invalid_configured_methods() {
        let error = Authorization::from_config(
            &Config::builder()
                .add_source(
                    MapSource::new("quarkus-invalid-method", 100)
                        .with("quarkus.http.auth.permission.secured.paths", "/resource")
                        .with(
                            "quarkus.http.auth.permission.secured.methods",
                            "GET,not a method",
                        )
                        .with(
                            "quarkus.http.auth.permission.secured.policy",
                            "authenticated",
                        ),
                )
                .build(),
        )
        .expect_err("invalid method should be rejected");

        assert!(
            error.to_string().contains(
                "failed to convert config property `quarkus.http.auth.permission.secured.methods` value `NOT A METHOD`"
            ),
            "{error}"
        );
    }

    #[tokio::test]
    async fn authorization_exact_path_matches_trailing_slash() {
        let authorization = Authorization::from_config(
            &Config::builder()
                .add_source(
                    MapSource::new("quarkus-exact-path-trailing-slash", 100)
                        .with("quarkus.http.auth.permission.deny.paths", "/forbidden")
                        .with("quarkus.http.auth.permission.deny.policy", "deny"),
                )
                .build(),
        )
        .expect("authorization config should load");
        let app = authz_app(authorization);

        let response = app
            .clone()
            .oneshot(request("/forbidden", Some("Bearer test-token")))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = app
            .oneshot(request("/forbidden/", Some("Bearer test-token")))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn authorization_explicit_trailing_slash_path_wins() {
        let authorization = Authorization::from_config(
            &Config::builder()
                .add_source(
                    MapSource::new("quarkus-explicit-trailing-slash", 100)
                        .with("quarkus.http.auth.permission.deny.paths", "/forbidden")
                        .with("quarkus.http.auth.permission.deny.policy", "deny")
                        .with("quarkus.http.auth.permission.permit.paths", "/forbidden/")
                        .with("quarkus.http.auth.permission.permit.policy", "permit"),
                )
                .build(),
        )
        .expect("authorization config should load");
        let app = authz_app(authorization);

        let response = app
            .clone()
            .oneshot(request("/forbidden", Some("Bearer test-token")))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = app
            .oneshot(request("/forbidden/", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn authorization_prepends_root_path_to_relative_permission_paths() {
        let authorization = Authorization::from_config(
            &Config::builder()
                .add_source(
                    MapSource::new("quarkus-root-path-relative", 100)
                        .with("quarkus.http.root-path", "/api")
                        .with("quarkus.http.auth.permission.deny.paths", "admin/*")
                        .with("quarkus.http.auth.permission.deny.policy", "deny"),
                )
                .build(),
        )
        .expect("authorization config should load");
        let app = authz_app(authorization);

        let response = app
            .clone()
            .oneshot(request("/admin/users", Some("Bearer test-token")))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(request("/api/admin/users", Some("Bearer test-token")))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn authorization_keeps_absolute_permission_paths_with_root_path() {
        let authorization = Authorization::from_config(
            &Config::builder()
                .add_source(
                    MapSource::new("quarkus-root-path-absolute", 100)
                        .with("quarkus.http.root-path", "/api")
                        .with("quarkus.http.auth.permission.deny.paths", "/admin/*")
                        .with("quarkus.http.auth.permission.deny.policy", "deny"),
                )
                .build(),
        )
        .expect("authorization config should load");
        let app = authz_app(authorization);

        let response = app
            .clone()
            .oneshot(request("/api/admin/users", Some("Bearer test-token")))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(request("/admin/users", Some("Bearer test-token")))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn authorization_prefers_method_specific_permission_for_same_path() {
        let authorization = Authorization::from_config(
            &Config::builder()
                .add_source(
                    MapSource::new("quarkus-method-specific-permission", 100)
                        .with("quarkus.http.auth.permission.deny.paths", "/resource")
                        .with("quarkus.http.auth.permission.deny.policy", "deny")
                        .with("quarkus.http.auth.permission.permit-get.paths", "/resource")
                        .with("quarkus.http.auth.permission.permit-get.methods", "GET")
                        .with("quarkus.http.auth.permission.permit-get.policy", "permit"),
                )
                .build(),
        )
        .expect("authorization config should load");
        let app = authz_app(authorization);

        let response = app
            .clone()
            .oneshot(request("/resource", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(request_with_method(http::Method::POST, "/resource", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(request_with_method(
                http::Method::POST,
                "/resource",
                Some("Bearer test-token"),
            ))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn authorization_rejects_path_match_without_method_match() {
        let authorization = Authorization::from_config(
            &Config::builder()
                .add_source(
                    MapSource::new("quarkus-method-mismatch", 100)
                        .with(
                            "quarkus.http.auth.permission.permit-get.paths",
                            "/resource/*",
                        )
                        .with("quarkus.http.auth.permission.permit-get.methods", "GET")
                        .with("quarkus.http.auth.permission.permit-get.policy", "permit"),
                )
                .build(),
        )
        .expect("authorization config should load");
        let app = authz_app(authorization);

        let response = app
            .clone()
            .oneshot(request("/resource/item", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(request_with_method(
                http::Method::POST,
                "/resource/item",
                None,
            ))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(request_with_method(
                http::Method::POST,
                "/resource/item",
                Some("Bearer test-token"),
            ))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let response = app
            .oneshot(request_with_method(
                http::Method::POST,
                "/unmatched",
                Some("Bearer test-token"),
            ))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn authorization_matches_single_segment_wildcards() {
        let authorization = Authorization::from_config(
            &Config::builder()
                .add_source(
                    MapSource::new("quarkus-segment-wildcard", 100)
                        .with(
                            "quarkus.http.auth.permission.secured.paths",
                            "/api/*/detail",
                        )
                        .with(
                            "quarkus.http.auth.permission.secured.policy",
                            "authenticated",
                        )
                        .with(
                            "quarkus.http.auth.permission.public.paths",
                            "/api/public-product/detail",
                        )
                        .with("quarkus.http.auth.permission.public.policy", "permit"),
                )
                .build(),
        )
        .expect("authorization config should load");
        let app = authz_app(authorization);

        let response = app
            .clone()
            .oneshot(request("/api/product/detail", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(request("/api/product/detail", Some("Bearer test-token")))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(request("/api/product/other", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .oneshot(request("/api/public-product/detail", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn path_match_scores_single_segment_wildcards_by_specificity() {
        let exact = path_match_score("/one/two/three/four/five", "/one/two/three/four/five")
            .expect("exact path should match");
        let trailing = path_match_score("/one/two/three/four/*", "/one/two/three/four/five")
            .expect("trailing wildcard path should match");
        let middle = path_match_score("/one/two/three/*/five", "/one/two/three/four/five")
            .expect("middle wildcard path should match");
        let root = path_match_score("/*", "/one/two/three/four/five")
            .expect("root wildcard path should match");

        assert!(exact > trailing);
        assert!(trailing > middle);
        assert!(middle > root);
        assert_eq!(
            path_match_score("/one/two/*/five", "/one/two/three/four/five"),
            None
        );
        assert_eq!(
            path_match_score("/one/two/*four/five", "/one/two/three/four/five"),
            None
        );
        assert!(path_match_score("/public*", "/public").is_some());
        assert!(path_match_score("/public*", "/public/css/site.css").is_some());
        assert_eq!(path_match_score("/public*", "/public-info"), None);
    }

    #[test]
    fn relative_permission_paths_are_normalized_with_root_path() {
        assert_eq!(
            normalize_permission_paths(vec!["public/*".to_owned(), "/fixed/*".to_owned()], "/api/"),
            vec!["/api/public/*".to_owned(), "/fixed/*".to_owned()]
        );
    }

    #[test]
    fn claim_path_parts_preserve_quoted_segments() {
        assert_eq!(
            claim_path_parts("resource_access.\"https://claims.example/roles\".roles"),
            vec![
                "resource_access".to_owned(),
                "https://claims.example/roles".to_owned(),
                "roles".to_owned()
            ]
        );
        assert_eq!(
            claim_path_parts("\"https://claims.example/roles\""),
            vec!["https://claims.example/roles".to_owned()]
        );
    }

    #[tokio::test]
    async fn authorization_applies_shared_permissions_with_most_specific_match() {
        let authorization = Authorization::from_config(
            &Config::builder()
                .add_source(
                    MapSource::new("quarkus-shared-permission", 100)
                        .with("quarkus.http.auth.permission.shared.paths", "/api/*")
                        .with(
                            "quarkus.http.auth.permission.shared.policy",
                            "authenticated",
                        )
                        .with("quarkus.http.auth.permission.shared.shared", "true")
                        .with("quarkus.http.auth.permission.permit.paths", "/api/public")
                        .with("quarkus.http.auth.permission.permit.policy", "permit"),
                )
                .build(),
        )
        .expect("authorization config should load");
        let app = authz_app(authorization);

        let response = app
            .clone()
            .oneshot(request("/api/public", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .clone()
            .oneshot(request("/api/public", Some("Bearer test-token")))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);

        let response = app
            .clone()
            .oneshot(request("/api/other", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(request("/outside", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);
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

    #[tokio::test]
    async fn authorization_requires_all_winning_role_policies() {
        let authorization = Authorization::from_config(
            &Config::builder()
                .add_source(
                    MapSource::new("quarkus-both-permissions-win", 100)
                        .with("quarkus.http.auth.policy.user.roles-allowed", "user")
                        .with("quarkus.http.auth.policy.admin.roles-allowed", "admin")
                        .with("quarkus.http.auth.permission.users.paths", "/api/*")
                        .with("quarkus.http.auth.permission.users.policy", "user")
                        .with("quarkus.http.auth.permission.admins.paths", "/api/*")
                        .with("quarkus.http.auth.permission.admins.policy", "admin"),
                )
                .build(),
        )
        .expect("authorization config should load");

        let app = authz_app_with_principal(
            authorization.clone(),
            Principal::with_groups("test", ["user"]),
        );
        let response = app
            .oneshot(request("/api/orders", Some("Bearer test-token")))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        let app = authz_app_with_principal(
            authorization,
            Principal::with_groups("test", ["user", "admin"]),
        );
        let response = app
            .oneshot(request("/api/orders", Some("Bearer test-token")))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn authorization_roles_within_one_policy_are_alternatives() {
        let authorization = Authorization::from_config(
            &Config::builder()
                .add_source(
                    MapSource::new("quarkus-policy-role-alternatives", 100)
                        .with("quarkus.http.auth.policy.staff.roles-allowed", "user,admin")
                        .with("quarkus.http.auth.permission.staff.paths", "/api/*")
                        .with("quarkus.http.auth.permission.staff.policy", "staff"),
                )
                .build(),
        )
        .expect("authorization config should load");
        let app = authz_app_with_principal(authorization, Principal::with_groups("test", ["user"]));

        let response = app
            .oneshot(request("/api/orders", Some("Bearer test-token")))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn authorization_double_star_role_requires_authentication_only() {
        let authorization = Authorization::from_config(
            &Config::builder()
                .add_source(
                    MapSource::new("quarkus-policy-double-star", 100)
                        .with("quarkus.http.auth.policy.any.roles-allowed", "**")
                        .with("quarkus.http.auth.permission.any.paths", "/authenticated")
                        .with("quarkus.http.auth.permission.any.policy", "any"),
                )
                .build(),
        )
        .expect("authorization config should load");
        let app = authz_app_with_principal(authorization, Principal::new("test"));

        let response = app
            .clone()
            .oneshot(request("/authenticated", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(request("/authenticated", Some("Bearer test-token")))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn authorization_applies_global_role_mappings() {
        let authorization = Authorization::from_config(
            &Config::builder()
                .add_source(
                    MapSource::new("quarkus-global-role-mapping", 100)
                        .with("quarkus.http.auth.roles-mapping.admin", "Admin1")
                        .with("quarkus.http.auth.policy.mapped.roles-allowed", "Admin1")
                        .with("quarkus.http.auth.permission.mapped.paths", "/mapped")
                        .with("quarkus.http.auth.permission.mapped.policy", "mapped"),
                )
                .build(),
        )
        .expect("authorization config should load");
        let app =
            authz_app_with_principal(authorization, Principal::with_groups("test", ["admin"]));

        let response = app
            .clone()
            .oneshot(request("/mapped", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(request("/mapped", Some("Bearer test-token")))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn authorization_rejects_empty_global_role_mapping() {
        let error = Authorization::from_config(
            &Config::builder()
                .add_source(
                    MapSource::new("quarkus-empty-global-role-mapping", 100)
                        .with("quarkus.http.auth.roles-mapping.admin", " , "),
                )
                .build(),
        )
        .expect_err("empty global role mapping should be rejected");

        assert!(
            error
                .to_string()
                .contains("quarkus.http.auth.roles-mapping.admin"),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("role mappings must include at least one mapped role"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn authorization_applies_policy_role_mappings() {
        let authorization = Authorization::from_config(
            &Config::builder()
                .add_source(
                    MapSource::new("quarkus-policy-role-mapping", 100)
                        .with("quarkus.http.auth.policy.mapped.roles-allowed", "Admin1")
                        .with("quarkus.http.auth.policy.mapped.roles.admin", "Admin1")
                        .with("quarkus.http.auth.permission.mapped.paths", "/mapped")
                        .with("quarkus.http.auth.permission.mapped.policy", "mapped"),
                )
                .build(),
        )
        .expect("authorization config should load");
        let app =
            authz_app_with_principal(authorization, Principal::with_groups("test", ["admin"]));

        let response = app
            .clone()
            .oneshot(request("/mapped", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(request("/mapped", Some("Bearer test-token")))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn authorization_rejects_empty_policy_role_mapping() {
        let error = Authorization::from_config(
            &Config::builder()
                .add_source(
                    MapSource::new("quarkus-empty-policy-role-mapping", 100)
                        .with("quarkus.http.auth.policy.mapped.roles-allowed", "Admin1")
                        .with("quarkus.http.auth.policy.mapped.roles.admin", " , ")
                        .with("quarkus.http.auth.permission.mapped.paths", "/mapped")
                        .with("quarkus.http.auth.permission.mapped.policy", "mapped"),
                )
                .build(),
        )
        .expect_err("empty policy role mapping should be rejected");

        assert!(
            error
                .to_string()
                .contains("quarkus.http.auth.policy.mapped.roles.admin"),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("role mappings must include at least one mapped role"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn authorization_role_mapping_policy_requires_authentication() {
        let authorization = Authorization::from_config(
            &Config::builder()
                .add_source(
                    MapSource::new("quarkus-mapping-only-policy", 100)
                        .with("quarkus.http.auth.policy.mapped.roles.admin", "Admin1")
                        .with("quarkus.http.auth.permission.mapped.paths", "/mapped")
                        .with("quarkus.http.auth.permission.mapped.policy", "mapped"),
                )
                .build(),
        )
        .expect("authorization config should load");
        let app =
            authz_app_with_principal(authorization, Principal::with_groups("test", ["admin"]));

        let response = app
            .clone()
            .oneshot(request("/mapped", None))
            .await
            .expect("request should complete");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = app
            .oneshot(request("/mapped", Some("Bearer test-token")))
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
        authz_app_with_principal(authorization, Principal::with_groups("test", ["test"]))
    }

    fn authz_app_with_principal(authorization: Authorization, principal: Principal) -> Router {
        Router::new().fallback(|| async { "ok" }).layer(
            Oidc::builder(OidcConfig::default())
                .validator(StaticTokenValidator::principal("test-token", principal))
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

    fn static_tenant_with_id(token: &str, subject: &str, tenant_id: &str) -> Oidc {
        Oidc::builder(OidcConfig {
            tenant_id: Some(tenant_id.to_owned()),
            ..OidcConfig::default()
        })
        .validator(StaticTokenValidator::bearer(token, subject))
        .build()
    }

    fn static_tenant_with_issuer(token: &str, subject: &str, issuer: &str) -> Oidc {
        Oidc::builder(OidcConfig {
            auth_server_url: Some(issuer.to_owned()),
            ..OidcConfig::default()
        })
        .validator(StaticTokenValidator::bearer(token, subject))
        .build()
    }

    async fn response_body(response: Response) -> String {
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("response body should be readable");
        String::from_utf8(body.to_vec()).expect("response body should be UTF-8")
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
        jwt_value(claims, true)
    }

    fn jwt_without_iat(claims: impl Serialize) -> String {
        jwt_value(claims, false)
    }

    fn jwt_with_header_type(token_type: &str, claims: impl Serialize) -> String {
        let mut header = Header::default();
        header.typ = Some(token_type.to_owned());
        jwt_value_with_header(header, claims, true)
    }

    fn jwt_value(claims: impl Serialize, include_default_iat: bool) -> String {
        jwt_value_with_header(Header::default(), claims, include_default_iat)
    }

    fn jwt_value_with_header(
        header: Header,
        claims: impl Serialize,
        include_default_iat: bool,
    ) -> String {
        let mut claims = serde_json::to_value(claims).expect("test claims should serialize");
        if include_default_iat {
            if let Value::Object(claims) = &mut claims {
                claims.entry("iat").or_insert_with(|| Value::from(TEST_IAT));
            }
        }
        encode(&header, &claims, &EncodingKey::from_secret(b"secret"))
            .expect("test token should encode")
    }

    fn jwt_rs256(claims: impl Serialize) -> String {
        let mut claims = serde_json::to_value(claims).expect("test claims should serialize");
        if let Value::Object(claims) = &mut claims {
            claims.entry("iat").or_insert_with(|| Value::from(TEST_IAT));
        }
        encode(
            &Header::new(Algorithm::RS256),
            &claims,
            &EncodingKey::from_rsa_pem(PRIVATE_RSA_KEY.as_bytes())
                .expect("test RSA private key should parse"),
        )
        .expect("test token should encode")
    }

    fn jwt_with_kid(kid: &str, claims: TestClaims<'_>) -> String {
        jwt_with_kid_and_secret(kid, b"secret", claims)
    }

    fn jwt_with_kid_and_secret(kid: &str, secret: &[u8], claims: impl Serialize) -> String {
        let mut header = Header::default();
        header.kid = Some(kid.to_owned());
        let mut claims = serde_json::to_value(claims).expect("test claims should serialize");
        if let Value::Object(claims) = &mut claims {
            claims.entry("iat").or_insert_with(|| Value::from(TEST_IAT));
        }

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
            authorization_endpoint: None,
            token_endpoint: None,
            registration_endpoint: None,
            revocation_endpoint: None,
            introspection_endpoint: None,
            userinfo_endpoint: None,
            end_session_endpoint: None,
        }
    }

    fn test_introspection_metadata() -> ProviderMetadata {
        ProviderMetadata {
            introspection_endpoint: Some("http://127.0.0.1:1/introspect".to_owned()),
            ..test_metadata()
        }
    }

    fn test_user_info_metadata() -> ProviderMetadata {
        ProviderMetadata {
            userinfo_endpoint: Some("http://127.0.0.1:1/userinfo".to_owned()),
            ..test_metadata()
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
    struct StringScopeClaims<'a> {
        sub: &'a str,
        iss: &'a str,
        aud: &'a str,
        scope: &'a str,
        exp: u64,
    }

    #[derive(Serialize)]
    struct ProfilePrincipalClaims<'a> {
        sub: &'a str,
        iss: &'a str,
        aud: &'a str,
        profile: ProfileClaims<'a>,
        exp: u64,
    }

    #[derive(Serialize)]
    struct ProfileClaims<'a> {
        email: &'a str,
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
    struct ClientResourceRoleClaims<'a> {
        sub: &'a str,
        iss: &'a str,
        aud: &'a str,
        exp: u64,
        resource_access: ClientResourceAccessClaims<'a>,
    }

    #[derive(Serialize)]
    struct NamespacedRoleClaims<'a> {
        sub: &'a str,
        iss: &'a str,
        aud: &'a str,
        exp: u64,
        #[serde(rename = "https://claims.example/roles")]
        namespaced_roles: Vec<&'a str>,
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
    struct ClientResourceAccessClaims<'a> {
        #[serde(rename = "orders-service")]
        orders_service: ResourceRolesClaims<'a>,
    }

    #[derive(Serialize)]
    struct ResourceRolesClaims<'a> {
        roles: Vec<&'a str>,
    }
}

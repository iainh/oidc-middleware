use crate::config_helpers::{load_optional_non_empty_string, load_required_claims, split_csv};
use crate::token::validate_authorization_scheme;
use jsonwebtoken::Algorithm;
use mp_config::{Config, ConfigProperties};
use std::collections::HashMap;
use std::str::FromStr;
use std::time::Duration;

const DEFAULT_ROLE_CLAIM_PATH: &str = "groups,realm_access.roles";

/// OIDC configuration loaded from the MicroProfile-style config model.
#[derive(Clone, Debug, ConfigProperties, Eq, PartialEq)]
#[config(prefix = "oidc", rename_all = "kebab-case")]
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
    /// Browser authentication settings used by `web-app` applications.
    #[config(nested)]
    pub authentication: OidcAuthenticationConfig,
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
    /// Loads `oidc.*` properties from an [`mp_config::Config`].
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
            authentication: OidcAuthenticationConfig::default(),
            credentials: OidcCredentialsConfig::default(),
            introspection_credentials: OidcIntrospectionCredentialsConfig::default(),
            token: OidcTokenConfig::default(),
            roles: OidcRolesConfig::default(),
        }
    }
}

/// Browser authentication settings loaded from `oidc.authentication.*`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcAuthenticationConfig {
    /// Redirect URI path or absolute URI used for authorization-code callbacks.
    pub redirect_path: String,
    /// Return users to their original path after completing the code flow.
    pub restore_path_after_redirect: bool,
    /// OIDC scopes requested from the provider.
    pub scopes: Vec<String>,
}

impl Default for OidcAuthenticationConfig {
    fn default() -> Self {
        Self {
            redirect_path: "/q/oidc/callback".to_owned(),
            restore_path_after_redirect: true,
            scopes: vec!["openid".to_owned()],
        }
    }
}

impl ConfigProperties for OidcAuthenticationConfig {
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

        let redirect_path = config
            .get_optional::<String>(&key("redirect-path"))?
            .unwrap_or_else(|| "/q/oidc/callback".to_owned());
        if redirect_path.trim().is_empty() {
            return Err(mp_config::ConfigError::Conversion {
                name: key("redirect-path"),
                value: redirect_path,
                message: "redirect-path must not be empty".to_owned(),
            });
        }

        let scopes = config
            .get_optional::<String>(&key("scopes"))?
            .map(|scopes| split_csv(&scopes))
            .unwrap_or_else(|| vec!["openid".to_owned()]);
        if scopes.is_empty() || !scopes.iter().any(|scope| scope == "openid") {
            return Err(mp_config::ConfigError::Conversion {
                name: key("scopes"),
                value: scopes.join(","),
                message: "web-app authentication scopes must include `openid`".to_owned(),
            });
        }

        Ok(Self {
            redirect_path,
            restore_path_after_redirect: config
                .get_optional(&key("restore-path-after-redirect"))?
                .unwrap_or(true),
            scopes,
        })
    }
}

/// Client credential configuration loaded from `oidc.credentials.*`.
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
    pub(crate) fn effective_client_secret(&self) -> Option<&str> {
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
    pub(crate) fn auth_server_url(self) -> Option<&'static str> {
        match self {
            Self::Google => Some("https://accounts.google.com"),
            _ => None,
        }
    }

    pub(crate) fn as_config_value(self) -> &'static str {
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

/// Token validation configuration loaded from `oidc.token.*`.
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

/// Token binding validation configuration loaded from `oidc.token.binding.*`.
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
    pub(crate) fn audiences(&self) -> Vec<String> {
        self.audience.as_deref().map(split_csv).unwrap_or_default()
    }

    pub(crate) fn accepts_any_audience(&self) -> bool {
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

/// Role extraction configuration loaded from `oidc.roles.*`.
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

pub(crate) fn role_claim_paths_for_source(config: &OidcConfig, source: RolesSource) -> Vec<String> {
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
    pub(crate) fn algorithm(self) -> Algorithm {
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

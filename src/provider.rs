use crate::{BuildError, OidcConfig};
use serde::Deserialize;

/// OpenID Provider metadata used by discovery.
///
/// This models the provider fields this crate needs rather than the full OIDC
/// discovery document. Unknown metadata is ignored; endpoint-specific features
/// are enabled only when the corresponding field is present or explicitly
/// configured.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct ProviderMetadata {
    /// Canonical issuer returned by the provider.
    ///
    /// When token issuer configuration is absent, this value becomes the
    /// expected `iss` claim for JWT and introspection validation.
    pub issuer: Option<String>,
    /// JSON Web Key Set URL returned by the provider.
    ///
    /// This endpoint is required for provider-backed JWT validation.
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
    ///
    /// This is mainly useful for tests or applications that fetch and cache
    /// discovery metadata outside the middleware builder.
    pub fn from_json(json: &str) -> std::result::Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

pub(crate) fn discovery_url(
    auth_server_url: &str,
    discovery_path: &str,
) -> crate::BuildResult<reqwest::Url> {
    provider_endpoint_url(auth_server_url, discovery_path)
}

pub(crate) fn auth_server_url_from_config(config: &OidcConfig) -> crate::BuildResult<String> {
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

pub(crate) fn provider_endpoint_url(
    auth_server_url: &str,
    path: &str,
) -> crate::BuildResult<reqwest::Url> {
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

pub(crate) fn provider_validation_config(
    config: &OidcConfig,
    metadata: &ProviderMetadata,
) -> OidcConfig {
    let mut validation_config = config.clone();
    if validation_config.token.issuer.is_none() {
        validation_config.token.issuer = metadata.issuer.clone();
    }
    validation_config
}

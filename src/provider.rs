#[cfg(all(feature = "http-client", feature = "jwt"))]
use crate::{BuildError, OidcConfig};
use serde::Deserialize;

/// OpenID Provider metadata used by discovery.
///
/// This models the provider fields this crate needs rather than the full OIDC
/// discovery document. Unknown metadata is ignored; endpoint-specific features
/// are enabled only when the corresponding field is present or explicitly
/// configured. The field names follow OpenID Connect Discovery 1.0 Section 3,
/// with `end_session_endpoint` included for RP-Initiated Logout discovery.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(try_from = "RawProviderMetadata")]
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

#[derive(Deserialize)]
struct RawProviderMetadata {
    issuer: Option<String>,
    jwks_uri: String,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    registration_endpoint: Option<String>,
    revocation_endpoint: Option<String>,
    introspection_endpoint: Option<String>,
    userinfo_endpoint: Option<String>,
    end_session_endpoint: Option<String>,
}

impl TryFrom<RawProviderMetadata> for ProviderMetadata {
    type Error = &'static str;

    fn try_from(raw: RawProviderMetadata) -> Result<Self, Self::Error> {
        if raw.issuer.as_deref().is_none_or(str::is_empty) {
            return Err("provider metadata requires a non-empty issuer");
        }
        Ok(Self {
            issuer: raw.issuer,
            jwks_uri: raw.jwks_uri,
            authorization_endpoint: raw.authorization_endpoint,
            token_endpoint: raw.token_endpoint,
            registration_endpoint: raw.registration_endpoint,
            revocation_endpoint: raw.revocation_endpoint,
            introspection_endpoint: raw.introspection_endpoint,
            userinfo_endpoint: raw.userinfo_endpoint,
            end_session_endpoint: raw.end_session_endpoint,
        })
    }
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

#[cfg(all(feature = "http-client", feature = "jwt"))]
pub(crate) fn discovery_url(
    auth_server_url: &str,
    discovery_path: &str,
) -> crate::BuildResult<reqwest::Url> {
    provider_endpoint_url(auth_server_url, discovery_path)
}

#[cfg(all(feature = "http-client", feature = "jwt"))]
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

#[cfg(all(feature = "http-client", feature = "jwt"))]
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
    let parsed = reqwest::Url::parse(&url).map_err(|error| BuildError::InvalidUrl {
        url,
        message: error.to_string(),
    })?;
    validate_secure_url(&parsed)?;
    Ok(parsed)
}

#[cfg(all(feature = "http-client", feature = "jwt"))]
fn validate_secure_url(url: &reqwest::Url) -> crate::BuildResult<()> {
    let loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(BuildError::InvalidUrl {
            url: url.to_string(),
            message: "security-sensitive OIDC URLs must use HTTPS (HTTP is allowed only for loopback development)".to_owned(),
        });
    }
    Ok(())
}

#[cfg(all(feature = "http-client", feature = "jwt"))]
pub(crate) fn validate_provider_metadata(
    metadata: &ProviderMetadata,
    expected_issuer: Option<&str>,
) -> crate::BuildResult<()> {
    let issuer = metadata
        .issuer
        .as_deref()
        .ok_or_else(|| BuildError::InvalidConfiguration {
            message: "provider metadata requires an issuer".to_owned(),
        })?;
    if expected_issuer.is_some_and(|expected| expected != issuer) {
        return Err(BuildError::InvalidConfiguration {
            message: format!(
                "provider metadata issuer `{issuer}` did not exactly match configured issuer `{}`",
                expected_issuer.unwrap()
            ),
        });
    }

    for endpoint in std::iter::once(issuer)
        .chain(std::iter::once(metadata.jwks_uri.as_str()))
        .chain(
            [
                metadata.authorization_endpoint.as_deref(),
                metadata.token_endpoint.as_deref(),
                metadata.registration_endpoint.as_deref(),
                metadata.revocation_endpoint.as_deref(),
                metadata.introspection_endpoint.as_deref(),
                metadata.userinfo_endpoint.as_deref(),
                metadata.end_session_endpoint.as_deref(),
            ]
            .into_iter()
            .flatten(),
        )
    {
        let url = reqwest::Url::parse(endpoint).map_err(|error| BuildError::InvalidUrl {
            url: endpoint.to_owned(),
            message: error.to_string(),
        })?;
        validate_secure_url(&url)?;
    }
    Ok(())
}

#[cfg(all(feature = "http-client", feature = "jwt"))]
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

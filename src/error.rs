use crate::{BoxError, WellKnownProvider};
use axum::response::{IntoResponse, Response};
use http::header::WWW_AUTHENTICATE;
use http::{HeaderValue, StatusCode};
use std::error::Error as StdError;
use std::fmt;

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

    pub(crate) fn into_response_with_scheme(self, scheme: &str) -> Response {
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

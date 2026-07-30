use crate::{BoxError, WellKnownProvider};
use axum::response::{IntoResponse, Response};
use http::header::WWW_AUTHENTICATE;
use http::{HeaderValue, Method, StatusCode};
use std::error::Error as StdError;
use std::fmt;
use tracing::error;

/// Error type returned while authenticating a request.
///
/// The type also implements Axum's response conversion so middleware can turn
/// authentication failures into RFC 6750-style HTTP responses. `401` responses
/// include `WWW-Authenticate`; authorization failures use `403`; disabled
/// tenants use `404` to avoid advertising inactive tenant resources.
#[derive(Debug)]
pub enum Error {
    /// The request did not include an authorization token.
    ///
    /// The challenged scheme follows `oidc.token.authorization-scheme` when
    /// configured, so non-Bearer deployments still get consistent responses.
    MissingBearerToken,
    /// The `Authorization` header was not valid UTF-8 or not in bearer format.
    InvalidAuthorizationHeader,
    /// The configured token header exceeded the maximum accepted size.
    AuthorizationHeaderTooLarge,
    /// An OIDC form-post callback had an invalid method, content type, or body.
    InvalidCallbackRequest,
    /// An OIDC form-post callback body exceeded the defensive size limit.
    CallbackBodyTooLarge,
    /// The selected tenant is disabled.
    ///
    /// This maps to `404 Not Found`, mirroring the common Quarkus behaviour of
    /// hiding disabled tenant routes rather than treating them as bad tokens.
    TenantDisabled,
    /// The authenticated principal is not allowed to access the route.
    ///
    /// This is used after authentication succeeds but a route layer or handler
    /// macro rejects the principal's roles.
    Forbidden,
    /// The validator rejected the token.
    TokenRejected(BoxError),
    /// Web-app redirect or token-state handling failed.
    Session(BoxError),
}

impl Error {
    fn status(&self) -> StatusCode {
        match self {
            Self::TenantDisabled => StatusCode::NOT_FOUND,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::InvalidCallbackRequest => StatusCode::BAD_REQUEST,
            Self::CallbackBodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Session(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::MissingBearerToken
            | Self::InvalidAuthorizationHeader
            | Self::AuthorizationHeaderTooLarge
            | Self::TokenRejected(_) => StatusCode::UNAUTHORIZED,
        }
    }

    fn challenge(&self) -> HeaderValue {
        self.challenge_with_scheme("Bearer")
    }

    fn challenge_with_scheme(&self, scheme: &str) -> HeaderValue {
        let value = match self {
            Self::MissingBearerToken | Self::TenantDisabled | Self::Forbidden => scheme.to_owned(),
            Self::InvalidAuthorizationHeader | Self::AuthorizationHeaderTooLarge => {
                format!(r#"{scheme} error="invalid_request""#)
            }
            Self::TokenRejected(_) => format!(r#"{scheme} error="invalid_token""#),
            Self::InvalidCallbackRequest | Self::CallbackBodyTooLarge => scheme.to_owned(),
            Self::Session(_) => scheme.to_owned(),
        };
        HeaderValue::from_str(&value).unwrap_or_else(|_| self.challenge())
    }

    pub(crate) fn into_response_with_scheme_for_request(
        self,
        scheme: &str,
        method: &Method,
        path: &str,
    ) -> Response {
        let status = self.status();
        self.log_opaque_server_error_for_request(status, method, path);
        let mut response = status.into_response();
        if status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, self.challenge_with_scheme(scheme));
        }
        response
    }

    pub(crate) fn into_callback_response_for_request(
        self,
        method: &Method,
        path: &str,
    ) -> Response {
        let status = self.status();
        self.log_opaque_server_error_for_request(status, method, path);
        status.into_response()
    }

    fn log_opaque_server_error(&self, status: StatusCode) {
        if status.is_server_error() {
            error!(
                status = status.as_u16(),
                error = %self,
                "OIDC authentication failed with an opaque server error response"
            );
        }
    }

    fn log_opaque_server_error_for_request(&self, status: StatusCode, method: &Method, path: &str) {
        if status.is_server_error() {
            error!(
                %method,
                path,
                status = status.as_u16(),
                error = %self,
                "OIDC authentication failed with an opaque server error response"
            );
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingBearerToken => write!(f, "missing bearer token"),
            Self::InvalidAuthorizationHeader => write!(f, "invalid authorization header"),
            Self::AuthorizationHeaderTooLarge => write!(f, "authorization token header too large"),
            Self::InvalidCallbackRequest => write!(f, "invalid OIDC callback request"),
            Self::CallbackBodyTooLarge => write!(f, "OIDC callback body too large"),
            Self::TenantDisabled => write!(f, "OIDC tenant is disabled"),
            Self::Forbidden => write!(f, "authenticated principal is not allowed"),
            Self::TokenRejected(source) => write!(f, "token rejected: {source}"),
            Self::Session(source) => write!(f, "OIDC web-app state handling failed: {source}"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::TokenRejected(source) => Some(source.as_ref()),
            Self::Session(source) => Some(source.as_ref()),
            _ => None,
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let status = self.status();
        self.log_opaque_server_error(status);
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
///
/// Build errors are deliberately separated from request-time [`Error`] values.
/// They describe configuration, provider discovery, and endpoint wiring issues
/// that should normally be caught during application startup.
#[derive(Debug)]
pub enum BuildError {
    /// Loading `mp-config` backed OIDC configuration failed.
    Config(mp_config::ConfigError),
    /// Provider discovery requires `oidc.auth-server-url`.
    MissingAuthServerUrl,
    /// The configured well-known provider has no built-in issuer URL yet.
    UnsupportedWellKnownProvider(WellKnownProvider),
    /// Direct JWKS loading requires `oidc.jwks-path`.
    MissingJwksPath,
    /// Remote token introspection requires a configured or discovered endpoint.
    MissingIntrospectionEndpoint,
    /// UserInfo token validation requires a configured or discovered endpoint.
    MissingUserInfoEndpoint,
    /// Web-app authorization-code redirects require an authorization endpoint.
    MissingAuthorizationEndpoint,
    /// Web-app authorization-code callbacks require a token endpoint.
    MissingTokenEndpoint,
    /// Web-app authorization-code flow requires `oidc.client-id`.
    MissingClientId,
    /// Web-app and hybrid applications require a local ID-token verifier.
    MissingIdTokenValidator,
    /// Web-app authorization-code flow requires the `web-app` crate feature.
    WebAppFeatureDisabled,
    /// The configured public key could not be parsed.
    InvalidPublicKey(BoxError),
    /// A configured provider or metadata URL could not be parsed.
    InvalidUrl {
        /// The URL value assembled from configuration or discovery metadata.
        url: String,
        /// Parser detail suitable for startup logs or diagnostics.
        message: String,
    },
    /// OIDC configuration was structurally valid but unusable.
    InvalidConfiguration {
        /// Configuration detail suitable for startup logs or diagnostics.
        message: String,
    },
    /// Fetching provider metadata or keys failed.
    #[cfg(feature = "http-client")]
    Http(reqwest::Error),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(source) => write!(f, "OIDC configuration failed: {source}"),
            Self::MissingAuthServerUrl => {
                write!(f, "OIDC provider discovery requires `oidc.auth-server-url`")
            }
            Self::UnsupportedWellKnownProvider(provider) => write!(
                f,
                "well-known OIDC provider `{}` requires `oidc.auth-server-url` until its issuer URL is built in",
                provider.as_config_value()
            ),
            Self::MissingJwksPath => write!(
                f,
                "OIDC JWKS loading requires `oidc.jwks-path` when discovery is disabled"
            ),
            Self::MissingIntrospectionEndpoint => write!(
                f,
                "OIDC token introspection requires an introspection endpoint"
            ),
            Self::MissingUserInfoEndpoint => {
                write!(f, "OIDC UserInfo validation requires a UserInfo endpoint")
            }
            Self::MissingAuthorizationEndpoint => {
                write!(
                    f,
                    "OIDC web-app authentication requires an authorization endpoint"
                )
            }
            Self::MissingTokenEndpoint => {
                write!(f, "OIDC web-app authentication requires a token endpoint")
            }
            Self::MissingClientId => {
                write!(f, "OIDC web-app authentication requires `oidc.client-id`")
            }
            Self::MissingIdTokenValidator => write!(
                f,
                "OIDC web-app and hybrid applications require a local ID-token validator"
            ),
            Self::WebAppFeatureDisabled => write!(
                f,
                "OIDC web-app authentication requires the `web-app` crate feature"
            ),
            Self::InvalidPublicKey(source) => write!(f, "invalid OIDC public key: {source}"),
            Self::InvalidUrl { url, message } => write!(f, "invalid URL `{url}`: {message}"),
            Self::InvalidConfiguration { message } => {
                write!(f, "invalid OIDC configuration: {message}")
            }
            #[cfg(feature = "http-client")]
            Self::Http(source) => write!(f, "OIDC provider request failed: {source}"),
        }
    }
}

impl StdError for BuildError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Config(source) => Some(source),
            Self::InvalidPublicKey(source) => Some(source.as_ref()),
            #[cfg(feature = "http-client")]
            Self::Http(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(feature = "http-client")]
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

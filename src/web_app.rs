use crate::provider::provider_endpoint_url;
use crate::{BuildError, Error, OidcConfig, Principal, Result, TokenValidator};
use axum::body::Body;
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::header::{CONTENT_TYPE, HOST, LOCATION};
use http::{HeaderValue, Request, StatusCode};
use serde::{Deserialize, Serialize};
use std::error::Error as StdError;
use std::sync::Arc;
use tower_sessions::Session;
use tracing::{debug, trace};
use url::form_urlencoded;

const PRINCIPAL_KEY: &str = "oidc.principal";
const STATE_KEY: &str = "oidc.state";
const ORIGINAL_URI_KEY: &str = "oidc.original-uri";

#[derive(Clone)]
pub(crate) struct WebApp {
    client: reqwest::Client,
    client_id: String,
    client_secret: Option<String>,
    authorization_endpoint: String,
    token_endpoint: String,
    redirect_path: String,
    restore_path_after_redirect: bool,
    scopes: Vec<String>,
}

impl WebApp {
    pub(crate) fn from_config(
        config: &OidcConfig,
        client: reqwest::Client,
    ) -> crate::BuildResult<Self> {
        let auth_server_url = config.auth_server_url.as_deref();
        let authorization_endpoint = endpoint(
            auth_server_url,
            config.authorization_path.as_deref(),
            BuildError::MissingAuthorizationEndpoint,
        )?;
        let token_endpoint = endpoint(
            auth_server_url,
            config.token_path.as_deref(),
            BuildError::MissingTokenEndpoint,
        )?;
        debug!(
            authorization_endpoint = %authorization_endpoint,
            token_endpoint = %token_endpoint,
            "building web-app support from configured endpoints"
        );
        Self::new(config, client, authorization_endpoint, token_endpoint)
    }

    pub(crate) fn from_provider_metadata(
        config: &OidcConfig,
        client: reqwest::Client,
        authorization_endpoint: Option<String>,
        token_endpoint: Option<String>,
    ) -> crate::BuildResult<Self> {
        let authorization_endpoint =
            authorization_endpoint.ok_or(BuildError::MissingAuthorizationEndpoint)?;
        let token_endpoint = token_endpoint.ok_or(BuildError::MissingTokenEndpoint)?;
        debug!(
            authorization_endpoint = %authorization_endpoint,
            token_endpoint = %token_endpoint,
            "building web-app support from provider metadata"
        );
        Self::new(config, client, authorization_endpoint, token_endpoint)
    }

    fn new(
        config: &OidcConfig,
        client: reqwest::Client,
        authorization_endpoint: String,
        token_endpoint: String,
    ) -> crate::BuildResult<Self> {
        debug!(
            redirect_path = %config.authentication.redirect_path,
            restore_path_after_redirect = config.authentication.restore_path_after_redirect,
            scopes = ?config.authentication.scopes,
            has_client_secret = config.credentials.effective_client_secret().is_some(),
            "configured OIDC web-app flow"
        );
        Ok(Self {
            client,
            client_id: config
                .client_id
                .clone()
                .ok_or(BuildError::MissingClientId)?,
            client_secret: config
                .credentials
                .effective_client_secret()
                .map(ToOwned::to_owned),
            authorization_endpoint,
            token_endpoint,
            redirect_path: config.authentication.redirect_path.clone(),
            restore_path_after_redirect: config.authentication.restore_path_after_redirect,
            scopes: config.authentication.scopes.clone(),
        })
    }

    pub(crate) fn is_callback(&self, request: &Request<Body>) -> bool {
        path_matches(&self.redirect_path, request.uri().path())
    }

    pub(crate) async fn session_principal(
        &self,
        request: &mut Request<Body>,
    ) -> Result<Option<Principal>> {
        let Some(session) = session(request) else {
            trace!(path = %request.uri().path(), "web-app request has no session extension");
            return Ok(None);
        };
        let stored = session
            .get::<StoredPrincipal>(PRINCIPAL_KEY)
            .await
            .map_err(session_error)?;
        trace!(
            path = %request.uri().path(),
            has_principal = stored.is_some(),
            "checked web-app session for stored principal"
        );
        Ok(stored.map(StoredPrincipal::into_principal))
    }

    pub(crate) async fn authorization_redirect(
        &self,
        request: &mut Request<Body>,
    ) -> Result<Response> {
        let session = session(request).ok_or_else(|| {
            Error::Session(std::io::Error::other("missing tower-sessions Session extension").into())
        })?;
        let original_uri = request.uri().to_string();
        let redirect_uri = self.redirect_uri(request)?;
        let state = random_state()?;
        debug!(
            original_uri = %original_uri,
            redirect_uri = %redirect_uri,
            authorization_endpoint = %self.authorization_endpoint,
            "creating OIDC authorization redirect"
        );
        session
            .insert(STATE_KEY, state.clone())
            .await
            .map_err(session_error)?;
        if self.restore_path_after_redirect {
            trace!(original_uri = %original_uri, "storing original URI before OIDC redirect");
            session
                .insert(ORIGINAL_URI_KEY, original_uri)
                .await
                .map_err(session_error)?;
        }

        let mut serializer = form_urlencoded::Serializer::new(String::new());
        serializer
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("scope", &self.scopes.join(" "))
            .append_pair("state", &state);
        redirect_response(&format!(
            "{}?{}",
            self.authorization_endpoint,
            serializer.finish()
        ))
    }

    pub(crate) async fn callback(
        &self,
        request: &mut Request<Body>,
        validator: Arc<dyn TokenValidator>,
    ) -> Result<Response> {
        let session = session(request).ok_or_else(|| {
            Error::Session(std::io::Error::other("missing tower-sessions Session extension").into())
        })?;
        let query = request.uri().query().unwrap_or_default().to_owned();
        let redirect_uri = self.redirect_uri(request)?;
        let params = form_urlencoded::parse(query.as_bytes()).collect::<Vec<_>>();
        debug!(redirect_uri = %redirect_uri, "processing OIDC authorization callback");
        if let Some(error) = value(&params, "error") {
            debug!(provider_error = %error, "OIDC authorization endpoint returned an error");
            return Err(Error::TokenRejected(
                std::io::Error::other(format!("authorization endpoint returned `{error}`")).into(),
            ));
        }
        let code = value(&params, "code").ok_or(Error::InvalidAuthorizationHeader)?;
        let state = value(&params, "state").ok_or(Error::InvalidAuthorizationHeader)?;
        let expected_state = session
            .get::<String>(STATE_KEY)
            .await
            .map_err(session_error)?
            .ok_or(Error::InvalidAuthorizationHeader)?;
        if expected_state != state {
            debug!("OIDC callback state did not match session state");
            return Err(Error::InvalidAuthorizationHeader);
        }
        session
            .remove::<String>(STATE_KEY)
            .await
            .map_err(session_error)?;

        let token_response = self.exchange_code(&code, &redirect_uri).await?;
        trace!(
            has_id_token = token_response.id_token.is_some(),
            "OIDC token endpoint returned callback tokens"
        );
        let token = token_response
            .id_token
            .as_deref()
            .unwrap_or(&token_response.access_token);
        let principal = validator.validate(Arc::from(token.to_owned())).await?;
        session
            .insert(PRINCIPAL_KEY, StoredPrincipal::from_principal(&principal))
            .await
            .map_err(session_error)?;

        trace!(
            groups = principal.groups().count(),
            "stored web-app principal in session"
        );
        let redirect_to = session
            .remove::<String>(ORIGINAL_URI_KEY)
            .await
            .map_err(session_error)?
            .unwrap_or_else(|| "/".to_owned());
        debug!(redirect_to = %redirect_to, "OIDC web-app callback completed");
        redirect_response(&redirect_to)
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> Result<TokenResponse> {
        let mut form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", self.client_id.as_str()),
        ];
        if let Some(secret) = self.client_secret.as_deref() {
            form.push(("client_secret", secret));
        }
        debug!(token_endpoint = %self.token_endpoint, "exchanging OIDC authorization code for tokens");
        let response = self
            .client
            .post(&self.token_endpoint)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&form)
            .send()
            .await
            .map_err(|error| Error::TokenRejected(error.into()))?
            .error_for_status()
            .map_err(|error| Error::TokenRejected(error.into()))?
            .json::<TokenResponse>()
            .await
            .map_err(|error| Error::TokenRejected(error.into()))?;
        Ok(response)
    }

    fn redirect_uri(&self, request: &Request<Body>) -> Result<String> {
        if self.redirect_path.starts_with("http://") || self.redirect_path.starts_with("https://") {
            trace!(redirect_uri = %self.redirect_path, "using absolute OIDC redirect URI");
            return Ok(self.redirect_path.clone());
        }
        let host = request
            .headers()
            .get("x-forwarded-host")
            .or_else(|| request.headers().get(HOST))
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| {
                Error::Session(
                    std::io::Error::other("missing Host header for OIDC redirect URI").into(),
                )
            })?;
        let scheme = request
            .headers()
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok())
            .or_else(|| request.uri().scheme_str())
            .unwrap_or("http");
        let redirect_uri = format!("{scheme}://{host}{}", self.redirect_path);
        trace!(redirect_uri = %redirect_uri, "built OIDC redirect URI from request headers");
        Ok(redirect_uri)
    }
}

fn endpoint(
    auth_server_url: Option<&str>,
    path: Option<&str>,
    missing_error: BuildError,
) -> crate::BuildResult<String> {
    let path = path.ok_or(missing_error)?;
    if let Some(auth_server_url) = auth_server_url {
        return provider_endpoint_url(auth_server_url, path).map(|url| url.into());
    }
    reqwest::Url::parse(path)
        .map(|url| url.into())
        .map_err(|error| BuildError::InvalidUrl {
            url: path.to_owned(),
            message: error.to_string(),
        })
}

fn path_matches(configured: &str, actual: &str) -> bool {
    if configured.starts_with("http://") || configured.starts_with("https://") {
        return reqwest::Url::parse(configured)
            .map(|url| url.path() == actual)
            .unwrap_or(false);
    }
    configured == actual
}

fn session(request: &Request<Body>) -> Option<Session> {
    request.extensions().get::<Session>().cloned()
}

fn value(
    params: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
    name: &str,
) -> Option<String> {
    params
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.to_string())
}

fn redirect_response(location: &str) -> Result<Response> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::FOUND;
    response.headers_mut().insert(
        LOCATION,
        HeaderValue::from_str(location).map_err(|error| {
            Error::Session(
                std::io::Error::other(format!("invalid redirect location: {error}")).into(),
            )
        })?,
    );
    Ok(response)
}

fn random_state() -> Result<String> {
    let mut bytes = [0_u8; 32];
    getrandom::getrandom(&mut bytes).map_err(|error| {
        Error::Session(
            std::io::Error::other(format!("failed to generate OIDC state: {error}")).into(),
        )
    })?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn session_error<E>(error: E) -> Error
where
    E: StdError + Send + Sync + 'static,
{
    Error::Session(error.into())
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    id_token: Option<String>,
}

#[derive(Deserialize, Serialize)]
struct StoredPrincipal {
    subject: String,
    issuer: Option<String>,
    audience: Vec<String>,
    groups: Vec<String>,
}

impl StoredPrincipal {
    fn from_principal(principal: &Principal) -> Self {
        Self {
            subject: principal.subject().to_owned(),
            issuer: principal.issuer().map(ToOwned::to_owned),
            audience: principal.audience().map(ToOwned::to_owned).collect(),
            groups: principal.groups().map(ToOwned::to_owned).collect(),
        }
    }

    fn into_principal(self) -> Principal {
        Principal::from_parts(self.subject, self.issuer, self.audience, self.groups)
    }
}

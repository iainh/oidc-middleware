use crate::provider::provider_endpoint_url;
use crate::validation_claims::unix_timestamp;
use crate::{
    BuildError, Error, IdToken, IdTokenClaims, OidcConfig, Principal, Result, TokenValidator,
};
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
const ID_TOKEN_KEY: &str = "oidc.id-token";
const TOKEN_STATE_KEY: &str = "oidc.token-state";
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
    refresh_expired: bool,
    refresh_token_time_skew: Option<u64>,
    lifespan_grace: u64,
    session_age_extension: u64,
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
            refresh_expired: config.token.refresh_expired,
            refresh_token_time_skew: config
                .token
                .refresh_token_time_skew
                .map(|duration| duration.as_secs()),
            lifespan_grace: config.token.lifespan_grace.unwrap_or_default(),
            session_age_extension: config.authentication.session_age_extension.as_secs(),
            scopes: config.authentication.scopes.clone(),
        })
    }

    pub(crate) fn is_callback(&self, request: &Request<Body>) -> bool {
        path_matches(&self.redirect_path, request.uri().path())
    }

    pub(crate) async fn session_context(
        &self,
        request: &mut Request<Body>,
        validator: Arc<dyn TokenValidator>,
    ) -> Result<Option<WebAppSession>> {
        let Some(session) = session(request) else {
            trace!(path = %request.uri().path(), "web-app request has no session extension");
            return Ok(None);
        };
        let stored_principal = session
            .get::<StoredPrincipal>(PRINCIPAL_KEY)
            .await
            .map_err(session_error)?;
        let stored_id_token = session
            .get::<StoredIdToken>(ID_TOKEN_KEY)
            .await
            .map_err(session_error)?;
        let stored_token_state = session
            .get::<StoredTokenState>(TOKEN_STATE_KEY)
            .await
            .map_err(session_error)?;
        trace!(
            path = %request.uri().path(),
            has_principal = stored_principal.is_some(),
            has_id_token = stored_id_token.is_some(),
            has_token_state = stored_token_state.is_some(),
            "checked web-app session for stored principal"
        );
        let Some(stored_principal) = stored_principal else {
            return Ok(None);
        };
        let Some(stored_token_state) = stored_token_state else {
            debug!("web-app session principal did not include token state");
            clear_authentication(&session).await?;
            return Ok(None);
        };

        match stored_token_state.freshness(
            unix_timestamp()?,
            self.refresh_token_time_skew,
            self.lifespan_grace,
            self.session_age_extension,
        ) {
            TokenFreshness::Current => Ok(Some(WebAppSession {
                principal: stored_principal.into_principal(),
                id_token: stored_id_token.map(StoredIdToken::into_id_token),
            })),
            TokenFreshness::RefreshNeeded if self.refresh_enabled() => {
                let Some(refresh_token) = stored_token_state.refresh_token.as_deref() else {
                    if stored_token_state.is_expired(unix_timestamp()?, self.lifespan_grace) {
                        clear_authentication(&session).await?;
                        return Ok(None);
                    }
                    return Ok(Some(WebAppSession {
                        principal: stored_principal.into_principal(),
                        id_token: stored_id_token.map(StoredIdToken::into_id_token),
                    }));
                };
                match self.refresh_tokens(refresh_token).await {
                    Ok(token_response) => {
                        let refreshed = match self
                            .validated_tokens(token_response, validator, Some(refresh_token))
                            .await
                        {
                            Ok(refreshed) => refreshed,
                            Err(error) => {
                                debug!(%error, "OIDC refreshed tokens were rejected; clearing web-app session");
                                clear_authentication(&session).await?;
                                return Ok(None);
                            }
                        };
                        store_authentication(&session, &refreshed).await?;
                        Ok(Some(refreshed.into_session()))
                    }
                    Err(error) => {
                        debug!(%error, "OIDC token refresh failed; clearing web-app session");
                        clear_authentication(&session).await?;
                        Ok(None)
                    }
                }
            }
            TokenFreshness::RefreshNeeded | TokenFreshness::Expired => {
                debug!("web-app session tokens are expired and refresh is unavailable");
                clear_authentication(&session).await?;
                Ok(None)
            }
        }
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
        let authenticated = self
            .validated_tokens(token_response, validator, None)
            .await?;
        store_authentication(&session, &authenticated).await?;

        trace!(
            groups = authenticated.principal.groups().count(),
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

    fn refresh_enabled(&self) -> bool {
        self.refresh_expired || self.refresh_token_time_skew.is_some()
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
        let response = self.token_request(&form).await?;
        Ok(response)
    }

    async fn refresh_tokens(&self, refresh_token: &str) -> Result<TokenResponse> {
        let mut form = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", self.client_id.as_str()),
        ];
        if let Some(secret) = self.client_secret.as_deref() {
            form.push(("client_secret", secret));
        }
        debug!(token_endpoint = %self.token_endpoint, "refreshing OIDC web-app tokens");
        self.token_request(&form).await
    }

    async fn token_request(&self, form: &[(&str, &str)]) -> Result<TokenResponse> {
        let response = self
            .client
            .post(&self.token_endpoint)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(form)
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

    async fn validated_tokens(
        &self,
        token_response: TokenResponse,
        validator: Arc<dyn TokenValidator>,
        previous_refresh_token: Option<&str>,
    ) -> Result<AuthenticatedTokens> {
        let validated_id_token = match token_response.id_token.as_deref() {
            Some(raw) => Some(validate_id_token(raw, validator.clone()).await?),
            None => None,
        };
        let principal = match validator
            .validate(Arc::from(token_response.access_token.clone()))
            .await
        {
            Ok(principal) => principal,
            Err(error) => match &validated_id_token {
                Some((_, principal)) => principal.clone(),
                None => return Err(error),
            },
        };
        let now = unix_timestamp()?;
        let id_token = validated_id_token.map(|(id_token, _)| id_token);
        let token_state = StoredTokenState::from_response(
            &token_response,
            previous_refresh_token,
            &id_token,
            now,
        );

        Ok(AuthenticatedTokens {
            principal,
            id_token,
            token_state,
        })
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

pub(crate) struct WebAppSession {
    pub(crate) principal: Principal,
    pub(crate) id_token: Option<IdToken>,
}

struct AuthenticatedTokens {
    principal: Principal,
    id_token: Option<IdToken>,
    token_state: StoredTokenState,
}

impl AuthenticatedTokens {
    fn into_session(self) -> WebAppSession {
        WebAppSession {
            principal: self.principal,
            id_token: self.id_token,
        }
    }
}

async fn validate_id_token(
    token: &str,
    validator: Arc<dyn TokenValidator>,
) -> Result<(IdToken, Principal)> {
    let principal = validator.validate(Arc::from(token.to_owned())).await?;
    let claims = decode_id_token_claims(token)?;
    Ok((IdToken::with_raw(claims, token), principal))
}

fn decode_id_token_claims(token: &str) -> Result<IdTokenClaims> {
    let mut parts = token.split('.');
    let Some(_header) = parts.next() else {
        return Err(Error::TokenRejected("ID token is missing a header".into()));
    };
    let Some(payload) = parts.next() else {
        return Err(Error::TokenRejected("ID token is missing a payload".into()));
    };
    if parts.next().is_none() {
        return Err(Error::TokenRejected(
            "ID token is missing a signature".into(),
        ));
    }
    if parts.next().is_some() {
        return Err(Error::TokenRejected(
            "ID token has too many segments".into(),
        ));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|error| Error::TokenRejected(Box::new(error)))?;
    serde_json::from_slice::<IdTokenClaims>(&decoded)
        .map_err(|error| Error::TokenRejected(Box::new(error)))
}

fn unverified_jwt_exp(token: &str) -> Option<u64> {
    let payload = token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims = serde_json::from_slice::<serde_json::Value>(&decoded).ok()?;
    claims.get("exp").and_then(serde_json::Value::as_u64)
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

async fn store_authentication(
    session: &Session,
    authenticated: &AuthenticatedTokens,
) -> Result<()> {
    session
        .insert(
            PRINCIPAL_KEY,
            StoredPrincipal::from_principal(&authenticated.principal),
        )
        .await
        .map_err(session_error)?;
    match &authenticated.id_token {
        Some(id_token) => {
            session
                .insert(ID_TOKEN_KEY, StoredIdToken::from_id_token(id_token))
                .await
                .map_err(session_error)?;
        }
        None => {
            session
                .remove::<StoredIdToken>(ID_TOKEN_KEY)
                .await
                .map_err(session_error)?;
        }
    }
    session
        .insert(TOKEN_STATE_KEY, &authenticated.token_state)
        .await
        .map_err(session_error)?;
    Ok(())
}

async fn clear_authentication(session: &Session) -> Result<()> {
    session
        .remove::<StoredPrincipal>(PRINCIPAL_KEY)
        .await
        .map_err(session_error)?;
    session
        .remove::<StoredIdToken>(ID_TOKEN_KEY)
        .await
        .map_err(session_error)?;
    session
        .remove::<StoredTokenState>(TOKEN_STATE_KEY)
        .await
        .map_err(session_error)?;
    Ok(())
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
    refresh_token: Option<String>,
    expires_in: Option<u64>,
}

#[derive(Deserialize, Serialize)]
struct StoredPrincipal {
    subject: String,
    issuer: Option<String>,
    audience: Vec<String>,
    groups: Vec<String>,
}

#[derive(Deserialize, Serialize)]
struct StoredIdToken {
    claims: IdTokenClaims,
    raw: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
struct StoredTokenState {
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<u64>,
}

enum TokenFreshness {
    Current,
    RefreshNeeded,
    Expired,
}

impl StoredTokenState {
    fn from_response(
        response: &TokenResponse,
        previous_refresh_token: Option<&str>,
        id_token: &Option<IdToken>,
        now: u64,
    ) -> Self {
        let expires_at = [
            id_token.as_ref().and_then(IdToken::expires_at),
            unverified_jwt_exp(&response.access_token),
            response
                .expires_in
                .map(|expires_in| now.saturating_add(expires_in)),
        ]
        .into_iter()
        .flatten()
        .min();

        Self {
            access_token: response.access_token.clone(),
            refresh_token: response
                .refresh_token
                .clone()
                .or_else(|| previous_refresh_token.map(ToOwned::to_owned)),
            expires_at,
        }
    }

    fn freshness(
        &self,
        now: u64,
        refresh_token_time_skew: Option<u64>,
        lifespan_grace: u64,
        session_age_extension: u64,
    ) -> TokenFreshness {
        let Some(expires_at) = self.expires_at else {
            return TokenFreshness::Current;
        };
        let expires_with_grace = expires_at.saturating_add(lifespan_grace);
        let refreshable_until = expires_with_grace.saturating_add(session_age_extension);
        if now >= refreshable_until {
            return TokenFreshness::Expired;
        }
        if now >= expires_with_grace {
            return TokenFreshness::RefreshNeeded;
        }
        if refresh_token_time_skew.is_some_and(|skew| now.saturating_add(skew) > expires_at) {
            return TokenFreshness::RefreshNeeded;
        }
        TokenFreshness::Current
    }

    fn is_expired(&self, now: u64, lifespan_grace: u64) -> bool {
        self.expires_at
            .is_some_and(|expires_at| now >= expires_at.saturating_add(lifespan_grace))
    }
}

impl StoredIdToken {
    fn from_id_token(id_token: &IdToken) -> Self {
        Self {
            claims: id_token.claims().clone(),
            raw: id_token.raw().map(ToOwned::to_owned),
        }
    }

    fn into_id_token(self) -> IdToken {
        match self.raw {
            Some(raw) => IdToken::with_raw(self.claims, raw),
            None => IdToken::new(self.claims),
        }
    }
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

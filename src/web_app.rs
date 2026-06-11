use crate::provider::provider_endpoint_url;
use crate::validation_claims::unix_timestamp;
use crate::{
    BuildError, ClientSecretMethod, Error, IdToken, IdTokenClaims, OidcConfig, Principal, Result,
    TokenValidator,
};
use axum::body::Body;
use axum::response::Response;
use axum::routing::{MethodRouter, get_service};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use cookie::time::Duration as CookieDuration;
use cookie::{Cookie, CookieJar, Key, SameSite};
use http::header::{CONTENT_TYPE, COOKIE, HOST, LOCATION, SET_COOKIE};
use http::{HeaderValue, Request, StatusCode};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::convert::Infallible;
use std::error::Error as StdError;
use std::future::{Future, Ready, ready};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower_service::Service;
use tracing::{debug, trace, warn};
use url::form_urlencoded;

const TOKEN_STATE_COOKIE_NAME: &str = "q_oidc";
const REDIRECT_STATE_COOKIE_NAME: &str = "q_oidc_redirect";
const REDIRECT_STATE_COOKIE_MAX_AGE_SECS: i64 = 600;
const MAX_COOKIE_HEADER_BYTES: usize = 16 * 1024;
const MAX_COOKIE_SEGMENTS: usize = 64;

#[derive(Clone)]
pub(crate) struct WebApp {
    client: reqwest::Client,
    client_id: String,
    client_secret: Option<String>,
    client_secret_method: ClientSecretMethod,
    authorization_endpoint: String,
    token_endpoint: String,
    end_session_endpoint: Option<String>,
    redirect_path: String,
    restore_path_after_redirect: bool,
    refresh_expired: bool,
    refresh_token_time_skew: Option<u64>,
    lifespan_grace: u64,
    session_age_extension: u64,
    scopes: Vec<String>,
    token_state_cookie: CookieTokenStateManager,
    redirect_state_cookie: RedirectStateCookieManager,
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
        let end_session_endpoint =
            optional_endpoint(auth_server_url, config.end_session_path.as_deref())?;
        debug!(
            authorization_endpoint = %authorization_endpoint,
            token_endpoint = %token_endpoint,
            end_session_endpoint = ?end_session_endpoint,
            "building web-app support from configured endpoints"
        );
        Self::new(
            config,
            client,
            authorization_endpoint,
            token_endpoint,
            end_session_endpoint,
        )
    }

    pub(crate) fn from_provider_metadata(
        config: &OidcConfig,
        client: reqwest::Client,
        authorization_endpoint: Option<String>,
        token_endpoint: Option<String>,
        end_session_endpoint: Option<String>,
    ) -> crate::BuildResult<Self> {
        let authorization_endpoint =
            authorization_endpoint.ok_or(BuildError::MissingAuthorizationEndpoint)?;
        let token_endpoint = token_endpoint.ok_or(BuildError::MissingTokenEndpoint)?;
        debug!(
            authorization_endpoint = %authorization_endpoint,
            token_endpoint = %token_endpoint,
            end_session_endpoint = ?end_session_endpoint,
            "building web-app support from provider metadata"
        );
        Self::new(
            config,
            client,
            authorization_endpoint,
            token_endpoint,
            end_session_endpoint,
        )
    }

    fn new(
        config: &OidcConfig,
        client: reqwest::Client,
        authorization_endpoint: String,
        token_endpoint: String,
        end_session_endpoint: Option<String>,
    ) -> crate::BuildResult<Self> {
        debug!(
            redirect_path = %config.authentication.redirect_path,
            restore_path_after_redirect = config.authentication.restore_path_after_redirect,
            scopes = ?config.authentication.scopes,
            has_client_secret = config.credentials.effective_client_secret().is_some(),
            refresh_expired = config.token.refresh_expired,
            refresh_token_time_skew_secs = ?config
                .token
                .refresh_token_time_skew
                .map(|duration| duration.as_secs()),
            lifespan_grace_secs = config.token.lifespan_grace.unwrap_or_default(),
            session_age_extension_secs = config.authentication.session_age_extension.as_secs(),
            has_token_state_cookie_key = config.authentication.token_state_cookie_key.is_some(),
            "configured OIDC web-app flow"
        );
        let configured_cookie_key = config.authentication.token_state_cookie_key.as_deref();
        let cookie_key = web_app_cookie_key(configured_cookie_key)?;
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
            client_secret_method: config.credentials.client_secret.method,
            authorization_endpoint,
            token_endpoint,
            end_session_endpoint,
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
            token_state_cookie: CookieTokenStateManager::new(
                cookie_key.clone(),
                configured_cookie_key.is_some(),
                config.token.lifespan_grace.unwrap_or_default(),
                config.authentication.session_age_extension.as_secs(),
                config.token.refresh_expired || config.token.refresh_token_time_skew.is_some(),
            )?,
            redirect_state_cookie: RedirectStateCookieManager::new(
                cookie_key,
                configured_cookie_key.is_some(),
            ),
        })
    }

    pub(crate) fn is_callback(&self, request: &Request<Body>) -> bool {
        path_matches(&self.redirect_path, request.uri().path())
    }

    pub(crate) fn callback_path(&self) -> Result<String> {
        if self.redirect_path.starts_with("http://") || self.redirect_path.starts_with("https://") {
            return reqwest::Url::parse(&self.redirect_path)
                .map(|url| url.path().to_owned())
                .map_err(|error| {
                    Error::Session(
                        std::io::Error::other(format!(
                            "invalid OIDC callback redirect URI `{}`: {error}",
                            self.redirect_path
                        ))
                        .into(),
                    )
                });
        }
        Ok(self.redirect_path.clone())
    }

    pub(crate) async fn session_context(
        &self,
        request: &mut Request<Body>,
        validator: Arc<dyn TokenValidator>,
    ) -> Result<Option<WebAppSession>> {
        let stored_authentication = self.token_state_cookie.load(request)?;
        trace!(
            path = %request.uri().path(),
            has_authentication = stored_authentication.is_some(),
            "checked web-app token-state cookie for stored authentication"
        );
        let Some(stored_authentication) = stored_authentication else {
            if self.token_state_cookie.has_cookie(request) {
                debug!("web-app token-state cookie could not be decrypted; clearing it");
                queue_cookie(request, self.token_state_cookie.clear()?);
            }
            return Ok(None);
        };
        let stored_principal = stored_authentication.principal;
        let stored_id_token = stored_authentication.id_token;
        let stored_token_state = stored_authentication.token_state;

        let freshness = stored_token_state.freshness(
            unix_timestamp()?,
            self.refresh_token_time_skew,
            self.lifespan_grace,
            self.session_age_extension,
        );
        trace!(
            freshness = freshness.as_str(),
            expires_at = ?stored_token_state.expires_at,
            has_refresh_token = stored_token_state.refresh_token.is_some(),
            refresh_enabled = self.refresh_enabled(),
            "classified web-app token-state freshness"
        );

        match freshness {
            TokenFreshness::Current => Ok(Some(WebAppSession {
                principal: stored_principal.into_principal(),
                id_token: stored_id_token.map(StoredIdToken::into_id_token),
            })),
            TokenFreshness::RefreshNeeded if self.refresh_enabled() => {
                let Some(refresh_token) = stored_token_state.refresh_token.as_deref() else {
                    if stored_token_state.is_expired(unix_timestamp()?, self.lifespan_grace) {
                        debug!(
                            expires_at = ?stored_token_state.expires_at,
                            lifespan_grace_secs = self.lifespan_grace,
                            "web-app token state is expired without a refresh token"
                        );
                        clear_authentication(request, &self.token_state_cookie)?;
                        return Ok(None);
                    }
                    trace!(
                        expires_at = ?stored_token_state.expires_at,
                        lifespan_grace_secs = self.lifespan_grace,
                        "web-app token state needs refresh but remains within grace without refresh token"
                    );
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
                                debug!(error = %error, "OIDC refreshed tokens were rejected; clearing token-state cookie");
                                clear_authentication(request, &self.token_state_cookie)?;
                                return Ok(None);
                            }
                        };
                        debug!(
                            expires_at = ?refreshed.token_state.expires_at,
                            has_id_token = refreshed.id_token.is_some(),
                            has_refresh_token = refreshed.token_state.refresh_token.is_some(),
                            "OIDC token refresh succeeded"
                        );
                        store_authentication(request, &self.token_state_cookie, &refreshed)?;
                        Ok(Some(refreshed.into_session()))
                    }
                    Err(error) => {
                        debug!(error = %error, "OIDC token refresh failed; clearing token-state cookie");
                        clear_authentication(request, &self.token_state_cookie)?;
                        Ok(None)
                    }
                }
            }
            TokenFreshness::RefreshNeeded | TokenFreshness::Expired => {
                debug!("web-app token-state cookie is expired and refresh is unavailable");
                clear_authentication(request, &self.token_state_cookie)?;
                Ok(None)
            }
        }
    }

    pub(crate) async fn authorization_redirect(
        &self,
        request: &mut Request<Body>,
    ) -> Result<Response> {
        let original_uri = request.uri().to_string();
        let redirect_uri = self.redirect_uri(request)?;
        let state = random_state()?;
        debug!(
            original_uri = %original_uri,
            redirect_uri = %redirect_uri,
            authorization_endpoint = %self.authorization_endpoint,
            "creating OIDC authorization redirect"
        );
        let redirect_state = RedirectState {
            state: state.clone(),
            original_uri: self
                .restore_path_after_redirect
                .then_some(original_uri.clone()),
        };

        let mut serializer = form_urlencoded::Serializer::new(String::new());
        // OpenID Connect Core 1.0 Section 3.1.2.1 requires `scope` with
        // `openid`, `response_type=code`, `client_id`, and the `redirect_uri`
        // used for the token request. Section 3.1.2.2 leaves `state`
        // RECOMMENDED; Quarkus and Payara both bind the code flow to local
        // state. We store that state in an encrypted cookie instead of sending
        // a nonce, which is optional for Authorization Code Flow unless sent.
        serializer
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("scope", &self.scopes.join(" "))
            .append_pair("state", &state);
        let mut response = redirect_response(&format!(
            "{}?{}",
            self.authorization_endpoint,
            serializer.finish()
        ))?;
        response.headers_mut().append(
            SET_COOKIE,
            self.redirect_state_cookie.store(&redirect_state)?,
        );
        with_pending_cookies(request, response)
    }

    pub(crate) async fn callback(
        &self,
        request: &mut Request<Body>,
        validator: Arc<dyn TokenValidator>,
    ) -> Result<Response> {
        let redirect_uri = self.redirect_uri(request)?;
        let params = CallbackQuery::parse(request.uri().query().unwrap_or_default());
        debug!(redirect_uri = %redirect_uri, "processing OIDC authorization callback");
        if let Some(error) = params.error {
            debug!(provider_error = %error, "OIDC authorization endpoint returned an error");
            return Err(Error::TokenRejected(
                std::io::Error::other(format!("authorization endpoint returned `{error}`")).into(),
            ));
        }
        let code = params.code.ok_or_else(|| {
            warn!("OIDC callback did not include an authorization code");
            Error::InvalidAuthorizationHeader
        })?;
        let state = params.state.ok_or_else(|| {
            warn!("OIDC callback did not include a state parameter");
            Error::InvalidAuthorizationHeader
        })?;
        let redirect_state = self.redirect_state_cookie.load(request)?.ok_or_else(|| {
            warn!("OIDC callback did not include a readable redirect-state cookie");
            Error::InvalidAuthorizationHeader
        })?;
        if redirect_state.state != state {
            warn!("OIDC callback state did not match redirect-state cookie");
            return Err(Error::InvalidAuthorizationHeader);
        }

        // OpenID Connect Core 1.0 Section 3.1.3.1 requires the authorization
        // code grant token request to include the code and redirect_uri used in
        // the Authentication Request. The state check above is the local
        // correlation guard before exchanging the code.
        let token_response = self.exchange_code(&code, &redirect_uri).await?;
        trace!(
            has_id_token = token_response.id_token.is_some(),
            "OIDC token endpoint returned callback tokens"
        );
        let authenticated = self
            .validated_tokens(token_response, validator, None)
            .await?;
        let redirect_to = redirect_state
            .original_uri
            .unwrap_or_else(|| "/".to_owned());
        let mut response = redirect_response(&redirect_to)?;
        response
            .headers_mut()
            .append(SET_COOKIE, self.redirect_state_cookie.clear()?);
        store_authentication_cookie(&self.token_state_cookie, &mut response, &authenticated)?;

        trace!(
            groups = authenticated.principal.groups().count(),
            "stored web-app principal in token-state cookie"
        );
        debug!(redirect_to = %redirect_to, "OIDC web-app callback completed");
        Ok(response)
    }

    fn refresh_enabled(&self) -> bool {
        self.refresh_expired || self.refresh_token_time_skew.is_some()
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> Result<TokenResponse> {
        let form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
        ];
        debug!(token_endpoint = %self.token_endpoint, "exchanging OIDC authorization code for tokens");
        let response = self.token_request(&form).await?;
        Ok(response)
    }

    async fn refresh_tokens(&self, refresh_token: &str) -> Result<TokenResponse> {
        let form = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ];
        debug!(token_endpoint = %self.token_endpoint, "refreshing OIDC web-app tokens");
        self.token_request(&form).await
    }

    async fn token_request(&self, form: &[(&str, &str)]) -> Result<TokenResponse> {
        let grant_type = form
            .iter()
            .find_map(|(name, value)| (*name == "grant_type").then_some(*value))
            .unwrap_or("unknown");
        trace!(
            grant_type,
            token_endpoint = %self.token_endpoint,
            client_secret_method = ?self.client_secret_method,
            has_client_secret = self.client_secret.is_some(),
            "sending OIDC token endpoint request"
        );
        // OpenID Connect Core 1.0 Section 9 defines client authentication for
        // token endpoint calls. This maps the Quarkus-compatible
        // `credentials.client-secret.method` setting to the common
        // client_secret_basic, client_secret_post, and query-parameter shapes.
        let request = match (self.client_secret.as_deref(), self.client_secret_method) {
            (Some(secret), ClientSecretMethod::Basic) => self
                .client
                .post(&self.token_endpoint)
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .form(form)
                .basic_auth(&self.client_id, Some(secret)),
            (Some(secret), ClientSecretMethod::Post) => {
                let mut authenticated_form = form.to_vec();
                authenticated_form.push(("client_id", self.client_id.as_str()));
                authenticated_form.push(("client_secret", secret));
                self.client
                    .post(&self.token_endpoint)
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .form(&authenticated_form)
            }
            (Some(secret), ClientSecretMethod::Query) => self
                .client
                .post(&self.token_endpoint)
                .query(&[
                    ("client_id", self.client_id.as_str()),
                    ("client_secret", secret),
                ])
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .form(form),
            (None, _) => {
                let mut public_form = form.to_vec();
                public_form.push(("client_id", self.client_id.as_str()));
                self.client
                    .post(&self.token_endpoint)
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .form(&public_form)
            }
        };
        let response = request
            .send()
            .await
            .map_err(|error| Error::TokenRejected(error.into()))?
            .error_for_status()
            .map_err(|error| Error::TokenRejected(error.into()))?
            .json::<TokenResponse>()
            .await
            .map_err(|error| Error::TokenRejected(error.into()))?;
        trace!(
            grant_type,
            has_id_token = response.id_token.is_some(),
            has_refresh_token = response.refresh_token.is_some(),
            expires_in = ?response.expires_in,
            "received OIDC token endpoint response"
        );
        Ok(response)
    }

    async fn validated_tokens(
        &self,
        token_response: TokenResponse,
        validator: Arc<dyn TokenValidator>,
        previous_refresh_token: Option<&str>,
    ) -> Result<AuthenticatedTokens> {
        trace!(
            has_id_token = token_response.id_token.is_some(),
            has_refresh_token = token_response.refresh_token.is_some(),
            expires_in = ?token_response.expires_in,
            previous_refresh_token = previous_refresh_token.is_some(),
            "validating OIDC web-app token response"
        );
        // OpenID Connect Core 1.0 Section 3.1.3.7 requires ID Token validation
        // after a successful code exchange. Access-token validation is
        // deliberately application-specific in Section 3.1.3.8, so the same
        // configured validator is used for both token shapes and provider
        // conventions can be selected by configuration.
        let validated_id_token = match token_response.id_token.as_deref() {
            Some(raw) => Some(validate_id_token(raw, validator.clone()).await?),
            None => None,
        };
        let principal = match validator
            .validate(Arc::from(token_response.access_token.clone()))
            .await
        {
            Ok(principal) => {
                trace!("validated OIDC access token from web-app token response");
                principal
            }
            Err(error) => match &validated_id_token {
                Some((_, principal)) => {
                    debug!(
                        error = %error,
                        "access token validation failed; using validated ID token principal"
                    );
                    principal.clone()
                }
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
        absolute_request_uri(request, &self.redirect_path, "OIDC redirect URI")
    }

    fn logout(&self, request: Request<Body>, options: &OidcLogoutOptions) -> Result<Response> {
        let id_token_hint = if options.id_token_hint {
            match self.token_state_cookie.load(&request) {
                Ok(authentication) => authentication
                    .and_then(|authentication| authentication.id_token)
                    .and_then(|id_token| id_token.raw),
                Err(error) => {
                    debug!(error = %error, "OIDC logout could not read token-state cookie for id_token_hint");
                    None
                }
            }
        } else {
            None
        };

        // RP-Initiated Logout 1.0 defines `id_token_hint` and
        // `post_logout_redirect_uri`. Quarkus and Payara both treat provider
        // notification as an optional redirect to the discovered or configured
        // end-session endpoint after clearing local RP state.
        let mut response = match self.end_session_endpoint.as_deref() {
            Some(endpoint) => {
                self.end_session_redirect(&request, endpoint, id_token_hint, options)?
            }
            None => {
                let location = options
                    .post_logout_redirect
                    .as_deref()
                    .unwrap_or(OidcLogoutOptions::DEFAULT_POST_LOGOUT_REDIRECT);
                redirect_response(location)?
            }
        };
        append_logout_cookies(
            &self.token_state_cookie,
            &self.redirect_state_cookie,
            &mut response,
        )?;
        Ok(response)
    }

    fn end_session_redirect(
        &self,
        request: &Request<Body>,
        endpoint: &str,
        id_token_hint: Option<String>,
        options: &OidcLogoutOptions,
    ) -> Result<Response> {
        let mut url = reqwest::Url::parse(endpoint).map_err(|error| {
            Error::Session(
                std::io::Error::other(format!(
                    "invalid OIDC end-session endpoint `{endpoint}`: {error}"
                ))
                .into(),
            )
        })?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(id_token_hint) = id_token_hint {
                query.append_pair("id_token_hint", &id_token_hint);
            }
            if let Some(post_logout_redirect) = options.post_logout_redirect.as_deref() {
                let post_logout_redirect_uri = absolute_request_uri(
                    request,
                    post_logout_redirect,
                    "OIDC post-logout redirect URI",
                )?;
                query.append_pair(
                    &options.post_logout_redirect_uri_parameter,
                    &post_logout_redirect_uri,
                );
            }
            for (name, value) in &options.extra_params {
                query.append_pair(name, value);
            }
        }
        debug!(end_session_endpoint = %endpoint, "redirecting to OIDC provider logout endpoint");
        redirect_response(url.as_str())
    }
}

fn absolute_request_uri(
    request: &Request<Body>,
    path_or_uri: &str,
    purpose: &str,
) -> Result<String> {
    if path_or_uri.starts_with("http://") || path_or_uri.starts_with("https://") {
        trace!(uri = %path_or_uri, purpose, "using absolute URI");
        return Ok(path_or_uri.to_owned());
    }
    if !path_or_uri.starts_with('/') {
        return Err(Error::Session(
            std::io::Error::other(format!("{purpose} path must start with `/`")).into(),
        ));
    }
    let host = request_host(request).ok_or_else(|| {
        warn!(
            path = %request.uri().path(),
            configured_path = %path_or_uri,
            "cannot build absolute OIDC URI without Host, X-Forwarded-Host, URI authority, or an absolute configured URI"
        );
        Error::Session(
            std::io::Error::other(
                format!("missing request host for {purpose}; set Host/X-Forwarded-Host, use an absolute request URI, or configure an absolute URI"),
            )
            .into(),
        )
    })?;
    let scheme = request
        .headers()
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .or_else(|| request.uri().scheme_str())
        .unwrap_or("http");
    let uri = format!("{scheme}://{host}{path_or_uri}");
    trace!(uri = %uri, purpose, "built absolute OIDC URI from request origin");
    Ok(uri)
}

pub(crate) struct WebAppSession {
    pub(crate) principal: Principal,
    pub(crate) id_token: Option<IdToken>,
}

/// Options used by the web-app logout route.
///
/// The logout route always clears the local OIDC cookies. When the provider
/// exposes an end-session endpoint, the route redirects there after clearing
/// local state. Otherwise it redirects to [`Self::post_logout_redirect`], which
/// defaults to `/`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcLogoutOptions {
    /// Local or absolute URI to redirect to after logout.
    ///
    /// Relative values must start with `/`. For provider logout, relative
    /// values are expanded to an absolute `post_logout_redirect_uri` from the
    /// request host and scheme. For local-only logout, the same value is used
    /// directly as the response `Location`.
    pub post_logout_redirect: Option<String>,
    /// Provider query parameter name used for the post-logout redirect URI.
    pub post_logout_redirect_uri_parameter: String,
    /// Extra query parameters sent to the provider end-session endpoint.
    pub extra_params: HashMap<String, String>,
    /// Include the current raw ID token as `id_token_hint` when redirecting to
    /// the provider end-session endpoint.
    pub id_token_hint: bool,
}

impl OidcLogoutOptions {
    const DEFAULT_POST_LOGOUT_REDIRECT: &'static str = "/";
}

impl Default for OidcLogoutOptions {
    fn default() -> Self {
        Self {
            post_logout_redirect: Some(Self::DEFAULT_POST_LOGOUT_REDIRECT.to_owned()),
            post_logout_redirect_uri_parameter: "post_logout_redirect_uri".to_owned(),
            extra_params: HashMap::new(),
            id_token_hint: true,
        }
    }
}

/// Options used by [`crate::Oidc::web_app_routes`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcWebAppRoutesOptions {
    /// Relative application path that starts logout.
    pub logout_path: String,
    /// Logout route behavior.
    pub logout: OidcLogoutOptions,
}

impl Default for OidcWebAppRoutesOptions {
    fn default() -> Self {
        Self {
            logout_path: "/q/oidc/logout".to_owned(),
            logout: OidcLogoutOptions::default(),
        }
    }
}

/// Axum service backing the OIDC authorization-code callback route.
#[derive(Clone)]
pub(crate) struct OidcCallbackService {
    web_app: Arc<WebApp>,
    validator: Arc<dyn TokenValidator>,
    authorization_scheme: String,
}

impl OidcCallbackService {
    pub(crate) fn new(
        web_app: Arc<WebApp>,
        validator: Arc<dyn TokenValidator>,
        authorization_scheme: String,
    ) -> Self {
        Self {
            web_app,
            validator,
            authorization_scheme,
        }
    }

    pub(crate) fn route<S>(self) -> MethodRouter<S>
    where
        S: Clone,
    {
        get_service(self)
    }
}

impl Service<Request<Body>> for OidcCallbackService {
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = std::result::Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, mut request: Request<Body>) -> Self::Future {
        let web_app = self.web_app.clone();
        let validator = self.validator.clone();
        let authorization_scheme = self.authorization_scheme.clone();

        Box::pin(async move {
            let method = request.method().clone();
            let path = request.uri().path().to_owned();
            let response = web_app
                .callback(&mut request, validator)
                .await
                .unwrap_or_else(|error| {
                    error.into_response_with_scheme_for_request(
                        &authorization_scheme,
                        &method,
                        &path,
                    )
                });
            Ok(response)
        })
    }
}

/// Axum service backing [`crate::Oidc::logout_route`].
#[derive(Clone)]
pub struct OidcLogoutService {
    web_app: Option<Arc<WebApp>>,
    options: OidcLogoutOptions,
    authorization_scheme: String,
}

impl OidcLogoutService {
    pub(crate) fn new(
        web_app: Option<Arc<WebApp>>,
        options: OidcLogoutOptions,
        authorization_scheme: String,
    ) -> Self {
        Self {
            web_app,
            options,
            authorization_scheme,
        }
    }

    /// Converts this service into a `GET` route.
    ///
    /// Add the route outside [`crate::Oidc::layer`] so logout can clear local
    /// session cookies without first requiring a valid session.
    pub fn route<S>(self) -> MethodRouter<S>
    where
        S: Clone,
    {
        get_service(self)
    }
}

impl Service<Request<Body>> for OidcLogoutService {
    type Response = Response;
    type Error = Infallible;
    type Future = Ready<std::result::Result<Response, Infallible>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<std::result::Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let response = match &self.web_app {
            Some(web_app) => web_app.logout(request, &self.options),
            None => local_logout_response(&self.options),
        }
        .unwrap_or_else(|error| {
            error.into_response_with_scheme_for_request(&self.authorization_scheme, &method, &path)
        });
        ready(Ok(response))
    }
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
    trace!("validating OIDC ID token from web-app token response");
    // The validator enforces signature, issuer, audience, exp, and iat policy.
    // If this crate starts sending a nonce in the Authentication Request,
    // OpenID Connect Core 1.0 Section 3.1.3.7 requires checking the returned
    // ID Token `nonce` here against the stored redirect state.
    let principal = validator.validate(Arc::from(token.to_owned())).await?;
    let claims = decode_id_token_claims(token)?;
    trace!(
        has_subject = claims.sub.is_some(),
        has_issuer = claims.iss.is_some(),
        audiences = claims.aud.len(),
        expires_at = ?claims.exp,
        "decoded OIDC ID token claims"
    );
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

fn optional_endpoint(
    auth_server_url: Option<&str>,
    path: Option<&str>,
) -> crate::BuildResult<Option<String>> {
    path.map(|path| {
        endpoint(
            auth_server_url,
            Some(path),
            BuildError::MissingTokenEndpoint,
        )
    })
    .transpose()
}

fn path_matches(configured: &str, actual: &str) -> bool {
    if configured.starts_with("http://") || configured.starts_with("https://") {
        return reqwest::Url::parse(configured)
            .map(|url| url.path() == actual)
            .unwrap_or(false);
    }
    configured == actual
}

fn request_host(request: &Request<Body>) -> Option<&str> {
    request
        .headers()
        .get("x-forwarded-host")
        .or_else(|| request.headers().get(HOST))
        .and_then(|value| value.to_str().ok())
        .or_else(|| request.uri().authority().map(http::uri::Authority::as_str))
}

#[derive(Clone)]
pub(crate) struct PendingWebAppCookies(Vec<HeaderValue>);

impl PendingWebAppCookies {
    pub(crate) fn append_to(self, response: &mut Response) {
        trace!(
            cookies = self.0.len(),
            "appending pending web-app cookies to response"
        );
        for cookie in self.0 {
            response.headers_mut().append(SET_COOKIE, cookie);
        }
    }
}

fn queue_cookie(request: &mut Request<Body>, cookie: HeaderValue) {
    if let Some(pending) = request.extensions_mut().get_mut::<PendingWebAppCookies>() {
        pending.0.push(cookie);
    } else {
        request
            .extensions_mut()
            .insert(PendingWebAppCookies(vec![cookie]));
    }
}

fn with_pending_cookies(request: &mut Request<Body>, mut response: Response) -> Result<Response> {
    if let Some(pending) = request.extensions_mut().remove::<PendingWebAppCookies>() {
        pending.append_to(&mut response);
    }
    Ok(response)
}

fn store_authentication(
    request: &mut Request<Body>,
    token_state_cookie: &CookieTokenStateManager,
    authenticated: &AuthenticatedTokens,
) -> Result<()> {
    queue_cookie(request, token_state_cookie.store(authenticated)?);
    Ok(())
}

fn store_authentication_cookie(
    token_state_cookie: &CookieTokenStateManager,
    response: &mut Response,
    authenticated: &AuthenticatedTokens,
) -> Result<()> {
    response
        .headers_mut()
        .append(SET_COOKIE, token_state_cookie.store(authenticated)?);
    Ok(())
}

fn append_logout_cookies(
    token_state_cookie: &CookieTokenStateManager,
    redirect_state_cookie: &RedirectStateCookieManager,
    response: &mut Response,
) -> Result<()> {
    response
        .headers_mut()
        .append(SET_COOKIE, token_state_cookie.clear()?);
    response
        .headers_mut()
        .append(SET_COOKIE, redirect_state_cookie.clear()?);
    Ok(())
}

fn local_logout_response(options: &OidcLogoutOptions) -> Result<Response> {
    let location = options
        .post_logout_redirect
        .as_deref()
        .unwrap_or(OidcLogoutOptions::DEFAULT_POST_LOGOUT_REDIRECT);
    redirect_response(location)
}

fn clear_authentication(
    request: &mut Request<Body>,
    token_state_cookie: &CookieTokenStateManager,
) -> Result<()> {
    queue_cookie(request, token_state_cookie.clear()?);
    Ok(())
}

#[derive(Clone)]
struct CookieTokenStateManager {
    key: Key,
    lifespan_grace: u64,
    session_age_extension: u64,
    refresh_enabled: bool,
}

impl CookieTokenStateManager {
    fn new(
        key: Key,
        has_configured_key: bool,
        lifespan_grace: u64,
        session_age_extension: u64,
        refresh_enabled: bool,
    ) -> crate::BuildResult<Self> {
        debug!(
            has_configured_key,
            lifespan_grace_secs = lifespan_grace,
            session_age_extension_secs = session_age_extension,
            refresh_enabled,
            "configured web-app token-state cookie manager"
        );
        Ok(Self {
            key,
            lifespan_grace,
            session_age_extension,
            refresh_enabled,
        })
    }

    fn load(&self, request: &Request<Body>) -> Result<Option<StoredAuthentication>> {
        let jar = request_cookie_jar(request);
        let Some(cookie) = jar.private(&self.key).get(TOKEN_STATE_COOKIE_NAME) else {
            trace!("web-app token-state cookie was not present or could not be decrypted");
            return Ok(None);
        };
        trace!("loaded encrypted web-app token-state cookie");
        serde_json::from_str(cookie.value())
            .map(Some)
            .map_err(session_error)
    }

    fn has_cookie(&self, request: &Request<Body>) -> bool {
        request_cookie_jar(request)
            .get(TOKEN_STATE_COOKIE_NAME)
            .is_some()
    }

    fn store(&self, authenticated: &AuthenticatedTokens) -> Result<HeaderValue> {
        self.store_stored(&StoredAuthentication::from_authenticated(authenticated))
    }

    fn store_stored(&self, authentication: &StoredAuthentication) -> Result<HeaderValue> {
        let value = serde_json::to_string(authentication).map_err(session_error)?;
        let mut jar = CookieJar::new();
        let max_age = self.max_age(authentication.token_state.expires_at);
        trace!(
            expires_at = ?authentication.token_state.expires_at,
            max_age_secs = ?max_age.map(|duration| duration.whole_seconds()),
            has_refresh_token = authentication.token_state.refresh_token.is_some(),
            has_id_token = authentication.id_token.is_some(),
            "storing web-app token state in encrypted cookie"
        );
        jar.private_mut(&self.key)
            .add(self.cookie_builder(value, max_age).build());
        let encrypted = jar.get(TOKEN_STATE_COOKIE_NAME).ok_or_else(|| {
            session_error(std::io::Error::other("token-state cookie was not created"))
        })?;
        header_value(encrypted.encoded().to_string())
    }

    fn clear(&self) -> Result<HeaderValue> {
        trace!("clearing web-app token-state cookie");
        header_value(
            Cookie::build((TOKEN_STATE_COOKIE_NAME, ""))
                .path("/")
                .http_only(true)
                .same_site(SameSite::Lax)
                .max_age(CookieDuration::ZERO)
                .build()
                .encoded()
                .to_string(),
        )
    }

    fn cookie_builder(
        &self,
        value: String,
        max_age: Option<CookieDuration>,
    ) -> cookie::CookieBuilder<'static> {
        let mut builder = Cookie::build((TOKEN_STATE_COOKIE_NAME, value))
            .path("/")
            .http_only(true)
            .same_site(SameSite::Lax);
        if let Some(max_age) = max_age {
            builder = builder.max_age(max_age);
        }
        builder
    }

    fn max_age(&self, expires_at: Option<u64>) -> Option<CookieDuration> {
        let expires_at = expires_at?;
        let extension = if self.refresh_enabled {
            self.session_age_extension
        } else {
            0
        };
        let valid_until = expires_at
            .saturating_add(self.lifespan_grace)
            .saturating_add(extension);
        let now = unix_timestamp().ok()?;
        let seconds = valid_until.saturating_sub(now);
        Some(CookieDuration::seconds(seconds.min(i64::MAX as u64) as i64))
    }
}

#[derive(Clone)]
struct RedirectStateCookieManager {
    key: Key,
}

impl RedirectStateCookieManager {
    fn new(key: Key, has_configured_key: bool) -> Self {
        debug!(
            has_configured_key,
            max_age_secs = REDIRECT_STATE_COOKIE_MAX_AGE_SECS,
            "configured web-app redirect-state cookie manager"
        );
        Self { key }
    }

    fn load(&self, request: &Request<Body>) -> Result<Option<RedirectState>> {
        let jar = request_cookie_jar(request);
        let Some(cookie) = jar.private(&self.key).get(REDIRECT_STATE_COOKIE_NAME) else {
            trace!("web-app redirect-state cookie was not present or could not be decrypted");
            return Ok(None);
        };
        trace!("loaded encrypted web-app redirect-state cookie");
        serde_json::from_str(cookie.value())
            .map(Some)
            .map_err(session_error)
    }

    fn store(&self, redirect_state: &RedirectState) -> Result<HeaderValue> {
        let value = serde_json::to_string(redirect_state).map_err(session_error)?;
        let mut jar = CookieJar::new();
        trace!(
            has_original_uri = redirect_state.original_uri.is_some(),
            max_age_secs = REDIRECT_STATE_COOKIE_MAX_AGE_SECS,
            "storing web-app redirect state in encrypted cookie"
        );
        jar.private_mut(&self.key)
            .add(self.cookie_builder(value).build());
        let encrypted = jar.get(REDIRECT_STATE_COOKIE_NAME).ok_or_else(|| {
            session_error(std::io::Error::other(
                "redirect-state cookie was not created",
            ))
        })?;
        header_value(encrypted.encoded().to_string())
    }

    fn clear(&self) -> Result<HeaderValue> {
        trace!("clearing web-app redirect-state cookie");
        header_value(
            Cookie::build((REDIRECT_STATE_COOKIE_NAME, ""))
                .path("/")
                .http_only(true)
                .same_site(SameSite::Lax)
                .max_age(CookieDuration::ZERO)
                .build()
                .encoded()
                .to_string(),
        )
    }

    fn cookie_builder(&self, value: String) -> cookie::CookieBuilder<'static> {
        Cookie::build((REDIRECT_STATE_COOKIE_NAME, value))
            .path("/")
            .http_only(true)
            .same_site(SameSite::Lax)
            .max_age(CookieDuration::seconds(REDIRECT_STATE_COOKIE_MAX_AGE_SECS))
    }
}

fn request_cookie_jar(request: &Request<Body>) -> CookieJar {
    let mut jar = CookieJar::new();
    let mut parsed = 0_usize;
    let mut ignored = 0_usize;
    for header in request.headers().get_all(COOKIE) {
        if header.as_bytes().len() > MAX_COOKIE_HEADER_BYTES {
            ignored += 1;
            trace!(
                header_bytes = header.as_bytes().len(),
                max_header_bytes = MAX_COOKIE_HEADER_BYTES,
                "ignored oversized cookie header while parsing web-app state"
            );
            continue;
        }
        let Ok(header) = header.to_str() else {
            ignored += 1;
            continue;
        };
        for cookie in header.split(';') {
            if parsed + ignored >= MAX_COOKIE_SEGMENTS {
                trace!(
                    max_cookie_segments = MAX_COOKIE_SEGMENTS,
                    "stopped parsing request cookies after reaching segment limit"
                );
                break;
            }
            let Ok(cookie) = Cookie::parse_encoded(cookie.trim().to_owned()) else {
                ignored += 1;
                continue;
            };
            parsed += 1;
            jar.add_original(cookie);
        }
    }
    trace!(
        parsed_cookies = parsed,
        ignored_cookie_segments = ignored,
        "parsed request cookies for web-app state"
    );
    jar
}

fn web_app_cookie_key(configured_key: Option<&str>) -> crate::BuildResult<Key> {
    match configured_key {
        Some(configured_key) => key_from_config(configured_key),
        None => generated_cookie_key(),
    }
}

fn generated_cookie_key() -> crate::BuildResult<Key> {
    let mut bytes = [0_u8; 64];
    getrandom::fill(&mut bytes).map_err(|error| BuildError::InvalidConfiguration {
        message: format!("failed to generate web-app token-state cookie key: {error}"),
    })?;
    warn!(
        "generated ephemeral web-app cookie key; configure oidc.authentication.token-state-cookie-key when callbacks can be handled by another process or middleware instance"
    );
    Ok(Key::from(&bytes))
}

fn key_from_config(value: &str) -> crate::BuildResult<Key> {
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| STANDARD.decode(value))
        .map_err(|error| BuildError::InvalidConfiguration {
            message: format!(
                "oidc.authentication.token-state-cookie-key must be base64-encoded key material: {error}"
            ),
        })?;
    let key =
        Key::try_from(decoded.as_slice()).map_err(|error| BuildError::InvalidConfiguration {
            message: format!("oidc.authentication.token-state-cookie-key is invalid: {error}"),
        })?;
    debug!(
        key_bytes = decoded.len(),
        "loaded configured web-app token-state cookie key"
    );
    Ok(key)
}

fn header_value(cookie: String) -> Result<HeaderValue> {
    HeaderValue::from_str(&cookie).map_err(|error| {
        Error::Session(
            std::io::Error::other(format!("invalid token-state cookie header: {error}")).into(),
        )
    })
}

struct CallbackQuery<'a> {
    code: Option<Cow<'a, str>>,
    state: Option<Cow<'a, str>>,
    error: Option<Cow<'a, str>>,
}

impl<'a> CallbackQuery<'a> {
    fn parse(query: &'a str) -> Self {
        let mut parsed = Self {
            code: None,
            state: None,
            error: None,
        };

        for (key, value) in form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "code" => parsed.code = Some(value),
                "state" => parsed.state = Some(value),
                "error" => parsed.error = Some(value),
                _ => {}
            }
        }

        parsed
    }
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
    getrandom::fill(&mut bytes).map_err(|error| {
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

#[derive(Deserialize, Serialize)]
struct StoredAuthentication {
    principal: StoredPrincipal,
    id_token: Option<StoredIdToken>,
    token_state: StoredTokenState,
}

#[derive(Deserialize, Serialize)]
struct RedirectState {
    state: String,
    original_uri: Option<String>,
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

impl TokenFreshness {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::RefreshNeeded => "refresh-needed",
            Self::Expired => "expired",
        }
    }
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

impl StoredAuthentication {
    fn from_authenticated(authenticated: &AuthenticatedTokens) -> Self {
        Self {
            principal: StoredPrincipal::from_principal(&authenticated.principal),
            id_token: authenticated
                .id_token
                .as_ref()
                .map(StoredIdToken::from_id_token),
            token_state: authenticated.token_state.clone(),
        }
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

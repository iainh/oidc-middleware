use crate::claims::{ClaimPath, compile_claim_paths, extract_roles};
use crate::config::role_claim_paths_for_source;
use crate::provider::provider_endpoint_url;
use crate::validation_claims::unix_timestamp;
use crate::{
    BuildError, ClientSecretMethod, Error, IdToken, IdTokenClaims, IdTokenValidator, OidcConfig,
    OidcResponseMode, Principal, Result, RolesSource, TokenValidator,
};
use axum::body::{Body, to_bytes};
use axum::response::{IntoResponse, Response};
use axum::routing::{MethodRouter, get_service, post_service};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use cookie::time::Duration as CookieDuration;
use cookie::{Cookie, CookieJar, Key, SameSite};
use http::header::{CONTENT_TYPE, COOKIE, HOST, LOCATION, SET_COOKIE};
use http::{HeaderValue, Request, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::HashMap;
use std::convert::Infallible;
use std::error::Error as StdError;
use std::future::{Future, Ready, poll_fn, ready};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use tower_service::Service;
use tracing::{debug, trace, warn};
use url::form_urlencoded;

const TOKEN_STATE_COOKIE_NAME: &str = "q_oidc";
const REDIRECT_STATE_COOKIE_NAME: &str = "q_oidc_redirect";
const REDIRECT_STATE_COOKIE_MAX_AGE_SECS: i64 = 600;
// Common browsers limit a cookie to 4096 bytes. Apply that limit to the whole
// encoded Set-Cookie value so the name and attributes are included as well.
const MAX_SET_COOKIE_BYTES: usize = 4096;
const MAX_COOKIE_HEADER_BYTES: usize = 16 * 1024;
const MAX_COOKIE_SEGMENTS: usize = 64;
const MAX_CALLBACK_FORM_BYTES: usize = 16 * 1024;
// Local defensive bounds for RFC 7239 parsing; the header ABNF is a list
// grammar and does not provide operational size limits.
const MAX_FORWARDED_HEADER_BYTES: usize = 8 * 1024;
const MAX_FORWARDED_HEADER_FIELDS: usize = 16;
const MAX_FORWARDED_ELEMENTS: usize = 32;
const MAX_FORWARDED_PARAMETERS: usize = 16;
const REFRESH_FLIGHT_RETENTION: Duration = Duration::from_secs(60);

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
    response_mode: OidcResponseMode,
    trust_forwarded_headers: bool,
    restore_path_after_redirect: bool,
    refresh_expired: bool,
    refresh_token_time_skew: Option<u64>,
    lifespan_grace: u64,
    session_age_extension: u64,
    scopes: Vec<String>,
    nonce_required: bool,
    id_token_role_claim_paths: Arc<[ClaimPath]>,
    role_claim_separator: Arc<str>,
    token_state_cookie: CookieTokenStateManager,
    redirect_state_cookie: RedirectStateCookieManager,
    refresh_flights: RefreshFlights,
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
            response_mode: config.authentication.response_mode,
            trust_forwarded_headers: config.authentication.trust_forwarded_headers,
            restore_path_after_redirect: config.authentication.restore_path_after_redirect,
            refresh_expired: config.token.refresh_expired,
            refresh_token_time_skew: config
                .token
                .refresh_token_time_skew
                .map(|duration| duration.as_secs()),
            lifespan_grace: config.token.lifespan_grace.unwrap_or_default(),
            session_age_extension: config.authentication.session_age_extension.as_secs(),
            scopes: config.authentication.scopes.clone(),
            nonce_required: config.authentication.nonce_required,
            id_token_role_claim_paths: compile_claim_paths(&role_claim_paths_for_source(
                config,
                RolesSource::IdToken,
            )),
            role_claim_separator: Arc::from(config.roles.role_claim_separator.clone()),
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
                config.authentication.response_mode,
            ),
            refresh_flights: RefreshFlights::default(),
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
        id_token_validator: Arc<dyn IdTokenValidator>,
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
        let stored_id_token = stored_authentication
            .id_token
            .map(StoredIdToken::into_id_token);
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
                id_token: stored_id_token,
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
                        id_token: stored_id_token,
                    }));
                };
                match self
                    .coordinated_refresh(
                        refresh_token,
                        validator,
                        id_token_validator,
                        stored_id_token.as_ref(),
                    )
                    .await
                {
                    Ok(refreshed) => {
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
        let nonce = self.nonce_required.then(random_nonce).transpose()?;
        let nonce_hash = nonce.as_deref().map(hash_nonce);
        let code_verifier = random_code_verifier()?;
        let code_challenge = pkce_code_challenge(&code_verifier);
        debug!(
            original_uri = %original_uri,
            redirect_uri = %redirect_uri,
            authorization_endpoint = %self.authorization_endpoint,
            "creating OIDC authorization redirect"
        );
        let redirect_state = RedirectState {
            state: state.clone(),
            nonce,
            code_verifier,
            original_uri: self
                .restore_path_after_redirect
                .then_some(original_uri.clone()),
        };

        let mut authorization_url =
            reqwest::Url::parse(&self.authorization_endpoint).map_err(|error| {
                Error::Session(
                    std::io::Error::other(format!(
                        "invalid OIDC authorization endpoint `{}`: {error}",
                        self.authorization_endpoint
                    ))
                    .into(),
                )
            })?;
        // OpenID Connect Core 1.0 Section 3.1.2.1 requires `scope` with
        // `openid`, `response_type=code`, `client_id`, and the `redirect_uri`
        // used for the token request. Section 3.1.2.2 leaves `state`
        // RECOMMENDED; Quarkus and Payara both bind the code flow to local
        // state. Like Payara, keep the secret nonce in local transient state
        // and send its SHA-256 hash to the provider.
        let mut query = authorization_url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("scope", &self.scopes.join(" "))
            .append_pair("state", &state)
            .append_pair("code_challenge", &code_challenge)
            .append_pair("code_challenge_method", "S256");
        if self.response_mode == OidcResponseMode::FormPost {
            query.append_pair("response_mode", "form_post");
        }
        if let Some(nonce_hash) = nonce_hash.as_deref() {
            query.append_pair("nonce", nonce_hash);
        }
        drop(query);
        let mut response = redirect_response(authorization_url.as_str())?;
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
        id_token_validator: Arc<dyn IdTokenValidator>,
    ) -> Result<Response> {
        // A callback consumes its one-time correlation state regardless of its
        // outcome. Queue the removal before parsing or contacting the provider
        // so every terminal callback response clears it.
        queue_cookie(request, self.redirect_state_cookie.clear()?);
        let redirect_uri = self.redirect_uri(request)?;
        let params = match self.response_mode {
            OidcResponseMode::Query => {
                CallbackQuery::parse(request.uri().query().unwrap_or_default())
            }
            OidcResponseMode::FormPost => {
                let content_type = request
                    .headers()
                    .get(CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok());
                if content_type != Some("application/x-www-form-urlencoded") {
                    return Err(Error::InvalidCallbackRequest);
                }
                let body = std::mem::replace(request.body_mut(), Body::empty());
                let bytes = to_bytes(body, MAX_CALLBACK_FORM_BYTES)
                    .await
                    .map_err(|_| Error::CallbackBodyTooLarge)?;
                let form =
                    std::str::from_utf8(&bytes).map_err(|_| Error::InvalidCallbackRequest)?;
                CallbackQuery::parse(form)
            }
        };
        debug!(redirect_uri = %redirect_uri, "processing OIDC authorization callback");
        if let Some(error) = params.error {
            debug!(provider_error = %error, "OIDC authorization endpoint returned an error");
            return Err(Error::InvalidCallbackRequest);
        }
        let code = params.code.ok_or_else(|| {
            warn!("OIDC callback did not include an authorization code");
            Error::InvalidCallbackRequest
        })?;
        let state = params.state.ok_or_else(|| {
            warn!("OIDC callback did not include a state parameter");
            Error::InvalidCallbackRequest
        })?;
        let redirect_state = self.redirect_state_cookie.load(request)?.ok_or_else(|| {
            warn!("OIDC callback did not include a readable redirect-state cookie");
            Error::InvalidCallbackRequest
        })?;
        if redirect_state.state != state {
            warn!("OIDC callback state did not match redirect-state cookie");
            return Err(Error::InvalidCallbackRequest);
        }

        // OpenID Connect Core 1.0 Section 3.1.3.1 requires the authorization
        // code grant token request to include the code and redirect_uri used in
        // the Authentication Request. The state check above is the local
        // correlation guard before exchanging the code.
        let token_response = self
            .exchange_code(&code, &redirect_uri, &redirect_state.code_verifier)
            .await?;
        trace!(
            has_id_token = token_response.id_token.is_some(),
            "OIDC token endpoint returned callback tokens"
        );
        let expected_nonce = match redirect_state.nonce.as_deref() {
            Some(nonce) => Some(hash_nonce(nonce)),
            None if self.nonce_required => {
                return Err(Error::TokenRejected(
                    "redirect state is missing the nonce required for validation".into(),
                ));
            }
            None => None,
        };
        let authenticated = self
            .validated_tokens(
                token_response,
                validator,
                id_token_validator,
                None,
                expected_nonce.as_deref(),
                None,
            )
            .await?;
        let redirect_to = redirect_state
            .original_uri
            .unwrap_or_else(|| "/".to_owned());
        let mut response = redirect_response(&redirect_to)?;
        store_authentication_cookie(&self.token_state_cookie, &mut response, &authenticated)?;

        trace!(
            groups = authenticated.principal.groups().count(),
            "stored web-app principal in token-state cookie"
        );
        debug!(redirect_to = %redirect_to, "OIDC web-app callback completed");
        with_pending_cookies(request, response)
    }

    fn refresh_enabled(&self) -> bool {
        self.refresh_expired || self.refresh_token_time_skew.is_some()
    }

    async fn coordinated_refresh(
        &self,
        refresh_token: &str,
        validator: Arc<dyn TokenValidator>,
        id_token_validator: Arc<dyn IdTokenValidator>,
        previous_id_token: Option<&IdToken>,
    ) -> Result<AuthenticatedTokens> {
        let key: [u8; 32] = Sha256::digest(refresh_token.as_bytes()).into();
        let (flight, leader) = self.refresh_flights.join(key);
        if let Some(leader) = leader {
            let outcome = match self.refresh_tokens(refresh_token).await {
                Ok(response) => self
                    .validated_tokens(
                        response,
                        validator,
                        id_token_validator,
                        Some(refresh_token),
                        None,
                        previous_id_token,
                    )
                    .await
                    .map(RefreshOutcome::Success)
                    .unwrap_or_else(|error| {
                        debug!(error = %error, "OIDC refresh single-flight validation failed");
                        RefreshOutcome::Failed
                    }),
                Err(error) => {
                    debug!(error = %error, "OIDC refresh single-flight leader failed");
                    RefreshOutcome::Failed
                }
            };
            leader.complete(outcome);
        }
        flight.wait().await
    }

    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        code_verifier: &str,
    ) -> Result<TokenResponse> {
        let form = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", code_verifier),
        ];
        debug!(token_endpoint = %self.token_endpoint, "exchanging OIDC authorization code for tokens");
        let response = self.token_request(&form).await?;
        validate_token_response(&response, TokenResponseKind::Initial)?;
        Ok(response)
    }

    async fn refresh_tokens(&self, refresh_token: &str) -> Result<TokenResponse> {
        let form = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
        ];
        debug!(token_endpoint = %self.token_endpoint, "refreshing OIDC web-app tokens");
        let response = self.token_request(&form).await?;
        validate_token_response(&response, TokenResponseKind::Refresh)?;
        Ok(response)
    }

    #[allow(deprecated)]
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
        // client_secret_basic and client_secret_post shapes. The deprecated
        // Query variant is treated as POST so programmatic configuration can
        // never put a secret in a URL.
        let request = match (self.client_secret.as_deref(), self.client_secret_method) {
            (Some(secret), ClientSecretMethod::Basic) => self
                .client
                .post(&self.token_endpoint)
                .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                .form(form)
                .basic_auth(&self.client_id, Some(secret)),
            (Some(secret), ClientSecretMethod::Post)
            | (Some(secret), ClientSecretMethod::Query) => {
                let mut authenticated_form = form.to_vec();
                authenticated_form.push(("client_id", self.client_id.as_str()));
                authenticated_form.push(("client_secret", secret));
                self.client
                    .post(&self.token_endpoint)
                    .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .form(&authenticated_form)
            }
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
        validate_token_response_type(&response)?;
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
        id_token_validator: Arc<dyn IdTokenValidator>,
        previous_refresh_token: Option<&str>,
        expected_nonce: Option<&str>,
        previous_id_token: Option<&IdToken>,
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
        // ID tokens use a purpose-specific validator and never the access-token
        // introspection or UserInfo fallback.
        let validated_id_token = match token_response.id_token.as_deref() {
            Some(raw) => {
                let validated = validate_id_token(raw, id_token_validator, expected_nonce).await?;
                if let Some(previous) = previous_id_token {
                    validate_refreshed_id_token(previous.claims(), validated.0.claims())?;
                }
                Some(validated)
            }
            None => None,
        };
        let mut principal = match validator
            .validate(Arc::from(token_response.access_token.as_str()))
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
        if !self.id_token_role_claim_paths.is_empty() {
            let role_id_token = validated_id_token
                .as_ref()
                .map(|(id_token, _)| id_token)
                .or(previous_id_token);
            let Some(id_token) = role_id_token else {
                return Err(Error::TokenRejected(
                    "ID token is required when roles.source is idtoken".into(),
                ));
            };
            let groups = extract_roles(
                &serde_json::Value::Object(id_token.claims().extra.clone()),
                &self.id_token_role_claim_paths,
                &self.role_claim_separator,
            )
            .into_iter()
            .map(Arc::from)
            .collect();
            principal = principal.with_claim_groups(groups);
        }
        let now = unix_timestamp()?;
        let refreshed_id_token = validated_id_token.map(|(id_token, _)| id_token);
        let token_state = StoredTokenState::from_response(
            &token_response,
            previous_refresh_token,
            &refreshed_id_token,
            now,
        );
        let id_token = refreshed_or_previous_id_token(refreshed_id_token, previous_id_token);

        Ok(AuthenticatedTokens {
            principal,
            id_token,
            token_state,
        })
    }

    fn redirect_uri(&self, request: &Request<Body>) -> Result<String> {
        absolute_request_uri(
            request,
            &self.redirect_path,
            "OIDC redirect URI",
            self.trust_forwarded_headers,
        )
    }

    fn logout(&self, request: &Request<Body>, options: &OidcLogoutOptions) -> Result<Response> {
        // The token-state cookie is encrypted, HttpOnly, and SameSite=Lax. Requiring
        // it on POST makes it a practical CSRF credential: cross-site POSTs do not
        // carry it, while callers cannot manufacture a valid value.
        let Some(authentication) = self
            .token_state_cookie
            .load(request)
            .unwrap_or_else(|error| {
                debug!(error = %error, "OIDC logout rejected an invalid token-state cookie");
                None
            })
        else {
            debug!("OIDC logout rejected because no valid token-state cookie was supplied");
            return Ok(StatusCode::FORBIDDEN.into_response());
        };

        let id_token_hint = if options.id_token_hint {
            authentication.id_token.and_then(|id_token| id_token.raw)
        } else {
            None
        };

        // RP-Initiated Logout 1.0 defines `id_token_hint` and
        // `post_logout_redirect_uri`. Quarkus and Payara both treat provider
        // notification as an optional redirect to the discovered or configured
        // end-session endpoint after clearing local RP state.
        let mut response = match self.end_session_endpoint.as_deref() {
            Some(endpoint) => {
                self.end_session_redirect(request, endpoint, id_token_hint, options)?
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
                    self.trust_forwarded_headers,
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
    trust_forwarded_headers: bool,
) -> Result<String> {
    if path_or_uri.starts_with("http://") || path_or_uri.starts_with("https://") {
        reqwest::Url::parse(path_or_uri).map_err(|error| {
            Error::Session(
                std::io::Error::other(format!("invalid {purpose} `{path_or_uri}`: {error}")).into(),
            )
        })?;
        trace!(uri = %path_or_uri, purpose, "using absolute URI");
        return Ok(path_or_uri.to_owned());
    }
    if !path_or_uri.starts_with('/') {
        return Err(Error::Session(
            std::io::Error::other(format!("{purpose} path must start with `/`")).into(),
        ));
    }
    let forwarded = trust_forwarded_headers
        .then(|| forwarded_origin(request))
        .flatten();
    let forwarded_host = forwarded.as_ref().and_then(|origin| origin.host.as_deref());
    let host = request_host(request, trust_forwarded_headers, forwarded_host)
        .ok_or_else(|| {
        warn!(
            path = %request.uri().path(),
            configured_path = %path_or_uri,
            "cannot build absolute OIDC URI without Host, URI authority, or an absolute configured URI"
        );
        Error::Session(
            std::io::Error::other(
                format!("missing request host for {purpose}; set Host, use an absolute request URI, or configure an absolute URI"),
            )
            .into(),
        )
    })?;
    let scheme = request_scheme(
        request,
        trust_forwarded_headers,
        forwarded.as_ref().and_then(|origin| origin.proto),
    );
    let uri = format!("{scheme}://{host}{path_or_uri}");
    reqwest::Url::parse(&uri).map_err(|error| {
        Error::Session(
            std::io::Error::other(format!("invalid generated {purpose} `{uri}`: {error}")).into(),
        )
    })?;
    trace!(uri = %uri, purpose, "built absolute OIDC URI from request origin");
    Ok(uri)
}

#[derive(Debug, Default, Eq, PartialEq)]
struct ForwardedOrigin {
    host: Option<String>,
    proto: Option<&'static str>,
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
    id_token_validator: Arc<dyn IdTokenValidator>,
}

impl OidcCallbackService {
    pub(crate) fn new(
        web_app: Arc<WebApp>,
        validator: Arc<dyn TokenValidator>,
        id_token_validator: Arc<dyn IdTokenValidator>,
        _authorization_scheme: String,
    ) -> Self {
        Self {
            web_app,
            validator,
            id_token_validator,
        }
    }

    pub(crate) fn route<S>(self) -> MethodRouter<S>
    where
        S: Clone,
    {
        match self.web_app.response_mode {
            OidcResponseMode::Query => get_service(self),
            OidcResponseMode::FormPost => post_service(self),
        }
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
        let id_token_validator = self.id_token_validator.clone();
        Box::pin(async move {
            let response = match web_app
                .callback(&mut request, validator, id_token_validator)
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    let mut response = error
                        .into_callback_response_for_request(request.method(), request.uri().path());
                    if let Some(pending) = request.extensions_mut().remove::<PendingWebAppCookies>()
                    {
                        pending.append_to(&mut response);
                    }
                    response
                }
            };
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

    /// Converts this service into a `POST` route.
    ///
    /// Add the route outside [`crate::Oidc::layer`]. The request must include a
    /// valid local token-state cookie before logout can mutate the session.
    pub fn route<S>(self) -> MethodRouter<S>
    where
        S: Clone,
    {
        post_service(self)
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
        let response = match &self.web_app {
            Some(web_app) => web_app.logout(&request, &self.options),
            None => local_logout_response(&self.options),
        }
        .unwrap_or_else(|error| {
            error.into_response_with_scheme_for_request(
                &self.authorization_scheme,
                request.method(),
                request.uri().path(),
            )
        });
        ready(Ok(response))
    }
}

#[derive(Clone)]
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
    validator: Arc<dyn IdTokenValidator>,
    expected_nonce: Option<&str>,
) -> Result<(IdToken, Principal)> {
    trace!("validating OIDC ID token from web-app token response");
    // The validator enforces signature, issuer, audience, exp, and iat policy.
    let id_token = validator.validate(Arc::from(token)).await?;
    let claims = id_token.claims();
    validate_id_token_nonce(&claims, expected_nonce)?;
    trace!(
        has_subject = claims.sub.is_some(),
        has_issuer = claims.iss.is_some(),
        audiences = claims.aud.len(),
        expires_at = ?claims.exp,
        "decoded OIDC ID token claims"
    );
    let principal = Principal::new(claims.sub.clone().expect("ID-token validator requires sub"));
    Ok((id_token, principal))
}

fn validate_id_token_nonce(claims: &IdTokenClaims, expected_nonce: Option<&str>) -> Result<()> {
    let Some(expected_nonce) = expected_nonce else {
        return Ok(());
    };
    match claims.nonce.as_deref() {
        Some(nonce) if nonce == expected_nonce => Ok(()),
        Some(_) => Err(Error::TokenRejected(
            "ID token nonce does not match the authentication request".into(),
        )),
        None => Err(Error::TokenRejected(
            "ID token is missing the nonce claim".into(),
        )),
    }
}

fn validate_refreshed_id_token(previous: &IdTokenClaims, refreshed: &IdTokenClaims) -> Result<()> {
    if refreshed.iss != previous.iss {
        return Err(Error::TokenRejected(
            "refreshed ID token issuer does not match the original ID token".into(),
        ));
    }
    if refreshed.sub != previous.sub {
        return Err(Error::TokenRejected(
            "refreshed ID token subject does not match the original ID token".into(),
        ));
    }
    if refreshed.aud.len() != previous.aud.len()
        || !refreshed.aud.iter().all(|aud| previous.aud.contains(aud))
    {
        return Err(Error::TokenRejected(
            "refreshed ID token audience does not match the original ID token".into(),
        ));
    }
    if previous.auth_time.is_some() && refreshed.auth_time != previous.auth_time {
        return Err(Error::TokenRejected(
            "refreshed ID token auth_time does not match the original ID token".into(),
        ));
    }
    if refreshed.nonce.is_some() && refreshed.nonce != previous.nonce {
        return Err(Error::TokenRejected(
            "refreshed ID token nonce does not match the original ID token".into(),
        ));
    }
    Ok(())
}

fn refreshed_or_previous_id_token(
    refreshed: Option<IdToken>,
    previous: Option<&IdToken>,
) -> Option<IdToken> {
    refreshed.or_else(|| previous.cloned())
}

#[cfg(test)]
mod refresh_id_token_tests {
    use super::*;

    fn claims() -> IdTokenClaims {
        IdTokenClaims {
            iss: Some("https://issuer.example".to_owned()),
            sub: Some("alice".to_owned()),
            aud: vec!["client".to_owned(), "api".to_owned()],
            auth_time: Some(1_700_000_000),
            nonce: Some("original-nonce".to_owned()),
            ..IdTokenClaims::default()
        }
    }

    #[test]
    fn refreshed_id_token_rejects_subject_audience_and_issuer_changes() {
        let previous = claims();

        let mut refreshed = claims();
        refreshed.sub = Some("mallory".to_owned());
        assert!(validate_refreshed_id_token(&previous, &refreshed).is_err());

        let mut refreshed = claims();
        refreshed.aud = vec!["other-client".to_owned()];
        assert!(validate_refreshed_id_token(&previous, &refreshed).is_err());

        let mut refreshed = claims();
        refreshed.iss = Some("https://other-issuer.example".to_owned());
        assert!(validate_refreshed_id_token(&previous, &refreshed).is_err());
    }

    #[test]
    fn refresh_without_id_token_preserves_previous_validated_token() {
        let previous = IdToken::with_raw(claims(), "original.jwt");
        let retained = refreshed_or_previous_id_token(None, Some(&previous));

        assert_eq!(retained, Some(previous));
    }

    #[test]
    fn valid_refreshed_id_token_preserves_authentication_event_semantics() {
        let previous = claims();
        let mut refreshed = claims();
        refreshed.aud.reverse();
        refreshed.nonce = None;

        validate_refreshed_id_token(&previous, &refreshed)
            .expect("audience order and an omitted refresh nonce are valid");

        refreshed.auth_time = None;
        assert!(validate_refreshed_id_token(&previous, &refreshed).is_err());

        let mut refreshed = claims();
        refreshed.nonce = Some("different-nonce".to_owned());
        assert!(validate_refreshed_id_token(&previous, &refreshed).is_err());
    }
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

fn request_scheme(
    request: &Request<Body>,
    trust_forwarded_headers: bool,
    forwarded_proto: Option<&'static str>,
) -> &'static str {
    // RFC 7239 Section 8.1: forwarded values can be client-modified, so treat
    // every origin source as untrusted and validate before URL construction.
    trust_forwarded_headers
        .then(|| {
            request
                .headers()
                .get("x-forwarded-proto")
                .and_then(|value| value.to_str().ok())
                .and_then(header_proto)
                .or(forwarded_proto)
        })
        .flatten()
        .or_else(|| request.uri().scheme_str().and_then(header_proto))
        .unwrap_or("http")
}

fn request_host<'a>(
    request: &'a Request<Body>,
    trust_forwarded_headers: bool,
    forwarded_host: Option<&'a str>,
) -> Option<Cow<'a, str>> {
    // RFC 7239 Section 8.1 applies to forwarded hosts; apply the same
    // authority validation to legacy X-Forwarded-Host and Host as well.
    trust_forwarded_headers
        .then(|| {
            request
                .headers()
                .get("x-forwarded-host")
                .and_then(|value| value.to_str().ok())
                .map(trim_ows_str)
                .and_then(valid_authority)
                .map(Cow::Borrowed)
                .or_else(|| forwarded_host.and_then(valid_authority).map(Cow::Borrowed))
        })
        .flatten()
        .or_else(|| {
            request
                .headers()
                .get(HOST)
                .and_then(|value| value.to_str().ok())
                .map(trim_ows_str)
                .and_then(valid_authority)
                .map(Cow::Borrowed)
        })
        .or_else(|| {
            request
                .uri()
                .authority()
                .map(http::uri::Authority::as_str)
                .and_then(valid_authority)
                .map(Cow::Borrowed)
        })
}

fn forwarded_origin(request: &Request<Body>) -> Option<ForwardedOrigin> {
    // RFC 7239 Sections 4 and 7.1: Forwarded is an HTTP list that may be split
    // over multiple header fields. Each list element is one proxy hop; use the
    // first valid element that supplies the origin data needed for callbacks.
    let mut header_count = 0;
    for header in request.headers().get_all("forwarded") {
        header_count += 1;
        if header_count > MAX_FORWARDED_HEADER_FIELDS {
            return None;
        }
        if header.as_bytes().len() > MAX_FORWARDED_HEADER_BYTES {
            continue;
        }
        let Some(elements) = split_forwarded(header.as_bytes(), b',') else {
            continue;
        };
        let mut element_count = 0;
        for element in elements {
            element_count += 1;
            if element_count > MAX_FORWARDED_ELEMENTS {
                continue;
            }
            let Some(origin) = parse_forwarded_element(element) else {
                continue;
            };
            if origin.host.is_some() || origin.proto.is_some() {
                return Some(origin);
            }
        }
    }
    None
}

fn parse_forwarded_element(element: &[u8]) -> Option<ForwardedOrigin> {
    // RFC 7239 Section 4: a forwarded-element is semicolon-separated
    // token=value pairs, names are case-insensitive, values are token or
    // quoted-string, and each parameter name may appear only once.
    let params = split_forwarded(element, b';')?;
    let mut parameter_count = 0;
    let mut seen_host = false;
    let mut seen_proto = false;
    let mut origin = ForwardedOrigin::default();

    for param in params {
        parameter_count += 1;
        if parameter_count > MAX_FORWARDED_PARAMETERS {
            return None;
        }
        let param = trim_ows(param);
        if param.is_empty() {
            continue;
        }
        let (name, value) = split_once_byte(param, b'=')?;
        let name = trim_ows(name);
        if !is_token(name) {
            return None;
        }

        let value = trim_ows(value);
        if name.eq_ignore_ascii_case(b"host") {
            // RFC 7239 Section 5.3: host is the original Host field value and
            // must conform to Host syntax after quoted-string unescaping.
            if seen_host {
                return None;
            }
            seen_host = true;
            let value = parse_forwarded_value(value)?;
            origin.host = Some(forwarded_host(&value)?);
        } else if name.eq_ignore_ascii_case(b"proto") {
            // RFC 7239 Section 5.4: proto is a URI scheme; this crate only
            // accepts http/https because those are valid OIDC redirect bases.
            if seen_proto {
                return None;
            }
            seen_proto = true;
            let value = parse_forwarded_value(value)?;
            origin.proto = Some(forwarded_proto(&value)?);
        } else if !is_forwarded_value(value) {
            return None;
        }
    }

    Some(origin)
}

fn split_forwarded(value: &[u8], delimiter: u8) -> Option<ForwardedParts<'_>> {
    // RFC 7239 Section 4 and Section 7.1: comma separates list elements and
    // semicolon separates pairs, but delimiters inside quoted-string are data.
    debug_assert!(matches!(delimiter, b',' | b';'));
    has_balanced_forwarded_quotes(value).then_some(ForwardedParts {
        value,
        delimiter,
        start: 0,
        finished: false,
    })
}

struct ForwardedParts<'a> {
    value: &'a [u8],
    delimiter: u8,
    start: usize,
    finished: bool,
}

impl<'a> Iterator for ForwardedParts<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }

        let mut in_quotes = false;
        let mut escaped = false;
        for index in self.start..self.value.len() {
            let byte = self.value[index];
            if escaped {
                escaped = false;
                continue;
            }
            match byte {
                b'\\' if in_quotes => escaped = true,
                b'"' => in_quotes = !in_quotes,
                byte if byte == self.delimiter && !in_quotes => {
                    let part = &self.value[self.start..index];
                    self.start = index + 1;
                    return Some(part);
                }
                _ => {}
            }
        }

        self.finished = true;
        Some(&self.value[self.start..])
    }
}

fn has_balanced_forwarded_quotes(value: &[u8]) -> bool {
    let mut in_quotes = false;
    let mut escaped = false;

    for byte in value.iter().copied() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' if in_quotes => escaped = true,
            b'"' => in_quotes = !in_quotes,
            _ => {}
        }
    }

    !in_quotes && !escaped
}

fn parse_forwarded_value(value: &[u8]) -> Option<Cow<'_, [u8]>> {
    // RFC 7239 Section 4: forwarded-pair values are token / quoted-string.
    // Section 5.3 and 5.4 validation runs after any quoted-pair unescaping.
    if value.starts_with(b"\"") {
        parse_quoted_forwarded_value(value).map(Cow::Owned)
    } else {
        is_token(value).then_some(Cow::Borrowed(value))
    }
}

fn parse_quoted_forwarded_value(value: &[u8]) -> Option<Vec<u8>> {
    let value = value.strip_prefix(b"\"")?;
    let mut parsed = Vec::new();
    let mut escaped = false;

    for (index, byte) in value.iter().copied().enumerate() {
        if escaped {
            if !is_quoted_pair_byte(byte) {
                return None;
            }
            parsed.push(byte);
            escaped = false;
            continue;
        }

        match byte {
            b'\\' => escaped = true,
            b'"' => return (index + 1 == value.len()).then_some(parsed),
            byte if is_quoted_text_byte(byte) => parsed.push(byte),
            _ => return None,
        }
    }

    None
}

fn is_forwarded_value(value: &[u8]) -> bool {
    if value.starts_with(b"\"") {
        validate_quoted_forwarded_value(value)
    } else {
        is_token(value)
    }
}

fn validate_quoted_forwarded_value(value: &[u8]) -> bool {
    let Some(value) = value.strip_prefix(b"\"") else {
        return false;
    };
    let mut escaped = false;

    for (index, byte) in value.iter().copied().enumerate() {
        if escaped {
            if !is_quoted_pair_byte(byte) {
                return false;
            }
            escaped = false;
            continue;
        }

        match byte {
            b'\\' => escaped = true,
            b'"' => return index + 1 == value.len(),
            byte if is_quoted_text_byte(byte) => {}
            _ => return false,
        }
    }

    false
}

fn header_proto(value: &str) -> Option<&'static str> {
    forwarded_proto(trim_ows(value.as_bytes()))
}

fn forwarded_proto(value: &[u8]) -> Option<&'static str> {
    if value.eq_ignore_ascii_case(b"http") {
        Some("http")
    } else if value.eq_ignore_ascii_case(b"https") {
        Some("https")
    } else {
        None
    }
}

fn forwarded_host(value: &[u8]) -> Option<String> {
    let value = std::str::from_utf8(value).ok()?;
    valid_authority(value).map(ToOwned::to_owned)
}

fn valid_authority(value: &str) -> Option<&str> {
    (!value.is_empty() && !value.contains('@') && value.parse::<http::uri::Authority>().is_ok())
        .then_some(value)
}

fn trim_ows_str(value: &str) -> &str {
    std::str::from_utf8(trim_ows(value.as_bytes())).expect("trimmed str should remain valid UTF-8")
}

fn split_once_byte(value: &[u8], delimiter: u8) -> Option<(&[u8], &[u8])> {
    value
        .iter()
        .position(|byte| *byte == delimiter)
        .map(|index| (&value[..index], &value[index + 1..]))
}

fn trim_ows(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | b'\t'))
        .map_or(start, |index| index + 1);
    &value[start..end]
}

fn is_token(value: &[u8]) -> bool {
    !value.is_empty() && value.iter().copied().all(is_token_byte)
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn is_quoted_text_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' ' | b'!' | b'#'..=b'[' | b']'..=b'~' | 0x80..=0xff)
}

fn is_quoted_pair_byte(byte: u8) -> bool {
    matches!(byte, b'\t' | b' ' | b'!'..=b'~' | 0x80..=0xff)
}

#[cfg(test)]
mod forwarded_tests {
    use super::*;

    #[test]
    fn nonce_hash_is_sha256_base64url_without_padding() {
        assert_eq!(
            hash_nonce("nonce-123"),
            "HZZkR4rdvk7nGGwZsqLJjkYad9weGDZU82kWv5-1HLo"
        );
    }

    #[test]
    fn id_token_nonce_must_match_when_expected() {
        let matching = IdTokenClaims {
            nonce: Some("expected".to_owned()),
            ..IdTokenClaims::default()
        };
        assert!(validate_id_token_nonce(&matching, Some("expected")).is_ok());

        let mismatch = validate_id_token_nonce(&matching, Some("different"))
            .expect_err("a mismatched nonce should be rejected");
        assert!(mismatch.to_string().contains("nonce does not match"));

        let missing = validate_id_token_nonce(&IdTokenClaims::default(), Some("expected"))
            .expect_err("a missing nonce should be rejected");
        assert!(missing.to_string().contains("missing the nonce claim"));
    }

    #[test]
    fn id_token_nonce_is_ignored_when_not_requested() {
        assert!(validate_id_token_nonce(&IdTokenClaims::default(), None).is_ok());
    }

    fn token_response(json: &str) -> TokenResponse {
        serde_json::from_str(json).expect("token response should deserialize")
    }

    #[test]
    fn initial_token_response_requires_id_token_without_nonce() {
        let response = token_response(r#"{"access_token":"access","token_type":"Bearer"}"#);
        let error = validate_token_response(&response, TokenResponseKind::Initial)
            .expect_err("initial response without an ID token should be rejected");
        assert!(error.to_string().contains("missing an ID token"));
    }

    #[test]
    fn refresh_token_response_may_omit_id_token() {
        let response = token_response(r#"{"access_token":"access","token_type":"Bearer"}"#);
        assert!(validate_token_response(&response, TokenResponseKind::Refresh).is_ok());
    }

    #[test]
    fn token_response_requires_token_type() {
        let error = serde_json::from_str::<TokenResponse>(r#"{"access_token":"access"}"#)
            .err()
            .expect("missing token_type should fail deserialization");
        assert!(error.to_string().contains("token_type"));
    }

    #[test]
    fn token_response_rejects_unsupported_token_type() {
        let response = token_response(r#"{"access_token":"access","token_type":"MAC"}"#);
        let error = validate_token_response_type(&response)
            .expect_err("unsupported token_type should be rejected");
        assert!(error.to_string().contains("unsupported token type `MAC`"));
    }

    #[test]
    fn token_response_accepts_bearer_case_insensitively() {
        for token_type in ["Bearer", "bearer", "BEARER", "BeArEr"] {
            let response = token_response(&format!(
                r#"{{"access_token":"access","token_type":"{token_type}"}}"#
            ));
            assert!(validate_token_response_type(&response).is_ok());
        }
    }

    fn request_with_forwarded(values: &[&str]) -> Request<Body> {
        let mut builder = Request::builder().uri("/protected");
        for value in values {
            builder = builder.header("forwarded", *value);
        }
        builder
            .body(Body::empty())
            .expect("test request should be valid")
    }

    #[test]
    fn forwarded_origin_parses_proto_and_host() {
        let request = request_with_forwarded(&["proto=https;host=app.example"]);

        assert_eq!(
            forwarded_origin(&request),
            Some(ForwardedOrigin {
                host: Some("app.example".to_owned()),
                proto: Some("https"),
            })
        );
    }

    #[test]
    fn forwarded_origin_parses_case_insensitive_quoted_values() {
        let request =
            request_with_forwarded(&[r#"For=unknown;Proto="HTTPS";Host="app.example:8443""#]);

        assert_eq!(
            forwarded_origin(&request),
            Some(ForwardedOrigin {
                host: Some("app.example:8443".to_owned()),
                proto: Some("https"),
            })
        );
    }

    #[test]
    fn forwarded_origin_splits_quoted_commas_and_semicolons() {
        let request = request_with_forwarded(&[
            r#"for="client,with;punctuation";proto=https;host=app.example, proto=http;host=internal.example"#,
        ]);

        assert_eq!(
            forwarded_origin(&request),
            Some(ForwardedOrigin {
                host: Some("app.example".to_owned()),
                proto: Some("https"),
            })
        );
    }

    #[test]
    fn forwarded_origin_unescapes_quoted_pairs() {
        let request = request_with_forwarded(&[r#"proto="https";host="app\.example""#]);

        assert_eq!(
            forwarded_origin(&request),
            Some(ForwardedOrigin {
                host: Some("app.example".to_owned()),
                proto: Some("https"),
            })
        );
    }

    #[test]
    fn forwarded_origin_accepts_obs_text_in_ignored_quoted_extension() {
        let request = Request::builder()
            .uri("/protected")
            .header(
                "forwarded",
                HeaderValue::from_bytes(b"ext=\"\xff\";proto=https;host=app.example")
                    .expect("header value should be valid"),
            )
            .body(Body::empty())
            .expect("test request should be valid");

        assert_eq!(
            forwarded_origin(&request),
            Some(ForwardedOrigin {
                host: Some("app.example".to_owned()),
                proto: Some("https"),
            })
        );
    }

    #[test]
    fn forwarded_origin_reads_multiple_header_fields() {
        let request = request_with_forwarded(&["for=unknown", "proto=https;host=app.example"]);

        assert_eq!(
            forwarded_origin(&request),
            Some(ForwardedOrigin {
                host: Some("app.example".to_owned()),
                proto: Some("https"),
            })
        );
    }

    #[test]
    fn forwarded_origin_uses_next_valid_element_after_duplicate_parameter() {
        let request =
            request_with_forwarded(&["proto=http;proto=https, proto=https;host=app.example"]);

        assert_eq!(
            forwarded_origin(&request),
            Some(ForwardedOrigin {
                host: Some("app.example".to_owned()),
                proto: Some("https"),
            })
        );
    }

    #[test]
    fn forwarded_origin_uses_next_valid_element_after_invalid_known_value() {
        let request = request_with_forwarded(&[
            "proto=ftp;host=app.example, proto=https;host=public.example",
        ]);

        assert_eq!(
            forwarded_origin(&request),
            Some(ForwardedOrigin {
                host: Some("public.example".to_owned()),
                proto: Some("https"),
            })
        );
    }

    #[test]
    fn forwarded_origin_does_not_combine_distinct_elements() {
        let request = request_with_forwarded(&["proto=https, host=app.example"]);

        assert_eq!(
            forwarded_origin(&request),
            Some(ForwardedOrigin {
                host: None,
                proto: Some("https"),
            })
        );
    }

    #[test]
    fn forwarded_origin_ignores_invalid_values() {
        let request = request_with_forwarded(&[
            r#"proto=ftp;host="bad host""#,
            r#"proto="https;host=app.example"#,
        ]);

        assert_eq!(forwarded_origin(&request), None);
    }

    #[test]
    fn forwarded_origin_rejects_host_with_userinfo() {
        let request = request_with_forwarded(&["proto=https;host=user@app.example"]);

        assert_eq!(forwarded_origin(&request), None);
    }

    #[test]
    fn request_scheme_ignores_invalid_x_forwarded_proto() {
        let request = Request::builder()
            .uri("https://app.example/protected")
            .header("x-forwarded-proto", "javascript")
            .body(Body::empty())
            .expect("test request should be valid");

        assert_eq!(request_scheme(&request, true, None), "https");
    }

    #[test]
    fn request_host_ignores_invalid_header_authorities() {
        let request = Request::builder()
            .uri("https://uri.example/protected")
            .header("x-forwarded-host", "attacker.example/path")
            .header(HOST, "user@app.example")
            .body(Body::empty())
            .expect("test request should be valid");

        assert_eq!(
            request_host(&request, true, None).as_deref(),
            Some("uri.example")
        );
    }
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
        header_value(encrypted.encoded().to_string(), "token-state")
    }

    fn clear(&self) -> Result<HeaderValue> {
        trace!("clearing web-app token-state cookie");
        header_value(
            Cookie::build((TOKEN_STATE_COOKIE_NAME, ""))
                .path("/")
                .secure(true)
                .http_only(true)
                .same_site(SameSite::Lax)
                .max_age(CookieDuration::ZERO)
                .build()
                .encoded()
                .to_string(),
            "token-state",
        )
    }

    fn cookie_builder(
        &self,
        value: String,
        max_age: Option<CookieDuration>,
    ) -> cookie::CookieBuilder<'static> {
        let mut builder = Cookie::build((TOKEN_STATE_COOKIE_NAME, value))
            .path("/")
            .secure(true)
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
    same_site: SameSite,
}

impl RedirectStateCookieManager {
    fn new(key: Key, has_configured_key: bool, response_mode: OidcResponseMode) -> Self {
        debug!(
            has_configured_key,
            max_age_secs = REDIRECT_STATE_COOKIE_MAX_AGE_SECS,
            "configured web-app redirect-state cookie manager"
        );
        Self {
            key,
            same_site: match response_mode {
                OidcResponseMode::Query => SameSite::Lax,
                OidcResponseMode::FormPost => SameSite::None,
            },
        }
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
        header_value(encrypted.encoded().to_string(), "redirect-state")
    }

    fn clear(&self) -> Result<HeaderValue> {
        trace!("clearing web-app redirect-state cookie");
        header_value(
            Cookie::build((REDIRECT_STATE_COOKIE_NAME, ""))
                .path("/")
                .secure(true)
                .http_only(true)
                .same_site(self.same_site)
                .max_age(CookieDuration::ZERO)
                .build()
                .encoded()
                .to_string(),
            "redirect-state",
        )
    }

    fn cookie_builder(&self, value: String) -> cookie::CookieBuilder<'static> {
        Cookie::build((REDIRECT_STATE_COOKIE_NAME, value))
            .path("/")
            .secure(true)
            .http_only(true)
            .same_site(self.same_site)
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

fn header_value(cookie: String, state_kind: &str) -> Result<HeaderValue> {
    if cookie.len() > MAX_SET_COOKIE_BYTES {
        return Err(session_error(std::io::Error::other(format!(
            "encrypted {state_kind} cookie is {} bytes, exceeding the {MAX_SET_COOKIE_BYTES}-byte Set-Cookie limit; reduce token/claim/session data or use server-side session storage",
            cookie.len()
        ))));
    }
    HeaderValue::from_str(&cookie).map_err(|error| {
        Error::Session(
            std::io::Error::other(format!("invalid {state_kind} cookie header: {error}")).into(),
        )
    })
}

struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

impl CallbackQuery {
    fn parse(query: &str) -> Self {
        let mut parsed = Self {
            code: None,
            state: None,
            error: None,
        };

        for (key, value) in form_urlencoded::parse(query.as_bytes()) {
            match key.as_ref() {
                "code" => parsed.code = Some(value.into_owned()),
                "state" => parsed.state = Some(value.into_owned()),
                "error" => parsed.error = Some(value.into_owned()),
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

fn random_nonce() -> Result<String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| {
        Error::Session(
            std::io::Error::other(format!("failed to generate OIDC nonce: {error}")).into(),
        )
    })?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn random_code_verifier() -> Result<String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| {
        Error::Session(
            std::io::Error::other(format!("failed to generate PKCE code verifier: {error}")).into(),
        )
    })?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn pkce_code_challenge(code_verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()))
}

fn hash_nonce(nonce: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(nonce.as_bytes()))
}

fn session_error<E>(error: E) -> Error
where
    E: StdError + Send + Sync + 'static,
{
    Error::Session(error.into())
}

#[derive(Clone, Default)]
struct RefreshFlights(Arc<Mutex<HashMap<[u8; 32], Arc<RefreshFlight>>>>);

impl RefreshFlights {
    fn join(&self, key: [u8; 32]) -> (Arc<RefreshFlight>, Option<RefreshLeaderGuard>) {
        let mut flights = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        flights.retain(|_, flight| !flight.is_stale());
        if let Some(flight) = flights.get(&key) {
            return (flight.clone(), None);
        }
        let flight = Arc::new(RefreshFlight::default());
        flights.insert(key, flight.clone());
        let leader = RefreshLeaderGuard {
            flights: self.clone(),
            key,
            flight: flight.clone(),
            armed: true,
        };
        (flight, Some(leader))
    }

    fn remove(&self, key: &[u8; 32], flight: &Arc<RefreshFlight>) {
        let mut flights = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if flights
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, flight))
        {
            flights.remove(key);
        }
    }
}

struct RefreshLeaderGuard {
    flights: RefreshFlights,
    key: [u8; 32],
    flight: Arc<RefreshFlight>,
    armed: bool,
}

impl RefreshLeaderGuard {
    fn complete(mut self, outcome: RefreshOutcome) {
        self.flight.complete(outcome);
        self.armed = false;
    }
}

impl Drop for RefreshLeaderGuard {
    fn drop(&mut self) {
        if self.armed {
            self.flight.complete(RefreshOutcome::Failed);
            self.flights.remove(&self.key, &self.flight);
        }
    }
}

#[derive(Default)]
struct RefreshFlight {
    state: Mutex<RefreshFlightState>,
}

#[derive(Default)]
struct RefreshFlightState {
    outcome: Option<RefreshOutcome>,
    completed_at: Option<Instant>,
    waiters: Vec<Waker>,
}

#[derive(Clone)]
enum RefreshOutcome {
    Success(AuthenticatedTokens),
    Failed,
}

impl RefreshFlight {
    fn complete(&self, outcome: RefreshOutcome) {
        let waiters = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.outcome = Some(outcome);
            state.completed_at = Some(Instant::now());
            std::mem::take(&mut state.waiters)
        };
        for waiter in waiters {
            waiter.wake();
        }
    }

    async fn wait(&self) -> Result<AuthenticatedTokens> {
        poll_fn(|cx| {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match state.outcome.clone() {
                Some(RefreshOutcome::Success(response)) => Poll::Ready(Ok(response)),
                Some(RefreshOutcome::Failed) => Poll::Ready(Err(Error::TokenRejected(
                    "coordinated OIDC token refresh failed".into(),
                ))),
                None => {
                    if !state
                        .waiters
                        .iter()
                        .any(|waiter| waiter.will_wake(cx.waker()))
                    {
                        state.waiters.push(cx.waker().clone());
                    }
                    Poll::Pending
                }
            }
        })
        .await
    }

    fn is_stale(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .completed_at
            .is_some_and(|completed| completed.elapsed() >= REFRESH_FLIGHT_RETENTION)
    }
}

#[cfg(test)]
mod refresh_flight_tests {
    use super::*;

    #[test]
    fn cancelled_leader_fails_followers_and_allows_retry() {
        let flights = RefreshFlights::default();
        let key = Sha256::digest(b"test refresh token").into();
        let (flight, leader) = flights.join(key);
        let leader = leader.expect("first refresh should lead the flight");
        let (follower_flight, follower_leader) = flights.join(key);
        assert!(follower_leader.is_none());

        let mut leader_wait = Box::pin(flight.wait());
        let mut follower_wait = Box::pin(follower_flight.wait());
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        assert!(leader_wait.as_mut().poll(&mut context).is_pending());
        assert!(follower_wait.as_mut().poll(&mut context).is_pending());

        drop(leader);

        assert!(follower_wait.as_mut().poll(&mut context).is_ready());
        assert!(flights.0.lock().unwrap().is_empty());

        let (retry_flight, retry_leader) = flights.join(key);
        let retry_leader = retry_leader.expect("a later refresh should be able to retry");
        let mut retry_wait = Box::pin(retry_flight.wait());
        assert!(retry_wait.as_mut().poll(&mut context).is_pending());
        retry_leader.complete(RefreshOutcome::Failed);
        assert!(retry_wait.as_mut().poll(&mut context).is_ready());
    }
}

#[derive(Clone, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    id_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
}

#[derive(Clone, Copy)]
enum TokenResponseKind {
    Initial,
    Refresh,
}

fn validate_token_response(response: &TokenResponse, kind: TokenResponseKind) -> Result<()> {
    if matches!(kind, TokenResponseKind::Initial) && response.id_token.is_none() {
        return Err(Error::TokenRejected(
            "initial authorization-code token response is missing an ID token".into(),
        ));
    }
    Ok(())
}

fn validate_token_response_type(response: &TokenResponse) -> Result<()> {
    if !response.token_type.eq_ignore_ascii_case("Bearer") {
        return Err(Error::TokenRejected(
            format!(
                "token response uses unsupported token type `{}`; expected Bearer",
                response.token_type
            )
            .into(),
        ));
    }
    Ok(())
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
    #[serde(default)]
    nonce: Option<String>,
    code_verifier: String,
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

#[cfg(test)]
mod cookie_size_tests {
    use super::*;

    #[test]
    fn set_cookie_limit_includes_name_value_and_attributes_at_boundary() {
        let attributes = "; Path=/; Secure; HttpOnly; SameSite=Lax";
        let prefix = "q_oidc=";
        let value = "x".repeat(MAX_SET_COOKIE_BYTES - prefix.len() - attributes.len());
        let cookie = format!("{prefix}{value}{attributes}");

        assert_eq!(cookie.len(), MAX_SET_COOKIE_BYTES);
        assert!(header_value(cookie, "token-state").is_ok());

        let oversized = format!("{prefix}{value}x{attributes}");
        let error = header_value(oversized, "token-state").unwrap_err();
        assert!(error.to_string().contains("4096-byte Set-Cookie limit"));
        assert!(error.to_string().contains("server-side session storage"));
    }

    #[test]
    fn rejects_encrypted_token_state_with_large_jwt_data() {
        let manager = CookieTokenStateManager::new(Key::generate(), true, 0, 0, false).unwrap();
        let jwt = format!("{}.{}.signature", "header", "x".repeat(6_000));
        let authentication = StoredAuthentication {
            principal: StoredPrincipal {
                subject: "alice".to_owned(),
                issuer: None,
                audience: vec![],
                groups: vec![],
            },
            id_token: None,
            token_state: StoredTokenState {
                access_token: jwt,
                refresh_token: Some("r".repeat(1_000)),
                expires_at: None,
            },
        };

        let error = manager.store_stored(&authentication).unwrap_err();
        assert!(error.to_string().contains("encrypted token-state cookie"));
        assert!(error.to_string().contains("4096-byte Set-Cookie limit"));
    }

    #[test]
    fn rejects_encrypted_redirect_state_when_original_uri_is_oversized() {
        let manager =
            RedirectStateCookieManager::new(Key::generate(), true, OidcResponseMode::Query);
        let state = RedirectState {
            state: "state".to_owned(),
            nonce: Some("nonce".to_owned()),
            code_verifier: "verifier".to_owned(),
            original_uri: Some(format!("/return?data={}", "x".repeat(6_000))),
        };

        let error = manager.store(&state).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("encrypted redirect-state cookie")
        );
        assert!(error.to_string().contains("4096-byte Set-Cookie limit"));
    }
}

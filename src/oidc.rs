#[cfg(feature = "http-client")]
use crate::BuildError;
#[cfg(any(feature = "http-client", feature = "jwt"))]
use crate::BuildResult;
#[cfg(all(feature = "http-client", feature = "jwt"))]
use crate::IntrospectionFallbackValidator;
#[cfg(any(all(feature = "http-client", feature = "jwt"), feature = "web-app"))]
use crate::ProviderMetadata;
#[cfg(all(feature = "http-client", feature = "jwt"))]
use crate::UserInfoRolesValidator;
#[cfg(feature = "http-client")]
use crate::introspection::http_token_introspector;
#[cfg(all(feature = "http-client", feature = "jwt"))]
use crate::jwks::HttpJwksProvider;
#[cfg(all(feature = "http-client", feature = "jwt"))]
use crate::provider::{
    auth_server_url_from_config, provider_validation_config, validate_provider_metadata,
};
#[cfg(all(feature = "http-client", feature = "jwt"))]
use crate::provider::{discovery_url, provider_endpoint_url};
use crate::token::bearer_token;
#[cfg(feature = "web-app")]
use crate::token::unverified_token_from_request;
#[cfg(feature = "http-client")]
use crate::user_info::HttpUserInfoProvider;
use crate::validator::RejectAllTokens;
#[cfg(feature = "web-app")]
use crate::web_app::PendingWebAppCookies;
#[cfg(feature = "web-app")]
use crate::web_app::WebApp;
#[cfg(feature = "web-app")]
use crate::web_app::{
    OidcCallbackService, OidcLogoutOptions, OidcLogoutService, OidcWebAppRoutesOptions,
};
use crate::{
    ApplicationType, Error, IdTokenValidator, IntrospectionValidator, OidcConfig, Result,
    RolesSource, TokenIntrospector, TokenValidator, UserInfoProvider, UserInfoValidator,
};
#[cfg(feature = "jwt")]
use crate::{JoseIdTokenValidator, JwtValidator};
#[cfg(feature = "web-app")]
use axum::Router;
use axum::body::Body;
use axum::response::Response;
#[cfg(feature = "web-app")]
use axum::routing::MethodRouter;
use http::{HeaderName, Request};
#[cfg(all(feature = "http-client", feature = "jwt"))]
use jsonwebtoken::jwk::JwkSet;
use mp_config::Config;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower_layer::Layer;
use tower_service::Service;
#[cfg(feature = "web-app")]
use tracing::warn;
use tracing::{debug, trace};

#[cfg(feature = "web-app")]
enum WebAppPrincipal {
    Authenticated,
    Redirect(Response),
}

/// OIDC middleware entry point.
///
/// `Oidc` is the single-tenant authentication layer. It is cheap to clone and
/// intended to wrap the routes that require identity. Keep health checks,
/// static assets, and other public routes outside the layer unless they should
/// also challenge unauthenticated callers.
///
/// Build it directly with [`Oidc::builder`], load `oidc.*` properties with
/// [`Oidc::from_config`], or let [`Oidc::discover_from_config`] fetch provider
/// metadata and install a JWKS-backed validator during startup.
#[derive(Clone)]
pub struct Oidc {
    pub(crate) config: OidcConfig,
    validator: Arc<dyn TokenValidator>,
    id_token_validator: Arc<dyn IdTokenValidator>,
    pub(crate) token_header_name: Option<HeaderName>,
    #[cfg(feature = "web-app")]
    web_app: Option<Arc<WebApp>>,
}

impl Oidc {
    /// Starts building OIDC middleware from configuration.
    ///
    /// Use this path when configuration is already represented as Rust values
    /// or when tests need a custom validator. Provider-backed applications
    /// usually call [`OidcBuilder::discover`] before serving traffic.
    pub fn builder(config: OidcConfig) -> OidcBuilder {
        OidcBuilder {
            config,
            validator: None,
            id_token_validator: None,
            #[cfg(feature = "web-app")]
            web_app: None,
        }
    }

    /// Loads `oidc.*` configuration.
    ///
    /// This mirrors Quarkus' configuration prefix but deliberately does not
    /// install authorization rules. Route authorization should be expressed in
    /// Axum with [`crate::RequireAuthenticatedLayer`],
    /// [`crate::RequireRolesLayer`], or handler macros.
    pub fn from_config(config: &Config) -> mp_config::Result<OidcBuilder> {
        oidc_builder_from_config(
            OidcConfig::from_config(config)?,
            OidcConfigPropertyNames {
                public_key: "oidc.public-key",
                roles_source: "oidc.roles.source",
                token_binding_certificate: "oidc.token.binding.certificate",
                token_decrypt_access_token: "oidc.token.decrypt-access-token",
                token_decrypt_id_token: "oidc.token.decrypt-id-token",
                token_refresh_expired: "oidc.token.refresh-expired",
                token_refresh_token_time_skew: "oidc.token.refresh-token-time-skew",
            },
        )
    }

    /// Loads configuration, discovers the provider, and builds the middleware.
    ///
    /// This is the closest equivalent to Quarkus' provider-backed startup: it
    /// reads `oidc.*`, resolves the issuer, fetches discovery metadata, and
    /// installs the right JWT, introspection, UserInfo, or web-app pieces based
    /// on configuration.
    ///
    /// This is the config-driven path for bearer-service and web-app middleware:
    /// local `public-key` validation is installed without network access, while
    /// provider-backed configurations fetch discovery metadata and keys.
    #[cfg(all(feature = "http-client", feature = "jwt"))]
    pub async fn discover_from_config(config: &Config) -> BuildResult<Oidc> {
        Self::from_config(config)?.discover().await
    }

    /// Loads configuration, then discovers the provider with a caller-supplied client.
    #[cfg(all(feature = "http-client", feature = "jwt"))]
    pub async fn discover_from_config_with_client(
        config: &Config,
        client: reqwest::Client,
    ) -> BuildResult<Oidc> {
        Self::from_config(config)?
            .discover_with_client(client)
            .await
    }

    /// Returns a Tower layer suitable for `Router::layer` or nested routers.
    ///
    /// The layer validates the request before handlers run and inserts
    /// [`crate::Principal`] into request extensions. Put authorization layers
    /// inside the same protected router so they run after authentication has
    /// created the principal.
    pub fn layer(self) -> OidcLayer {
        OidcLayer { oidc: self }
    }

    /// Returns the application routes owned by this OIDC middleware.
    ///
    /// Service applications do not expose local OIDC protocol routes, so this
    /// returns an empty router for [`ApplicationType::Service`]. Web-app and
    /// hybrid applications return callback and logout routes that should be
    /// merged outside [`Oidc::layer`].
    /// ```
    /// use axum::{Router, routing::get};
    /// use oidc_middleware::{ApplicationType, Oidc, OidcConfig};
    ///
    /// # fn app() -> Router {
    /// let oidc = Oidc::builder(OidcConfig {
    ///     application_type: ApplicationType::WebApp,
    ///     client_id: Some("orders-web".to_owned()),
    ///     ..OidcConfig::default()
    /// })
    /// .build();
    ///
    /// let protected = Router::new()
    ///     .route("/", get(|| async { "ok" }))
    ///     .layer(oidc.clone().layer());
    ///
    /// Router::new()
    ///     .merge(oidc.routes())
    ///     .merge(protected)
    /// # }
    /// ```
    #[cfg(feature = "web-app")]
    pub fn routes<S>(&self) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        match self.config.application_type {
            ApplicationType::Service => Router::new(),
            ApplicationType::WebApp | ApplicationType::Hybrid => self.web_app_routes(),
        }
    }

    /// Returns the web-app callback and logout routes.
    ///
    /// Merge these routes outside [`Oidc::layer`] so the callback can complete
    /// the authorization-code flow and logout can clear local OIDC cookies
    /// without first requiring an authenticated session.
    #[cfg(feature = "web-app")]
    pub fn web_app_routes<S>(&self) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        self.web_app_routes_with_options(self.web_app_routes_options())
    }

    /// Returns web-app routes with caller-supplied route options.
    #[cfg(feature = "web-app")]
    pub fn web_app_routes_with_options<S>(&self, options: OidcWebAppRoutesOptions) -> Router<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        let Some(web_app) = &self.web_app else {
            debug!("web-app routes requested but web-app support is not installed");
            return Router::new();
        };

        let mut router = Router::new();
        match web_app.callback_path() {
            Ok(callback_path) if is_route_path(&callback_path) => {
                router = router.route(
                    &callback_path,
                    OidcCallbackService::new(
                        web_app.clone(),
                        self.validator.clone(),
                        self.id_token_validator.clone(),
                        self.config.token.authorization_scheme.clone(),
                    )
                    .route(),
                );
            }
            Ok(callback_path) => {
                warn!(callback_path = %callback_path, "OIDC callback path is not an application route path; callback route was not registered");
            }
            Err(error) => {
                warn!(error = %error, "OIDC callback route could not be registered");
            }
        }

        if is_route_path(&options.logout_path) {
            router = router.route(
                &options.logout_path,
                self.logout_service_with_options(options.logout).route(),
            );
        } else {
            warn!(logout_path = %options.logout_path, "OIDC logout path is not an application route path; logout route was not registered");
        }

        router
    }

    /// Returns a route that performs web-app logout.
    ///
    /// Prefer [`Oidc::routes`] for most web-apps. Use this when an application
    /// needs to mount only the logout route manually.
    ///
    /// The route clears the local token-state and redirect-state cookies. When
    /// provider metadata or configuration includes an end-session endpoint, it
    /// redirects there with `id_token_hint` and the configured post-logout
    /// redirect parameter when available. Otherwise it redirects locally.
    ///
    #[cfg(feature = "web-app")]
    pub fn logout_route<S>(&self) -> MethodRouter<S>
    where
        S: Clone,
    {
        self.logout_service().route()
    }

    /// Returns a web-app logout route with caller-supplied options.
    #[cfg(feature = "web-app")]
    pub fn logout_route_with_options<S>(&self, options: OidcLogoutOptions) -> MethodRouter<S>
    where
        S: Clone,
    {
        self.logout_service_with_options(options).route()
    }

    /// Returns the service used by [`Oidc::logout_route`].
    #[cfg(feature = "web-app")]
    pub fn logout_service(&self) -> OidcLogoutService {
        self.logout_service_with_options(self.logout_options())
    }

    /// Returns the service used by [`Oidc::logout_route_with_options`].
    #[cfg(feature = "web-app")]
    pub fn logout_service_with_options(&self, options: OidcLogoutOptions) -> OidcLogoutService {
        OidcLogoutService::new(
            self.web_app.clone(),
            options,
            self.config.token.authorization_scheme.clone(),
        )
    }

    #[cfg(feature = "web-app")]
    fn web_app_routes_options(&self) -> OidcWebAppRoutesOptions {
        OidcWebAppRoutesOptions {
            logout_path: self.config.logout.path.clone(),
            logout: self.logout_options(),
        }
    }

    #[cfg(feature = "web-app")]
    fn logout_options(&self) -> OidcLogoutOptions {
        OidcLogoutOptions {
            post_logout_redirect: self.config.logout.post_logout_path.clone(),
            post_logout_redirect_uri_parameter: self.config.logout.post_logout_uri_param.clone(),
            extra_params: self.config.logout.extra_params.clone(),
            id_token_hint: true,
        }
    }

    pub(crate) async fn authenticate(&self, request: &mut Request<Body>) -> Result<()> {
        trace!(method = %request.method(), path = %request.uri().path(), "starting bearer-service authentication");
        if !self.config.enabled {
            debug!(method = %request.method(), path = %request.uri().path(), "OIDC middleware is disabled; request is passed through");
            return Ok(());
        }

        if !self.config.tenant_enabled {
            debug!(method = %request.method(), path = %request.uri().path(), "OIDC tenant is disabled; request will be hidden");
            return Err(Error::TenantDisabled);
        }

        match self.authenticate_principal(request).await {
            Ok(groups) => {
                trace!(
                    method = %request.method(),
                    path = %request.uri().path(),
                    groups,
                    "bearer-service authentication succeeded"
                );
                Ok(())
            }
            Err(error) => {
                debug!(method = %request.method(), path = %request.uri().path(), error = %error, "bearer-service authentication failed");
                Err(error)
            }
        }
    }

    #[cfg(feature = "web-app")]
    pub(crate) async fn authenticate_web_app(
        &self,
        request: &mut Request<Body>,
    ) -> Result<Option<Response>> {
        trace!(method = %request.method(), path = %request.uri().path(), "starting web-app authentication");
        if !self.config.enabled {
            debug!(method = %request.method(), path = %request.uri().path(), "OIDC web-app middleware is disabled; request is passed through");
            return Ok(None);
        }

        if !self.config.tenant_enabled {
            debug!(method = %request.method(), path = %request.uri().path(), "OIDC web-app tenant is disabled; request will be hidden");
            return Err(Error::TenantDisabled);
        }

        let Some(web_app) = &self.web_app else {
            debug!(method = %request.method(), path = %request.uri().path(), "web-app middleware has no authorization-code endpoints configured");
            return Err(Error::Session(
                std::io::Error::other(
                    "`web-app` requires provider discovery or configured authorization and token endpoints",
                )
                .into(),
            ));
        };

        if web_app.is_callback(request) {
            debug!(method = %request.method(), path = %request.uri().path(), "handling OIDC web-app callback");
            return match web_app
                .callback(
                    request,
                    self.validator.clone(),
                    self.id_token_validator.clone(),
                )
                .await
            {
                Ok(response) => Ok(Some(response)),
                Err(error) => {
                    warn!(method = %request.method(), path = %request.uri().path(), error = %error, "OIDC web-app callback failed");
                    Err(error)
                }
            };
        }

        match self.web_app_principal_or_redirect(request, web_app).await? {
            WebAppPrincipal::Authenticated => {
                trace!(method = %request.method(), path = %request.uri().path(), "web-app token-state authentication succeeded");
                Ok(None)
            }
            WebAppPrincipal::Redirect(response) => {
                debug!(method = %request.method(), path = %request.uri().path(), "web-app request requires authorization redirect");
                Ok(Some(response))
            }
        }
    }

    #[cfg(feature = "web-app")]
    async fn web_app_principal_or_redirect(
        &self,
        request: &mut Request<Body>,
        web_app: &WebApp,
    ) -> Result<WebAppPrincipal> {
        if let Some(session) = web_app
            .session_context(
                request,
                self.validator.clone(),
                self.id_token_validator.clone(),
            )
            .await?
        {
            trace!(
                path = %request.uri().path(),
                groups = session.principal.groups().count(),
                has_id_token = session.id_token.is_some(),
                "restored principal from web-app token state"
            );
            request.extensions_mut().insert(session.principal);
            if let Some(id_token) = session.id_token {
                request.extensions_mut().insert(id_token);
            }
            return Ok(WebAppPrincipal::Authenticated);
        }

        trace!(path = %request.uri().path(), "web-app token state did not contain a principal");
        web_app
            .authorization_redirect(request)
            .await
            .map(WebAppPrincipal::Redirect)
    }

    async fn authenticate_principal(&self, request: &mut Request<Body>) -> Result<usize> {
        let token = bearer_token(request, &self.config.token, self.token_header_name.as_ref())?;
        trace!(path = %request.uri().path(), "validating extracted OIDC token");
        let principal = self.validator.validate(token).await?;
        let groups = principal.groups().count();
        request.extensions_mut().insert(principal);
        trace!(
            path = %request.uri().path(),
            groups,
            "inserted authenticated principal into request extensions"
        );
        Ok(groups)
    }

    pub(crate) async fn authenticate_or_response(
        &self,
        request: &mut Request<Body>,
    ) -> Result<Option<Response>> {
        match self.config.application_type {
            ApplicationType::Service => {
                self.authenticate(request).await?;
                Ok(None)
            }
            ApplicationType::WebApp => self.authenticate_web_app_or_feature_error(request).await,
            ApplicationType::Hybrid => {
                #[cfg(feature = "web-app")]
                {
                    if self
                        .web_app
                        .as_ref()
                        .is_some_and(|web_app| web_app.is_callback(request))
                    {
                        return self.authenticate_web_app(request).await;
                    }
                    if unverified_token_from_request(
                        request,
                        &self.config.token,
                        self.token_header_name.as_ref(),
                    )
                    .is_some()
                    {
                        self.authenticate(request).await?;
                        return Ok(None);
                    }
                    if self.web_app.is_some() {
                        return self.authenticate_web_app(request).await;
                    }
                }

                self.authenticate(request).await?;
                Ok(None)
            }
        }
    }

    #[cfg(feature = "web-app")]
    async fn authenticate_web_app_or_feature_error(
        &self,
        request: &mut Request<Body>,
    ) -> Result<Option<Response>> {
        self.authenticate_web_app(request).await
    }

    #[cfg(not(feature = "web-app"))]
    async fn authenticate_web_app_or_feature_error(
        &self,
        _request: &mut Request<Body>,
    ) -> Result<Option<Response>> {
        Err(Error::Session(
            std::io::Error::other(
                "OIDC web-app authentication requires the `web-app` crate feature",
            )
            .into(),
        ))
    }
}

pub(crate) fn oidc_builder_from_config(
    config: OidcConfig,
    property_names: OidcConfigPropertyNames<'_>,
) -> mp_config::Result<OidcBuilder> {
    let public_key = config.public_key.clone();
    #[cfg(feature = "jwt")]
    let mut builder = Oidc::builder(config);
    #[cfg(not(feature = "jwt"))]
    let builder = Oidc::builder(config);
    if !builder.config.enabled {
        debug!("OIDC builder loaded disabled configuration; provider validation setup is skipped");
        return Ok(builder);
    }
    validate_service_roles_source(&builder.config, property_names.roles_source)?;
    validate_service_token_binding_certificate(
        &builder.config,
        property_names.token_binding_certificate,
    )?;
    validate_service_token_decryption(
        &builder.config,
        property_names.token_decrypt_access_token,
        property_names.token_decrypt_id_token,
    )?;
    validate_service_token_refresh(
        &builder.config,
        property_names.token_refresh_expired,
        property_names.token_refresh_token_time_skew,
    )?;
    if let Some(public_key) = public_key {
        #[cfg(not(feature = "jwt"))]
        {
            return Err(mp_config::ConfigError::Conversion {
                name: property_names.public_key.to_owned(),
                value: public_key,
                message: "configured public-key validation requires the `jwt` crate feature"
                    .to_owned(),
            });
        }

        #[cfg(feature = "jwt")]
        {
            debug!(
                property = property_names.public_key,
                "installing configured public-key validator"
            );
            builder = builder.public_key(&public_key).map_err(|error| {
                mp_config::ConfigError::Conversion {
                    name: property_names.public_key.to_owned(),
                    value: public_key,
                    message: error.to_string(),
                }
            })?;
        }
    }
    Ok(builder)
}

pub(crate) struct OidcConfigPropertyNames<'a> {
    pub(crate) public_key: &'a str,
    pub(crate) roles_source: &'a str,
    pub(crate) token_binding_certificate: &'a str,
    pub(crate) token_decrypt_access_token: &'a str,
    pub(crate) token_decrypt_id_token: &'a str,
    pub(crate) token_refresh_expired: &'a str,
    pub(crate) token_refresh_token_time_skew: &'a str,
}

fn validate_service_roles_source(
    config: &OidcConfig,
    property_name: &str,
) -> mp_config::Result<()> {
    if config.roles.source == RolesSource::IdToken
        && config.application_type != ApplicationType::WebApp
    {
        return Err(mp_config::ConfigError::Conversion {
            name: property_name.to_owned(),
            value: "idtoken".to_owned(),
            message: "`idtoken` roles require the `web-app` application type".to_owned(),
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

fn validate_service_token_refresh(
    config: &OidcConfig,
    refresh_expired_property: &str,
    refresh_token_time_skew_property: &str,
) -> mp_config::Result<()> {
    if config.application_type == ApplicationType::WebApp {
        return Ok(());
    }

    if let Some(refresh_token_time_skew) = config.token.refresh_token_time_skew {
        return Err(mp_config::ConfigError::Conversion {
            name: refresh_token_time_skew_property.to_owned(),
            value: format!("{}s", refresh_token_time_skew.as_secs()),
            message: "`token.refresh-token-time-skew` requires the `web-app` application type"
                .to_owned(),
        });
    }

    if config.token.refresh_expired {
        return Err(mp_config::ConfigError::Conversion {
            name: refresh_expired_property.to_owned(),
            value: "true".to_owned(),
            message: "`token.refresh-expired` requires the `web-app` application type".to_owned(),
        });
    }

    Ok(())
}

#[cfg(feature = "http-client")]
fn oidc_http_client(config: &OidcConfig) -> BuildResult<reqwest::Client> {
    trace!(
        timeout_ms = config.connection_timeout.as_millis(),
        "building OIDC HTTP client"
    );
    Ok(reqwest::Client::builder()
        .connect_timeout(config.connection_timeout)
        .build()?)
}

/// Builder for [`Oidc`].
///
/// The builder separates provider configuration from the token validation
/// backend. This makes tests simple with [`crate::StaticTokenValidator`] while
/// production services can choose discovery, static public keys, introspection,
/// UserInfo, or custom validators without changing router code.
pub struct OidcBuilder {
    config: OidcConfig,
    validator: Option<Arc<dyn TokenValidator>>,
    id_token_validator: Option<Arc<dyn IdTokenValidator>>,
    #[cfg(feature = "web-app")]
    web_app: Option<Arc<WebApp>>,
}

impl OidcBuilder {
    /// Sets the dedicated validator used only for web-app ID tokens.
    pub fn id_token_validator<V>(mut self, validator: V) -> Self
    where
        V: IdTokenValidator,
    {
        self.id_token_validator = Some(Arc::new(validator));
        self
    }
    /// Sets the bearer token validator.
    ///
    /// Use this for custom validation, tests, or when another component owns
    /// token verification. If no validator is installed, the middleware rejects
    /// all bearer tokens so protected routes fail closed.
    pub fn validator<V>(mut self, validator: V) -> Self
    where
        V: TokenValidator,
    {
        debug!("installing custom OIDC token validator");
        self.validator = Some(Arc::new(validator));
        self
    }

    /// Installs a `oidc.public-key` backed JWT validator.
    ///
    /// Static public keys avoid network access at startup, but they do not
    /// rotate automatically. Prefer discovery or refreshable JWKS when the
    /// provider rotates signing keys.
    #[cfg(feature = "jwt")]
    pub fn public_key(mut self, public_key: &str) -> BuildResult<Self> {
        debug!("installing static public-key JWT validator");
        self.validator = Some(Arc::new(JwtValidator::public_key(
            public_key,
            &self.config,
        )?));
        Ok(self)
    }

    /// Installs a custom token introspection validator.
    ///
    /// Choose this when access tokens are opaque or must be validated by the
    /// provider on every request. The introspection response is still checked
    /// against configured issuer, audience, required claims, and role paths.
    pub fn token_introspector<I>(mut self, introspector: I) -> Self
    where
        I: TokenIntrospector,
    {
        debug!("installing custom token introspection validator");
        self.validator = Some(Arc::new(IntrospectionValidator::new(
            introspector,
            &self.config,
        )));
        self
    }

    /// Installs an HTTP token introspection validator.
    ///
    /// This is useful when discovery is disabled or the provider exposes a
    /// non-standard introspection endpoint. Client credentials come from
    /// `oidc.credentials.*` and `oidc.introspection-credentials.*`.
    #[cfg(feature = "http-client")]
    pub fn introspection_endpoint(self, endpoint: &str) -> BuildResult<Self> {
        let client = oidc_http_client(&self.config)?;
        self.introspection_endpoint_with_client(endpoint, client)
    }

    /// Installs an HTTP token introspection validator using a caller-supplied client.
    #[cfg(feature = "http-client")]
    pub fn introspection_endpoint_with_client(
        mut self,
        endpoint: &str,
        client: reqwest::Client,
    ) -> BuildResult<Self> {
        reqwest::Url::parse(endpoint).map_err(|error| BuildError::InvalidUrl {
            url: endpoint.to_owned(),
            message: error.to_string(),
        })?;
        debug!(endpoint = %endpoint, "installing HTTP token introspection validator");
        self.validator = Some(Arc::new(IntrospectionValidator::new(
            http_token_introspector(&self.config, client, endpoint.to_owned()),
            &self.config,
        )));
        Ok(self)
    }

    /// Installs a custom UserInfo-backed token validator.
    ///
    /// Use this when the UserInfo response is the authoritative identity source
    /// for a bearer token. For JWT validation plus UserInfo roles, configure
    /// `oidc.roles.source=userinfo` instead of replacing the validator.
    pub fn user_info_provider<P>(mut self, provider: P) -> Self
    where
        P: UserInfoProvider,
    {
        debug!("installing custom UserInfo token validator");
        self.validator = Some(Arc::new(UserInfoValidator::new(provider, &self.config)));
        self
    }

    /// Installs an HTTP UserInfo-backed token validator.
    #[cfg(feature = "http-client")]
    pub fn user_info_endpoint(self, endpoint: &str) -> BuildResult<Self> {
        let client = oidc_http_client(&self.config)?;
        self.user_info_endpoint_with_client(endpoint, client)
    }

    /// Installs an HTTP UserInfo-backed token validator using a caller-supplied client.
    #[cfg(feature = "http-client")]
    pub fn user_info_endpoint_with_client(
        mut self,
        endpoint: &str,
        client: reqwest::Client,
    ) -> BuildResult<Self> {
        reqwest::Url::parse(endpoint).map_err(|error| BuildError::InvalidUrl {
            url: endpoint.to_owned(),
            message: error.to_string(),
        })?;
        debug!(endpoint = %endpoint, "installing HTTP UserInfo token validator");
        self.validator = Some(Arc::new(UserInfoValidator::new(
            HttpUserInfoProvider::new(client, endpoint.to_owned()),
            &self.config,
        )));
        Ok(self)
    }

    /// Discovers provider metadata and installs provider-backed validation.
    ///
    /// Discovery is the recommended production path. It derives endpoints from
    /// the issuer, uses JWKS for JWT validation by default, and switches to
    /// introspection or UserInfo when the token configuration asks for it.
    #[cfg(all(feature = "http-client", feature = "jwt"))]
    pub async fn discover(self) -> BuildResult<Oidc> {
        let client = oidc_http_client(&self.config)?;
        self.discover_with_client(client).await
    }

    /// Discovers provider metadata using a caller-supplied HTTP client.
    #[cfg(all(feature = "http-client", feature = "jwt"))]
    pub async fn discover_with_client(self, client: reqwest::Client) -> BuildResult<Oidc> {
        if !self.config.enabled {
            debug!("OIDC discovery skipped because middleware is disabled");
            return Ok(self.build());
        }
        if self.config.public_key.is_some()
            && self.config.application_type != ApplicationType::WebApp
        {
            debug!("OIDC discovery skipped because a static public key is configured");
            let mut builder = self;
            builder.install_web_app_from_config(client)?;
            return Ok(builder.build());
        }

        let auth_server_url = auth_server_url_from_config(&self.config)?;
        debug!(auth_server_url = %auth_server_url, discovery_enabled = self.config.discovery_enabled, "starting OIDC provider setup");
        if !self.config.discovery_enabled {
            let mut builder = self;
            builder.install_web_app_from_config(client.clone())?;
            if builder.config.public_key.is_some() {
                return Ok(builder.build());
            }
            if builder.config.token.require_jwt_introspection_only {
                debug!("discovery disabled; installing configured introspection-only validator");
                let introspection_path = builder
                    .config
                    .introspection_path
                    .clone()
                    .ok_or(BuildError::MissingIntrospectionEndpoint)?;
                let endpoint = provider_endpoint_url(&auth_server_url, &introspection_path)?;
                return builder
                    .introspection_endpoint_with_client(endpoint.as_str(), client)
                    .map(OidcBuilder::build);
            }

            if builder.config.token.verify_access_token_with_user_info {
                debug!("discovery disabled; installing configured UserInfo token validator");
                let user_info_path = builder
                    .config
                    .user_info_path
                    .clone()
                    .ok_or(BuildError::MissingUserInfoEndpoint)?;
                let endpoint = provider_endpoint_url(&auth_server_url, &user_info_path)?;
                return builder
                    .user_info_endpoint_with_client(endpoint.as_str(), client)
                    .map(OidcBuilder::build);
            }

            if builder.uses_user_info_roles() {
                builder
                    .config
                    .user_info_path
                    .as_ref()
                    .ok_or(BuildError::MissingUserInfoEndpoint)?;
            }

            let jwks_path = builder
                .config
                .jwks_path
                .clone()
                .ok_or(BuildError::MissingJwksPath)?;
            let jwks_url = provider_endpoint_url(&auth_server_url, &jwks_path)?;
            debug!(jwks_url = %jwks_url, "discovery disabled; loading configured JWKS");
            let jwks: JwkSet = client
                .get(jwks_url)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            builder.install_jwks_with_optional_introspection(jwks, client);
            return Ok(builder.build());
        }

        let metadata_url = discovery_url(&auth_server_url, &self.config.discovery_path)?;
        debug!(metadata_url = %metadata_url, "fetching OIDC provider metadata");
        let metadata: ProviderMetadata = client
            .get(metadata_url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        // Bind the document to the issuer that selected its discovery URL before
        // trusting any endpoint supplied by the document.
        validate_provider_metadata(&metadata, Some(&auth_server_url))?;

        debug!(
            issuer = ?metadata.issuer,
            jwks_uri = %metadata.jwks_uri,
            has_introspection_endpoint = metadata.introspection_endpoint.is_some(),
            has_userinfo_endpoint = metadata.userinfo_endpoint.is_some(),
            "OIDC provider metadata loaded"
        );
        let mut builder = self;
        builder.install_web_app_from_metadata(&metadata, client.clone())?;
        if builder.config.public_key.is_some() {
            return Ok(builder.build());
        }

        if builder.config.token.require_jwt_introspection_only {
            debug!("provider metadata requires introspection-only validation");
            let endpoint = metadata
                .introspection_endpoint
                .as_deref()
                .ok_or(BuildError::MissingIntrospectionEndpoint)?;
            return builder
                .introspection_endpoint_with_client(endpoint, client)
                .map(OidcBuilder::build);
        }

        if builder.config.token.verify_access_token_with_user_info {
            debug!("provider metadata requires UserInfo token validation");
            let endpoint = metadata
                .userinfo_endpoint
                .as_deref()
                .ok_or(BuildError::MissingUserInfoEndpoint)?;
            return builder
                .user_info_endpoint_with_client(endpoint, client)
                .map(OidcBuilder::build);
        }

        if builder.uses_user_info_roles() {
            metadata
                .userinfo_endpoint
                .as_ref()
                .ok_or(BuildError::MissingUserInfoEndpoint)?;
        }

        debug!(jwks_uri = %metadata.jwks_uri, "fetching provider JWKS");
        let jwks: JwkSet = client
            .get(&metadata.jwks_uri)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        builder.provider_metadata_refreshing(metadata, jwks, client)
    }

    /// Installs already-fetched provider metadata and a JWKS-backed JWT validator.
    ///
    /// Use this when another startup component owns discovery caching, retries,
    /// or trust policy but you still want this crate's validation behaviour.
    #[cfg(all(feature = "http-client", feature = "jwt"))]
    pub fn provider_metadata(
        mut self,
        metadata: ProviderMetadata,
        jwks: JwkSet,
    ) -> BuildResult<Oidc> {
        debug!("installing validator from supplied provider metadata");
        validate_provider_metadata(&metadata, self.config.auth_server_url.as_deref())?;
        self.install_web_app_from_metadata(&metadata, reqwest::Client::new())?;
        self.install_id_token_jwks(&metadata, jwks.clone())?;
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
    ///
    /// The validator refreshes keys when a token references an unknown `kid`,
    /// throttled by `oidc.token.forced-jwk-refresh-interval`. This handles key
    /// rotation without refreshing on every rejected token.
    #[cfg(all(feature = "http-client", feature = "jwt"))]
    pub fn provider_metadata_refreshing(
        mut self,
        metadata: ProviderMetadata,
        jwks: JwkSet,
        client: reqwest::Client,
    ) -> BuildResult<Oidc> {
        debug!("installing refreshable validator from supplied provider metadata");
        validate_provider_metadata(&metadata, self.config.auth_server_url.as_deref())?;
        self.install_web_app_from_metadata(&metadata, client.clone())?;
        if self.config.application_type != ApplicationType::Service {
            let issuer =
                metadata
                    .issuer
                    .as_deref()
                    .ok_or_else(|| BuildError::InvalidConfiguration {
                        message: "provider metadata issuer is required for ID-token validation"
                            .to_owned(),
                    })?;
            let client_id = self
                .config
                .client_id
                .as_deref()
                .ok_or(BuildError::MissingClientId)?;
            self.id_token_validator = Some(Arc::new(JoseIdTokenValidator::refreshable_jwks(
                jwks.clone(),
                HttpJwksProvider::new(client.clone(), metadata.jwks_uri.clone()),
                issuer,
                client_id,
                &self.config,
            )));
        }
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
            HttpJwksProvider::new(client.clone(), metadata.jwks_uri.clone()),
            &validation_config,
        );
        let validator = self.jwt_with_metadata_introspection(jwt, metadata.clone(), client.clone());
        self.validator = Some(self.with_metadata_user_info_roles(validator, metadata, client));
        Ok(self.build())
    }

    #[cfg(all(feature = "http-client", feature = "jwt"))]
    fn install_jwks_with_optional_introspection(&mut self, jwks: JwkSet, client: reqwest::Client) {
        debug!("installing JWKS validator with optional introspection fallback");
        if self.config.application_type != ApplicationType::Service
            && let (Some(issuer), Some(client_id)) = (
                self.config.auth_server_url.as_deref(),
                self.config.client_id.as_deref(),
            )
        {
            self.id_token_validator = Some(Arc::new(JoseIdTokenValidator::jwks(
                jwks.clone(),
                issuer,
                client_id,
                self.config.token.lifespan_grace.unwrap_or_default(),
            )));
        }
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
                    Arc::new(HttpUserInfoProvider::new(client, endpoint)),
                    &self.config,
                ))
            }
            _ => validator,
        });
    }

    #[cfg(all(feature = "http-client", feature = "jwt"))]
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
            trace!(
                "provider metadata did not include an introspection endpoint; JWT fallback is disabled"
            );
            return Arc::new(jwt);
        };
        debug!(endpoint = %endpoint, "installing metadata introspection fallback");
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

    #[cfg(all(feature = "http-client", feature = "jwt"))]
    fn install_metadata_introspection(
        &mut self,
        metadata: ProviderMetadata,
        client: reqwest::Client,
    ) -> BuildResult<()> {
        let endpoint = metadata
            .introspection_endpoint
            .clone()
            .ok_or(BuildError::MissingIntrospectionEndpoint)?;
        debug!(endpoint = %endpoint, "installing metadata introspection validator");
        let validation_config = provider_validation_config(&self.config, &metadata);
        self.validator = Some(Arc::new(IntrospectionValidator::new(
            http_token_introspector(&validation_config, client, endpoint),
            &validation_config,
        )));
        Ok(())
    }

    #[cfg(all(feature = "http-client", feature = "jwt"))]
    fn install_metadata_user_info(
        &mut self,
        metadata: ProviderMetadata,
        client: reqwest::Client,
    ) -> BuildResult<()> {
        let endpoint = metadata
            .userinfo_endpoint
            .clone()
            .ok_or(BuildError::MissingUserInfoEndpoint)?;
        debug!(endpoint = %endpoint, "installing metadata UserInfo validator");
        let validation_config = provider_validation_config(&self.config, &metadata);
        self.validator = Some(Arc::new(UserInfoValidator::new(
            HttpUserInfoProvider::new(client, endpoint),
            &validation_config,
        )));
        Ok(())
    }

    #[cfg(all(feature = "http-client", feature = "jwt"))]
    fn uses_user_info_roles(&self) -> bool {
        self.config.roles.source == RolesSource::UserInfo
            && !self.config.token.verify_access_token_with_user_info
    }

    #[cfg(all(feature = "http-client", feature = "jwt"))]
    fn install_id_token_jwks(
        &mut self,
        metadata: &ProviderMetadata,
        jwks: JwkSet,
    ) -> BuildResult<()> {
        if self.config.application_type == ApplicationType::Service {
            return Ok(());
        }
        let issuer =
            metadata
                .issuer
                .as_deref()
                .ok_or_else(|| BuildError::InvalidConfiguration {
                    message: "provider metadata issuer is required for ID-token validation"
                        .to_owned(),
                })?;
        let client_id = self
            .config
            .client_id
            .as_deref()
            .ok_or(BuildError::MissingClientId)?;
        self.id_token_validator = Some(Arc::new(JoseIdTokenValidator::jwks(
            jwks,
            issuer,
            client_id,
            self.config.token.lifespan_grace.unwrap_or_default(),
        )));
        Ok(())
    }

    #[cfg(feature = "web-app")]
    fn install_web_app_from_config(&mut self, client: reqwest::Client) -> BuildResult<()> {
        if self.config.application_type == ApplicationType::Service {
            return Ok(());
        }
        debug!("installing web-app support from configured endpoints");
        self.web_app = Some(Arc::new(WebApp::from_config(&self.config, client)?));
        Ok(())
    }

    #[cfg(all(feature = "http-client", feature = "jwt", not(feature = "web-app")))]
    fn install_web_app_from_config(&mut self, _client: reqwest::Client) -> BuildResult<()> {
        if self.config.application_type != ApplicationType::Service {
            return Err(BuildError::WebAppFeatureDisabled);
        }
        Ok(())
    }

    #[cfg(feature = "web-app")]
    fn install_web_app_from_metadata(
        &mut self,
        metadata: &ProviderMetadata,
        client: reqwest::Client,
    ) -> BuildResult<()> {
        if self.config.application_type == ApplicationType::Service {
            return Ok(());
        }
        debug!("installing web-app support from provider metadata");
        self.web_app = Some(Arc::new(WebApp::from_provider_metadata(
            &self.config,
            client,
            metadata.authorization_endpoint.clone(),
            metadata.token_endpoint.clone(),
            metadata.end_session_endpoint.clone(),
        )?));
        Ok(())
    }

    #[cfg(all(feature = "http-client", feature = "jwt", not(feature = "web-app")))]
    fn install_web_app_from_metadata(
        &mut self,
        _metadata: &ProviderMetadata,
        _client: reqwest::Client,
    ) -> BuildResult<()> {
        if self.config.application_type != ApplicationType::Service {
            return Err(BuildError::WebAppFeatureDisabled);
        }
        Ok(())
    }

    #[cfg(all(feature = "http-client", feature = "jwt"))]
    fn user_info_endpoint_from_config(&self) -> Option<String> {
        let auth_server_url = self.config.auth_server_url.as_deref()?;
        let user_info_path = self.config.user_info_path.as_deref()?;
        provider_endpoint_url(auth_server_url, user_info_path)
            .ok()
            .map(Into::into)
    }

    #[cfg(all(feature = "http-client", feature = "jwt"))]
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
            Arc::new(HttpUserInfoProvider::new(client, endpoint)),
            &self.config,
        ))
    }

    #[cfg(all(feature = "http-client", feature = "jwt"))]
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
            Arc::new(HttpUserInfoProvider::new(client, endpoint)),
            &self.config,
        ))
    }

    /// Finishes the OIDC middleware.
    ///
    /// Building without a validator is allowed so routing can be wired before a
    /// provider is available, but requests fail closed with `invalid_token`.
    /// Install a validator or call discovery before exposing protected routes.
    ///
    /// If no validator is supplied, all bearer tokens are rejected. This keeps
    /// protected routes closed while allowing configuration and routing to be
    /// wired before a JWT/JWKS backend is added.
    pub fn build(self) -> Oidc {
        let has_validator = self.validator.is_some();
        #[cfg(feature = "web-app")]
        let has_web_app = self.web_app.is_some();
        #[cfg(not(feature = "web-app"))]
        let has_web_app = false;
        debug!(has_validator, has_web_app, "building OIDC middleware");
        let token_header_name = self.config.token.header.parse::<HeaderName>().ok();
        Oidc {
            config: self.config,
            validator: self.validator.unwrap_or_else(|| Arc::new(RejectAllTokens)),
            id_token_validator: self
                .id_token_validator
                .unwrap_or_else(|| Arc::new(crate::id_token::RejectAllIdTokens)),
            token_header_name,
            #[cfg(feature = "web-app")]
            web_app: self.web_app,
        }
    }
}

/// Tower layer produced by [`Oidc::layer`].
///
/// Most applications do not name this type directly; it is public so routers
/// can store or compose the layer explicitly when needed.
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
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            match oidc.authenticate_or_response(&mut request).await {
                Ok(Some(response)) => Ok(response),
                Ok(None) => {
                    #[cfg(feature = "web-app")]
                    let pending_cookies = request.extensions_mut().remove::<PendingWebAppCookies>();
                    let response = inner.call(request).await?;
                    #[cfg(feature = "web-app")]
                    let mut response = response;
                    #[cfg(feature = "web-app")]
                    if let Some(pending_cookies) = pending_cookies {
                        pending_cookies.append_to(&mut response);
                    }
                    Ok(response)
                }
                Err(error) => Ok(error.into_response_with_scheme_for_request(
                    &authorization_scheme,
                    request.method(),
                    request.uri().path(),
                )),
            }
        })
    }
}

#[cfg(feature = "web-app")]
fn is_route_path(path: &str) -> bool {
    path.starts_with('/')
}

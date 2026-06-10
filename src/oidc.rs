use crate::introspection::http_token_introspector;
use crate::jwks::HttpJwksProvider;
use crate::provider::{
    auth_server_url_from_config, discovery_url, provider_endpoint_url, provider_validation_config,
};
use crate::token::bearer_token;
use crate::user_info::HttpUserInfoProvider;
use crate::validator::RejectAllTokens;
use crate::web_app::WebApp;
use crate::{
    ApplicationType, BuildError, BuildResult, Error, IntrospectionFallbackValidator,
    IntrospectionValidator, JwtValidator, OidcConfig, Principal, ProviderMetadata, Result,
    RolesSource, TokenIntrospector, TokenValidator, UserInfoProvider, UserInfoRolesValidator,
    UserInfoValidator,
};
use axum::body::Body;
use axum::response::Response;
use http::Request;
use jsonwebtoken::jwk::JwkSet;
use mp_config::Config;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower_layer::Layer;
use tower_service::Service;

enum WebAppPrincipal {
    Authenticated,
    Redirect(Response),
}

/// OIDC middleware entry point.
#[derive(Clone)]
pub struct Oidc {
    pub(crate) config: OidcConfig,
    validator: Arc<dyn TokenValidator>,
    web_app: Option<Arc<WebApp>>,
}

impl Oidc {
    /// Starts building OIDC middleware from configuration.
    pub fn builder(config: OidcConfig) -> OidcBuilder {
        OidcBuilder {
            config,
            validator: None,
            web_app: None,
        }
    }

    /// Loads `oidc.*` configuration.
    pub fn from_config(config: &Config) -> mp_config::Result<OidcBuilder> {
        oidc_builder_from_config(
            OidcConfig::from_config(config)?,
            "oidc.public-key",
            "oidc.application-type",
            "oidc.roles.source",
            "oidc.token.binding.certificate",
            "oidc.token.decrypt-access-token",
            "oidc.token.decrypt-id-token",
        )
    }

    /// Loads configuration, discovers the provider, and builds the middleware.
    ///
    /// This is the config-driven path for bearer-service and web-app middleware:
    /// local `public-key` validation is installed without network access, while
    /// provider-backed configurations fetch discovery metadata and keys.
    pub async fn discover_from_config(config: &Config) -> BuildResult<Oidc> {
        Self::from_config(config)?.discover().await
    }

    /// Loads configuration, then discovers the provider with a caller-supplied client.
    pub async fn discover_from_config_with_client(
        config: &Config,
        client: reqwest::Client,
    ) -> BuildResult<Oidc> {
        Self::from_config(config)?
            .discover_with_client(client)
            .await
    }

    /// Returns a tower layer suitable for `Router::layer`.
    pub fn layer(self) -> OidcLayer {
        OidcLayer { oidc: self }
    }

    pub(crate) async fn authenticate(&self, request: &mut Request<Body>) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        if !self.config.tenant_enabled {
            return Err(Error::TenantDisabled);
        }

        self.authenticate_principal(request).await?;
        Ok(())
    }

    pub(crate) async fn authenticate_web_app(
        &self,
        request: &mut Request<Body>,
    ) -> Result<Option<Response>> {
        if !self.config.enabled {
            return Ok(None);
        }

        if !self.config.tenant_enabled {
            return Err(Error::TenantDisabled);
        }

        let Some(web_app) = &self.web_app else {
            return Err(Error::Session(
                std::io::Error::other(
                    "`web-app` requires provider discovery or configured authorization and token endpoints",
                )
                .into(),
            ));
        };

        if web_app.is_callback(request) {
            return web_app
                .callback(request, self.validator.clone())
                .await
                .map(Some);
        }

        match self.web_app_principal_or_redirect(request, web_app).await? {
            WebAppPrincipal::Authenticated => Ok(None),
            WebAppPrincipal::Redirect(response) => Ok(Some(response)),
        }
    }

    async fn web_app_principal_or_redirect(
        &self,
        request: &mut Request<Body>,
        web_app: &WebApp,
    ) -> Result<WebAppPrincipal> {
        if let Some(principal) = web_app.session_principal(request).await? {
            request.extensions_mut().insert(principal.clone());
            return Ok(WebAppPrincipal::Authenticated);
        }

        web_app
            .authorization_redirect(request)
            .await
            .map(WebAppPrincipal::Redirect)
    }

    async fn authenticate_principal(&self, request: &mut Request<Body>) -> Result<Principal> {
        let token = bearer_token(request, &self.config.token)?;
        let principal = self.validator.validate(token).await?;
        request.extensions_mut().insert(principal.clone());
        Ok(principal)
    }

    pub(crate) async fn authenticate_or_response(
        &self,
        request: &mut Request<Body>,
    ) -> Result<Option<Response>> {
        if self.config.application_type != ApplicationType::WebApp {
            self.authenticate(request).await?;
            return Ok(None);
        }

        match self.authenticate_web_app(request).await {
            Ok(response) => Ok(response),
            Err(error) => Err(error),
        }
    }
}

pub(crate) fn oidc_builder_from_config(
    config: OidcConfig,
    public_key_property: &str,
    _application_type_property: &str,
    roles_source_property: &str,
    token_binding_certificate_property: &str,
    token_decrypt_access_token_property: &str,
    token_decrypt_id_token_property: &str,
) -> mp_config::Result<OidcBuilder> {
    let public_key = config.public_key.clone();
    let mut builder = Oidc::builder(config);
    if !builder.config.enabled {
        return Ok(builder);
    }
    validate_service_roles_source(&builder.config, roles_source_property)?;
    validate_service_token_binding_certificate(
        &builder.config,
        token_binding_certificate_property,
    )?;
    validate_service_token_decryption(
        &builder.config,
        token_decrypt_access_token_property,
        token_decrypt_id_token_property,
    )?;
    if let Some(public_key) = public_key {
        builder = builder.public_key(&public_key).map_err(|error| {
            mp_config::ConfigError::Conversion {
                name: public_key_property.to_owned(),
                value: public_key,
                message: error.to_string(),
            }
        })?;
    }
    Ok(builder)
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

fn oidc_http_client(config: &OidcConfig) -> BuildResult<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .connect_timeout(config.connection_timeout)
        .build()?)
}

/// Builder for [`Oidc`].
pub struct OidcBuilder {
    config: OidcConfig,
    validator: Option<Arc<dyn TokenValidator>>,
    web_app: Option<Arc<WebApp>>,
}

impl OidcBuilder {
    /// Sets the bearer token validator.
    pub fn validator<V>(mut self, validator: V) -> Self
    where
        V: TokenValidator,
    {
        self.validator = Some(Arc::new(validator));
        self
    }

    /// Installs a `oidc.public-key` backed JWT validator.
    pub fn public_key(mut self, public_key: &str) -> BuildResult<Self> {
        self.validator = Some(Arc::new(JwtValidator::public_key(
            public_key,
            &self.config,
        )?));
        Ok(self)
    }

    /// Installs a custom token introspection validator.
    pub fn token_introspector<I>(mut self, introspector: I) -> Self
    where
        I: TokenIntrospector,
    {
        self.validator = Some(Arc::new(IntrospectionValidator::new(
            introspector,
            &self.config,
        )));
        self
    }

    /// Installs an HTTP token introspection validator.
    pub fn introspection_endpoint(self, endpoint: &str) -> BuildResult<Self> {
        let client = oidc_http_client(&self.config)?;
        self.introspection_endpoint_with_client(endpoint, client)
    }

    /// Installs an HTTP token introspection validator using a caller-supplied client.
    pub fn introspection_endpoint_with_client(
        mut self,
        endpoint: &str,
        client: reqwest::Client,
    ) -> BuildResult<Self> {
        reqwest::Url::parse(endpoint).map_err(|error| BuildError::InvalidUrl {
            url: endpoint.to_owned(),
            message: error.to_string(),
        })?;
        self.validator = Some(Arc::new(IntrospectionValidator::new(
            http_token_introspector(&self.config, client, endpoint.to_owned()),
            &self.config,
        )));
        Ok(self)
    }

    /// Installs a custom UserInfo-backed token validator.
    pub fn user_info_provider<P>(mut self, provider: P) -> Self
    where
        P: UserInfoProvider,
    {
        self.validator = Some(Arc::new(UserInfoValidator::new(provider, &self.config)));
        self
    }

    /// Installs an HTTP UserInfo-backed token validator.
    pub fn user_info_endpoint(self, endpoint: &str) -> BuildResult<Self> {
        let client = oidc_http_client(&self.config)?;
        self.user_info_endpoint_with_client(endpoint, client)
    }

    /// Installs an HTTP UserInfo-backed token validator using a caller-supplied client.
    pub fn user_info_endpoint_with_client(
        mut self,
        endpoint: &str,
        client: reqwest::Client,
    ) -> BuildResult<Self> {
        reqwest::Url::parse(endpoint).map_err(|error| BuildError::InvalidUrl {
            url: endpoint.to_owned(),
            message: error.to_string(),
        })?;
        self.validator = Some(Arc::new(UserInfoValidator::new(
            HttpUserInfoProvider::new(client, endpoint.to_owned()),
            &self.config,
        )));
        Ok(self)
    }

    /// Discovers provider metadata and installs a JWKS-backed JWT validator.
    pub async fn discover(self) -> BuildResult<Oidc> {
        let client = oidc_http_client(&self.config)?;
        self.discover_with_client(client).await
    }

    /// Discovers provider metadata using a caller-supplied HTTP client.
    pub async fn discover_with_client(self, client: reqwest::Client) -> BuildResult<Oidc> {
        if !self.config.enabled {
            return Ok(self.build());
        }
        if self.config.public_key.is_some()
            && self.config.application_type != ApplicationType::WebApp
        {
            let mut builder = self;
            builder.install_web_app_from_config(client)?;
            return Ok(builder.build());
        }

        let auth_server_url = auth_server_url_from_config(&self.config)?;
        if !self.config.discovery_enabled {
            let mut builder = self;
            builder.install_web_app_from_config(client.clone())?;
            if builder.config.public_key.is_some() {
                return Ok(builder.build());
            }
            if builder.config.token.require_jwt_introspection_only {
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
        let metadata: ProviderMetadata = client
            .get(metadata_url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        let mut builder = self;
        builder.install_web_app_from_metadata(&metadata, client.clone())?;
        if builder.config.public_key.is_some() {
            return Ok(builder.build());
        }

        if builder.config.token.require_jwt_introspection_only {
            let endpoint = metadata
                .introspection_endpoint
                .as_deref()
                .ok_or(BuildError::MissingIntrospectionEndpoint)?;
            return builder
                .introspection_endpoint_with_client(endpoint, client)
                .map(OidcBuilder::build);
        }

        if builder.config.token.verify_access_token_with_user_info {
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

        let jwks: JwkSet = client
            .get(&metadata.jwks_uri)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        builder.provider_metadata_refreshing(metadata, jwks, client)
    }

    /// Installs provider metadata and a JWKS-backed JWT validator.
    pub fn provider_metadata(
        mut self,
        metadata: ProviderMetadata,
        jwks: JwkSet,
    ) -> BuildResult<Oidc> {
        self.install_web_app_from_metadata(&metadata, reqwest::Client::new())?;
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
    pub fn provider_metadata_refreshing(
        mut self,
        metadata: ProviderMetadata,
        jwks: JwkSet,
        client: reqwest::Client,
    ) -> BuildResult<Oidc> {
        self.install_web_app_from_metadata(&metadata, client.clone())?;
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

    fn install_jwks_with_optional_introspection(&mut self, jwks: JwkSet, client: reqwest::Client) {
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
            return Arc::new(jwt);
        };
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

    fn install_metadata_introspection(
        &mut self,
        metadata: ProviderMetadata,
        client: reqwest::Client,
    ) -> BuildResult<()> {
        let endpoint = metadata
            .introspection_endpoint
            .clone()
            .ok_or(BuildError::MissingIntrospectionEndpoint)?;
        let validation_config = provider_validation_config(&self.config, &metadata);
        self.validator = Some(Arc::new(IntrospectionValidator::new(
            http_token_introspector(&validation_config, client, endpoint),
            &validation_config,
        )));
        Ok(())
    }

    fn install_metadata_user_info(
        &mut self,
        metadata: ProviderMetadata,
        client: reqwest::Client,
    ) -> BuildResult<()> {
        let endpoint = metadata
            .userinfo_endpoint
            .clone()
            .ok_or(BuildError::MissingUserInfoEndpoint)?;
        let validation_config = provider_validation_config(&self.config, &metadata);
        self.validator = Some(Arc::new(UserInfoValidator::new(
            HttpUserInfoProvider::new(client, endpoint),
            &validation_config,
        )));
        Ok(())
    }

    fn uses_user_info_roles(&self) -> bool {
        self.config.roles.source == RolesSource::UserInfo
            && !self.config.token.verify_access_token_with_user_info
    }

    fn install_web_app_from_config(&mut self, client: reqwest::Client) -> BuildResult<()> {
        if self.config.application_type != ApplicationType::WebApp {
            return Ok(());
        }
        self.web_app = Some(Arc::new(WebApp::from_config(&self.config, client)?));
        Ok(())
    }

    fn install_web_app_from_metadata(
        &mut self,
        metadata: &ProviderMetadata,
        client: reqwest::Client,
    ) -> BuildResult<()> {
        if self.config.application_type != ApplicationType::WebApp {
            return Ok(());
        }
        self.web_app = Some(Arc::new(WebApp::from_provider_metadata(
            &self.config,
            client,
            metadata.authorization_endpoint.clone(),
            metadata.token_endpoint.clone(),
        )?));
        Ok(())
    }

    fn user_info_endpoint_from_config(&self) -> Option<String> {
        let auth_server_url = self.config.auth_server_url.as_deref()?;
        let user_info_path = self.config.user_info_path.as_deref()?;
        provider_endpoint_url(auth_server_url, user_info_path)
            .ok()
            .map(Into::into)
    }

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
    /// If no validator is supplied, all bearer tokens are rejected. This keeps
    /// protected routes closed while allowing configuration and routing to be
    /// wired before a JWT/JWKS backend is added.
    pub fn build(self) -> Oidc {
        Oidc {
            config: self.config,
            validator: self.validator.unwrap_or_else(|| Arc::new(RejectAllTokens)),
            web_app: self.web_app,
        }
    }
}

/// Tower layer produced by [`Oidc::layer`].
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
        let mut inner = self.inner.clone();

        Box::pin(async move {
            match oidc.authenticate_or_response(&mut request).await {
                Ok(Some(response)) => Ok(response),
                Ok(None) => inner.call(request).await,
                Err(error) => Ok(error.into_response_with_scheme(&authorization_scheme)),
            }
        })
    }
}

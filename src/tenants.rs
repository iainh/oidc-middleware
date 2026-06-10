use crate::config_helpers::{has_default_tenant_config, named_tenant_configs, split_csv};
use crate::path::path_match_score;
use crate::token::{unverified_token_from_request, unverified_token_issuer};
use crate::{BuildResult, Oidc, OidcBuilder, OidcConfig, oidc_builder_from_config};
use axum::body::Body;
use axum::response::Response;
use http::Request;
use mp_config::{Config, ConfigProperties};
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower_layer::Layer;
use tower_service::Service;

/// Multi-tenant OIDC middleware.
#[derive(Clone, Default)]
pub struct Tenants {
    tenants: Arc<[RegisteredTenant]>,
    pub(crate) default_tenant: Option<Oidc>,
    pub(crate) header_name: Option<http::HeaderName>,
    resolve_with_issuer: bool,
}

impl Tenants {
    /// Starts building a multi-tenant OIDC layer.
    pub fn builder() -> TenantsBuilder {
        TenantsBuilder::default()
    }

    /// Loads the default tenant and named tenants from `mp-config`.
    ///
    /// The default tenant uses `oidc.*`; named tenants use
    /// `oidc.<tenant>.*`. Tenant selection uses each tenant's
    /// `tenant-paths` property.
    pub fn from_config(config: &Config) -> mp_config::Result<TenantsBuilder> {
        let mut builder = Tenants::builder().resolve_with_issuer(
            config
                .get_optional::<bool>("oidc.resolve-tenants-with-issuer")?
                .unwrap_or_default(),
        );
        if let Some(header_name) = config.get_optional::<String>("oidc.tenant-id-header")? {
            let parsed = http::HeaderName::from_str(&header_name).map_err(|error| {
                mp_config::ConfigError::Conversion {
                    name: "oidc.tenant-id-header".to_owned(),
                    value: header_name,
                    message: error.to_string(),
                }
            })?;
            builder = builder.tenant_header(parsed);
        }
        if has_default_tenant_config(config) {
            let default_config = OidcConfig::from_config(config)?;
            let default_tenant = oidc_builder_from_config(
                default_config,
                "oidc.public-key",
                "oidc.application-type",
                "oidc.roles.source",
                "oidc.token.binding.certificate",
                "oidc.token.decrypt-access-token",
                "oidc.token.decrypt-id-token",
            )?
            .build();
            builder = builder.default_tenant(default_tenant);
        }

        for tenant in named_tenant_configs(config) {
            let prefix = format!("oidc.{}", tenant.prefix_segment);
            let tenant_config = OidcConfig::from_config_prefix(config, &prefix)?;
            validate_configured_tenant_paths(&tenant_config, &format!("{prefix}.tenant-paths"))?;
            let oidc = oidc_builder_from_config(
                tenant_config,
                &format!("{prefix}.public-key"),
                &format!("{prefix}.application-type"),
                &format!("{prefix}.roles.source"),
                &format!("{prefix}.token.binding.certificate"),
                &format!("{prefix}.token.decrypt-access-token"),
                &format!("{prefix}.token.decrypt-id-token"),
            )?
            .build();
            builder = builder.tenant(tenant.name, oidc);
        }

        Ok(builder)
    }

    /// Loads configured tenants, discovers their providers, and builds the registry.
    ///
    /// The default tenant uses `oidc.*`; named tenants use
    /// `oidc.<tenant>.*`. Local `public-key` tenants are built without
    /// network access, while provider-backed tenants fetch discovery metadata
    /// and keys.
    pub async fn discover_from_config(config: &Config) -> BuildResult<Tenants> {
        discover_tenants_from_config(config, None).await
    }

    /// Loads configured tenants and discovers providers with a caller-supplied client.
    pub async fn discover_from_config_with_client(
        config: &Config,
        client: reqwest::Client,
    ) -> BuildResult<Tenants> {
        discover_tenants_from_config(config, Some(client)).await
    }

    /// Returns a tower layer suitable for `Router::layer`.
    pub fn layer(self) -> TenantsLayer {
        TenantsLayer { tenants: self }
    }

    fn select(&self, request: &Request<Body>) -> Option<&Oidc> {
        if let Some(header_name) = &self.header_name {
            if let Some(value) = request
                .headers()
                .get(header_name)
                .and_then(|value| value.to_str().ok())
            {
                if let Some(tenant) = self.tenants.iter().find(|tenant| tenant.matches_id(value)) {
                    return Some(&tenant.oidc);
                }
            }
        }

        if self.resolve_with_issuer {
            if let Some(tenant) = self.tenants.iter().find(|tenant| {
                tenant
                    .unverified_request_issuer(request)
                    .is_some_and(|issuer| tenant.issuer_matches(&issuer))
            }) {
                return Some(&tenant.oidc);
            }
        }

        let path = request.uri().path();
        self.tenants
            .iter()
            .filter_map(|tenant| tenant.match_score(path).map(|score| (score, tenant)))
            .max_by_key(|(score, _)| *score)
            .map(|(_, tenant)| &tenant.oidc)
            .or(self.default_tenant.as_ref())
    }
}

fn validate_configured_tenant_paths(
    config: &OidcConfig,
    property_name: &str,
) -> mp_config::Result<()> {
    if let Some(value) = &config.tenant_paths {
        if split_csv(value).is_empty() {
            return Err(mp_config::ConfigError::Conversion {
                name: property_name.to_owned(),
                value: value.clone(),
                message: "tenant-paths must include at least one path".to_owned(),
            });
        }
    }

    Ok(())
}

/// Builder for [`Tenants`].
#[derive(Default)]
pub struct TenantsBuilder {
    tenants: Vec<RegisteredTenant>,
    default_tenant: Option<Oidc>,
    header_name: Option<http::HeaderName>,
    resolve_with_issuer: bool,
}

impl TenantsBuilder {
    /// Sets the fallback tenant used when no named tenant matches.
    pub fn default_tenant(mut self, oidc: Oidc) -> Self {
        self.default_tenant = Some(oidc);
        self
    }

    /// Adds a named tenant.
    pub fn tenant(mut self, name: impl Into<String>, oidc: Oidc) -> Self {
        let name: Arc<str> = Arc::from(name.into());
        let id: Arc<str> = Arc::from(
            oidc.config
                .tenant_id
                .as_deref()
                .unwrap_or(name.as_ref())
                .to_owned(),
        );
        let mut tenant_paths = oidc
            .config
            .tenant_paths
            .as_deref()
            .map(split_csv)
            .unwrap_or_default();
        if tenant_paths.is_empty() {
            tenant_paths.push(default_tenant_path(name.as_ref()));
        }
        self.tenants.push(RegisteredTenant {
            name,
            id,
            tenant_paths,
            oidc,
        });
        self
    }

    /// Selects tenants from a request header before path matching.
    pub fn tenant_header(mut self, header_name: http::HeaderName) -> Self {
        self.header_name = Some(header_name);
        self
    }

    /// Selects tenants by matching bearer token `iss` claims.
    pub fn resolve_with_issuer(mut self, enabled: bool) -> Self {
        self.resolve_with_issuer = enabled;
        self
    }

    /// Finishes the tenant registry.
    pub fn build(self) -> Tenants {
        Tenants {
            tenants: Arc::from(self.tenants),
            default_tenant: self.default_tenant,
            header_name: self.header_name,
            resolve_with_issuer: self.resolve_with_issuer,
        }
    }
}

async fn discover_tenants_from_config(
    config: &Config,
    client: Option<reqwest::Client>,
) -> BuildResult<Tenants> {
    let mut builder = Tenants::builder().resolve_with_issuer(
        config
            .get_optional::<bool>("oidc.resolve-tenants-with-issuer")?
            .unwrap_or_default(),
    );
    if let Some(header_name) = config.get_optional::<String>("oidc.tenant-id-header")? {
        let parsed = http::HeaderName::from_str(&header_name).map_err(|error| {
            mp_config::ConfigError::Conversion {
                name: "oidc.tenant-id-header".to_owned(),
                value: header_name,
                message: error.to_string(),
            }
        })?;
        builder = builder.tenant_header(parsed);
    }
    if has_default_tenant_config(config) {
        let default_config = OidcConfig::from_config(config)?;
        let default_tenant = oidc_builder_from_config(
            default_config,
            "oidc.public-key",
            "oidc.application-type",
            "oidc.roles.source",
            "oidc.token.binding.certificate",
            "oidc.token.decrypt-access-token",
            "oidc.token.decrypt-id-token",
        )?;
        let default_tenant = discover_oidc_builder(default_tenant, client.as_ref()).await?;
        builder = builder.default_tenant(default_tenant);
    }

    for tenant in named_tenant_configs(config) {
        let prefix = format!("oidc.{}", tenant.prefix_segment);
        let tenant_config = OidcConfig::from_config_prefix(config, &prefix)?;
        validate_configured_tenant_paths(&tenant_config, &format!("{prefix}.tenant-paths"))?;
        let oidc = oidc_builder_from_config(
            tenant_config,
            &format!("{prefix}.public-key"),
            &format!("{prefix}.application-type"),
            &format!("{prefix}.roles.source"),
            &format!("{prefix}.token.binding.certificate"),
            &format!("{prefix}.token.decrypt-access-token"),
            &format!("{prefix}.token.decrypt-id-token"),
        )?;
        let oidc = discover_oidc_builder(oidc, client.as_ref()).await?;
        builder = builder.tenant(tenant.name, oidc);
    }

    Ok(builder.build())
}

async fn discover_oidc_builder(
    builder: OidcBuilder,
    client: Option<&reqwest::Client>,
) -> BuildResult<Oidc> {
    match client {
        Some(client) => builder.discover_with_client(client.clone()).await,
        None => builder.discover().await,
    }
}

#[derive(Clone)]
struct RegisteredTenant {
    name: Arc<str>,
    id: Arc<str>,
    tenant_paths: Vec<String>,
    oidc: Oidc,
}

impl RegisteredTenant {
    fn matches_id(&self, value: &str) -> bool {
        self.id.as_ref() == value || self.name.as_ref() == value
    }

    fn match_score(&self, request_path: &str) -> Option<usize> {
        self.tenant_paths
            .iter()
            .filter_map(|path| path_match_score(path, request_path))
            .max()
    }

    fn issuer_matches(&self, issuer: &str) -> bool {
        self.oidc
            .config
            .token
            .issuer
            .as_deref()
            .filter(|expected| *expected != "any")
            .or(self.oidc.config.auth_server_url.as_deref())
            .is_some_and(|expected| expected == issuer)
    }

    fn unverified_request_issuer(&self, request: &Request<Body>) -> Option<String> {
        unverified_token_from_request(request, &self.oidc.config.token)
            .and_then(unverified_token_issuer)
    }
}

fn default_tenant_path(name: &str) -> String {
    format!("/{name}/*")
}

/// Tower layer produced by [`Tenants::layer`].
#[derive(Clone)]
pub struct TenantsLayer {
    tenants: Tenants,
}

impl<S> Layer<S> for TenantsLayer {
    type Service = TenantsService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TenantsService {
            inner,
            tenants: self.tenants.clone(),
        }
    }
}

/// Tower service that selects a tenant and authenticates requests.
#[derive(Clone)]
pub struct TenantsService<S> {
    inner: S,
    tenants: Tenants,
}

impl<S> Service<Request<Body>> for TenantsService<S>
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
        let tenants = self.tenants.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let Some(tenant) = tenants.select(&request) else {
                return inner.call(request).await;
            };

            match tenant.authenticate_or_response(&mut request).await {
                Ok(Some(response)) => Ok(response),
                Ok(None) => inner.call(request).await,
                Err(error) => {
                    Ok(error.into_response_with_scheme(&tenant.config.token.authorization_scheme))
                }
            }
        })
    }
}

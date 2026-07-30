use crate::{Error, Principal};
use axum::body::Body;
use axum::response::{IntoResponse, Response};
use http::Request;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tower_layer::Layer;
use tower_service::Service;
use tracing::{debug, trace};

/// Requires a route to run only after OIDC authentication has succeeded.
///
/// This layer is intentionally small: it checks for the [`Principal`] extension
/// that [`crate::Oidc::layer`] inserts and returns `401 Unauthorized` when the
/// route is reached without one. That makes it useful for nested routers where
/// authentication and authorization are composed separately.
///
/// ```
/// use axum::{Router, routing::get};
/// use oidc_middleware::{Oidc, OidcConfig, RequireAuthenticatedLayer, StaticTokenValidator};
///
/// # fn app() -> Router {
/// let oidc = Oidc::builder(OidcConfig::default())
///     .validator(StaticTokenValidator::bearer("dev-token", "alice"))
///     .build();
///
/// Router::new()
///     .route("/account", get(|| async { "account" }))
///     .route_layer(RequireAuthenticatedLayer::new())
///     .layer(oidc.layer())
/// # }
/// ```
///
/// Prefer wrapping only protected routes. A global OIDC layer will challenge
/// every request it sees, including routes that would otherwise be public.
#[derive(Clone, Debug, Default)]
pub struct RequireAuthenticatedLayer;

impl RequireAuthenticatedLayer {
    /// Creates an authentication requirement layer.
    ///
    /// The layer does not validate tokens by itself. It is meant to run after
    /// OIDC middleware or another component has inserted a [`Principal`].
    pub fn new() -> Self {
        Self
    }
}

impl<S> Layer<S> for RequireAuthenticatedLayer {
    type Service = RequireAuthenticatedService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequireAuthenticatedService { inner }
    }
}

/// Tower service produced by [`RequireAuthenticatedLayer`].
#[derive(Clone, Debug)]
pub struct RequireAuthenticatedService<S> {
    inner: S,
}

impl<S> Service<Request<Body>> for RequireAuthenticatedService<S>
where
    S: Service<Request<Body>, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        Box::pin(async move {
            if request.extensions().get::<Principal>().is_none() {
                debug!(
                    method = %request.method(),
                    path = %request.uri().path(),
                    "authenticated route reached without a principal extension"
                );
                return Ok(Error::MissingBearerToken.into_response());
            }

            trace!(
                method = %request.method(),
                path = %request.uri().path(),
                "authenticated route authorization passed"
            );
            inner.call(request).await
        })
    }
}

/// Requires the authenticated principal to carry route-specific roles.
///
/// This is the Axum-native counterpart to Quarkus role policies: provider and
/// token validation stay in OIDC configuration, while authorization is visible
/// where the route is defined. Missing authentication returns `401`; a
/// principal without the required roles returns `403`.
///
/// ```
/// use axum::{Router, routing::get};
/// use oidc_middleware::{Oidc, OidcConfig, Principal, RequireRolesLayer, StaticTokenValidator};
///
/// # fn app() -> Router {
/// let oidc = Oidc::builder(OidcConfig::default())
///     .validator(StaticTokenValidator::principal(
///         "dev-token",
///         Principal::with_groups("alice", ["orders-reader"]),
///     ))
///     .build();
///
/// Router::new()
///     .route(
///         "/orders",
///         get(|| async { "orders" })
///             .route_layer(RequireRolesLayer::any(["orders-reader", "orders-admin"])),
///     )
///     .layer(oidc.layer())
/// # }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequireRolesLayer {
    roles: Arc<[String]>,
    mode: RoleMode,
}

impl RequireRolesLayer {
    /// Creates a role layer that allows any one of the listed roles.
    ///
    /// An empty role list is never useful for `any`: authenticated principals
    /// will fail the role check and receive `403 Forbidden`. Use
    /// [`RequireAuthenticatedLayer`] when no role distinction is needed.
    pub fn any(roles: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            roles: collect_roles(roles),
            mode: RoleMode::Any,
        }
    }

    /// Creates a role layer that requires every listed role.
    ///
    /// Use this for operations that require independent grants, such as both a
    /// product role and an operational break-glass role. For alternatives,
    /// prefer [`RequireRolesLayer::any`].
    pub fn all(roles: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            roles: collect_roles(roles),
            mode: RoleMode::All,
        }
    }
}

impl<S> Layer<S> for RequireRolesLayer {
    type Service = RequireRolesService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RequireRolesService {
            inner,
            roles: self.roles.clone(),
            mode: self.mode,
        }
    }
}

/// Tower service produced by [`RequireRolesLayer`].
#[derive(Clone, Debug)]
pub struct RequireRolesService<S> {
    inner: S,
    roles: Arc<[String]>,
    mode: RoleMode,
}

impl<S> Service<Request<Body>> for RequireRolesService<S>
where
    S: Service<Request<Body>, Response = Response, Error = Infallible> + Clone + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response, Infallible>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let roles = self.roles.clone();
        let mode = self.mode;

        Box::pin(async move {
            let Some(principal) = request.extensions().get::<Principal>() else {
                debug!(
                    method = %request.method(),
                    path = %request.uri().path(),
                    required_roles = ?roles,
                    "role-protected route reached without a principal extension"
                );
                return Ok(Error::MissingBearerToken.into_response());
            };

            let allowed = match mode {
                RoleMode::Any => roles.iter().any(|role| principal.has_group(role.as_str())),
                RoleMode::All => roles.iter().all(|role| principal.has_group(role.as_str())),
            };

            if !allowed {
                debug!(
                    method = %request.method(),
                    path = %request.uri().path(),
                    required_roles = ?roles,
                    mode = ?mode,
                    "principal did not satisfy route role requirement"
                );
                return Ok(Error::Forbidden.into_response());
            }

            trace!(
                method = %request.method(),
                path = %request.uri().path(),
                required_roles = ?roles,
                mode = ?mode,
                "route role authorization passed"
            );
            inner.call(request).await
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RoleMode {
    Any,
    All,
}

fn collect_roles(roles: impl IntoIterator<Item = impl Into<String>>) -> Arc<[String]> {
    roles.into_iter().map(Into::into).collect::<Vec<_>>().into()
}

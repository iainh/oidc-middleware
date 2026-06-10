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

/// Requires a request to have an authenticated [`Principal`] extension.
///
/// Apply this as an axum route layer after [`crate::Oidc::layer`] has
/// authenticated the request and inserted the principal.
#[derive(Clone, Debug, Default)]
pub struct RequireAuthenticatedLayer;

impl RequireAuthenticatedLayer {
    /// Creates an authentication requirement layer.
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
        let mut inner = self.inner.clone();

        Box::pin(async move {
            if request.extensions().get::<Principal>().is_none() {
                return Ok(Error::MissingBearerToken.into_response());
            }

            inner.call(request).await
        })
    }
}

/// Requires a request principal to have configured roles.
///
/// Apply this as an axum route layer after [`crate::Oidc::layer`] has
/// authenticated the request and inserted the principal. `any` accepts any one
/// of the listed roles; `all` requires every listed role.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequireRolesLayer {
    roles: Arc<[String]>,
    mode: RoleMode,
}

impl RequireRolesLayer {
    /// Creates a role layer that allows any listed role.
    pub fn any(roles: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            roles: collect_roles(roles),
            mode: RoleMode::Any,
        }
    }

    /// Creates a role layer that requires every listed role.
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
        let mut inner = self.inner.clone();
        let roles = self.roles.clone();
        let mode = self.mode;

        Box::pin(async move {
            let Some(principal) = request.extensions().get::<Principal>() else {
                return Ok(Error::MissingBearerToken.into_response());
            };

            let allowed = match mode {
                RoleMode::Any => roles.iter().any(|role| principal.has_group(role.as_str())),
                RoleMode::All => roles.iter().all(|role| principal.has_group(role.as_str())),
            };

            if !allowed {
                return Ok(Error::Forbidden.into_response());
            }

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

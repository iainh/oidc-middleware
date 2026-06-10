use crate::{Error, Principal, Result};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tracing::trace;

pub(crate) type ValidationFuture = Pin<Box<dyn Future<Output = Result<Principal>> + Send>>;

/// Validates a bearer token and returns the authenticated principal.
///
/// Implement this trait when token validation is owned by your application,
/// another service, or a test fixture. The returned [`Principal`] is the single
/// identity object used by extractors, route layers, and handler macros.
pub trait TokenValidator: Send + Sync + 'static {
    /// Validates a raw bearer token.
    ///
    /// The token value does not include the authorization scheme. Return
    /// [`crate::Error::TokenRejected`] for invalid tokens so the middleware can
    /// produce a consistent `invalid_token` challenge.
    fn validate(&self, token: Arc<str>) -> ValidationFuture;
}

impl<F, Fut> TokenValidator for F
where
    F: Fn(Arc<str>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Principal>> + Send + 'static,
{
    fn validate(&self, token: Arc<str>) -> ValidationFuture {
        Box::pin(self(token))
    }
}

/// Development/test token validator that accepts exactly one bearer token.
///
/// This validator is intentionally narrow. It is useful for examples and tests
/// that need to exercise middleware behaviour without generating JWTs or
/// starting a provider. Production services should use JWT, introspection,
/// UserInfo, or a custom [`TokenValidator`].
#[derive(Clone, Debug)]
pub struct StaticTokenValidator {
    token: Arc<str>,
    principal: Principal,
}

impl StaticTokenValidator {
    /// Creates a validator that accepts `token` and maps it to `subject`.
    ///
    /// The resulting principal has no groups; use [`StaticTokenValidator::principal`]
    /// when examples or tests need role-based authorization.
    pub fn bearer(token: impl Into<String>, subject: impl Into<String>) -> Self {
        Self::principal(token, Principal::new(subject))
    }

    /// Creates a validator that accepts `token` and returns `principal`.
    pub fn principal(token: impl Into<String>, principal: Principal) -> Self {
        Self {
            token: Arc::from(token.into()),
            principal,
        }
    }
}

impl TokenValidator for StaticTokenValidator {
    fn validate(&self, token: Arc<str>) -> ValidationFuture {
        let principal = self.principal.clone();
        let expected = self.token.clone();
        Box::pin(async move {
            if token == expected {
                trace!(
                    groups = principal.groups().count(),
                    "static token validator accepted token"
                );
                Ok(principal)
            } else {
                trace!("static token validator rejected token");
                Err(Error::TokenRejected("bearer token did not match".into()))
            }
        })
    }
}

#[derive(Clone)]
pub(crate) struct RejectAllTokens;

impl TokenValidator for RejectAllTokens {
    fn validate(&self, _token: Arc<str>) -> ValidationFuture {
        Box::pin(async { Err(Error::TokenRejected("no token validator configured".into())) })
    }
}

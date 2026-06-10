use crate::{Error, Principal, Result};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub(crate) type ValidationFuture = Pin<Box<dyn Future<Output = Result<Principal>> + Send>>;

/// Validates a bearer token and returns the authenticated principal.
pub trait TokenValidator: Send + Sync + 'static {
    /// Validates a raw bearer token.
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
#[derive(Clone, Debug)]
pub struct StaticTokenValidator {
    token: Arc<str>,
    principal: Principal,
}

impl StaticTokenValidator {
    /// Creates a validator that accepts `token` and maps it to `subject`.
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
                Ok(principal)
            } else {
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

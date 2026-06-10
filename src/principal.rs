use crate::claims::extract_roles;
use crate::validation_claims::{TokenClaims, principal_name};
use crate::{Error, Result};
use axum::extract::FromRequestParts;
use http::request::Parts;
use std::sync::Arc;

/// Authenticated identity stored in request extensions.
///
/// A `Principal` is the normalized identity produced after token validation.
/// It intentionally contains only the values most applications authorize with:
/// subject, issuer, audience, and groups. Keep provider-specific raw claims in
/// custom validators if handlers need them.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Principal {
    subject: Arc<str>,
    issuer: Option<Arc<str>>,
    audience: Vec<Arc<str>>,
    groups: Vec<Arc<str>>,
}

impl Principal {
    /// Creates a principal with the supplied subject.
    ///
    /// This is mostly useful for tests and examples. Real request principals
    /// normally come from JWT, introspection, or UserInfo validation.
    pub fn new(subject: impl Into<String>) -> Self {
        Self {
            subject: Arc::from(subject.into()),
            issuer: None,
            audience: Vec::new(),
            groups: Vec::new(),
        }
    }

    /// Creates a principal with group memberships.
    ///
    /// Use this in tests or local examples that exercise role authorization
    /// without constructing provider tokens.
    pub fn with_groups(
        subject: impl Into<String>,
        groups: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            subject: Arc::from(subject.into()),
            issuer: None,
            audience: Vec::new(),
            groups: groups
                .into_iter()
                .map(|group| Arc::from(group.into()))
                .collect(),
        }
    }

    /// Returns the token subject.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the token issuer when present.
    pub fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    /// Returns token audiences.
    pub fn audience(&self) -> impl Iterator<Item = &str> {
        self.audience.iter().map(AsRef::as_ref)
    }

    /// Returns group or role names carried by the token.
    ///
    /// Groups are derived from configured role claim paths and are the values
    /// checked by [`crate::RequireRolesLayer`] and `roles_allowed`.
    pub fn groups(&self) -> impl Iterator<Item = &str> {
        self.groups.iter().map(AsRef::as_ref)
    }

    /// Returns true when this principal has `group`.
    pub fn has_group(&self, group: &str) -> bool {
        self.groups
            .iter()
            .any(|candidate| candidate.as_ref() == group)
    }

    /// Returns true when this principal has at least one of `groups`.
    pub fn has_any_group<'a>(&self, groups: impl IntoIterator<Item = &'a str>) -> bool {
        groups.into_iter().any(|group| self.has_group(group))
    }

    pub(crate) fn from_claims(
        claims: TokenClaims,
        role_claim_paths: &[String],
        role_claim_separator: &str,
        principal_claim: Option<&str>,
    ) -> Result<Self> {
        let subject = principal_name(&claims, principal_claim)?;
        Ok(Self {
            subject: Arc::from(subject),
            issuer: claims.iss.map(Arc::from),
            audience: claims.aud.into_iter().map(Arc::from).collect(),
            groups: extract_roles(&claims.extra, role_claim_paths, role_claim_separator)
                .into_iter()
                .map(Arc::from)
                .collect(),
        })
    }

    pub(crate) fn with_claim_groups(mut self, groups: Vec<Arc<str>>) -> Self {
        self.groups = groups;
        self
    }

    #[cfg(feature = "web-app")]
    pub(crate) fn from_parts(
        subject: String,
        issuer: Option<String>,
        audience: Vec<String>,
        groups: Vec<String>,
    ) -> Self {
        Self {
            subject: Arc::from(subject),
            issuer: issuer.map(Arc::from),
            audience: audience.into_iter().map(Arc::from).collect(),
            groups: groups.into_iter().map(Arc::from).collect(),
        }
    }
}

/// Axum extractor for the authenticated OIDC principal.
///
/// Use this in handlers that should fail with `403 Forbidden` when called
/// without an authenticated principal extension. It is also the expected
/// principal argument for `roles_allowed` and `authenticated`
/// handler macros.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OidcPrincipal(Principal);

impl OidcPrincipal {
    /// Consumes the extractor wrapper and returns the principal.
    ///
    /// Deref is available for read-only handler logic; consume the wrapper when
    /// a handler needs to pass ownership to another component.
    pub fn into_inner(self) -> Principal {
        self.0
    }
}

impl std::ops::Deref for OidcPrincipal {
    type Target = Principal;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<S> FromRequestParts<S> for OidcPrincipal
where
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> std::result::Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Principal>()
            .cloned()
            .map(Self)
            .ok_or(Error::Forbidden)
    }
}

use crate::claims::deserialize_audience;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

/// Validated OpenID Connect ID token data.
///
/// ID tokens describe the authentication event and user profile context for the
/// client application. They are intentionally separate from [`crate::Principal`],
/// which remains the access-token-derived value used for API authorization.
#[derive(Clone, Debug, PartialEq)]
pub struct IdToken {
    claims: IdTokenClaims,
    raw: Option<Arc<str>>,
}

impl IdToken {
    /// Creates an ID token wrapper from parsed claims.
    pub fn new(claims: IdTokenClaims) -> Self {
        Self { claims, raw: None }
    }

    /// Creates an ID token wrapper from parsed claims and the original token.
    pub fn with_raw(claims: IdTokenClaims, raw: impl Into<String>) -> Self {
        Self {
            claims,
            raw: Some(Arc::from(raw.into())),
        }
    }

    /// Returns the parsed ID token claims.
    pub fn claims(&self) -> &IdTokenClaims {
        &self.claims
    }

    /// Returns the original compact token when it was retained.
    pub fn raw(&self) -> Option<&str> {
        self.raw.as_deref()
    }

    /// Returns the subject claim.
    pub fn subject(&self) -> Option<&str> {
        self.claims.sub.as_deref()
    }

    /// Returns the issuer claim.
    pub fn issuer(&self) -> Option<&str> {
        self.claims.iss.as_deref()
    }

    /// Returns the audience claims.
    pub fn audience(&self) -> impl Iterator<Item = &str> {
        self.claims.aud.iter().map(AsRef::as_ref)
    }

    /// Returns the expiration timestamp.
    pub fn expires_at(&self) -> Option<u64> {
        self.claims.exp
    }

    /// Returns the issued-at timestamp.
    pub fn issued_at(&self) -> Option<u64> {
        self.claims.iat
    }

    /// Returns the nonce claim.
    pub fn nonce(&self) -> Option<&str> {
        self.claims.nonce.as_deref()
    }

    /// Returns the authorized party claim.
    pub fn authorized_party(&self) -> Option<&str> {
        self.claims.azp.as_deref()
    }

    /// Returns a standard or provider-specific claim by name.
    pub fn claim(&self, name: &str) -> Option<&Value> {
        self.claims.extra.get(name)
    }

    /// Returns the email claim when present.
    pub fn email(&self) -> Option<&str> {
        self.claims.email.as_deref()
    }

    /// Returns the email verification claim when present.
    pub fn email_verified(&self) -> Option<bool> {
        self.claims.email_verified
    }
}

/// Parsed OpenID Connect ID token claims.
///
/// Standard claims are modelled directly. Additional provider-specific claims
/// are preserved in [`IdTokenClaims::extra`] so applications can map them into
/// their own user types.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct IdTokenClaims {
    /// Subject identifier.
    #[serde(default)]
    pub sub: Option<String>,
    /// Issuer identifier.
    #[serde(default)]
    pub iss: Option<String>,
    /// Audience values.
    #[serde(default, deserialize_with = "deserialize_audience")]
    pub aud: Vec<String>,
    /// Expiration timestamp.
    #[serde(default)]
    pub exp: Option<u64>,
    /// Issued-at timestamp.
    #[serde(default)]
    pub iat: Option<u64>,
    /// Authentication time timestamp.
    #[serde(default)]
    pub auth_time: Option<u64>,
    /// Nonce used to bind authentication response to request state.
    #[serde(default)]
    pub nonce: Option<String>,
    /// Authorized party.
    #[serde(default)]
    pub azp: Option<String>,
    /// End-user email address.
    #[serde(default)]
    pub email: Option<String>,
    /// Whether the provider reports the email address as verified.
    #[serde(default)]
    pub email_verified: Option<bool>,
    /// Additional provider-specific claims.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

impl IdTokenClaims {
    /// Parses ID token claims from JSON.
    pub fn from_json(json: &str) -> std::result::Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

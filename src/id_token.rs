use crate::claims::deserialize_audience;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

#[cfg(feature = "jwt")]
use crate::Error;
use crate::Result;
use std::future::Future;
use std::pin::Pin;

/// Future returned by an [`IdTokenValidator`].
pub type IdTokenValidationFuture = Pin<Box<dyn Future<Output = Result<IdToken>> + Send>>;

/// Validates an OpenID Connect ID token for a relying party.
///
/// This extension point is deliberately separate from bearer-token validation:
/// implementations must apply ID-token signature and claim rules and must not
/// use introspection or UserInfo as a fallback.
pub trait IdTokenValidator: Send + Sync + 'static {
    /// Validates a compact ID token and returns its trusted claims.
    fn validate(&self, token: Arc<str>) -> IdTokenValidationFuture;
}

impl<F, Fut> IdTokenValidator for F
where
    F: Fn(Arc<str>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<IdToken>> + Send + 'static,
{
    fn validate(&self, token: Arc<str>) -> IdTokenValidationFuture {
        Box::pin(self(token))
    }
}

#[cfg(feature = "web-app")]
#[derive(Clone)]
pub(crate) struct RejectAllIdTokens;

#[cfg(feature = "web-app")]
impl IdTokenValidator for RejectAllIdTokens {
    fn validate(&self, _token: Arc<str>) -> IdTokenValidationFuture {
        Box::pin(async {
            Err(Error::TokenRejected(
                "no ID-token validator configured".into(),
            ))
        })
    }
}

#[cfg(feature = "jwt")]
mod jose {
    use super::*;
    use crate::jwks::{JwtKeys, supported_algorithms};
    use crate::jwt::{public_decoding_key, public_key_algorithm};
    use crate::{BuildResult, JwksProvider, OidcConfig};
    use jsonwebtoken::jwk::JwkSet;
    use jsonwebtoken::{Algorithm, Validation, decode};

    /// Local JOSE validator for OpenID Connect ID tokens.
    #[derive(Clone)]
    pub struct JoseIdTokenValidator {
        keys: JwtKeys,
        validation: Validation,
        client_id: Arc<str>,
    }

    impl JoseIdTokenValidator {
        /// Builds an ID-token validator backed by a static PEM public key.
        pub fn public_key(
            public_key: &str,
            issuer: &str,
            client_id: &str,
            config: &OidcConfig,
        ) -> BuildResult<Self> {
            let mut validation = Validation::new(public_key_algorithm(config));
            validation.leeway = config.token.lifespan_grace.unwrap_or_default();
            validation.set_issuer(&[issuer]);
            validation.set_audience(&[client_id]);
            validation
                .required_spec_claims
                .extend(["iat".into(), "sub".into()]);
            let key = public_decoding_key(public_key, &validation)?;
            Ok(Self {
                keys: JwtKeys::single(key),
                validation,
                client_id: Arc::from(client_id),
            })
        }

        /// Builds an ID-token validator backed by a JWKS.
        pub fn jwks(jwks: JwkSet, issuer: &str, client_id: &str, leeway: u64) -> Self {
            let mut validation = Validation::new(Algorithm::RS256);
            validation.leeway = leeway;
            validation.set_issuer(&[issuer]);
            validation.set_audience(&[client_id]);
            validation
                .required_spec_claims
                .extend(["iat".into(), "sub".into()]);
            let algorithms = supported_algorithms(&jwks);
            if !algorithms.is_empty() {
                validation.algorithms = algorithms;
            }
            Self {
                keys: JwtKeys::set(jwks),
                validation,
                client_id: Arc::from(client_id),
            }
        }

        /// Builds a refreshable JWKS-backed ID-token validator.
        pub fn refreshable_jwks<P>(
            jwks: JwkSet,
            provider: P,
            issuer: &str,
            client_id: &str,
            config: &OidcConfig,
        ) -> Self
        where
            P: JwksProvider,
        {
            let mut value = Self::jwks(
                jwks.clone(),
                issuer,
                client_id,
                config.token.lifespan_grace.unwrap_or_default(),
            );
            value.keys =
                JwtKeys::refreshing(jwks, provider, config.token.forced_jwk_refresh_interval);
            value
        }
    }

    impl IdTokenValidator for JoseIdTokenValidator {
        fn validate(&self, token: Arc<str>) -> IdTokenValidationFuture {
            let keys = self.keys.clone();
            let validation = self.validation.clone();
            let client_id = self.client_id.clone();
            Box::pin(async move {
                let key = keys.decoding_key(&token).await?;
                let data = decode::<IdTokenClaims>(token.as_ref(), &key, &validation)
                    .map_err(|error| Error::TokenRejected(Box::new(error)))?;
                let claims = data.claims;
                if claims.iat.is_none() || claims.sub.as_deref().is_none_or(str::is_empty) {
                    return Err(Error::TokenRejected(
                        "ID token requires iat and non-empty sub claims".into(),
                    ));
                }
                if claims.aud.len() > 1 && claims.azp.as_deref() != Some(client_id.as_ref()) {
                    return Err(Error::TokenRejected(
                        "ID token with additional audiences requires azp equal to client_id".into(),
                    ));
                }
                if let Some(azp) = claims.azp.as_deref()
                    && azp != client_id.as_ref()
                {
                    return Err(Error::TokenRejected(
                        "ID token azp did not match client_id".into(),
                    ));
                }
                Ok(IdToken {
                    claims,
                    raw: Some(token),
                })
            })
        }
    }
}

#[cfg(feature = "jwt")]
pub use jose::JoseIdTokenValidator;

/// Validated OpenID Connect ID token data.
///
/// ID tokens describe the authentication event and user profile context for the
/// client application. They are intentionally separate from [`crate::Principal`],
/// though web apps may configure ID-token claims as the principal's role source.
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

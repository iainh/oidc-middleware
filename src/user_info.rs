use crate::claims::{deserialize_audience, extract_roles};
use crate::validation_claims::{
    TokenClaims, validate_required_claims, validate_subject, validate_token_age,
};
use crate::{
    BoxError, Error, OidcConfig, Principal, RolesSource, TokenValidator, UserInfoFuture,
    ValidationFuture, role_claim_paths_for_source,
};
use http::HeaderValue;
use http::header::AUTHORIZATION;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

/// OIDC UserInfo response.
///
/// Standard token-like fields are modelled directly and the remaining claims
/// are available for principal, required-claim, and role extraction.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct UserInfoResponse {
    /// Subject identifier.
    #[serde(default)]
    pub sub: Option<String>,
    /// Issuer, when returned by the provider.
    #[serde(default)]
    pub iss: Option<String>,
    /// Audience, when returned by the provider.
    #[serde(default, deserialize_with = "deserialize_audience")]
    pub aud: Vec<String>,
    /// Token or response type, when returned by the provider.
    #[serde(default)]
    pub typ: Option<String>,
    /// Issued-at timestamp, when returned by the provider.
    #[serde(default)]
    pub iat: Option<u64>,
    /// Additional UserInfo claims.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

impl UserInfoResponse {
    /// Parses a UserInfo response from JSON.
    pub fn from_json(json: &str) -> std::result::Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    fn into_claims(self) -> TokenClaims {
        TokenClaims {
            sub: self.sub,
            iss: self.iss,
            aud: self.aud,
            typ: self.typ,
            iat: self.iat,
            extra: Value::Object(self.extra),
        }
    }
}

/// Source used to fetch OIDC UserInfo for an access token.
pub trait UserInfoProvider: Send + Sync + 'static {
    /// Fetches UserInfo for a raw bearer token.
    fn user_info(&self, token: Arc<str>) -> UserInfoFuture;
}

impl<F, Fut> UserInfoProvider for F
where
    F: Fn(Arc<str>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = std::result::Result<UserInfoResponse, BoxError>> + Send + 'static,
{
    fn user_info(&self, token: Arc<str>) -> UserInfoFuture {
        Box::pin(self(token))
    }
}

/// Token validator backed by the OIDC UserInfo endpoint.
#[derive(Clone)]
pub struct UserInfoValidator {
    provider: Arc<dyn UserInfoProvider>,
    role_claim_paths: Arc<[String]>,
    role_claim_separator: Arc<str>,
    subject_required: bool,
    required_claims: Arc<HashMap<String, Vec<String>>>,
    principal_claim: Option<Arc<str>>,
    token_age: Option<Duration>,
    leeway: u64,
}

impl UserInfoValidator {
    /// Builds a UserInfo-backed token validator.
    pub fn new<P>(provider: P, config: &OidcConfig) -> Self
    where
        P: UserInfoProvider,
    {
        Self {
            provider: Arc::new(provider),
            role_claim_paths: Arc::from(role_claim_paths_for_source(config, RolesSource::UserInfo)),
            role_claim_separator: Arc::from(config.roles.role_claim_separator.clone()),
            subject_required: config.token.subject_required,
            required_claims: Arc::new(config.token.required_claims.clone()),
            principal_claim: config.token.principal_claim.clone().map(Arc::from),
            token_age: config.token.age,
            leeway: config.token.lifespan_grace.unwrap_or_default(),
        }
    }
}

impl TokenValidator for UserInfoValidator {
    fn validate(&self, token: Arc<str>) -> ValidationFuture {
        let provider = self.provider.clone();
        let role_claim_paths = self.role_claim_paths.clone();
        let role_claim_separator = self.role_claim_separator.clone();
        let subject_required = self.subject_required;
        let required_claims = self.required_claims.clone();
        let principal_claim = self.principal_claim.clone();
        let token_age = self.token_age;
        let leeway = self.leeway;

        Box::pin(async move {
            let claims = provider
                .user_info(token)
                .await
                .map_err(Error::TokenRejected)?
                .into_claims();
            validate_subject(&claims, subject_required)?;
            validate_required_claims(&claims, &required_claims)?;
            if claims.iat.is_some() {
                validate_token_age(&claims, token_age, leeway)?;
            }
            Principal::from_claims(
                claims,
                &role_claim_paths,
                &role_claim_separator,
                principal_claim.as_deref(),
            )
        })
    }
}

/// Token validator that validates a bearer token first, then loads roles from UserInfo.
#[derive(Clone)]
pub struct UserInfoRolesValidator {
    token_validator: Arc<dyn TokenValidator>,
    provider: Arc<dyn UserInfoProvider>,
    role_claim_paths: Arc<[String]>,
    role_claim_separator: Arc<str>,
}

impl UserInfoRolesValidator {
    /// Builds a validator that preserves token validation and sources roles from UserInfo.
    pub fn new<V, P>(token_validator: V, provider: P, config: &OidcConfig) -> Self
    where
        V: TokenValidator,
        P: UserInfoProvider,
    {
        Self::from_parts(Arc::new(token_validator), Arc::new(provider), config)
    }

    pub(crate) fn from_parts(
        token_validator: Arc<dyn TokenValidator>,
        provider: Arc<dyn UserInfoProvider>,
        config: &OidcConfig,
    ) -> Self {
        Self {
            token_validator,
            provider,
            role_claim_paths: Arc::from(role_claim_paths_for_source(config, RolesSource::UserInfo)),
            role_claim_separator: Arc::from(config.roles.role_claim_separator.clone()),
        }
    }
}

impl TokenValidator for UserInfoRolesValidator {
    fn validate(&self, token: Arc<str>) -> ValidationFuture {
        let token_validator = self.token_validator.clone();
        let provider = self.provider.clone();
        let role_claim_paths = self.role_claim_paths.clone();
        let role_claim_separator = self.role_claim_separator.clone();

        Box::pin(async move {
            let principal = token_validator.validate(token.clone()).await?;
            let claims = provider
                .user_info(token)
                .await
                .map_err(Error::TokenRejected)?
                .into_claims();

            if let Some(user_info_subject) = claims.sub.as_deref() {
                if user_info_subject != principal.subject() {
                    return Err(Error::TokenRejected(
                        "UserInfo subject did not match access token subject".into(),
                    ));
                }
            }

            Ok(principal.with_claim_groups(
                extract_roles(&claims.extra, &role_claim_paths, &role_claim_separator)
                    .into_iter()
                    .map(Arc::from)
                    .collect(),
            ))
        })
    }
}

#[derive(Clone)]
pub(crate) struct HttpUserInfoProvider {
    client: reqwest::Client,
    endpoint: String,
}

impl HttpUserInfoProvider {
    pub(crate) fn new(client: reqwest::Client, endpoint: String) -> Self {
        Self { client, endpoint }
    }
}

impl UserInfoProvider for HttpUserInfoProvider {
    fn user_info(&self, token: Arc<str>) -> UserInfoFuture {
        let client = self.client.clone();
        let endpoint = self.endpoint.clone();
        Box::pin(async move {
            let authorization = HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|error| Box::new(error) as BoxError)?;
            client
                .get(endpoint)
                .header(AUTHORIZATION, authorization)
                .send()
                .await?
                .error_for_status()?
                .json::<UserInfoResponse>()
                .await
                .map_err(|error| Box::new(error) as BoxError)
        })
    }
}

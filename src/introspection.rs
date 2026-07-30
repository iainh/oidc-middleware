#[cfg(feature = "http-client")]
use crate::ClientSecretMethod;
use crate::claims::deserialize_audience;
use crate::claims::{ClaimPath, compile_claim_paths};
use crate::validation_claims::{
    TokenClaims, validate_introspection_audience, validate_introspection_issuer,
    validate_issued_at, validate_required_claims, validate_subject, validate_token_age,
    validate_token_type,
};
use crate::{
    BoxError, Error, IntrospectionFuture, OidcConfig, Principal, RolesSource, TokenValidator,
    ValidationFuture, role_claim_paths_for_source,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, trace};

/// Token validator that falls back to introspection after local JWT rejection.
///
/// This mirrors deployments where JWTs should be validated locally when
/// possible, but opaque tokens or selected JWT failures must be checked with the
/// provider. The token configuration controls whether JWT-looking tokens,
/// opaque tokens, or both may use the fallback.
#[derive(Clone)]
pub struct IntrospectionFallbackValidator {
    jwt: Arc<dyn TokenValidator>,
    introspection: Arc<dyn TokenValidator>,
    allow_jwt_introspection: bool,
    allow_opaque_token_introspection: bool,
}

impl IntrospectionFallbackValidator {
    /// Builds a fallback validator from a local JWT validator and introspection validator.
    pub fn new<J, I>(jwt: J, introspection: I, config: &OidcConfig) -> Self
    where
        J: TokenValidator,
        I: TokenValidator,
    {
        Self {
            jwt: Arc::new(jwt),
            introspection: Arc::new(introspection),
            allow_jwt_introspection: config.token.allow_jwt_introspection,
            allow_opaque_token_introspection: config.token.allow_opaque_token_introspection,
        }
    }
}

impl TokenValidator for IntrospectionFallbackValidator {
    fn validate(&self, token: Arc<str>) -> ValidationFuture {
        let jwt = self.jwt.clone();
        let introspection = self.introspection.clone();
        let allow_jwt_introspection = self.allow_jwt_introspection;
        let allow_opaque_token_introspection = self.allow_opaque_token_introspection;

        Box::pin(async move {
            trace!("starting JWT validation before optional introspection fallback");
            match jwt.validate(token.clone()).await {
                Ok(principal) => {
                    trace!("primary JWT validation succeeded; introspection fallback not used");
                    Ok(principal)
                }
                Err(error) => {
                    if explicitly_typed_as_id_token(&token) {
                        debug!(
                            "explicitly typed ID token is ineligible for introspection fallback"
                        );
                        return Err(error);
                    }
                    let token_is_jwt = token_looks_like_jwt(&token);
                    debug!(
                        token_is_jwt,
                        allow_jwt_introspection,
                        allow_opaque_token_introspection,
                        error = %error,
                        "primary JWT validation failed; evaluating introspection fallback"
                    );
                    if (token_is_jwt && !allow_jwt_introspection)
                        || (!token_is_jwt && !allow_opaque_token_introspection)
                    {
                        trace!(
                            token_is_jwt,
                            "introspection fallback is disabled for token shape"
                        );
                        return Err(error);
                    }
                    introspection.validate(token).await
                }
            }
        })
    }
}

fn token_looks_like_jwt(token: &str) -> bool {
    token.split('.').count() == 3
}

fn explicitly_typed_as_id_token(token: &str) -> bool {
    let Some(header) = token.split('.').next() else {
        return false;
    };
    let Ok(decoded) = URL_SAFE_NO_PAD.decode(header) else {
        return false;
    };
    let Ok(header) = serde_json::from_slice::<serde_json::Value>(&decoded) else {
        return false;
    };
    header
        .get("typ")
        .and_then(Value::as_str)
        .is_some_and(|typ| {
            typ.eq_ignore_ascii_case("id_token") || typ.eq_ignore_ascii_case("id+jwt")
        })
}

/// OAuth2 token introspection response.
///
/// The response is normalized into the same validation pipeline as JWT claims:
/// issuer, audience, token type, age, required claims, principal selection, and
/// role extraction are all applied after the provider says the token is active.
///
/// RFC 7662 Section 2.2 makes the `active` member the normative acceptance
/// gate; inactive responses are not protocol errors and must be rejected
/// without relying on any other fields. Common JWT-style members are modelled
/// directly and remaining claims are preserved for role, principal, and
/// required-claim extraction.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct IntrospectionResponse {
    /// Whether the token is currently active.
    ///
    /// Inactive responses are rejected even if they include otherwise valid
    /// claims.
    #[serde(default)]
    pub active: bool,
    /// Token subject.
    #[serde(default)]
    pub sub: Option<String>,
    /// Token issuer.
    #[serde(default)]
    pub iss: Option<String>,
    /// Token audience.
    #[serde(default, deserialize_with = "deserialize_audience")]
    pub aud: Vec<String>,
    /// Token type.
    #[serde(default)]
    pub typ: Option<String>,
    /// Issued-at timestamp.
    #[serde(default)]
    pub iat: Option<u64>,
    /// Additional introspection claims.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

impl IntrospectionResponse {
    /// Parses an introspection response from JSON.
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

/// Source used to introspect opaque or remote-validated bearer tokens.
///
/// Implement this trait when the application owns the HTTP call, caching,
/// retries, or provider-specific request shape. For standard OAuth2 endpoints,
/// [`crate::OidcBuilder::introspection_endpoint`] is usually enough.
pub trait TokenIntrospector: Send + Sync + 'static {
    /// Introspects a raw bearer token.
    fn introspect(&self, token: Arc<str>) -> IntrospectionFuture;
}

impl<F, Fut> TokenIntrospector for F
where
    F: Fn(Arc<str>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = std::result::Result<IntrospectionResponse, BoxError>> + Send + 'static,
{
    fn introspect(&self, token: Arc<str>) -> IntrospectionFuture {
        Box::pin(self(token))
    }
}

/// Token validator backed by OAuth2 token introspection.
///
/// Use this for opaque tokens or providers that require remote validation. It
/// accepts only active introspection responses and then applies local claim
/// validation so provider responses still obey application policy.
#[derive(Clone)]
pub struct IntrospectionValidator {
    introspector: Arc<dyn TokenIntrospector>,
    expected_issuer: Option<Arc<str>>,
    audiences: Arc<[String]>,
    accepts_any_audience: bool,
    role_claim_paths: Arc<[ClaimPath]>,
    role_claim_separator: Arc<str>,
    token_type: Option<Arc<str>>,
    subject_required: bool,
    issued_at_required: bool,
    required_claims: Arc<HashMap<String, Vec<String>>>,
    principal_claim: Option<Arc<str>>,
    token_age: Option<Duration>,
    leeway: u64,
}

impl IntrospectionValidator {
    /// Builds a token introspection validator.
    pub fn new<I>(introspector: I, config: &OidcConfig) -> Self
    where
        I: TokenIntrospector,
    {
        let expected_issuer = config
            .token
            .issuer
            .as_deref()
            .or(config.auth_server_url.as_deref())
            .filter(|issuer| *issuer != "any")
            .map(|issuer| Arc::from(issuer.to_owned()));
        let audiences = config.token.audiences();

        debug!(
            has_expected_issuer = expected_issuer.is_some(),
            audiences = ?audiences,
            accepts_any_audience = config.token.accepts_any_audience(),
            required_claims = config.token.required_claims.len(),
            "building introspection validator"
        );
        Self {
            introspector: Arc::new(introspector),
            expected_issuer,
            audiences: Arc::from(audiences.into_boxed_slice()),
            accepts_any_audience: config.token.accepts_any_audience(),
            role_claim_paths: compile_claim_paths(&role_claim_paths_for_source(
                config,
                RolesSource::AccessToken,
            )),
            role_claim_separator: Arc::from(config.roles.role_claim_separator.clone()),
            token_type: config.token.token_type.clone().map(Arc::from),
            subject_required: config.token.subject_required,
            issued_at_required: config.token.issued_at_required,
            required_claims: Arc::new(config.token.required_claims.clone()),
            principal_claim: config.token.principal_claim.clone().map(Arc::from),
            token_age: config.token.age,
            leeway: config.token.lifespan_grace.unwrap_or_default(),
        }
    }
}

impl TokenValidator for IntrospectionValidator {
    fn validate(&self, token: Arc<str>) -> ValidationFuture {
        let introspector = self.introspector.clone();
        let expected_issuer = self.expected_issuer.clone();
        let audiences = self.audiences.clone();
        let accepts_any_audience = self.accepts_any_audience;
        let role_claim_paths = self.role_claim_paths.clone();
        let role_claim_separator = self.role_claim_separator.clone();
        let token_type = self.token_type.clone();
        let subject_required = self.subject_required;
        let issued_at_required = self.issued_at_required;
        let required_claims = self.required_claims.clone();
        let principal_claim = self.principal_claim.clone();
        let token_age = self.token_age;
        let leeway = self.leeway;

        Box::pin(async move {
            trace!("calling token introspector");
            let response = introspector
                .introspect(token)
                .await
                .map_err(Error::TokenRejected)?;
            if !response.active {
                debug!("token introspection response was inactive");
                return Err(Error::TokenRejected(
                    "token introspection is not active".into(),
                ));
            }

            trace!(
                has_subject = response.sub.is_some(),
                has_issuer = response.iss.is_some(),
                audiences = response.aud.len(),
                extra_claims = response.extra.len(),
                "token introspection response is active"
            );
            let claims = response.into_claims();
            validate_introspection_issuer(&claims, expected_issuer.as_deref())?;
            validate_introspection_audience(&claims, &audiences, accepts_any_audience)?;
            validate_token_type(None, &claims, token_type.as_deref())?;
            validate_subject(&claims, subject_required)?;
            validate_issued_at(&claims, issued_at_required, leeway)?;
            validate_required_claims(&claims, &required_claims)?;
            validate_token_age(&claims, token_age, leeway)?;
            let principal = Principal::from_claims(
                claims,
                &role_claim_paths,
                &role_claim_separator,
                principal_claim.as_deref(),
            )?;
            trace!(
                groups = principal.groups().count(),
                "introspection validation succeeded"
            );
            Ok(principal)
        })
    }
}

#[cfg(feature = "http-client")]
#[derive(Clone)]
pub(crate) struct HttpTokenIntrospector {
    pub(crate) client: reqwest::Client,
    pub(crate) endpoint: String,
    pub(crate) client_id: Option<String>,
    pub(crate) client_auth_name: Option<String>,
    pub(crate) client_secret: Option<String>,
    pub(crate) client_secret_method: ClientSecretMethod,
    pub(crate) include_client_id: bool,
}

#[cfg(feature = "http-client")]
impl TokenIntrospector for HttpTokenIntrospector {
    fn introspect(&self, token: Arc<str>) -> IntrospectionFuture {
        let client = self.client.clone();
        let endpoint = self.endpoint.clone();
        let client_id = self.client_id.clone();
        let client_auth_name = self.client_auth_name.clone();
        let client_secret = self.client_secret.clone();
        let client_secret_method = self.client_secret_method;
        let include_client_id = self.include_client_id;
        Box::pin(async move {
            debug!(
                endpoint = %endpoint,
                client_secret_method = ?client_secret_method,
                include_client_id,
                has_client_id = client_id.is_some(),
                has_client_secret = client_secret.is_some(),
                "sending token introspection request"
            );
            introspection_request(
                &client,
                &endpoint,
                token.as_ref(),
                IntrospectionRequestAuth {
                    client_id: client_id.as_deref(),
                    client_auth_name: client_auth_name.as_deref(),
                    client_secret: client_secret.as_deref(),
                    client_secret_method,
                    include_client_id,
                },
            )
            .send()
            .await?
            .error_for_status()?
            .json::<IntrospectionResponse>()
            .await
            .map_err(|error| Box::new(error) as BoxError)
        })
    }
}

#[cfg(feature = "http-client")]
pub(crate) fn http_token_introspector(
    config: &OidcConfig,
    client: reqwest::Client,
    endpoint: String,
) -> HttpTokenIntrospector {
    let introspection_secret = config.introspection_credentials.secret.clone();
    let has_introspection_credentials = introspection_secret.is_some();
    let client_auth_name = if has_introspection_credentials {
        config
            .introspection_credentials
            .name
            .clone()
            .or_else(|| config.client_id.clone())
    } else {
        config.client_id.clone()
    };
    let client_secret = introspection_secret.or_else(|| {
        config
            .credentials
            .effective_client_secret()
            .map(ToOwned::to_owned)
    });
    let client_secret_method = if has_introspection_credentials {
        ClientSecretMethod::Basic
    } else {
        config.credentials.client_secret.method
    };

    HttpTokenIntrospector {
        client,
        endpoint,
        client_id: config.client_id.clone(),
        client_auth_name,
        client_secret,
        client_secret_method,
        include_client_id: has_introspection_credentials
            && config.introspection_credentials.include_client_id,
    }
}

#[cfg(feature = "http-client")]
pub(crate) fn introspection_request<'a>(
    client: &'a reqwest::Client,
    endpoint: &'a str,
    token: &'a str,
    auth: IntrospectionRequestAuth<'a>,
) -> reqwest::RequestBuilder {
    match (
        auth.client_id,
        auth.client_auth_name,
        auth.client_secret,
        auth.client_secret_method,
    ) {
        (client_id, Some(client_auth_name), Some(client_secret), ClientSecretMethod::Basic) => {
            let mut form = vec![("token", token)];
            if auth.include_client_id
                && let Some(client_id) = client_id
            {
                form.push(("client_id", client_id));
            }
            client
                .post(endpoint)
                .form(&form)
                .basic_auth(client_auth_name, Some(client_secret))
        }
        (Some(client_id), _, Some(client_secret), ClientSecretMethod::Post) => {
            client.post(endpoint).form(&[
                ("token", token),
                ("client_id", client_id),
                ("client_secret", client_secret),
            ])
        }
        (Some(client_id), _, Some(client_secret), ClientSecretMethod::Query) => client
            .post(endpoint)
            .query(&[("client_id", client_id), ("client_secret", client_secret)])
            .form(&[("token", token)]),
        _ => client.post(endpoint).form(&[("token", token)]),
    }
}

#[cfg(feature = "http-client")]
#[derive(Clone, Copy)]
pub(crate) struct IntrospectionRequestAuth<'a> {
    pub(crate) client_id: Option<&'a str>,
    pub(crate) client_auth_name: Option<&'a str>,
    pub(crate) client_secret: Option<&'a str>,
    pub(crate) client_secret_method: ClientSecretMethod,
    pub(crate) include_client_id: bool,
}

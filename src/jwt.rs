use crate::jwks::{JwtKeys, supported_algorithms};
use crate::validation_claims::{
    TokenClaims, validate_issued_at, validate_required_claims, validate_subject,
    validate_token_age, validate_token_type,
};
use crate::{
    BuildError, BuildResult, Error, JwksProvider, OidcConfig, Principal, RolesSource,
    TokenValidator, ValidationFuture, role_claim_paths_for_source,
};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, trace};

/// JWT bearer token validator.
#[derive(Clone)]
pub struct JwtValidator {
    keys: JwtKeys,
    validation: Validation,
    role_claim_paths: Arc<[String]>,
    role_claim_separator: Arc<str>,
    token_type: Option<Arc<str>>,
    subject_required: bool,
    issued_at_required: bool,
    required_claims: Arc<HashMap<String, Vec<String>>>,
    principal_claim: Option<Arc<str>>,
    token_age: Option<Duration>,
}

impl JwtValidator {
    /// Builds an HS256 JWT validator.
    ///
    /// This is useful for tests and development providers. Production OIDC
    /// deployments should normally use asymmetric keys from provider metadata,
    /// which will be added as the discovery/JWKS support grows.
    pub fn hs256(secret: impl AsRef<[u8]>, config: &OidcConfig) -> Self {
        debug!("building HS256 JWT validator");
        let mut validation = Validation::new(Algorithm::HS256);
        apply_validation_config(&mut validation, config);
        apply_signature_algorithm_config(&mut validation, config);

        Self {
            keys: JwtKeys::single(DecodingKey::from_secret(secret.as_ref())),
            validation,
            role_claim_paths: Arc::from(role_claim_paths_for_source(
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
        }
    }

    /// Builds a JWT validator backed by a JSON Web Key Set.
    ///
    /// The token header `kid` is matched against the supplied key set. If the
    /// header has no `kid` and the set contains exactly one key, that key is
    /// used. Supported key algorithms are inferred from JWK `alg` fields when
    /// present.
    pub fn jwks(jwks: JwkSet, config: &OidcConfig) -> Self {
        debug!(keys = jwks.keys.len(), "building JWKS JWT validator");
        let mut validation = Validation::new(Algorithm::RS256);
        apply_validation_config(&mut validation, config);
        apply_jwks_algorithm_config(&mut validation, &jwks, config);

        Self {
            keys: JwtKeys::set(jwks),
            validation,
            role_claim_paths: Arc::from(role_claim_paths_for_source(
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
        }
    }

    /// Builds a JWT validator backed by `oidc.public-key`.
    pub fn public_key(public_key: &str, config: &OidcConfig) -> BuildResult<Self> {
        debug!("building public-key JWT validator");
        let mut validation = Validation::new(public_key_algorithm(config));
        apply_validation_config(&mut validation, config);
        apply_signature_algorithm_config(&mut validation, config);
        let key = public_decoding_key(public_key, &validation)?;

        Ok(Self {
            keys: JwtKeys::single(key),
            validation,
            role_claim_paths: Arc::from(role_claim_paths_for_source(
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
        })
    }

    /// Builds a JWT validator backed by a refreshable JSON Web Key Set.
    ///
    /// The current key set is used first. If a token contains an unknown `kid`,
    /// the provider is called once to refresh the set before rejecting the
    /// token.
    pub fn refreshable_jwks<P>(jwks: JwkSet, provider: P, config: &OidcConfig) -> Self
    where
        P: JwksProvider,
    {
        let mut validation = Validation::new(Algorithm::RS256);
        apply_validation_config(&mut validation, config);
        apply_jwks_algorithm_config(&mut validation, &jwks, config);

        Self {
            keys: JwtKeys::refreshing(jwks, provider, config.token.forced_jwk_refresh_interval),
            validation,
            role_claim_paths: Arc::from(role_claim_paths_for_source(
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
        }
    }
}

impl TokenValidator for JwtValidator {
    fn validate(&self, token: Arc<str>) -> ValidationFuture {
        let keys = self.keys.clone();
        let validation = self.validation.clone();
        let role_claim_paths = self.role_claim_paths.clone();
        let role_claim_separator = self.role_claim_separator.clone();
        let token_type = self.token_type.clone();
        let subject_required = self.subject_required;
        let issued_at_required = self.issued_at_required;
        let required_claims = self.required_claims.clone();
        let principal_claim = self.principal_claim.clone();
        let token_age = self.token_age;
        let leeway = validation.leeway;

        Box::pin(async move {
            trace!(
                algorithms = ?validation.algorithms,
                validate_audience = validation.validate_aud,
                required_claims = required_claims.len(),
                "starting JWT validation"
            );
            let key = keys.decoding_key(&token).await?;
            let data = match decode::<TokenClaims>(&token, &key, &validation) {
                Ok(data) => data,
                Err(error) => {
                    debug!(error = %error, "JWT decode or standard claim validation failed");
                    return Err(Error::TokenRejected(Box::new(error)));
                }
            };
            let result = (|| {
                validate_token_type(
                    data.header.typ.as_deref(),
                    &data.claims,
                    token_type.as_deref(),
                )?;
                validate_subject(&data.claims, subject_required)?;
                validate_issued_at(&data.claims, issued_at_required, leeway)?;
                validate_required_claims(&data.claims, &required_claims)?;
                validate_token_age(&data.claims, token_age, leeway)?;
                Principal::from_claims(
                    data.claims,
                    &role_claim_paths,
                    &role_claim_separator,
                    principal_claim.as_deref(),
                )
            })();
            match result {
                Ok(principal) => {
                    trace!(
                        groups = principal.groups().count(),
                        "JWT validation succeeded"
                    );
                    Ok(principal)
                }
                Err(error) => {
                    debug!(error = %error, "JWT application claim validation failed");
                    Err(error)
                }
            }
        })
    }
}

fn apply_validation_config(validation: &mut Validation, config: &OidcConfig) {
    validation.leeway = config.token.lifespan_grace.unwrap_or_default();

    let issuer = config
        .token
        .issuer
        .as_deref()
        .or(config.auth_server_url.as_deref());
    if let Some(issuer) = issuer.filter(|issuer| *issuer != "any") {
        trace!(issuer = %issuer, "configuring JWT issuer validation");
        validation.set_issuer(&[issuer]);
    }

    if config.token.accepts_any_audience() {
        debug!("JWT audience validation disabled because audience is configured as any");
        validation.validate_aud = false;
        return;
    }

    let audiences = config.token.audiences();
    if audiences.is_empty() {
        trace!("JWT audience validation disabled because no audience is configured");
        validation.validate_aud = false;
    } else {
        trace!(audiences = ?audiences, "configuring JWT audience validation");
        validation.set_audience(&audiences);
    }
}

fn apply_signature_algorithm_config(validation: &mut Validation, config: &OidcConfig) {
    if let Some(algorithm) = config.token.signature_algorithm {
        debug!(algorithm = ?algorithm, "configuring explicit JWT signature algorithm");
        validation.algorithms = vec![algorithm.algorithm()];
    }
}

fn apply_jwks_algorithm_config(validation: &mut Validation, jwks: &JwkSet, config: &OidcConfig) {
    if config.token.signature_algorithm.is_some() {
        apply_signature_algorithm_config(validation, config);
        return;
    }

    let algorithms = supported_algorithms(jwks);
    if !algorithms.is_empty() {
        trace!(algorithms = ?algorithms, "configuring JWT algorithms from JWKS metadata");
        validation.algorithms = algorithms;
    }
}

fn public_key_algorithm(config: &OidcConfig) -> Algorithm {
    config
        .token
        .signature_algorithm
        .map(|algorithm| algorithm.algorithm())
        .unwrap_or(Algorithm::RS256)
}

fn public_decoding_key(public_key: &str, validation: &Validation) -> BuildResult<DecodingKey> {
    let key = public_key.as_bytes();
    let algorithm = validation
        .algorithms
        .first()
        .copied()
        .unwrap_or(Algorithm::RS256);

    match algorithm {
        Algorithm::ES256 | Algorithm::ES384 => DecodingKey::from_ec_pem(key),
        Algorithm::EdDSA => DecodingKey::from_ed_pem(key),
        Algorithm::RS256
        | Algorithm::RS384
        | Algorithm::RS512
        | Algorithm::PS256
        | Algorithm::PS384
        | Algorithm::PS512 => DecodingKey::from_rsa_pem(key),
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            return Err(BuildError::InvalidPublicKey(
                "public-key does not support HMAC signature algorithms".into(),
            ));
        }
    }
    .map_err(|error| BuildError::InvalidPublicKey(Box::new(error)))
}

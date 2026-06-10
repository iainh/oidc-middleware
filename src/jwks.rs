use crate::{BoxError, Error, Result};
use jsonwebtoken::jwk::{JwkSet, KeyAlgorithm};
use jsonwebtoken::{Algorithm, DecodingKey, decode_header};
use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tracing::{debug, trace};

/// Future returned by [`JwksProvider`].
///
/// The future resolves to a complete JWKS document. Returning a boxed error lets
/// applications preserve provider, cache, or transport-specific diagnostics.
pub type JwksRefreshFuture =
    Pin<Box<dyn Future<Output = std::result::Result<JwkSet, BoxError>> + Send>>;

/// Source used to refresh a provider JSON Web Key Set.
///
/// Implement this trait when JWKS retrieval is owned by application
/// infrastructure, for example a shared cache, custom retry policy, or service
/// mesh endpoint. The built-in provider is used automatically by discovery.
pub trait JwksProvider: Send + Sync + 'static {
    /// Fetches the current JSON Web Key Set.
    ///
    /// Implementations should return the full active set, not only the missing
    /// key, because the validator replaces its cached set on successful refresh.
    fn fetch(&self) -> JwksRefreshFuture;
}

impl<F, Fut> JwksProvider for F
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = std::result::Result<JwkSet, BoxError>> + Send + 'static,
{
    fn fetch(&self) -> JwksRefreshFuture {
        Box::pin(self())
    }
}

#[cfg(all(feature = "http-client", feature = "jwt"))]
#[derive(Clone)]
pub(crate) struct HttpJwksProvider {
    client: reqwest::Client,
    jwks_uri: String,
}

#[cfg(all(feature = "http-client", feature = "jwt"))]
impl HttpJwksProvider {
    pub(crate) fn new(client: reqwest::Client, jwks_uri: String) -> Self {
        Self { client, jwks_uri }
    }
}

#[cfg(all(feature = "http-client", feature = "jwt"))]
impl JwksProvider for HttpJwksProvider {
    fn fetch(&self) -> JwksRefreshFuture {
        let client = self.client.clone();
        let jwks_uri = self.jwks_uri.clone();
        Box::pin(async move {
            debug!(jwks_uri = %jwks_uri, "fetching JWKS from provider");
            client
                .get(&jwks_uri)
                .send()
                .await?
                .error_for_status()?
                .json::<JwkSet>()
                .await
                .map_err(|error| Box::new(error) as BoxError)
        })
    }
}

#[derive(Clone)]
pub(crate) enum JwtKeys {
    Single(Arc<DecodingKey>),
    Set(Arc<JwkSet>),
    Refreshing(RefreshingJwks),
}

impl JwtKeys {
    pub(crate) fn single(key: DecodingKey) -> Self {
        Self::Single(Arc::new(key))
    }

    pub(crate) fn set(jwks: JwkSet) -> Self {
        Self::Set(Arc::new(jwks))
    }

    pub(crate) fn refreshing<P>(
        jwks: JwkSet,
        provider: P,
        forced_refresh_interval: Duration,
    ) -> Self
    where
        P: JwksProvider,
    {
        Self::Refreshing(RefreshingJwks {
            current: Arc::new(Mutex::new(jwks)),
            provider: Arc::new(provider),
            last_forced_refresh: Arc::new(Mutex::new(None)),
            forced_refresh_interval,
        })
    }

    pub(crate) async fn decoding_key(&self, token: &str) -> Result<DecodingKey> {
        match self {
            Self::Single(key) => {
                trace!("using single configured JWT decoding key");
                Ok((**key).clone())
            }
            Self::Set(jwks) => {
                trace!(
                    keys = jwks.keys.len(),
                    "selecting JWT decoding key from JWKS"
                );
                decoding_key_from_jwks(jwks, token)
            }
            Self::Refreshing(jwks) => {
                let key_result = {
                    let current = jwks
                        .current
                        .lock()
                        .map_err(|_| Error::TokenRejected("JWKS cache lock was poisoned".into()))?;
                    decoding_key_from_jwks(&current, token)
                };

                match key_result {
                    Ok(key) => Ok(key),
                    Err(error) if should_refresh_jwks(&error) => {
                        debug!(error = %error, "JWT key id was not found in cached JWKS");
                        if !jwks.should_force_refresh()? {
                            trace!("JWKS refresh suppressed by forced refresh interval");
                            return Err(error);
                        }
                        debug!("refreshing JWKS after unknown JWT key id");
                        let refreshed =
                            jwks.provider.fetch().await.map_err(Error::TokenRejected)?;
                        debug!(keys = refreshed.keys.len(), "JWKS refresh succeeded");
                        let key = decoding_key_from_jwks(&refreshed, token)?;
                        let mut current = jwks.current.lock().map_err(|_| {
                            Error::TokenRejected("JWKS cache lock was poisoned".into())
                        })?;
                        *current = refreshed;
                        Ok(key)
                    }
                    Err(error) => Err(error),
                }
            }
        }
    }
}

#[derive(Clone)]
pub(crate) struct RefreshingJwks {
    current: Arc<Mutex<JwkSet>>,
    provider: Arc<dyn JwksProvider>,
    last_forced_refresh: Arc<Mutex<Option<SystemTime>>>,
    forced_refresh_interval: Duration,
}

impl RefreshingJwks {
    fn should_force_refresh(&self) -> Result<bool> {
        let mut last_forced_refresh = self
            .last_forced_refresh
            .lock()
            .map_err(|_| Error::TokenRejected("JWKS refresh lock was poisoned".into()))?;
        let now = SystemTime::now();
        if last_forced_refresh
            .and_then(|last| now.duration_since(last).ok())
            .is_some_and(|elapsed| elapsed < self.forced_refresh_interval)
        {
            return Ok(false);
        }

        *last_forced_refresh = Some(now);
        Ok(true)
    }
}

fn decoding_key_from_jwks(jwks: &JwkSet, token: &str) -> Result<DecodingKey> {
    let header = decode_header(token).map_err(|error| Error::TokenRejected(Box::new(error)))?;
    trace!(kid = ?header.kid, algorithm = ?header.alg, "decoded JWT header for key selection");
    let jwk = match header.kid.as_deref() {
        Some(kid) => jwks
            .find(kid)
            .ok_or_else(|| Error::TokenRejected(UnknownKid(kid.to_owned()).into()))?,
        None if jwks.keys.len() == 1 => {
            trace!("JWT header had no kid; using only key in JWKS");
            &jwks.keys[0]
        }
        None => {
            debug!(
                keys = jwks.keys.len(),
                "JWT header did not include a key id and JWKS has multiple keys"
            );
            return Err(Error::TokenRejected(
                "JWT header did not include a key id".into(),
            ));
        }
    };

    DecodingKey::from_jwk(jwk).map_err(|error| Error::TokenRejected(Box::new(error)))
}

fn should_refresh_jwks(error: &Error) -> bool {
    matches!(error, Error::TokenRejected(source) if source.is::<UnknownKid>())
}

pub(crate) fn supported_algorithms(jwks: &JwkSet) -> Vec<Algorithm> {
    let mut algorithms = Vec::new();
    for algorithm in jwks
        .keys
        .iter()
        .filter_map(|jwk| jwk_algorithm(jwk.common.key_algorithm))
    {
        if !algorithms.contains(&algorithm) {
            algorithms.push(algorithm);
        }
    }
    algorithms
}

fn jwk_algorithm(algorithm: Option<KeyAlgorithm>) -> Option<Algorithm> {
    Algorithm::from_str(&algorithm?.to_string()).ok()
}

#[derive(Debug)]
struct UnknownKid(String);

impl fmt::Display for UnknownKid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "no JWK matched token key id `{}`", self.0)
    }
}

impl StdError for UnknownKid {}

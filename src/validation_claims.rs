use crate::claims::{claim_path_value, deserialize_audience};
use crate::{Error, Result};
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) fn validate_introspection_issuer(
    claims: &TokenClaims,
    expected: Option<&str>,
) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };

    match claims.iss.as_deref() {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(Error::TokenRejected(
            format!("introspection issuer `{actual}` did not match expected `{expected}`").into(),
        )),
        None => Err(Error::TokenRejected(
            "introspection issuer claim is required".into(),
        )),
    }
}

pub(crate) fn validate_introspection_audience(
    claims: &TokenClaims,
    audiences: &[String],
    accepts_any_audience: bool,
) -> Result<()> {
    if accepts_any_audience || audiences.is_empty() {
        return Ok(());
    }

    if claims
        .aud
        .iter()
        .any(|actual| audiences.iter().any(|expected| actual == expected))
    {
        return Ok(());
    }

    Err(Error::TokenRejected(
        "introspection audience did not include a configured audience".into(),
    ))
}

pub(crate) fn validate_token_type(
    header_token_type: Option<&str>,
    claims: &TokenClaims,
    expected: Option<&str>,
) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };

    match header_token_type
        .filter(|actual| *actual != "JWT")
        .or(claims.typ.as_deref())
    {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(Error::TokenRejected(
            format!("JWT typ `{actual}` did not match expected `{expected}`").into(),
        )),
        None => Err(Error::TokenRejected(
            format!("JWT typ is required to be `{expected}`").into(),
        )),
    }
}

pub(crate) fn validate_subject(claims: &TokenClaims, subject_required: bool) -> Result<()> {
    if subject_required && claims.sub.is_none() {
        return Err(Error::TokenRejected("JWT sub claim is required".into()));
    }

    Ok(())
}

pub(crate) fn validate_issued_at(
    claims: &TokenClaims,
    issued_at_required: bool,
    leeway: u64,
) -> Result<()> {
    let Some(issued_at) = claims.iat else {
        if issued_at_required {
            return Err(Error::TokenRejected("JWT iat claim is required".into()));
        }
        return Ok(());
    };
    let now = unix_timestamp()?;

    if issued_at > now.saturating_add(leeway) {
        return Err(Error::TokenRejected(
            "JWT iat claim is later than the allowed lifespan grace".into(),
        ));
    }

    Ok(())
}

pub(crate) fn validate_required_claims(
    claims: &TokenClaims,
    required_claims: &HashMap<String, Vec<String>>,
) -> Result<()> {
    for (claim_name, expected_values) in required_claims {
        let actual_values = claim_string_values(claims, claim_name).ok_or_else(|| {
            Error::TokenRejected(format!("JWT claim `{claim_name}` is required").into())
        })?;

        for expected in expected_values {
            if !actual_values.iter().any(|actual| actual == expected) {
                return Err(Error::TokenRejected(
                    format!("JWT claim `{claim_name}` did not include required value `{expected}`")
                        .into(),
                ));
            }
        }
    }

    Ok(())
}

pub(crate) fn validate_token_age(
    claims: &TokenClaims,
    max_age: Option<Duration>,
    leeway: u64,
) -> Result<()> {
    let Some(max_age) = max_age else {
        return Ok(());
    };
    let issued_at = claims.iat.ok_or_else(|| {
        Error::TokenRejected("JWT iat claim is required for token age validation".into())
    })?;
    let now = unix_timestamp()?;

    if issued_at > now.saturating_add(leeway) {
        return Err(Error::TokenRejected(
            "JWT iat claim is later than the allowed lifespan grace".into(),
        ));
    }

    if now
        > issued_at
            .saturating_add(max_age.as_secs())
            .saturating_add(leeway)
    {
        return Err(Error::TokenRejected(
            "JWT age exceeded the configured token age".into(),
        ));
    }

    Ok(())
}

pub(crate) fn unix_timestamp() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| Error::TokenRejected(Box::new(error)))
}

pub(crate) fn principal_name(
    claims: &TokenClaims,
    principal_claim: Option<&str>,
) -> Result<String> {
    if let Some(claim_name) = principal_claim {
        return claim_string_value(claims, claim_name).ok_or_else(|| {
            Error::TokenRejected(
                format!("JWT principal claim `{claim_name}` is required to be a string").into(),
            )
        });
    }

    claim_string_value(claims, "upn")
        .or_else(|| claim_string_value(claims, "preferred_username"))
        .or_else(|| claims.sub.clone())
        .ok_or_else(|| {
            Error::TokenRejected(
                "JWT must include a principal claim such as `upn`, `preferred_username`, or `sub`"
                    .into(),
            )
        })
}

fn claim_string_value(claims: &TokenClaims, claim_name: &str) -> Option<String> {
    match claim_name {
        "sub" => claims.sub.clone(),
        "iss" => claims.iss.clone(),
        "typ" => claims.typ.clone(),
        _ => claim_path_value(&claims.extra, claim_name)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
    }
}

fn claim_string_values(claims: &TokenClaims, claim_name: &str) -> Option<Vec<String>> {
    match claim_name {
        "sub" => claims.sub.clone().map(|subject| vec![subject]),
        "iss" => claims.iss.clone().map(|issuer| vec![issuer]),
        "aud" => Some(claims.aud.clone()),
        "typ" => claims.typ.clone().map(|token_type| vec![token_type]),
        "iat" => claims.iat.map(|issued_at| vec![issued_at.to_string()]),
        _ => json_string_values(claim_path_value(&claims.extra, claim_name)?),
    }
}

fn json_string_values(value: &Value) -> Option<Vec<String>> {
    match value {
        Value::String(value) => {
            let mut values = vec![value.clone()];
            values.extend(value.split_whitespace().map(ToOwned::to_owned));
            values.sort();
            values.dedup();
            Some(values)
        }
        Value::Array(values) => values
            .iter()
            .map(|value| value.as_str().map(ToOwned::to_owned))
            .collect(),
        _ => None,
    }
}

#[derive(Debug)]
pub(crate) struct TokenClaims {
    pub(crate) sub: Option<String>,
    pub(crate) iss: Option<String>,
    pub(crate) aud: Vec<String>,
    pub(crate) typ: Option<String>,
    pub(crate) iat: Option<u64>,
    pub(crate) extra: Value,
}

impl<'de> Deserialize<'de> for TokenClaims {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawClaims {
            #[serde(default)]
            sub: Option<String>,
            #[serde(default)]
            iss: Option<String>,
            #[serde(default, deserialize_with = "deserialize_audience")]
            aud: Vec<String>,
            #[serde(default)]
            typ: Option<String>,
            #[serde(default)]
            iat: Option<u64>,
            #[serde(flatten)]
            extra: serde_json::Map<String, Value>,
        }

        let raw = RawClaims::deserialize(deserializer)?;

        Ok(Self {
            sub: raw.sub,
            iss: raw.iss,
            aud: raw.aud,
            typ: raw.typ,
            iat: raw.iat,
            extra: Value::Object(raw.extra),
        })
    }
}

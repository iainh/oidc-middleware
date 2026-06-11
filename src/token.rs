use crate::{Error, OidcTokenConfig, Result};
use axum::body::Body;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::header::AUTHORIZATION;
use http::{HeaderName, HeaderValue, Request};
use serde_json::Value;
use std::sync::Arc;
use tracing::{debug, trace};

pub(crate) const MAX_TOKEN_BYTES: usize = 16 * 1024;
const MAX_AUTHORIZATION_HEADER_BYTES: usize = MAX_TOKEN_BYTES + 128;

pub(crate) fn validate_authorization_scheme(
    property_name: &str,
    value: &str,
) -> mp_config::Result<()> {
    if value.is_empty() || !value.bytes().all(is_http_token_char) {
        return Err(mp_config::ConfigError::Conversion {
            name: property_name.to_owned(),
            value: value.to_owned(),
            message: "authorization scheme must be a non-empty HTTP token".to_owned(),
        });
    }

    Ok(())
}

fn is_http_token_char(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#'..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'0'..=b'9' | b'A'..=b'Z' | b'^'..=b'z' | b'|' | b'~'
    )
}

pub(crate) fn bearer_token(
    request: &Request<Body>,
    config: &OidcTokenConfig,
    header_name: Option<&HeaderName>,
) -> Result<Arc<str>> {
    let header_name = header_name.ok_or(Error::InvalidAuthorizationHeader)?;
    let Some(header) = request.headers().get(header_name) else {
        trace!(
            configured_header = %config.header,
            "authorization token header was not present"
        );
        return Err(Error::MissingBearerToken);
    };
    validate_header_size(header)?;
    if header_name == AUTHORIZATION {
        trace!(
            authorization_scheme = %config.authorization_scheme,
            "extracting bearer token from Authorization header"
        );
        return bearer_token_from_authorization_header(header, &config.authorization_scheme);
    }
    let token = header
        .to_str()
        .map_err(|_| Error::InvalidAuthorizationHeader)?
        .trim();
    validate_token_shape(token)?;
    if token.is_empty() {
        trace!(configured_header = %config.header, "configured token header was empty");
        return Err(Error::InvalidAuthorizationHeader);
    }
    trace!(configured_header = %config.header, "extracted token from configured header");
    Ok(Arc::from(token))
}

pub(crate) fn unverified_token_from_request<'a>(
    request: &'a Request<Body>,
    config: &OidcTokenConfig,
    header_name: Option<&HeaderName>,
) -> Option<&'a str> {
    let header_name = header_name?;
    let header = request.headers().get(header_name)?;
    if header.as_bytes().len() > MAX_AUTHORIZATION_HEADER_BYTES {
        return None;
    }
    if header_name == AUTHORIZATION {
        return header
            .to_str()
            .ok()
            .and_then(|value| token_with_scheme(value, &config.authorization_scheme))
            .filter(|token| token_has_valid_shape(token));
    }
    header
        .to_str()
        .ok()
        .map(str::trim)
        .filter(|token| token_has_valid_shape(token))
}

fn bearer_token_from_authorization_header(
    header: &HeaderValue,
    authorization_scheme: &str,
) -> Result<Arc<str>> {
    let value = header
        .to_str()
        .map_err(|_| Error::InvalidAuthorizationHeader)?;
    let token = token_with_scheme(value, authorization_scheme)
        .filter(|token| token_has_valid_shape(token))
        .ok_or(Error::InvalidAuthorizationHeader)?;

    Ok(Arc::from(token))
}

fn validate_header_size(header: &HeaderValue) -> Result<()> {
    if header.as_bytes().len() <= MAX_AUTHORIZATION_HEADER_BYTES {
        return Ok(());
    }

    debug!(
        header_bytes = header.as_bytes().len(),
        max_header_bytes = MAX_AUTHORIZATION_HEADER_BYTES,
        "authorization token header exceeded size limit"
    );
    Err(Error::AuthorizationHeaderTooLarge)
}

fn validate_token_shape(token: &str) -> Result<()> {
    if token_has_valid_shape(token) {
        return Ok(());
    }

    debug!(
        token_bytes = token.len(),
        max_token_bytes = MAX_TOKEN_BYTES,
        contains_whitespace = token.bytes().any(|byte| byte.is_ascii_whitespace()),
        "authorization token had invalid shape"
    );
    Err(Error::InvalidAuthorizationHeader)
}

fn token_has_valid_shape(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_BYTES
        && !token.bytes().any(|byte| byte.is_ascii_whitespace())
}

fn token_with_scheme<'a>(value: &'a str, scheme: &str) -> Option<&'a str> {
    let (actual_scheme, token) = value.split_once(char::is_whitespace)?;
    if !actual_scheme.eq_ignore_ascii_case(scheme) {
        return None;
    }

    Some(token.trim_start())
}

pub(crate) fn unverified_token_issuer(token: &str) -> Option<String> {
    if !token_has_valid_shape(token) {
        trace!(
            token_bytes = token.len(),
            max_token_bytes = MAX_TOKEN_BYTES,
            contains_whitespace = token.bytes().any(|byte| byte.is_ascii_whitespace()),
            "skipping unverified issuer extraction for invalid token shape"
        );
        return None;
    }
    let payload = token.split('.').nth(1)?;
    if payload.len() > MAX_TOKEN_BYTES {
        trace!(
            payload_bytes = payload.len(),
            max_token_bytes = MAX_TOKEN_BYTES,
            "skipping unverified issuer extraction for oversized JWT payload"
        );
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims = serde_json::from_slice::<Value>(&decoded).ok()?;
    claims
        .get("iss")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

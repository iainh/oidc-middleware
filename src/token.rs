use crate::{Error, OidcTokenConfig, Result};
use axum::body::Body;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::header::AUTHORIZATION;
use http::{HeaderValue, Request};
use serde_json::Value;
use std::str::FromStr;
use std::sync::Arc;

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

pub(crate) fn bearer_token(request: &Request<Body>, config: &OidcTokenConfig) -> Result<Arc<str>> {
    let header_name = http::HeaderName::from_str(&config.header)
        .map_err(|_| Error::InvalidAuthorizationHeader)?;
    let Some(header) = request.headers().get(&header_name) else {
        return Err(Error::MissingBearerToken);
    };
    if header_name == AUTHORIZATION {
        return bearer_token_from_authorization_header(header, &config.authorization_scheme);
    }
    let token = header
        .to_str()
        .map_err(|_| Error::InvalidAuthorizationHeader)?
        .trim();
    if token.is_empty() {
        return Err(Error::InvalidAuthorizationHeader);
    }
    Ok(Arc::from(token))
}

pub(crate) fn unverified_token_from_request<'a>(
    request: &'a Request<Body>,
    config: &OidcTokenConfig,
) -> Option<&'a str> {
    let header_name = http::HeaderName::from_str(&config.header).ok()?;
    let header = request.headers().get(&header_name)?;
    if header_name == AUTHORIZATION {
        return header
            .to_str()
            .ok()
            .and_then(|value| token_with_scheme(value, &config.authorization_scheme))
            .filter(|token| !token.is_empty());
    }
    header
        .to_str()
        .ok()
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

fn bearer_token_from_authorization_header(
    header: &HeaderValue,
    authorization_scheme: &str,
) -> Result<Arc<str>> {
    let value = header
        .to_str()
        .map_err(|_| Error::InvalidAuthorizationHeader)?;
    let token = token_with_scheme(value, authorization_scheme)
        .filter(|token| !token.is_empty())
        .ok_or(Error::InvalidAuthorizationHeader)?;

    Ok(Arc::from(token))
}

fn token_with_scheme<'a>(value: &'a str, scheme: &str) -> Option<&'a str> {
    let (actual_scheme, token) = value.split_once(char::is_whitespace)?;
    if !actual_scheme.eq_ignore_ascii_case(scheme) {
        return None;
    }

    Some(token.trim_start())
}

pub(crate) fn unverified_token_issuer(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let claims = serde_json::from_slice::<Value>(&decoded).ok()?;
    claims
        .get("iss")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

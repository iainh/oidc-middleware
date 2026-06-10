use mp_config::Config;
use std::collections::{BTreeSet, HashMap};

pub(crate) fn load_optional_non_empty_string(
    config: &Config,
    key: &str,
) -> mp_config::Result<Option<String>> {
    let value = config.get_optional::<String>(key)?;
    if let Some(value) = &value {
        if value.trim().is_empty() {
            return Err(mp_config::ConfigError::Conversion {
                name: key.to_owned(),
                value: value.clone(),
                message: "value must not be empty when configured".to_owned(),
            });
        }
    }
    Ok(value)
}

pub(crate) fn load_required_claims(
    config: &Config,
    prefix: &str,
) -> mp_config::Result<HashMap<String, Vec<String>>> {
    let mut claims = HashMap::new();
    let property_prefix = format!("{prefix}.");

    for key in config.property_names() {
        let Some(claim_name) = key.strip_prefix(&property_prefix) else {
            continue;
        };
        let Some(claim_name) = config_map_entry_name(claim_name) else {
            continue;
        };

        let value = config.get::<String>(&key)?;
        let expected_values = split_csv(&value);
        if expected_values.is_empty() {
            return Err(mp_config::ConfigError::Conversion {
                name: key,
                value,
                message: "required claims must include at least one expected value".to_owned(),
            });
        }

        claims.insert(claim_name, expected_values);
    }

    Ok(claims)
}

pub(crate) fn config_map_entry_name(name: &str) -> Option<String> {
    if let Some(quoted) = name
        .strip_prefix('"')
        .and_then(|name| name.strip_suffix('"'))
    {
        return (!quoted.is_empty()).then(|| quoted.to_owned());
    }

    if name.is_empty() || name.contains('.') {
        return None;
    }

    Some(name.to_owned())
}

pub(crate) fn has_default_tenant_config(config: &Config) -> bool {
    config.property_names().into_iter().any(|key| {
        key == "oidc.enabled"
            || key == "oidc.tenant-enabled"
            || key == "oidc.auth-server-url"
            || key == "oidc.provider"
            || key == "oidc.connection-timeout"
            || key == "oidc.discovery-enabled"
            || key == "oidc.discovery-path"
            || key == "oidc.jwks-path"
            || key == "oidc.authorization-path"
            || key == "oidc.token-path"
            || key == "oidc.registration-path"
            || key == "oidc.revoke-path"
            || key == "oidc.introspection-path"
            || key == "oidc.user-info-path"
            || key == "oidc.end-session-path"
            || key == "oidc.client-id"
            || key == "oidc.client-name"
            || key == "oidc.tenant-id"
            || key == "oidc.tenant-id-header"
            || key == "oidc.tenant-paths"
            || key == "oidc.public-key"
            || key == "oidc.application-type"
            || key.starts_with("oidc.authentication.")
            || key.starts_with("oidc.credentials.")
            || key.starts_with("oidc.introspection-credentials.")
            || key.starts_with("oidc.token.")
            || key.starts_with("oidc.roles.")
    })
}

#[cfg(test)]
pub(crate) fn named_tenant_names(config: &Config) -> Vec<String> {
    named_tenant_configs(config)
        .into_iter()
        .map(|tenant| tenant.name)
        .collect()
}

#[derive(Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) struct NamedTenantConfig {
    pub(crate) name: String,
    pub(crate) prefix_segment: String,
}

pub(crate) fn named_tenant_configs(config: &Config) -> Vec<NamedTenantConfig> {
    let mut names = BTreeSet::new();
    for key in config.property_names() {
        let Some(rest) = key.strip_prefix("oidc.") else {
            continue;
        };
        let Some((name, prefix_segment, property)) = named_tenant_key_parts(rest) else {
            continue;
        };
        let tenant_property = matches!(
            property,
            "enabled"
                | "tenant-enabled"
                | "auth-server-url"
                | "provider"
                | "connection-timeout"
                | "discovery-enabled"
                | "discovery-path"
                | "jwks-path"
                | "authorization-path"
                | "token-path"
                | "registration-path"
                | "revoke-path"
                | "introspection-path"
                | "user-info-path"
                | "end-session-path"
                | "client-id"
                | "client-name"
                | "tenant-id"
                | "tenant-paths"
                | "public-key"
                | "application-type"
        ) || property.starts_with("authentication.")
            || property.starts_with("token.")
            || property.starts_with("credentials.")
            || property.starts_with("introspection-credentials.")
            || property.starts_with("roles.");
        if !matches!(
            name.as_str(),
            "authentication" | "credentials" | "introspection-credentials" | "token" | "roles"
        ) && tenant_property
        {
            names.insert(NamedTenantConfig {
                name,
                prefix_segment,
            });
        }
    }
    names.into_iter().collect()
}

fn named_tenant_key_parts(rest: &str) -> Option<(String, String, &str)> {
    if let Some(rest) = rest.strip_prefix('"') {
        let end = rest.find('"')?;
        let name = &rest[..end];
        if name.is_empty() {
            return None;
        }
        let property = rest[end + 1..].strip_prefix('.')?;
        return Some((name.to_owned(), format!(r#""{name}""#), property));
    }

    let (name, property) = rest.split_once('.')?;
    if name.is_empty() {
        return None;
    }
    Some((name.to_owned(), name.to_owned(), property))
}

pub(crate) fn permission_names(config: &Config) -> Vec<String> {
    let mut names = BTreeSet::new();

    for key in config.property_names() {
        if let Some(name) = key
            .strip_prefix("quarkus.http.auth.permission.")
            .and_then(|suffix| suffix.strip_suffix(".paths"))
        {
            names.insert(name.to_owned());
        }
    }

    names.into_iter().collect()
}

pub(crate) fn has_authorization_config(config: &Config) -> bool {
    !permission_names(config).is_empty()
}

pub(crate) fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

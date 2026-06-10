use crate::Principal;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

pub(crate) fn extract_roles(claims: &Value, paths: &[String], separator: &str) -> Vec<String> {
    let mut roles = Vec::new();
    for path in paths {
        if let Some(value) = claim_path_value(claims, path) {
            collect_roles(value, &mut roles, separator);
        }
    }
    deduplicate(&mut roles);
    roles
}

pub(crate) fn apply_role_mappings(
    principal: &mut Principal,
    role_mappings: &HashMap<String, Vec<String>>,
) {
    if role_mappings.is_empty() {
        return;
    }

    let mapped_roles = principal
        .group_arcs()
        .filter_map(|role| role_mappings.get(role.as_ref()))
        .flatten()
        .map(|role| Arc::from(role.clone()))
        .collect::<Vec<_>>();
    principal.add_groups(mapped_roles);
}

pub(crate) fn claim_path_value<'a>(claims: &'a Value, path: &str) -> Option<&'a Value> {
    claim_path_parts(path)
        .into_iter()
        .try_fold(claims, |value, part| value.get(part))
}

pub(crate) fn claim_path_parts(path: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut quoted = false;

    for character in path.chars() {
        match character {
            '"' => quoted = !quoted,
            '.' | '/' if !quoted => {
                if !current.is_empty() {
                    parts.push(std::mem::take(&mut current));
                }
            }
            character => current.push(character),
        }
    }

    if !current.is_empty() {
        parts.push(current);
    }

    parts
}

fn collect_roles(value: &Value, roles: &mut Vec<String>, separator: &str) {
    match value {
        Value::String(role) => split_roles(role, separator, roles),
        Value::Array(values) => {
            for value in values {
                collect_roles(value, roles, separator);
            }
        }
        _ => {}
    }
}

fn split_roles(value: &str, separator: &str, roles: &mut Vec<String>) {
    if separator.is_empty() {
        let role = value.trim();
        if !role.is_empty() {
            roles.push(role.to_owned());
        }
        return;
    }

    roles.extend(
        value
            .split(separator)
            .map(str::trim)
            .filter(|role| !role.is_empty())
            .map(ToOwned::to_owned),
    );
}

pub(crate) fn deserialize_audience<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?.unwrap_or(Value::Null);
    match value {
        Value::Null => Ok(Vec::new()),
        Value::String(audience) => Ok(vec![audience]),
        Value::Array(values) => values
            .into_iter()
            .map(|value| match value {
                Value::String(audience) => Ok(audience),
                _ => Err(serde::de::Error::custom("audience entries must be strings")),
            })
            .collect(),
        _ => Err(serde::de::Error::custom(
            "audience must be a string or string array",
        )),
    }
}

fn deduplicate(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

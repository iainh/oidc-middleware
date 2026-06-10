use crate::config_helpers::{config_map_entry_name, permission_names, split_csv};
use crate::path::{normalize_permission_paths, path_match_score};
use mp_config::Config;
use std::collections::HashMap;
use std::sync::Arc;

/// Quarkus-style HTTP authorization policies.
///
/// Load this from `quarkus.http.auth.permission.*` and
/// `quarkus.http.auth.policy.*` properties with [`Authorization::from_config`],
/// then attach it with [`crate::OidcBuilder::authorization`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Authorization {
    permissions: Arc<[HttpPermission]>,
    role_mappings: Arc<HashMap<String, Vec<String>>>,
}

impl Authorization {
    /// Loads Quarkus-style HTTP authorization configuration.
    pub fn from_config(config: &Config) -> mp_config::Result<Self> {
        let role_policies = load_role_policies(config)?;
        let role_mappings = load_role_mappings(config, "quarkus.http.auth.roles-mapping")?;
        let root_path = config
            .get_optional::<String>("quarkus.http.root-path")?
            .unwrap_or_else(|| "/".to_owned());
        let mut permissions = Vec::new();

        for name in permission_names(config) {
            let prefix = format!("quarkus.http.auth.permission.{name}");
            if !config
                .get_optional::<bool>(&format!("{prefix}.enabled"))?
                .unwrap_or(true)
            {
                continue;
            }

            let paths_key = format!("{prefix}.paths");
            let paths_value = config.get::<String>(&paths_key)?;
            let paths = split_csv(&paths_value);
            if paths.is_empty() {
                return Err(mp_config::ConfigError::Conversion {
                    name: paths_key,
                    value: paths_value,
                    message: "permission paths must include at least one path".to_owned(),
                });
            }
            let paths = normalize_permission_paths(paths, &root_path);
            let methods_key = format!("{prefix}.methods");
            let methods = config
                .get_optional::<String>(&methods_key)?
                .map(|methods| parse_configured_http_methods(&methods_key, &methods))
                .transpose()?
                .unwrap_or_default();
            let policy_key = format!("{prefix}.policy");
            let policy_name = config.get::<String>(&policy_key)?;
            let policy = policy_from_config(&policy_key, &policy_name, &role_policies)?;
            let shared = config
                .get_optional::<bool>(&format!("{prefix}.shared"))?
                .unwrap_or_default();

            permissions.push(HttpPermission {
                paths,
                methods,
                policy,
                shared,
            });
        }

        Ok(Self {
            permissions: Arc::from(permissions),
            role_mappings: Arc::new(role_mappings),
        })
    }

    pub(crate) fn requirement(&self, method: &http::Method, path: &str) -> AuthRequirement {
        let path_matches = self
            .permissions
            .iter()
            .filter_map(|permission| {
                permission
                    .path_match_score(path)
                    .map(|path_score| PermissionMatch {
                        path_score,
                        method_score: permission.method_match_score(method),
                        permission,
                    })
            })
            .collect::<Vec<_>>();

        if path_matches.is_empty() {
            return AuthRequirement::Permit;
        }

        let shared_policies = path_matches
            .iter()
            .filter(|permission_match| {
                permission_match.permission.shared && permission_match.method_score.is_some()
            })
            .map(|permission_match| &permission_match.permission.policy)
            .collect::<Vec<_>>();
        let unshared_matches = path_matches
            .iter()
            .filter(|permission_match| !permission_match.permission.shared)
            .collect::<Vec<_>>();

        let Some(max_path_score) = unshared_matches
            .iter()
            .map(|permission_match| permission_match.path_score)
            .max()
        else {
            if shared_policies.is_empty() {
                return AuthRequirement::Deny;
            }
            return policies_requirement(shared_policies, &self.role_mappings);
        };

        let unshared_matches = unshared_matches
            .into_iter()
            .filter(|permission_match| permission_match.path_score == max_path_score)
            .collect::<Vec<_>>();
        let Some(max_method_score) = unshared_matches
            .iter()
            .filter_map(|permission_match| permission_match.method_score)
            .max()
        else {
            return AuthRequirement::Deny;
        };

        let mut policies = shared_policies;
        policies.extend(
            unshared_matches
                .into_iter()
                .filter(|permission_match| permission_match.method_score == Some(max_method_score))
                .map(|permission_match| &permission_match.permission.policy),
        );

        policies_requirement(policies, &self.role_mappings)
    }
}

struct PermissionMatch<'a> {
    path_score: usize,
    method_score: Option<usize>,
    permission: &'a HttpPermission,
}

fn policies_requirement(
    policies: Vec<&HttpPolicy>,
    global_role_mappings: &HashMap<String, Vec<String>>,
) -> AuthRequirement {
    if policies.is_empty() {
        return AuthRequirement::Permit;
    }

    if policies
        .iter()
        .any(|policy| matches!(policy, HttpPolicy::Deny))
    {
        return AuthRequirement::Deny;
    }

    let mut role_sets = Vec::new();
    let mut role_mappings = global_role_mappings.clone();
    let mut authenticated = false;
    for policy in policies {
        match policy {
            HttpPolicy::Authenticated => authenticated = true,
            HttpPolicy::Roles(role_policy) => {
                authenticated = true;
                if !role_policy.roles_allowed.is_empty()
                    && !role_policy
                        .roles_allowed
                        .iter()
                        .any(|role| role.as_str() == "**")
                {
                    let mut roles = role_policy.roles_allowed.clone();
                    roles.sort();
                    roles.dedup();
                    role_sets.push(roles);
                }
                merge_role_mappings(&mut role_mappings, &role_policy.role_mappings);
            }
            HttpPolicy::Permit | HttpPolicy::Deny => {}
        }
    }

    if !role_sets.is_empty() {
        return AuthRequirement::Roles {
            role_sets,
            role_mappings,
        };
    }

    if authenticated {
        AuthRequirement::Authenticated(role_mappings)
    } else {
        AuthRequirement::Permit
    }
}

fn merge_role_mappings(
    target: &mut HashMap<String, Vec<String>>,
    source: &HashMap<String, Vec<String>>,
) {
    for (role, mapped_roles) in source {
        target
            .entry(role.clone())
            .or_default()
            .extend(mapped_roles.iter().cloned());
    }
}

fn parse_configured_http_methods(
    property_name: &str,
    value: &str,
) -> mp_config::Result<Vec<String>> {
    let methods = parse_http_methods(property_name, value)?;
    if methods.is_empty() {
        return Err(mp_config::ConfigError::Conversion {
            name: property_name.to_owned(),
            value: value.to_owned(),
            message: "permission methods must include at least one method when configured"
                .to_owned(),
        });
    }

    Ok(methods)
}

pub(crate) fn parse_http_methods(
    property_name: &str,
    value: &str,
) -> mp_config::Result<Vec<String>> {
    split_csv(value)
        .into_iter()
        .map(|method| {
            let method = method.to_ascii_uppercase();
            http::Method::from_bytes(method.as_bytes())
                .map(|_| method.clone())
                .map_err(|error| mp_config::ConfigError::Conversion {
                    name: property_name.to_owned(),
                    value: method,
                    message: error.to_string(),
                })
        })
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HttpPermission {
    paths: Vec<String>,
    methods: Vec<String>,
    policy: HttpPolicy,
    shared: bool,
}

impl HttpPermission {
    fn path_match_score(&self, request_path: &str) -> Option<usize> {
        self.paths
            .iter()
            .filter_map(|path| path_match_score(path, request_path))
            .max()
    }

    fn method_match_score(&self, method: &http::Method) -> Option<usize> {
        if self.methods.is_empty() {
            return Some(0);
        }

        if !self.methods.is_empty()
            && !self
                .methods
                .iter()
                .any(|configured| configured == method.as_str())
        {
            return None;
        }

        Some(1)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum HttpPolicy {
    Permit,
    Deny,
    Authenticated,
    Roles(RolePolicy),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct RolePolicy {
    roles_allowed: Vec<String>,
    role_mappings: HashMap<String, Vec<String>>,
}

pub(crate) enum AuthRequirement {
    Permit,
    Deny,
    Authenticated(HashMap<String, Vec<String>>),
    Roles {
        role_sets: Vec<Vec<String>>,
        role_mappings: HashMap<String, Vec<String>>,
    },
}

fn load_role_policies(config: &Config) -> mp_config::Result<HashMap<String, RolePolicy>> {
    let mut policies = HashMap::new();

    for key in config.property_names() {
        if let Some(name) = key
            .strip_prefix("quarkus.http.auth.policy.")
            .and_then(|suffix| suffix.strip_suffix(".roles-allowed"))
        {
            let value = config.get::<String>(&key)?;
            let roles_allowed = split_csv(&value);
            if roles_allowed.is_empty() {
                return Err(mp_config::ConfigError::Conversion {
                    name: key,
                    value,
                    message: "roles-allowed must include at least one role".to_owned(),
                });
            }
            policies
                .entry(name.to_owned())
                .or_insert_with(RolePolicy::default)
                .roles_allowed = roles_allowed;
            continue;
        }

        let Some((name, role)) = key
            .strip_prefix("quarkus.http.auth.policy.")
            .and_then(|suffix| suffix.split_once(".roles."))
        else {
            continue;
        };

        let Some(role) = config_map_entry_name(role) else {
            continue;
        };

        policies
            .entry(name.to_owned())
            .or_insert_with(RolePolicy::default)
            .role_mappings
            .insert(role, load_role_mapping(config, &key)?);
    }

    Ok(policies)
}

fn load_role_mappings(
    config: &Config,
    prefix: &str,
) -> mp_config::Result<HashMap<String, Vec<String>>> {
    let mut mappings = HashMap::new();
    let property_prefix = format!("{prefix}.");

    for key in config.property_names() {
        let Some(role) = key.strip_prefix(&property_prefix) else {
            continue;
        };
        let Some(role) = config_map_entry_name(role) else {
            continue;
        };

        mappings.insert(role, load_role_mapping(config, &key)?);
    }

    Ok(mappings)
}

fn load_role_mapping(config: &Config, key: &str) -> mp_config::Result<Vec<String>> {
    let value = config.get::<String>(key)?;
    let mapped_roles = split_csv(&value);
    if mapped_roles.is_empty() {
        return Err(mp_config::ConfigError::Conversion {
            name: key.to_owned(),
            value,
            message: "role mappings must include at least one mapped role".to_owned(),
        });
    }
    Ok(mapped_roles)
}

fn policy_from_config(
    property_name: &str,
    name: &str,
    role_policies: &HashMap<String, RolePolicy>,
) -> mp_config::Result<HttpPolicy> {
    match name {
        "permit" => Ok(HttpPolicy::Permit),
        "deny" => Ok(HttpPolicy::Deny),
        "authenticated" => Ok(HttpPolicy::Authenticated),
        name => role_policies
            .get(name)
            .cloned()
            .map(HttpPolicy::Roles)
            .ok_or_else(|| mp_config::ConfigError::Conversion {
                name: property_name.to_owned(),
                value: name.to_owned(),
                message: format!("authorization policy `{name}` is not defined"),
            }),
    }
}

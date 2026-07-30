use super::*;
use crate::claims::{claim_path_parts, validate_claim_path};
use crate::config_helpers::named_tenant_names;
use crate::introspection::{
    IntrospectionRequestAuth, http_token_introspector, introspection_request,
};
use crate::provider::{auth_server_url_from_config, discovery_url, provider_endpoint_url};
use crate::validation_claims::unix_timestamp;
use axum::Router;
use axum::body::Body;
use axum::extract::Extension;
use axum::response::Response;
use axum::routing::get;
use http::Request;
use http::header::{AUTHORIZATION, COOKIE, HOST, LOCATION, SET_COOKIE, WWW_AUTHENTICATE};
use http::{HeaderValue, StatusCode};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use mp_config::{Config, ConfigProperties, MapSource};
use serde::Serialize;
use serde_json::Value;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tower::ServiceExt;

const TEST_IAT: u64 = 1_700_000_000;

const PRIVATE_RSA_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJETqse41HRBsc
7cfcq3ak4oZWFCoZlcic525A3FfO4qW9BMtRO/iXiyCCHn8JhiL9y8j5JdVP2Q9Z
IpfElcFd3/guS9w+5RqQGgCR+H56IVUyHZWtTJbKPcwWXQdNUX0rBFcsBzCRESJL
eelOEdHIjG7LRkx5l/FUvlqsyHDVJEQsHwegZ8b8C0fz0EgT2MMEdn10t6Ur1rXz
jMB/wvCg8vG8lvciXmedyo9xJ8oMOh0wUEgxziVDMMovmC+aJctcHUAYubwoGN8T
yzcvnGqL7JSh36Pwy28iPzXZ2RLhAyJFU39vLaHdljwthUaupldlNyCfa6Ofy4qN
ctlUPlN1AgMBAAECggEAdESTQjQ70O8QIp1ZSkCYXeZjuhj081CK7jhhp/4ChK7J
GlFQZMwiBze7d6K84TwAtfQGZhQ7km25E1kOm+3hIDCoKdVSKch/oL54f/BK6sKl
qlIzQEAenho4DuKCm3I4yAw9gEc0DV70DuMTR0LEpYyXcNJY3KNBOTjN5EYQAR9s
2MeurpgK2MdJlIuZaIbzSGd+diiz2E6vkmcufJLtmYUT/k/ddWvEtz+1DnO6bRHh
xuuDMeJA/lGB/EYloSLtdyCF6sII6C6slJJtgfb0bPy7l8VtL5iDyz46IKyzdyzW
tKAn394dm7MYR1RlUBEfqFUyNK7C+pVMVoTwCC2V4QKBgQD64syfiQ2oeUlLYDm4
CcKSP3RnES02bcTyEDFSuGyyS1jldI4A8GXHJ/lG5EYgiYa1RUivge4lJrlNfjyf
dV230xgKms7+JiXqag1FI+3mqjAgg4mYiNjaao8N8O3/PD59wMPeWYImsWXNyeHS
55rUKiHERtCcvdzKl4u35ZtTqQKBgQDNKnX2bVqOJ4WSqCgHRhOm386ugPHfy+8j
m6cicmUR46ND6ggBB03bCnEG9OtGisxTo/TuYVRu3WP4KjoJs2LD5fwdwJqpgtHl
yVsk45Y1Hfo+7M6lAuR8rzCi6kHHNb0HyBmZjysHWZsn79ZM+sQnLpgaYgQGRbKV
DZWlbw7g7QKBgQCl1u+98UGXAP1jFutwbPsx40IVszP4y5ypCe0gqgon3UiY/G+1
zTLp79GGe/SjI2VpQ7AlW7TI2A0bXXvDSDi3/5Dfya9ULnFXv9yfvH1QwWToySpW
Kvd1gYSoiX84/WCtjZOr0e0HmLIb0vw0hqZA4szJSqoxQgvF22EfIWaIaQKBgQCf
34+OmMYw8fEvSCPxDxVvOwW2i7pvV14hFEDYIeZKW2W1HWBhVMzBfFB5SE8yaCQy
pRfOzj9aKOCm2FjjiErVNpkQoi6jGtLvScnhZAt/lr2TXTrl8OwVkPrIaN0bG/AS
aUYxmBPCpXu3UjhfQiWqFq/mFyzlqlgvuCc9g95HPQKBgAscKP8mLxdKwOgX8yFW
GcZ0izY/30012ajdHY+/QK5lsMoxTnn0skdS+spLxaS5ZEO4qvPVb8RAoCkWMMal
2pOhmquJQVDPDLuZHdrIiKiDM20dy9sMfHygWcZjQ4WSxf/J7T9canLZIXFhHAZT
3wc9h4G8BBCtWN2TN/LsGZdB
-----END PRIVATE KEY-----"#;

const PUBLIC_RSA_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyRE6rHuNR0QbHO3H3Kt2
pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5/CYYi/cvI+SXVT9kPWSKXxJXB
Xd/4LkvcPuUakBoAkfh+eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHR
yIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG/AtH89BIE9jDBHZ9dLelK9a184zAf8Lw
oPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xq
i+yUod+j8MtvIj812dkS4QMiRVN/by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5T
dQIDAQAB
-----END PUBLIC KEY-----"#;

#[test]
fn config_loads_quarkus_oidc_properties() {
    let config = Config::builder()
        .add_source(
            MapSource::new("test", 100)
                .with("oidc.auth-server-url", "https://issuer.example/realms/app")
                .with("oidc.provider", "github")
                .with("oidc.connection-timeout", "2s")
                .with("oidc.resolve-tenants-with-issuer", "true")
                .with("oidc.discovery-enabled", "false")
                .with("oidc.discovery-path", "custom-discovery")
                .with("oidc.jwks-path", "protocol/openid-connect/certs")
                .with("oidc.authorization-path", "protocol/openid-connect/auth")
                .with("oidc.token-path", "protocol/openid-connect/token")
                .with(
                    "oidc.registration-path",
                    "clients-registrations/openid-connect",
                )
                .with("oidc.revoke-path", "protocol/openid-connect/revoke")
                .with(
                    "oidc.introspection-path",
                    "protocol/openid-connect/token/introspect",
                )
                .with("oidc.user-info-path", "protocol/openid-connect/userinfo")
                .with("oidc.end-session-path", "protocol/openid-connect/logout")
                .with("oidc.client-id", "orders-service")
                .with("oidc.client-name", "Orders Service")
                .with("oidc.credentials.secret", "orders-secret")
                .with("oidc.credentials.client-secret.method", "post")
                .with("oidc.introspection-credentials.name", "introspect")
                .with("oidc.introspection-credentials.secret", "introspect-secret")
                .with("oidc.introspection-credentials.include-client-id", "false")
                .with("oidc.tenant-id", "orders-tenant")
                .with("oidc.public-key", "configured-public-key")
                .with("oidc.application-type", "hybrid")
                .with("oidc.authentication.redirect-path", "/login/callback")
                .with("oidc.authentication.restore-path-after-redirect", "false")
                .with("oidc.authentication.session-age-extension", "120s")
                .with(
                    "oidc.authentication.token-state-cookie-key",
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                )
                .with("oidc.authentication.nonce-required", "false")
                .with("oidc.authentication.scopes", "openid,email,profile")
                .with("oidc.logout.path", "/signout")
                .with("oidc.logout.post-logout-path", "/signed-out")
                .with("oidc.logout.post-logout-uri-param", "returnTo")
                .with("oidc.logout.extra-params.ui_locales", "en-CA")
                .with("oidc.logout.extra-params.\"client.name\"", "orders")
                .with("oidc.token.audience", "orders-api")
                .with("oidc.token.token-type", "bearer")
                .with("oidc.token.signature-algorithm", "rs256")
                .with(
                    "oidc.token.decryption-key-location",
                    "/etc/oidc/decryption.pem",
                )
                .with("oidc.token.decrypt-id-token", "false")
                .with("oidc.token.decrypt-access-token", "false")
                .with("oidc.token.subject-required", "true")
                .with("oidc.token.issued-at-required", "false")
                .with("oidc.token.required-claims.org_id", "org_xyz")
                .with("oidc.token.required-claims.scope", "read,write")
                .with(
                    "oidc.token.required-claims.\"resource_access.orders.roles\"",
                    "orders-admin",
                )
                .with("oidc.token.principal-claim", "email")
                .with("oidc.token.header", "x-access-token")
                .with("oidc.token.authorization-scheme", "Token")
                .with("oidc.token.lifespan-grace", "5")
                .with("oidc.token.age", "60s")
                .with("oidc.token.refresh-expired", "true")
                .with("oidc.token.refresh-token-time-skew", "15s")
                .with("oidc.token.forced-jwk-refresh-interval", "30s")
                .with("oidc.token.allow-jwt-introspection", "false")
                .with("oidc.token.require-jwt-introspection-only", "true")
                .with("oidc.token.allow-opaque-token-introspection", "false")
                .with("oidc.token.verify-access-token-with-user-info", "true")
                .with("oidc.token.binding.certificate", "true")
                .with("oidc.roles.role-claim-path", "resource_access.api.roles")
                .with("oidc.roles.source", "userinfo")
                .with("oidc.roles.role-claim-separator", "|"),
        )
        .build();

    let oidc = OidcConfig::from_config(&config).expect("config should load");

    assert_eq!(
        oidc,
        OidcConfig {
            enabled: true,
            tenant_enabled: true,
            resolve_tenants_with_issuer: true,
            auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
            provider: Some(WellKnownProvider::Github),
            connection_timeout: Duration::from_secs(2),
            discovery_enabled: false,
            discovery_path: "custom-discovery".to_owned(),
            jwks_path: Some("protocol/openid-connect/certs".to_owned()),
            authorization_path: Some("protocol/openid-connect/auth".to_owned()),
            token_path: Some("protocol/openid-connect/token".to_owned()),
            registration_path: Some("clients-registrations/openid-connect".to_owned()),
            revoke_path: Some("protocol/openid-connect/revoke".to_owned()),
            introspection_path: Some("protocol/openid-connect/token/introspect".to_owned()),
            user_info_path: Some("protocol/openid-connect/userinfo".to_owned()),
            end_session_path: Some("protocol/openid-connect/logout".to_owned()),
            client_id: Some("orders-service".to_owned()),
            client_name: Some("Orders Service".to_owned()),
            tenant_id: Some("orders-tenant".to_owned()),
            tenant_paths: None,
            public_key: Some("configured-public-key".to_owned()),
            application_type: ApplicationType::Hybrid,
            authentication: OidcAuthenticationConfig {
                redirect_path: "/login/callback".to_owned(),
                restore_path_after_redirect: false,
                session_age_extension: Duration::from_secs(120),
                token_state_cookie_key: Some(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                        .to_owned(),
                ),
                nonce_required: false,
                scopes: vec![
                    "openid".to_owned(),
                    "email".to_owned(),
                    "profile".to_owned(),
                ],
            },
            logout: OidcLogoutConfig {
                path: "/signout".to_owned(),
                post_logout_path: Some("/signed-out".to_owned()),
                post_logout_uri_param: "returnTo".to_owned(),
                extra_params: HashMap::from([
                    ("ui_locales".to_owned(), "en-CA".to_owned()),
                    ("client.name".to_owned(), "orders".to_owned()),
                ]),
            },
            credentials: OidcCredentialsConfig {
                secret: Some("orders-secret".to_owned()),
                client_secret: OidcClientSecretConfig {
                    value: None,
                    method: ClientSecretMethod::Post,
                },
            },
            introspection_credentials: OidcIntrospectionCredentialsConfig {
                name: Some("introspect".to_owned()),
                secret: Some("introspect-secret".to_owned()),
                include_client_id: false,
            },
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                token_type: Some("bearer".to_owned()),
                signature_algorithm: Some(TokenSignatureAlgorithm::Rs256),
                decryption_key_location: Some("/etc/oidc/decryption.pem".to_owned()),
                decrypt_id_token: Some(false),
                decrypt_access_token: false,
                subject_required: true,
                issued_at_required: false,
                required_claims: HashMap::from([
                    ("org_id".to_owned(), vec!["org_xyz".to_owned()]),
                    (
                        "scope".to_owned(),
                        vec!["read".to_owned(), "write".to_owned()],
                    ),
                    (
                        "resource_access.orders.roles".to_owned(),
                        vec!["orders-admin".to_owned()],
                    ),
                ]),
                principal_claim: Some("email".to_owned()),
                header: "x-access-token".to_owned(),
                authorization_scheme: "Token".to_owned(),
                lifespan_grace: Some(5),
                age: Some(Duration::from_secs(60)),
                refresh_expired: true,
                refresh_token_time_skew: Some(Duration::from_secs(15)),
                forced_jwk_refresh_interval: Duration::from_secs(30),
                allow_jwt_introspection: false,
                require_jwt_introspection_only: true,
                allow_opaque_token_introspection: false,
                verify_access_token_with_user_info: true,
                binding: OidcTokenBindingConfig { certificate: true },
            },
            roles: OidcRolesConfig {
                source: RolesSource::UserInfo,
                role_claim_path: "resource_access.api.roles".to_owned(),
                role_claim_separator: "|".to_owned(),
            },
        }
    );
}

#[test]
fn config_rejects_unknown_roles_source() {
    let config = Config::builder()
        .add_source(MapSource::new("test", 100).with("oidc.roles.source", "session"))
        .build();

    let error = OidcConfig::from_config(&config).expect_err("roles source should be rejected");

    assert!(
        error
            .to_string()
            .contains("expected one of `accesstoken`, `idtoken`, or `userinfo`"),
        "{error}"
    );
}

#[test]
fn config_rejects_empty_role_claim_path() {
    let config = Config::builder()
        .add_source(
            MapSource::new("empty-role-claim-path", 100).with("oidc.roles.role-claim-path", " , "),
        )
        .build();

    let error =
        OidcConfig::from_config(&config).expect_err("empty role claim path should be rejected");

    assert!(
        error.to_string().contains("oidc.roles.role-claim-path"),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .contains("role-claim-path must include at least one claim path"),
        "{error}"
    );
}

#[test]
fn config_rejects_malformed_role_claim_path() {
    for path in ["resource_access..roles", "resource_access.\"roles"] {
        let config = Config::builder()
            .add_source(
                MapSource::new("malformed-role-claim-path", 100)
                    .with("oidc.roles.role-claim-path", path),
            )
            .build();

        let error =
            OidcConfig::from_config(&config).expect_err("malformed role claim path should fail");

        assert!(
            error.to_string().contains("oidc.roles.role-claim-path"),
            "{error}"
        );
    }
}

#[test]
fn config_rejects_invalid_logout_path() {
    let config = Config::builder()
        .add_source(MapSource::new("invalid-logout-path", 100).with("oidc.logout.path", "logout"))
        .build();

    let error = OidcConfig::from_config(&config).expect_err("logout path should be rejected");

    assert!(error.to_string().contains("logout path"), "{error}");
}

#[test]
fn config_rejects_invalid_post_logout_path() {
    let config = Config::builder()
        .add_source(
            MapSource::new("invalid-post-logout-path", 100)
                .with("oidc.logout.post-logout-path", "signed-out"),
        )
        .build();

    let error = OidcConfig::from_config(&config).expect_err("post logout path should be rejected");

    assert!(error.to_string().contains("post-logout-path"), "{error}");
}

#[test]
fn config_loads_id_token_roles_source() {
    let config = Config::builder()
        .add_source(MapSource::new("test", 100).with("oidc.roles.source", "idtoken"))
        .build();

    let oidc = OidcConfig::from_config(&config).expect("config should load");

    assert_eq!(oidc.roles.source, RolesSource::IdToken);
}

#[test]
fn config_defaults_token_binding_certificate_to_false() {
    let config = Config::builder()
        .add_source(MapSource::new("test", 100))
        .build();

    let oidc = OidcConfig::from_config(&config).expect("config should load");

    assert!(!oidc.token.binding.certificate);
}

#[test]
fn config_rejects_unknown_provider() {
    let config = Config::builder()
        .add_source(MapSource::new("test", 100).with("oidc.provider", "custom"))
        .build();

    let error = OidcConfig::from_config(&config).expect_err("provider should be rejected");

    assert!(
        error
            .to_string()
            .contains("expected one of `apple`, `discord`, `facebook`"),
        "{error}"
    );
}

#[test]
fn config_loads_client_secret_value() {
    let config = Config::builder()
        .add_source(
            MapSource::new("test", 100)
                .with("oidc.credentials.client-secret.value", "orders-secret"),
        )
        .build();

    let oidc = OidcConfig::from_config(&config).expect("config should load");

    assert_eq!(
        oidc.credentials.effective_client_secret(),
        Some("orders-secret")
    );
}

#[test]
fn config_prefers_credentials_secret_over_client_secret_value() {
    let config = Config::builder()
        .add_source(
            MapSource::new("test", 100)
                .with("oidc.credentials.secret", "primary-secret")
                .with("oidc.credentials.client-secret.value", "fallback-secret"),
        )
        .build();

    let oidc = OidcConfig::from_config(&config).expect("config should load");

    assert_eq!(
        oidc.credentials.effective_client_secret(),
        Some("primary-secret")
    );
}

#[test]
fn config_rejects_empty_credentials_secret() {
    let config = Config::builder()
        .add_source(
            MapSource::new("empty-credentials-secret", 100).with("oidc.credentials.secret", " "),
        )
        .build();

    let error =
        OidcConfig::from_config(&config).expect_err("empty credentials secret should be rejected");

    assert!(
        error.to_string().contains("oidc.credentials.secret"),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .contains("value must not be empty when configured"),
        "{error}"
    );
}

#[test]
fn config_rejects_empty_client_secret_value() {
    let config = Config::builder()
        .add_source(
            MapSource::new("empty-client-secret-value", 100)
                .with("oidc.credentials.client-secret.value", " "),
        )
        .build();

    let error =
        OidcConfig::from_config(&config).expect_err("empty client secret value should be rejected");

    assert!(
        error
            .to_string()
            .contains("oidc.credentials.client-secret.value"),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .contains("value must not be empty when configured"),
        "{error}"
    );
}

#[test]
fn config_loads_introspection_credentials() {
    let config = Config::builder()
        .add_source(
            MapSource::new("test", 100)
                .with("oidc.introspection-credentials.name", "introspect")
                .with("oidc.introspection-credentials.secret", "introspect-secret")
                .with("oidc.introspection-credentials.include-client-id", "false"),
        )
        .build();

    let oidc = OidcConfig::from_config(&config).expect("config should load");

    assert_eq!(
        oidc.introspection_credentials,
        OidcIntrospectionCredentialsConfig {
            name: Some("introspect".to_owned()),
            secret: Some("introspect-secret".to_owned()),
            include_client_id: false,
        }
    );
}

#[test]
fn config_rejects_empty_introspection_credentials_name() {
    let config = Config::builder()
        .add_source(
            MapSource::new("empty-introspection-name", 100)
                .with("oidc.introspection-credentials.name", " "),
        )
        .build();

    let error = OidcConfig::from_config(&config)
        .expect_err("empty introspection credentials name should be rejected");

    assert!(
        error
            .to_string()
            .contains("oidc.introspection-credentials.name"),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .contains("value must not be empty when configured"),
        "{error}"
    );
}

#[test]
fn config_rejects_empty_introspection_credentials_secret() {
    let config = Config::builder()
        .add_source(
            MapSource::new("empty-introspection-secret", 100)
                .with("oidc.introspection-credentials.secret", " "),
        )
        .build();

    let error = OidcConfig::from_config(&config)
        .expect_err("empty introspection credentials secret should be rejected");

    assert!(
        error
            .to_string()
            .contains("oidc.introspection-credentials.secret"),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .contains("value must not be empty when configured"),
        "{error}"
    );
}

#[test]
fn config_loads_query_client_secret_method() {
    let config = Config::builder()
        .add_source(
            MapSource::new("test", 100).with("oidc.credentials.client-secret.method", "query"),
        )
        .build();

    let oidc = OidcConfig::from_config(&config).expect("config should load");

    assert_eq!(
        oidc.credentials.client_secret.method,
        ClientSecretMethod::Query
    );
}

#[test]
fn config_rejects_unknown_client_secret_method() {
    let config = Config::builder()
        .add_source(
            MapSource::new("test", 100).with("oidc.credentials.client-secret.method", "post-jwt"),
        )
        .build();

    let error =
        OidcConfig::from_config(&config).expect_err("client secret method should be rejected");

    assert!(
        error
            .to_string()
            .contains("expected one of `basic`, `post`, or `query`"),
        "{error}"
    );
}

#[test]
fn config_loads_application_type_case_insensitively() {
    let config = Config::builder()
        .add_source(MapSource::new("test", 100).with("oidc.application-type", "WEB-APP"))
        .build();

    let oidc = OidcConfig::from_config(&config).expect("config should load");

    assert_eq!(oidc.application_type, ApplicationType::WebApp);
}

#[test]
fn config_loads_hybrid_application_type() {
    let config = Config::builder()
        .add_source(MapSource::new("test", 100).with("oidc.application-type", "hybrid"))
        .build();

    let oidc = OidcConfig::from_config(&config).expect("config should load");

    assert_eq!(oidc.application_type, ApplicationType::Hybrid);
}

#[test]
fn config_rejects_invalid_token_header() {
    let config = Config::builder()
        .add_source(MapSource::new("test", 100).with("oidc.token.header", "not a header"))
        .build();

    let error = match OidcConfig::from_config(&config) {
        Err(error) => error,
        Ok(_) => panic!("token header should be rejected"),
    };

    assert!(error.to_string().contains("oidc.token.header"), "{error}");
}

#[test]
fn config_loads_valid_authorization_scheme() {
    let config = Config::builder()
        .add_source(MapSource::new("test", 100).with("oidc.token.authorization-scheme", "DPoP"))
        .build();

    let oidc = OidcConfig::from_config(&config).expect("config should load");

    assert_eq!(oidc.token.authorization_scheme, "DPoP");
}

#[test]
fn config_defaults_token_header_to_authorization() {
    let config = Config::builder()
        .add_source(MapSource::new("test", 100))
        .build();

    let oidc = OidcConfig::from_config(&config).expect("config should load");

    assert_eq!(oidc.token.header, "Authorization");
}

#[test]
fn config_rejects_invalid_authorization_scheme() {
    for scheme in ["Bearer Token", "Bearer/Token"] {
        let config = Config::builder()
            .add_source(MapSource::new("test", 100).with("oidc.token.authorization-scheme", scheme))
            .build();

        let error =
            OidcConfig::from_config(&config).expect_err("authorization scheme should be rejected");

        assert!(
            error
                .to_string()
                .contains("oidc.token.authorization-scheme"),
            "{error}"
        );
        assert!(
            error
                .to_string()
                .contains("authorization scheme must be a non-empty HTTP token"),
            "{error}"
        );
    }
}

#[test]
fn id_token_claims_parse_standard_and_extra_claims() {
    let claims = IdTokenClaims::from_json(
        r#"{
            "sub": "alice",
            "iss": "https://issuer.example/realms/app",
            "aud": ["client-a", "client-b"],
            "exp": 4102444800,
            "iat": 1700000000,
            "auth_time": 1699999999,
            "nonce": "nonce-123",
            "azp": "client-a",
            "email": "alice@example.com",
            "email_verified": true,
            "tenant": "north"
        }"#,
    )
    .expect("ID token claims should parse");

    let token = IdToken::with_raw(claims, "raw-token");

    assert_eq!(token.subject(), Some("alice"));
    assert_eq!(token.issuer(), Some("https://issuer.example/realms/app"));
    assert_eq!(
        token.audience().collect::<Vec<_>>(),
        ["client-a", "client-b"]
    );
    assert_eq!(token.expires_at(), Some(4_102_444_800));
    assert_eq!(token.issued_at(), Some(1_700_000_000));
    assert_eq!(token.nonce(), Some("nonce-123"));
    assert_eq!(token.authorized_party(), Some("client-a"));
    assert_eq!(token.email(), Some("alice@example.com"));
    assert_eq!(token.email_verified(), Some(true));
    assert_eq!(
        token.claim("tenant").and_then(serde_json::Value::as_str),
        Some("north")
    );
    assert_eq!(token.raw(), Some("raw-token"));
}

#[test]
fn id_token_claims_parse_string_audience() {
    let claims = IdTokenClaims::from_json(r#"{"sub":"alice","aud":"client-a"}"#)
        .expect("ID token claims should parse");

    let token = IdToken::new(claims);

    assert_eq!(token.audience().collect::<Vec<_>>(), ["client-a"]);
    assert_eq!(token.raw(), None);
}

#[tokio::test]
async fn disabled_oidc_allows_request_without_bearer_token() {
    let response = public_app(
        Oidc::builder(OidcConfig {
            enabled: false,
            ..OidcConfig::default()
        })
        .build(),
    )
    .oneshot(request("/protected", None))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn missing_bearer_token_is_challenged() {
    let response = app(oidc())
        .oneshot(request("/protected", None))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(WWW_AUTHENTICATE).unwrap(),
        HeaderValue::from_static("Bearer")
    );
}

#[tokio::test]
async fn invalid_bearer_token_is_challenged() {
    let response = app(oidc())
        .oneshot(request("/protected", Some("Bearer wrong-token")))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(WWW_AUTHENTICATE).unwrap(),
        HeaderValue::from_static(r#"Bearer error="invalid_token""#)
    );
}

#[tokio::test]
async fn oversized_authorization_header_is_rejected_before_validation() {
    let mut token = String::with_capacity(crate::token::MAX_TOKEN_BYTES + 1);
    token.extend(std::iter::repeat_n('a', crate::token::MAX_TOKEN_BYTES + 1));
    let authorization = format!("Bearer {token}");

    let response = app(oidc())
        .oneshot(request("/protected", Some(&authorization)))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(WWW_AUTHENTICATE).unwrap(),
        HeaderValue::from_static(r#"Bearer error="invalid_request""#)
    );
}

#[tokio::test]
async fn bearer_token_with_embedded_whitespace_is_rejected() {
    let response = app(oidc())
        .oneshot(request("/protected", Some("Bearer test-token extra")))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(WWW_AUTHENTICATE).unwrap(),
        HeaderValue::from_static(r#"Bearer error="invalid_request""#)
    );
}

#[tokio::test]
async fn configured_authorization_scheme_is_accepted() {
    let response = app(Oidc::builder(OidcConfig {
        token: OidcTokenConfig {
            authorization_scheme: "Token".to_owned(),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    })
    .validator(StaticTokenValidator::bearer("test-token", "alice"))
    .build())
    .oneshot(request("/protected", Some("Token test-token")))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn default_authorization_scheme_is_case_insensitive() {
    let response = app(oidc())
        .oneshot(request("/protected", Some("bearer test-token")))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn configured_authorization_scheme_is_case_insensitive() {
    let response = app(Oidc::builder(OidcConfig {
        token: OidcTokenConfig {
            authorization_scheme: "Token".to_owned(),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    })
    .validator(StaticTokenValidator::bearer("test-token", "alice"))
    .build())
    .oneshot(request("/protected", Some("token test-token")))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn configured_authorization_scheme_is_used_in_missing_token_challenge() {
    let response = app(Oidc::builder(OidcConfig {
        token: OidcTokenConfig {
            authorization_scheme: "Token".to_owned(),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    })
    .validator(StaticTokenValidator::bearer("test-token", "alice"))
    .build())
    .oneshot(request("/protected", None))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(WWW_AUTHENTICATE).unwrap(),
        HeaderValue::from_static("Token")
    );
}

#[tokio::test]
async fn configured_authorization_scheme_is_used_in_invalid_token_challenge() {
    let response = app(Oidc::builder(OidcConfig {
        token: OidcTokenConfig {
            authorization_scheme: "Token".to_owned(),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    })
    .validator(StaticTokenValidator::bearer("test-token", "alice"))
    .build())
    .oneshot(request("/protected", Some("Token wrong-token")))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(WWW_AUTHENTICATE).unwrap(),
        HeaderValue::from_static(r#"Token error="invalid_token""#)
    );
}

#[tokio::test]
async fn configured_authorization_scheme_rejects_default_scheme() {
    let response = app(Oidc::builder(OidcConfig {
        token: OidcTokenConfig {
            authorization_scheme: "Token".to_owned(),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    })
    .validator(StaticTokenValidator::bearer("test-token", "alice"))
    .build())
    .oneshot(request("/protected", Some("Bearer test-token")))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn configured_token_header_is_accepted() {
    let response = app(Oidc::builder(OidcConfig {
        token: OidcTokenConfig {
            header: "x-access-token".to_owned(),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    })
    .validator(StaticTokenValidator::bearer("test-token", "alice"))
    .build())
    .oneshot(request_with_header(
        "/protected",
        "x-access-token",
        "test-token",
    ))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn configured_authorization_token_header_uses_scheme() {
    let response = app(Oidc::builder(OidcConfig {
        token: OidcTokenConfig {
            header: "Authorization".to_owned(),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    })
    .validator(StaticTokenValidator::bearer("test-token", "alice"))
    .build())
    .oneshot(request("/protected", Some("Bearer test-token")))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn configured_authorization_token_header_respects_custom_scheme() {
    let response = app(Oidc::builder(OidcConfig {
        token: OidcTokenConfig {
            header: "Authorization".to_owned(),
            authorization_scheme: "Token".to_owned(),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    })
    .validator(StaticTokenValidator::bearer("test-token", "alice"))
    .build())
    .oneshot(request("/protected", Some("Token test-token")))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn valid_bearer_token_adds_principal_extension() {
    let response = app(oidc())
        .oneshot(request("/protected", Some("Bearer test-token")))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn oidc_session_extractor_reads_authenticated_principal() {
    let app = Router::new()
        .route(
            "/session",
            get(|session: OidcSession| async move { session.principal().subject().to_owned() }),
        )
        .layer(oidc().layer());

    let response = app
        .oneshot(request("/session", Some("Bearer test-token")))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_body(response).await, "alice");
}

#[tokio::test]
async fn oidc_session_extractor_rejects_missing_principal() {
    let app = Router::new().route(
        "/session",
        get(|session: OidcSession| async move { session.principal().subject().to_owned() }),
    );

    let response = app
        .oneshot(request("/session", None))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn tenant_disabled_returns_not_found() {
    let response = app(Oidc::builder(OidcConfig {
        tenant_enabled: false,
        ..OidcConfig::default()
    })
    .validator(StaticTokenValidator::bearer("test-token", "alice"))
    .build())
    .oneshot(request("/protected", Some("Bearer test-token")))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn jwt_validator_accepts_signed_token_and_extracts_claims() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            token_type: None,
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(TestClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        groups: vec!["admin"],
        realm_access: RealmAccessClaims {
            roles: vec!["user"],
        },
    });

    let response = claims_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build(),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn introspection_validator_accepts_active_token_and_extracts_roles() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        client_id: Some("orders-service".to_owned()),
        token: OidcTokenConfig {
            audience: Some("orders-api".to_owned()),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let validator = IntrospectionValidator::new(
        |token: Arc<str>| async move {
            assert_eq!(token.as_ref(), "opaque-token");
            Ok(IntrospectionResponse::from_json(
                r#"{
                        "active": true,
                        "sub": "alice",
                        "iss": "https://issuer.example/realms/app",
                        "aud": ["orders-api"],
                        "iat": 1700000000,
                        "groups": ["orders-user"],
                        "realm_access": {
                            "roles": ["realm-admin"]
                        },
                        "resource_access": {
                            "orders-service": {
                                "roles": ["orders-admin"]
                            }
                        }
                    }"#,
            )
            .expect("introspection response should parse"))
        },
        &config,
    );

    let principal = validator
        .validate(Arc::from("opaque-token"))
        .await
        .expect("active token should validate");

    assert_eq!(principal.subject(), "alice");
    assert_eq!(
        principal.issuer(),
        Some("https://issuer.example/realms/app")
    );
    assert_eq!(principal.audience().collect::<Vec<_>>(), vec!["orders-api"]);
    assert_eq!(
        principal.groups().collect::<Vec<_>>(),
        vec!["orders-user", "realm-admin", "orders-admin"]
    );
}

#[tokio::test]
async fn introspection_validator_rejects_inactive_token() {
    let validator = IntrospectionValidator::new(
        |_token: Arc<str>| async move { Ok(IntrospectionResponse::default()) },
        &OidcConfig::default(),
    );

    let error = validator
        .validate(Arc::from("opaque-token"))
        .await
        .expect_err("inactive token should be rejected");

    assert!(
        error.to_string().contains("introspection is not active"),
        "{error}"
    );
}

#[tokio::test]
async fn introspection_validator_applies_configured_audience() {
    let config = OidcConfig {
        token: OidcTokenConfig {
            audience: Some("orders-api".to_owned()),
            issued_at_required: false,
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let validator = IntrospectionValidator::new(
        |_token: Arc<str>| async move {
            Ok(IntrospectionResponse::from_json(
                r#"{
                        "active": true,
                        "sub": "alice",
                        "aud": "inventory-api"
                    }"#,
            )
            .expect("introspection response should parse"))
        },
        &config,
    );

    let error = validator
        .validate(Arc::from("opaque-token"))
        .await
        .expect_err("wrong audience should be rejected");

    assert!(
        error
            .to_string()
            .contains("introspection audience did not include"),
        "{error}"
    );
}

#[test]
fn introspection_request_uses_basic_auth_when_client_secret_is_configured() {
    let request = introspection_request(
        &reqwest::Client::new(),
        "https://issuer.example/realms/app/protocol/openid-connect/token/introspect",
        "opaque-token",
        IntrospectionRequestAuth {
            client_id: Some("orders-service"),
            client_auth_name: Some("orders-service"),
            client_secret: Some("orders-secret"),
            client_secret_method: ClientSecretMethod::Basic,
            include_client_id: false,
        },
    )
    .build()
    .expect("request should build");

    assert_eq!(
        request.headers().get(AUTHORIZATION),
        Some(&HeaderValue::from_static(
            "Basic b3JkZXJzLXNlcnZpY2U6b3JkZXJzLXNlY3JldA=="
        ))
    );
}

#[test]
fn introspection_request_can_include_client_id_with_basic_auth() {
    let request = introspection_request(
        &reqwest::Client::new(),
        "https://issuer.example/realms/app/protocol/openid-connect/token/introspect",
        "opaque-token",
        IntrospectionRequestAuth {
            client_id: Some("orders-service"),
            client_auth_name: Some("introspect"),
            client_secret: Some("introspect-secret"),
            client_secret_method: ClientSecretMethod::Basic,
            include_client_id: true,
        },
    )
    .build()
    .expect("request should build");
    let body = request
        .body()
        .and_then(reqwest::Body::as_bytes)
        .and_then(|body| std::str::from_utf8(body).ok())
        .expect("request body should be buffered form data");

    assert_eq!(
        request.headers().get(AUTHORIZATION),
        Some(&HeaderValue::from_static(
            "Basic aW50cm9zcGVjdDppbnRyb3NwZWN0LXNlY3JldA=="
        ))
    );
    assert!(body.contains("token=opaque-token"), "{body}");
    assert!(body.contains("client_id=orders-service"), "{body}");
}

#[test]
fn introspection_request_posts_client_secret_when_configured() {
    let request = introspection_request(
        &reqwest::Client::new(),
        "https://issuer.example/realms/app/protocol/openid-connect/token/introspect",
        "opaque-token",
        IntrospectionRequestAuth {
            client_id: Some("orders-service"),
            client_auth_name: Some("orders-service"),
            client_secret: Some("orders-secret"),
            client_secret_method: ClientSecretMethod::Post,
            include_client_id: false,
        },
    )
    .build()
    .expect("request should build");
    let body = request
        .body()
        .and_then(reqwest::Body::as_bytes)
        .and_then(|body| std::str::from_utf8(body).ok())
        .expect("request body should be buffered form data");

    assert!(!request.headers().contains_key(AUTHORIZATION));
    assert!(body.contains("token=opaque-token"), "{body}");
    assert!(body.contains("client_id=orders-service"), "{body}");
    assert!(body.contains("client_secret=orders-secret"), "{body}");
}

#[test]
fn introspection_request_uses_query_client_secret_when_configured() {
    let request = introspection_request(
        &reqwest::Client::new(),
        "https://issuer.example/realms/app/protocol/openid-connect/token/introspect",
        "opaque-token",
        IntrospectionRequestAuth {
            client_id: Some("orders-service"),
            client_auth_name: Some("orders-service"),
            client_secret: Some("orders-secret"),
            client_secret_method: ClientSecretMethod::Query,
            include_client_id: false,
        },
    )
    .build()
    .expect("request should build");
    let body = request
        .body()
        .and_then(reqwest::Body::as_bytes)
        .and_then(|body| std::str::from_utf8(body).ok())
        .expect("request body should be buffered form data");
    let query = request.url().query().expect("query should be present");

    assert!(!request.headers().contains_key(AUTHORIZATION));
    assert!(body.contains("token=opaque-token"), "{body}");
    assert!(!body.contains("client_id="), "{body}");
    assert!(!body.contains("client_secret="), "{body}");
    assert!(query.contains("client_id=orders-service"), "{query}");
    assert!(query.contains("client_secret=orders-secret"), "{query}");
}

#[test]
fn introspection_request_skips_basic_auth_without_client_secret() {
    let request = introspection_request(
        &reqwest::Client::new(),
        "https://issuer.example/realms/app/protocol/openid-connect/token/introspect",
        "opaque-token",
        IntrospectionRequestAuth {
            client_id: Some("orders-service"),
            client_auth_name: Some("orders-service"),
            client_secret: None,
            client_secret_method: ClientSecretMethod::Basic,
            include_client_id: false,
        },
    )
    .build()
    .expect("request should build");

    assert!(!request.headers().contains_key(AUTHORIZATION));
}

#[test]
fn http_introspector_uses_client_secret_value() {
    let config = OidcConfig {
        client_id: Some("orders-service".to_owned()),
        credentials: OidcCredentialsConfig {
            client_secret: OidcClientSecretConfig {
                value: Some("orders-secret".to_owned()),
                ..OidcClientSecretConfig::default()
            },
            ..OidcCredentialsConfig::default()
        },
        ..OidcConfig::default()
    };
    let introspector = http_token_introspector(
        &config,
        reqwest::Client::new(),
        "https://issuer.example/realms/app/protocol/openid-connect/token/introspect".to_owned(),
    );

    assert_eq!(introspector.client_secret.as_deref(), Some("orders-secret"));
}

#[test]
fn http_introspector_uses_introspection_credentials() {
    let config = OidcConfig {
        client_id: Some("orders-service".to_owned()),
        credentials: OidcCredentialsConfig {
            secret: Some("orders-secret".to_owned()),
            client_secret: OidcClientSecretConfig {
                method: ClientSecretMethod::Query,
                ..OidcClientSecretConfig::default()
            },
        },
        introspection_credentials: OidcIntrospectionCredentialsConfig {
            name: Some("introspect".to_owned()),
            secret: Some("introspect-secret".to_owned()),
            include_client_id: true,
        },
        ..OidcConfig::default()
    };
    let introspector = http_token_introspector(
        &config,
        reqwest::Client::new(),
        "https://issuer.example/realms/app/protocol/openid-connect/token/introspect".to_owned(),
    );

    assert_eq!(introspector.client_auth_name.as_deref(), Some("introspect"));
    assert_eq!(
        introspector.client_secret.as_deref(),
        Some("introspect-secret")
    );
    assert_eq!(introspector.client_secret_method, ClientSecretMethod::Basic);
    assert!(introspector.include_client_id);
}

#[tokio::test]
async fn introspection_fallback_uses_primary_jwt_validator_first() {
    let validator = IntrospectionFallbackValidator::new(
        StaticTokenValidator::bearer("jwt-token", "alice"),
        StaticTokenValidator::bearer("opaque-token", "bob"),
        &OidcConfig::default(),
    );

    let principal = validator
        .validate(Arc::from("jwt-token"))
        .await
        .expect("primary validator should accept token");

    assert_eq!(principal.subject(), "alice");
}

#[tokio::test]
async fn introspection_fallback_accepts_opaque_token_when_enabled() {
    let validator = IntrospectionFallbackValidator::new(
        StaticTokenValidator::bearer("jwt-token", "alice"),
        StaticTokenValidator::bearer("opaque-token", "bob"),
        &OidcConfig::default(),
    );

    let principal = validator
        .validate(Arc::from("opaque-token"))
        .await
        .expect("opaque token should fall back to introspection");

    assert_eq!(principal.subject(), "bob");
}

#[tokio::test]
async fn introspection_fallback_rejects_opaque_token_when_disabled() {
    let config = OidcConfig {
        token: OidcTokenConfig {
            allow_opaque_token_introspection: false,
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let validator = IntrospectionFallbackValidator::new(
        StaticTokenValidator::bearer("jwt-token", "alice"),
        StaticTokenValidator::bearer("opaque-token", "bob"),
        &config,
    );

    let error = validator
        .validate(Arc::from("opaque-token"))
        .await
        .expect_err("opaque fallback should be disabled");

    assert!(error.to_string().contains("bearer token did not match"));
}

#[tokio::test]
async fn introspection_fallback_rejects_jwt_token_when_jwt_introspection_disabled() {
    let config = OidcConfig {
        token: OidcTokenConfig {
            allow_jwt_introspection: false,
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let validator = IntrospectionFallbackValidator::new(
        StaticTokenValidator::bearer("jwt-token", "alice"),
        StaticTokenValidator::bearer("a.b.c", "bob"),
        &config,
    );

    let error = validator
        .validate(Arc::from("a.b.c"))
        .await
        .expect_err("JWT fallback should be disabled");

    assert!(error.to_string().contains("bearer token did not match"));
}

#[tokio::test]
async fn user_info_validator_accepts_response_and_extracts_roles() {
    let config = OidcConfig {
        client_id: Some("orders-service".to_owned()),
        token: OidcTokenConfig {
            principal_claim: Some("preferred_username".to_owned()),
            ..OidcTokenConfig::default()
        },
        roles: OidcRolesConfig {
            source: RolesSource::UserInfo,
            ..OidcRolesConfig::default()
        },
        ..OidcConfig::default()
    };
    let validator = UserInfoValidator::new(
        |token: Arc<str>| async move {
            assert_eq!(token.as_ref(), "opaque-token");
            Ok(UserInfoResponse::from_json(
                r#"{
                        "sub": "alice-subject",
                        "preferred_username": "alice",
                        "groups": ["orders-user"],
                        "realm_access": {
                            "roles": ["realm-admin"]
                        },
                        "resource_access": {
                            "orders-service": {
                                "roles": ["orders-admin"]
                            }
                        }
                    }"#,
            )
            .expect("UserInfo response should parse"))
        },
        &config,
    );

    let principal = validator
        .validate(Arc::from("opaque-token"))
        .await
        .expect("UserInfo response should validate");

    assert_eq!(principal.subject(), "alice");
    assert_eq!(
        principal.groups().collect::<Vec<_>>(),
        vec!["orders-user", "realm-admin", "orders-admin"]
    );
}

#[tokio::test]
async fn user_info_validator_skips_roles_when_source_is_access_token() {
    let validator = UserInfoValidator::new(
        |_token: Arc<str>| async move {
            Ok(UserInfoResponse::from_json(
                r#"{
                        "sub": "alice",
                        "groups": ["orders-admin"]
                    }"#,
            )
            .expect("UserInfo response should parse"))
        },
        &OidcConfig::default(),
    );

    let principal = validator
        .validate(Arc::from("opaque-token"))
        .await
        .expect("UserInfo response should validate");

    assert_eq!(principal.groups().collect::<Vec<_>>(), Vec::<&str>::new());
}

#[tokio::test]
async fn user_info_validator_applies_required_claims() {
    let config = OidcConfig {
        token: OidcTokenConfig {
            required_claims: HashMap::from([("scope".to_owned(), vec!["orders:read".to_owned()])]),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let validator = UserInfoValidator::new(
        |_token: Arc<str>| async move {
            Ok(UserInfoResponse::from_json(
                r#"{
                        "sub": "alice",
                        "scope": "orders:write"
                    }"#,
            )
            .expect("UserInfo response should parse"))
        },
        &config,
    );

    let error = validator
        .validate(Arc::from("opaque-token"))
        .await
        .expect_err("missing required claim should be rejected");

    assert!(
        error
            .to_string()
            .contains("claim `scope` did not include required value"),
        "{error}"
    );
}

#[tokio::test]
async fn user_info_roles_validator_preserves_jwt_validation() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            token_type: None,
            ..OidcTokenConfig::default()
        },
        roles: OidcRolesConfig {
            source: RolesSource::UserInfo,
            ..OidcRolesConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(TestClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        groups: vec!["token-role"],
        realm_access: RealmAccessClaims { roles: Vec::new() },
    });
    let validator = UserInfoRolesValidator::new(
        JwtValidator::hs256("secret", &config),
        |_token: Arc<str>| async move {
            Ok(UserInfoResponse::from_json(
                r#"{
                        "sub": "alice",
                        "groups": ["orders-admin", "orders-user"]
                    }"#,
            )
            .expect("UserInfo response should parse"))
        },
        &config,
    );

    let principal = validator
        .validate(Arc::from(token))
        .await
        .expect("JWT and UserInfo roles should validate");

    assert_eq!(principal.subject(), "alice");
    assert_eq!(
        principal.groups().collect::<Vec<_>>(),
        vec!["orders-admin", "orders-user"]
    );
}

#[tokio::test]
async fn user_info_roles_validator_rejects_subject_mismatch() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            token_type: None,
            ..OidcTokenConfig::default()
        },
        roles: OidcRolesConfig {
            source: RolesSource::UserInfo,
            ..OidcRolesConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(TestClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        groups: Vec::new(),
        realm_access: RealmAccessClaims { roles: Vec::new() },
    });
    let validator = UserInfoRolesValidator::new(
        JwtValidator::hs256("secret", &config),
        |_token: Arc<str>| async move {
            Ok(UserInfoResponse::from_json(
                r#"{
                        "sub": "bob",
                        "groups": ["orders-admin"]
                    }"#,
            )
            .expect("UserInfo response should parse"))
        },
        &config,
    );

    let error = validator
        .validate(Arc::from(token))
        .await
        .expect_err("UserInfo subject mismatch should be rejected");

    assert!(
        error
            .to_string()
            .contains("UserInfo subject did not match access token subject"),
        "{error}"
    );
}

#[tokio::test]
async fn oidc_from_config_uses_public_key_for_local_jwt_verification() {
    let config = Config::builder()
        .add_source(
            MapSource::new("public-key", 100)
                .with("oidc.public-key", PUBLIC_RSA_KEY)
                .with("oidc.auth-server-url", "https://issuer.example/realms/app")
                .with("oidc.token.audience", "orders-api"),
        )
        .build();
    let token = jwt_rs256(TestClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        groups: vec!["admin"],
        realm_access: RealmAccessClaims {
            roles: vec!["user"],
        },
    });

    let response = claims_app(
        Oidc::from_config(&config)
            .expect("public key config should load")
            .build(),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn oidc_discover_from_config_builds_public_key_validator() {
    let config = Config::builder()
        .add_source(
            MapSource::new("public-key-discovery", 100)
                .with("oidc.public-key", PUBLIC_RSA_KEY)
                .with("oidc.auth-server-url", "https://issuer.example/realms/app")
                .with("oidc.token.audience", "orders-api"),
        )
        .build();
    let token = jwt_rs256(TestClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        groups: vec!["admin"],
        realm_access: RealmAccessClaims {
            roles: vec!["user"],
        },
    });

    let response = claims_app(
        Oidc::discover_from_config(&config)
            .await
            .expect("public key config should build without provider discovery"),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn oidc_discover_from_config_requires_auth_server_url_for_provider_discovery() {
    let config = Config::builder()
        .add_source(MapSource::new("provider-discovery", 100))
        .build();

    let error = match Oidc::discover_from_config(&config).await {
        Ok(_) => panic!("provider discovery should require an auth-server-url"),
        Err(error) => error,
    };

    assert!(matches!(error, BuildError::MissingAuthServerUrl));
}

#[test]
fn oidc_from_config_rejects_invalid_public_key() {
    let config = Config::builder()
        .add_source(
            MapSource::new("public-key", 100).with("oidc.public-key", "not a pem public key"),
        )
        .build();

    let Err(error) = Oidc::from_config(&config) else {
        panic!("invalid public key should fail");
    };
    assert!(matches!(
        error,
        mp_config::ConfigError::Conversion { name, .. }
            if name == "oidc.public-key"
    ));
}

#[test]
fn oidc_from_config_ignores_public_key_when_disabled() {
    let config = Config::builder()
        .add_source(
            MapSource::new("disabled-public-key", 100)
                .with("oidc.enabled", "false")
                .with("oidc.public-key", "not a pem public key"),
        )
        .build();

    let _builder = Oidc::from_config(&config).expect("disabled OIDC should not parse key");
}

#[test]
fn oidc_from_config_rejects_id_token_roles_source() {
    let config = Config::builder()
        .add_source(
            MapSource::new("idtoken-roles", 100)
                .with("oidc.public-key", PUBLIC_RSA_KEY)
                .with("oidc.roles.source", "idtoken"),
        )
        .build();

    let Err(error) = Oidc::from_config(&config) else {
        panic!("ID token roles should be rejected for bearer-service middleware");
    };
    assert!(matches!(
        error,
        mp_config::ConfigError::Conversion { ref name, .. }
            if name == "oidc.roles.source"
    ));
    assert!(
        error
            .to_string()
            .contains("`idtoken` roles require the `web-app` application type"),
        "{error}"
    );
}

#[test]
fn oidc_from_config_rejects_refresh_expired_for_service() {
    let config = Config::builder()
        .add_source(
            MapSource::new("refresh-expired", 100).with("oidc.token.refresh-expired", "true"),
        )
        .build();

    let Err(error) = Oidc::from_config(&config) else {
        panic!("refresh-expired should be rejected for bearer-service middleware");
    };
    assert!(matches!(
        error,
        mp_config::ConfigError::Conversion { ref name, .. }
            if name == "oidc.token.refresh-expired"
    ));
    assert!(
        error
            .to_string()
            .contains("`token.refresh-expired` requires the `web-app` application type"),
        "{error}"
    );
}

#[test]
fn oidc_from_config_rejects_refresh_token_time_skew_for_service() {
    let config = Config::builder()
        .add_source(
            MapSource::new("refresh-token-time-skew", 100)
                .with("oidc.token.refresh-token-time-skew", "15s"),
        )
        .build();

    let Err(error) = Oidc::from_config(&config) else {
        panic!("refresh-token-time-skew should be rejected for bearer-service middleware");
    };
    assert!(matches!(
        error,
        mp_config::ConfigError::Conversion { ref name, .. }
            if name == "oidc.token.refresh-token-time-skew"
    ));
    assert!(
        error
            .to_string()
            .contains("`token.refresh-token-time-skew` requires the `web-app` application type"),
        "{error}"
    );
}

#[test]
fn oidc_from_config_accepts_web_app_application_type() {
    let config = Config::builder()
        .add_source(
            MapSource::new("web-app", 100)
                .with("oidc.public-key", PUBLIC_RSA_KEY)
                .with("oidc.application-type", "web-app"),
        )
        .build();

    let _builder = Oidc::from_config(&config).expect("web-app should be accepted");
}

fn web_app_redirect_test_app() -> Router {
    let oidc = Oidc::builder(OidcConfig {
        application_type: ApplicationType::WebApp,
        client_id: Some("orders-web".to_owned()),
        authentication: OidcAuthenticationConfig {
            redirect_path: "/login/callback".to_owned(),
            restore_path_after_redirect: true,
            session_age_extension: Duration::from_secs(300),
            token_state_cookie_key: None,
            nonce_required: false,
            scopes: vec!["openid".to_owned()],
        },
        ..OidcConfig::default()
    })
    .provider_metadata(
        ProviderMetadata {
            issuer: Some("https://issuer.example/realms/app".to_owned()),
            jwks_uri: "https://issuer.example/realms/app/certs".to_owned(),
            authorization_endpoint: Some("https://issuer.example/realms/app/auth".to_owned()),
            token_endpoint: Some("https://issuer.example/realms/app/token".to_owned()),
            registration_endpoint: None,
            revocation_endpoint: None,
            introspection_endpoint: None,
            userinfo_endpoint: None,
            end_session_endpoint: None,
        },
        JwkSet { keys: vec![] },
    )
    .expect("web-app provider metadata should build");

    Router::new()
        .route("/protected", get(|| async { "ok" }))
        .layer(oidc.layer())
}

async fn web_app_authorization_redirect_location(request: Request<Body>) -> reqwest::Url {
    let response = web_app_redirect_test_app()
        .oneshot(request)
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect location should be present");
    reqwest::Url::parse(location).expect("redirect location should be a URL")
}

#[tokio::test]
async fn web_app_redirects_unauthenticated_request_to_authorization_endpoint() {
    let oidc = Oidc::builder(OidcConfig {
        application_type: ApplicationType::WebApp,
        client_id: Some("orders-web".to_owned()),
        authentication: OidcAuthenticationConfig {
            redirect_path: "/login/callback".to_owned(),
            restore_path_after_redirect: true,
            session_age_extension: Duration::from_secs(300),
            token_state_cookie_key: None,
            nonce_required: true,
            scopes: vec!["openid".to_owned(), "email".to_owned()],
        },
        ..OidcConfig::default()
    })
    .provider_metadata(
        ProviderMetadata {
            issuer: Some("https://issuer.example/realms/app".to_owned()),
            jwks_uri: "https://issuer.example/realms/app/certs".to_owned(),
            authorization_endpoint: Some("https://issuer.example/realms/app/auth".to_owned()),
            token_endpoint: Some("https://issuer.example/realms/app/token".to_owned()),
            registration_endpoint: None,
            revocation_endpoint: None,
            introspection_endpoint: None,
            userinfo_endpoint: None,
            end_session_endpoint: None,
        },
        JwkSet { keys: vec![] },
    )
    .expect("web-app provider metadata should build");
    let app = Router::new()
        .route("/protected", get(|| async { "ok" }))
        .layer(oidc.layer());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected?item=1")
                .header(HOST, "app.example")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect location should be present");
    let location = reqwest::Url::parse(location).expect("redirect location should be a URL");
    assert_eq!(
        location.as_str().split('?').next().unwrap(),
        "https://issuer.example/realms/app/auth"
    );
    let query = location.query_pairs().collect::<HashMap<_, _>>();
    assert_eq!(
        query.get("response_type").map(|value| value.as_ref()),
        Some("code")
    );
    assert_eq!(
        query.get("client_id").map(|value| value.as_ref()),
        Some("orders-web")
    );
    assert_eq!(
        query.get("redirect_uri").map(|value| value.as_ref()),
        Some("http://app.example/login/callback")
    );
    assert_eq!(
        query.get("scope").map(|value| value.as_ref()),
        Some("openid email")
    );
    assert!(query.contains_key("state"));
    let nonce = query
        .get("nonce")
        .expect("nonce should be sent by default for web-app authentication");
    assert_eq!(nonce.len(), 43);
    assert_ne!(query.get("state"), Some(nonce));
}

#[tokio::test]
async fn web_app_redirects_without_external_session_layer() {
    let oidc = Oidc::builder(OidcConfig {
        application_type: ApplicationType::WebApp,
        client_id: Some("orders-web".to_owned()),
        authentication: OidcAuthenticationConfig {
            redirect_path: "/login/callback".to_owned(),
            restore_path_after_redirect: true,
            session_age_extension: Duration::from_secs(300),
            token_state_cookie_key: None,
            nonce_required: false,
            scopes: vec!["openid".to_owned()],
        },
        ..OidcConfig::default()
    })
    .provider_metadata(
        ProviderMetadata {
            issuer: Some("https://issuer.example/realms/app".to_owned()),
            jwks_uri: "https://issuer.example/realms/app/certs".to_owned(),
            authorization_endpoint: Some("https://issuer.example/realms/app/auth".to_owned()),
            token_endpoint: Some("https://issuer.example/realms/app/token".to_owned()),
            registration_endpoint: None,
            revocation_endpoint: None,
            introspection_endpoint: None,
            userinfo_endpoint: None,
            end_session_endpoint: None,
        },
        JwkSet { keys: vec![] },
    )
    .expect("web-app provider metadata should build");
    let app = Router::new()
        .route("/protected", get(|| async { "ok" }))
        .layer(oidc.layer());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(HOST, "app.example")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect location should be present");
    let location = reqwest::Url::parse(location).expect("redirect location should parse");
    let query = location.query_pairs().collect::<HashMap<_, _>>();
    assert!(!query.contains_key("nonce"));
}

#[tokio::test]
async fn web_app_redirect_uri_uses_absolute_request_authority_without_host_header() {
    let oidc = Oidc::builder(OidcConfig {
        application_type: ApplicationType::WebApp,
        client_id: Some("orders-web".to_owned()),
        authentication: OidcAuthenticationConfig {
            redirect_path: "/login/callback".to_owned(),
            restore_path_after_redirect: true,
            session_age_extension: Duration::from_secs(300),
            token_state_cookie_key: None,
            nonce_required: false,
            scopes: vec!["openid".to_owned()],
        },
        ..OidcConfig::default()
    })
    .provider_metadata(
        ProviderMetadata {
            issuer: Some("https://issuer.example/realms/app".to_owned()),
            jwks_uri: "https://issuer.example/realms/app/certs".to_owned(),
            authorization_endpoint: Some("https://issuer.example/realms/app/auth".to_owned()),
            token_endpoint: Some("https://issuer.example/realms/app/token".to_owned()),
            registration_endpoint: None,
            revocation_endpoint: None,
            introspection_endpoint: None,
            userinfo_endpoint: None,
            end_session_endpoint: None,
        },
        JwkSet { keys: vec![] },
    )
    .expect("web-app provider metadata should build");
    let app = Router::new()
        .route("/protected", get(|| async { "ok" }))
        .layer(oidc.layer());

    let response = app
        .oneshot(
            Request::builder()
                .uri("https://app.example/protected")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect location should be present");
    let location = reqwest::Url::parse(location).expect("redirect location should be a URL");
    let query = location.query_pairs().collect::<HashMap<_, _>>();
    assert_eq!(
        query.get("redirect_uri").map(|value| value.as_ref()),
        Some("https://app.example/login/callback")
    );
}

#[tokio::test]
async fn web_app_redirect_uri_uses_forwarded_header_origin() {
    let location = web_app_authorization_redirect_location(
        Request::builder()
            .uri("/protected")
            .header("forwarded", "proto=https;host=app.example")
            .body(Body::empty())
            .expect("request should be valid"),
    )
    .await;
    let query = location.query_pairs().collect::<HashMap<_, _>>();

    assert_eq!(
        query.get("redirect_uri").map(|value| value.as_ref()),
        Some("https://app.example/login/callback")
    );
}

#[tokio::test]
async fn web_app_redirect_uri_prefers_x_forwarded_headers_over_forwarded() {
    let location = web_app_authorization_redirect_location(
        Request::builder()
            .uri("/protected")
            .header("forwarded", "proto=http;host=forwarded.example")
            .header("x-forwarded-proto", "https")
            .header("x-forwarded-host", "x-forwarded.example")
            .body(Body::empty())
            .expect("request should be valid"),
    )
    .await;
    let query = location.query_pairs().collect::<HashMap<_, _>>();

    assert_eq!(
        query.get("redirect_uri").map(|value| value.as_ref()),
        Some("https://x-forwarded.example/login/callback")
    );
}

#[tokio::test]
async fn web_app_redirect_uri_ignores_invalid_forwarded_origin_headers() {
    let location = web_app_authorization_redirect_location(
        Request::builder()
            .uri("/protected")
            .header("forwarded", "proto=https;host=forwarded.example")
            .header("x-forwarded-proto", "javascript")
            .header("x-forwarded-host", "attacker.example/path")
            .header(HOST, "app.example")
            .body(Body::empty())
            .expect("request should be valid"),
    )
    .await;
    let query = location.query_pairs().collect::<HashMap<_, _>>();

    assert_eq!(
        query.get("redirect_uri").map(|value| value.as_ref()),
        Some("https://forwarded.example/login/callback")
    );
}

#[tokio::test]
async fn web_app_redirect_uri_requires_request_origin_for_relative_redirect_path() {
    let oidc = Oidc::builder(OidcConfig {
        application_type: ApplicationType::WebApp,
        client_id: Some("orders-web".to_owned()),
        authentication: OidcAuthenticationConfig {
            redirect_path: "/login/callback".to_owned(),
            restore_path_after_redirect: true,
            session_age_extension: Duration::from_secs(300),
            token_state_cookie_key: None,
            nonce_required: false,
            scopes: vec!["openid".to_owned()],
        },
        ..OidcConfig::default()
    })
    .provider_metadata(
        ProviderMetadata {
            issuer: Some("https://issuer.example/realms/app".to_owned()),
            jwks_uri: "https://issuer.example/realms/app/certs".to_owned(),
            authorization_endpoint: Some("https://issuer.example/realms/app/auth".to_owned()),
            token_endpoint: Some("https://issuer.example/realms/app/token".to_owned()),
            registration_endpoint: None,
            revocation_endpoint: None,
            introspection_endpoint: None,
            userinfo_endpoint: None,
            end_session_endpoint: None,
        },
        JwkSet { keys: vec![] },
    )
    .expect("web-app provider metadata should build");
    let app = Router::new()
        .route("/protected", get(|| async { "ok" }))
        .layer(oidc.layer());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[test]
fn web_app_rejects_invalid_token_state_cookie_key() {
    let Err(error) = Oidc::builder(OidcConfig {
        application_type: ApplicationType::WebApp,
        client_id: Some("orders-web".to_owned()),
        authentication: OidcAuthenticationConfig {
            token_state_cookie_key: Some("too-short".to_owned()),
            ..OidcAuthenticationConfig::default()
        },
        ..OidcConfig::default()
    })
    .provider_metadata(
        ProviderMetadata {
            issuer: Some("https://issuer.example/realms/app".to_owned()),
            jwks_uri: "https://issuer.example/realms/app/certs".to_owned(),
            authorization_endpoint: Some("https://issuer.example/realms/app/auth".to_owned()),
            token_endpoint: Some("https://issuer.example/realms/app/token".to_owned()),
            registration_endpoint: None,
            revocation_endpoint: None,
            introspection_endpoint: None,
            userinfo_endpoint: None,
            end_session_endpoint: None,
        },
        JwkSet { keys: vec![] },
    ) else {
        panic!("invalid token-state cookie key should be rejected");
    };

    assert!(
        error
            .to_string()
            .contains("token-state-cookie-key must be base64-encoded"),
        "{error}"
    );
}

#[tokio::test]
async fn web_app_callback_exchanges_code_and_stores_token_state_cookie() {
    let token = jwt_with_kid_and_secret(
        "test-key",
        b"secret",
        json!({
            "sub": "alice",
            "iss": "https://issuer.example/realms/app",
            "aud": "orders-web",
            "exp": 4_102_444_800_u64,
            "groups": [],
            "realm_access": { "roles": [] },
            "email": "alice@example.com",
            "email_verified": true
        }),
    );
    let token_endpoint = one_shot_token_endpoint("opaque-access-token".to_owned(), Some(token));
    let oidc = Oidc::builder(OidcConfig {
        application_type: ApplicationType::WebApp,
        client_id: Some("orders-web".to_owned()),
        authentication: OidcAuthenticationConfig {
            redirect_path: "/login/callback".to_owned(),
            restore_path_after_redirect: true,
            session_age_extension: Duration::from_secs(300),
            token_state_cookie_key: None,
            nonce_required: false,
            scopes: vec!["openid".to_owned()],
        },
        ..OidcConfig::default()
    })
    .provider_metadata(
        ProviderMetadata {
            issuer: Some("https://issuer.example/realms/app".to_owned()),
            jwks_uri: "https://issuer.example/realms/app/certs".to_owned(),
            authorization_endpoint: Some("https://issuer.example/realms/app/auth".to_owned()),
            token_endpoint: Some(token_endpoint),
            registration_endpoint: None,
            revocation_endpoint: None,
            introspection_endpoint: None,
            userinfo_endpoint: None,
            end_session_endpoint: None,
        },
        test_jwks(),
    )
    .expect("web-app provider metadata should build");
    let app = Router::new()
        .route(
            "/protected",
            get(|session: OidcSession| async move {
                format!(
                    "{}:{}",
                    session.principal().subject(),
                    identity_email(&session).unwrap_or("missing-email")
                )
            }),
        )
        .layer(oidc.layer());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/protected?item=1")
                .header(HOST, "app.example")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::FOUND);
    let cookie = cookie_header(&response);
    let redirect = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect location should be present");
    let state = reqwest::Url::parse(redirect)
        .expect("redirect location should parse")
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .expect("state should be present");

    let callback = format!("/login/callback?code=good-code&state={state}");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(callback)
                .header(HOST, "app.example")
                .header(COOKIE, &cookie)
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(LOCATION).unwrap(),
        HeaderValue::from_static("/protected?item=1")
    );
    let token_state_cookie = set_cookie_header(&response, "q_oidc")
        .expect("token-state cookie should be set after callback");
    assert!(token_state_cookie.contains("; Secure"));
    assert!(!token_state_cookie.contains("opaque-access-token"));
    assert!(!token_state_cookie.contains("alice@example.com"));
    let cookie = cookie_header(&response);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected?item=1")
                .header(HOST, "app.example")
                .header(COOKIE, cookie)
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_body(response).await, "alice:alice@example.com");
}

#[tokio::test]
async fn web_app_callback_uses_configured_basic_client_secret_method() {
    let token = jwt_with_kid_and_secret(
        "test-key",
        b"secret",
        json!({
            "sub": "alice",
            "iss": "https://issuer.example/realms/app",
            "aud": "orders-web",
            "exp": 4_102_444_800_u64,
            "groups": [],
            "realm_access": { "roles": [] },
            "email": "alice@example.com",
            "email_verified": true
        }),
    );
    let (token_endpoint, requests) = token_endpoint_request_sequence(vec![token_response_body(
        "opaque-access-token",
        Some(&token),
        None,
        None,
    )]);
    let oidc = Oidc::builder(OidcConfig {
        application_type: ApplicationType::WebApp,
        client_id: Some("orders-web".to_owned()),
        credentials: OidcCredentialsConfig {
            client_secret: OidcClientSecretConfig {
                value: Some("orders-secret".to_owned()),
                method: ClientSecretMethod::Basic,
            },
            ..OidcCredentialsConfig::default()
        },
        authentication: OidcAuthenticationConfig {
            redirect_path: "/login/callback".to_owned(),
            restore_path_after_redirect: true,
            token_state_cookie_key: None,
            nonce_required: false,
            scopes: vec!["openid".to_owned()],
            ..OidcAuthenticationConfig::default()
        },
        ..OidcConfig::default()
    })
    .provider_metadata(
        ProviderMetadata {
            issuer: Some("https://issuer.example/realms/app".to_owned()),
            jwks_uri: "https://issuer.example/realms/app/certs".to_owned(),
            authorization_endpoint: Some("https://issuer.example/realms/app/auth".to_owned()),
            token_endpoint: Some(token_endpoint),
            registration_endpoint: None,
            revocation_endpoint: None,
            introspection_endpoint: None,
            userinfo_endpoint: None,
            end_session_endpoint: None,
        },
        test_jwks(),
    )
    .expect("web-app provider metadata should build");
    let app = Router::new()
        .route("/protected", get(|| async { "ok" }))
        .layer(oidc.layer());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(HOST, "app.example")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::FOUND);
    let cookie = cookie_header(&response);
    let state = redirect_state(&response);

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/login/callback?code=good-code&state={state}"))
                .header(HOST, "app.example")
                .header(COOKIE, cookie)
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FOUND);
    let requests = requests
        .lock()
        .expect("captured token endpoint requests should not be poisoned");
    let request = requests
        .first()
        .expect("token endpoint request should be captured");
    assert!(
        request.contains("authorization: Basic b3JkZXJzLXdlYjpvcmRlcnMtc2VjcmV0"),
        "{request}"
    );
    let body = request
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .expect("request should include a body");
    assert!(body.contains("grant_type=authorization_code"), "{body}");
    assert!(!body.contains("client_secret="), "{body}");
}

#[tokio::test]
async fn hybrid_callback_uses_web_app_flow_without_bearer_token() {
    let token = jwt_with_kid_and_secret(
        "test-key",
        b"secret",
        json!({
            "sub": "alice",
            "iss": "https://issuer.example/realms/app",
            "aud": "orders-web",
            "exp": 4_102_444_800_u64,
            "groups": [],
            "realm_access": { "roles": [] },
            "email": "alice@example.com",
            "email_verified": true
        }),
    );
    let token_endpoint = one_shot_token_endpoint("opaque-access-token".to_owned(), Some(token));
    let oidc = Oidc::builder(OidcConfig {
        application_type: ApplicationType::Hybrid,
        client_id: Some("orders-web".to_owned()),
        authentication: OidcAuthenticationConfig {
            redirect_path: "/login/callback".to_owned(),
            restore_path_after_redirect: true,
            session_age_extension: Duration::from_secs(300),
            token_state_cookie_key: None,
            nonce_required: false,
            scopes: vec!["openid".to_owned()],
        },
        ..OidcConfig::default()
    })
    .provider_metadata(
        ProviderMetadata {
            issuer: Some("https://issuer.example/realms/app".to_owned()),
            jwks_uri: "https://issuer.example/realms/app/certs".to_owned(),
            authorization_endpoint: Some("https://issuer.example/realms/app/auth".to_owned()),
            token_endpoint: Some(token_endpoint),
            registration_endpoint: None,
            revocation_endpoint: None,
            introspection_endpoint: None,
            userinfo_endpoint: None,
            end_session_endpoint: None,
        },
        test_jwks(),
    )
    .expect("hybrid provider metadata should build");
    let app = Router::new()
        .route("/protected", get(|| async { "ok" }))
        .layer(oidc.layer());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(HOST, "app.example")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::FOUND);
    let cookie = cookie_header(&response);
    let state = redirect_state(&response);

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/login/callback?code=good-code&state={state}"))
                .header(HOST, "app.example")
                .header(COOKIE, cookie)
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_ne!(
        response.headers().get(WWW_AUTHENTICATE),
        Some(&HeaderValue::from_static("Bearer"))
    );
}

#[tokio::test]
async fn web_app_clears_tampered_token_state_cookie() {
    let token = jwt_with_kid_and_secret(
        "test-key",
        b"secret",
        json!({
            "sub": "alice",
            "iss": "https://issuer.example/realms/app",
            "aud": "orders-web",
            "exp": 4_102_444_800_u64,
            "groups": [],
            "realm_access": { "roles": [] },
            "email": "alice@example.com"
        }),
    );
    let token_endpoint = one_shot_token_endpoint("opaque-access-token".to_owned(), Some(token));
    let oidc = Oidc::builder(OidcConfig {
        application_type: ApplicationType::WebApp,
        client_id: Some("orders-web".to_owned()),
        authentication: OidcAuthenticationConfig {
            nonce_required: false,
            ..OidcAuthenticationConfig::default()
        },
        ..OidcConfig::default()
    })
    .provider_metadata(
        ProviderMetadata {
            issuer: Some("https://issuer.example/realms/app".to_owned()),
            jwks_uri: "https://issuer.example/realms/app/certs".to_owned(),
            authorization_endpoint: Some("https://issuer.example/realms/app/auth".to_owned()),
            token_endpoint: Some(token_endpoint),
            registration_endpoint: None,
            revocation_endpoint: None,
            introspection_endpoint: None,
            userinfo_endpoint: None,
            end_session_endpoint: None,
        },
        test_jwks(),
    )
    .expect("web-app provider metadata should build");
    let app = Router::new()
        .route("/protected", get(|| async { "ok" }))
        .layer(oidc.layer());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(HOST, "app.example")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");
    let cookie = cookie_header(&response);
    let state = redirect_state(&response);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/q/oidc/callback?code=good-code&state={state}"))
                .header(HOST, "app.example")
                .header(COOKIE, &cookie)
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::FOUND);
    let cookie = tamper_cookie_value(&cookie_header(&response), "q_oidc");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(HOST, "app.example")
                .header(COOKIE, cookie)
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect location should be present");
    assert!(location.starts_with("https://issuer.example/realms/app/auth?"));
    let cleared = set_cookie_header(&response, "q_oidc")
        .expect("tampered token-state cookie should be cleared");
    assert!(cleared.contains("Max-Age=0"));
}

#[tokio::test]
async fn routes_are_empty_for_service_applications() {
    let app = Router::new().merge(oidc().routes());

    let response = app
        .oneshot(request("/q/oidc/logout", None))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn web_app_logout_route_clears_local_session_and_redirects_locally() {
    let token = jwt_with_kid_and_secret(
        "test-key",
        b"secret",
        json!({
            "sub": "alice",
            "iss": "https://issuer.example/realms/app",
            "aud": "orders-web",
            "exp": 4_102_444_800_u64,
            "groups": [],
            "realm_access": { "roles": [] },
            "email": "alice@example.com"
        }),
    );
    let token_endpoint = one_shot_token_endpoint("opaque-access-token".to_owned(), Some(token));
    let oidc = Oidc::builder(OidcConfig {
        application_type: ApplicationType::WebApp,
        client_id: Some("orders-web".to_owned()),
        authentication: OidcAuthenticationConfig {
            nonce_required: false,
            ..OidcAuthenticationConfig::default()
        },
        logout: OidcLogoutConfig {
            path: "/signout".to_owned(),
            post_logout_path: Some("/signed-out".to_owned()),
            post_logout_uri_param: "returnTo".to_owned(),
            extra_params: HashMap::from([("ui_locales".to_owned(), "en-CA".to_owned())]),
        },
        ..OidcConfig::default()
    })
    .provider_metadata(
        ProviderMetadata {
            issuer: Some("https://issuer.example/realms/app".to_owned()),
            jwks_uri: "https://issuer.example/realms/app/certs".to_owned(),
            authorization_endpoint: Some("https://issuer.example/realms/app/auth".to_owned()),
            token_endpoint: Some(token_endpoint),
            registration_endpoint: None,
            revocation_endpoint: None,
            introspection_endpoint: None,
            userinfo_endpoint: None,
            end_session_endpoint: None,
        },
        test_jwks(),
    )
    .expect("web-app provider metadata should build");
    let app = Router::new()
        .route(
            "/logout",
            oidc.logout_route_with_options(OidcLogoutOptions {
                post_logout_redirect: Some("/signed-out".to_owned()),
                ..OidcLogoutOptions::default()
            }),
        )
        .merge(
            Router::new()
                .route("/protected", get(|| async { "ok" }))
                .layer(oidc.layer()),
        );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(HOST, "app.example")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");
    let cookie = cookie_header(&response);
    let state = redirect_state(&response);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/q/oidc/callback?code=good-code&state={state}"))
                .header(HOST, "app.example")
                .header(COOKIE, cookie)
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::FOUND);
    let session_cookie = cookie_header(&response);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/logout")
                .header(HOST, "app.example")
                .header(COOKIE, session_cookie)
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers().get(LOCATION),
        Some(&HeaderValue::from_static("/signed-out"))
    );
    let cleared =
        set_cookie_header(&response, "q_oidc").expect("logout should clear token-state cookie");
    assert!(cleared.contains("Max-Age=0"));
    assert!(cleared.contains("; Secure"));
    let cleared_redirect = set_cookie_header(&response, "q_oidc_redirect")
        .expect("logout should clear redirect-state cookie");
    assert!(cleared_redirect.contains("Max-Age=0"));
    assert!(cleared_redirect.contains("; Secure"));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(HOST, "app.example")
                .header(COOKIE, cookie_header(&response))
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect location should be present");
    assert!(location.starts_with("https://issuer.example/realms/app/auth?"));
}

#[tokio::test]
async fn web_app_logout_route_redirects_to_provider_end_session_endpoint() {
    let token = jwt_with_kid_and_secret(
        "test-key",
        b"secret",
        json!({
            "sub": "alice",
            "iss": "https://issuer.example/realms/app",
            "aud": "orders-web",
            "exp": 4_102_444_800_u64,
            "groups": [],
            "realm_access": { "roles": [] },
            "email": "alice@example.com"
        }),
    );
    let token_endpoint =
        one_shot_token_endpoint("opaque-access-token".to_owned(), Some(token.clone()));
    let oidc = Oidc::builder(OidcConfig {
        application_type: ApplicationType::WebApp,
        client_id: Some("orders-web".to_owned()),
        authentication: OidcAuthenticationConfig {
            nonce_required: false,
            ..OidcAuthenticationConfig::default()
        },
        logout: OidcLogoutConfig {
            path: "/signout".to_owned(),
            post_logout_path: Some("/signed-out".to_owned()),
            post_logout_uri_param: "returnTo".to_owned(),
            extra_params: HashMap::from([("ui_locales".to_owned(), "en-CA".to_owned())]),
        },
        ..OidcConfig::default()
    })
    .provider_metadata(
        ProviderMetadata {
            issuer: Some("https://issuer.example/realms/app".to_owned()),
            jwks_uri: "https://issuer.example/realms/app/certs".to_owned(),
            authorization_endpoint: Some("https://issuer.example/realms/app/auth".to_owned()),
            token_endpoint: Some(token_endpoint),
            registration_endpoint: None,
            revocation_endpoint: None,
            introspection_endpoint: None,
            userinfo_endpoint: None,
            end_session_endpoint: Some(
                "https://issuer.example/realms/app/logout?client_id=orders-web".to_owned(),
            ),
        },
        test_jwks(),
    )
    .expect("web-app provider metadata should build");
    let app = Router::new().merge(oidc.routes()).merge(
        Router::new()
            .route("/protected", get(|| async { "ok" }))
            .layer(oidc.layer()),
    );

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(HOST, "app.example")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");
    let cookie = cookie_header(&response);
    let state = redirect_state(&response);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/q/oidc/callback?code=good-code&state={state}"))
                .header(HOST, "app.example")
                .header(COOKIE, cookie)
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::FOUND);
    let session_cookie = cookie_header(&response);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/signout")
                .header(HOST, "app.example")
                .header("x-forwarded-proto", "https")
                .header(COOKIE, session_cookie)
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect location should be present");
    let location = reqwest::Url::parse(location).expect("logout redirect should be a URL");
    assert_eq!(
        location.as_str().split('?').next().unwrap(),
        "https://issuer.example/realms/app/logout"
    );
    let query = location.query_pairs().collect::<HashMap<_, _>>();
    assert_eq!(
        query.get("client_id").map(|value| value.as_ref()),
        Some("orders-web")
    );
    assert_eq!(
        query.get("id_token_hint").map(|value| value.as_ref()),
        Some(token.as_str())
    );
    assert_eq!(
        query.get("returnTo").map(|value| value.as_ref()),
        Some("https://app.example/signed-out")
    );
    assert_eq!(
        query.get("ui_locales").map(|value| value.as_ref()),
        Some("en-CA")
    );
    let cleared =
        set_cookie_header(&response, "q_oidc").expect("logout should clear token-state cookie");
    assert!(cleared.contains("Max-Age=0"));
}

#[tokio::test]
async fn web_app_token_state_cookie_lifetime_tracks_tokens() {
    let token = jwt_with_kid_and_secret(
        "test-key",
        b"secret",
        json!({
            "sub": "alice",
            "iss": "https://issuer.example/realms/app",
            "aud": "orders-web",
            "exp": 4_102_444_800_u64,
            "groups": [],
            "realm_access": { "roles": [] },
            "email": "alice@example.com"
        }),
    );
    let token_endpoint = one_shot_token_endpoint_with_refresh(
        "opaque-access-token".to_owned(),
        Some(token),
        Some("refresh-token".to_owned()),
        Some(30),
    );
    let oidc = Oidc::builder(OidcConfig {
        application_type: ApplicationType::WebApp,
        client_id: Some("orders-web".to_owned()),
        authentication: OidcAuthenticationConfig {
            session_age_extension: Duration::from_secs(20),
            nonce_required: false,
            ..OidcAuthenticationConfig::default()
        },
        token: OidcTokenConfig {
            lifespan_grace: Some(10),
            refresh_expired: true,
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    })
    .provider_metadata(
        ProviderMetadata {
            issuer: Some("https://issuer.example/realms/app".to_owned()),
            jwks_uri: "https://issuer.example/realms/app/certs".to_owned(),
            authorization_endpoint: Some("https://issuer.example/realms/app/auth".to_owned()),
            token_endpoint: Some(token_endpoint),
            registration_endpoint: None,
            revocation_endpoint: None,
            introspection_endpoint: None,
            userinfo_endpoint: None,
            end_session_endpoint: None,
        },
        test_jwks(),
    )
    .expect("web-app provider metadata should build");
    let app = Router::new()
        .route("/protected", get(|| async { "ok" }))
        .layer(oidc.layer());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(HOST, "app.example")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");
    let cookie = cookie_header(&response);
    let state = redirect_state(&response);

    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/q/oidc/callback?code=good-code&state={state}"))
                .header(HOST, "app.example")
                .header(COOKIE, &cookie)
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FOUND);
    let token_state_cookie = set_cookie_header(&response, "q_oidc")
        .expect("token-state cookie should be set after callback");
    let max_age = cookie_attribute(&token_state_cookie, "Max-Age")
        .and_then(|value| value.parse::<u64>().ok())
        .expect("token-state cookie should have Max-Age");
    assert!(
        (55..=60).contains(&max_age),
        "expected Max-Age near 60 seconds, got {max_age}: {token_state_cookie}"
    );
}

#[tokio::test]
async fn web_app_refreshes_expired_session_tokens() {
    let initial_token = jwt_with_kid_and_secret(
        "test-key",
        b"secret",
        json!({
            "sub": "alice",
            "iss": "https://issuer.example/realms/app",
            "aud": "orders-web",
            "exp": 4_102_444_800_u64,
            "groups": [],
            "realm_access": { "roles": [] },
            "email": "alice@example.com"
        }),
    );
    let refreshed_token = jwt_with_kid_and_secret(
        "test-key",
        b"secret",
        json!({
            "sub": "alice",
            "iss": "https://issuer.example/realms/app",
            "aud": "orders-web",
            "exp": 4_102_444_800_u64,
            "groups": [],
            "realm_access": { "roles": [] },
            "email": "refreshed@example.com"
        }),
    );
    let (token_endpoint, forms) = token_endpoint_sequence(vec![
        token_response_body(
            "opaque-access-token",
            Some(&initial_token),
            Some("initial-refresh-token"),
            Some(0),
        ),
        token_response_body(
            "opaque-refreshed-token",
            Some(&refreshed_token),
            Some("rotated-refresh-token"),
            Some(3600),
        ),
    ]);
    let oidc = Oidc::builder(OidcConfig {
        application_type: ApplicationType::WebApp,
        client_id: Some("orders-web".to_owned()),
        authentication: OidcAuthenticationConfig {
            nonce_required: false,
            ..OidcAuthenticationConfig::default()
        },
        token: OidcTokenConfig {
            refresh_expired: true,
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    })
    .provider_metadata(
        ProviderMetadata {
            issuer: Some("https://issuer.example/realms/app".to_owned()),
            jwks_uri: "https://issuer.example/realms/app/certs".to_owned(),
            authorization_endpoint: Some("https://issuer.example/realms/app/auth".to_owned()),
            token_endpoint: Some(token_endpoint),
            registration_endpoint: None,
            revocation_endpoint: None,
            introspection_endpoint: None,
            userinfo_endpoint: None,
            end_session_endpoint: None,
        },
        test_jwks(),
    )
    .expect("web-app provider metadata should build");
    let app = Router::new()
        .route(
            "/protected",
            get(|session: OidcSession| async move {
                identity_email(&session)
                    .unwrap_or("missing-email")
                    .to_owned()
            }),
        )
        .layer(oidc.layer());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(HOST, "app.example")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");
    let cookie = cookie_header(&response);
    let state = redirect_state(&response);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/q/oidc/callback?code=good-code&state={state}"))
                .header(HOST, "app.example")
                .header(COOKIE, &cookie)
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::FOUND);
    let cookie = cookie_header(&response);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(HOST, "app.example")
                .header(COOKIE, cookie)
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_body(response).await, "refreshed@example.com");
    let forms = forms
        .lock()
        .expect("captured token endpoint forms should not be poisoned");
    assert_eq!(forms.len(), 2);
    assert!(forms[0].contains("grant_type=authorization_code"));
    assert!(forms[1].contains("grant_type=refresh_token"));
    assert!(forms[1].contains("refresh_token=initial-refresh-token"));
}

#[tokio::test]
async fn web_app_redirects_when_expired_session_refresh_is_disabled() {
    let token = jwt_with_kid_and_secret(
        "test-key",
        b"secret",
        json!({
            "sub": "alice",
            "iss": "https://issuer.example/realms/app",
            "aud": "orders-web",
            "exp": 4_102_444_800_u64,
            "groups": [],
            "realm_access": { "roles": [] },
            "email": "alice@example.com"
        }),
    );
    let token_endpoint = one_shot_token_endpoint_with_refresh(
        "opaque-access-token".to_owned(),
        Some(token),
        Some("refresh-token".to_owned()),
        Some(0),
    );
    let oidc = Oidc::builder(OidcConfig {
        application_type: ApplicationType::WebApp,
        client_id: Some("orders-web".to_owned()),
        authentication: OidcAuthenticationConfig {
            nonce_required: false,
            ..OidcAuthenticationConfig::default()
        },
        ..OidcConfig::default()
    })
    .provider_metadata(
        ProviderMetadata {
            issuer: Some("https://issuer.example/realms/app".to_owned()),
            jwks_uri: "https://issuer.example/realms/app/certs".to_owned(),
            authorization_endpoint: Some("https://issuer.example/realms/app/auth".to_owned()),
            token_endpoint: Some(token_endpoint),
            registration_endpoint: None,
            revocation_endpoint: None,
            introspection_endpoint: None,
            userinfo_endpoint: None,
            end_session_endpoint: None,
        },
        test_jwks(),
    )
    .expect("web-app provider metadata should build");
    let app = Router::new()
        .route("/protected", get(|| async { "ok" }))
        .layer(oidc.layer());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(HOST, "app.example")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");
    let cookie = cookie_header(&response);
    let state = redirect_state(&response);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/q/oidc/callback?code=good-code&state={state}"))
                .header(HOST, "app.example")
                .header(COOKIE, &cookie)
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::FOUND);
    let cookie = cookie_header(&response);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(HOST, "app.example")
                .header(COOKIE, cookie)
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FOUND);
    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect location should be present");
    assert!(location.starts_with("https://issuer.example/realms/app/auth?"));
}

#[tokio::test]
async fn web_app_refresh_token_time_skew_enables_proactive_refresh() {
    let initial_token = jwt_with_kid_and_secret(
        "test-key",
        b"secret",
        json!({
            "sub": "alice",
            "iss": "https://issuer.example/realms/app",
            "aud": "orders-web",
            "exp": 4_102_444_800_u64,
            "groups": [],
            "realm_access": { "roles": [] },
            "email": "alice@example.com"
        }),
    );
    let refreshed_token = jwt_with_kid_and_secret(
        "test-key",
        b"secret",
        json!({
            "sub": "alice",
            "iss": "https://issuer.example/realms/app",
            "aud": "orders-web",
            "exp": 4_102_444_800_u64,
            "groups": [],
            "realm_access": { "roles": [] },
            "email": "proactive@example.com"
        }),
    );
    let (token_endpoint, forms) = token_endpoint_sequence(vec![
        token_response_body(
            "opaque-access-token",
            Some(&initial_token),
            Some("initial-refresh-token"),
            Some(3600),
        ),
        token_response_body(
            "opaque-refreshed-token",
            Some(&refreshed_token),
            Some("rotated-refresh-token"),
            Some(3600),
        ),
    ]);
    let oidc = Oidc::builder(OidcConfig {
        application_type: ApplicationType::WebApp,
        client_id: Some("orders-web".to_owned()),
        authentication: OidcAuthenticationConfig {
            nonce_required: false,
            ..OidcAuthenticationConfig::default()
        },
        token: OidcTokenConfig {
            refresh_token_time_skew: Some(Duration::from_secs(7200)),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    })
    .provider_metadata(
        ProviderMetadata {
            issuer: Some("https://issuer.example/realms/app".to_owned()),
            jwks_uri: "https://issuer.example/realms/app/certs".to_owned(),
            authorization_endpoint: Some("https://issuer.example/realms/app/auth".to_owned()),
            token_endpoint: Some(token_endpoint),
            registration_endpoint: None,
            revocation_endpoint: None,
            introspection_endpoint: None,
            userinfo_endpoint: None,
            end_session_endpoint: None,
        },
        test_jwks(),
    )
    .expect("web-app provider metadata should build");
    let app = Router::new()
        .route(
            "/protected",
            get(|session: OidcSession| async move {
                identity_email(&session)
                    .unwrap_or("missing-email")
                    .to_owned()
            }),
        )
        .layer(oidc.layer());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(HOST, "app.example")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");
    let cookie = cookie_header(&response);
    let state = redirect_state(&response);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/q/oidc/callback?code=good-code&state={state}"))
                .header(HOST, "app.example")
                .header(COOKIE, &cookie)
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::FOUND);
    let cookie = cookie_header(&response);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(HOST, "app.example")
                .header(COOKIE, cookie)
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_body(response).await, "proactive@example.com");
    let forms = forms
        .lock()
        .expect("captured token endpoint forms should not be poisoned");
    assert_eq!(forms.len(), 2);
    assert!(forms[1].contains("grant_type=refresh_token"));
}

#[tokio::test]
async fn web_app_session_age_extension_bounds_expired_token_refresh() {
    let token = jwt_with_kid_and_secret(
        "test-key",
        b"secret",
        json!({
            "sub": "alice",
            "iss": "https://issuer.example/realms/app",
            "aud": "orders-web",
            "exp": 4_102_444_800_u64,
            "groups": [],
            "realm_access": { "roles": [] },
            "email": "alice@example.com"
        }),
    );
    let refreshed_token = jwt_with_kid_and_secret(
        "test-key",
        b"secret",
        json!({
            "sub": "alice",
            "iss": "https://issuer.example/realms/app",
            "aud": "orders-web",
            "exp": 4_102_444_800_u64,
            "groups": [],
            "realm_access": { "roles": [] },
            "email": "should-not-refresh@example.com"
        }),
    );
    let (token_endpoint, forms) = token_endpoint_sequence(vec![
        token_response_body(
            "opaque-access-token",
            Some(&token),
            Some("refresh-token"),
            Some(0),
        ),
        token_response_body(
            "opaque-refreshed-token",
            Some(&refreshed_token),
            Some("rotated-refresh-token"),
            Some(3600),
        ),
    ]);
    let oidc = Oidc::builder(OidcConfig {
        application_type: ApplicationType::WebApp,
        client_id: Some("orders-web".to_owned()),
        authentication: OidcAuthenticationConfig {
            session_age_extension: Duration::from_secs(0),
            nonce_required: false,
            ..OidcAuthenticationConfig::default()
        },
        token: OidcTokenConfig {
            refresh_expired: true,
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    })
    .provider_metadata(
        ProviderMetadata {
            issuer: Some("https://issuer.example/realms/app".to_owned()),
            jwks_uri: "https://issuer.example/realms/app/certs".to_owned(),
            authorization_endpoint: Some("https://issuer.example/realms/app/auth".to_owned()),
            token_endpoint: Some(token_endpoint),
            registration_endpoint: None,
            revocation_endpoint: None,
            introspection_endpoint: None,
            userinfo_endpoint: None,
            end_session_endpoint: None,
        },
        test_jwks(),
    )
    .expect("web-app provider metadata should build");
    let app = Router::new()
        .route("/protected", get(|| async { "ok" }))
        .layer(oidc.layer());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(HOST, "app.example")
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");
    let cookie = cookie_header(&response);
    let state = redirect_state(&response);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/q/oidc/callback?code=good-code&state={state}"))
                .header(HOST, "app.example")
                .header(COOKIE, &cookie)
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");
    assert_eq!(response.status(), StatusCode::FOUND);
    let cookie = cookie_header(&response);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/protected")
                .header(HOST, "app.example")
                .header(COOKIE, cookie)
                .body(Body::empty())
                .expect("request should be valid"),
        )
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FOUND);
    let forms = forms
        .lock()
        .expect("captured token endpoint forms should not be poisoned");
    assert_eq!(forms.len(), 1);
    assert!(forms[0].contains("grant_type=authorization_code"));
}

fn identity_email(identity: &impl OidcIdentity) -> Option<&str> {
    identity.id_token().and_then(IdToken::email)
}

#[test]
fn oidc_from_config_rejects_token_binding_certificate() {
    let config = Config::builder()
        .add_source(
            MapSource::new("token-binding", 100).with("oidc.token.binding.certificate", "true"),
        )
        .build();

    let Err(error) = Oidc::from_config(&config) else {
        panic!("certificate-bound tokens should be rejected for bearer-service middleware");
    };
    assert!(matches!(
        error,
        mp_config::ConfigError::Conversion { ref name, .. }
            if name == "oidc.token.binding.certificate"
    ));
    assert!(
        error
            .to_string()
            .contains("requires client certificate thumbprint extraction"),
        "{error}"
    );
}

#[test]
fn oidc_from_config_rejects_decrypt_access_token() {
    let config = Config::builder()
        .add_source(
            MapSource::new("decrypt-access-token", 100)
                .with("oidc.token.decrypt-access-token", "true"),
        )
        .build();

    let Err(error) = Oidc::from_config(&config) else {
        panic!("encrypted access tokens should be rejected until JWE support is implemented");
    };
    assert!(matches!(
        error,
        mp_config::ConfigError::Conversion { ref name, .. }
            if name == "oidc.token.decrypt-access-token"
    ));
    assert!(
        error
            .to_string()
            .contains("requires JWE access-token decryption"),
        "{error}"
    );
}

#[test]
fn oidc_from_config_rejects_decrypt_id_token() {
    let config = Config::builder()
        .add_source(
            MapSource::new("decrypt-id-token", 100).with("oidc.token.decrypt-id-token", "true"),
        )
        .build();

    let Err(error) = Oidc::from_config(&config) else {
        panic!("encrypted ID tokens should be rejected until web-app support is implemented");
    };
    assert!(matches!(
        error,
        mp_config::ConfigError::Conversion { ref name, .. }
            if name == "oidc.token.decrypt-id-token"
    ));
    assert!(
        error
            .to_string()
            .contains("requires web-app ID token decryption"),
        "{error}"
    );
}

#[test]
fn oidc_from_config_accepts_hybrid_application_type() {
    let config = Config::builder()
        .add_source(
            MapSource::new("hybrid", 100)
                .with("oidc.public-key", PUBLIC_RSA_KEY)
                .with("oidc.application-type", "hybrid"),
        )
        .build();

    let _builder = Oidc::from_config(&config).expect("hybrid should support bearer middleware");
}

#[tokio::test]
async fn jwt_validator_extracts_configured_role_claim_path() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            token_type: None,
            ..OidcTokenConfig::default()
        },
        roles: OidcRolesConfig {
            role_claim_path: "resource_access.orders.roles".to_owned(),
            ..OidcRolesConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(CustomRoleClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        resource_access: ResourceAccessClaims {
            orders: ResourceRolesClaims {
                roles: vec!["orders-admin", "orders-user"],
            },
        },
    });

    let response = custom_roles_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build(),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwt_validator_extracts_default_client_resource_roles() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        client_id: Some("orders-service".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            token_type: None,
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(ClientResourceRoleClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        resource_access: ClientResourceAccessClaims {
            orders_service: ResourceRolesClaims {
                roles: vec!["orders-admin", "orders-user"],
            },
        },
    });

    let response = custom_roles_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build(),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwt_validator_extracts_slash_separated_role_claim_path() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            token_type: None,
            ..OidcTokenConfig::default()
        },
        roles: OidcRolesConfig {
            role_claim_path: "resource_access/orders/roles".to_owned(),
            ..OidcRolesConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(CustomRoleClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        resource_access: ResourceAccessClaims {
            orders: ResourceRolesClaims {
                roles: vec!["orders-admin", "orders-user"],
            },
        },
    });

    let response = custom_roles_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build(),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwt_validator_extracts_quoted_namespace_role_claim_path() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            token_type: None,
            ..OidcTokenConfig::default()
        },
        roles: OidcRolesConfig {
            role_claim_path: "\"https://claims.example/roles\"".to_owned(),
            ..OidcRolesConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(NamespacedRoleClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        namespaced_roles: vec!["orders-admin", "orders-user"],
    });

    let response = custom_roles_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build(),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwt_validator_splits_string_role_claims_with_configured_separator() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            token_type: None,
            ..OidcTokenConfig::default()
        },
        roles: OidcRolesConfig {
            source: RolesSource::AccessToken,
            role_claim_path: "permissions".to_owned(),
            role_claim_separator: "|".to_owned(),
        },
        ..OidcConfig::default()
    };
    let token = jwt(StringRoleClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        permissions: "orders-admin|orders-user",
    });

    let response = custom_roles_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build(),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwt_validator_skips_roles_when_source_is_user_info() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            token_type: None,
            ..OidcTokenConfig::default()
        },
        roles: OidcRolesConfig {
            source: RolesSource::UserInfo,
            ..OidcRolesConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(TestClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        groups: vec!["orders-admin"],
        realm_access: RealmAccessClaims {
            roles: vec!["realm-admin"],
        },
    });

    let principal = JwtValidator::hs256("secret", &config)
        .validate(Arc::from(token))
        .await
        .expect("JWT should validate");

    assert_eq!(principal.groups().collect::<Vec<_>>(), Vec::<&str>::new());
}

#[tokio::test]
async fn jwt_validator_uses_default_principal_claim_order() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(PrincipalClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        preferred_username: Some("preferred-alice"),
        upn: Some("alice@example.com"),
        email: Some("alice@orders.example"),
        exp: 4_102_444_800,
    });

    let response = subject_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build(),
        "alice@example.com",
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwt_validator_uses_configured_principal_claim() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            principal_claim: Some("email".to_owned()),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(PrincipalClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        preferred_username: Some("preferred-alice"),
        upn: Some("alice@example.com"),
        email: Some("alice@orders.example"),
        exp: 4_102_444_800,
    });

    let response = subject_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build(),
        "alice@orders.example",
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwt_validator_uses_configured_principal_claim_path() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            principal_claim: Some("profile.email".to_owned()),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(ProfilePrincipalClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        profile: ProfileClaims {
            email: "alice@orders.example",
        },
        exp: 4_102_444_800,
    });

    let response = subject_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build(),
        "alice@orders.example",
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwt_validator_rejects_missing_configured_principal_claim() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            principal_claim: Some("email".to_owned()),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(TestClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        groups: Vec::new(),
        realm_access: RealmAccessClaims { roles: Vec::new() },
    });

    let response = app(Oidc::builder(config.clone())
        .validator(JwtValidator::hs256("secret", &config))
        .build())
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_validator_accepts_missing_subject_when_not_required() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(NoSubjectClaims {
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        preferred_username: Some("preferred-alice"),
        exp: 4_102_444_800,
    });

    let response = subject_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build(),
        "preferred-alice",
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwt_validator_rejects_missing_subject_when_required() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            subject_required: true,
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(NoSubjectClaims {
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        preferred_username: Some("preferred-alice"),
        exp: 4_102_444_800,
    });

    let response = app(Oidc::builder(config.clone())
        .validator(JwtValidator::hs256("secret", &config))
        .build())
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_validator_rejects_token_without_principal_claims() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(NoSubjectClaims {
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        preferred_username: None,
        exp: 4_102_444_800,
    });

    let response = app(Oidc::builder(config.clone())
        .validator(JwtValidator::hs256("secret", &config))
        .build())
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_validator_does_not_require_audience_when_unconfigured() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        client_id: Some("orders-api".to_owned()),
        ..OidcConfig::default()
    };
    let token = jwt(TestClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        groups: vec!["admin"],
        realm_access: RealmAccessClaims { roles: Vec::new() },
    });

    let response = claims_subject_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build(),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwt_validator_does_not_use_client_id_as_default_audience() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        client_id: Some("orders-api".to_owned()),
        ..OidcConfig::default()
    };
    let token = jwt(TestClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "other-api",
        exp: 4_102_444_800,
        groups: vec!["admin"],
        realm_access: RealmAccessClaims { roles: Vec::new() },
    });

    let response = claims_subject_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build(),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwt_validator_accepts_any_configured_audience() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api,billing-api".to_owned()),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(TestClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "billing-api",
        exp: 4_102_444_800,
        groups: vec!["admin"],
        realm_access: RealmAccessClaims { roles: Vec::new() },
    });

    let response = claims_subject_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build(),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwt_validator_rejects_unlisted_configured_audience() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api,billing-api".to_owned()),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(TestClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "inventory-api",
        exp: 4_102_444_800,
        groups: Vec::new(),
        realm_access: RealmAccessClaims { roles: Vec::new() },
    });

    let response = app(Oidc::builder(config.clone())
        .validator(JwtValidator::hs256("secret", &config))
        .build())
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_validator_skips_audience_validation_when_configured_any() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        client_id: Some("orders-api".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("any".to_owned()),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(TestClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "inventory-api",
        exp: 4_102_444_800,
        groups: vec!["admin"],
        realm_access: RealmAccessClaims { roles: Vec::new() },
    });

    let response = claims_subject_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build(),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwt_validator_accepts_configured_token_type() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            token_type: Some("bearer".to_owned()),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(TokenTypeClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        typ: "bearer",
        exp: 4_102_444_800,
    });

    let response = claims_subject_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build(),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwt_validator_accepts_configured_header_token_type() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            token_type: Some("at+jwt".to_owned()),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt_with_header_type(
        "at+jwt",
        TestClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            exp: 4_102_444_800,
            groups: Vec::new(),
            realm_access: RealmAccessClaims { roles: Vec::new() },
        },
    );

    let response = claims_subject_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build(),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwt_validator_rejects_wrong_token_type() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            token_type: Some("bearer".to_owned()),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(TokenTypeClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        typ: "id_token",
        exp: 4_102_444_800,
    });

    let response = app(Oidc::builder(config.clone())
        .validator(JwtValidator::hs256("secret", &config))
        .build())
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_validator_rejects_missing_token_type() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            token_type: Some("bearer".to_owned()),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(TestClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        groups: Vec::new(),
        realm_access: RealmAccessClaims { roles: Vec::new() },
    });

    let response = app(Oidc::builder(config.clone())
        .validator(JwtValidator::hs256("secret", &config))
        .build())
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_validator_rejects_unexpected_signature_algorithm() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            signature_algorithm: Some(TokenSignatureAlgorithm::Rs256),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(TestClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        groups: Vec::new(),
        realm_access: RealmAccessClaims { roles: Vec::new() },
    });

    let response = app(Oidc::builder(config.clone())
        .validator(JwtValidator::hs256("secret", &config))
        .build())
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn config_rejects_unknown_signature_algorithm() {
    let config = Config::builder()
        .add_source(MapSource::new("test", 100).with("oidc.token.signature-algorithm", "hs256"))
        .build();

    let error = OidcConfig::from_config(&config).expect_err("config should reject hs256");

    assert!(
        error
            .to_string()
            .contains("expected one of `rs256`, `rs384`, `rs512`"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn jwt_validator_accepts_required_claim_values() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            required_claims: HashMap::from([
                ("org_id".to_owned(), vec!["org_xyz".to_owned()]),
                (
                    "scope".to_owned(),
                    vec!["read".to_owned(), "write".to_owned()],
                ),
            ]),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(RequiredClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        org_id: "org_xyz",
        scope: vec!["read", "write", "delete"],
        exp: 4_102_444_800,
    });

    let response = claims_subject_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build(),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwt_validator_accepts_space_separated_required_claim_values() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            required_claims: HashMap::from([(
                "scope".to_owned(),
                vec!["read".to_owned(), "write".to_owned()],
            )]),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(StringScopeClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        scope: "read write delete",
        exp: 4_102_444_800,
    });

    let response = claims_subject_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build(),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwt_validator_accepts_nested_required_claim_values() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            required_claims: HashMap::from([(
                "resource_access.orders.roles".to_owned(),
                vec!["orders-admin".to_owned()],
            )]),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(CustomRoleClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        resource_access: ResourceAccessClaims {
            orders: ResourceRolesClaims {
                roles: vec!["orders-admin", "orders-user"],
            },
        },
    });

    let response = claims_subject_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build(),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwt_validator_loads_quoted_nested_required_claims_from_config() {
    let config = Config::builder()
        .add_source(
            MapSource::new("quoted-required-claims", 100)
                .with("oidc.auth-server-url", "https://issuer.example/realms/app")
                .with("oidc.token.audience", "orders-api")
                .with(
                    "oidc.token.required-claims.\"resource_access.orders.roles\"",
                    "orders-admin",
                ),
        )
        .build();
    let config = OidcConfig::from_config(&config).expect("OIDC config should load");
    let token = jwt(CustomRoleClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        resource_access: ResourceAccessClaims {
            orders: ResourceRolesClaims {
                roles: vec!["orders-admin", "orders-user"],
            },
        },
    });

    let response = claims_subject_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build(),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwt_validator_loads_slash_separated_required_claims_from_config() {
    let config = Config::builder()
        .add_source(
            MapSource::new("slash-required-claims", 100)
                .with("oidc.auth-server-url", "https://issuer.example/realms/app")
                .with("oidc.token.audience", "orders-api")
                .with(
                    "oidc.token.required-claims.\"resource_access/orders/roles\"",
                    "orders-admin",
                ),
        )
        .build();
    let config = OidcConfig::from_config(&config).expect("OIDC config should load");
    let token = jwt(CustomRoleClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        resource_access: ResourceAccessClaims {
            orders: ResourceRolesClaims {
                roles: vec!["orders-admin", "orders-user"],
            },
        },
    });

    let response = claims_subject_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build(),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
fn config_rejects_empty_required_claim_values() {
    let config = Config::builder()
        .add_source(
            MapSource::new("empty-required-claims", 100)
                .with("oidc.token.required-claims.scope", " , "),
        )
        .build();

    let error = OidcConfig::from_config(&config)
        .expect_err("empty required claim values should be rejected");

    assert!(
        error
            .to_string()
            .contains("oidc.token.required-claims.scope"),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .contains("required claims must include at least one expected value"),
        "{error}"
    );
}

#[test]
fn config_rejects_empty_token_audience() {
    let config = Config::builder()
        .add_source(MapSource::new("empty-token-audience", 100).with("oidc.token.audience", " , "))
        .build();

    let error =
        OidcConfig::from_config(&config).expect_err("empty token audience should be rejected");

    assert!(error.to_string().contains("oidc.token.audience"), "{error}");
    assert!(
        error
            .to_string()
            .contains("token audience must include at least one audience"),
        "{error}"
    );
}

#[test]
fn config_rejects_empty_token_type() {
    let config = Config::builder()
        .add_source(MapSource::new("empty-token-type", 100).with("oidc.token.token-type", " "))
        .build();

    let error = OidcConfig::from_config(&config).expect_err("empty token type should be rejected");

    assert!(
        error.to_string().contains("oidc.token.token-type"),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .contains("value must not be empty when configured"),
        "{error}"
    );
}

#[test]
fn config_rejects_empty_principal_claim() {
    let config = Config::builder()
        .add_source(
            MapSource::new("empty-principal-claim", 100).with("oidc.token.principal-claim", " "),
        )
        .build();

    let error =
        OidcConfig::from_config(&config).expect_err("empty principal claim should be rejected");

    assert!(
        error.to_string().contains("oidc.token.principal-claim"),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .contains("value must not be empty when configured"),
        "{error}"
    );
}

#[test]
fn config_rejects_malformed_principal_claim() {
    let config = Config::builder()
        .add_source(
            MapSource::new("malformed-principal-claim", 100)
                .with("oidc.token.principal-claim", "profile..email"),
        )
        .build();

    let error =
        OidcConfig::from_config(&config).expect_err("malformed principal claim should be rejected");

    assert!(
        error.to_string().contains("oidc.token.principal-claim"),
        "{error}"
    );
    assert!(error.to_string().contains("empty segments"), "{error}");
}

#[test]
fn config_rejects_malformed_required_claim_path() {
    let config = Config::builder()
        .add_source(MapSource::new("malformed-required-claim", 100).with(
            "oidc.token.required-claims.\"profile..email\"",
            "alice@example.com",
        ))
        .build();

    let error = OidcConfig::from_config(&config)
        .expect_err("malformed required claim path should be rejected");

    assert!(
        error.to_string().contains("oidc.token.required-claims"),
        "{error}"
    );
    assert!(error.to_string().contains("empty segments"), "{error}");
}

#[tokio::test]
async fn jwt_validator_rejects_missing_required_claim() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            required_claims: HashMap::from([("org_id".to_owned(), vec!["org_xyz".to_owned()])]),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(TestClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        groups: Vec::new(),
        realm_access: RealmAccessClaims { roles: Vec::new() },
    });

    let response = app(Oidc::builder(config.clone())
        .validator(JwtValidator::hs256("secret", &config))
        .build())
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_validator_rejects_missing_required_claim_value() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            required_claims: HashMap::from([(
                "scope".to_owned(),
                vec!["read".to_owned(), "write".to_owned()],
            )]),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(RequiredClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        org_id: "org_xyz",
        scope: vec!["read"],
        exp: 4_102_444_800,
    });

    let response = app(Oidc::builder(config.clone())
        .validator(JwtValidator::hs256("secret", &config))
        .build())
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_validator_accepts_expiry_within_lifespan_grace() {
    let now = unix_timestamp().expect("system time should be after epoch");
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            lifespan_grace: Some(5),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(TimeClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: now - 2,
        iat: now - 30,
    });

    let response = claims_subject_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build(),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwt_validator_rejects_token_older_than_configured_age() {
    let now = unix_timestamp().expect("system time should be after epoch");
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            age: Some(Duration::from_secs(5)),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(TimeClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: now + 60,
        iat: now - 30,
    });

    let response = app(Oidc::builder(config.clone())
        .validator(JwtValidator::hs256("secret", &config))
        .build())
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_validator_rejects_missing_iat_by_default() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt_without_iat(TestClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        groups: Vec::new(),
        realm_access: RealmAccessClaims { roles: Vec::new() },
    });

    let response = app(Oidc::builder(config.clone())
        .validator(JwtValidator::hs256("secret", &config))
        .build())
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_validator_accepts_missing_iat_when_not_required() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            issued_at_required: false,
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt_without_iat(TestClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        groups: Vec::new(),
        realm_access: RealmAccessClaims { roles: Vec::new() },
    });

    let response = app(Oidc::builder(config.clone())
        .validator(JwtValidator::hs256("secret", &config))
        .build())
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwt_validator_rejects_future_iat_beyond_lifespan_grace() {
    let now = unix_timestamp().expect("system time should be after epoch");
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            lifespan_grace: Some(5),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(TimeClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: now + 60,
        iat: now + 10,
    });

    let response = app(Oidc::builder(config.clone())
        .validator(JwtValidator::hs256("secret", &config))
        .build())
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_validator_rejects_missing_iat_when_token_age_is_configured() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            age: Some(Duration::from_secs(60)),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt_without_iat(TestClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        groups: Vec::new(),
        realm_access: RealmAccessClaims { roles: Vec::new() },
    });

    let response = app(Oidc::builder(config.clone())
        .validator(JwtValidator::hs256("secret", &config))
        .build())
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jwt_validator_rejects_wrong_issuer() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        ..OidcConfig::default()
    };
    let token = jwt(TestClaims {
        sub: "alice",
        iss: "https://other-issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        groups: Vec::new(),
        realm_access: RealmAccessClaims { roles: Vec::new() },
    });

    let response = app(Oidc::builder(config.clone())
        .validator(JwtValidator::hs256("secret", &config))
        .build())
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(WWW_AUTHENTICATE).unwrap(),
        HeaderValue::from_static(r#"Bearer error="invalid_token""#)
    );
}

#[tokio::test]
async fn jwt_validator_skips_issuer_validation_when_configured_any() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: Some("any".to_owned()),
            audience: Some("orders-api".to_owned()),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt(TestClaims {
        sub: "alice",
        iss: "https://other-issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        groups: vec!["admin"],
        realm_access: RealmAccessClaims { roles: Vec::new() },
    });

    let response = claims_subject_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::hs256("secret", &config))
            .build(),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwks_validator_selects_key_by_kid() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            token_type: None,
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let token = jwt_with_kid(
        "test-key",
        TestClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            exp: 4_102_444_800,
            groups: vec!["admin"],
            realm_access: RealmAccessClaims {
                roles: vec!["user"],
            },
        },
    );

    let response = claims_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::jwks(test_jwks(), &config))
            .build(),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn jwks_validator_rejects_unknown_kid() {
    let config = OidcConfig::default();
    let token = jwt_with_kid(
        "other-key",
        TestClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            exp: 4_102_444_800,
            groups: Vec::new(),
            realm_access: RealmAccessClaims { roles: Vec::new() },
        },
    );

    let response = app(Oidc::builder(config.clone())
        .validator(JwtValidator::jwks(test_jwks(), &config))
        .build())
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        response.headers().get(WWW_AUTHENTICATE).unwrap(),
        HeaderValue::from_static(r#"Bearer error="invalid_token""#)
    );
}

#[tokio::test]
async fn refreshable_jwks_fetches_when_kid_is_missing() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            token_type: None,
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let refreshed = rotated_jwks();
    let token = jwt_with_kid_and_secret(
        "rotated-key",
        b"rotated",
        TestClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            exp: 4_102_444_800,
            groups: vec!["admin"],
            realm_access: RealmAccessClaims {
                roles: vec!["user"],
            },
        },
    );

    let response = claims_app(
        Oidc::builder(config.clone())
            .validator(JwtValidator::refreshable_jwks(
                test_jwks(),
                move || {
                    let refreshed = refreshed.clone();
                    async move { Ok(refreshed) }
                },
                &config,
            ))
            .build(),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn refreshable_jwks_throttles_forced_refreshes() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        token: OidcTokenConfig {
            issuer: None,
            audience: Some("orders-api".to_owned()),
            token_type: None,
            forced_jwk_refresh_interval: Duration::from_secs(600),
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    };
    let refreshes = Arc::new(Mutex::new(0usize));
    let refreshed = rotated_jwks();
    let provider_refreshes = refreshes.clone();
    let validator = JwtValidator::refreshable_jwks(
        test_jwks(),
        move || {
            let refreshed = refreshed.clone();
            let provider_refreshes = provider_refreshes.clone();
            async move {
                let mut refreshes = provider_refreshes
                    .lock()
                    .expect("refresh counter should not be poisoned");
                *refreshes += 1;
                Ok(refreshed)
            }
        },
        &config,
    );
    let token = jwt_with_kid(
        "missing-key",
        TestClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            exp: 4_102_444_800,
            groups: Vec::new(),
            realm_access: RealmAccessClaims { roles: Vec::new() },
        },
    );

    for _ in 0..2 {
        let response = app(Oidc::builder(config.clone())
            .validator(validator.clone())
            .build())
        .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
        .await
        .expect("request should complete");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    assert_eq!(
        *refreshes
            .lock()
            .expect("refresh counter should not be poisoned"),
        1
    );
}

#[test]
fn discovery_url_appends_well_known_path() {
    assert_eq!(
        discovery_url(
            "https://issuer.example/realms/app",
            ".well-known/openid-configuration"
        )
        .expect("discovery URL should parse")
        .as_str(),
        "https://issuer.example/realms/app/.well-known/openid-configuration"
    );
    assert_eq!(
        discovery_url(
            "https://issuer.example/realms/app/",
            ".well-known/openid-configuration"
        )
        .expect("discovery URL should parse")
        .as_str(),
        "https://issuer.example/realms/app/.well-known/openid-configuration"
    );
    assert_eq!(
        discovery_url("https://issuer.example/realms/app", "custom-discovery")
            .expect("discovery URL should parse")
            .as_str(),
        "https://issuer.example/realms/app/custom-discovery"
    );
}

#[test]
fn provider_google_supplies_auth_server_url() {
    let config = OidcConfig {
        provider: Some(WellKnownProvider::Google),
        ..OidcConfig::default()
    };

    assert_eq!(
        auth_server_url_from_config(&config)
            .expect("google provider should supply auth-server-url")
            .as_str(),
        "https://accounts.google.com"
    );
    assert_eq!(
        discovery_url(
            auth_server_url_from_config(&config)
                .expect("google provider should supply auth-server-url")
                .as_str(),
            ".well-known/openid-configuration",
        )
        .expect("discovery URL should parse")
        .as_str(),
        "https://accounts.google.com/.well-known/openid-configuration"
    );
}

#[test]
fn explicit_auth_server_url_overrides_provider() {
    let config = OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        provider: Some(WellKnownProvider::Google),
        ..OidcConfig::default()
    };

    assert_eq!(
        auth_server_url_from_config(&config)
            .expect("explicit auth-server-url should be used")
            .as_str(),
        "https://issuer.example/realms/app"
    );
}

#[test]
fn unsupported_provider_requires_auth_server_url() {
    let config = OidcConfig {
        provider: Some(WellKnownProvider::Github),
        ..OidcConfig::default()
    };

    assert!(matches!(
        auth_server_url_from_config(&config),
        Err(BuildError::UnsupportedWellKnownProvider(
            WellKnownProvider::Github
        ))
    ));
    assert!(
        auth_server_url_from_config(&config)
            .expect_err("github provider should require explicit auth-server-url")
            .to_string()
            .contains("well-known OIDC provider `github` requires"),
    );
}

#[test]
fn provider_endpoint_url_supports_relative_and_absolute_paths() {
    assert_eq!(
        provider_endpoint_url(
            "https://issuer.example/realms/app",
            "/protocol/openid-connect/certs"
        )
        .expect("endpoint URL should parse")
        .as_str(),
        "https://issuer.example/realms/app/protocol/openid-connect/certs"
    );
    assert_eq!(
        provider_endpoint_url(
            "https://issuer.example/realms/app",
            "https://keys.example/jwks"
        )
        .expect("endpoint URL should parse")
        .as_str(),
        "https://keys.example/jwks"
    );
}

#[tokio::test]
async fn discovery_disabled_requires_jwks_path() {
    let result = Oidc::builder(OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        discovery_enabled: false,
        ..OidcConfig::default()
    })
    .discover()
    .await;
    let Err(error) = result else {
        panic!("disabled discovery requires jwks-path");
    };

    assert!(matches!(error, BuildError::MissingJwksPath));
}

#[tokio::test]
async fn discovery_disabled_requires_introspection_path_for_introspection_only() {
    let result = Oidc::builder(OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        discovery_enabled: false,
        token: OidcTokenConfig {
            require_jwt_introspection_only: true,
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    })
    .discover()
    .await;
    let Err(error) = result else {
        panic!("introspection-only discovery requires introspection-path");
    };

    assert!(matches!(error, BuildError::MissingIntrospectionEndpoint));
}

#[tokio::test]
async fn discovery_disabled_requires_user_info_path_for_user_info_validation() {
    let result = Oidc::builder(OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        discovery_enabled: false,
        token: OidcTokenConfig {
            verify_access_token_with_user_info: true,
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    })
    .discover()
    .await;
    let Err(error) = result else {
        panic!("UserInfo validation requires user-info-path");
    };

    assert!(matches!(error, BuildError::MissingUserInfoEndpoint));
}

#[tokio::test]
async fn discovery_disabled_requires_user_info_path_for_user_info_roles() {
    let result = Oidc::builder(OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        discovery_enabled: false,
        jwks_path: Some("certs".to_owned()),
        roles: OidcRolesConfig {
            source: RolesSource::UserInfo,
            ..OidcRolesConfig::default()
        },
        ..OidcConfig::default()
    })
    .discover()
    .await;
    let Err(error) = result else {
        panic!("UserInfo roles require user-info-path");
    };

    assert!(matches!(error, BuildError::MissingUserInfoEndpoint));
}

#[test]
fn provider_metadata_parses_oidc_discovery_document() {
    let metadata = ProviderMetadata::from_json(
            r#"{
                "issuer": "https://issuer.example/realms/app",
                "jwks_uri": "https://issuer.example/realms/app/protocol/openid-connect/certs",
                "authorization_endpoint": "https://issuer.example/realms/app/protocol/openid-connect/auth",
                "token_endpoint": "https://issuer.example/realms/app/protocol/openid-connect/token",
                "registration_endpoint": "https://issuer.example/realms/app/clients-registrations/openid-connect",
                "revocation_endpoint": "https://issuer.example/realms/app/protocol/openid-connect/revoke",
                "introspection_endpoint": "https://issuer.example/realms/app/protocol/openid-connect/token/introspect",
                "userinfo_endpoint": "https://issuer.example/realms/app/protocol/openid-connect/userinfo",
                "end_session_endpoint": "https://issuer.example/realms/app/protocol/openid-connect/logout"
            }"#,
        )
        .expect("provider metadata should parse");

    assert_eq!(
        metadata,
        ProviderMetadata {
            issuer: Some("https://issuer.example/realms/app".to_owned()),
            jwks_uri: "https://issuer.example/realms/app/protocol/openid-connect/certs".to_owned(),
            authorization_endpoint: Some(
                "https://issuer.example/realms/app/protocol/openid-connect/auth".to_owned(),
            ),
            token_endpoint: Some(
                "https://issuer.example/realms/app/protocol/openid-connect/token".to_owned(),
            ),
            registration_endpoint: Some(
                "https://issuer.example/realms/app/clients-registrations/openid-connect".to_owned(),
            ),
            revocation_endpoint: Some(
                "https://issuer.example/realms/app/protocol/openid-connect/revoke".to_owned(),
            ),
            introspection_endpoint: Some(
                "https://issuer.example/realms/app/protocol/openid-connect/token/introspect"
                    .to_owned(),
            ),
            userinfo_endpoint: Some(
                "https://issuer.example/realms/app/protocol/openid-connect/userinfo".to_owned(),
            ),
            end_session_endpoint: Some(
                "https://issuer.example/realms/app/protocol/openid-connect/logout".to_owned(),
            ),
        }
    );
}

#[test]
fn provider_metadata_json_requires_issuer() {
    let error = ProviderMetadata::from_json(r#"{"jwks_uri":"https://issuer.example/certs"}"#)
        .expect_err("discovery metadata without an issuer must be rejected");
    assert!(error.to_string().contains("requires a non-empty issuer"));
}

#[test]
fn supplied_provider_metadata_must_match_configured_issuer() {
    let result = Oidc::builder(OidcConfig {
        auth_server_url: Some("https://configured.example".to_owned()),
        ..OidcConfig::default()
    })
    .provider_metadata(test_metadata(), test_jwks());

    assert!(matches!(
        result,
        Err(BuildError::InvalidConfiguration { .. })
    ));
}

#[test]
fn supplied_provider_metadata_rejects_non_loopback_http_endpoints() {
    let mut metadata = test_metadata();
    metadata.jwks_uri = "http://issuer.example/certs".to_owned();

    let result = Oidc::builder(OidcConfig::default()).provider_metadata(metadata, test_jwks());
    assert!(matches!(result, Err(BuildError::InvalidUrl { .. })));
}

#[test]
fn loopback_http_provider_metadata_is_allowed_for_development() {
    let mut metadata = test_metadata();
    metadata.issuer = Some("http://127.0.0.1:8080".to_owned());
    metadata.jwks_uri = "http://127.0.0.1:8080/certs".to_owned();

    Oidc::builder(OidcConfig {
        auth_server_url: Some("http://127.0.0.1:8080".to_owned()),
        ..OidcConfig::default()
    })
    .provider_metadata(metadata, test_jwks())
    .expect("loopback HTTP should remain available for local development");
}

#[tokio::test]
async fn provider_metadata_installs_issuer_and_jwks_validator() {
    let token = jwt_with_kid(
        "test-key",
        TestClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            exp: 4_102_444_800,
            groups: vec!["admin"],
            realm_access: RealmAccessClaims {
                roles: vec!["user"],
            },
        },
    );

    let response = claims_app(
        Oidc::builder(OidcConfig {
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                token_type: None,
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        })
        .provider_metadata(test_metadata(), test_jwks())
        .expect("provider metadata should install validator"),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn provider_metadata_uses_introspection_when_required() {
    let token = jwt_with_kid(
        "test-key",
        TestClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            exp: 4_102_444_800,
            groups: vec!["admin"],
            realm_access: RealmAccessClaims {
                roles: vec!["user"],
            },
        },
    );

    let response = claims_app(
        Oidc::builder(OidcConfig {
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                token_type: None,
                require_jwt_introspection_only: true,
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        })
        .provider_metadata(test_introspection_metadata(), test_jwks())
        .expect("provider metadata should install introspection validator"),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn provider_metadata_uses_user_info_when_configured() {
    let token = jwt_with_kid(
        "test-key",
        TestClaims {
            sub: "alice",
            iss: "https://issuer.example/realms/app",
            aud: "orders-api",
            exp: 4_102_444_800,
            groups: vec!["admin"],
            realm_access: RealmAccessClaims {
                roles: vec!["user"],
            },
        },
    );

    let response = claims_app(
        Oidc::builder(OidcConfig {
            token: OidcTokenConfig {
                issuer: None,
                audience: Some("orders-api".to_owned()),
                token_type: None,
                verify_access_token_with_user_info: true,
                ..OidcTokenConfig::default()
            },
            ..OidcConfig::default()
        })
        .provider_metadata(test_user_info_metadata(), test_jwks())
        .expect("provider metadata should install UserInfo validator"),
    )
    .oneshot(request("/protected", Some(&format!("Bearer {token}"))))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn provider_metadata_requires_introspection_endpoint() {
    let result = Oidc::builder(OidcConfig {
        token: OidcTokenConfig {
            require_jwt_introspection_only: true,
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    })
    .provider_metadata(test_metadata(), test_jwks());

    assert!(matches!(
        result,
        Err(BuildError::MissingIntrospectionEndpoint)
    ));
}

#[test]
fn provider_metadata_requires_user_info_endpoint_for_validation() {
    let result = Oidc::builder(OidcConfig {
        token: OidcTokenConfig {
            verify_access_token_with_user_info: true,
            ..OidcTokenConfig::default()
        },
        ..OidcConfig::default()
    })
    .provider_metadata(test_metadata(), test_jwks());

    assert!(matches!(result, Err(BuildError::MissingUserInfoEndpoint)));
}

#[test]
fn provider_metadata_requires_user_info_endpoint_for_roles() {
    let result = Oidc::builder(OidcConfig {
        roles: OidcRolesConfig {
            source: RolesSource::UserInfo,
            ..OidcRolesConfig::default()
        },
        ..OidcConfig::default()
    })
    .provider_metadata(test_metadata(), test_jwks());

    assert!(matches!(result, Err(BuildError::MissingUserInfoEndpoint)));
}

#[test]
fn tenants_load_named_tenant_paths_from_config() {
    let config = Config::builder()
        .add_source(
            MapSource::new("tenants", 100)
                .with("oidc.tenant-paths", "/api/default")
                .with("oidc.tenant-a.tenant-paths", "/api/a/*")
                .with("oidc.tenant-a.provider", "google")
                .with("oidc.tenant-a.connection-timeout", "3s")
                .with("oidc.tenant-a.client-id", "tenant-a-client")
                .with("oidc.tenant-a.client-name", "Tenant A")
                .with("oidc.tenant-a.tenant-id", "orders")
                .with("oidc.tenant-b.tenant-enabled", "false")
                .with("oidc.tenant-b.tenant-paths", "/api/b/*"),
        )
        .build();

    assert_eq!(
        named_tenant_names(&config),
        vec!["tenant-a".to_owned(), "tenant-b".to_owned()]
    );

    let tenant_a = OidcConfig::from_config_prefix(&config, "oidc.tenant-a").unwrap();
    assert_eq!(tenant_a.tenant_paths, Some("/api/a/*".to_owned()));
    assert_eq!(tenant_a.provider, Some(WellKnownProvider::Google));
    assert_eq!(tenant_a.connection_timeout, Duration::from_secs(3));
    assert_eq!(tenant_a.client_id, Some("tenant-a-client".to_owned()));
    assert_eq!(tenant_a.client_name, Some("Tenant A".to_owned()));
    assert_eq!(tenant_a.tenant_id, Some("orders".to_owned()));
}

#[test]
fn tenants_from_config_rejects_empty_named_tenant_paths() {
    let config = Config::builder()
        .add_source(
            MapSource::new("empty-tenant-paths", 100).with("oidc.tenant-a.tenant-paths", " , "),
        )
        .build();

    let Err(error) = Tenants::from_config(&config) else {
        panic!("empty named tenant paths should be rejected");
    };

    assert!(
        error.to_string().contains("oidc.tenant-a.tenant-paths"),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .contains("tenant-paths must include at least one path"),
        "{error}"
    );
}

#[test]
fn tenants_load_quoted_named_tenant_config() {
    let config = Config::builder()
        .add_source(
            MapSource::new("quoted-tenants", 100)
                .with(r#"oidc."tenant.with.dot".tenant-paths"#, "/api/quoted/*")
                .with(r#"oidc."tenant.with.dot".client-id"#, "quoted-client")
                .with(
                    r#"oidc."tenant.with.dot".roles.role-claim-path"#,
                    "permissions",
                ),
        )
        .build();

    assert_eq!(
        named_tenant_names(&config),
        vec!["tenant.with.dot".to_owned()]
    );

    let tenant = OidcConfig::from_config_prefix(&config, r#"oidc."tenant.with.dot""#).unwrap();
    assert_eq!(tenant.tenant_paths, Some("/api/quoted/*".to_owned()));
    assert_eq!(tenant.client_id, Some("quoted-client".to_owned()));
    assert_eq!(tenant.roles.role_claim_path, "permissions");

    let _tenants = Tenants::from_config(&config)
        .expect("quoted tenant config should load")
        .build();
}

#[test]
fn tenants_from_config_rejects_named_id_token_roles_source() {
    let config = Config::builder()
        .add_source(
            MapSource::new("tenant-idtoken-roles", 100)
                .with("oidc.tenant-a.tenant-paths", "/api/a/*")
                .with("oidc.tenant-a.roles.source", "idtoken"),
        )
        .build();

    let Err(error) = Tenants::from_config(&config) else {
        panic!("ID token roles should be rejected for named bearer-service tenants");
    };
    assert!(matches!(
        error,
        mp_config::ConfigError::Conversion { ref name, .. }
            if name == "oidc.tenant-a.roles.source"
    ));
    assert!(
        error
            .to_string()
            .contains("`idtoken` roles require the `web-app` application type"),
        "{error}"
    );
}

#[test]
fn tenants_from_config_rejects_named_empty_role_claim_path() {
    let config = Config::builder()
        .add_source(
            MapSource::new("tenant-empty-role-claim-path", 100)
                .with("oidc.tenant-a.tenant-paths", "/api/a/*")
                .with("oidc.tenant-a.roles.role-claim-path", " , "),
        )
        .build();

    let Err(error) = Tenants::from_config(&config) else {
        panic!("empty role claim path should be rejected for named tenants");
    };
    assert!(
        error
            .to_string()
            .contains("oidc.tenant-a.roles.role-claim-path"),
        "{error}"
    );
    assert!(
        error
            .to_string()
            .contains("role-claim-path must include at least one claim path"),
        "{error}"
    );
}

#[test]
fn tenants_from_config_accepts_named_web_app_application_type() {
    let config = Config::builder()
        .add_source(
            MapSource::new("tenant-web-app", 100)
                .with("oidc.tenant-a.tenant-paths", "/api/a/*")
                .with("oidc.tenant-a.application-type", "web-app"),
        )
        .build();

    let _builder = Tenants::from_config(&config).expect("named web-app tenants should be accepted");
}

#[test]
fn tenants_from_config_rejects_named_refresh_token_time_skew_for_service() {
    let config = Config::builder()
        .add_source(
            MapSource::new("tenant-refresh-token-time-skew", 100)
                .with("oidc.tenant-a.tenant-paths", "/api/a/*")
                .with("oidc.tenant-a.token.refresh-token-time-skew", "15s"),
        )
        .build();

    let Err(error) = Tenants::from_config(&config) else {
        panic!("refresh-token-time-skew should be rejected for named bearer-service tenants");
    };
    assert!(matches!(
        error,
        mp_config::ConfigError::Conversion { ref name, .. }
            if name == "oidc.tenant-a.token.refresh-token-time-skew"
    ));
    assert!(
        error
            .to_string()
            .contains("`token.refresh-token-time-skew` requires the `web-app` application type"),
        "{error}"
    );
}

#[test]
fn tenants_from_config_rejects_named_token_binding_certificate() {
    let config = Config::builder()
        .add_source(
            MapSource::new("tenant-token-binding", 100)
                .with("oidc.tenant-a.tenant-paths", "/api/a/*")
                .with("oidc.tenant-a.token.binding.certificate", "true"),
        )
        .build();

    let Err(error) = Tenants::from_config(&config) else {
        panic!("certificate-bound tokens should be rejected for named bearer-service tenants");
    };
    assert!(matches!(
        error,
        mp_config::ConfigError::Conversion { ref name, .. }
            if name == "oidc.tenant-a.token.binding.certificate"
    ));
    assert!(
        error
            .to_string()
            .contains("requires client certificate thumbprint extraction"),
        "{error}"
    );
}

#[test]
fn tenants_from_config_rejects_named_decrypt_access_token() {
    let config = Config::builder()
        .add_source(
            MapSource::new("tenant-decrypt-access-token", 100)
                .with("oidc.tenant-a.tenant-paths", "/api/a/*")
                .with("oidc.tenant-a.token.decrypt-access-token", "true"),
        )
        .build();

    let Err(error) = Tenants::from_config(&config) else {
        panic!("encrypted access tokens should be rejected for named bearer-service tenants");
    };
    assert!(matches!(
        error,
        mp_config::ConfigError::Conversion { ref name, .. }
            if name == "oidc.tenant-a.token.decrypt-access-token"
    ));
    assert!(
        error
            .to_string()
            .contains("requires JWE access-token decryption"),
        "{error}"
    );
}

#[test]
fn tenants_detect_named_tenant_credentials_config() {
    let config = Config::builder()
        .add_source(
            MapSource::new("tenant-credentials", 100)
                .with("oidc.tenant-a.credentials.secret", "tenant-secret")
                .with("oidc.tenant-a.credentials.client-secret.method", "post"),
        )
        .build();

    assert_eq!(named_tenant_names(&config), vec!["tenant-a".to_owned()]);

    let tenant = OidcConfig::from_config_prefix(&config, "oidc.tenant-a")
        .expect("tenant credentials should load");
    assert_eq!(
        tenant.credentials,
        OidcCredentialsConfig {
            secret: Some("tenant-secret".to_owned()),
            client_secret: OidcClientSecretConfig {
                value: None,
                method: ClientSecretMethod::Post,
            },
        }
    );
}

#[test]
fn tenants_detect_named_tenant_introspection_credentials_config() {
    let config = Config::builder()
        .add_source(
            MapSource::new("tenant-introspection-credentials", 100)
                .with("oidc.tenant-a.introspection-credentials.name", "introspect")
                .with(
                    "oidc.tenant-a.introspection-credentials.secret",
                    "introspect-secret",
                ),
        )
        .build();

    assert_eq!(named_tenant_names(&config), vec!["tenant-a".to_owned()]);

    let tenant = OidcConfig::from_config_prefix(&config, "oidc.tenant-a")
        .expect("tenant introspection credentials should load");
    assert_eq!(
        tenant.introspection_credentials,
        OidcIntrospectionCredentialsConfig {
            name: Some("introspect".to_owned()),
            secret: Some("introspect-secret".to_owned()),
            include_client_id: true,
        }
    );
}

#[test]
fn tenants_detect_default_tenant_roles_config() {
    let config = Config::builder()
        .add_source(
            MapSource::new("tenant-roles", 100).with("oidc.roles.role-claim-path", "permissions"),
        )
        .build();

    let tenants = Tenants::from_config(&config)
        .expect("default tenant roles config should load")
        .build();
    let default_tenant = tenants
        .default_tenant
        .expect("roles config should create default tenant");

    assert_eq!(default_tenant.config.roles.role_claim_path, "permissions");
}

#[test]
fn tenants_detect_default_tenant_authentication_config() {
    let config = Config::builder()
        .add_source(
            MapSource::new("tenant-authentication", 100)
                .with("oidc.authentication.redirect-path", "/login/callback"),
        )
        .build();

    let tenants = Tenants::from_config(&config)
        .expect("default tenant authentication config should load")
        .build();
    let default_tenant = tenants
        .default_tenant
        .expect("authentication config should create default tenant");

    assert_eq!(
        default_tenant.config.authentication.redirect_path,
        "/login/callback"
    );
    assert!(named_tenant_names(&config).is_empty());
}

#[test]
fn tenants_detect_default_tenant_introspection_credentials_config() {
    let config = Config::builder()
        .add_source(
            MapSource::new("tenant-introspection-credentials", 100)
                .with("oidc.introspection-credentials.secret", "introspect-secret"),
        )
        .build();

    let tenants = Tenants::from_config(&config)
        .expect("default tenant introspection credentials config should load")
        .build();
    let default_tenant = tenants
        .default_tenant
        .expect("introspection credentials config should create default tenant");

    assert_eq!(
        default_tenant
            .config
            .introspection_credentials
            .secret
            .as_deref(),
        Some("introspect-secret")
    );
}

#[test]
fn tenants_load_tenant_id_header_from_config() {
    let config = Config::builder()
        .add_source(
            MapSource::new("tenant-header", 100)
                .with("oidc.tenant-id-header", "x-oidc-tenant")
                .with("oidc.tenant-a.tenant-id", "orders"),
        )
        .build();

    let tenants = Tenants::from_config(&config)
        .expect("tenant header config should load")
        .build();

    assert_eq!(
        tenants.header_name,
        Some(http::HeaderName::from_static("x-oidc-tenant"))
    );
}

#[test]
fn tenants_reject_invalid_tenant_id_header_from_config() {
    let config = Config::builder()
        .add_source(
            MapSource::new("tenant-header", 100).with("oidc.tenant-id-header", "not a header"),
        )
        .build();

    let error = match Tenants::from_config(&config) {
        Ok(_) => panic!("tenant header should be rejected"),
        Err(error) => error,
    };

    assert!(matches!(
        error,
        mp_config::ConfigError::Conversion { name, .. }
            if name == "oidc.tenant-id-header"
    ));
}

#[tokio::test]
async fn tenants_discover_from_config_builds_named_public_key_tenant() {
    let config = Config::builder()
        .add_source(
            MapSource::new("tenant-public-key-discovery", 100)
                .with("oidc.tenant-a.public-key", PUBLIC_RSA_KEY)
                .with(
                    "oidc.tenant-a.auth-server-url",
                    "https://issuer.example/realms/app",
                )
                .with("oidc.tenant-a.token.audience", "orders-api"),
        )
        .build();
    let token = jwt_rs256(TestClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/app",
        aud: "orders-api",
        exp: 4_102_444_800,
        groups: vec!["admin"],
        realm_access: RealmAccessClaims {
            roles: vec!["user"],
        },
    });

    let response = tenant_app(
        Tenants::discover_from_config(&config)
            .await
            .expect("public key tenant config should build without provider discovery"),
    )
    .oneshot(request(
        "/tenant-a/protected",
        Some(&format!("Bearer {token}")),
    ))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response_body(response).await, "alice");
}

#[tokio::test]
async fn tenants_select_by_most_specific_tenant_path() {
    let response = tenant_app(
        Tenants::builder()
            .default_tenant(static_tenant("default-token", "default"))
            .tenant(
                "tenant-a",
                static_tenant_with_paths("a-token", "tenant-a", "/api/a/*"),
            )
            .tenant(
                "tenant-b",
                static_tenant_with_paths("b-token", "tenant-b", "/api/a/special"),
            )
            .build(),
    )
    .oneshot(request("/api/a/special", Some("Bearer b-token")))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn tenants_select_named_tenant_from_first_path_segment() {
    let response = tenant_app(
        Tenants::builder()
            .default_tenant(static_tenant("default-token", "default"))
            .tenant("tenant-a", static_tenant("a-token", "tenant-a"))
            .tenant("tenant-b", static_tenant("b-token", "tenant-b"))
            .build(),
    )
    .oneshot(request("/tenant-b/bearer", Some("Bearer b-token")))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn tenants_select_by_header_before_path() {
    let response = tenant_app(
        Tenants::builder()
            .tenant_header(http::HeaderName::from_static("x-oidc-tenant"))
            .tenant(
                "tenant-a",
                static_tenant_with_paths("a-token", "tenant-a", "/api/a/*"),
            )
            .tenant(
                "tenant-b",
                static_tenant_with_paths("b-token", "tenant-b", "/api/b/*"),
            )
            .build(),
    )
    .oneshot(
        Request::builder()
            .uri("/api/a/resource")
            .header(AUTHORIZATION, "Bearer b-token")
            .header("x-oidc-tenant", "tenant-b")
            .body(Body::empty())
            .expect("request should be valid"),
    )
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn tenants_select_by_configured_tenant_id_header() {
    let response = tenant_app(
        Tenants::builder()
            .tenant_header(http::HeaderName::from_static("x-oidc-tenant"))
            .tenant(
                "tenant-a",
                static_tenant_with_id("a-token", "tenant-a", "orders"),
            )
            .tenant(
                "tenant-b",
                static_tenant_with_id("b-token", "tenant-b", "billing"),
            )
            .build(),
    )
    .oneshot(
        Request::builder()
            .uri("/unmatched")
            .header(AUTHORIZATION, "Bearer a-token")
            .header("x-oidc-tenant", "orders")
            .body(Body::empty())
            .expect("request should be valid"),
    )
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_body(response).await,
        "tenant-a",
        "tenant-id should select tenant-a"
    );
}

#[tokio::test]
async fn tenants_select_by_token_issuer_when_enabled() {
    let tenant_a_token = jwt(TestClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/a",
        aud: "orders-api",
        exp: 4_102_444_800,
        groups: vec![],
        realm_access: RealmAccessClaims { roles: vec![] },
    });
    let tenant_b_token = jwt(TestClaims {
        sub: "bob",
        iss: "https://issuer.example/realms/b",
        aud: "orders-api",
        exp: 4_102_444_800,
        groups: vec![],
        realm_access: RealmAccessClaims { roles: vec![] },
    });

    let response = tenant_app(
        Tenants::builder()
            .resolve_with_issuer(true)
            .tenant(
                "tenant-a",
                static_tenant_with_issuer(
                    &tenant_a_token,
                    "tenant-a",
                    "https://issuer.example/realms/a",
                ),
            )
            .tenant(
                "tenant-b",
                static_tenant_with_issuer(
                    &tenant_b_token,
                    "tenant-b",
                    "https://issuer.example/realms/b",
                ),
            )
            .build(),
    )
    .oneshot(request(
        "/unmatched",
        Some(&format!("Bearer {tenant_b_token}")),
    ))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_body(response).await,
        "tenant-b",
        "issuer should select tenant-b"
    );
}

#[tokio::test]
async fn tenants_select_by_token_issuer_with_configured_scheme() {
    let tenant_a_token = jwt(TestClaims {
        sub: "alice",
        iss: "https://issuer.example/realms/a",
        aud: "orders-api",
        exp: 4_102_444_800,
        groups: vec![],
        realm_access: RealmAccessClaims { roles: vec![] },
    });
    let tenant_b_token = jwt(TestClaims {
        sub: "bob",
        iss: "https://issuer.example/realms/b",
        aud: "orders-api",
        exp: 4_102_444_800,
        groups: vec![],
        realm_access: RealmAccessClaims { roles: vec![] },
    });

    let response = tenant_app(
        Tenants::builder()
            .resolve_with_issuer(true)
            .tenant(
                "tenant-a",
                static_tenant_with_issuer(
                    &tenant_a_token,
                    "tenant-a",
                    "https://issuer.example/realms/a",
                ),
            )
            .tenant(
                "tenant-b",
                Oidc::builder(OidcConfig {
                    auth_server_url: Some("https://issuer.example/realms/b".to_owned()),
                    token: OidcTokenConfig {
                        authorization_scheme: "Token".to_owned(),
                        ..OidcTokenConfig::default()
                    },
                    ..OidcConfig::default()
                })
                .validator(StaticTokenValidator::bearer(&tenant_b_token, "tenant-b"))
                .build(),
            )
            .build(),
    )
    .oneshot(request(
        "/unmatched",
        Some(&format!("Token {tenant_b_token}")),
    ))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_body(response).await,
        "tenant-b",
        "configured scheme should select tenant-b by issuer"
    );
}

#[tokio::test]
async fn tenants_select_by_token_issuer_with_configured_header() {
    let token = jwt(TestClaims {
        sub: "bob",
        iss: "https://issuer.example/realms/b",
        aud: "orders-api",
        exp: 4_102_444_800,
        groups: vec![],
        realm_access: RealmAccessClaims { roles: vec![] },
    });

    let response = tenant_app(
        Tenants::builder()
            .resolve_with_issuer(true)
            .tenant(
                "tenant-b",
                Oidc::builder(OidcConfig {
                    auth_server_url: Some("https://issuer.example/realms/b".to_owned()),
                    token: OidcTokenConfig {
                        header: "x-access-token".to_owned(),
                        ..OidcTokenConfig::default()
                    },
                    ..OidcConfig::default()
                })
                .validator(StaticTokenValidator::bearer(&token, "tenant-b"))
                .build(),
            )
            .build(),
    )
    .oneshot(request_with_header("/unmatched", "x-access-token", &token))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_body(response).await,
        "tenant-b",
        "configured token header should select tenant-b by issuer"
    );
}

#[tokio::test]
async fn tenant_header_takes_precedence_over_token_issuer() {
    let token = jwt(TestClaims {
        sub: "bob",
        iss: "https://issuer.example/realms/b",
        aud: "orders-api",
        exp: 4_102_444_800,
        groups: vec![],
        realm_access: RealmAccessClaims { roles: vec![] },
    });

    let response = tenant_app(
        Tenants::builder()
            .tenant_header(http::HeaderName::from_static("x-oidc-tenant"))
            .resolve_with_issuer(true)
            .tenant(
                "tenant-a",
                static_tenant_with_issuer(&token, "tenant-a", "https://issuer.example/realms/a"),
            )
            .tenant(
                "tenant-b",
                static_tenant_with_issuer(&token, "tenant-b", "https://issuer.example/realms/b"),
            )
            .build(),
    )
    .oneshot(
        Request::builder()
            .uri("/unmatched")
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .header("x-oidc-tenant", "tenant-a")
            .body(Body::empty())
            .expect("request should be valid"),
    )
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response_body(response).await,
        "tenant-a",
        "header should select tenant-a"
    );
}

#[tokio::test]
async fn tenants_preserve_disabled_tenant_behaviour() {
    let response = tenant_app(
        Tenants::builder()
            .tenant(
                "tenant-a",
                Oidc::builder(OidcConfig {
                    tenant_enabled: false,
                    tenant_paths: Some("/api/a/*".to_owned()),
                    ..OidcConfig::default()
                })
                .validator(StaticTokenValidator::bearer("a-token", "tenant-a"))
                .build(),
            )
            .build(),
    )
    .oneshot(request("/api/a/resource", Some("Bearer a-token")))
    .await
    .expect("request should complete");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn require_authenticated_layer_allows_principal() {
    let app = Router::new()
        .route("/protected", get(|| async { "ok" }))
        .route_layer(RequireAuthenticatedLayer::new())
        .layer(oidc().layer());

    let response = app
        .oneshot(request("/protected", Some("Bearer test-token")))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn require_authenticated_layer_rejects_missing_principal() {
    let app = Router::new()
        .route("/protected", get(|| async { "ok" }))
        .route_layer(RequireAuthenticatedLayer::new());

    let response = app
        .oneshot(request("/protected", None))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn require_roles_layer_allows_any_matching_role() {
    let app = Router::new()
        .route("/admin", get(|| async { "ok" }))
        .route_layer(RequireRolesLayer::any(["admin", "operator"]))
        .layer(
            Oidc::builder(OidcConfig::default())
                .validator(StaticTokenValidator::principal(
                    "test-token",
                    Principal::with_groups("alice", ["admin"]),
                ))
                .build()
                .layer(),
        );

    let response = app
        .oneshot(request("/admin", Some("Bearer test-token")))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn require_roles_layer_rejects_missing_role() {
    let app = Router::new()
        .route("/admin", get(|| async { "ok" }))
        .route_layer(RequireRolesLayer::any(["admin"]))
        .layer(
            Oidc::builder(OidcConfig::default())
                .validator(StaticTokenValidator::principal(
                    "test-token",
                    Principal::with_groups("alice", ["user"]),
                ))
                .build()
                .layer(),
        );

    let response = app
        .oneshot(request("/admin", Some("Bearer test-token")))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn require_roles_layer_requires_all_roles() {
    let app = Router::new()
        .route("/admin", get(|| async { "ok" }))
        .route_layer(RequireRolesLayer::all(["user", "admin"]))
        .layer(
            Oidc::builder(OidcConfig::default())
                .validator(StaticTokenValidator::principal(
                    "test-token",
                    Principal::with_groups("alice", ["user"]),
                ))
                .build()
                .layer(),
        );

    let response = app
        .oneshot(request("/admin", Some("Bearer test-token")))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn route_layer_authorization_preserves_unmatched_routes() {
    let app = Router::new()
        .route("/protected", get(|| async { "ok" }))
        .route_layer(RequireAuthenticatedLayer::new());

    let response = app
        .oneshot(request("/missing", None))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[test]
fn claim_path_parts_preserve_quoted_segments() {
    assert_eq!(
        claim_path_parts("resource_access.\"https://claims.example/roles\".roles"),
        vec![
            "resource_access".to_owned(),
            "https://claims.example/roles".to_owned(),
            "roles".to_owned()
        ]
    );
    assert_eq!(
        claim_path_parts("\"https://claims.example/roles\""),
        vec!["https://claims.example/roles".to_owned()]
    );
}

#[test]
fn claim_path_validation_rejects_ambiguous_paths() {
    for path in [
        "",
        "profile..email",
        ".email",
        "profile.",
        "profile.\"email",
    ] {
        assert!(
            validate_claim_path(path).is_err(),
            "{path:?} should be rejected"
        );
    }
}

fn oidc() -> Oidc {
    Oidc::builder(OidcConfig::default())
        .validator(StaticTokenValidator::bearer("test-token", "alice"))
        .build()
}

fn app(oidc: Oidc) -> Router {
    Router::new()
        .route(
            "/protected",
            get(|Extension(principal): Extension<Principal>| async move {
                principal.subject().to_owned()
            }),
        )
        .layer(oidc.layer())
}

fn public_app(oidc: Oidc) -> Router {
    Router::new()
        .route("/protected", get(|| async { "ok" }))
        .layer(oidc.layer())
}

fn tenant_app(tenants: Tenants) -> Router {
    Router::new()
        .fallback(|Extension(principal): Extension<Principal>| async move {
            principal.subject().to_owned()
        })
        .layer(tenants.layer())
}

fn static_tenant(token: &str, subject: &str) -> Oidc {
    Oidc::builder(OidcConfig::default())
        .validator(StaticTokenValidator::bearer(token, subject))
        .build()
}

fn static_tenant_with_paths(token: &str, subject: &str, paths: &str) -> Oidc {
    Oidc::builder(OidcConfig {
        tenant_paths: Some(paths.to_owned()),
        ..OidcConfig::default()
    })
    .validator(StaticTokenValidator::bearer(token, subject))
    .build()
}

fn static_tenant_with_id(token: &str, subject: &str, tenant_id: &str) -> Oidc {
    Oidc::builder(OidcConfig {
        tenant_id: Some(tenant_id.to_owned()),
        ..OidcConfig::default()
    })
    .validator(StaticTokenValidator::bearer(token, subject))
    .build()
}

fn static_tenant_with_issuer(token: &str, subject: &str, issuer: &str) -> Oidc {
    Oidc::builder(OidcConfig {
        auth_server_url: Some(issuer.to_owned()),
        ..OidcConfig::default()
    })
    .validator(StaticTokenValidator::bearer(token, subject))
    .build()
}

async fn response_body(response: Response) -> String {
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("response body should be readable");
    String::from_utf8(body.to_vec()).expect("response body should be UTF-8")
}

fn claims_app(oidc: Oidc) -> Router {
    Router::new()
        .route(
            "/protected",
            get(|Extension(principal): Extension<Principal>| async move {
                assert_eq!(principal.subject(), "alice");
                assert_eq!(
                    principal.issuer(),
                    Some("https://issuer.example/realms/app")
                );
                assert_eq!(principal.audience().collect::<Vec<_>>(), vec!["orders-api"]);
                assert_eq!(
                    principal.groups().collect::<Vec<_>>(),
                    vec!["admin", "user"]
                );
                "ok"
            }),
        )
        .layer(oidc.layer())
}

fn claims_subject_app(oidc: Oidc) -> Router {
    Router::new()
        .route(
            "/protected",
            get(|Extension(principal): Extension<Principal>| async move {
                assert_eq!(principal.subject(), "alice");
                "ok"
            }),
        )
        .layer(oidc.layer())
}

fn subject_app(oidc: Oidc, expected_subject: &'static str) -> Router {
    Router::new()
        .route(
            "/protected",
            get(
                move |Extension(principal): Extension<Principal>| async move {
                    assert_eq!(principal.subject(), expected_subject);
                    "ok"
                },
            ),
        )
        .layer(oidc.layer())
}

fn custom_roles_app(oidc: Oidc) -> Router {
    Router::new()
        .route(
            "/protected",
            get(|Extension(principal): Extension<Principal>| async move {
                assert_eq!(
                    principal.groups().collect::<Vec<_>>(),
                    vec!["orders-admin", "orders-user"]
                );
                "ok"
            }),
        )
        .layer(oidc.layer())
}

fn request(uri: &str, authorization: Option<&str>) -> Request<Body> {
    request_with_method(http::Method::GET, uri, authorization)
}

fn request_with_method(
    method: http::Method,
    uri: &str,
    authorization: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder().uri(uri);
    builder = builder.method(method);
    if let Some(authorization) = authorization {
        builder = builder.header(AUTHORIZATION, authorization);
    }
    builder
        .body(Body::empty())
        .expect("request should be valid")
}

fn request_with_header(uri: &str, header_name: &str, header_value: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header(header_name, header_value)
        .body(Body::empty())
        .expect("request should be valid")
}

fn cookie_header(response: &Response) -> String {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|value| value.split_once(';').map(|(cookie, _)| cookie.to_owned()))
        .collect::<Vec<_>>()
        .join("; ")
}

fn set_cookie_header(response: &Response, name: &str) -> Option<String> {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find(|value| value.starts_with(&format!("{name}=")))
        .map(ToOwned::to_owned)
}

fn cookie_attribute(cookie: &str, name: &str) -> Option<String> {
    cookie.split(';').skip(1).find_map(|attribute| {
        let attribute = attribute.trim();
        let (attribute_name, attribute_value) = attribute.split_once('=')?;
        attribute_name
            .eq_ignore_ascii_case(name)
            .then(|| attribute_value.to_owned())
    })
}

fn tamper_cookie_value(header: &str, name: &str) -> String {
    header
        .split("; ")
        .map(|cookie| {
            let Some((cookie_name, cookie_value)) = cookie.split_once('=') else {
                return cookie.to_owned();
            };
            if cookie_name == name {
                format!("{cookie_name}={cookie_value}a")
            } else {
                cookie.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}

fn redirect_state(response: &Response) -> String {
    let redirect = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect location should be present");
    reqwest::Url::parse(redirect)
        .expect("redirect location should parse")
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .expect("state should be present")
}

fn one_shot_token_endpoint(access_token: String, id_token: Option<String>) -> String {
    one_shot_token_endpoint_with_refresh(access_token, id_token, None, None)
}

fn one_shot_token_endpoint_with_refresh(
    access_token: String,
    id_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
) -> String {
    let body = token_response_body(
        &access_token,
        id_token.as_deref(),
        refresh_token.as_deref(),
        expires_in,
    );
    token_endpoint_sequence(vec![body]).0
}

fn token_endpoint_sequence(responses: Vec<String>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("token endpoint should bind");
    let endpoint = format!(
        "http://{}/token",
        listener
            .local_addr()
            .expect("token endpoint address should be available")
    );
    let forms = Arc::new(Mutex::new(Vec::new()));
    let captured_forms = forms.clone();
    std::thread::spawn(move || {
        use std::io::Write;

        for body in responses {
            let (mut stream, _) = listener
                .accept()
                .expect("token endpoint should accept a request");
            let request = read_http_request(&mut stream);
            let form = request
                .split_once("\r\n\r\n")
                .map(|(_, body)| body.to_owned())
                .unwrap_or_default();
            captured_forms
                .lock()
                .expect("captured forms should not be poisoned")
                .push(form);
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("token endpoint response should write");
        }
    });
    (endpoint, forms)
}

fn token_endpoint_request_sequence(responses: Vec<String>) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("token endpoint should bind");
    let endpoint = format!(
        "http://{}/token",
        listener
            .local_addr()
            .expect("token endpoint address should be available")
    );
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured_requests = requests.clone();
    std::thread::spawn(move || {
        use std::io::Write;

        for body in responses {
            let (mut stream, _) = listener
                .accept()
                .expect("token endpoint should accept a request");
            let request = read_http_request(&mut stream);
            captured_requests
                .lock()
                .expect("captured requests should not be poisoned")
                .push(request);
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("token endpoint response should write");
        }
    });
    (endpoint, requests)
}

fn token_response_body(
    access_token: &str,
    id_token: Option<&str>,
    refresh_token: Option<&str>,
    expires_in: Option<u64>,
) -> String {
    let id_token = id_token
        .map(|token| format!(r#","id_token":"{token}""#))
        .unwrap_or_default();
    let refresh_token = refresh_token
        .map(|token| format!(r#","refresh_token":"{token}""#))
        .unwrap_or_default();
    let expires_in = expires_in
        .map(|expires_in| format!(r#","expires_in":{expires_in}"#))
        .unwrap_or_default();
    format!(
        r#"{{"access_token":"{access_token}","token_type":"Bearer"{id_token}{refresh_token}{expires_in}}}"#
    )
}

fn read_http_request(stream: &mut std::net::TcpStream) -> String {
    use std::io::Read;

    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("test token endpoint should set read timeout");
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        let count = stream
            .read(&mut buffer)
            .expect("token endpoint request should read");
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
        let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
            continue;
        };
        let headers = String::from_utf8_lossy(&bytes[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or_default();
        if bytes.len() >= header_end + 4 + content_length {
            break;
        }
    }
    String::from_utf8(bytes).expect("token endpoint request should be UTF-8")
}

fn jwt(claims: impl Serialize) -> String {
    jwt_value(claims, true)
}

fn jwt_without_iat(claims: impl Serialize) -> String {
    jwt_value(claims, false)
}

fn jwt_with_header_type(token_type: &str, claims: impl Serialize) -> String {
    let header = Header {
        typ: Some(token_type.to_owned()),
        ..Default::default()
    };
    jwt_value_with_header(header, claims, true)
}

fn jwt_value(claims: impl Serialize, include_default_iat: bool) -> String {
    jwt_value_with_header(Header::default(), claims, include_default_iat)
}

fn jwt_value_with_header(
    header: Header,
    claims: impl Serialize,
    include_default_iat: bool,
) -> String {
    let mut claims = serde_json::to_value(claims).expect("test claims should serialize");
    if include_default_iat && let Value::Object(claims) = &mut claims {
        claims.entry("iat").or_insert_with(|| Value::from(TEST_IAT));
    }
    encode(&header, &claims, &EncodingKey::from_secret(b"secret"))
        .expect("test token should encode")
}

fn jwt_rs256(claims: impl Serialize) -> String {
    let mut claims = serde_json::to_value(claims).expect("test claims should serialize");
    if let Value::Object(claims) = &mut claims {
        claims.entry("iat").or_insert_with(|| Value::from(TEST_IAT));
    }
    encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(PRIVATE_RSA_KEY.as_bytes())
            .expect("test RSA private key should parse"),
    )
    .expect("test token should encode")
}

fn jwt_with_kid(kid: &str, claims: TestClaims<'_>) -> String {
    jwt_with_kid_and_secret(kid, b"secret", claims)
}

fn jwt_with_kid_and_secret(kid: &str, secret: &[u8], claims: impl Serialize) -> String {
    let header = Header {
        kid: Some(kid.to_owned()),
        ..Default::default()
    };
    let mut claims = serde_json::to_value(claims).expect("test claims should serialize");
    if let Value::Object(claims) = &mut claims {
        claims.entry("iat").or_insert_with(|| Value::from(TEST_IAT));
    }

    encode(&header, &claims, &EncodingKey::from_secret(secret)).expect("test token should encode")
}

fn test_jwks() -> JwkSet {
    serde_json::from_value(json!({
        "keys": [
            {
                "kty": "oct",
                "alg": "HS256",
                "kid": "test-key",
                "k": "c2VjcmV0"
            }
        ]
    }))
    .expect("test JWKS should parse")
}

fn rotated_jwks() -> JwkSet {
    serde_json::from_value(json!({
        "keys": [
            {
                "kty": "oct",
                "alg": "HS256",
                "kid": "rotated-key",
                "k": "cm90YXRlZA"
            }
        ]
    }))
    .expect("test JWKS should parse")
}

fn test_metadata() -> ProviderMetadata {
    ProviderMetadata {
        issuer: Some("https://issuer.example/realms/app".to_owned()),
        jwks_uri: "https://issuer.example/realms/app/certs".to_owned(),
        authorization_endpoint: None,
        token_endpoint: None,
        registration_endpoint: None,
        revocation_endpoint: None,
        introspection_endpoint: None,
        userinfo_endpoint: None,
        end_session_endpoint: None,
    }
}

fn test_introspection_metadata() -> ProviderMetadata {
    ProviderMetadata {
        introspection_endpoint: Some("http://127.0.0.1:1/introspect".to_owned()),
        ..test_metadata()
    }
}

fn test_user_info_metadata() -> ProviderMetadata {
    ProviderMetadata {
        userinfo_endpoint: Some("http://127.0.0.1:1/userinfo".to_owned()),
        ..test_metadata()
    }
}

#[derive(Serialize)]
struct TestClaims<'a> {
    sub: &'a str,
    iss: &'a str,
    aud: &'a str,
    exp: u64,
    groups: Vec<&'a str>,
    realm_access: RealmAccessClaims<'a>,
}

#[derive(Serialize)]
struct PrincipalClaims<'a> {
    sub: &'a str,
    iss: &'a str,
    aud: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    preferred_username: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upn: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<&'a str>,
    exp: u64,
}

#[derive(Serialize)]
struct NoSubjectClaims<'a> {
    iss: &'a str,
    aud: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    preferred_username: Option<&'a str>,
    exp: u64,
}

#[derive(Serialize)]
struct TokenTypeClaims<'a> {
    sub: &'a str,
    iss: &'a str,
    aud: &'a str,
    typ: &'a str,
    exp: u64,
}

#[derive(Serialize)]
struct RequiredClaims<'a> {
    sub: &'a str,
    iss: &'a str,
    aud: &'a str,
    org_id: &'a str,
    scope: Vec<&'a str>,
    exp: u64,
}

#[derive(Serialize)]
struct StringScopeClaims<'a> {
    sub: &'a str,
    iss: &'a str,
    aud: &'a str,
    scope: &'a str,
    exp: u64,
}

#[derive(Serialize)]
struct ProfilePrincipalClaims<'a> {
    sub: &'a str,
    iss: &'a str,
    aud: &'a str,
    profile: ProfileClaims<'a>,
    exp: u64,
}

#[derive(Serialize)]
struct ProfileClaims<'a> {
    email: &'a str,
}

#[derive(Serialize)]
struct TimeClaims<'a> {
    sub: &'a str,
    iss: &'a str,
    aud: &'a str,
    exp: u64,
    iat: u64,
}

#[derive(Serialize)]
struct RealmAccessClaims<'a> {
    roles: Vec<&'a str>,
}

#[derive(Serialize)]
struct CustomRoleClaims<'a> {
    sub: &'a str,
    iss: &'a str,
    aud: &'a str,
    exp: u64,
    resource_access: ResourceAccessClaims<'a>,
}

#[derive(Serialize)]
struct ClientResourceRoleClaims<'a> {
    sub: &'a str,
    iss: &'a str,
    aud: &'a str,
    exp: u64,
    resource_access: ClientResourceAccessClaims<'a>,
}

#[derive(Serialize)]
struct NamespacedRoleClaims<'a> {
    sub: &'a str,
    iss: &'a str,
    aud: &'a str,
    exp: u64,
    #[serde(rename = "https://claims.example/roles")]
    namespaced_roles: Vec<&'a str>,
}

#[derive(Serialize)]
struct StringRoleClaims<'a> {
    sub: &'a str,
    iss: &'a str,
    aud: &'a str,
    exp: u64,
    permissions: &'a str,
}

#[derive(Serialize)]
struct ResourceAccessClaims<'a> {
    orders: ResourceRolesClaims<'a>,
}

#[derive(Serialize)]
struct ClientResourceAccessClaims<'a> {
    #[serde(rename = "orders-service")]
    orders_service: ResourceRolesClaims<'a>,
}

#[derive(Serialize)]
struct ResourceRolesClaims<'a> {
    roles: Vec<&'a str>,
}

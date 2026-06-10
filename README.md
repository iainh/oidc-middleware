# oidc-middleware

`oidc-middleware` is an axum OIDC middleware crate inspired by the Quarkus OIDC
extension. It uses `mp-config` to load Quarkus-style `oidc.*`
configuration, can load Quarkus-style HTTP authorization policies, and exposes
a tower layer that protects axum routes with bearer-token authentication.

This crate is in early development. The current implementation includes:

- `OidcConfig` loaded from `oidc.*` properties, including
  `client-id`, `client-name`, and well-known `provider` values. `provider=google`
  supplies the Google issuer URL when `auth-server-url` is not configured.
  Other provider identifiers require an explicit `auth-server-url` until their
  issuer URLs are built in. `Oidc::from_config` also applies configured
  `quarkus.http.auth.permission.*` policies.
- Service and hybrid `oidc.application-type` bearer-token middleware,
  plus `web-app` authorization-code flow when built through provider discovery
  or explicit authorization and token endpoint configuration.
- Web-app session state is stored through `tower-sessions`; applications using
  `application-type=web-app` must install a `SessionManagerLayer` outside the
  OIDC layer.
- `Oidc::layer()` for protecting axum routers.
- request `Principal` extensions after successful authentication.
- pluggable bearer-token validation through `TokenValidator`.
- OIDC provider discovery from `auth-server-url` and discovered `jwks_uri`,
  including `oidc.discovery-path` and direct `jwks-path` loading when
  `oidc.discovery-enabled=false`. Provider HTTP clients created by the
  crate honour `oidc.connection-timeout`. Use
  `Oidc::discover_from_config` or `Tenants::discover_from_config` to load
  `mp-config` properties and build provider-backed middleware in one step.
- Quarkus-style endpoint path configuration for authorization, token,
  registration, revocation, introspection, user info, and end-session endpoints,
  plus parsing of the matching discovery metadata.
- Web-app browser authentication configuration with
  `oidc.authentication.redirect-path`,
  `oidc.authentication.restore-path-after-redirect`, and
  `oidc.authentication.scopes`. The scope list must include `openid`.
- Local JWT verification with `oidc.public-key`.
- Audience validation from one or more configured
  `oidc.token.audience` values.
- Quarkus `any` issuer and audience bypass values for providers with variable
  claims.
- Signature algorithm restrictions with
  `oidc.token.signature-algorithm`.
- JWT `typ` header or claim enforcement with `oidc.token.token-type`.
- Optional `sub` enforcement with `oidc.token.subject-required`.
- JWT string claim enforcement with `oidc.token.required-claims.*`,
  including nested claim paths through quoted map keys and space-separated
  string claim values such as `scope`.
- JWT lifespan grace and age checks with `oidc.token.lifespan-grace`
  and `oidc.token.age`, including
  `oidc.token.issued-at-required`.
- Principal-name selection with `oidc.token.principal-claim`,
  including nested claim paths.
- Token extraction with `oidc.token.header` and case-insensitive
  `oidc.token.authorization-scheme`, including matching challenge
  responses.
- Certificate-bound access-token configuration through
  `oidc.token.binding.certificate` is rejected until request client
  certificate thumbprints are supported.
- JWE token decryption configuration through
  `oidc.token.decrypt-access-token` and
  `oidc.token.decrypt-id-token` is rejected until token decryption is
  supported.
- Multi-tenant routing with `oidc.<tenant>.tenant-paths`, quoted tenant
  aliases, tenant IDs, static first-path-segment tenant selection, and optional
  header-based (`oidc.tenant-id-header`) or issuer-based tenant
  selection. `Tenants::from_config` applies the same configured HTTP
  authorization policies to each configured tenant.
- Refreshable provider JWKS validation when a token references an unknown `kid`,
  with `oidc.token.forced-jwk-refresh-interval` throttling.
- Quarkus token introspection configuration flags for JWT, opaque-token, and
  UserInfo validation modes.
- OAuth2 token introspection through `IntrospectionValidator`, custom
  `TokenIntrospector` implementations, or explicit HTTP introspection endpoint
  builder methods, plus provider-backed installation for
  `oidc.token.require-jwt-introspection-only` and fallback from JWKS
  validation when JWT or opaque-token introspection is enabled. HTTP
  introspection uses `oidc.client-id` with
  `oidc.credentials.secret` for Basic authentication by default, or
  form-post or query credentials with
  `oidc.credentials.client-secret.method`. Endpoint-specific
  introspection Basic credentials can be set with
  `oidc.introspection-credentials.*`.
- UserInfo-backed opaque-token validation through `UserInfoValidator`, custom
  `UserInfoProvider` implementations, or provider-backed installation for
  `oidc.token.verify-access-token-with-user-info`.
- HS256 and static JWKS validation with issuer, audience, groups, and Keycloak
  realm roles.
- Configurable role extraction with `oidc.roles.role-claim-path`,
  including quoted namespace paths and default Keycloak
  `resource_access/<client-id>/roles` support, plus
  `oidc.roles.role-claim-separator` and access-token or UserInfo
  role sources with `oidc.roles.source`.
- Quarkus-style `quarkus.http.auth.permission.*` path policies for `permit`,
  `deny`, `authenticated`, named `roles-allowed` policies including the `**`
  authenticated role, method-specific matches, `quarkus.http.root-path`
  relative path handling, exact trailing-slash matching, segment wildcards,
  method-mismatch rejection, simultaneous winning role policies, disabled or
  shared permission entries, and global or policy-local role mappings.
- `#[roles_allowed(...)]` and `#[authenticated]` handler macros for
  Quarkus-style authorization checks with the `OidcPrincipal` extractor,
  including `**` for any authenticated principal.
- Quarkus-style handling for disabled OIDC and disabled tenants.

```rust
use axum::{Router, routing::get};
use oidc_middleware::{Oidc, OidcConfig, StaticTokenValidator};

let oidc = Oidc::builder(OidcConfig::default())
    .validator(StaticTokenValidator::bearer("dev-token", "alice"))
    .build();

let app = Router::new()
    .route("/protected", get(|| async { "ok" }))
    .layer(oidc.layer());
```

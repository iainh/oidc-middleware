# oidc-middleware

`oidc-middleware` is an axum OIDC middleware crate inspired by the Quarkus OIDC
extension. It uses `mp-config` to load Quarkus-style `quarkus.oidc.*`
configuration, can load Quarkus-style HTTP authorization policies, and exposes
a tower layer that protects axum routes with bearer-token authentication.

This crate is in early development. The current implementation includes:

- `OidcConfig` loaded from `quarkus.oidc.*` properties, with `Oidc::from_config`
  also applying configured `quarkus.http.auth.permission.*` policies.
- `Oidc::layer()` for protecting axum routers.
- request `Principal` extensions after successful authentication.
- pluggable bearer-token validation through `TokenValidator`.
- OIDC provider discovery from `auth-server-url` and discovered `jwks_uri`,
  including `quarkus.oidc.discovery-path` and direct `jwks-path` loading when
  `quarkus.oidc.discovery-enabled=false`.
- Quarkus-style endpoint path configuration for authorization, token,
  registration, revocation, introspection, user info, and end-session endpoints,
  plus parsing of the matching discovery metadata.
- Local JWT verification with `quarkus.oidc.public-key`.
- Audience validation from one or more configured
  `quarkus.oidc.token.audience` values.
- Quarkus `any` issuer and audience bypass values for providers with variable
  claims.
- Signature algorithm restrictions with
  `quarkus.oidc.token.signature-algorithm`.
- JWT `typ` header or claim enforcement with `quarkus.oidc.token.token-type`.
- Optional `sub` enforcement with `quarkus.oidc.token.subject-required`.
- JWT string claim enforcement with `quarkus.oidc.token.required-claims.*`,
  including nested claim paths through quoted map keys and space-separated
  string claim values such as `scope`.
- JWT lifespan grace and age checks with `quarkus.oidc.token.lifespan-grace`
  and `quarkus.oidc.token.age`, including
  `quarkus.oidc.token.issued-at-required`.
- Principal-name selection with `quarkus.oidc.token.principal-claim`,
  including nested claim paths.
- Token extraction with `quarkus.oidc.token.header` and case-insensitive
  `quarkus.oidc.token.authorization-scheme`, including matching challenge
  responses.
- Multi-tenant routing with `quarkus.oidc.<tenant>.tenant-paths`, quoted tenant
  aliases, tenant IDs, static first-path-segment tenant selection, and optional
  header-based (`quarkus.oidc.tenant-id-header`) or issuer-based tenant
  selection. `Tenants::from_config` applies the same configured HTTP
  authorization policies to each configured tenant.
- Refreshable provider JWKS validation when a token references an unknown `kid`,
  with `quarkus.oidc.token.forced-jwk-refresh-interval` throttling.
- Quarkus token introspection configuration flags for JWT, opaque-token, and
  UserInfo validation modes.
- OAuth2 token introspection through `IntrospectionValidator`, custom
  `TokenIntrospector` implementations, or explicit HTTP introspection endpoint
  builder methods, plus provider-backed installation for
  `quarkus.oidc.token.require-jwt-introspection-only` and fallback from JWKS
  validation when JWT or opaque-token introspection is enabled. HTTP
  introspection uses `quarkus.oidc.client-id` with
  `quarkus.oidc.credentials.secret` for Basic authentication by default, or
  form-post or query credentials with
  `quarkus.oidc.credentials.client-secret.method`. Endpoint-specific
  introspection Basic credentials can be set with
  `quarkus.oidc.introspection-credentials.*`.
- UserInfo-backed opaque-token validation through `UserInfoValidator`, custom
  `UserInfoProvider` implementations, or provider-backed installation for
  `quarkus.oidc.token.verify-access-token-with-user-info`.
- HS256 and static JWKS validation with issuer, audience, groups, and Keycloak
  realm roles.
- Configurable role extraction with `quarkus.oidc.roles.role-claim-path`,
  including quoted namespace paths and default Keycloak
  `resource_access/<client-id>/roles` support, plus
  `quarkus.oidc.roles.role-claim-separator` and
  `quarkus.oidc.roles.source`.
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

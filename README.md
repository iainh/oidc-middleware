# oidc-middleware

`oidc-middleware` is an axum OIDC middleware crate inspired by the Quarkus OIDC
extension. It uses `mp-config` to load Quarkus-style `quarkus.oidc.*`
configuration and exposes a tower layer that protects axum routes with bearer
token authentication.

This crate is in early development. The current implementation includes:

- `OidcConfig` loaded from `quarkus.oidc.*` properties.
- `Oidc::layer()` for protecting axum routers.
- request `Principal` extensions after successful authentication.
- pluggable bearer-token validation through `TokenValidator`.
- OIDC provider discovery from `auth-server-url` and discovered `jwks_uri`.
- Audience validation from one or more `quarkus.oidc.token.audience` values,
  defaulting to `quarkus.oidc.client-id` when present.
- Quarkus `any` issuer and audience bypass values for providers with variable
  claims.
- Signature algorithm restrictions with
  `quarkus.oidc.token.signature-algorithm`.
- JWT `typ` claim enforcement with `quarkus.oidc.token.token-type`.
- Optional `sub` enforcement with `quarkus.oidc.token.subject-required`.
- JWT string claim enforcement with `quarkus.oidc.token.required-claims.*`.
- JWT lifespan grace and age checks with `quarkus.oidc.token.lifespan-grace`
  and `quarkus.oidc.token.age`.
- Principal-name selection with `quarkus.oidc.token.principal-claim`.
- Token extraction with `quarkus.oidc.token.header` and
  `quarkus.oidc.token.authorization-scheme`.
- Multi-tenant routing with `quarkus.oidc.<tenant>.tenant-paths` and optional
  header-based tenant selection.
- Refreshable provider JWKS validation when a token references an unknown `kid`.
- HS256 and static JWKS validation with issuer, audience, groups, and Keycloak
  realm roles.
- Configurable role extraction with `quarkus.oidc.roles.role-claim-path` and
  `quarkus.oidc.roles.role-claim-separator`.
- Quarkus-style `quarkus.http.auth.permission.*` path policies for `permit`,
  `deny`, `authenticated`, named `roles-allowed` policies, method-specific
  matches, method-mismatch rejection, and disabled or shared permission entries.
- `#[roles_allowed(...)]` handler macro for Quarkus-style role checks with the
  `OidcPrincipal` extractor.
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

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
- HS256 and static JWKS validation with issuer, audience, groups, and Keycloak
  realm roles.
- Quarkus-style `quarkus.http.auth.permission.*` path policies for `permit`,
  `deny`, `authenticated`, and named `roles-allowed` policies.
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

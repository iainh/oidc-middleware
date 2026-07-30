# oidc-middleware

`oidc-middleware` is an experimental OpenID Connect (OIDC) middleware library for
Axum applications. It is inspired by the Quarkus OIDC extension: keep provider
configuration declarative, predictable, and close to the familiar `oidc.*`
property model, while expressing authorization in idiomatic Rust with Axum
routes, Tower layers, extractors, and optional handler macros.

The goal is to make common OIDC setups feel straightforward without hiding the
security decisions that Rust application developers usually want to own.

## Project status

This project is experimental and not yet a security-audited authentication
library. You should review the implementation, configuration model, dependency
set, and threat assumptions before using it in production. The onus is on each
application developer to decide whether the crate meets their security,
compliance, operational, and provider-compatibility requirements.

## What it provides

- Axum and Tower middleware for protecting routers and routes.
- Quarkus-inspired `oidc.*` configuration through `mp-config`.
- Bearer-token authentication for service APIs.
- Browser `web-app` authorization-code flow with encrypted redirect-state and
  token-state cookies, plus nonce-bound ID-token validation.
- Web-app callback and logout route helpers for authorization-code flow
  completion and RP-initiated logout.
- Static public-key, JWKS, refreshable JWKS, introspection, and UserInfo-backed
  validation options.
- Multi-tenant OIDC routing by path, tenant ID header, or token issuer.
- Route-local authorization with `RequireAuthenticatedLayer` and
  `RequireRolesLayer`.
- Optional `#[authenticated]` and `#[roles_allowed]` handler macros.
- Application-specific identity extractors that can derive authorization and
  conversion from the OIDC principal or web session.
- Feature flags for applications that want to reduce dependency and exploit
  surface.

## Quick start

For tests, examples, and local development, you can inject a custom token
validator and protect only the routes that require identity:

```rust
use axum::{Router, routing::get};
use oidc_middleware::{Oidc, OidcConfig, RequireRolesLayer, StaticTokenValidator};

let oidc = Oidc::builder(OidcConfig::default())
    .validator(StaticTokenValidator::bearer("dev-token", "alice"))
    .build();

let protected = Router::new()
    .route(
        "/orders",
        get(|| async { "ok" }).route_layer(RequireRolesLayer::any([
            "orders-user",
            "orders-admin",
        ])),
    )
    .layer(oidc.layer());

let app = Router::new()
    .route("/health", get(|| async { "ok" }))
    .merge(protected);
```

Provider-backed applications usually start from `Oidc::from_config`,
`Oidc::discover_from_config`, or `Tenants::discover_from_config`, then apply the
resulting layer to the protected part of the router.

## Examples

Start with the focused examples in [`examples/`](examples/). They are intended
to be easier to evaluate than a single large demo application.

- [`bearer_service.rs`](examples/bearer_service.rs): Protect an Axum API with
  bearer-token authentication.
- [`route_authorization.rs`](examples/route_authorization.rs): Apply
  `RequireAuthenticatedLayer` and `RequireRolesLayer` at route boundaries.
- [`handler_macros.rs`](examples/handler_macros.rs): Use `#[authenticated]`,
  `#[roles_allowed]`, and a derived application-specific user extractor on
  handlers.
- [`mp_config.rs`](examples/mp_config.rs): Load `oidc.*` settings through
  `mp-config`.
- [`provider_discovery.rs`](examples/provider_discovery.rs): Build JWKS-backed
  JWT validation from provider discovery.
- [`local_public_key.rs`](examples/local_public_key.rs): Validate JWTs with an
  out-of-band public key.
- [`introspection.rs`](examples/introspection.rs): Validate opaque tokens with
  token introspection.
- [`user_info.rs`](examples/user_info.rs): Validate bearer tokens through
  UserInfo.
- [`web_app.rs`](examples/web_app.rs): Configure browser login with encrypted
  redirect-state and token-state cookies; web-app handlers can extract
  `OidcSession` to access the principal and validated ID token claims.
- [`multi_tenant.rs`](examples/multi_tenant.rs): Select tenant-specific OIDC
  middleware by path.

## Quarkus inspiration, Rust shape

Quarkus is the main design reference for configuration. This crate follows the
same broad vocabulary, including settings such as `oidc.auth-server-url`,
`oidc.client-id`, `oidc.application-type`, `oidc.roles.*`, and `oidc.token.*`.

The runtime shape is intentionally Rust-oriented. Authentication is a Tower
layer. Authorization is applied where Axum developers expect to see it: on the
route, router, or handler being protected. Public routes should usually stay
outside `Oidc::layer`; protected routes fail closed when credentials are missing
or rejected.

## Application identity

Handlers can extract the library-provided `OidcPrincipal` directly:

```rust
use oidc_middleware::{Error, OidcPrincipal};

async fn profile(principal: OidcPrincipal) -> Result<String, Error> {
    Ok(format!("profile for {}", principal.subject()))
}
```

For larger applications, prefer an application-specific extractor so handler
signatures use your domain language. With the `macros` feature enabled, derive
`OidcAuthorize` and `FromOidcPrincipal` for bearer-token routes:

```rust
use oidc_middleware::{FromOidcPrincipal, OidcAuthorize, Principal};

#[derive(Clone, OidcAuthorize, FromOidcPrincipal)]
struct User {
    #[oidc(principal)]
    principal: Principal,
    #[oidc(subject)]
    account_id: String,
}
```

The handler macros can then authorize against that local type:

```rust
use oidc_middleware::{Error, roles_allowed};

#[roles_allowed("admin", principal = user)]
async fn account(user: User) -> Result<String, Error> {
    Ok(format!("account {}", user.account_id))
}
```

For browser `web-app` flows, extract `OidcSession` when the handler needs both
the access-token principal and the validated ID token:

```rust
use oidc_middleware::{Error, OidcSession};

async fn dashboard(session: OidcSession) -> Result<String, Error> {
    let email = session
        .id_token()
        .and_then(|token| token.claim("email"))
        .and_then(|claim| claim.as_str())
        .unwrap_or(session.subject());

    Ok(format!("dashboard for {email}"))
}
```

If you want the same domain-style handler signatures for browser routes, derive
`FromOidcSession` and map selected ID token claims into your own type:

```rust
use oidc_middleware::{FromOidcSession, IdToken, OidcAuthorize, Principal};

#[derive(Clone, OidcAuthorize, FromOidcSession)]
struct WebUser {
    #[oidc(principal)]
    principal: Principal,
    #[oidc(subject)]
    account_id: String,
    #[oidc(id_token)]
    id_token: Option<IdToken>,
    #[oidc(id_token_claim = "email")]
    email: Option<String>,
}
```

This keeps OIDC mechanics at the edge of the application while letting route
handlers receive the identity shape the rest of the codebase understands.

Add the OIDC-owned web-app routes outside the protected OIDC layer so callback
and logout can complete without passing through the protected application layer:

```rust
use axum::{Router, routing::get};
use oidc_middleware::Oidc;

# fn app(oidc: Oidc) -> Router {
let protected = Router::new()
    .route("/", get(|| async { "ok" }))
    .layer(oidc.clone().layer());

Router::new()
    .merge(oidc.routes())
    .merge(protected)
# }
```

For `web-app` and `hybrid` applications, `Oidc::routes()` registers the
configured callback path and logout path. For `service` applications, it returns
an empty router. Logout is a state-changing `POST`; forms or clients must send a
POST request with the current web-app session cookie. The route rejects `GET`
and requests without a valid encrypted token-state cookie, using that
`SameSite=Lax` cookie as a practical CSRF credential before it clears the
token-state and redirect-state cookies. If provider discovery or `oidc.end-session-path`
supplies an end-session endpoint, the route redirects there with
`id_token_hint`, the configured post-logout redirect parameter, and any
configured extra logout parameters.

## Configuration highlights

The current implementation supports:

- Service and hybrid `oidc.application-type` bearer-token middleware.
- Browser `web-app` login routes with `Oidc::routes()` when provider discovery
  or explicit authorization and token endpoints are configured.
- Nonce-bound ID-token validation for browser login, enabled by default; set
  `oidc.authentication.nonce-required=false` only for incompatible providers.
- Query/GET callbacks by default. Set
  `oidc.authentication.response-mode=form_post` to request an OIDC form-post
  response; the callback then accepts only a bounded
  `application/x-www-form-urlencoded` POST and uses a transient
  `SameSite=None; Secure` correlation cookie.
- Browser `web-app` logout with Quarkus-style `oidc.logout.path`,
  `oidc.logout.post-logout-path`, `oidc.logout.post-logout-uri-param`, and
  `oidc.logout.extra-params.*` settings. Logout endpoints accept only `POST`
  with a valid local token-state cookie; use a POST form rather than a link.
- Absolute `oidc.authentication.redirect-path` values for deployments where
  the public callback origin differs from the direct request origin.
- Forwarding headers are ignored when callback and post-logout URIs are built
  by default. Set `oidc.authentication.trust-forwarded-headers=true` only behind
  a trusted proxy that strips client-supplied `Forwarded` and `X-Forwarded-*`
  headers; otherwise configure an absolute redirect/post-logout URI. Direct
  `Host` headers and absolute request URI authorities remain supported.
- OIDC provider discovery from `oidc.auth-server-url` and discovered `jwks_uri`.
- Direct `oidc.jwks-path` loading when `oidc.discovery-enabled=false`.
- Local JWT verification with `oidc.public-key`.
- Audience, issuer, token type, subject, required-claim, token-age, and
  signature-algorithm checks.
- Configurable principal-name and role extraction, including Keycloak-style
  resource roles.
- Token introspection for opaque-token and fallback validation modes.
- UserInfo-backed token validation and UserInfo-backed role loading.
- Disabled-OIDC and disabled-tenant behaviour modelled after Quarkus.

Unsupported or intentionally rejected settings include certificate-bound access
tokens and JWE token decryption. Those configuration values currently fail at
startup rather than pretending to enforce unsupported security controls.

## Feature flags

Default features preserve the full convenience API:

```toml
[dependencies]
oidc-middleware = { version = "0.9.0" }
```

Applications that provide their own validators can opt into a smaller dependency
surface:

```toml
[dependencies]
oidc-middleware = { version = "0.9.0", default-features = false }
```

Available features:

- `http-client`: Enables `reqwest`-backed provider discovery, HTTP
  introspection, HTTP UserInfo, and remote JWKS loading.
- `jwt`: Enables `jsonwebtoken`, `JwtValidator`, JWKS support, and static
  public-key validation.
- `macros`: Enables the optional handler authorization macros.
- `native-tls`: Enables the platform-native TLS backend for `reqwest`.
- `rustls`: Enables the rustls TLS backend for `reqwest`; this is included in
  the default features.
- `rustls-native-certs`: Enables the rustls TLS backend with platform-native
  certificate roots.
- `web-app`: Enables browser login support with encrypted redirect-state and
  token-state cookies; this also enables `http-client` and `jwt`.

With `default-features = false`, the crate keeps the Axum middleware, config
model, route authorization layers, custom validator traits, introspection model,
and UserInfo model, while avoiding the optional HTTP client, TLS, JWT, proc
macro, cookie, random-state, and URL-parsing stacks.

When enabling `http-client` or `web-app` without default features, also enable
one TLS backend for HTTPS provider calls:

```toml
[dependencies]
oidc-middleware = { version = "0.9.0", default-features = false, features = ["web-app", "rustls-native-certs"] }
```

## Design guidance

A typical API should:

1. Load or construct `OidcConfig`.
2. Install a validator with provider discovery, a static key, introspection,
   UserInfo, or a custom `TokenValidator`.
3. Apply `Oidc::layer()` only to protected routes.
4. Use `RequireAuthenticatedLayer`, `RequireRolesLayer`, or handler macros for
   authorization.
5. Merge `Oidc::routes()` outside protected routers for web-app callback and
   logout endpoints.

This keeps provider setup declarative while keeping authorization visible in the
Axum router.

## Licence

Licensed under either of:

- Apache License, Version 2.0
- MIT licence

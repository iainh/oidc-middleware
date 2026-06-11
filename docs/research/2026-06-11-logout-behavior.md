# Research: Logout Behaviour

**Date**: 2026-06-11
**Question**: How does logout work with this middleware? Is there a batteries-included logout endpoint?
**Status**: Complete

## Findings

### Web-app session state is cookie-backed

The web-app middleware stores authenticated browser state in the encrypted `q_oidc` cookie and redirect flow state in `q_oidc_redirect`. The callback handler validates the code flow response, clears redirect state, and stores token state in `q_oidc`.

References:

- `src/web_app.rs:21`
- `src/web_app.rs:300`
- `src/web_app.rs:330`

### Session cleanup exists, but only as internal invalidation

The middleware clears `q_oidc` when the cookie cannot be decrypted, when token refresh fails, when refreshed tokens are rejected, or when token state expires without usable refresh. Clearing is implemented by setting `Max-Age=0` on the cookie.

References:

- `src/web_app.rs:160`
- `src/web_app.rs:198`
- `src/web_app.rs:220`
- `src/web_app.rs:234`
- `src/web_app.rs:240`
- `src/web_app.rs:751`

### No built-in logout route is installed

The web-app request path only special-cases the configured callback path. Otherwise it restores a session from `q_oidc` or redirects to the authorization endpoint. There is no branch for logout, signout, revoke, or provider end-session.

References:

- `src/oidc.rs:203`
- `src/oidc.rs:214`
- `src/oidc.rs:249`

### End-session metadata is parsed but not used

Configuration includes `oidc.end-session-path`, and discovery metadata includes `end_session_endpoint`. However, web-app construction only accepts authorization and token endpoints. The metadata installer passes only `authorization_endpoint` and `token_endpoint` into `WebApp::from_provider_metadata`.

References:

- `src/config.rs:92`
- `src/provider.rs:34`
- `src/web_app.rs:68`
- `src/oidc.rs:976`

## Original Conclusion

There is no batteries-included logout endpoint today. Applications need to provide their own route if they want logout behaviour. The middleware currently has the primitives internally to clear the local token-state cookie, but they are private and only used on failed or expired session restoration. Provider logout via `end_session_endpoint` is not wired into runtime behaviour.

## Practical Implication

A complete logout feature would likely need to expose a web-app logout path that clears `q_oidc`, optionally clears `q_oidc_redirect`, and optionally redirects to the provider `end_session_endpoint` with provider-specific parameters such as `id_token_hint` and `post_logout_redirect_uri`.

## Implementation Follow-up

The middleware now exposes `Oidc::logout_route()` and `Oidc::logout_route_with_options(...)` for applications to add a logout endpoint to their router. The route should be added outside `Oidc::layer`.

Implemented behaviour:

- Clears `q_oidc`.
- Clears `q_oidc_redirect`.
- Uses discovered or configured `end_session_endpoint` when present.
- Adds `id_token_hint` from the stored raw ID token when available.
- Adds `post_logout_redirect_uri` from `OidcLogoutOptions::post_logout_redirect`.
- Falls back to a local redirect when no provider end-session endpoint is available.

References:

- `src/oidc.rs`
- `src/web_app.rs`
- `src/tests.rs`
- `examples/web_app.rs`

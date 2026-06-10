# Research: Web-App Token Refresh

**Date**: 2026-06-10
**Question**: Does the Axum web-app flow refresh OIDC tokens, and how does it compare with Quarkus OIDC?
**Status**: Complete

## Context

The crate intentionally mirrors Quarkus-style OIDC configuration. The question is whether the browser `web-app` authorization-code flow includes Quarkus-like session refresh behaviour.

## Findings

### Current Web-App Flow

The local web-app flow implements the initial authorization-code exchange and session restoration:

- `WebApp::authorization_redirect` stores `state` and optional original URI, then redirects with `response_type=code`, `client_id`, `redirect_uri`, `scope`, and `state`.
- `WebApp::callback` validates `state`, exchanges the authorization code at the token endpoint, validates the returned access token and optional ID token, then stores a serialized `Principal` and optional `IdToken` in `tower-sessions`.
- Later requests call `session_context`; if a stored principal exists, it is restored directly into request extensions.

### Refresh Is Not Implemented

There is no refresh-token implementation in the web-app flow:

- `TokenResponse` only models `access_token` and optional `id_token`; a provider `refresh_token` response field is ignored by Serde.
- The access token itself is not stored, only the derived `Principal`.
- There is no `grant_type=refresh_token` request path.
- There is no web-app session expiry check against the stored ID token or access token claims when restoring the session.
- There are no config properties equivalent to Quarkus `token.refresh-expired`, `token.refresh-token-time-skew`, or `authentication.session-age-extension`.

The practical result is that authentication validity is bounded by the `tower-sessions` store/cookie configuration, not by token refresh. Once a principal is in the session, this middleware accepts it until the session layer drops it or application code clears it.

### Quarkus OIDC Behaviour

Quarkus OIDC documents a fuller token state lifecycle for `web-app` applications:

- The code flow exchanges the authorization code for ID, access, and refresh tokens.
- Quarkus stores token state through `TokenStateManager`, defaulting to encrypted session-cookie token storage.
- By default, the Quarkus local session is based on ID token expiration and an expired session is redirected for re-authentication.
- If `quarkus.oidc.token.refresh-expired=true`, Quarkus uses the refresh token to refresh expired ID/access tokens and update the local session.
- `quarkus.oidc.token.refresh-token-time-skew` enables proactive refresh before token expiry.
- `quarkus.oidc.authentication.session-age-extension` is part of making refresh effective because the refresh token is kept in the user session.

## Recommendation

If this crate is expected to match Quarkus web-app semantics, token refresh is a missing feature. A Quarkus-like implementation would need to store token state securely, track token expiry on each restored session, call the token endpoint with `grant_type=refresh_token`, rotate stored refresh tokens when returned, and invalidate or redirect when refresh fails.

If the current simpler model is intentional, document that `web-app` mode performs login and session restoration only, and that session lifetime must be managed by `tower-sessions`.

## References

- `src/web_app.rs`
- `src/oidc.rs`
- `src/config.rs`
- Quarkus OIDC authorization-code flow guide: https://quarkus.io/guides/security-oidc-code-flow-authentication
- Quarkus OIDC configuration properties: https://quarkus.io/guides/security-oidc-configuration-properties-reference

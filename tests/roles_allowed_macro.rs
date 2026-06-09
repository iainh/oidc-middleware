use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header::AUTHORIZATION};
use axum::routing::get;
use oidc_middleware::{
    Error, Oidc, OidcConfig, OidcPrincipal, Principal, StaticTokenValidator, roles_allowed,
};
use tower::ServiceExt;

#[roles_allowed("admin")]
async fn admin(principal: OidcPrincipal) -> Result<&'static str, Error> {
    assert_eq!(principal.subject(), "alice");
    Ok("admin")
}

#[roles_allowed("**")]
async fn authenticated(principal: OidcPrincipal) -> Result<&'static str, Error> {
    assert_eq!(principal.subject(), "alice");
    Ok("authenticated")
}

#[tokio::test]
async fn roles_allowed_macro_accepts_matching_group() {
    let response = app(["admin"])
        .oneshot(request(Some("Bearer test-token")))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn roles_allowed_macro_rejects_missing_group() {
    let response = app(["user"])
        .oneshot(request(Some("Bearer test-token")))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn roles_allowed_macro_requires_authentication() {
    let response = app(["admin"])
        .oneshot(request(None))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn roles_allowed_macro_double_star_accepts_authenticated_without_group() {
    let response = app(["user"])
        .oneshot(request_to("/authenticated", Some("Bearer test-token")))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn roles_allowed_macro_double_star_requires_authentication() {
    let response = app(["admin"])
        .oneshot(request_to("/authenticated", None))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

fn app(groups: impl IntoIterator<Item = &'static str>) -> Router {
    Router::new()
        .route("/admin", get(admin))
        .route("/authenticated", get(authenticated))
        .layer(
            Oidc::builder(OidcConfig::default())
                .validator(StaticTokenValidator::principal(
                    "test-token",
                    Principal::with_groups("alice", groups),
                ))
                .build()
                .layer(),
        )
}

fn request(authorization: Option<&str>) -> Request<Body> {
    request_to("/admin", authorization)
}

fn request_to(uri: &str, authorization: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().uri(uri);
    if let Some(authorization) = authorization {
        builder = builder.header(AUTHORIZATION, authorization);
    }
    builder
        .body(Body::empty())
        .expect("request should be valid")
}

use axum::Router;
use axum::body::Body;
use axum::extract::FromRequestParts;
use axum::http::{Request, StatusCode, header::AUTHORIZATION};
use axum::routing::get;
use http::request::Parts;
use oidc_middleware::{
    Error, Oidc, OidcAuthorize, OidcConfig, OidcPrincipal, Principal, StaticTokenValidator,
    authenticated, roles_allowed,
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

#[authenticated]
async fn authenticated_macro(principal: OidcPrincipal) -> Result<&'static str, Error> {
    assert_eq!(principal.subject(), "alice");
    Ok("authenticated")
}

#[derive(Clone)]
struct User {
    principal: Principal,
    subject: String,
}

impl OidcAuthorize for User {
    fn principal(&self) -> &Principal {
        &self.principal
    }
}

impl<S> FromRequestParts<S> for User
where
    S: Send + Sync,
{
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let principal = OidcPrincipal::from_request_parts(parts, state)
            .await?
            .into_inner();
        Ok(Self {
            subject: principal.subject().to_owned(),
            principal,
        })
    }
}

#[roles_allowed("admin", principal = user)]
async fn user_admin(user: User) -> Result<&'static str, Error> {
    assert_eq!(user.subject, "alice");
    Ok("user-admin")
}

#[authenticated(principal = user)]
async fn user_profile(user: User) -> Result<&'static str, Error> {
    assert_eq!(user.subject, "alice");
    Ok("user-profile")
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

#[tokio::test]
async fn authenticated_macro_accepts_authenticated_without_group() {
    let response = app(["user"])
        .oneshot(request_to(
            "/authenticated-macro",
            Some("Bearer test-token"),
        ))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn authenticated_macro_requires_authentication() {
    let response = app(["admin"])
        .oneshot(request_to("/authenticated-macro", None))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn roles_allowed_macro_accepts_application_user() {
    let response = app(["admin"])
        .oneshot(request_to("/user-admin", Some("Bearer test-token")))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn authenticated_macro_accepts_application_user() {
    let response = app(["user"])
        .oneshot(request_to("/user-profile", Some("Bearer test-token")))
        .await
        .expect("request should complete");

    assert_eq!(response.status(), StatusCode::OK);
}

fn app(groups: impl IntoIterator<Item = &'static str>) -> Router {
    Router::new()
        .route("/admin", get(admin))
        .route("/authenticated", get(authenticated))
        .route("/authenticated-macro", get(authenticated_macro))
        .route("/user-admin", get(user_admin))
        .route("/user-profile", get(user_profile))
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

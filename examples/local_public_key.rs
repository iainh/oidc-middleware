//! Local JWT validation with a configured public key.
//!
//! This is useful for tests, demos, or deployments that distribute signing keys
//! out of band and do not want provider discovery at startup.

use axum::{Extension, Router, routing::get};
use oidc_middleware::{Oidc, OidcConfig, Principal};

const PUBLIC_KEY_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyRE6rHuNR0QbHO3H3Kt2
pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5/CYYi/cvI+SXVT9kPWSKXxJXB
Xd/4LkvcPuUakBoAkfh+eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHR
yIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG/AtH89BIE9jDBHZ9dLelK9a184zAf8Lw
oPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xq
i+yUod+j8MtvIj812dkS4QMiRVN/by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5T
dQIDAQAB
-----END PUBLIC KEY-----"#;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let _app = app()?;
    Ok(())
}

fn app() -> Result<Router, Box<dyn std::error::Error + Send + Sync>> {
    let oidc = Oidc::builder(OidcConfig {
        auth_server_url: Some("https://issuer.example/realms/app".to_owned()),
        client_id: Some("orders-api".to_owned()),
        ..OidcConfig::default()
    })
    .public_key(PUBLIC_KEY_PEM)?
    .build();

    Ok(Router::new().route("/me", get(me)).layer(oidc.layer()))
}

async fn me(Extension(principal): Extension<Principal>) -> String {
    format!("subject={}", principal.subject())
}

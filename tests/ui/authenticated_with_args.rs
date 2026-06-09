use oidc_middleware::{Error, OidcPrincipal, authenticated};

#[authenticated("admin")]
async fn profile(principal: OidcPrincipal) -> Result<(), Error> {
    assert_eq!(principal.subject(), "alice");
    Ok(())
}

fn main() {}

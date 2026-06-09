use oidc_middleware::{Error, OidcPrincipal, roles_allowed};

#[roles_allowed("")]
async fn admin(principal: OidcPrincipal) -> Result<(), Error> {
    let _ = principal;
    Ok(())
}

fn main() {}

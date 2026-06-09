use oidc_middleware::{OidcPrincipal, roles_allowed};

#[roles_allowed("admin")]
async fn admin(principal: OidcPrincipal) {
    let _ = principal;
}

fn main() {}

use oidc_middleware::{Error, roles_allowed};

#[roles_allowed("admin")]
async fn admin() -> Result<(), Error> {
    Ok(())
}

fn main() {}

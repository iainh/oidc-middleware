use oidc_middleware::{Error, authenticated};

#[authenticated]
async fn profile() -> Result<(), Error> {
    Ok(())
}

fn main() {}

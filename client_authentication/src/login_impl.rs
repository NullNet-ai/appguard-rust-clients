use super::token_wrapper::TokenWrapper;
use nullnet_libappguard::AppGuardGrpcInterface;

pub(crate) async fn login_impl(
    addr: &str,
    port: u16,
    app_id: String,
    app_secret: String,
) -> Result<TokenWrapper, String> {
    let jwt: String = AppGuardGrpcInterface::new(addr, port, false)
        .await?
        .login(app_id, app_secret)
        .await?;

    let token = TokenWrapper::from_jwt(jwt)?;
    Ok(token)
}

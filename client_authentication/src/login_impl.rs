use nullnet_libappguard::AppGuardGrpcInterface;
use nullnet_libtoken::Token;

pub(crate) async fn login_impl(
    mut client: AppGuardGrpcInterface,
    app_id: String,
    app_secret: String,
) -> Result<Token, String> {
    let jwt: String = client.login(app_id, app_secret).await?;

    let token = Token::from_jwt(&jwt)?;
    Ok(token)
}

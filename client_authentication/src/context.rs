use crate::control_channel::start_control_stream;
use crate::storage::{Secret, Storage};
use crate::token_provider::TokenProvider;
use nullnet_libappguard::AppGuardGrpcInterface;
use nullnet_libappguard::appguard_commands::FirewallDefaults;
use nullnet_liberror::{Error, ErrorHandler, location, Location};
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct Context {
    pub app_id: String,
    pub app_secret: String,
    pub token_provider: TokenProvider,
    pub server: AppGuardGrpcInterface,
    pub firewall_defaults: Arc<Mutex<FirewallDefaults>>,
}

impl Context {
    #[allow(clippy::missing_errors_doc)]
    pub async fn new(mut server: AppGuardGrpcInterface) -> Result<Self, Error> {
        Storage::init().await?;

        let app_id = Storage::get_value(Secret::AppId)
            .await
            .or_else(|| std::env::var("APP_ID").ok())
            .unwrap_or_default();

        let app_secret = Storage::get_value(Secret::AppSecret)
            .await
            .or_else(|| std::env::var("APP_SECRET").ok())
            .unwrap_or_default();

        let installation_code = Storage::get_value(Secret::InstallationCode)
            .await
            .or_else(|| std::env::var("INSTALLATION_CODE").ok())
            .unwrap_or_default();
        Storage::set_value(Secret::InstallationCode, &installation_code).await?;

        let token_provider = TokenProvider::new();

        let token = token_provider.get().await.unwrap_or_default();
        let firewall_defaults = server
            .firewall_defaults_request(token)
            .await
            .handle_err(location!())?;

        let ctx = Self {
            app_id,
            app_secret,
            token_provider,
            server,
            firewall_defaults: Arc::new(Mutex::new(firewall_defaults)),
        };

        start_control_stream(ctx.clone(), installation_code).await;

        Ok(ctx)
    }
}

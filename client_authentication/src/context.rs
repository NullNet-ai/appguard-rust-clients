use crate::control_channel::start_control_stream;
use crate::storage::{Secret, Storage};
use crate::token_provider::TokenProvider;
use nullnet_libappguard::AppGuardGrpcInterface;
use nullnet_libappguard::appguard_commands::{FirewallDefaults, FirewallPolicy};
use nullnet_liberror::Error;
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
    pub async fn new(server: AppGuardGrpcInterface) -> Result<Self, Error> {
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

        let ctx = Self {
            app_id,
            app_secret,
            token_provider,
            server,
            firewall_defaults: Arc::new(Mutex::new(FirewallDefaults {
                timeout: 1000,
                policy: FirewallPolicy::default().into(),
            })),
        };

        start_control_stream(ctx.clone(), installation_code).await;

        Ok(ctx)
    }
}

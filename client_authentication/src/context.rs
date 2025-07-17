use crate::token_provider::TokenProvider;
use nullnet_liberror::Error;
use std::sync::Arc;
use nullnet_libappguard::appguard_commands::{FirewallDefaults, FirewallPolicy};
use nullnet_libappguard::AppGuardGrpcInterface;
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
        let app_id = std::env::var("APP_ID").unwrap_or_default();
        let app_secret = std::env::var("APP_SECRET").unwrap_or_default();
        let token_provider = TokenProvider::new();

        Ok(Self {
            app_id,
            app_secret,
            token_provider,
            server,
            firewall_defaults: Arc::new(Mutex::new(FirewallDefaults {
                timeout: 1000,
                policy: FirewallPolicy::default().into(),
            })),
        })
    }
}

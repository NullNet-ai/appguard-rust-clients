use crate::cache_key::CacheKey;
use crate::control_channel::start_control_stream;
use crate::storage::{Secret, Storage};
use crate::token_provider::TokenProvider;
use nullnet_libappguard::AppGuardGrpcInterface;
use nullnet_libappguard::appguard_commands::{FirewallDefaults, FirewallPolicy};
use nullnet_liberror::{Error, ErrorHandler, Location, location};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct Context {
    pub token_provider: TokenProvider,
    pub server: AppGuardGrpcInterface,
    pub firewall_defaults: Arc<Mutex<FirewallDefaults>>,
    pub cache: Arc<Mutex<HashMap<CacheKey, FirewallPolicy>>>,
}

impl Context {
    #[allow(clippy::missing_errors_doc)]
    pub async fn new(r#type: String) -> Result<Self, Error> {
        let host = std::env::var("CONTROL_SERVICE_ADDR").handle_err(location!())?;
        let port_str = std::env::var("CONTROL_SERVICE_PORT").handle_err(location!())?;
        let port = port_str.parse::<u16>().handle_err(location!())?;

        let mut server = AppGuardGrpcInterface::new(&host, port, false)
            .await
            .handle_err(location!())?;

        Storage::init().await?;

        let mut installation_code_res = std::env::var("INSTALLATION_CODE").handle_err(location!());
        if installation_code_res.is_err() {
            installation_code_res = Storage::get_value(Secret::InstallationCode)
                .await
                .ok_or("Installation code not set")
                .handle_err(location!());
        }
        let installation_code = installation_code_res?;
        Storage::set_value(Secret::InstallationCode, &installation_code).await?;

        let token_provider = TokenProvider::new();

        let ctx = Self {
            token_provider: token_provider.clone(),
            server: server.clone(),
            firewall_defaults: Arc::new(Mutex::new(FirewallDefaults::default())),
            cache: Arc::new(Mutex::new(HashMap::new())),
        };

        start_control_stream(ctx.clone(), installation_code, r#type).await;

        let mut token = token_provider.get().await.unwrap_or_default();
        while token.is_empty() {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            token = token_provider.get().await.unwrap_or_default();
        }

        let firewall_defaults = server
            .firewall_defaults_request(token)
            .await
            .handle_err(location!())?;
        *ctx.firewall_defaults.lock().await = firewall_defaults;

        Ok(ctx)
    }
}

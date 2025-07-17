mod heartbeat;
mod control_channel;
mod context;
mod token_provider;

use nullnet_libappguard::AppGuardGrpcInterface;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AuthHandler {
    app_id: String,
    app_secret: String,
    token: Arc<RwLock<String>>,
    client: AppGuardGrpcInterface,
}

impl AuthHandler {
    #[must_use]
    pub async fn new(client: AppGuardGrpcInterface) -> Self {
        let app_id = std::env::var("APP_ID").unwrap_or_default();
        let app_secret = std::env::var("APP_SECRET").unwrap_or_default();
        let auth = Self {
            app_id,
            app_secret,
            client: client.clone(),
            token: Arc::new(RwLock::new(String::new())),
        };

        let auth_2 = auth.clone();
        tokio::spawn(async move { heartbeat::routine(auth_2).await });

        log::info!("Waiting for the first server heartbeat");
        while auth.token.read().await.is_empty() {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        }
        log::info!("Received the first server heartbeat");

        auth
    }

    pub async fn get_token(&self) -> String {
        self.token.read().await.clone()
    }
}

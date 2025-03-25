mod heartbeat;
mod login_impl;

use login_impl::login_impl;
use nullnet_libappguard::{AppGuardGrpcInterface, Authentication, DeviceStatus, SetupRequest};
use nullnet_libtoken::Token;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AuthHandler {
    app_id: String,
    app_secret: String,
    token: Arc<Mutex<Option<Token>>>,
    client: AppGuardGrpcInterface,
}

impl AuthHandler {
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub async fn new(client: AppGuardGrpcInterface) -> Self {
        let app_id = std::env::var("APP_ID").unwrap_or_default();
        let app_secret = std::env::var("APP_SECRET").unwrap_or_default();
        let mut auth = Self {
            app_id,
            app_secret,
            client: client.clone(),
            token: Arc::new(Mutex::new(None)),
        };

        let status = auth
            .fetch_status()
            .await
            .expect("Failed to fetch device status");

        if status == DeviceStatus::DsDraft {
            auth.setup_request().await.expect("Setup request failed");
        } else if status == DeviceStatus::DsArchived || status == DeviceStatus::DsDeleted {
            log::warn!("Device has been archived or deleted, aborting execution ...",);
            std::process::exit(0);
        }

        let auth_2 = auth.clone();
        tokio::spawn(async move { heartbeat::routine(auth_2, client).await });

        auth
    }

    #[allow(clippy::missing_errors_doc)]
    #[allow(clippy::missing_panics_doc)]
    pub async fn obtain_token_safe(&self) -> Result<String, String> {
        let mut token = self.token.lock().await;

        if token.as_ref().is_none_or(Token::is_expired) {
            let new_token = login_impl(
                self.client.clone(),
                self.app_id.clone(),
                self.app_secret.clone(),
            )
            .await?;

            *token = Some(new_token);
        }

        Ok(token.as_ref().unwrap().jwt.clone())
    }

    async fn setup_request(&mut self) -> Result<(), String> {
        let token = self.obtain_token_safe().await.expect("Unauthenticated");

        let _ = self
            .client
            .setup(SetupRequest {
                auth: Some(Authentication { token }),
                device_version: "".to_string(),
                device_uuid: "".to_string(),
            })
            .await?;

        Ok(())
    }

    async fn fetch_status(&mut self) -> Result<DeviceStatus, String> {
        let token = self.obtain_token_safe().await.expect("Unauthenticated");

        let response = self.client.status(token).await?;

        let status = DeviceStatus::try_from(response.status)
            .map_err(|e| format!("Wrong DeviceStatus value: {}", e.0))?;

        Ok(status)
    }
}

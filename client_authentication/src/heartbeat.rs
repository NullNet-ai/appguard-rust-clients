use futures_util::StreamExt;
use std::time::Duration;

use crate::AuthHandler;
use nullnet_libappguard::{DeviceStatus, HeartbeatResponse};

pub async fn routine(auth_handler: AuthHandler) {
    loop {
        let mut client = auth_handler.client.clone();
        let Ok(mut heartbeat_stream) = client
            .heartbeat(
                auth_handler.app_id.clone(),
                auth_handler.app_secret.clone(),
                String::new(),
                String::new(),
            )
            .await
        else {
            log::warn!("Failed to send heartbeat to the server. Retrying in 10 seconds...");
            tokio::time::sleep(Duration::from_secs(10)).await;
            continue;
        };

        while let Some(Ok(heartbeat_response)) = heartbeat_stream.next().await {
            handle_hb_response(&heartbeat_response);
            let mut t = auth_handler.token.write().await;
            *t = heartbeat_response.token;
            drop(t);
        }
    }
}

fn handle_hb_response(response: &HeartbeatResponse) {
    match DeviceStatus::try_from(response.status) {
        Ok(DeviceStatus::DsArchived | DeviceStatus::DsDeleted) => {
            log::warn!("Device has been archived or deleted, aborting execution ...",);
            std::process::exit(0);
        }
        Ok(_) => {}
        Err(_) => log::error!("Unknown device status value {}", response.status),
    }
}

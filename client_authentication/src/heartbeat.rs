use std::time::Duration;

use crate::AuthHandler;
use nullnet_libappguard::{AppGuardGrpcInterface, DeviceStatus, HeartbeatResponse};

pub async fn routine(auth: AuthHandler, mut client: AppGuardGrpcInterface) {
    loop {
        match auth.obtain_token_safe().await {
            Ok(token) => match client.heartbeat(token).await {
                Ok(response) => {
                    handle_hb_response(response);
                }
                Err(msg) => log::error!("Heartbeat: Request failed failed - {msg}"),
            },
            Err(msg) => log::error!("Heartbeat: Authentication failed - {msg}"),
        };

        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

fn handle_hb_response(response: HeartbeatResponse) {
    match DeviceStatus::try_from(response.status) {
        Ok(DeviceStatus::DsArchived | DeviceStatus::DsDeleted) => {
            log::warn!("Device has been archived or deleted, aborting execution ...",);
            std::process::exit(0);
        }
        Ok(_) => {}
        Err(_) => log::error!("Unknown device status value {}", response.status),
    }
}

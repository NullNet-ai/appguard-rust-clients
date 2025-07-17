use crate::AuthHandler;

pub async fn routine(auth_handler: AuthHandler) {

}

// fn handle_hb_response(response: &HeartbeatResponse) {
//     match DeviceStatus::try_from(response.status) {
//         Ok(DeviceStatus::Archived | DeviceStatus::Deleted) => {
//             log::warn!("Device has been archived or deleted, aborting execution ...",);
//             std::process::exit(0);
//         }
//         Ok(_) => {}
//         Err(_) => log::error!("Unknown device status value {}", response.status),
//     }
// }

use crate::control_channel::{InboundStream, OutboundStream};
use crate::storage::{Secret, Storage};
use nullnet_libappguard::appguard_commands::{
    AuthorizationRequest, ClientMessage, client_message, server_message,
};
use nullnet_liberror::{Error, ErrorHandler, Location, location};
use smbioslib::{SMBiosSystemInformation, table_load_from_device};

pub enum Verdict {
    Approved,
    Rejected,
}

pub async fn await_authorization(
    inbound: InboundStream,
    outbound: OutboundStream,
    installation_code: impl Into<String>,
) -> Result<Verdict, Error> {
    let uuid = table_load_from_device()
        .handle_err(location!())?
        .find_map(|value: SMBiosSystemInformation| value.uuid())
        .map(|uuid| uuid.to_string())
        .ok_or("Failed to retrieve device UUID")
        .handle_err(location!())?;
    let message = ClientMessage {
        message: Some(client_message::Message::AuthorizationRequest(
            AuthorizationRequest {
                uuid,
                code: installation_code.into(),
                category: String::from("AppGuard Client"),
                r#type: String::new(),
                target_os: String::new(),
            },
        )),
    };

    outbound
        .lock()
        .await
        .send(message)
        .await
        .handle_err(location!())?;

    loop {
        let message = inbound
            .lock()
            .await
            .message()
            .await
            .handle_err(location!())?
            .ok_or("Server sent an empty message")
            .handle_err(location!())?
            .message
            .ok_or("Malformed message (empty payload)")
            .handle_err(location!())?;

        match message {
            server_message::Message::DeviceAuthorized(data) => {
                if let Some(app_id) = data.app_id {
                    Storage::set_value(Secret::AppId, &app_id).await?;
                }

                if let Some(app_secret) = data.app_secret {
                    Storage::set_value(Secret::AppSecret, &app_secret).await?;
                }

                return Ok(Verdict::Approved);
            }
            server_message::Message::AuthorizationRejected(()) => {
                return Ok(Verdict::Rejected);
            }
            server_message::Message::Heartbeat(()) => {
                log::debug!("Awaiting authorization: heartbeat");
            }
            _ => Err("Unexpected message").handle_err(location!())?,
        }
    }
}

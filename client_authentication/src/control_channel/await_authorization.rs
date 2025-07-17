use nullnet_liberror::{location, Error, ErrorHandler, Location};
use nullnet_libappguard::appguard_commands::{
    client_message, server_message, AuthorizationRequest, ClientMessage,
};

use crate::{
    control_channel::{InboundStream, OutboundStream},
};

pub enum Verdict {
    Approved,
    Rejected,
}

pub async fn await_authorization(
    inbound: InboundStream,
    outbound: OutboundStream,
) -> Result<Verdict, Error> {
    let message = ClientMessage {
        message: Some(client_message::Message::AuthorizationRequest(
            AuthorizationRequest {
                uuid: client_data.uuid,
                org_id: "".to_string(),
                category: client_data.category,
                model: "".to_string(),
                target_os: client_data.target_os.to_string(),
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
            server_message::Message::AuthorizationRejected(_) => {
                return Ok(Verdict::Rejected);
            }
            server_message::Message::Heartbeat(_) => {
                log::debug!("Awaiting authorization: heartbeat");
                continue;
            }
            _ => Err("Unexpected message").handle_err(location!())?,
        };
    }
}

use crate::control_channel::OutboundStream;
use crate::storage::{Secret, Storage};
use nullnet_libappguard::appguard_commands::{Authentication, ClientMessage, client_message};
use nullnet_liberror::{Error, ErrorHandler, Location, location};

pub async fn send_authenticate(outbound: OutboundStream) -> Result<(), Error> {
    let app_id = Storage::get_value(Secret::AppId)
        .await
        .ok_or("AppId not set")
        .handle_err(location!())?;

    let app_secret = Storage::get_value(Secret::AppSecret)
        .await
        .ok_or("AppSecret not set")
        .handle_err(location!())?;

    let message = ClientMessage {
        message: Some(client_message::Message::Authentication(Authentication {
            app_id,
            app_secret,
        })),
    };

    outbound
        .lock()
        .await
        .send(message)
        .await
        .handle_err(location!())
}

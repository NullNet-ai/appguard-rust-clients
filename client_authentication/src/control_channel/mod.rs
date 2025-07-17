use crate::context::Context;
use crate::control_channel::command::ExecutableCommand;
use crate::control_channel::commands::{HeartbeatCommand, SetFirewallDefaultsCommand, UpdateTokenCommand};
use crate::control_channel::post_startup::post_startup;
use await_authorization::await_authorization;
use nullnet_liberror::{location, Error, ErrorHandler, Location};
use send_authenticate::send_authenticate;
use std::sync::Arc;
use nullnet_libappguard::appguard_commands::{server_message, ClientMessage, ServerMessage};
use nullnet_libappguard::appguard_commands::server_message::Message;
use nullnet_libappguard::appguard_commands::server_message::Message::SetFirewallDefaults;
use nullnet_libappguard::Streaming;
use tokio::sync::{broadcast, mpsc, Mutex};

mod await_authorization;
mod command;
mod commands;
mod post_startup;
mod send_authenticate;

pub(crate) type InboundStream = Arc<Mutex<Streaming<ServerMessage>>>;
pub(crate) type OutboundStream = Arc<Mutex<mpsc::Sender<ClientMessage>>>;

#[derive(Clone)]
pub struct ControlChannel {
    context: Context,
    terminate: broadcast::Sender<()>,
}

impl ControlChannel {
    pub fn new(context: Context, code: String) -> Self {
        let (terminate, _) = broadcast::channel(1);

        tokio::spawn(stream_wrapper(
            context.clone(),
            code.clone(),
            terminate.subscribe(),
        ));

        Self { context, terminate }
    }

    pub async fn terminate(&self) {
        let _ = self.terminate.send(());
    }
}

async fn stream_wrapper(
    context: Context,
    installation_code: String,
    mut terminate: broadcast::Receiver<()>,
) {
    tokio::select! {
        _ = terminate.recv() => {}
        _ = control_stream(context.clone()) => { }
    };
}

async fn control_stream(context: Context) -> Result<(), Error> {
    let (outbound, receiver) = mpsc::channel(64);
    let inbound = context.server.control_channel(receiver).await.handle_err(location!())?;

    let inbound = Arc::new(Mutex::new(inbound));
    let outbound = Arc::new(Mutex::new(outbound));

    match await_authorization(
        inbound.clone(),
        outbound.clone(),
        context.client_data.clone(),
    )
    .await?
    {
        await_authorization::Verdict::Approved => {}
        await_authorization::Verdict::Rejected => {
            Err("Auhtorization has been rejected").handle_err(location!())?;
            // Cleanup ??
            // Remove ORG ID?
            // Enter some other state or something?
        }
    }

    // Clone the outbound stream to keep it alive—closing it signals
    // an error to the server, which closes the connection.
    send_authenticate(outbound.clone()).await?;

    tokio::spawn(post_startup(context.clone()));

    while let Ok(message) = inbound.lock().await.message().await {
        let message = message
            .and_then(|message| message.message)
            .ok_or("Malformed message")
            .handle_err(location!())?;

        match message {
            server_message::Message::UpdateTokenCommand(token) => {
                let cmd = UpdateTokenCommand::new(context.clone(), token);

                if let Err(err) = cmd.execute().await {
                    log::error!("UpdateTokenCommand execution failed: {}", err.to_str());
                }
            }
            server_message::Message::Heartbeat(_) => {
                let cmd = HeartbeatCommand::new();

                if let Err(err) = cmd.execute().await {
                    log::error!("HeartbeatCommand execution failed: {}", err.to_str());
                }
            }
            server_message::Message::DeviceDeauthorized(_) => {
                // // @TODO: Command
                // _ = Storage::delete_value(Secret::AppId).await;
                // _ = Storage::delete_value(Secret::AppSecret).await;
                // // Gracefuly transition to IDLE state
                todo!();
            }
            server_message::Message::AuthorizationRejected(_) => {
                Err("Unexpected message").handle_err(location!())?
            }
            server_message::Message::DeviceAuthorized(_) => {
                Err("Unexpected message").handle_err(location!())?
            }
            Message::SetFirewallDefaults(defaults) => {
                let cmd = SetFirewallDefaultsCommand::new(context.clone(), defaults);

                if let Err(err) = cmd.execute().await {
                    log::error!("SetFirewallDefaultsCommand execution failed: {}", err.to_str());
                }
            }
        }
    }

    Ok(())
}

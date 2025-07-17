use crate::{context::Context, control_channel::command::ExecutableCommand};
use nullnet_libappguard::appguard_commands::FirewallDefaults;

pub struct SetFirewallDefaultsCommand {
    context: Context,
    defaults: FirewallDefaults,
}

impl SetFirewallDefaultsCommand {
    pub fn new(context: Context, defaults: FirewallDefaults) -> Self {
        Self { context, defaults }
    }
}

impl ExecutableCommand for SetFirewallDefaultsCommand {
    async fn execute(self) -> Result<(), nullnet_liberror::Error> {
        log::debug!("Received UpdateTokenCommand");
        *self.context.firewall_defaults.lock().await = self.defaults;
        Ok(())
    }
}

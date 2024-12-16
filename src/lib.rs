pub use tonic::transport::Channel;

pub use grpc::{
    handle_http_request, handle_http_response, handle_tcp_connection, new_appguard_client,
};
pub use proto::appguard::{
    app_guard_client::AppGuardClient, AppGuardHttpRequest, AppGuardHttpResponse,
    AppGuardTcpConnection, AppGuardTcpInfo, FirewallPolicy,
};

mod grpc;
mod proto;

#[derive(Default, Clone, Copy)]
/// `AppGuard` client configuration
pub struct AppGuardConfig {
    /// Hostname of the `AppGuard` server
    pub host: &'static str,
    /// Port of the `AppGuard` server
    pub port: u16,
    /// Whether traffic to the `AppGuard` server should be secured with TLS
    pub tls: bool,
    /// Timeout for calls to the `AppGuard` server (milliseconds)
    pub timeout: Option<u64>,
    /// Default firewall policy to apply when the `AppGuard` server times out
    pub default_policy: FirewallPolicy,
}

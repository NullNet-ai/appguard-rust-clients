use std::future::Future;

use tonic::transport::{Channel, ClientTlsConfig};
use tonic::{Request, Response, Status};

use crate::proto::appguard::app_guard_client::AppGuardClient;
use crate::proto::appguard::{
    AppGuardHttpRequest, AppGuardHttpResponse, AppGuardResponse, AppGuardTcpConnection,
    AppGuardTcpInfo, AppGuardTcpResponse,
};
use crate::FirewallPolicy;

pub async fn new_appguard_client(
    host: &str,
    port: u16,
    tls: bool,
) -> Result<AppGuardClient<Channel>, String> {
    let protocol = if tls { "https" } else { "http" };

    let mut endpoint = Channel::from_shared(format!("{protocol}://{host}:{port}"))
        .map_err(|e| e.to_string())?
        .connect_timeout(std::time::Duration::from_secs(10));

    if tls {
        endpoint = endpoint
            .tls_config(ClientTlsConfig::new().with_native_roots())
            .map_err(|e| e.to_string())?;
    }

    let channel = endpoint.connect().await.map_err(|e| e.to_string())?;

    Ok(AppGuardClient::new(channel))
}

pub async fn handle_tcp_connection(
    client: &mut AppGuardClient<Channel>,
    timeout: Option<u64>,
    tcp_connection: AppGuardTcpConnection,
) -> Result<AppGuardTcpResponse, Status> {
    client
        .handle_tcp_connection(Request::new(tcp_connection.clone()))
        .wait_until_timeout(
            timeout,
            AppGuardTcpResponse {
                tcp_info: Some(AppGuardTcpInfo {
                    connection: Some(tcp_connection),
                    ..Default::default()
                }),
            },
        )
        .await
}

pub async fn handle_http_request(
    client: &mut AppGuardClient<Channel>,
    timeout: Option<u64>,
    default_policy: FirewallPolicy,
    http_request: AppGuardHttpRequest,
) -> Result<AppGuardResponse, Status> {
    client
        .handle_http_request(Request::new(http_request))
        .wait_until_timeout(
            timeout,
            AppGuardResponse {
                policy: default_policy as i32,
            },
        )
        .await
}

pub async fn handle_http_response(
    client: &mut AppGuardClient<Channel>,
    timeout: Option<u64>,
    default_policy: FirewallPolicy,
    http_response: AppGuardHttpResponse,
) -> Result<AppGuardResponse, Status> {
    client
        .handle_http_response(Request::new(http_response))
        .wait_until_timeout(
            timeout,
            AppGuardResponse {
                policy: default_policy as i32,
            },
        )
        .await
}

trait WaitUntilTimeout<T> {
    async fn wait_until_timeout(self, timeout: Option<u64>, default: T) -> Result<T, Status>;
}

impl<T, F: Future<Output = Result<Response<T>, Status>>> WaitUntilTimeout<T> for F {
    async fn wait_until_timeout(self, timeout: Option<u64>, default: T) -> Result<T, Status> {
        if let Some(t) = timeout {
            if let Ok(res) = tokio::time::timeout(std::time::Duration::from_millis(t), self).await {
                res.map(Response::into_inner)
            } else {
                // handler timed out, return default value
                Ok(default)
            }
        } else {
            self.await.map(Response::into_inner)
        }
    }
}

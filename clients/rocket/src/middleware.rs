use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Status;
use rocket::{Data, Request, Response};

use appguard_client_authentication::AuthHandler;
use nullnet_libappguard::{AppGuardGrpcInterface, AppGuardTcpResponse, FirewallPolicy};

use crate::conversions::{
    to_appguard_http_request, to_appguard_http_response, to_appguard_tcp_connection,
};

/// `AppGuard` client configuration.
pub struct AppGuardConfig {
    client: AppGuardGrpcInterface,
    default_policy: FirewallPolicy,
    timeout: Option<u64>,
    auth: AuthHandler,
}

impl AppGuardConfig {
    /// Create a new configuration for the client.
    ///
    /// # Arguments
    ///
    /// * `host` - Hostname of the `AppGuard` server.
    /// * `port` - Port of the `AppGuard` server.
    /// * `tls` - Whether traffic to the `AppGuard` server should be secured with TLS.
    /// * `timeout` - Timeout for calls to the `AppGuard` server (milliseconds).
    /// * `default_policy` - Default firewall policy to apply when the `AppGuard` server times out.
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub async fn new(
        host: &'static str,
        port: u16,
        tls: bool,
        timeout: Option<u64>,
        default_policy: FirewallPolicy,
    ) -> Option<Self> {
        let client = AppGuardGrpcInterface::new(host, port, tls).await.ok()?;
        let auth = AuthHandler::new(client.clone()).await;
        Some(AppGuardConfig {
            client,
            default_policy,
            timeout,
            auth,
        })
    }
}

#[rocket::async_trait]
impl Fairing for AppGuardConfig {
    fn info(&self) -> Info {
        Info {
            name: "AppGuard",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, req: &mut Request<'_>, _data: &mut Data<'_>) {
        let mut client = self.client.clone();
        let token = self.auth.obtain_token_safe().await.unwrap();

        let AppGuardTcpResponse { tcp_info } = client
            .handle_tcp_connection(self.timeout, to_appguard_tcp_connection(req, token.clone()))
            .await
            .expect("Internal server error");

        req.local_cache(|| tcp_info.clone());

        let request_handler_res = client
            .handle_http_request(
                self.timeout,
                self.default_policy,
                to_appguard_http_request(req, tcp_info, token),
            )
            .await
            .expect("Internal server error");

        let policy = FirewallPolicy::try_from(request_handler_res.policy).unwrap_or_default();
        assert_ne!(policy, FirewallPolicy::Deny, "Unauthorized");
    }

    async fn on_response<'r>(&self, req: &'r Request<'_>, resp: &mut Response<'r>) {
        let mut client = self.client.clone();
        let token = self.auth.obtain_token_safe().await.unwrap();

        let tcp_info = req.local_cache(|| None);

        let Ok(response_handler_res) = client
            .handle_http_response(
                self.timeout,
                self.default_policy,
                to_appguard_http_response(resp, tcp_info.to_owned(), token),
            )
            .await
        else {
            *resp = internal_server_error_response();
            return;
        };

        let policy = FirewallPolicy::try_from(response_handler_res.policy).unwrap_or_default();
        if policy == FirewallPolicy::Deny {
            *resp = unauthorized_response();
            return;
        }
    }
}

fn unauthorized_response<'r>() -> Response<'r> {
    let mut response = Response::new();
    let body = "Unauthorized";
    response.set_sized_body(body.len(), std::io::Cursor::new(body));
    response.set_status(Status::Unauthorized);
    response
}

fn internal_server_error_response<'r>() -> Response<'r> {
    let mut response = Response::new();
    let body = "Internal server error";
    response.set_sized_body(body.len(), std::io::Cursor::new(body));
    response.set_status(Status::InternalServerError);
    response
}

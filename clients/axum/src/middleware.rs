use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use axum::{body::Body, extract::Request, response::Response};
use futures::executor::block_on;
use std::task::{Context, Poll};
use tower::{Layer, Service};

use appguard_client_authentication::AuthHandler;
use nullnet_libappguard::{AppGuardGrpcInterface, AppGuardTcpResponse, FirewallPolicy};

use crate::conversions::{
    to_appguard_http_request, to_appguard_http_response, to_appguard_tcp_connection,
};

#[derive(Default, Clone, Copy)]
/// `AppGuard` client configuration.
pub struct AppGuardConfig {
    host: &'static str,
    port: u16,
    tls: bool,
    timeout: Option<u64>,
    default_policy: FirewallPolicy,
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
    pub fn new(
        host: &'static str,
        port: u16,
        tls: bool,
        timeout: Option<u64>,
        default_policy: FirewallPolicy,
    ) -> Self {
        AppGuardConfig {
            host,
            port,
            tls,
            timeout,
            default_policy,
        }
    }
}

type LocalBoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

impl<S> Layer<S> for AppGuardConfig {
    type Service = AppGuardMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        let config = self;
        let client = block_on(AppGuardGrpcInterface::new(
            config.host,
            config.port,
            config.tls,
        ))
        .expect("Unable to start gRPC client");
        AppGuardMiddleware {
            client,
            default_policy: config.default_policy,
            timeout: config.timeout,
            auth: AuthHandler::new(
                "".to_string(),
                "".to_string(),
                config.host.to_string(),
                config.port,
            ),
            next_service: Arc::new(Mutex::new(inner)),
        }
    }
}

#[derive(Clone)]
pub struct AppGuardMiddleware<S> {
    client: AppGuardGrpcInterface,
    default_policy: FirewallPolicy,
    timeout: Option<u64>,
    auth: AuthHandler,
    next_service: Arc<Mutex<S>>,
}

impl<S> Service<Request> for AppGuardMiddleware<S>
where
    S: Service<Request, Response = Response> + Send + 'static,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = LocalBoxFuture<Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.next_service.lock().unwrap().poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let mut client = self.client.clone();
        let timeout = self.timeout;
        let default_policy = self.default_policy;
        let auth = self.auth.clone();
        let next_service = self.next_service.clone();

        Box::pin(async move {
            let token = auth.obtain_token_safe().await.unwrap();

            let Ok(AppGuardTcpResponse { tcp_info }) = client
                .handle_tcp_connection(timeout, to_appguard_tcp_connection(&req, token.clone()))
                .await
            else {
                return Ok(internal_server_error_response());
            };

            let Ok(request_handler_res) = client
                .handle_http_request(
                    timeout,
                    default_policy,
                    to_appguard_http_request(&req, tcp_info.clone(), token.clone()),
                )
                .await
            else {
                return Ok(internal_server_error_response());
            };

            let policy = FirewallPolicy::try_from(request_handler_res.policy).unwrap_or_default();
            if policy == FirewallPolicy::Deny {
                return Ok(unauthorized_response());
            }

            let fut = next_service.lock().unwrap().call(req);

            let resp: Response = fut.await?;

            let Ok(response_handler_res) = client
                .handle_http_response(
                    timeout,
                    default_policy,
                    to_appguard_http_response(&resp, tcp_info, token),
                )
                .await
            else {
                return Ok(internal_server_error_response());
            };

            let policy = FirewallPolicy::try_from(response_handler_res.policy).unwrap_or_default();
            if policy == FirewallPolicy::Deny {
                return Ok(unauthorized_response());
            }

            Ok(resp)
        })
    }
}

fn unauthorized_response() -> Response {
    let mut response = Response::new(Body::from("Unauthorized"));
    *response.status_mut() = StatusCode::UNAUTHORIZED;
    response
}

fn internal_server_error_response() -> Response {
    let mut response = Response::new(Body::from("Internal server error"));
    *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
    response
}

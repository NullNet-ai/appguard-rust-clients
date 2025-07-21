use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use axum::{body::Body, extract::Request, response::Response};
use nullnet_libappguard::appguard::AppGuardTcpResponse;
use nullnet_libappguard::appguard_commands::FirewallPolicy;
use nullnet_libappguard::AppGuardGrpcInterface;
use std::task::Poll;
use tower::{Layer, Service};

use appguard_client_authentication::Context;

use crate::conversions::{
    to_appguard_http_request, to_appguard_http_response, to_appguard_tcp_connection,
};

#[derive(Clone)]
/// `AppGuard` client configuration.
pub struct AppGuardConfig {
    client: AppGuardGrpcInterface,
    timeout: Option<u64>,
    default_policy: FirewallPolicy,
    ctx: Context,
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
    /// * `firewall` - Firewall expressions (infix notation).
    #[must_use]
    pub async fn new(host: &'static str, port: u16, tls: bool) -> Option<Self> {
        let mut client = AppGuardGrpcInterface::new(host, port, tls).await.ok()?;
        let ctx = Context::new(client.clone()).await.ok()?;

        // todo: get timeout and default_policy from server

        Some(AppGuardConfig {
            client,
            timeout,
            default_policy,
            ctx,
        })
    }
}

type LocalBoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

impl<S> Layer<S> for AppGuardConfig {
    type Service = AppGuardMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        let config = self.to_owned();
        AppGuardMiddleware {
            config,
            next_service: Arc::new(Mutex::new(inner)),
        }
    }
}

#[derive(Clone)]
pub struct AppGuardMiddleware<S> {
    config: AppGuardConfig,
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

    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.next_service.lock().unwrap().poll_ready(cx)
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let mut client = self.config.client.clone();
        let timeout = self.config.timeout;
        let default_policy = self.config.default_policy;
        let ctx = self.config.ctx.clone();
        let next_service = self.next_service.clone();

        Box::pin(async move {
            let token = ctx.token_provider.get().await.unwrap_or_default();

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

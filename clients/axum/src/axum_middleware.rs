use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use axum::{body::Body, extract::Request, response::Response};
use futures::executor::block_on;
use std::task::{Context, Poll};
use tower::{Layer, Service};

use appguard_clients_common::{
    handle_http_request, handle_http_response, handle_tcp_connection, new_appguard_client,
    AppGuardClient, AppGuardTcpResponse, Channel, FirewallPolicy,
};

use crate::conversions::{
    to_appguard_http_request, to_appguard_http_response, to_appguard_tcp_connection,
};

#[derive(Default, Clone, Copy)]
/// `AppGuard` client configuration.
pub struct AppGuardConfig(appguard_clients_common::AppGuardConfig);

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
        AppGuardConfig(appguard_clients_common::AppGuardConfig {
            host,
            port,
            tls,
            timeout,
            default_policy,
        })
    }
}

type LocalBoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

impl<S> Layer<S> for AppGuardConfig {
    type Service = AppGuardMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        let config = self.0;
        let client = block_on(new_appguard_client(config.host, config.port, config.tls)).unwrap();
        AppGuardMiddleware {
            client,
            default_policy: config.default_policy,
            timeout: config.timeout,
            next_service: Arc::new(Mutex::new(inner)),
        }
    }
}

#[derive(Clone)]
pub struct AppGuardMiddleware<S> {
    client: AppGuardClient<Channel>,
    default_policy: FirewallPolicy,
    timeout: Option<u64>,
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
        let next_service = self.next_service.clone();

        Box::pin(async move {
            let Ok(AppGuardTcpResponse { tcp_info }) =
                handle_tcp_connection(&mut client, timeout, to_appguard_tcp_connection(&req)).await
            else {
                let mut response = Response::new(Body::from("Internal server error"));
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                return Ok(response);
            };

            let Ok(request_handler_res) = handle_http_request(
                &mut client,
                timeout,
                default_policy,
                to_appguard_http_request(&req, tcp_info.clone()),
            )
            .await
            else {
                let mut response = Response::new(Body::from("Internal server error"));
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                return Ok(response);
            };

            let policy = FirewallPolicy::try_from(request_handler_res.policy).unwrap_or_default();
            if policy == FirewallPolicy::Deny {
                let mut response = Response::new(Body::from("Unauthorized"));
                *response.status_mut() = StatusCode::UNAUTHORIZED;
                return Ok(response);
            }

            let fut = next_service.lock().unwrap().call(req);

            let resp: Response = fut.await?;

            let Ok(response_handler_res) = handle_http_response(
                &mut client,
                timeout,
                default_policy,
                to_appguard_http_response(&resp, tcp_info),
            )
            .await
            else {
                let mut response = Response::new(Body::from("Internal server error"));
                *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                return Ok(response);
            };

            let policy = FirewallPolicy::try_from(response_handler_res.policy).unwrap_or_default();
            if policy == FirewallPolicy::Deny {
                let mut response = Response::new(Body::from("Unauthorized"));
                *response.status_mut() = StatusCode::UNAUTHORIZED;
                return Ok(response);
            }

            Ok(resp)
        })
    }
}

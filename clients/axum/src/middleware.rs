use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use axum::{body::Body, extract::Request, response::Response};
use nullnet_libappguard::appguard::AppGuardTcpResponse;
use nullnet_libappguard::appguard_commands::FirewallPolicy;
use std::task::Poll;
use tower::{Layer, Service};

use appguard_client_authentication::Context;

use crate::conversions::{
    to_appguard_http_request, to_appguard_http_response, to_appguard_tcp_connection, to_cache_key,
};

#[derive(Clone)]
/// `AppGuard` middleware.
pub struct AppGuardMiddleware {
    ctx: Context,
}

impl AppGuardMiddleware {
    /// Create a new `AppGuard` middleware instance.
    #[must_use]
    pub async fn new() -> Option<Self> {
        let ctx = Context::new(String::from("Axum")).await.ok()?;

        Some(AppGuardMiddleware { ctx })
    }
}

type LocalBoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

impl<S> Layer<S> for AppGuardMiddleware {
    type Service = AppGuardMiddlewareImpl<S>;

    fn layer(&self, inner: S) -> Self::Service {
        let middleware = self.to_owned();
        AppGuardMiddlewareImpl {
            middleware,
            next_service: Arc::new(Mutex::new(inner)),
        }
    }
}

#[derive(Clone)]
pub struct AppGuardMiddlewareImpl<S> {
    middleware: AppGuardMiddleware,
    next_service: Arc<Mutex<S>>,
}

impl<S> Service<Request> for AppGuardMiddlewareImpl<S>
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
        let mut server = self.middleware.ctx.server.clone();
        let ctx = self.middleware.ctx.clone();
        let next_service = self.next_service.clone();

        Box::pin(async move {
            // first check cache
            let cache_key = to_cache_key(&req);
            if let Some(policy) = ctx.cache.lock().await.get(&cache_key) {
                return if *policy == FirewallPolicy::Deny {
                    Ok(unauthorized_response())
                } else {
                    let fut = next_service.lock().unwrap().call(req);
                    fut.await
                };
            }

            let token = ctx.token_provider.get().await.unwrap_or_default();
            let fw_defaults = *ctx.firewall_defaults.lock().await;
            let timeout = fw_defaults.timeout;
            let default_policy = FirewallPolicy::try_from(fw_defaults.policy).unwrap_or_default();

            let Ok(AppGuardTcpResponse { tcp_info }) = server
                .handle_tcp_connection(timeout, to_appguard_tcp_connection(&req, token.clone()))
                .await
            else {
                return Ok(internal_server_error_response());
            };

            let Ok(request_handler_res) = server
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
                ctx.cache
                    .lock()
                    .await
                    .insert(cache_key, FirewallPolicy::Deny);
                return Ok(unauthorized_response());
            }

            let fut = next_service.lock().unwrap().call(req);

            let resp: Response = fut.await?;

            let Ok(response_handler_res) = server
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
                ctx.cache
                    .lock()
                    .await
                    .insert(cache_key, FirewallPolicy::Deny);
                return Ok(unauthorized_response());
            }

            ctx.cache
                .lock()
                .await
                .insert(cache_key, FirewallPolicy::Allow);
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

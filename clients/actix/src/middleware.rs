use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;

use crate::conversions::{
    to_appguard_http_request, to_appguard_http_response, to_appguard_tcp_connection,
};
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error, HttpResponse, ResponseError,
};
use appguard_client_authentication::Context;
use nullnet_libappguard::appguard_commands::FirewallPolicy;
use nullnet_libappguard::AppGuardGrpcInterface;

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

type LocalBoxFuture<T> = Pin<Box<dyn Future<Output = T> + 'static>>;

impl<S> Transform<S, ServiceRequest> for AppGuardConfig
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = S::Response;
    type Error = Error;
    type Transform = AppGuardMiddleware<S>;
    type InitError = ();
    type Future = LocalBoxFuture<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        let config = self.to_owned();
        Box::pin(async move {
            Ok(AppGuardMiddleware {
                config,
                next_service: Rc::new(service),
            })
        })
    }
}

pub struct AppGuardMiddleware<S> {
    config: AppGuardConfig,
    next_service: Rc<S>,
}

impl<S> Service<ServiceRequest> for AppGuardMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = S::Response;
    type Error = Error;
    type Future = LocalBoxFuture<Result<Self::Response, Self::Error>>;

    // this service is ready when its next service is ready
    forward_ready!(next_service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let mut client = self.config.client.clone();
        let timeout = self.config.timeout;
        let default_policy = self.config.default_policy;
        let ctx = self.config.ctx.clone();
        let next_service = self.next_service.clone();

        Box::pin(async move {
            let token = ctx.token_provider.get().await.unwrap_or_default();

            let tcp_info = client
                .handle_tcp_connection(timeout, to_appguard_tcp_connection(&req, token.clone()))
                .await
                .map_err(|e| GrcpError::new(e.message()))?
                .tcp_info;

            let request_handler_res = client
                .handle_http_request(
                    timeout,
                    default_policy,
                    to_appguard_http_request(&req, tcp_info.clone(), token.clone()),
                )
                .await
                .map_err(|e| GrcpError::new(e.message()))?;

            let policy = FirewallPolicy::try_from(request_handler_res.policy).unwrap_or_default();
            if policy == FirewallPolicy::Deny {
                return Ok(req.into_response(HttpResponse::Unauthorized().body("Unauthorized")));
            }

            let fut = next_service.call(req);

            let resp: ServiceResponse = fut.await?;

            let response_handler_res = client
                .handle_http_response(
                    timeout,
                    default_policy,
                    to_appguard_http_response(&resp, tcp_info, token),
                )
                .await
                .map_err(|e| GrcpError::new(e.message()))?;

            let policy = FirewallPolicy::try_from(response_handler_res.policy).unwrap_or_default();
            if policy == FirewallPolicy::Deny {
                return Ok(resp.into_response(HttpResponse::Unauthorized().body("Unauthorized")));
            }

            Ok(resp)
        })
    }
}

#[derive(Debug)]
struct GrcpError {
    message: String,
}

impl GrcpError {
    fn new(message: &str) -> Self {
        GrcpError {
            message: message.to_string(),
        }
    }
}

impl Display for GrcpError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl ResponseError for GrcpError {}

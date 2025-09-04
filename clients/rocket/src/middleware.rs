use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Status;
use rocket::{Data, Request, Response};

use crate::conversions::{
    to_appguard_http_request, to_appguard_http_response, to_appguard_tcp_connection, to_cache_key,
};
use appguard_client_authentication::Context;
use nullnet_libappguard::appguard::AppGuardTcpResponse;
use nullnet_libappguard::appguard_commands::FirewallPolicy;

/// `AppGuard` middleware.
pub struct AppGuardMiddleware {
    ctx: Context,
}

impl AppGuardMiddleware {
    /// Create a new `AppGuard` middleware instance.
    #[must_use]
    pub async fn new() -> Option<Self> {
        let ctx = Context::new(String::from("Rocket")).await.ok()?;

        Some(AppGuardMiddleware { ctx })
    }
}

#[rocket::async_trait]
impl Fairing for AppGuardMiddleware {
    fn info(&self) -> Info {
        Info {
            name: "AppGuard",
            kind: Kind::Request | Kind::Response,
        }
    }

    async fn on_request(&self, req: &mut Request<'_>, _data: &mut Data<'_>) {
        // first check cache
        let cache_key = to_cache_key(req);
        if let Some(policy) = self.ctx.cache.lock().await.get(&cache_key) {
            if *policy == FirewallPolicy::Deny {
                panic!("Unauthorized");
            } else {
                return;
            }
        }

        let mut server = self.ctx.server.clone();
        let token = self.ctx.token_provider.get().await.unwrap_or_default();
        let fw_defaults = *self.ctx.firewall_defaults.lock().await;
        let timeout = fw_defaults.timeout;
        let default_policy = FirewallPolicy::try_from(fw_defaults.policy).unwrap_or_default();

        let AppGuardTcpResponse { tcp_info } = server
            .handle_tcp_connection(timeout, to_appguard_tcp_connection(req, token.clone()))
            .await
            .expect("Internal server error");

        req.local_cache(|| tcp_info.clone());

        let request_handler_res = server
            .handle_http_request(
                timeout,
                default_policy,
                to_appguard_http_request(req, tcp_info, token),
            )
            .await
            .expect("Internal server error");

        let policy = FirewallPolicy::try_from(request_handler_res.policy).unwrap_or_default();
        if policy == FirewallPolicy::Deny {
            self.ctx
                .cache
                .lock()
                .await
                .insert(cache_key, FirewallPolicy::Deny);
            panic!("Unauthorized");
        }
    }

    async fn on_response<'r>(&self, req: &'r Request<'_>, resp: &mut Response<'r>) {
        // first check cache
        let cache_key = to_cache_key(req);
        if let Some(policy) = self.ctx.cache.lock().await.get(&cache_key) {
            if *policy == FirewallPolicy::Deny {
                *resp = unauthorized_response();
            }
            return;
        }

        let mut server = self.ctx.server.clone();
        let token = self.ctx.token_provider.get().await.unwrap_or_default();
        let fw_defaults = *self.ctx.firewall_defaults.lock().await;
        let timeout = fw_defaults.timeout;
        let default_policy = FirewallPolicy::try_from(fw_defaults.policy).unwrap_or_default();

        let tcp_info = req.local_cache(|| None);

        let Ok(response_handler_res) = server
            .handle_http_response(
                timeout,
                default_policy,
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
        }
        self.ctx.cache.lock().await.insert(cache_key, policy);
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

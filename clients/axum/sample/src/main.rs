use std::net::SocketAddr;
use appguard_axum::{AppGuardConfig, FirewallPolicy};
use axum::{routing::get, Router};

#[cfg(debug_assertions)]
const HOST: &str = "localhost";
#[cfg(not(debug_assertions))]
const HOST: &str = "appguard";

async fn hello() -> String {
    "Hello!".to_string()
}

// async fn not_found() -> impl Responder {
//     HttpResponse::NotFound().body("404 - Not Found")
// }

#[tokio::main]
async fn main() {
    let appguard_config = AppGuardConfig::new(HOST, 50051, true, Some(1000), FirewallPolicy::Allow);

    let listener = tokio::net::TcpListener::bind(format!("{HOST}:3000"))
        .await
        .unwrap();

    let app = Router::new()
        .route("/hello", get(hello))
        .layer(appguard_config)
        .into_make_service_with_connect_info::<SocketAddr>();

    axum::serve(listener, app).await.unwrap();
}

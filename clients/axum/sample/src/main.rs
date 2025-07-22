use appguard_axum::{AppGuardConfig};
use axum::http::{Response, StatusCode};
use axum::{routing::get, Router};
use axum_embed::{FallbackBehavior, ServeEmbed};
use rust_embed::RustEmbed;
use std::net::SocketAddr;

#[cfg(debug_assertions)]
const HOST: &str = "localhost";
#[cfg(not(debug_assertions))]
const HOST: &str = "appguard";

async fn hello() -> Response<String> {
    let mut response = Response::new("Hello!".to_string());
    *response.status_mut() = StatusCode::OK;
    response
}

async fn not_found() -> Response<String> {
    let mut response = Response::new("Not found".to_string());
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
}

#[derive(RustEmbed, Clone)]
#[folder = "../../../static/formMD"]
struct FormMD;

#[tokio::main]
async fn main() {
    // let logger_config = LoggerConfig::new(true, false, None, vec!["axum_sample"]);
    // Logger::init(logger_config);

    let appguard_config = AppGuardConfig::new(
        HOST,
        50051,
        false,
    )
    .await
    .unwrap();

    let listener = tokio::net::TcpListener::bind(format!("{HOST}:3002"))
        .await
        .unwrap();

    let serve_assets = ServeEmbed::<FormMD>::with_parameters(
        None,
        FallbackBehavior::NotFound,
        Some("index.html".to_string()),
    );

    let app = Router::new()
        .route("/hello", get(hello))
        .nest_service("/", serve_assets)
        .fallback(get(not_found))
        .layer(appguard_config)
        .into_make_service_with_connect_info::<SocketAddr>();

    axum::serve(listener, app).await.unwrap();
}

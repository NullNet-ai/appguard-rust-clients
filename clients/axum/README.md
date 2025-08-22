# appguard-axum

[AppGuard](https://github.com/NullNet-ai/appguard-server) client for [Axum](https://github.com/tokio-rs/axum).

### Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
appguard-axum = "0.2"
```

### Usage

```rust
use axum::Router;
use appguard_axum::AppGuardMiddleware;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let middleware = AppGuardMiddleware::new().await.unwrap();
    
    let listener = tokio::net::TcpListener::bind(format!("{HOST}:{PORT}"))
            .await
            .unwrap();
            
        let app = Router::new()
            .route(...)
            .fallback(...)
            .layer(middleware)
            .into_make_service_with_connect_info::<SocketAddr>();
    
        axum::serve(listener, app).await.unwrap();
}
```

A complete working example can be found [here](https://github.com/NullNet-ai/appguard-rust-clients/blob/main/clients/axum/sample/src/main.rs).

### Environment variables

The following environment variables must be set for the client to work:
- `CONTROL_SERVICE_ADDR`: AppGuard server's IP address
- `CONTROL_SERVICE_PORT`: AppGuard server's port
- `INSTALLATION_CODE`: installation code for this client

# appguard-actix

[AppGuard](https://github.com/NullNet-ai/appguard-server) client for [Actix Web](https://github.com/actix/actix-web).

### Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
appguard-actix = "0.2"
```

### Usage

```rust
use actix_web::{App, HttpServer};
use appguard_actix::AppGuardMiddleware;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let middleware = AppGuardMiddleware::new().await.unwrap();
    
        HttpServer::new(move || {
            App::new()
                .wrap(middleware.clone())
                .service(...)
        })
        .bind(...)?
        .run()
        .await
}
```

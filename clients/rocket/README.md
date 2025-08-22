# appguard-rocket

[AppGuard](https://github.com/NullNet-ai/appguard-server) client for [Rocket](https://github.com/rwf2/Rocket/).

### Installation

Add the following to your `Cargo.toml`:

```toml
[dependencies]
appguard-rocket = "0.2"
```

### Usage

```rust
#[macro_use]
extern crate rocket;
use appguard_rocket::AppGuardMiddleware;

#[launch]
async fn rocket() -> _ {
    let middleware = AppGuardMiddleware::new().await.unwrap();
 
    let addr = format!("{HOST}:{PORT}")
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    let rocket_config = rocket::Config::figment()
        .merge(("address", addr.ip()))
        .merge(("port", addr.port()))
        .merge(...);

    rocket::custom(rocket_config)
        .attach(middleware)
        .mount(...)
}
```

A complete working example can be found [here](https://github.com/NullNet-ai/appguard-rust-clients/blob/main/clients/rocket/sample/src/main.rs).

### Environment variables

The following environment variables must be set for the client to work:
- `CONTROL_SERVICE_ADDR`: AppGuard server's IP address
- `CONTROL_SERVICE_PORT`: AppGuard server's port
- `INSTALLATION_CODE`: installation code for this client

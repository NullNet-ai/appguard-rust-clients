#[macro_use]
extern crate rocket;

use appguard_rocket::AppGuardMiddleware;
use rocket::fs::{relative, FileServer};
use std::net::ToSocketAddrs;

#[cfg(debug_assertions)]
const HOST: &str = "localhost";
#[cfg(not(debug_assertions))]
const HOST: &str = "appguard";

#[launch]
async fn rocket() -> _ {
    env_logger::init();
    // let logger_config = LoggerConfig::new(true, false, None, vec!["rocket_sample"]);
    // Logger::init(logger_config);

    let addr = format!("{HOST}:3003")
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    let rocket_config = rocket::Config::figment()
        .merge(("address", addr.ip()))
        .merge(("port", addr.port()))
        .merge(("log_level", "critical"));

    let middleware = AppGuardMiddleware::new().await.unwrap();

    rocket::custom(rocket_config)
        .attach(middleware)
        .mount("/", FileServer::from(relative!("../../../static/formMD")))
}

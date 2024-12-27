#[macro_use]
extern crate rocket;

use appguard_rocket::AppGuardConfig;
use appguard_rocket::FirewallPolicy;
use rocket::fs::{relative, FileServer};
use std::net::ToSocketAddrs;

#[cfg(debug_assertions)]
const HOST: &str = "localhost";
#[cfg(not(debug_assertions))]
const HOST: &str = "appguard";

#[launch]
async fn rocket() -> _ {
    let addr = format!("{HOST}:3003")
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();

    let rocket_config = rocket::Config::figment()
        .merge(("address", addr.ip()))
        .merge(("port", addr.port()))
        .merge(("log_level", "critical"));

    let appguard_config =
        AppGuardConfig::new(HOST, 50051, true, Some(1000), FirewallPolicy::Allow).await;

    rocket::custom(rocket_config)
        .attach(appguard_config)
        .mount("/", FileServer::from(relative!("../../../static/formMD")))
}

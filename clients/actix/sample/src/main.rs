use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};

use appguard_actix::{AppGuardConfig, FirewallPolicy};

#[cfg(debug_assertions)]
const HOST: &str = "localhost";
#[cfg(not(debug_assertions))]
const HOST: &str = "appguard";

#[get("/hello")]
async fn hello() -> impl Responder {
    HttpResponse::Ok().body("Hello!")
}

async fn not_found() -> impl Responder {
    HttpResponse::NotFound().body("404 - Not Found")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let appguard_config = AppGuardConfig::new(HOST, 50051, true, Some(1000), FirewallPolicy::Allow);

    HttpServer::new(move || {
        App::new()
            .wrap(appguard_config)
            .service(hello)
            .service(
                actix_files::Files::new("/", "../../../static/formMD").index_file("index.html"),
            )
            .default_service(web::get().to(not_found))
    })
    .bind((HOST, 3000))?
    .run()
    .await
}

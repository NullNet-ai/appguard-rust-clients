use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};

use appguard_actix::{AppGuardConfig};

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
    // let logger_config = LoggerConfig::new(true, false, None, vec!["actix_sample"]);
    // Logger::init(logger_config);

    let appguard_config = AppGuardConfig::new(HOST, 50051, false).await.unwrap();

    HttpServer::new(move || {
        App::new()
            .wrap(appguard_config.clone())
            .service(hello)
            .service(actix_files::Files::new("/", "./static/formMD").index_file("index.html"))
            .default_service(web::get().to(not_found))
    })
    .bind((HOST, 3001))?
    .run()
    .await
}

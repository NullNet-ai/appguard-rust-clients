use actix_web::{web, App, HttpResponse, HttpServer, Responder};

const FILESERVER: &str = "fs.color.dnamicro.net";
const FILESERVER_PORT: u16 = 8080;
const WEBSERVER: &str = "0.0.0.0";

async fn remote_color() -> impl Responder {
    let remote = format!("http://{FILESERVER}:{FILESERVER_PORT}");
    let color = reqwest::get(remote).await.unwrap().text().await.unwrap();
    let body = format!("<!DOCTYPE html>
    <html>
        <body style=\"background:{color};display:flex;height:100vh;align-items:center;margin:0;\">
            <div align=\"center\" style=\"background:#ffffff55;color:#000000;overflow:auto;width:100vw;margin:0 auto;\">
                <h1><i>{color}</i></h1>
            </div>
        </body>
    </html>");
    HttpResponse::Ok().body(body)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    println!("Running on {WEBSERVER}:3001");
    println!("Interacting with file server at {FILESERVER}:{FILESERVER_PORT}");

    HttpServer::new(move || App::new().default_service(web::get().to(remote_color)))
        .bind((WEBSERVER, 3001))?
        .run()
        .await
}

use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;

const FILESERVER: &str = "fs.color.com";
const FILESERVER_PORT: u16 = 8080;
const WEBSERVER: &str = "0.0.0.0";
const TIMESTAMP_SERVER: &str = "ts.color.com:5555";

struct TimestampConn {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl TimestampConn {
    async fn fetch(&mut self) -> std::io::Result<String> {
        self.writer.write_all(b"ping\n").await?;
        let mut line = String::new();
        self.reader.read_line(&mut line).await?;
        Ok(line.trim().to_string())
    }
}

async fn remote_color(conn: web::Data<Mutex<TimestampConn>>) -> impl Responder {
    let timestamp = conn
        .lock()
        .await
        .fetch()
        .await
        .unwrap_or_else(|e| format!("timestamp error: {e}"));

    let remote = format!("http://{FILESERVER}:{FILESERVER_PORT}");
    let color = reqwest::get(remote).await.unwrap().text().await.unwrap();
    let body = format!(
        "<!DOCTYPE html>
    <html>
        <body style=\"background:{color};display:flex;height:100vh;align-items:center;margin:0;\">
            <div align=\"center\" style=\"background:#ffffff55;color:#000000;overflow:auto;width:100vw;margin:0 auto;\">
                <h1><i>{color}</i></h1>
                <p>timestamp: {timestamp}</p>
            </div>
        </body>
    </html>"
    );
    HttpResponse::Ok().body(body)
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    // loop {
    //     match TcpStream::connect(TIMESTAMP_SERVER).await {
    //         Ok(_) => break,
    //         Err(e) => {
    //             println!("Could not connect to timestamp server at {TIMESTAMP_SERVER}: {e}");
    //             println!("Retrying in 10 seconds...");
    //             tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
    //         }
    //     }
    // }

    println!("Connecting to timestamp server at {TIMESTAMP_SERVER}");
    let stream = TcpStream::connect(TIMESTAMP_SERVER).await?;
    let (r, w) = stream.into_split();
    let conn = web::Data::new(Mutex::new(TimestampConn {
        reader: BufReader::new(r),
        writer: w,
    }));

    println!("Running on {WEBSERVER}:3001");
    println!("Interacting with file server at {FILESERVER}:{FILESERVER_PORT}");

    HttpServer::new(move || {
        App::new()
            .app_data(conn.clone())
            .default_service(web::get().to(remote_color))
    })
    .bind((WEBSERVER, 3001))?
    .run()
    .await
}

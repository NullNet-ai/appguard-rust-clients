use std::process::Stdio;

use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::sync::Mutex;

const FILESERVER: &str = "fs.color.dnamicro.net";
const FILESERVER_PORT: u16 = 8080;
const WEBSERVER: &str = "0.0.0.0";
const TIMESTAMP_SERVER: &str = "timestamp_server.color.dnamicro.net:5555";
// Path inside the container; the host file is expected to be mounted here,
// e.g. -v /root/nullnet/members/nullnet-server/graph.dot:/graph.dot:ro
const GRAPH_DOT: &str = "/graph.dot";

struct TimestampConn {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
    opened_at: String,
}

impl TimestampConn {
    async fn fetch(&mut self) -> std::io::Result<String> {
        self.writer.write_all(b"ping\n").await?;
        let mut line = String::new();
        self.reader.read_line(&mut line).await?;
        Ok(line.trim().to_string())
    }
}

async fn render_graph_svg() -> Result<String, String> {
    let dot = tokio::fs::read(GRAPH_DOT)
        .await
        .map_err(|e| format!("could not read {GRAPH_DOT}: {e}"))?;

    let mut child = Command::new("dot")
        .arg("-Tsvg")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("could not spawn dot: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(&dot)
            .await
            .map_err(|e| format!("write to dot stdin: {e}"))?;
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("waiting for dot: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "dot exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    // Strip the XML/DOCTYPE prologue so the SVG embeds cleanly inline.
    let svg = String::from_utf8_lossy(&output.stdout).to_string();
    let svg = svg
        .find("<svg")
        .map(|i| svg[i..].to_string())
        .unwrap_or(svg);
    Ok(svg)
}

async fn remote_color(conn: web::Data<Mutex<TimestampConn>>) -> impl Responder {
    let (timestamp, opened_at) = {
        let mut guard = conn.lock().await;
        let opened_at = guard.opened_at.clone();
        let timestamp = guard
            .fetch()
            .await
            .unwrap_or_else(|e| format!("timestamp error: {e}"));
        (timestamp, opened_at)
    };

    let remote = format!("http://{FILESERVER}:{FILESERVER_PORT}");
    let color = reqwest::get(remote).await.unwrap().text().await.unwrap();
    let graph = match render_graph_svg().await {
        Ok(svg) => svg,
        Err(e) => format!("<pre>graph unavailable: {e}</pre>"),
    };
    let body = format!(
        "<!DOCTYPE html>
    <html>
        <body style=\"background:{color};display:flex;flex-direction:column;min-height:100vh;align-items:center;margin:0;\">
            <div align=\"center\" style=\"background:#ffffff55;color:#000000;overflow:auto;width:100vw;margin:0 auto;\">
                <h1><i>{color}</i></h1>
                <p>latest timestamp: {timestamp}</p>
                <p>connection opened at: {opened_at}</p>
            </div>
            <div align=\"center\" style=\"background:#ffffffcc;color:#000000;width:100vw;margin:0 auto;padding:1rem 0;\">
                <h2>architecture</h2>
                <div style=\"max-width:95vw;overflow:auto;\">{graph}</div>
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
    let mut conn = TimestampConn {
        reader: BufReader::new(r),
        writer: w,
        opened_at: String::new(),
    };
    conn.opened_at = conn.fetch().await?;
    println!(
        "TCP connection to timestamp server opened at {}",
        conn.opened_at
    );
    let conn = web::Data::new(Mutex::new(conn));

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

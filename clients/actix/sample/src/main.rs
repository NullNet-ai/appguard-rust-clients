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
// Directory inside the container; the host directory is expected to be mounted here,
// e.g. -v /root/nullnet/members/nullnet-server/graphs:/graphs:ro
const GRAPHS_DIR: &str = "/graphs";

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

async fn list_stacks() -> std::io::Result<Vec<String>> {
    let mut entries = tokio::fs::read_dir(GRAPHS_DIR).await?;
    let mut stacks = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("dot") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                stacks.push(stem.to_string());
            }
        }
    }
    stacks.sort();
    Ok(stacks)
}

async fn render_graph_svg(stack: &str) -> Result<String, String> {
    let path = format!("{GRAPHS_DIR}/{stack}.dot");
    let dot = tokio::fs::read(&path)
        .await
        .map_err(|e| format!("could not read {path}: {e}"))?;

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

async fn fetch_color_and_timestamp(
    conn: &web::Data<Mutex<TimestampConn>>,
) -> (String, String, String) {
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
    (color, timestamp, opened_at)
}

fn stack_nav(stacks: &[String], current: Option<&str>) -> String {
    if stacks.is_empty() {
        return String::from("<p>no stacks available</p>");
    }
    let mut html = String::from(
        "<div style=\"display:flex;flex-wrap:wrap;gap:0.5rem;justify-content:center;padding:0.5rem;\">",
    );
    for s in stacks {
        let active = current == Some(s.as_str());
        let style = if active {
            "background:#000;color:#fff;padding:0.3rem 0.7rem;border-radius:4px;text-decoration:none;"
        } else {
            "background:#fff;color:#000;padding:0.3rem 0.7rem;border-radius:4px;text-decoration:none;border:1px solid #000;"
        };
        let _ = std::fmt::Write::write_fmt(
            &mut html,
            format_args!("<a href=\"/{s}\" style=\"{style}\">{s}</a>"),
        );
    }
    html.push_str("</div>");
    html
}

async fn stack_page(stack: web::Path<String>) -> impl Responder {
    let stack = stack.into_inner();
    let stacks = list_stacks().await.unwrap_or_default();
    let nav = stack_nav(&stacks, Some(&stack));
    let graph = match render_graph_svg(&stack).await {
        Ok(svg) => svg,
        Err(e) => format!("<pre>graph unavailable: {e}</pre>"),
    };
    let body = format!(
        "<!DOCTYPE html>
    <html>
        <body style=\"display:flex;flex-direction:column;min-height:100vh;align-items:center;margin:0;\">
            <div align=\"center\" style=\"width:100vw;margin:0 auto;padding:1rem 0;\">
                {nav}
                <h2>{stack}</h2>
                <div style=\"max-width:95vw;overflow:auto;\">{graph}</div>
            </div>
        </body>
    </html>"
    );
    HttpResponse::Ok().body(body)
}

async fn index_page(conn: web::Data<Mutex<TimestampConn>>) -> impl Responder {
    let (color, timestamp, opened_at) = fetch_color_and_timestamp(&conn).await;
    let stacks = list_stacks().await.unwrap_or_default();
    let nav = stack_nav(&stacks, None);
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
                <h2>stacks</h2>
                {nav}
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
    println!("Serving graphs from {GRAPHS_DIR}");

    HttpServer::new(move || {
        App::new()
            .app_data(conn.clone())
            .route("/", web::get().to(index_page))
            .route("/{stack}", web::get().to(stack_page))
    })
    .bind((WEBSERVER, 3001))?
    .run()
    .await
}

// Raw-TCP test server: listens on TCP 5555 and writes the current Unix
// timestamp (seconds) to every connecting client, then closes.
//
// Run:    cargo run -p timestamp_server
// Test:   nc 127.0.0.1 5555

use std::io::Write;
use std::net::{TcpListener, TcpStream};

use chrono::Utc;

fn handle(mut stream: TcpStream) {
    let now = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    let _ = writeln!(stream, "{}", now);
}

fn main() {
    let addr = "0.0.0.0:5555";
    let listener = TcpListener::bind(addr).expect("bind");
    println!("listening on {addr}");

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let peer = s.peer_addr().ok();
                std::thread::spawn(move || {
                    handle(s);
                    if let Some(p) = peer {
                        println!("served {p}");
                    }
                });
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
}
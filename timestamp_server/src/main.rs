// Raw-TCP test server: listens on TCP 5555. Connections are long-lived: for
// every line the client sends, the server replies with the current UTC
// timestamp. Loops until the client disconnects.
//
// Run:    cargo run -p timestamp_server
// Test:   nc 127.0.0.1 5555   (then type ENTER repeatedly)

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};

use chrono::Utc;

fn handle(stream: TcpStream) {
    let peer = stream.peer_addr().ok();
    let mut writer = stream.try_clone().expect("clone stream");
    let mut reader = BufReader::new(stream);
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break, // EOF
            Ok(_) => {
                let now = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
                if writeln!(writer, "{}", now).is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    if let Some(p) = peer {
        println!("disconnected {p}");
    }
}

fn main() {
    let addr = "0.0.0.0:5555";
    let listener = TcpListener::bind(addr).expect("bind");
    println!("listening on {addr}");

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                if let Ok(p) = s.peer_addr() {
                    println!("connected {p}");
                }
                std::thread::spawn(move || handle(s));
            }
            Err(e) => eprintln!("accept error: {e}"),
        }
    }
}
use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

const RESP: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 27\r\nContent-Type: application/json\r\nConnection: keep-alive\r\n\r\n{\"status\":\"ok\",\"version\":1}";

fn main() {
    let listener = TcpListener::bind("0.0.0.0:19876").expect("bind");
    println!("Backend ready on :19876");
    for stream in listener.incoming() {
        let mut stream = stream.expect("accept");
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => { let _ = stream.write_all(RESP); }
                }
            }
        });
    }
}

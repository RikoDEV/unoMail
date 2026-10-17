//! Hostile MIME structures: parsing must stay bounded and never take the server down.

use std::time::{Duration, Instant};

fn nested(depth: usize) -> Vec<u8> {
    let mut out = String::from("From: a@b.example\r\nTo: c@d.example\r\nSubject: nested\r\nMIME-Version: 1.0\r\n");
    for level in 0..depth {
        out.push_str(&format!("Content-Type: multipart/mixed; boundary=\"b{level}\"\r\n\r\n--b{level}\r\n"));
    }
    out.push_str("Content-Type: text/plain\r\n\r\ndeep\r\n");
    for level in (0..depth).rev() {
        out.push_str(&format!("--b{level}--\r\n"));
    }
    out.into_bytes()
}

#[test]
fn deeply_nested_multiparts_parse_without_overflowing_the_stack() {
    for depth in [100, 1_000, 10_000, 50_000] {
        let raw = nested(depth);
        let started = Instant::now();
        // Parsed on a thread with the default stack, as a server task would be.
        let handle = std::thread::Builder::new().stack_size(2 * 1024 * 1024).spawn(move || mail_parser::MessageParser::default().parse(&raw).map(|m| m.parts.len())).unwrap();
        let parts = handle.join().expect("the parser must not overflow the stack");
        println!("depth {depth}: {parts:?} parts in {:?}", started.elapsed());
        assert!(started.elapsed() < Duration::from_secs(10), "depth {depth} took {:?}", started.elapsed());
    }
}

#[test]
fn many_parts_and_headers_stay_bounded() {
    let mut out = String::from("From: a@b.example\r\nSubject: wide\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"b\"\r\n");
    for i in 0..20_000 {
        out.push_str(&format!("X-Header-{i}: value\r\n"));
    }
    out.push_str("\r\n");
    for _ in 0..50_000 {
        out.push_str("--b\r\nContent-Type: text/plain\r\n\r\nx\r\n");
    }
    out.push_str("--b--\r\n");
    let started = Instant::now();
    let parsed = mail_parser::MessageParser::default().parse(out.as_bytes()).unwrap();
    println!("{} parts in {:?}", parsed.parts.len(), started.elapsed());
    assert!(started.elapsed() < Duration::from_secs(10));
}

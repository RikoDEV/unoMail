//! Incoming mail through external content filters (milter protocol).

mod common;

use common::{Client, TestEnv, message};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

async fn packet(stream: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    let mut length = [0u8; 4];
    stream.read_exact(&mut length).await.ok()?;
    let mut data = vec![0u8; u32::from_be_bytes(length) as usize];
    stream.read_exact(&mut data).await.ok()?;
    Some((data[0], data[1..].to_vec()))
}

async fn send(stream: &mut TcpStream, code: u8, data: &[u8]) {
    let mut out = ((data.len() + 1) as u32).to_be_bytes().to_vec();
    out.push(code);
    out.extend_from_slice(data);
    stream.write_all(&out).await.unwrap();
}

/// A filter that tags every message, rewrites its subject, and refuses bodies saying "virus".
async fn fake_milter(mut stream: TcpStream) {
    let mut body = Vec::new();
    while let Some((code, data)) = packet(&mut stream).await {
        match code {
            b'O' => {
                // Same actions as offered; ask for no step to be skipped.
                let mut reply = 6u32.to_be_bytes().to_vec();
                reply.extend_from_slice(&data[4..8]);
                reply.extend_from_slice(&0u32.to_be_bytes());
                send(&mut stream, b'O', &reply).await;
            }
            b'D' => {}
            b'B' => {
                body.extend_from_slice(&data);
                send(&mut stream, b'c', &[]).await;
            }
            b'E' => {
                if String::from_utf8_lossy(&body).contains("virus") {
                    send(&mut stream, b'y', b"554 5.7.1 Infected, says the filter\0").await;
                } else {
                    send(&mut stream, b'h', b"X-Filtered\0yes\0").await;
                    let mut change = 1u32.to_be_bytes().to_vec();
                    change.extend_from_slice(b"Subject\0[checked] Hello\0");
                    send(&mut stream, b'm', &change).await;
                    send(&mut stream, b'c', &[]).await;
                }
            }
            b'Q' => return,
            _ => send(&mut stream, b'c', &[]).await,
        }
    }
}

#[tokio::test]
async fn milters_edit_reject_and_fail_closed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(fake_milter(stream));
        }
    });
    let env = TestEnv::start_with(|cfg| cfg.milters = vec![address]).await;
    env.domain("example.org").await;
    let bob = env.account("bob@example.org").await;

    let mut smtp = Client::smtp(env.mx).await;
    let msg = message("alice@remote.example", "bob@example.org", "Hello", "a normal message");
    assert!(smtp.send_mail("alice@remote.example", &["bob@example.org"], &msg).await.starts_with("250"));
    let stored = env.inbox(&bob).await.pop().unwrap();
    assert!(stored.contains("X-Filtered: yes\r\n") && stored.contains("Subject: [checked] Hello\r\n") && !stored.contains("Subject: Hello"), "{stored}");
    assert!(stored.ends_with("a normal message\r\n"));

    let msg = message("alice@remote.example", "bob@example.org", "Bad", "contains a virus");
    assert_eq!(smtp.send_mail("alice@remote.example", &["bob@example.org"], &msg).await, "554 5.7.1 Infected, says the filter");
    assert_eq!(env.inbox(&bob).await.len(), 1);

    // An unreachable filter defers mail unless told to let it through.
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap().to_string();
    let env = TestEnv::start_with(|cfg| cfg.milters = vec![closed]).await;
    env.domain("example.org").await;
    env.account("bob@example.org").await;
    let mut smtp = Client::smtp(env.mx).await;
    let msg = message("alice@remote.example", "bob@example.org", "Hello", "x");
    assert!(smtp.send_mail("alice@remote.example", &["bob@example.org"], &msg).await.starts_with("451 4.7.1"));
}

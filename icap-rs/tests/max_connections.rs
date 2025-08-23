use std::io;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

use icap_rs::server::Server;

async fn pick_free_port() -> io::Result<u16> {
    let l = TcpListener::bind("127.0.0.1:0").await?;
    let port = l.local_addr()?.port();
    drop(l);
    Ok(port)
}

/// Запускаем сервер на 127.0.0.1:{port} с глобальным лимитом соединений.
async fn start_server_with_limit(
    limit: usize,
) -> Result<(tokio::task::JoinHandle<()>, u16), io::Error> {
    let port = pick_free_port().await?;
    let server = Server::builder()
        .bind(&format!("127.0.0.1:{port}"))
        .with_max_connections(limit)
        .build()
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("build: {e}")))?;

    // поднимаем сервер
    let handle = tokio::spawn(async move {
        let _ = server.run().await;
    });

    // даём серверу время забиндиться
    sleep(Duration::from_millis(50)).await;
    Ok((handle, port))
}

/// читаем чуть-чуть из сокета с таймаутом; Ok(Some(n)) — прочитали n байт; Ok(None) — EOF
async fn read_some_with_timeout(s: &mut TcpStream, ms: u64) -> io::Result<Option<usize>> {
    match timeout(Duration::from_millis(ms), s.read(&mut [0u8; 4096])).await {
        Ok(Ok(0)) => Ok(None),    // EOF
        Ok(Ok(n)) => Ok(Some(n)), // есть байты
        Ok(Err(e)) => Err(e),     // ошибка
        Err(_) => Ok(Some(0)),    // таймаут (сокет жив)
    }
}

/// минимальный OPTIONS-запрос
fn build_options(port: u16, svc: &str) -> Vec<u8> {
    format!("OPTIONS icap://127.0.0.1:{port}/{svc} ICAP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        .into_bytes()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn respects_global_max_connections() -> Result<(), std::io::Error> {
    let (_srv, port) = start_server_with_limit(1).await?;

    // 1-й коннект — занимает permit
    let _hold = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;

    // 2-й коннект — должен получить ICAP 503
    let mut c2 = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let mut buf = vec![0u8; 2048];
    let n =
        tokio::time::timeout(std::time::Duration::from_millis(500), c2.read(&mut buf)).await??;
    assert!(n > 0, "ожидали получить ICAP-ответ 503");

    let head = String::from_utf8_lossy(&buf[..n]).to_ascii_uppercase();
    assert!(
        head.starts_with("ICAP/1.0 503"),
        "должен прийти ICAP/1.0 503, получили:\n{head}"
    );
    assert!(
        head.contains("ENCAPSULATED: NULL-BODY=0"),
        "ожидали Encapsulated: null-body=0:\n{head}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn options_advertises_global_limit_in_default_response() -> Result<(), io::Error> {
    let (_srv, port) = start_server_with_limit(3).await?;

    let mut c = TcpStream::connect(("127.0.0.1", port)).await?;
    let req = build_options(port, "unknown");
    c.write_all(&req).await?;

    let mut buf = Vec::with_capacity(4096);
    let n = timeout(Duration::from_millis(500), c.read_buf(&mut buf)).await??;
    assert!(n > 0, "expected some response bytes");

    let s = String::from_utf8_lossy(&buf);
    assert!(s.starts_with("ICAP/1.0 "), "not an ICAP response:\n{s}");
    assert!(
        s.to_ascii_lowercase().contains("max-connections: 3"),
        "OPTIONS must advertise Max-Connections: 3\n{s}"
    );

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allows_two_connections_when_limit_is_two() -> Result<(), io::Error> {
    let (_srv, port) = start_server_with_limit(2).await?;

    let mut c1 = TcpStream::connect(("127.0.0.1", port)).await?;
    let mut c2 = TcpStream::connect(("127.0.0.1", port)).await?;

    let r1 = read_some_with_timeout(&mut c1, 200).await?;
    let r2 = read_some_with_timeout(&mut c2, 200).await?;
    // допускаем таймаут (Some(0)), но не EOF
    assert!(r1.is_some(), "conn1 should still be open");
    assert!(r2.is_some(), "conn2 should still be open");

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn returns_503_when_over_connection_limit() -> Result<(), io::Error> {
    // лимит 1: первый коннект держим открытым, второй должен получить ICAP 503
    let (_srv, port) = start_server_with_limit(1).await?;

    // первый коннект — занимает permit
    let _hold = TcpStream::connect(("127.0.0.1", port)).await?;
    sleep(Duration::from_millis(30)).await;

    // второй коннект — сервер должен сразу прислать ICAP/1.0 503 и закрыть сокет
    let mut c2 = TcpStream::connect(("127.0.0.1", port)).await?;

    // читаем чуть-чуть данных (заголовков достаточно), ожидаем, что придёт 503
    let mut buf = vec![0u8; 2048];
    let n = timeout(Duration::from_millis(500), c2.read(&mut buf)).await??;
    assert!(n > 0, "ожидали получить ICAP-ответ 503, но пришло 0 байт");

    let text = String::from_utf8_lossy(&buf[..n]).to_string();
    let start = text.lines().next().unwrap_or_default().to_ascii_uppercase();

    assert!(
        start.starts_with("ICAP/1.0 503"),
        "должен прийти статусная строка ICAP/1.0 503, получили:\n{}",
        start
    );

    // Дополнительно проверим Encapsulated и отсутствие тела
    let lower = text.to_ascii_lowercase();
    assert!(
        lower.contains("encapsulated: null-body=0"),
        "в ответе должен быть Encapsulated: null-body=0, получили:\n{}",
        text
    );

    Ok(())
}

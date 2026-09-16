//! Small networking helpers: HTTP CONNECT tunnelling and base64 (to avoid extra dependencies).

use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

use crate::config::ProxySpec;

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64[((n >> 18) & 63) as usize] as char);
        out.push(B64[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            B64[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Sends `CONNECT host:port` to the upstream proxy and returns the established stream.
pub async fn http_connect_tunnel(
    proxy: &ProxySpec,
    host: &str,
    port: u16,
) -> io::Result<TcpStream> {
    let url = Url::parse(&proxy.url)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("proxy url: {e}")))?;
    let phost = url
        .host_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "proxy url without host"))?;
    let pport = url.port_or_known_default().unwrap_or(3128);
    let mut s = TcpStream::connect((phost, pport)).await?;
    let mut req = format!(
        "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\nProxy-Connection: keep-alive\r\n"
    );
    if let Some(u) = &proxy.username {
        let cred = format!("{u}:{}", proxy.password.as_deref().unwrap_or(""));
        req.push_str(&format!(
            "Proxy-Authorization: Basic {}\r\n",
            base64_encode(cred.as_bytes())
        ));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        let n = s.read(&mut byte).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "proxy closed during CONNECT",
            ));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "proxy CONNECT response too large",
            ));
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let status = head.split_whitespace().nth(1).unwrap_or("");
    if status != "200" {
        return Err(io::Error::other(format!(
            "proxy refused CONNECT {host}:{port}: {}",
            head.lines().next().unwrap_or("")
        )));
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"user:pass"), "dXNlcjpwYXNz");
    }

    #[tokio::test]
    async fn connect_tunnel_talks_http() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = s.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            assert!(
                req.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"),
                "{req}"
            );
            assert!(
                req.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"),
                "{req}"
            );
            s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            s.write_all(b"tunnel-ok").await.unwrap();
        });
        let spec = ProxySpec {
            url: format!("http://{addr}"),
            username: Some("user".into()),
            password: Some("pass".into()),
        };
        let mut s = http_connect_tunnel(&spec, "example.com", 443)
            .await
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "tunnel-ok");
    }
}

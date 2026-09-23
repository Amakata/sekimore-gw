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
    // #151: read now, not at start: the secret store may have been unlocked, or the credential
    // changed, since the relay came up
    if let Some((u, p)) = proxy.credential() {
        let cred = format!("{u}:{p}");
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
    if status == "407" {
        // #151: say which credential was refused. Squid and the relay can read different ones, and
        // "407" alone left the operator comparing the two by hand
        return Err(io::Error::other(format!(
            "proxy refused CONNECT {host}:{port}: {} — the relay presented the credential from {}. \
             Set it with mise run gw:proxy-credential, and unlock the store (mise run gw:unlock)",
            head.lines().next().unwrap_or(""),
            proxy.credential_source()
        )));
    }
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

    /// A proxy that accepts one CONNECT, hands back the Proxy-Authorization it saw, and answers
    /// with `status`.
    async fn one_connect(status: &'static str) -> (String, tokio::sync::oneshot::Receiver<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 2048];
            let n = s.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).into_owned();
            let auth = req
                .lines()
                .find_map(|l| l.strip_prefix("Proxy-Authorization: "))
                .unwrap_or("-")
                .to_string();
            let _ = tx.send(auth);
            s.write_all(format!("HTTP/1.1 {status}\r\n\r\n").as_bytes())
                .await
                .unwrap();
        });
        (format!("http://{addr}"), rx)
    }

    #[tokio::test]
    async fn the_tunnel_presents_the_stored_credential_over_the_environments() {
        // #151: the passthrough got 407 because it only ever had the environment's credential
        let (url, seen) = one_connect("200 Connection established").await;
        let spec = ProxySpec {
            url,
            username: Some("env-user".into()),
            password: Some("env-pass".into()),
            stored: Default::default(),
        };
        spec.stored
            .set(Some(("store-user".into(), "store-pass".into())));
        http_connect_tunnel(&spec, "example.com", 443)
            .await
            .unwrap();
        assert_eq!(
            seen.await.unwrap(),
            format!("Basic {}", base64_encode(b"store-user:store-pass"))
        );
    }

    #[tokio::test]
    async fn a_407_says_whose_credential_was_refused() {
        let (url, _) = one_connect("407 Proxy Authentication Required").await;
        let spec = ProxySpec {
            url,
            username: Some("env-user".into()),
            password: None,
            stored: Default::default(),
        };
        let err = http_connect_tunnel(&spec, "example.com", 443)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("407"), "{err}");
        assert!(
            err.contains("SEKIMORE_UPSTREAM_PROXY_* or config.yml"),
            "{err}"
        );
        assert!(err.contains("gw:proxy-credential"), "{err}");
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
            stored: Default::default(),
        };
        let mut s = http_connect_tunnel(&spec, "example.com", 443)
            .await
            .unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).await.unwrap();
        assert_eq!(out, "tunnel-ok");
    }
}

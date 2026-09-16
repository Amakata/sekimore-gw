//! Rewriting the upstream receive-pack response (report-status).
//!
//! When we rewrite `refs/for/<base>` to `refs/heads/sekimore/<base>-<sha7>` before pushing, upstream replies with
//! `ok refs/heads/sekimore/...`. send-pack matches reports against the ref names it sent, so we have to map them
//! back to the original names (`refs/for/<base>`); a report for an unknown ref, or a missing one, is treated as an error.
//! We could strip `report-status` instead, but then the agent would never see an `ng` (non-fast-forward and the like), so we do not.
//!
//! When side-band-64k has been negotiated, report-status arrives as pkt-lines inside band 1.
//! We reassemble the band 1 byte stream, rewrite it, and re-emit it on band 1. Bands 2 (progress) and 3 (error) are passed through unchanged.

use std::collections::HashMap;

use bytes::{Buf, BytesMut};

use crate::pktline::{encode_into, parse_one, Frame, Pkt, PktError, FLUSH, MAX_PKT_LEN};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefStatus {
    Ok,
    Ng(String),
}

pub struct ResponseRewriter {
    sideband: bool,
    /// upstream ref → client ref
    map: HashMap<String, String>,
    inner: BytesMut,
    inner_cap: usize,
    results: HashMap<String, RefStatus>,
    unpack_ok: Option<bool>,
}

impl ResponseRewriter {
    pub fn new(map: HashMap<String, String>, sideband: bool) -> Self {
        ResponseRewriter {
            sideband,
            map,
            inner: BytesMut::new(),
            inner_cap: 1 << 20,
            results: HashMap::new(),
            unpack_ok: None,
        }
    }

    pub fn results(&self) -> &HashMap<String, RefStatus> {
        &self.results
    }

    pub fn unpack_ok(&self) -> Option<bool> {
        self.unpack_ok
    }

    /// Process one frame from upstream, appending the bytes to send to the client to `out`.
    pub fn feed(&mut self, frame: &Frame, out: &mut Vec<u8>) -> Result<(), PktError> {
        match frame {
            Frame::Flush | Frame::Delim | Frame::ResponseEnd => {
                if self.sideband && !self.inner.is_empty() {
                    // Emit truncated inner data unchanged; do not drop it, it helps diagnosis.
                    let rest = self.inner.split().freeze();
                    emit_band1(out, &rest)?;
                }
                out.extend_from_slice(&frame.raw());
                Ok(())
            }
            Frame::Data(_) => {
                let payload = frame.payload();
                if !self.sideband {
                    let line = self.rewrite_line(payload);
                    return encode_into(out, &line);
                }
                if payload.is_empty() || payload[0] != 1 {
                    out.extend_from_slice(&frame.raw());
                    return Ok(());
                }
                self.inner.extend_from_slice(&payload[1..]);
                if self.inner.len() > self.inner_cap {
                    return Err(PktError::SectionTooLarge {
                        cap: self.inner_cap,
                    });
                }
                loop {
                    enum Inner {
                        Flush,
                        Data(Vec<u8>),
                        Other,
                    }
                    let (kind, n) = match parse_one(&self.inner)? {
                        None => break,
                        Some((Pkt::Flush, n)) => (Inner::Flush, n),
                        Some((Pkt::Data(p), n)) => (Inner::Data(p.to_vec()), n),
                        Some((_, n)) => (Inner::Other, n),
                    };
                    match kind {
                        Inner::Flush => {
                            self.inner.advance(n);
                            emit_band1(out, FLUSH)?;
                        }
                        Inner::Data(p) => {
                            let line = self.rewrite_line(&p);
                            let mut enc = Vec::with_capacity(line.len() + 4);
                            encode_into(&mut enc, &line)?;
                            self.inner.advance(n);
                            emit_band1(out, &enc)?;
                        }
                        Inner::Other => {
                            let raw = self.inner.split_to(n).freeze();
                            emit_band1(out, &raw)?;
                        }
                    }
                }
                Ok(())
            }
        }
    }

    /// Called after upstream EOF: emit any leftover inner data unchanged.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), PktError> {
        if self.sideband && !self.inner.is_empty() {
            let rest = self.inner.split().freeze();
            emit_band1(out, &rest)?;
        }
        Ok(())
    }

    /// Map the ref in `ok <ref>` / `ng <ref> <msg>` / `option refname <ref>` back to its original name. Everything else is left unchanged.
    pub fn rewrite_line(&mut self, payload: &[u8]) -> Vec<u8> {
        let (body, nl) = match payload.last() {
            Some(b'\n') => (&payload[..payload.len() - 1], true),
            _ => (payload, false),
        };
        let Ok(text) = std::str::from_utf8(body) else {
            return payload.to_vec();
        };
        let rebuilt: Option<String> = if let Some(rest) = text.strip_prefix("unpack ") {
            self.unpack_ok = Some(rest.trim() == "ok");
            None
        } else if let Some(r) = text.strip_prefix("ok ") {
            let r = r.trim_end();
            let client = self.map.get(r).cloned().unwrap_or_else(|| r.to_string());
            self.results.insert(client.clone(), RefStatus::Ok);
            self.map.get(r).map(|c| format!("ok {c}"))
        } else if let Some(r) = text.strip_prefix("ng ") {
            let (name, msg) = match r.split_once(' ') {
                Some((n, m)) => (n, m),
                None => (r.trim_end(), ""),
            };
            let client = self
                .map
                .get(name)
                .cloned()
                .unwrap_or_else(|| name.to_string());
            self.results
                .insert(client.clone(), RefStatus::Ng(msg.to_string()));
            self.map.get(name).map(|c| {
                if msg.is_empty() {
                    format!("ng {c}")
                } else {
                    format!("ng {c} {msg}")
                }
            })
        } else if let Some(r) = text.strip_prefix("option refname ") {
            self.map
                .get(r.trim_end())
                .map(|c| format!("option refname {c}"))
        } else {
            None
        };
        match rebuilt {
            Some(mut s) => {
                if nl {
                    s.push('\n');
                }
                s.into_bytes()
            }
            None => payload.to_vec(),
        }
    }
}

/// Emit the bytes as band 1 pkts, splitting across several pkts when the inner byte stream is large.
fn emit_band1(out: &mut Vec<u8>, inner: &[u8]) -> Result<(), PktError> {
    const CHUNK: usize = MAX_PKT_LEN - 4 - 1;
    for chunk in inner.chunks(CHUNK) {
        let mut payload = Vec::with_capacity(chunk.len() + 1);
        payload.push(1);
        payload.extend_from_slice(chunk);
        encode_into(out, &payload)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pktline::{encode, PktReader};
    use bytes::Bytes;

    fn map() -> HashMap<String, String> {
        HashMap::from([(
            "refs/heads/sekimore/main-1234567".to_string(),
            "refs/for/main".to_string(),
        )])
    }

    fn data(payload: &[u8]) -> Frame {
        Frame::Data(Bytes::from(encode(payload).unwrap()))
    }

    #[test]
    fn plain_ok_ng_rewritten() {
        let mut rw = ResponseRewriter::new(map(), false);
        let mut out = Vec::new();
        rw.feed(&data(b"unpack ok\n"), &mut out).unwrap();
        rw.feed(&data(b"ok refs/heads/sekimore/main-1234567\n"), &mut out)
            .unwrap();
        rw.feed(&data(b"ng refs/heads/other non-fast-forward\n"), &mut out)
            .unwrap();
        rw.feed(&Frame::Flush, &mut out).unwrap();
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("ok refs/for/main\n"), "{s}");
        assert!(!s.contains("sekimore/main"), "{s}");
        assert!(s.contains("ng refs/heads/other non-fast-forward\n"));
        assert!(s.ends_with("0000"));
        assert_eq!(rw.results()["refs/for/main"], RefStatus::Ok);
        assert_eq!(
            rw.results()["refs/heads/other"],
            RefStatus::Ng("non-fast-forward".into())
        );
        assert_eq!(rw.unpack_ok(), Some(true));
        // The length header has been recomputed ("ok refs/for/main\n" = 17 + 4 = 0x15).
        assert!(s.contains("0015ok refs/for/main\n"), "{s}");
    }

    #[tokio::test]
    async fn sideband_inner_line_split_across_two_band1_packets() {
        // Inner stream: "unpack ok\n", "ok refs/heads/sekimore/main-1234567\n" and "0000"
        let mut inner = encode(b"unpack ok\n").unwrap();
        inner.extend_from_slice(&encode(b"ok refs/heads/sekimore/main-1234567\n").unwrap());
        inner.extend_from_slice(FLUSH);
        // Split it mid-stream into two band 1 packets, with a progress packet in between.
        let cut = 17;
        let mut p1 = vec![1u8];
        p1.extend_from_slice(&inner[..cut]);
        let mut p2 = vec![1u8];
        p2.extend_from_slice(&inner[cut..]);
        let mut progress = vec![2u8];
        progress.extend_from_slice(b"remote: done\n");

        let mut rw = ResponseRewriter::new(map(), true);
        let mut out = Vec::new();
        rw.feed(&data(&p1), &mut out).unwrap();
        rw.feed(&data(&progress), &mut out).unwrap();
        rw.feed(&data(&p2), &mut out).unwrap();
        rw.feed(&Frame::Flush, &mut out).unwrap();
        rw.finish(&mut out).unwrap();

        // Re-parse the output: concatenating band 1 gives back the rewritten inner stream.
        let mut reader = PktReader::new(&out[..]);
        let mut band1 = Vec::new();
        let mut band2 = Vec::new();
        while let Some(f) = reader.next().await.unwrap() {
            match f {
                Frame::Data(_) => {
                    let p = f.payload();
                    match p[0] {
                        1 => band1.extend_from_slice(&p[1..]),
                        2 => band2.extend_from_slice(&p[1..]),
                        _ => panic!("unexpected band"),
                    }
                }
                Frame::Flush => {}
                _ => panic!(),
            }
        }
        let s = String::from_utf8_lossy(&band1);
        assert!(s.contains("ok refs/for/main\n"), "{s}");
        assert!(!s.contains("sekimore/main"), "{s}");
        assert!(s.ends_with("0000"), "{s}");
        assert_eq!(band2, b"remote: done\n");
        assert_eq!(rw.results()["refs/for/main"], RefStatus::Ok);
    }

    #[test]
    fn report_status_v2_option_refname_and_garbage_pass_through() {
        let mut rw = ResponseRewriter::new(map(), false);
        let out = rw.rewrite_line(b"option refname refs/heads/sekimore/main-1234567\n");
        assert_eq!(out, b"option refname refs/for/main\n");
        let garbage = [0xff, 0xfe, b'\n'];
        assert_eq!(rw.rewrite_line(&garbage), garbage.to_vec());
        assert_eq!(
            rw.rewrite_line(b"something else"),
            b"something else".to_vec()
        );
        // An ng with only the ref name and no message
        assert_eq!(
            rw.rewrite_line(b"ng refs/heads/sekimore/main-1234567"),
            b"ng refs/for/main".to_vec()
        );
    }

    #[test]
    fn oversized_inner_pkt_is_split_into_multiple_band1_frames() {
        let mut out = Vec::new();
        let big = vec![b'x'; MAX_PKT_LEN];
        emit_band1(&mut out, &big).unwrap();
        let (_, n1) = parse_one(&out).unwrap().unwrap();
        assert!(n1 <= MAX_PKT_LEN);
        assert!(parse_one(&out[n1..]).unwrap().is_some());
    }
}

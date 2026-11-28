//! How Python turned the log files' bytes into text, for the followers to do the same.

use std::io::Read;

/// `sys.int_info.str_digits_check_threshold`'s default: `int()` of a longer string raises.
pub const INT_MAX_STR_DIGITS: usize = 4300;

/// `bytes.decode("utf-8", errors="ignore")`: the invalid bytes are left out.
pub fn decode_ignore(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
    }
    out
}

/// `io.TextIOWrapper.readline()` on a file opened with `open(path)`: UTF-8, strict, universal
/// newlines (`\r\n`, `\r` and `\n` all end a line and read as `\n`), read in chunks of 8 KiB.
///
/// The file keeps growing, so EOF is not the end: at EOF what has been decoded is returned even
/// without a line end (an empty string when there is nothing), and reading goes on from there on
/// the next call. Python decodes a chunk whole before returning any line in it, so an undecodable
/// byte loses the lines before it in the same chunk; at EOF it decodes with `final=True`, so a
/// character cut in half by the writer is an error there too.
pub struct TextReader<R> {
    inner: R,
    /// Bytes read and not yet decoded (an incomplete character at the end of a chunk)
    raw: Vec<u8>,
    /// Decoded, newline-translated text not yet returned
    text: String,
    /// A `\r` at the end of a chunk, held to see whether `\n` follows
    pending_cr: bool,
}

/// `UnicodeDecodeError`: Python's follower stopped there.
#[derive(Debug, PartialEq, Eq)]
pub struct DecodeError;

pub const CHUNK: usize = 8192;

impl<R: Read> TextReader<R> {
    pub fn new(inner: R) -> Self {
        TextReader {
            inner,
            raw: Vec::new(),
            text: String::new(),
            pending_cr: false,
        }
    }

    /// One `readline()`; an I/O error is returned as Python would have raised it.
    pub fn readline(&mut self) -> std::io::Result<Result<String, DecodeError>> {
        loop {
            if let Some(i) = self.text.find('\n') {
                let line: String = self.text.drain(..=i).collect();
                return Ok(Ok(line));
            }
            let mut chunk = vec![0u8; CHUNK];
            let n = loop {
                match self.inner.read(&mut chunk) {
                    Ok(n) => break n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            };
            let eof = n == 0;
            if let Err(e) = self.decode(chunk.get(..n).unwrap_or_default(), eof) {
                return Ok(Err(e));
            }
            if eof {
                return Ok(Ok(std::mem::take(&mut self.text)));
            }
        }
    }

    /// The UTF-8 decoder and `IncrementalNewlineDecoder(translate=True)` on one chunk.
    fn decode(&mut self, chunk: &[u8], final_: bool) -> Result<(), DecodeError> {
        self.raw.extend_from_slice(chunk);
        let mut out = String::new();
        let consumed = match std::str::from_utf8(&self.raw) {
            Ok(s) => {
                out.push_str(s);
                self.raw.len()
            }
            Err(e) if e.error_len().is_none() && !final_ => {
                let ok = e.valid_up_to();
                out.push_str(
                    std::str::from_utf8(self.raw.get(..ok).unwrap_or_default())
                        .map_err(|_| DecodeError)?,
                );
                ok
            }
            Err(_) => return Err(DecodeError),
        };
        self.raw.drain(..consumed);
        if self.pending_cr {
            out.insert(0, '\r');
            self.pending_cr = false;
        }
        if out.ends_with('\r') && !final_ {
            out.pop();
            self.pending_cr = true;
        }
        self.text
            .push_str(&out.replace("\r\n", "\n").replace('\r', "\n"));
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn invalid_bytes_are_left_out() {
        assert_eq!(decode_ignore(b"a\xffb\xe2\x82c\xe2\x82\xac"), "abc\u{20ac}");
        assert_eq!(decode_ignore(b"\xed\xa0\x80x\xc0\xaf"), "x");
    }

    /// A reader that hands out what it is given, a piece per read, then EOF once per piece.
    struct Pieces(Vec<Vec<u8>>);

    impl Read for Pieces {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.0.is_empty() {
                return Ok(0);
            }
            let p = &mut self.0[0];
            if p.is_empty() {
                self.0.remove(0);
                return Ok(0);
            }
            let n = p.len().min(buf.len());
            buf[..n].copy_from_slice(&p[..n]);
            p.drain(..n);
            Ok(n)
        }
    }

    fn lines(pieces: &[&[u8]]) -> Vec<Result<String, DecodeError>> {
        let mut r = TextReader::new(Pieces(pieces.iter().map(|p| p.to_vec()).collect()));
        let mut out = Vec::new();
        for _ in 0..20 {
            match r.readline().unwrap() {
                Ok(s) if s.is_empty() => {}
                Err(e) => {
                    out.push(Err(e));
                    break;
                }
                ok => out.push(ok),
            }
        }
        out
    }

    #[test]
    fn universal_newlines_and_partial_lines_at_eof() {
        assert_eq!(
            lines(&[b"a\r\nb\rc\nd"]),
            [
                Ok("a\n".into()),
                Ok("b\n".into()),
                Ok("c\n".into()),
                Ok("d".into())
            ]
        );
        // a \r at EOF ends the line there; a \n arriving later is a line of its own
        assert_eq!(
            lines(&[b"x\r", b"\ny\n"]),
            [Ok("x\n".into()), Ok("\n".into()), Ok("y\n".into())]
        );
        // a partial line at EOF is returned, and the rest comes as another line
        assert_eq!(
            lines(&[b"ab", b"cd\n"]),
            [Ok("ab".into()), Ok("cd\n".into())]
        );
    }

    #[test]
    fn an_undecodable_byte_stops_it_and_loses_its_chunk() {
        assert_eq!(
            lines(&[b"ok\n", b"lost\n\xff\n"]),
            [Ok("ok\n".into()), Err(DecodeError)]
        );
        // a character cut at EOF is an error (final=True)
        assert_eq!(
            lines(&[b"ok\n\xe2\x82", b"\xac\n"]),
            [Ok("ok\n".into()), Err(DecodeError)]
        );
        // a character cut between two chunks of one read is not
        let mut long = vec![b'a'; CHUNK - 1];
        long.extend_from_slice("\u{20ac}\n".as_bytes());
        let got = lines(&[&long]);
        assert_eq!(got.len(), 1);
        assert!(got[0].as_ref().unwrap().ends_with("\u{20ac}\n"));
    }
}

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

/// `io.TextIOWrapper.readline()` on a file opened with
/// `open(path, encoding="utf-8", errors="surrogateescape")`: universal newlines (`\r\n`, `\r` and
/// `\n` all end a line and read as `\n`), read in chunks of 8 KiB.
///
/// The file keeps growing, so EOF is not the end: at EOF what has been decoded is returned even
/// without a line end (an empty string when there is nothing), and reading goes on from there on
/// the next call. At EOF it decodes with `final=True`, so a character cut in half by the writer is
/// undecodable there.
///
/// A line holding bytes that are not UTF-8 comes back as [`Undecodable`], and only that line: the
/// lines around it read as usual. (Python's follower read strictly, so one such byte raised out of
/// `readline()`, lost the lines before it in the same chunk, and ended the follower.)
pub struct TextReader<R> {
    inner: R,
    /// Bytes read and not yet decoded (an incomplete character at the end of a chunk)
    raw: Vec<u8>,
    /// Decoded, newline-translated text not yet returned; an undecodable sequence is U+FFFD
    text: String,
    /// Where in `text` an undecodable sequence was put (byte offsets)
    bad: Vec<usize>,
    /// A `\r` not yet translated, held to see whether `\n` follows
    pending_cr: bool,
}

/// The line held bytes that are not UTF-8.
#[derive(Debug, PartialEq, Eq)]
pub struct Undecodable;

pub const CHUNK: usize = 8192;

impl<R: Read> TextReader<R> {
    pub fn new(inner: R) -> Self {
        TextReader {
            inner,
            raw: Vec::new(),
            text: String::new(),
            bad: Vec::new(),
            pending_cr: false,
        }
    }

    /// One `readline()`; an I/O error is returned as Python would have raised it.
    pub fn readline(&mut self) -> std::io::Result<Result<String, Undecodable>> {
        loop {
            if let Some(i) = self.text.find('\n') {
                let line: String = self.text.drain(..=i).collect();
                return Ok(self.take_line(line, i + 1));
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
            self.decode(chunk.get(..n).unwrap_or_default(), eof);
            if eof {
                let line = std::mem::take(&mut self.text);
                let len = line.len();
                return Ok(self.take_line(line, len));
            }
        }
    }

    /// `line`, the first `len` bytes of what was decoded, or [`Undecodable`] if it held a bad one.
    fn take_line(&mut self, line: String, len: usize) -> Result<String, Undecodable> {
        let tainted = self.bad.iter().any(|&b| b < len);
        self.bad.retain(|&b| b >= len);
        for b in &mut self.bad {
            *b -= len;
        }
        if tainted {
            Err(Undecodable)
        } else {
            Ok(line)
        }
    }

    /// One character through `IncrementalNewlineDecoder(translate=True)`.
    fn push(&mut self, c: char) {
        if self.pending_cr {
            self.pending_cr = false;
            self.text.push('\n');
            if c == '\n' {
                return;
            }
        }
        if c == '\r' {
            self.pending_cr = true;
        } else {
            self.text.push(c);
        }
    }

    /// The UTF-8 decoder (`surrogateescape`) and the newline decoder on one chunk.
    fn decode(&mut self, chunk: &[u8], final_: bool) {
        self.raw.extend_from_slice(chunk);
        let raw = std::mem::take(&mut self.raw);
        let mut pieces = raw.utf8_chunks().peekable();
        while let Some(piece) = pieces.next() {
            for c in piece.valid().chars() {
                self.push(c);
            }
            let invalid = piece.invalid();
            if invalid.is_empty() {
                continue;
            }
            // An incomplete character at the very end waits for the next chunk, unless final
            let at_end = pieces.peek().is_none();
            let incomplete =
                at_end && std::str::from_utf8(invalid).is_err_and(|e| e.error_len().is_none());
            if incomplete && !final_ {
                self.raw.extend_from_slice(invalid);
                continue;
            }
            self.push('\u{fffd}');
            let at = self.text.len() - '\u{fffd}'.len_utf8();
            self.bad.push(at);
        }
        if final_ && self.pending_cr {
            self.pending_cr = false;
            self.text.push('\n');
        }
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

    fn lines(pieces: &[&[u8]]) -> Vec<Result<String, Undecodable>> {
        let mut r = TextReader::new(Pieces(pieces.iter().map(|p| p.to_vec()).collect()));
        let mut out = Vec::new();
        for _ in 0..20 {
            match r.readline().unwrap() {
                Ok(s) if s.is_empty() => {}
                line => out.push(line),
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
    fn an_undecodable_byte_loses_only_its_own_line() {
        assert_eq!(
            lines(&[b"ok\n", b"kept\n\xff\nafter\n"]),
            [
                Ok("ok\n".into()),
                Ok("kept\n".into()),
                Err(Undecodable),
                Ok("after\n".into())
            ]
        );
        // a bad byte between \r and \n: the \r still ends its line, the bad one is the next
        assert_eq!(
            lines(&[b"a\r\xff\nb\n"]),
            [Ok("a\n".into()), Err(Undecodable), Ok("b\n".into())]
        );
        // a character cut at EOF (final=True) is undecodable, and so is the rest of it later
        assert_eq!(
            lines(&[b"ok\n\xe2\x82", b"\xac\nnext\n"]),
            [
                Ok("ok\n".into()),
                Err(Undecodable),
                Err(Undecodable),
                Ok("next\n".into())
            ]
        );
        // a character cut between two chunks of one read is not
        let mut long = vec![b'a'; CHUNK - 1];
        long.extend_from_slice("\u{20ac}\n".as_bytes());
        let got = lines(&[&long]);
        assert_eq!(got.len(), 1);
        assert!(got[0].as_ref().unwrap().ends_with("\u{20ac}\n"));
        // a U+FFFD that is really in the log is text like any other
        assert_eq!(lines(&["\u{fffd}\n".as_bytes()]), [Ok("\u{fffd}\n".into())]);
    }
}

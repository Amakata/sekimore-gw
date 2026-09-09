//! git pkt-line の解析・組み立て・ストリーム読み取り。
//!
//! 設計上の要点:
//!   - 借用でゼロコピー。`RefUpdate` は元バッファを指すだけで String を作らない
//!   - **入力長に上限**を設ける。1 pkt は 65520 バイト（git の上限）、区間は呼び出し側が cap を渡す。
//!     「長さを検証せずに巨大なメモリを要求する」型の問題（RUSTSEC-2026-0154 と同型）を防ぐ
//!   - **fail-closed**。解釈できないコマンド行は読み飛ばさずエラーにする
//!   - ref 名の差し替えは部分文字列置換ではなく、パース済みフィールドから再エンコードする
//!     （`refs/for/main` が `refs/for/main2` に一致する事故を防ぐ）
//!   - `PktReader` は flush 後の残余バイトを `into_parts()` で返す。呼び出し側は必ず前送すること

use std::fmt;

use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

/// git が許す 1 pkt-line の最大長（ヘッダ込み）。
pub const MAX_PKT_LEN: usize = 65520;
pub const FLUSH: &[u8] = b"0000";
pub const DELIM: &[u8] = b"0001";
pub const RESPONSE_END: &[u8] = b"0002";

#[derive(Debug, PartialEq, Eq)]
pub enum PktError {
    BadLength { at: usize },
    TooLong { at: usize, len: usize },
    Truncated { at: usize, want: usize },
    SectionTooLarge { cap: usize },
    MalformedCommand { at: usize, reason: &'static str },
    InvalidRef { name: String, reason: &'static str },
    PayloadTooLong { len: usize },
}

impl fmt::Display for PktError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PktError::BadLength { at } => write!(f, "invalid pkt-line length at byte {at}"),
            PktError::TooLong { at, len } => {
                write!(f, "pkt-line at {at} claims {len} bytes (max {MAX_PKT_LEN})")
            }
            PktError::Truncated { at, want } => {
                write!(
                    f,
                    "pkt-line at {at} claims {want} bytes but input ended early"
                )
            }
            PktError::SectionTooLarge { cap } => {
                write!(f, "pkt-line section exceeds {cap} bytes")
            }
            PktError::MalformedCommand { at, reason } => {
                write!(f, "malformed receive-pack command at byte {at}: {reason}")
            }
            PktError::InvalidRef { name, reason } => {
                write!(f, "invalid ref name {name:?}: {reason}")
            }
            PktError::PayloadTooLong { len } => {
                write!(f, "pkt-line payload of {len} bytes does not fit in one pkt")
            }
        }
    }
}

impl std::error::Error for PktError {}

impl From<PktError> for std::io::Error {
    fn from(e: PktError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    }
}

/// 1 つの pkt-line。`Data` のスライスはヘッダを除いたペイロード。
#[derive(Debug, PartialEq, Eq)]
pub enum Pkt<'a> {
    Flush,
    Delim,
    ResponseEnd,
    Data(&'a [u8]),
}

fn parse_hex4(hdr: &[u8]) -> Option<usize> {
    if hdr.len() != 4 {
        return None;
    }
    let mut n = 0usize;
    for &b in hdr {
        let d = (b as char).to_digit(16)? as usize;
        n = n * 16 + d;
    }
    Some(n)
}

/// バッファ先頭の pkt-line を 1 つ解析する。
///
/// `Ok(None)` はバイト不足（もっと読む必要がある）。`Ok(Some((pkt, n)))` の `n` はヘッダ込みの消費バイト数。
pub fn parse_one(buf: &[u8]) -> Result<Option<(Pkt<'_>, usize)>, PktError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let hdr = &buf[..4];
    match hdr {
        b"0000" => return Ok(Some((Pkt::Flush, 4))),
        b"0001" => return Ok(Some((Pkt::Delim, 4))),
        b"0002" => return Ok(Some((Pkt::ResponseEnd, 4))),
        _ => {}
    }
    let n = parse_hex4(hdr).ok_or(PktError::BadLength { at: 0 })?;
    if n < 4 {
        return Err(PktError::BadLength { at: 0 });
    }
    if n > MAX_PKT_LEN {
        return Err(PktError::TooLong { at: 0, len: n });
    }
    if buf.len() < n {
        return Ok(None);
    }
    Ok(Some((Pkt::Data(&buf[4..n]), n)))
}

fn shift(e: PktError, by: usize) -> PktError {
    match e {
        PktError::BadLength { at } => PktError::BadLength { at: at + by },
        PktError::TooLong { at, len } => PktError::TooLong { at: at + by, len },
        PktError::Truncated { at, want } => PktError::Truncated { at: at + by, want },
        PktError::MalformedCommand { at, reason } => PktError::MalformedCommand {
            at: at + by,
            reason,
        },
        other => other,
    }
}

/// スライス上の pkt-line を 1 行ずつ返すイテレータ。flush-pkt で終わる（flush 自身は返さない）。
pub struct PktLines<'a> {
    buf: &'a [u8],
    pos: usize,
    done: bool,
}

impl<'a> PktLines<'a> {
    /// flush を含めて消費したバイト数。
    pub fn consumed(&self) -> usize {
        self.pos
    }
    /// flush-pkt を見たか。
    pub fn saw_flush(&self) -> bool {
        self.done
    }
}

impl<'a> Iterator for PktLines<'a> {
    /// (行の開始位置, ペイロード)
    type Item = Result<(usize, &'a [u8]), PktError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let start = self.pos;
        let rest = &self.buf[start..];
        if rest.is_empty() {
            return None;
        }
        match parse_one(rest) {
            Ok(Some((Pkt::Flush, n))) => {
                self.pos += n;
                self.done = true;
                None
            }
            Ok(Some((Pkt::Data(payload), n))) => {
                self.pos += n;
                Some(Ok((start, payload)))
            }
            Ok(Some((Pkt::Delim, n))) | Ok(Some((Pkt::ResponseEnd, n))) => {
                // コマンド部には現れない。素通しせず不正扱い
                self.pos += n;
                self.done = true;
                Some(Err(PktError::MalformedCommand {
                    at: start,
                    reason: "unexpected delim/response-end pkt",
                }))
            }
            Ok(None) => {
                self.done = true;
                let want = if rest.len() >= 4 {
                    parse_hex4(&rest[..4]).unwrap_or(0)
                } else {
                    4
                };
                Some(Err(PktError::Truncated { at: start, want }))
            }
            Err(e) => {
                self.done = true;
                Some(Err(shift(e, start)))
            }
        }
    }
}

pub fn pkt_lines(buf: &[u8]) -> PktLines<'_> {
    PktLines {
        buf,
        pos: 0,
        done: false,
    }
}

// ---- receive-pack コマンド部 ----

/// ref 更新要求。すべて元バッファへの借用。
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RefUpdate<'a> {
    pub old: &'a str,
    pub new: &'a str,
    pub name: &'a str,
}

impl<'a> RefUpdate<'a> {
    /// `refs/for/<base>` なら base を返す。
    pub fn refs_for_base(&self) -> Option<&'a str> {
        self.name
            .strip_prefix("refs/for/")
            .filter(|b| !b.is_empty())
    }
    pub fn is_delete(&self) -> bool {
        self.new.bytes().all(|b| b == b'0')
    }
    pub fn is_create(&self) -> bool {
        self.old.bytes().all(|b| b == b'0')
    }
}

/// コマンド部の 1 行。順序を保って再エンコードする。
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum CommandLine<'a> {
    Update(RefUpdate<'a>),
    /// `shallow <sha>`（shallow clone からの push）。無変更で通す
    Shallow(&'a str),
}

/// 解析済みのコマンド部。
#[derive(Debug, PartialEq, Eq)]
pub struct CommandSection<'a> {
    pub lines: Vec<CommandLine<'a>>,
    /// 先頭行の NUL 以降（capabilities）。末尾の改行は除く
    pub caps: Option<&'a [u8]>,
    /// flush を含めて消費したバイト数
    pub consumed: usize,
}

impl<'a> CommandSection<'a> {
    pub fn updates(&self) -> impl Iterator<Item = &RefUpdate<'a>> {
        self.lines.iter().filter_map(|l| match l {
            CommandLine::Update(u) => Some(u),
            CommandLine::Shallow(_) => None,
        })
    }
}

fn is_hex_oid(s: &str) -> bool {
    (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `git check-ref-format` 相当の検証。`refs/` で始まることも要求する（fail-closed）。
pub fn validate_ref_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("empty");
    }
    if !name.starts_with("refs/") {
        return Err("must start with refs/");
    }
    if name.ends_with('/') || name.ends_with('.') {
        return Err("must not end with '/' or '.'");
    }
    if name.contains("..") {
        return Err("must not contain '..'");
    }
    if name.contains("@{") {
        return Err("must not contain '@{'");
    }
    for b in name.bytes() {
        if b < 0x20 || b == 0x7f {
            return Err("control character");
        }
        if matches!(b, b' ' | b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\') {
            return Err("forbidden character");
        }
    }
    for comp in name.split('/') {
        if comp.is_empty() {
            return Err("empty path component");
        }
        if comp.starts_with('.') {
            return Err("component starts with '.'");
        }
        if comp.ends_with(".lock") {
            return Err("component ends with .lock");
        }
    }
    Ok(())
}

/// receive-pack のコマンド部（flush まで）を解析する。
///
/// 解釈できない行はエラー（読み飛ばさない）。コマンドが 0 個（flush のみ）は `Ok` で `lines` が空。
pub fn parse_receive_pack(data: &[u8]) -> Result<CommandSection<'_>, PktError> {
    let mut lines = Vec::new();
    let mut caps = None;
    let mut it = pkt_lines(data);
    let mut saw_update = false;
    for item in it.by_ref() {
        let (at, payload) = item?;
        let (body, cap_part) = match payload.iter().position(|&b| b == 0) {
            Some(i) => (&payload[..i], Some(&payload[i + 1..])),
            None => (payload, None),
        };
        // git は capabilities を「最初の update コマンド行」に付ける（shallow 行には付けない）
        let is_shallow = body.starts_with(b"shallow ");
        if let Some(c) = cap_part {
            if saw_update || is_shallow {
                return Err(PktError::MalformedCommand {
                    at,
                    reason: "capabilities on a non-first command line",
                });
            }
            caps = Some(strip_nl(c));
        }
        if !is_shallow {
            saw_update = true;
        }
        let text = std::str::from_utf8(strip_nl(body)).map_err(|_| PktError::MalformedCommand {
            at,
            reason: "not valid UTF-8",
        })?;
        if text.starts_with("push-cert") {
            return Err(PktError::MalformedCommand {
                at,
                reason: "signed push (push-cert) is not supported by the relay",
            });
        }
        if let Some(sha) = text.strip_prefix("shallow ") {
            if !is_hex_oid(sha) {
                return Err(PktError::MalformedCommand {
                    at,
                    reason: "shallow line without a valid object id",
                });
            }
            lines.push(CommandLine::Shallow(sha));
            continue;
        }
        let mut fields = text.split(' ');
        let (old, new, name, extra) = (fields.next(), fields.next(), fields.next(), fields.next());
        let (Some(old), Some(new), Some(name)) = (old, new, name) else {
            return Err(PktError::MalformedCommand {
                at,
                reason: "expected '<old> <new> <ref>'",
            });
        };
        if extra.is_some() {
            return Err(PktError::MalformedCommand {
                at,
                reason: "too many fields",
            });
        }
        if !is_hex_oid(old) || !is_hex_oid(new) || old.len() != new.len() {
            return Err(PktError::MalformedCommand {
                at,
                reason: "object ids must be 40 or 64 lowercase hex",
            });
        }
        if let Err(reason) = validate_ref_name(name) {
            return Err(PktError::InvalidRef {
                name: name.to_string(),
                reason,
            });
        }
        lines.push(CommandLine::Update(RefUpdate { old, new, name }));
    }
    if !it.saw_flush() {
        return Err(PktError::Truncated {
            at: it.consumed(),
            want: 4,
        });
    }
    Ok(CommandSection {
        lines,
        caps,
        consumed: it.consumed(),
    })
}

fn strip_nl(b: &[u8]) -> &[u8] {
    match b.last() {
        Some(b'\n') => &b[..b.len() - 1],
        _ => b,
    }
}

/// 1 pkt-line を組み立てる（ヘッダ付き）。
pub fn encode(payload: &[u8]) -> Result<Vec<u8>, PktError> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    encode_into(&mut out, payload)?;
    Ok(out)
}

pub fn encode_into(out: &mut Vec<u8>, payload: &[u8]) -> Result<(), PktError> {
    let n = payload.len() + 4;
    if n > MAX_PKT_LEN {
        return Err(PktError::PayloadTooLong { len: payload.len() });
    }
    out.extend_from_slice(format!("{n:04x}").as_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

/// コマンド部を再エンコードする。先頭行に capabilities を付け、末尾に flush を置く。
pub fn encode_commands(
    lines: &[CommandLine<'_>],
    caps: Option<&[u8]>,
) -> Result<Vec<u8>, PktError> {
    let mut out = Vec::new();
    let mut caps_pending = caps;
    for line in lines.iter() {
        let mut payload = Vec::new();
        match line {
            CommandLine::Update(u) => {
                payload.extend_from_slice(u.old.as_bytes());
                payload.push(b' ');
                payload.extend_from_slice(u.new.as_bytes());
                payload.push(b' ');
                payload.extend_from_slice(u.name.as_bytes());
            }
            CommandLine::Shallow(sha) => {
                payload.extend_from_slice(b"shallow ");
                payload.extend_from_slice(sha.as_bytes());
            }
        }
        if matches!(line, CommandLine::Update(_)) {
            if let Some(c) = caps_pending.take() {
                payload.push(0);
                payload.extend_from_slice(c);
            }
        }
        payload.push(b'\n');
        encode_into(&mut out, &payload)?;
    }
    out.extend_from_slice(FLUSH);
    Ok(out)
}

/// capabilities 文字列（空白区切り）に `name` または `name=value` が含まれるか。
pub fn caps_contain(caps: &[u8], name: &str) -> bool {
    caps.split(|&b| b == b' ' || b == b'\n')
        .filter(|w| !w.is_empty())
        .any(|w| {
            w == name.as_bytes()
                || (w.starts_with(name.as_bytes()) && w.get(name.len()) == Some(&b'='))
        })
}

// ---- ストリーム読み取り ----

/// 所有権付きの 1 pkt。`raw` はヘッダ込み（素通し転送に使う）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Flush,
    Delim,
    ResponseEnd,
    Data(Bytes),
}

impl Frame {
    /// ヘッダ込みの生バイト。
    pub fn raw(&self) -> Bytes {
        match self {
            Frame::Flush => Bytes::from_static(FLUSH),
            Frame::Delim => Bytes::from_static(DELIM),
            Frame::ResponseEnd => Bytes::from_static(RESPONSE_END),
            Frame::Data(raw) => raw.clone(),
        }
    }
    /// ペイロード（Data 以外は空）。
    pub fn payload(&self) -> &[u8] {
        match self {
            Frame::Data(raw) => &raw[4..],
            _ => &[],
        }
    }
    pub fn is_flush(&self) -> bool {
        matches!(self, Frame::Flush)
    }
}

/// 非同期ストリームから pkt-line を読む。
pub struct PktReader<R> {
    inner: R,
    buf: BytesMut,
}

impl<R: AsyncRead + Unpin> PktReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: BytesMut::with_capacity(64 * 1024),
        }
    }

    /// 既に読み込んである残余バイトを先頭に置いて始める。
    pub fn with_leftover(inner: R, leftover: BytesMut) -> Self {
        Self {
            inner,
            buf: leftover,
        }
    }

    /// 内側のリーダと未消費バイトを返す。**未消費バイトは呼び出し側が必ず前送する。**
    pub fn into_parts(self) -> (R, BytesMut) {
        (self.inner, self.buf)
    }

    pub fn leftover(&self) -> &[u8] {
        &self.buf
    }

    async fn fill(&mut self) -> std::io::Result<usize> {
        self.inner.read_buf(&mut self.buf).await
    }

    /// 次の pkt を読む。きれいな EOF（未消費バイトなし）なら `Ok(None)`。途中で EOF ならエラー。
    pub async fn next(&mut self) -> std::io::Result<Option<Frame>> {
        loop {
            match parse_one(&self.buf)? {
                Some((Pkt::Flush, n)) => {
                    self.buf.advance_by(n);
                    return Ok(Some(Frame::Flush));
                }
                Some((Pkt::Delim, n)) => {
                    self.buf.advance_by(n);
                    return Ok(Some(Frame::Delim));
                }
                Some((Pkt::ResponseEnd, n)) => {
                    self.buf.advance_by(n);
                    return Ok(Some(Frame::ResponseEnd));
                }
                Some((Pkt::Data(_), n)) => {
                    let raw = self.buf.split_to(n).freeze();
                    return Ok(Some(Frame::Data(raw)));
                }
                None => {
                    let got = self.fill().await?;
                    if got == 0 {
                        if self.buf.is_empty() {
                            return Ok(None);
                        }
                        let want = if self.buf.len() >= 4 {
                            parse_hex4(&self.buf[..4]).unwrap_or(0)
                        } else {
                            4
                        };
                        return Err(PktError::Truncated { at: 0, want }.into());
                    }
                }
            }
        }
    }

    /// flush-pkt までの区間を生バイトで返す（flush を含む）。`cap` を超えたら即エラー。
    pub async fn read_section(&mut self, cap: usize) -> std::io::Result<Vec<u8>> {
        let mut end = 0usize; // 解析済みバイト数
        loop {
            match parse_one(&self.buf[end..])? {
                Some((Pkt::Flush, n)) => {
                    end += n;
                    let section = self.buf.split_to(end);
                    return Ok(section.to_vec());
                }
                Some((_, n)) => {
                    end += n;
                    if end > cap {
                        return Err(PktError::SectionTooLarge { cap }.into());
                    }
                }
                None => {
                    if self.buf.len() > cap {
                        return Err(PktError::SectionTooLarge { cap }.into());
                    }
                    let got = self.fill().await?;
                    if got == 0 {
                        let rest = &self.buf[end..];
                        let want = if rest.len() >= 4 {
                            parse_hex4(&rest[..4]).unwrap_or(0)
                        } else {
                            4
                        };
                        return Err(PktError::Truncated { at: end, want }.into());
                    }
                }
            }
        }
    }
}

trait AdvanceBy {
    fn advance_by(&mut self, n: usize);
}
impl AdvanceBy for BytesMut {
    fn advance_by(&mut self, n: usize) {
        use bytes::Buf;
        self.advance(n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(payload: &str) -> Vec<u8> {
        let mut v = format!("{:04x}", payload.len() + 4).into_bytes();
        v.extend_from_slice(payload.as_bytes());
        v
    }
    const ZERO: &str = "0000000000000000000000000000000000000000";
    const SHA: &str = "1234567890abcdef1234567890abcdef12345678";

    #[test]
    fn parses_refs_for_with_capabilities() {
        let mut data = pkt(&format!(
            "{ZERO} {SHA} refs/for/main\0report-status side-band-64k\n"
        ));
        data.extend_from_slice(b"0000PACK...");

        let sec = parse_receive_pack(&data).unwrap();
        let refs: Vec<_> = sec.updates().collect();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "refs/for/main");
        assert_eq!(refs[0].refs_for_base(), Some("main"));
        assert_eq!(sec.caps, Some(&b"report-status side-band-64k"[..]));
        assert_eq!(&data[sec.consumed..], b"PACK...");
    }

    #[test]
    fn parses_multiple_commands_in_order() {
        let mut data = pkt(&format!(
            "{ZERO} {SHA} refs/heads/feature-a\0report-status\n"
        ));
        data.extend_from_slice(&pkt(&format!("{ZERO} {SHA} refs/for/main\n")));
        data.extend_from_slice(FLUSH);
        let sec = parse_receive_pack(&data).unwrap();
        let names: Vec<_> = sec.updates().map(|u| u.name).collect();
        assert_eq!(names, vec!["refs/heads/feature-a", "refs/for/main"]);
    }

    #[test]
    fn empty_command_list_is_ok() {
        let sec = parse_receive_pack(b"0000").unwrap();
        assert!(sec.lines.is_empty());
        assert_eq!(sec.consumed, 4);
    }

    #[test]
    fn refs_for_base_rejects_empty_and_heads() {
        for (name, want) in [
            ("refs/for/main", Some("main")),
            ("refs/for/release/v1", Some("release/v1")),
            ("refs/heads/main", None),
            ("refs/for/", None),
        ] {
            let u = RefUpdate {
                old: ZERO,
                new: ZERO,
                name,
            };
            assert_eq!(u.refs_for_base(), want, "name={name}");
        }
    }

    #[test]
    fn encode_commands_recalculates_length_and_keeps_caps() {
        let mut data = pkt(&format!("{ZERO} {SHA} refs/for/main\0report-status\n"));
        data.extend_from_slice(b"0000PACKDATA");
        let sec = parse_receive_pack(&data).unwrap();

        let renamed: Vec<CommandLine> = sec
            .lines
            .iter()
            .map(|l| match l {
                CommandLine::Update(u) => CommandLine::Update(RefUpdate {
                    old: u.old,
                    new: u.new,
                    name: "refs/heads/sekimore/main-1234567",
                }),
                other => other.clone(),
            })
            .collect();
        let out = encode_commands(&renamed, sec.caps).unwrap();

        // 書き換え後も正しくパースできる
        let re = parse_receive_pack(&out).unwrap();
        assert_eq!(
            re.updates().next().unwrap().name,
            "refs/heads/sekimore/main-1234567"
        );
        // ヘッダが再計算されている
        assert_ne!(&out[..4], &data[..4]);
        // capabilities が生きている
        assert_eq!(re.caps, Some(&b"report-status"[..]));
        assert!(out.ends_with(FLUSH));
    }

    #[test]
    fn rename_does_not_touch_similar_refs() {
        // 旧実装の部分文字列置換だと refs/for/main が refs/for/main2 に一致した
        let mut data = pkt(&format!("{ZERO} {SHA} refs/for/main2\n"));
        data.extend_from_slice(FLUSH);
        let sec = parse_receive_pack(&data).unwrap();
        let u = sec.updates().next().unwrap();
        assert_eq!(u.refs_for_base(), Some("main2"));
        assert_ne!(u.name, "refs/for/main");
    }

    #[test]
    fn truncated_input_is_an_error_not_a_panic() {
        let data = b"0050short";
        assert!(matches!(
            parse_receive_pack(data),
            Err(PktError::Truncated { .. })
        ));
    }

    #[test]
    fn garbage_length_is_an_error() {
        let data = b"zzzzsomething";
        assert!(matches!(
            parse_receive_pack(data),
            Err(PktError::BadLength { .. })
        ));
    }

    #[test]
    fn missing_flush_is_truncated() {
        let data = pkt(&format!("{ZERO} {SHA} refs/heads/x\n"));
        assert!(matches!(
            parse_receive_pack(&data),
            Err(PktError::Truncated { .. })
        ));
    }

    #[test]
    fn malformed_command_is_error_not_skipped() {
        let mut data = pkt("hello world\n");
        data.extend_from_slice(FLUSH);
        assert!(matches!(
            parse_receive_pack(&data),
            Err(PktError::MalformedCommand { .. })
        ));

        let mut bad_utf8 = pkt("");
        bad_utf8.truncate(0);
        let mut payload = format!("{ZERO} {SHA} refs/heads/").into_bytes();
        payload.extend_from_slice(&[0xff, 0xfe, b'\n']);
        bad_utf8.extend_from_slice(format!("{:04x}", payload.len() + 4).as_bytes());
        bad_utf8.extend_from_slice(&payload);
        bad_utf8.extend_from_slice(FLUSH);
        assert!(matches!(
            parse_receive_pack(&bad_utf8),
            Err(PktError::MalformedCommand { .. })
        ));

        let mut bad_sha = pkt(&format!("{ZERO} deadbeef refs/heads/x\n"));
        bad_sha.extend_from_slice(FLUSH);
        assert!(matches!(
            parse_receive_pack(&bad_sha),
            Err(PktError::MalformedCommand { .. })
        ));

        let mut push_cert = pkt("push-cert\0report-status\n");
        push_cert.extend_from_slice(FLUSH);
        assert!(matches!(
            parse_receive_pack(&push_cert),
            Err(PktError::MalformedCommand { .. })
        ));
    }

    #[test]
    fn invalid_ref_names_are_rejected() {
        for name in [
            "main",
            "refs/heads/",
            "refs/heads/a..b",
            "refs/heads/a~b",
            "refs/heads/.hidden",
            "refs/heads/x.lock",
            "refs/heads/x@{1}",
            "refs//heads",
        ] {
            let mut data = pkt(&format!("{ZERO} {SHA} {name}\n"));
            data.extend_from_slice(FLUSH);
            assert!(
                matches!(parse_receive_pack(&data), Err(PktError::InvalidRef { .. })),
                "{name} should be invalid"
            );
        }
        assert!(validate_ref_name("refs/heads/a b").is_err());
        assert!(validate_ref_name("refs/heads/sekimore/release/v1-abc1234").is_ok());
        assert!(validate_ref_name("refs/for/main").is_ok());
    }

    #[test]
    fn shallow_lines_pass_through() {
        let mut data = pkt(&format!("shallow {SHA}\n"));
        data.extend_from_slice(&pkt(&format!(
            "{ZERO} {SHA} refs/for/main\0report-status\n"
        )));
        data.extend_from_slice(FLUSH);
        let sec = parse_receive_pack(&data).unwrap();
        assert_eq!(sec.lines.len(), 2);
        assert!(matches!(sec.lines[0], CommandLine::Shallow(_)));
        // caps は最初の update 行（2 行目）に付く。git は shallow 行に caps を付けない
        assert_eq!(sec.caps, Some(&b"report-status"[..]));
        let out = encode_commands(&sec.lines, sec.caps).unwrap();
        assert_eq!(parse_receive_pack(&out).unwrap().lines, sec.lines);
    }

    #[test]
    fn pkt_longer_than_max_is_error() {
        let data = b"fff1xxxx";
        assert!(matches!(
            parse_one(data),
            Err(PktError::TooLong { len: 0xfff1, .. })
        ));
        // 境界: ちょうど MAX_PKT_LEN は OK
        let payload = vec![b'a'; MAX_PKT_LEN - 4];
        let enc = encode(&payload).unwrap();
        assert!(matches!(
            parse_one(&enc),
            Ok(Some((Pkt::Data(_), MAX_PKT_LEN)))
        ));
        assert!(matches!(
            encode(&vec![b'a'; MAX_PKT_LEN - 3]),
            Err(PktError::PayloadTooLong { .. })
        ));
    }

    #[test]
    fn caps_contain_matches_exact_and_kv() {
        let caps = b"report-status side-band-64k agent=git/2.45 push-options";
        assert!(caps_contain(caps, "report-status"));
        assert!(caps_contain(caps, "side-band-64k"));
        assert!(caps_contain(caps, "agent"));
        assert!(!caps_contain(caps, "side-band"));
        assert!(!caps_contain(caps, "report-status-v2"));
    }

    #[tokio::test]
    async fn streaming_reader_handles_split_headers_and_leftover() {
        let mut data = pkt(&format!("{ZERO} {SHA} refs/for/main\0report-status\n"));
        data.extend_from_slice(FLUSH);
        data.extend_from_slice(b"PACKDATA-after-flush");

        // 1 バイトずつ届く遅いストリーム
        let (mut w, r) = tokio::io::duplex(4);
        let feed = data.clone();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            for chunk in feed.chunks(3) {
                w.write_all(chunk).await.unwrap();
            }
        });
        let mut reader = PktReader::new(r);
        let section = reader.read_section(1024).await.unwrap();
        assert_eq!(&section[..], &data[..section.len()]);
        assert!(section.ends_with(FLUSH));
        // 残余（pack 先頭）が失われていない
        let (mut inner, leftover) = reader.into_parts();
        let mut rest = leftover.to_vec();
        inner.read_to_end(&mut rest).await.unwrap();
        assert_eq!(&rest[..], b"PACKDATA-after-flush");
    }

    #[tokio::test]
    async fn section_cap_exceeded_is_error() {
        let mut data = Vec::new();
        for _ in 0..10 {
            data.extend_from_slice(&pkt(&format!("{ZERO} {SHA} refs/heads/sekimore/x\n")));
        }
        data.extend_from_slice(FLUSH);
        let mut reader = PktReader::new(&data[..]);
        let err = reader.read_section(200).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("exceeds 200"));
        // 境界ちょうどは OK
        let mut reader = PktReader::new(&data[..]);
        assert!(reader.read_section(data.len()).await.is_ok());
    }

    #[tokio::test]
    async fn next_returns_frames_then_none_on_clean_eof() {
        let mut data = pkt("hello\n");
        data.extend_from_slice(FLUSH);
        let mut reader = PktReader::new(&data[..]);
        let f = reader.next().await.unwrap().unwrap();
        assert_eq!(f.payload(), b"hello\n");
        assert_eq!(f.raw(), Bytes::from(pkt("hello\n")));
        assert!(reader.next().await.unwrap().unwrap().is_flush());
        assert!(reader.next().await.unwrap().is_none());
        // 途中 EOF はエラー
        let mut reader = PktReader::new(&b"0009he"[..]);
        assert!(reader.next().await.is_err());
    }
}

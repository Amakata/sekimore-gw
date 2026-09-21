//! Reading a pack as it streams past, far enough to know what a pushed tag is.
//!
//! Stage C of receive-pack forwards the pack byte for byte and never looks inside. That is the
//! right shape for a branch push — the objects are the agent's own work, and the policy question
//! (which ref) was settled from the command section. A tag push asks one more question the
//! command section cannot answer: **is the thing being published a signed tag at all?** A
//! lightweight tag is a bare commit sha, an annotated one is a tag object, and the signature is
//! inside that object. #89 saw an unsigned tag go up under a name every other tag in the
//! repository signs, and nothing in the relay could have told.
//!
//! So this module walks the pack: every object's header, every object's zlib stream (inflated
//! and thrown away, because the header carries no compressed length and the stream is the only
//! way to find the next object), the *contents* of tag objects, which are small, and — since
//! 0.2.29 (#59) — the *header block* of each commit, the bytes up to its first blank line. What
//! comes out is a map from sha to "a tag, signed or not", "a commit, signed or not, and its
//! parents", or "some other kind of object" — enough to judge each `refs/tags/*` command and each
//! branch push against.
//!
//! A commit's header block is where `gpgsig` / `gpgsig-sha256` live, and stopping at the blank
//! line is what keeps this bounded: a commit with a 100 KB message costs a few hundred bytes here,
//! where keeping whole commits would cost the message.
//!
//! What it deliberately does not do: verify a signature. That needs to know whose keys count, a
//! decision the configuration does not yet hold. Presence is what this checks, and presence is
//! what would have caught the tag in #89 — it was made with `tag.gpgsign=false`.
//!
//! Deltas: a tag object may arrive as a delta against another tag in the same pack (two release
//! tags differ by a version number), so those are applied when the base is a tag this scan has
//! seen. A delta against anything else is not resolved: its result cannot be a tag unless its
//! base was one, and bases outside the pack are commits, trees and blobs — git never picks a tag
//! it has not sent as a preferred base. Such an object is simply not a candidate.

use std::collections::HashMap;
use std::fmt;

use flate2::{Decompress, FlushDecompress, Status};
use sha1::{Digest, Sha1};

/// A tag object bigger than this is not kept. Real ones are a few hundred bytes; a signature adds
/// a few hundred more. The cap exists so the pack cannot make this scan hold arbitrary memory.
const MAX_TAG_BYTES: usize = 1024 * 1024;

/// How much of a commit's header block is kept. The scan stops at the first blank line anyway;
/// this is the guard for a commit that has no blank line at all, or an absurd one. A commit whose
/// header does not fit reads as unsigned, which refuses the push — the direction to fail in.
const MAX_COMMIT_HEADER: usize = 64 * 1024;

/// git's object types as the pack header encodes them.
const OBJ_COMMIT: u8 = 1;
const OBJ_TREE: u8 = 2;
const OBJ_BLOB: u8 = 3;
const OBJ_TAG: u8 = 4;
const OBJ_OFS_DELTA: u8 = 6;
const OBJ_REF_DELTA: u8 = 7;

/// The trailer every pack ends with: a SHA-1 over everything before it.
pub const TRAILER_LEN: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackError {
    /// The bytes do not start with a pack, or the header names a version this scan does not read
    NotAPack(String),
    /// A header or a zlib stream that cannot be read
    Malformed(String),
    /// More bytes after the trailer than a pack can have
    TrailingBytes(usize),
    /// The client closed before the pack was complete
    Truncated,
}

impl fmt::Display for PackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PackError::NotAPack(why) => write!(f, "not a pack: {why}"),
            PackError::Malformed(why) => write!(f, "malformed pack: {why}"),
            PackError::TrailingBytes(n) => write!(f, "{n} bytes after the pack trailer"),
            PackError::Truncated => write!(f, "the pack ended early"),
        }
    }
}

/// What the scan learned about one object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Object {
    /// An annotated tag; `signed` is whether its body carries a signature block
    Tag { signed: bool },
    /// 0.2.29 (#59): a commit, with whether its header block carries `gpgsig` / `gpgsig-sha256`
    /// and the shas it names as parents (which is how a push's new history is walked)
    Commit { signed: bool, parents: Vec<String> },
    /// A tree or blob — what a lightweight tag can also point at
    Other(&'static str),
    /// A tag object over `MAX_TAG_BYTES`, whose body this scan did not keep
    OversizedTag,
}

/// Every object whose sha the scan could establish, by hex sha.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Objects {
    pub by_sha: HashMap<String, Object>,
    /// Deltas whose base was not a tag in this pack. Not an error; they are not tags.
    pub unresolved_deltas: usize,
    /// 0.2.29 (#59): of those, the ones whose base *was* a commit in this pack, so the delta's
    /// result is a commit this scan could not read. Counted apart because it is the only kind of
    /// unresolved delta that can hide a commit from the signing check — a thin pack's external
    /// bases are trees and blobs (`pack-objects` builds them with `add_preferred_base`, which
    /// dereferences a commit to its tree), so an unresolved delta on an absent base is not one
    pub unresolved_commit_deltas: usize,
}

enum State {
    /// Waiting for the 12-byte header
    Header,
    /// Waiting for the next object's header (type + size varint, then the delta base)
    ObjectHeader,
    /// Inside one object's zlib stream
    Inflating {
        kind: u8,
        size: usize,
        offset: u64,
        base: DeltaBase,
        z: Box<Decompress>,
        out: Vec<u8>,
        /// How much of this object's bytes to hold on to
        keep: Keep,
        hasher: Option<Sha1>,
    },
    /// All objects read; only the trailer remains
    Trailer,
    Done,
}

/// What is worth holding of one object's inflated bytes. Everything else is inflated and dropped,
/// because the pack header carries no compressed length and the stream is the only way to find
/// the next object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Keep {
    /// Nothing: a tree, a blob, or something over its cap
    Nothing,
    /// The whole body (a tag, or a delta to apply)
    Whole,
    /// A commit's header block: bytes up to the first blank line, at most `MAX_COMMIT_HEADER`
    CommitHeader,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeltaBase {
    None,
    /// The base is `offset` bytes before this object
    Offset(u64),
    /// The base is the object with this sha, in this pack or on the upstream
    Ref([u8; 20]),
}

/// Walks a pack incrementally. Feed it every chunk in order; ask it what it found at the end.
pub struct PackScan {
    /// Bytes not yet consumed start at `pos`; the front is compacted only once it is worth it,
    /// so a pack of many small objects does not memmove the buffer once per object
    pending: Vec<u8>,
    pos: usize,
    /// Bytes consumed so far, i.e. the pack offset of `pending[pos]`
    consumed: u64,
    remaining_objects: u32,
    state: State,
    /// Decoded tag objects by pack offset (for OFS_DELTA) and by sha (for REF_DELTA)
    tags_by_offset: HashMap<u64, Vec<u8>>,
    tags_by_sha: HashMap<[u8; 20], Vec<u8>>,
    /// 0.2.29 (#59): the resolved type of the object at each offset, so a delta chain's result
    /// type is known even where its bytes are not
    resolved_type: HashMap<u64, u8>,
    objects: Objects,
    /// Recorded rather than returned from `feed`: the caller is in the middle of forwarding bytes
    /// and has nothing useful to do with an error until the end
    error: Option<PackError>,
}

impl Default for PackScan {
    fn default() -> Self {
        Self::new()
    }
}

impl PackScan {
    pub fn new() -> Self {
        PackScan {
            pending: Vec::new(),
            pos: 0,
            consumed: 0,
            remaining_objects: 0,
            state: State::Header,
            tags_by_offset: HashMap::new(),
            tags_by_sha: HashMap::new(),
            resolved_type: HashMap::new(),
            objects: Objects::default(),
            error: None,
        }
    }

    /// The next chunk of the pack, in order. Never fails mid-stream; see `finish`.
    pub fn feed(&mut self, data: &[u8]) {
        if self.error.is_some() {
            return;
        }
        self.pending.extend_from_slice(data);
        if let Err(e) = self.advance() {
            self.error = Some(e);
        }
    }

    /// Whether there is nothing left to learn: the trailer has been seen, or an error has.
    ///
    /// The caller cannot wait for the client to close its side — git keeps it open until it has
    /// read the report-status, which the upstream will not write until it has the whole pack,
    /// trailer included. So the verdict has to be given the moment the pack is complete.
    pub fn is_complete(&self) -> bool {
        self.error.is_some() || matches!(self.state, State::Done)
    }

    /// Everything the scan established, or why it could not.
    pub fn finish(mut self) -> Result<Objects, PackError> {
        if let Some(e) = self.error.take() {
            return Err(e);
        }
        match self.state {
            State::Done => Ok(self.objects),
            // An empty pack (a push whose objects are all upstream already) is a header, no
            // objects and a trailer — git sends it in full. Nothing at all is the client
            // hanging up, or a push with only deletes, in which case this scan is never fed.
            State::Header if self.buf().is_empty() && self.consumed == 0 => Ok(self.objects),
            _ => Err(PackError::Truncated),
        }
    }

    fn advance(&mut self) -> Result<(), PackError> {
        loop {
            match &mut self.state {
                State::Header => {
                    if self.buf().len() < 12 {
                        return Ok(());
                    }
                    if &self.buf()[..4] != b"PACK" {
                        return Err(PackError::NotAPack("no PACK signature".into()));
                    }
                    let version = u32::from_be_bytes(self.buf()[4..8].try_into().unwrap());
                    if version != 2 && version != 3 {
                        return Err(PackError::NotAPack(format!("version {version}")));
                    }
                    self.remaining_objects =
                        u32::from_be_bytes(self.buf()[8..12].try_into().unwrap());
                    self.drain(12);
                    self.state = if self.remaining_objects == 0 {
                        State::Trailer
                    } else {
                        State::ObjectHeader
                    };
                }
                State::ObjectHeader => {
                    let offset = self.consumed;
                    let Some((kind, size, base, used)) = parse_object_header(self.buf())? else {
                        return Ok(());
                    };
                    self.drain(used);
                    let keep = match kind {
                        OBJ_TAG | OBJ_OFS_DELTA | OBJ_REF_DELTA if size <= MAX_TAG_BYTES => {
                            Keep::Whole
                        }
                        // #59: only the header block, whatever the commit's total size — that is
                        // where a signature lives, and a long message must not cost memory
                        OBJ_COMMIT => Keep::CommitHeader,
                        _ => Keep::Nothing,
                    };
                    // Only whole objects get a sha: a delta's sha is its result's, which is
                    // known only once applied.
                    let hasher = match kind {
                        OBJ_COMMIT | OBJ_TREE | OBJ_BLOB | OBJ_TAG => {
                            let mut h = Sha1::new();
                            h.update(format!("{} {size}\0", type_name(kind)).as_bytes());
                            Some(h)
                        }
                        _ => None,
                    };
                    self.state = State::Inflating {
                        kind,
                        size,
                        offset,
                        base,
                        z: Box::new(Decompress::new(true)),
                        out: Vec::new(),
                        keep,
                        hasher,
                    };
                }
                State::Inflating { .. } => {
                    if self.buf().is_empty() {
                        return Ok(());
                    }
                    // Take the object's state out so the rest of `self` is free to be touched
                    let State::Inflating {
                        kind,
                        size,
                        offset,
                        base,
                        mut z,
                        mut out,
                        mut keep,
                        mut hasher,
                    } = std::mem::replace(&mut self.state, State::Done)
                    else {
                        unreachable!()
                    };
                    let before_in = z.total_in();
                    let before_out = z.total_out();
                    // A bounded scratch buffer: the stream decides how much comes out per call,
                    // and an object we are skipping must not cost memory proportional to itself.
                    let mut scratch = [0u8; 16 * 1024];
                    let status = z
                        .decompress(self.buf(), &mut scratch, FlushDecompress::None)
                        .map_err(|e| PackError::Malformed(format!("zlib: {e}")))?;
                    let used = (z.total_in() - before_in) as usize;
                    let produced = (z.total_out() - before_out) as usize;
                    if let Some(h) = hasher.as_mut() {
                        h.update(&scratch[..produced]);
                    }
                    match keep {
                        Keep::Nothing => {}
                        Keep::Whole => out.extend_from_slice(&scratch[..produced]),
                        Keep::CommitHeader => {
                            let before = out.len();
                            let room = MAX_COMMIT_HEADER.saturating_sub(before);
                            out.extend_from_slice(&scratch[..produced.min(room)]);
                            // The blank line can straddle two chunks, so rescan from one byte
                            // before what was just added
                            let from = before.saturating_sub(1);
                            if out.len() >= MAX_COMMIT_HEADER
                                || out[from..].windows(2).any(|w| w == b"\n\n")
                            {
                                keep = Keep::Nothing;
                            }
                        }
                    }
                    self.drain(used);
                    if status == Status::StreamEnd {
                        if z.total_out() as usize != size {
                            return Err(PackError::Malformed(format!(
                                "object at {offset} inflates to {} bytes, header says {size}",
                                z.total_out()
                            )));
                        }
                        let sha = hasher.take().map(|h| h.finalize());
                        self.finish_object(kind, offset, base, out, keep, sha.as_deref());
                        self.remaining_objects -= 1;
                        self.state = if self.remaining_objects == 0 {
                            State::Trailer
                        } else {
                            State::ObjectHeader
                        };
                        continue;
                    }
                    let stalled = used == 0 && produced == 0;
                    self.state = State::Inflating {
                        kind,
                        size,
                        offset,
                        base,
                        z,
                        out,
                        keep,
                        hasher,
                    };
                    if stalled {
                        // Neither side moved: the stream wants more input than we have
                        return Ok(());
                    }
                }
                State::Trailer => {
                    if self.buf().len() < TRAILER_LEN {
                        return Ok(());
                    }
                    if self.buf().len() > TRAILER_LEN {
                        return Err(PackError::TrailingBytes(self.buf().len() - TRAILER_LEN));
                    }
                    self.drain(TRAILER_LEN);
                    self.state = State::Done;
                }
                State::Done => {
                    if !self.buf().is_empty() {
                        return Err(PackError::TrailingBytes(self.buf().len()));
                    }
                    return Ok(());
                }
            }
        }
    }

    /// What has arrived and not been consumed
    fn buf(&self) -> &[u8] {
        &self.pending[self.pos..]
    }

    fn drain(&mut self, n: usize) {
        self.pos += n;
        self.consumed += n as u64;
        if self.pos >= 64 * 1024 && self.pos * 2 >= self.pending.len() {
            self.pending.drain(..self.pos);
            self.pos = 0;
        }
    }

    /// One object fully inflated. `body` holds what `keep` asked for: the whole object, a
    /// commit's header block, or nothing.
    fn finish_object(
        &mut self,
        kind: u8,
        offset: u64,
        base: DeltaBase,
        body: Vec<u8>,
        keep: Keep,
        sha: Option<&[u8]>,
    ) {
        match kind {
            OBJ_TAG => {
                let sha: [u8; 20] = sha.unwrap().try_into().unwrap();
                self.resolved_type.insert(offset, OBJ_TAG);
                // A tag is kept whole or not at all, so `Nothing` here means it was over the cap:
                // nothing can be said about a signature, and an empty body must not read as
                // "unsigned"
                if keep == Keep::Nothing {
                    self.objects
                        .by_sha
                        .insert(hex::encode(sha), Object::OversizedTag);
                } else {
                    self.record_tag(offset, sha, body);
                }
            }
            OBJ_COMMIT => {
                self.resolved_type.insert(offset, OBJ_COMMIT);
                self.objects.by_sha.insert(
                    hex::encode(sha.unwrap()),
                    Object::Commit {
                        signed: commit_is_signed(&body),
                        parents: commit_parents(&body),
                    },
                );
            }
            OBJ_TREE | OBJ_BLOB => {
                self.resolved_type.insert(offset, kind);
                self.objects
                    .by_sha
                    .insert(hex::encode(sha.unwrap()), Object::Other(type_name(kind)));
            }
            OBJ_OFS_DELTA | OBJ_REF_DELTA => {
                let base_at = match base {
                    DeltaBase::Offset(back) => offset.checked_sub(back),
                    _ => None,
                };
                // A delta's result has its base's type. Knowing it is what tells an unresolved
                // delta that could be hiding a commit from one that is a tree or a blob.
                let base_type = match base {
                    DeltaBase::Offset(_) => {
                        base_at.and_then(|at| self.resolved_type.get(&at).copied())
                    }
                    DeltaBase::Ref(sha) => match self.objects.by_sha.get(&hex::encode(sha)) {
                        Some(Object::Commit { .. }) => Some(OBJ_COMMIT),
                        Some(Object::Tag { .. }) | Some(Object::OversizedTag) => Some(OBJ_TAG),
                        Some(Object::Other("tree")) => Some(OBJ_TREE),
                        Some(Object::Other(_)) => Some(OBJ_BLOB),
                        None => None,
                    },
                    DeltaBase::None => None,
                };
                if let Some(t) = base_type {
                    self.resolved_type.insert(offset, t);
                }
                let base_body = match base {
                    DeltaBase::Offset(_) => base_at.and_then(|at| self.tags_by_offset.get(&at)),
                    DeltaBase::Ref(sha) => self.tags_by_sha.get(&sha),
                    DeltaBase::None => None,
                };
                match base_body.and_then(|b| apply_delta(b, &body)) {
                    Some(result) if result.len() <= MAX_TAG_BYTES => {
                        let mut h = Sha1::new();
                        h.update(format!("tag {}\0", result.len()).as_bytes());
                        h.update(&result);
                        let sha: [u8; 20] = h.finalize().into();
                        self.record_tag(offset, sha, result);
                    }
                    _ => {
                        self.objects.unresolved_deltas += 1;
                        // Only a commit-based one can hide a commit from the signing check. Only
                        // tag bodies are kept whole, so a commit delta is never applied and this
                        // is how the check learns to fail closed.
                        if base_type == Some(OBJ_COMMIT) {
                            self.objects.unresolved_commit_deltas += 1;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn record_tag(&mut self, offset: u64, sha: [u8; 20], body: Vec<u8>) {
        self.resolved_type.insert(offset, OBJ_TAG);
        let signed = tag_is_signed(&body);
        self.objects
            .by_sha
            .insert(hex::encode(sha), Object::Tag { signed });
        if body.len() <= MAX_TAG_BYTES {
            self.tags_by_offset.insert(offset, body.clone());
            self.tags_by_sha.insert(sha, body);
        }
    }
}

fn type_name(kind: u8) -> &'static str {
    match kind {
        OBJ_COMMIT => "commit",
        OBJ_TREE => "tree",
        OBJ_BLOB => "blob",
        OBJ_TAG => "tag",
        _ => "delta",
    }
}

/// `(kind, size, delta base, bytes used)`, or None when the buffer does not hold the whole header yet.
fn parse_object_header(buf: &[u8]) -> Result<Option<(u8, usize, DeltaBase, usize)>, PackError> {
    let mut i = 0;
    let Some(&c) = buf.first() else {
        return Ok(None);
    };
    i += 1;
    let kind = (c >> 4) & 0x07;
    let mut size = (c & 0x0f) as usize;
    let mut shift = 4;
    let mut c = c;
    while c & 0x80 != 0 {
        let Some(&next) = buf.get(i) else {
            return Ok(None);
        };
        i += 1;
        c = next;
        if shift > 60 {
            return Err(PackError::Malformed("object size varint too long".into()));
        }
        size |= ((c & 0x7f) as usize) << shift;
        shift += 7;
    }
    let base = match kind {
        OBJ_COMMIT | OBJ_TREE | OBJ_BLOB | OBJ_TAG => DeltaBase::None,
        OBJ_OFS_DELTA => {
            let Some(&first) = buf.get(i) else {
                return Ok(None);
            };
            i += 1;
            let mut c = first;
            let mut off = (c & 0x7f) as u64;
            while c & 0x80 != 0 {
                let Some(&next) = buf.get(i) else {
                    return Ok(None);
                };
                i += 1;
                c = next;
                off = ((off + 1) << 7) | (c & 0x7f) as u64;
            }
            DeltaBase::Offset(off)
        }
        OBJ_REF_DELTA => {
            if buf.len() < i + 20 {
                return Ok(None);
            }
            let sha: [u8; 20] = buf[i..i + 20].try_into().unwrap();
            i += 20;
            DeltaBase::Ref(sha)
        }
        other => {
            return Err(PackError::Malformed(format!("object type {other}")));
        }
    };
    Ok(Some((kind, size, base, i)))
}

/// git's delta format: two size varints, then copy (MSB set) and insert (MSB clear) instructions.
/// None when the delta does not fit its base.
fn apply_delta(base: &[u8], delta: &[u8]) -> Option<Vec<u8>> {
    fn varint(d: &[u8], i: &mut usize) -> Option<usize> {
        let mut v = 0usize;
        let mut shift = 0;
        loop {
            let c = *d.get(*i)?;
            *i += 1;
            v |= ((c & 0x7f) as usize) << shift;
            if c & 0x80 == 0 {
                return Some(v);
            }
            shift += 7;
            if shift > 60 {
                return None;
            }
        }
    }
    let mut i = 0;
    let base_size = varint(delta, &mut i)?;
    if base_size != base.len() {
        return None;
    }
    let result_size = varint(delta, &mut i)?;
    if result_size > MAX_TAG_BYTES {
        return None;
    }
    let mut out = Vec::with_capacity(result_size);
    while i < delta.len() {
        let op = delta[i];
        i += 1;
        if op & 0x80 != 0 {
            let mut off = 0usize;
            let mut len = 0usize;
            for (bit, shift) in [(0x01, 0), (0x02, 8), (0x04, 16), (0x08, 24)] {
                if op & bit != 0 {
                    off |= (*delta.get(i)? as usize) << shift;
                    i += 1;
                }
            }
            for (bit, shift) in [(0x10, 0), (0x20, 8), (0x40, 16)] {
                if op & bit != 0 {
                    len |= (*delta.get(i)? as usize) << shift;
                    i += 1;
                }
            }
            if len == 0 {
                len = 0x10000;
            }
            out.extend_from_slice(base.get(off..off.checked_add(len)?)?);
        } else if op == 0 {
            return None;
        } else {
            let n = op as usize;
            out.extend_from_slice(delta.get(i..i + n)?);
            i += n;
        }
    }
    (out.len() == result_size).then_some(out)
}

/// The header block of a commit: everything before the first blank line.
///
/// `body` is what the scan kept, which already stops at the blank line — but it may hold the
/// bytes that followed in the same chunk, and a caller with a whole commit in hand should get the
/// same answer. So the cut is made here too.
fn commit_header(body: &[u8]) -> &[u8] {
    match body.windows(2).position(|w| w == b"\n\n") {
        Some(at) => &body[..at + 1],
        None => body,
    }
}

/// Whether a commit's header block carries a signature (#59).
///
/// Presence, not validity — the same standard as `tag_is_signed`, and for the same reason. git
/// writes the signature as a `gpgsig` header (`gpgsig-sha256` in a sha256 repository) whose
/// continuation lines are indented by one space, so only a line *starting* a header counts: a
/// `gpgsig` inside the message, or inside another header's continuation, is text.
///
/// A header block this scan had to truncate reads as unsigned, which refuses the push. That is
/// the direction to fail in.
pub fn commit_is_signed(body: &[u8]) -> bool {
    commit_header(body)
        .split(|&b| b == b'\n')
        .any(|l| l.starts_with(b"gpgsig ") || l.starts_with(b"gpgsig-sha256 "))
}

/// The shas a commit names as parents, in order (#59). Used to walk the history a push adds.
pub fn commit_parents(body: &[u8]) -> Vec<String> {
    commit_header(body)
        .split(|&b| b == b'\n')
        .filter_map(|l| l.strip_prefix(b"parent "))
        .filter(|sha| sha.len() == 40 && sha.iter().all(|c| c.is_ascii_hexdigit()))
        .map(|sha| String::from_utf8_lossy(sha).to_ascii_lowercase())
        .collect()
}

/// Whether a tag object's body carries a signature block after its message.
///
/// Presence, not validity. The three openers are the ones git itself recognises
/// (`parse_signature`): OpenPGP, X.509 via gpgsm, and SSH.
pub fn tag_is_signed(body: &[u8]) -> bool {
    const OPENERS: [&[u8]; 3] = [
        b"-----BEGIN PGP SIGNATURE-----",
        b"-----BEGIN SIGNED MESSAGE-----",
        b"-----BEGIN SSH SIGNATURE-----",
    ];
    // Headers end at the first blank line; a signature lives in what follows
    let Some(at) = body.windows(2).position(|w| w == b"\n\n") else {
        return false;
    };
    let message = &body[at + 2..];
    let mut lines = message.split(|&b| b == b'\n');
    while let Some(line) = lines.next() {
        if let Some(opener) = OPENERS.iter().find(|o| line.starts_with(o)) {
            // and the matching END opens a later line — a pasted opener in a message, or an
            // END buried mid-line, is not a block
            let closer = [b"-----END ".as_slice(), &opener[b"-----BEGIN ".len()..]].concat();
            return lines.any(|l| l.starts_with(&closer));
        }
    }
    false
}

#[cfg(test)]
pub mod testutil {
    //! Building packs for tests. Also used by receive_pack's tests.
    use super::*;
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    pub fn sha_of(kind: &str, body: &[u8]) -> String {
        let mut h = Sha1::new();
        h.update(format!("{kind} {}\0", body.len()).as_bytes());
        h.update(body);
        hex::encode(h.finalize())
    }

    fn zlib(body: &[u8]) -> Vec<u8> {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(body).unwrap();
        e.finish().unwrap()
    }

    fn header(kind: u8, size: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut c = (kind << 4) | (size & 0x0f) as u8;
        let mut size = size >> 4;
        while size > 0 {
            out.push(c | 0x80);
            c = (size & 0x7f) as u8;
            size >>= 7;
        }
        out.push(c);
        out
    }

    pub enum Entry<'a> {
        Whole(u8, &'a [u8]),
        /// A delta against the entry `back` positions earlier, given as (base body, delta bytes)
        OfsDelta {
            back: usize,
            delta: &'a [u8],
        },
        RefDelta {
            base_sha: [u8; 20],
            delta: &'a [u8],
        },
    }

    pub fn pack(entries: &[Entry<'_>]) -> Vec<u8> {
        let mut out = b"PACK".to_vec();
        out.extend_from_slice(&2u32.to_be_bytes());
        out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        let mut offsets = Vec::new();
        for e in entries {
            offsets.push(out.len() as u64);
            match e {
                Entry::Whole(kind, body) => {
                    out.extend(header(*kind, body.len()));
                    out.extend(zlib(body));
                }
                Entry::OfsDelta { back, delta } => {
                    let here = out.len() as u64;
                    let base_at = offsets[offsets.len() - 1 - back];
                    out.extend(header(OBJ_OFS_DELTA, delta.len()));
                    out.extend(ofs(here - base_at));
                    out.extend(zlib(delta));
                }
                Entry::RefDelta { base_sha, delta } => {
                    out.extend(header(OBJ_REF_DELTA, delta.len()));
                    out.extend_from_slice(base_sha);
                    out.extend(zlib(delta));
                }
            }
        }
        let trailer = Sha1::digest(&out);
        out.extend_from_slice(&trailer);
        out
    }

    fn ofs(mut n: u64) -> Vec<u8> {
        // git's encoding, written back to front
        let mut bytes = vec![(n & 0x7f) as u8];
        n >>= 7;
        while n > 0 {
            n -= 1;
            bytes.push(((n & 0x7f) as u8) | 0x80);
            n >>= 7;
        }
        bytes.reverse();
        bytes
    }

    /// A delta that turns `base` into `result` the dumb way: one insert per 127 bytes.
    pub fn insert_only_delta(base: &[u8], result: &[u8]) -> Vec<u8> {
        fn varint(mut v: usize, out: &mut Vec<u8>) {
            loop {
                let c = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 {
                    out.push(c);
                    return;
                }
                out.push(c | 0x80);
            }
        }
        let mut d = Vec::new();
        varint(base.len(), &mut d);
        varint(result.len(), &mut d);
        for chunk in result.chunks(127) {
            d.push(chunk.len() as u8);
            d.extend_from_slice(chunk);
        }
        d
    }

    /// A delta that copies the whole base and then inserts `suffix`.
    pub fn copy_then_insert_delta(base: &[u8], suffix: &[u8]) -> Vec<u8> {
        let mut d = insert_only_delta(base, &[]);
        // rewrite the result size
        d.clear();
        let mut varint = |mut v: usize| loop {
            let c = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                d.push(c);
                break;
            }
            d.push(c | 0x80);
        };
        varint(base.len());
        varint(base.len() + suffix.len());
        // copy: offset 0, length base.len() (up to 3 bytes)
        let len = base.len();
        d.push(0x80 | 0x10 | 0x20 | 0x40);
        d.push((len & 0xff) as u8);
        d.push(((len >> 8) & 0xff) as u8);
        d.push(((len >> 16) & 0xff) as u8);
        for chunk in suffix.chunks(127) {
            d.push(chunk.len() as u8);
            d.extend_from_slice(chunk);
        }
        d
    }

    pub const COMMIT: &[u8] = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nauthor A <a@x> 0 +0000\ncommitter A <a@x> 0 +0000\n\nfirst\n";

    /// A commit body, optionally signed, with whatever parents and message are wanted (#59).
    pub fn commit_body(parents: &[&str], signed: bool, message: &str) -> Vec<u8> {
        let mut b = String::from("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n");
        for p in parents {
            b.push_str(&format!("parent {p}\n"));
        }
        b.push_str("author A <a@x> 0 +0000\ncommitter A <a@x> 0 +0000\n");
        if signed {
            // git's shape: the header value starts on the `gpgsig` line and continues on lines
            // indented by one space
            b.push_str("gpgsig -----BEGIN SSH SIGNATURE-----\n U1NIU0lHAAAAAQ==\n -----END SSH SIGNATURE-----\n");
        }
        b.push_str(&format!("\n{message}\n"));
        b.into_bytes()
    }

    pub fn tag_body(name: &str, target: &str, signed: bool) -> Vec<u8> {
        let mut b =
            format!("object {target}\ntype commit\ntag {name}\ntagger A <a@x> 0 +0000\n\n{name}\n");
        if signed {
            b.push_str(
                "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQ==\n-----END SSH SIGNATURE-----\n",
            );
        }
        b.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    fn scan(bytes: &[u8], chunk: usize) -> Result<Objects, PackError> {
        let mut s = PackScan::new();
        for c in bytes.chunks(chunk.max(1)) {
            s.feed(c);
        }
        s.finish()
    }

    #[test]
    fn a_signed_tag_is_seen_as_one_whatever_the_chunking() {
        let commit_sha = sha_of("commit", COMMIT);
        let tag = tag_body("v1", &commit_sha, true);
        let p = pack(&[
            Entry::Whole(OBJ_COMMIT, COMMIT),
            Entry::Whole(OBJ_TAG, &tag),
        ]);
        for chunk in [1, 7, 64, 4096] {
            let o = scan(&p, chunk).unwrap_or_else(|e| panic!("chunk {chunk}: {e}"));
            assert_eq!(
                o.by_sha.get(&sha_of("tag", &tag)),
                Some(&Object::Tag { signed: true }),
                "chunk {chunk}"
            );
            assert_eq!(
                o.by_sha.get(&commit_sha),
                Some(&Object::Commit {
                    signed: false,
                    parents: vec![]
                }),
                "chunk {chunk}"
            );
        }
    }

    #[test]
    fn an_annotated_tag_without_a_signature_is_a_tag_and_not_signed() {
        let tag = tag_body("v1", &sha_of("commit", COMMIT), false);
        let p = pack(&[Entry::Whole(OBJ_TAG, &tag)]);
        let o = scan(&p, 5).unwrap();
        assert_eq!(
            o.by_sha.get(&sha_of("tag", &tag)),
            Some(&Object::Tag { signed: false })
        );
    }

    #[test]
    fn a_tag_sent_as_a_delta_against_another_tag_is_resolved() {
        // Two release tags differ by a version number, which is exactly when git deltifies.
        let target = sha_of("commit", COMMIT);
        let v1 = tag_body("v1", &target, true);
        let v2 = tag_body("v2", &target, true);
        let delta = insert_only_delta(&v1, &v2);
        let p = pack(&[
            Entry::Whole(OBJ_TAG, &v1),
            Entry::OfsDelta {
                back: 1,
                delta: &delta,
            },
        ]);
        let o = scan(&p, 3).unwrap();
        assert_eq!(
            o.by_sha.get(&sha_of("tag", &v2)),
            Some(&Object::Tag { signed: true })
        );
        assert_eq!(o.unresolved_deltas, 0);

        // and by sha
        let mut base_sha = [0u8; 20];
        hex::decode_to_slice(sha_of("tag", &v1), &mut base_sha).unwrap();
        let p = pack(&[
            Entry::Whole(OBJ_TAG, &v1),
            Entry::RefDelta {
                base_sha,
                delta: &delta,
            },
        ]);
        let o = scan(&p, 1024).unwrap();
        assert_eq!(
            o.by_sha.get(&sha_of("tag", &v2)),
            Some(&Object::Tag { signed: true })
        );
    }

    #[test]
    fn a_delta_that_strips_the_signature_is_an_unsigned_tag() {
        let target = sha_of("commit", COMMIT);
        let signed = tag_body("v1", &target, true);
        let unsigned = tag_body("v1", &target, false);
        let delta = insert_only_delta(&signed, &unsigned);
        let p = pack(&[
            Entry::Whole(OBJ_TAG, &signed),
            Entry::OfsDelta {
                back: 1,
                delta: &delta,
            },
        ]);
        let o = scan(&p, 16).unwrap();
        assert_eq!(
            o.by_sha.get(&sha_of("tag", &unsigned)),
            Some(&Object::Tag { signed: false })
        );
    }

    #[test]
    fn a_delta_against_a_base_that_is_not_here_is_counted_not_guessed() {
        let delta = insert_only_delta(b"whatever", b"else");
        let p = pack(&[Entry::RefDelta {
            base_sha: [7u8; 20],
            delta: &delta,
        }]);
        let o = scan(&p, 1024).unwrap();
        assert!(o.by_sha.is_empty());
        assert_eq!(o.unresolved_deltas, 1);
    }

    #[test]
    fn an_empty_pack_has_no_objects_and_is_not_an_error() {
        let p = pack(&[]);
        assert_eq!(p.len(), 12 + TRAILER_LEN);
        assert_eq!(scan(&p, 5).unwrap(), Objects::default());
        // nothing at all: also fine (a push of only deletes sends no pack)
        assert_eq!(PackScan::new().finish().unwrap(), Objects::default());
    }

    #[test]
    fn a_pack_cut_short_says_so() {
        let tag = tag_body("v1", &sha_of("commit", COMMIT), true);
        let p = pack(&[Entry::Whole(OBJ_TAG, &tag)]);
        assert_eq!(scan(&p[..p.len() - 1], 1024), Err(PackError::Truncated));
        assert_eq!(scan(&p[..20], 1024), Err(PackError::Truncated));
    }

    #[test]
    fn bytes_after_the_trailer_are_refused() {
        let mut p = pack(&[]);
        p.push(0);
        assert_eq!(scan(&p, 1024), Err(PackError::TrailingBytes(1)));
    }

    #[test]
    fn something_that_is_not_a_pack_is_named_as_such() {
        assert!(matches!(
            scan(b"0000000000000000", 1024),
            Err(PackError::NotAPack(_))
        ));
    }

    #[test]
    fn a_size_that_does_not_match_the_stream_is_malformed() {
        let mut p = pack(&[Entry::Whole(OBJ_BLOB, b"hello")]);
        // header byte: type blob, size 5 -> claim 6
        p[12] = (OBJ_BLOB << 4) | 6;
        assert!(matches!(scan(&p, 1024), Err(PackError::Malformed(_))));
    }

    #[test]
    fn a_big_object_is_skipped_without_being_kept() {
        // A 3 MB blob in the same push as a tag: the blob must not be held, the tag must be found.
        let blob = vec![b'x'; 3 * 1024 * 1024];
        let tag = tag_body("v1", &sha_of("commit", COMMIT), true);
        let p = pack(&[Entry::Whole(OBJ_BLOB, &blob), Entry::Whole(OBJ_TAG, &tag)]);
        let o = scan(&p, 8192).unwrap();
        assert_eq!(
            o.by_sha.get(&sha_of("tag", &tag)),
            Some(&Object::Tag { signed: true })
        );
        assert_eq!(
            o.by_sha.get(&sha_of("blob", &blob)),
            Some(&Object::Other("blob"))
        );
    }

    #[test]
    fn signature_detection_reads_the_body_not_the_headers() {
        // An opener in the message that never closes is not a signature
        let mut body = tag_body("v1", &sha_of("commit", COMMIT), false);
        body.extend_from_slice(b"-----BEGIN PGP SIGNATURE-----\n");
        assert!(!tag_is_signed(&body));
        // The three formats git knows
        for opener in [
            "-----BEGIN PGP SIGNATURE-----\nabc\n-----END PGP SIGNATURE-----\n",
            "-----BEGIN SIGNED MESSAGE-----\nabc\n-----END SIGNED MESSAGE-----\n",
            "-----BEGIN SSH SIGNATURE-----\nabc\n-----END SSH SIGNATURE-----\n",
        ] {
            let mut body = tag_body("v1", &sha_of("commit", COMMIT), false);
            body.extend_from_slice(opener.as_bytes());
            assert!(tag_is_signed(&body), "{opener}");
        }
        // No blank line at all: not even a message
        assert!(!tag_is_signed(b"object x\ntype commit\n"));
    }

    #[test]
    fn a_pasted_opener_with_an_end_buried_mid_line_is_not_a_signature() {
        let mut body = tag_body("v1", &sha_of("commit", COMMIT), false);
        body.extend_from_slice(
            b"-----BEGIN SSH SIGNATURE-----\nsee the -----END SSH SIGNATURE----- marker\n",
        );
        assert!(!tag_is_signed(&body));
        // and an END of another kind does not close it
        let mut body = tag_body("v1", &sha_of("commit", COMMIT), false);
        body.extend_from_slice(
            b"-----BEGIN SSH SIGNATURE-----\nabc\n-----END PGP SIGNATURE-----\n",
        );
        assert!(!tag_is_signed(&body));
    }

    #[test]
    fn a_tag_over_the_cap_is_reported_as_such_not_as_unsigned() {
        let mut tag = tag_body("v1", &sha_of("commit", COMMIT), true);
        tag.extend(std::iter::repeat_n(b'x', MAX_TAG_BYTES));
        let p = pack(&[Entry::Whole(OBJ_TAG, &tag)]);
        let o = scan(&p, 8192).unwrap();
        assert_eq!(
            o.by_sha.get(&sha_of("tag", &tag)),
            Some(&Object::OversizedTag)
        );
    }

    #[test]
    fn many_small_objects_do_not_move_the_buffer_each_time() {
        // 5,000 tiny blobs in one 64 KiB feed: correctness is what is asserted; the cursor
        // keeps this from being quadratic
        let bodies: Vec<Vec<u8>> = (0..5000u32).map(|i| i.to_le_bytes().to_vec()).collect();
        let entries: Vec<Entry<'_>> = bodies.iter().map(|b| Entry::Whole(OBJ_BLOB, b)).collect();
        let p = pack(&entries);
        let o = scan(&p, 64 * 1024).unwrap();
        assert_eq!(o.by_sha.len(), 5000);
    }

    // ---- #59: commit header blocks ----

    #[test]
    fn a_commits_signature_and_parents_survive_every_chunking() {
        // The blank line that ends the header block, and the `gpgsig` inside it, both straddle
        // chunk boundaries at some size; the scan has to give the same answer at all of them.
        let p1 = sha_of("commit", &commit_body(&[], true, "one"));
        let p2 = sha_of("commit", &commit_body(&[], true, "two"));
        let signed = commit_body(&[&p1, &p2], true, "a merge");
        let plain = commit_body(&[&p1], false, "no signature here");
        let p = pack(&[
            Entry::Whole(OBJ_COMMIT, &signed),
            Entry::Whole(OBJ_COMMIT, &plain),
        ]);
        for chunk in [1, 3, 7, 64, 4096, 1 << 20] {
            let o = scan(&p, chunk).unwrap_or_else(|e| panic!("chunk {chunk}: {e}"));
            assert_eq!(
                o.by_sha.get(&sha_of("commit", &signed)),
                Some(&Object::Commit {
                    signed: true,
                    parents: vec![p1.clone(), p2.clone()]
                }),
                "chunk {chunk}"
            );
            assert_eq!(
                o.by_sha.get(&sha_of("commit", &plain)),
                Some(&Object::Commit {
                    signed: false,
                    parents: vec![p1.clone()]
                }),
                "chunk {chunk}"
            );
        }
    }

    #[test]
    fn a_hundred_kilobyte_commit_message_costs_nothing_and_still_reads_as_signed() {
        // The reason the scan stops at the blank line. The message is far over the header cap;
        // keeping whole commits would hold all of it, and the signature is in the first 500 bytes
        // either way.
        let message = "x".repeat(100 * 1024);
        let body = commit_body(&[], true, &message);
        assert!(body.len() > 100 * 1024);
        let p = pack(&[Entry::Whole(OBJ_COMMIT, &body)]);
        let o = scan(&p, 8192).unwrap();
        assert_eq!(
            o.by_sha.get(&sha_of("commit", &body)),
            Some(&Object::Commit {
                signed: true,
                parents: vec![]
            })
        );
    }

    #[test]
    fn a_header_block_over_the_cap_reads_as_unsigned_rather_than_as_signed() {
        // No blank line at all, and nothing that starts a `gpgsig` header. The scan gives up at
        // MAX_COMMIT_HEADER, and "cannot tell" has to come out as unsigned, which refuses.
        let body = format!(
            "tree {}\n{}",
            "4b825dc642cb6eb9a060e54bf8d69288fbee4904",
            "a".repeat(MAX_COMMIT_HEADER * 2)
        )
        .into_bytes();
        let p = pack(&[Entry::Whole(OBJ_COMMIT, &body)]);
        let o = scan(&p, 4096).unwrap();
        assert_eq!(
            o.by_sha.get(&sha_of("commit", &body)),
            Some(&Object::Commit {
                signed: false,
                parents: vec![]
            })
        );
    }

    #[test]
    fn only_a_header_line_counts_as_a_signature() {
        // `gpgsig` in the message, and `gpgsig` on a continuation line of another header, are
        // both text. Reading either as a signature would let an unsigned commit through a
        // `signing: required` project by writing a commit message.
        for message in [
            "gpgsig -----BEGIN SSH SIGNATURE-----",
            "look:\ngpgsig -----BEGIN SSH SIGNATURE-----\n",
        ] {
            assert!(
                !commit_is_signed(&commit_body(&[], false, message)),
                "{message:?}"
            );
        }
        let continued = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\nmergetag object 0000\n gpgsig not a header\n\nmsg\n";
        assert!(!commit_is_signed(continued));
        // and the real thing, in both spellings
        assert!(commit_is_signed(&commit_body(&[], true, "msg")));
        let sha256 = b"tree x\ngpgsig-sha256 -----BEGIN PGP SIGNATURE-----\n\nmsg\n";
        assert!(commit_is_signed(sha256));
    }

    #[test]
    fn a_parent_line_has_to_look_like_a_sha() {
        // The pack is written by the client; a header line is whatever it put there.
        let body = b"tree x\nparent not-a-sha\nparent 0123456789abcdef0123456789abcdef01234567\nparent 0123456789ABCDEF0123456789abcdef01234567\n\nm\n";
        assert_eq!(
            commit_parents(body),
            vec![
                "0123456789abcdef0123456789abcdef01234567".to_string(),
                "0123456789abcdef0123456789abcdef01234567".to_string()
            ]
        );
        // a `parent` after the blank line is message text
        assert_eq!(
            commit_parents(b"tree x\n\nparent 0123456789abcdef0123456789abcdef01234567\n"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn copy_instructions_are_applied() {
        let base = b"base bytes here";
        let delta = copy_then_insert_delta(base, b" and more");
        assert_eq!(
            apply_delta(base, &delta).unwrap(),
            b"base bytes here and more".to_vec()
        );
        // wrong base size
        assert!(apply_delta(b"short", &delta).is_none());
    }
}

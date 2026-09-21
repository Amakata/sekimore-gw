//! The envelope: a passphrase unlocks the KEK, the KEK unwraps the DEK, the DEK seals records.
//!
//! Value-level rather than page-level, deliberately. Page encryption (SQLCipher and friends) hands
//! back plaintext to every query once the connection is open, so an injection travelling on that
//! connection reads plaintext. Sealing each value means an injection that dumps every row gets
//! ciphertext, and decryption happens once per record in code that meant to.
//!
//! Everything here is pure Rust. The musl build and the CI check that neither `aws-lc-rs` nor
//! `openssl-sys` is in the tree both depend on that, which also means these implementations are
//! not FIPS-validated. `alg` and `kdf` are carried in the stored parameters so a validated backend
//! can replace them without a format change.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::StoreError;

/// Bytes that are wiped when they go out of scope. Not a guarantee — host root can read process
/// memory, and avoiding swap would need `mlock` and `CAP_IPC_LOCK`, which the gateway does not
/// hold — but it keeps a key from outliving its use in a freed allocation.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Self {
        Secret(bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    /// Never prints the bytes. A key reaching a log is the failure this store exists to prevent.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret({} bytes)", self.0.len())
    }
}

/// How a key is derived from a passphrase. Stored with the store, so the parameters that made a
/// key are the ones used to reproduce it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kdf {
    /// Memory-hard, and the reason to prefer it: the exported envelope is guarded by the
    /// passphrase alone, and Argon2id costs an attacker memory as well as time.
    Argon2id,
    /// FIPS-approved (SP 800-132) and memory-light, so materially weaker against GPUs for the same
    /// passphrase. Selectable for deployments that need the approval, not a default.
    Pbkdf2Sha256,
}

impl Kdf {
    pub fn as_str(self) -> &'static str {
        match self {
            Kdf::Argon2id => "argon2id",
            Kdf::Pbkdf2Sha256 => "pbkdf2-sha256",
        }
    }
    pub fn parse(s: &str) -> Result<Self, StoreError> {
        match s {
            "argon2id" => Ok(Kdf::Argon2id),
            "pbkdf2-sha256" => Ok(Kdf::Pbkdf2Sha256),
            other => Err(StoreError::Format(format!("unknown kdf {other:?}"))),
        }
    }
}

/// Argon2id parameters. Written into the store so a later unlock reproduces the same key even if
/// the defaults move.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    /// 64 MiB, three passes. Enough to cost an attacker real memory per guess while staying under
    /// a second on the machines this runs on, where a person is waiting at a prompt.
    fn default() -> Self {
        KdfParams {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }
}

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const SALT_LEN: usize = 16;

/// Derive the key-encryption key from a passphrase.
pub fn derive_kek(
    kdf: Kdf,
    params: KdfParams,
    passphrase: &Secret,
    salt: &[u8],
) -> Result<Secret, StoreError> {
    let mut out = vec![0u8; KEY_LEN];
    match kdf {
        Kdf::Argon2id => {
            let p = Params::new(
                params.memory_kib,
                params.iterations,
                params.parallelism,
                Some(KEY_LEN),
            )
            .map_err(|e| StoreError::Format(format!("argon2 parameters: {e}")))?;
            Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
                .hash_password_into(passphrase.as_bytes(), salt, &mut out)
                .map_err(|e| StoreError::Crypto(format!("argon2: {e}")))?;
        }
        Kdf::Pbkdf2Sha256 => {
            pbkdf2_sha256(passphrase.as_bytes(), salt, params.iterations, &mut out);
        }
    }
    Ok(Secret::new(out))
}

/// PBKDF2-HMAC-SHA-256 (RFC 8018). Small enough to keep here rather than take another dependency,
/// and only reached by a deployment that asked for it.
fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type H = Hmac<Sha256>;

    let mut block = 1u32;
    for chunk in out.chunks_mut(32) {
        let mut mac = <H as Mac>::new_from_slice(password).expect("hmac takes any key length");
        mac.update(salt);
        mac.update(&block.to_be_bytes());
        let mut u = mac.finalize().into_bytes();
        let mut acc = u;
        for _ in 1..iterations.max(1) {
            let mut mac = <H as Mac>::new_from_slice(password).expect("hmac takes any key length");
            mac.update(&u);
            u = mac.finalize().into_bytes();
            for (a, b) in acc.iter_mut().zip(u.iter()) {
                *a ^= b;
            }
        }
        let n = chunk.len();
        chunk.copy_from_slice(&acc[..n]);
        acc.zeroize();
        block += 1;
    }
}

/// Seal `plaintext` under `key`, binding `aad` to the result.
///
/// The nonce is random and 96 bits. SP 800-38D allows that below 2^32 uses of one key; this store
/// holds on the order of ten secrets, so the bound is not reachable and there is no counter to keep.
pub fn seal(key: &Secret, aad: &[u8], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>), StoreError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let mut nonce = vec![0u8; NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|e| StoreError::Crypto(format!("random: {e}")))?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| StoreError::Crypto("encrypt failed".into()))?;
    Ok((nonce, ct))
}

/// Open what `seal` produced. Fails when `aad` is not the one it was sealed with, which is what
/// stops a ciphertext being moved from one record to another.
pub fn open(key: &Secret, aad: &[u8], nonce: &[u8], ct: &[u8]) -> Result<Secret, StoreError> {
    if nonce.len() != NONCE_LEN {
        return Err(StoreError::Format("nonce is the wrong length".into()));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| StoreError::Locked)?;
    Ok(Secret::new(pt))
}

/// A fresh 256-bit data-encryption key.
pub fn new_dek() -> Result<Secret, StoreError> {
    let mut k = vec![0u8; KEY_LEN];
    getrandom::fill(&mut k).map_err(|e| StoreError::Crypto(format!("random: {e}")))?;
    Ok(Secret::new(k))
}

pub fn new_salt() -> Result<Vec<u8>, StoreError> {
    let mut s = vec![0u8; SALT_LEN];
    getrandom::fill(&mut s).map_err(|e| StoreError::Crypto(format!("random: {e}")))?;
    Ok(s)
}

#[cfg(test)]
pub fn pbkdf2_for_test(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    pbkdf2_sha256(password, salt, iterations, out)
}

/// The key the manifest MAC is taken under: derived from the DEK rather than the DEK itself, so a
/// key is used for one thing only.
pub fn manifest_key(dek: &Secret) -> Secret {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(dek.as_bytes()).expect("hmac takes any key length");
    mac.update(b"sekimore-store/manifest/v1");
    Secret::new(mac.finalize().into_bytes().to_vec())
}

/// HMAC-SHA-256 over the canonical manifest.
pub fn manifest_mac(key: &Secret, manifest: &str) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key.as_bytes()).expect("hmac takes any key length");
    mac.update(manifest.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// Constant time, so a wrong MAC does not leak how much of it was right.
pub fn mac_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

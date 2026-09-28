//! `sgw self-update` (#294): replace this binary with the one of a release.
//!
//! What install.sh does, in the binary: fetch `sgw-<target>.tar.gz` and its `.sha256` from the
//! release, check the digest, take `sgw` out of the archive, and put it where this one runs from.
//! `sgw update --apply` calls it first when a newer release is out, then runs itself again as
//! the new binary, so the operator types one command and the project's pins are raised by the
//! sgw of the release they move to.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};

use crate::i18n::{t, tf};

/// The Releases page; `SGW_RELEASES_URL` points a test at a server of its own.
pub fn releases_url() -> String {
    std::env::var("SGW_RELEASES_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "https://github.com/Amakata/sekimore-gw/releases".to_string())
}

/// The release asset built for this machine: the three install.sh knows.
pub fn target() -> Option<&'static str> {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some("aarch64-apple-darwin")
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some("x86_64-unknown-linux-musl")
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        Some("aarch64-unknown-linux-musl")
    } else {
        None
    }
}

/// `…/download/vX.Y.Z/sgw-<target>.tar.gz`, or `…/latest/download/…` with no version.
pub fn asset_url(base: &str, version: Option<&str>, target: &str) -> String {
    let asset = format!("sgw-{target}.tar.gz");
    match version {
        Some(v) => format!("{base}/download/v{}/{asset}", v.trim_start_matches('v')),
        None => format!("{base}/latest/download/{asset}"),
    }
}

/// The digest install.sh compares: the first word of the published `.sha256` file.
pub fn check_sha256(archive: &[u8], published: &str) -> anyhow::Result<()> {
    use sha2::Digest;
    let want = published
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if want.len() != 64 || !want.bytes().all(|c| c.is_ascii_hexdigit()) {
        bail!("the published .sha256 holds no digest: {published:?}");
    }
    let got = hex::encode(sha2::Sha256::digest(archive));
    if got != want {
        bail!("sha256 mismatch: the release says {want}, the download is {got}");
    }
    Ok(())
}

/// `sgw` out of the `.tar.gz`: the archive holds one file, and a tar member is a 512-byte header
/// (name at 0, size in octal at 124) followed by the data padded to 512.
pub fn extract_sgw(tar_gz: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut tar = Vec::new();
    flate2::read::GzDecoder::new(tar_gz)
        .read_to_end(&mut tar)
        .context("gunzip the release archive")?;
    let mut at = 0usize;
    while at + 512 <= tar.len() {
        let header = &tar[at..at + 512];
        if header.iter().all(|b| *b == 0) {
            break;
        }
        let name = String::from_utf8_lossy(&header[0..100])
            .trim_end_matches('\0')
            .to_string();
        let size_field = String::from_utf8_lossy(&header[124..136]);
        let size = usize::from_str_radix(size_field.trim_matches(|c| c == '\0' || c == ' '), 8)
            .with_context(|| format!("tar: bad size for {name:?}"))?;
        let data_at = at + 512;
        let data_end = data_at + size;
        if data_end > tar.len() {
            bail!("tar: {name:?} runs past the end of the archive");
        }
        let typeflag = header[156];
        let base = name.rsplit('/').next().unwrap_or(&name);
        if base == "sgw" && (typeflag == b'0' || typeflag == 0) {
            return Ok(tar[data_at..data_end].to_vec());
        }
        at = data_at + size.div_ceil(512) * 512;
    }
    bail!("the release archive holds no `sgw`")
}

/// Puts `binary` where this sgw runs from: written beside it and renamed over it, so a failure
/// half-way leaves the old one. A directory this user cannot write names the install script.
pub fn install(binary: &[u8], exe: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = exe.parent().context("the binary has no parent directory")?;
    let tmp = dir.join(format!(".sgw.new.{}", std::process::id()));
    let written = std::fs::write(&tmp, binary)
        .and_then(|_| std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)))
        .and_then(|_| std::fs::rename(&tmp, exe));
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        bail!(tf(
            "sgw.selfupdate.cannot_write",
            &[
                ("path", &exe.display().to_string()),
                ("error", &e.to_string()),
                ("install", super::update::INSTALL),
            ]
        ));
    }
    Ok(())
}

async fn fetch(url: &str) -> anyhow::Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .user_agent(format!("sgw/{}", super::update::VERSION))
        .build()?;
    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;
    if !resp.status().is_success() {
        bail!("GET {url}: HTTP {}", resp.status());
    }
    Ok(resp.bytes().await?.to_vec())
}

/// `sgw self-update [--version X]`: the whole thing, with what happened on stdout.
pub fn run(version: Option<&str>) -> anyhow::Result<i32> {
    let Some(target) = target() else {
        bail!(t("sgw.selfupdate.no_build"));
    };
    let exe = std::env::current_exe().context("where this sgw runs from")?;
    let url = asset_url(&releases_url(), version, target);
    println!("{}", tf("sgw.selfupdate.fetching", &[("url", &url)]));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (archive, published) = rt.block_on(async {
        let a = fetch(&url).await?;
        let s = fetch(&format!("{url}.sha256")).await?;
        anyhow::Ok((a, String::from_utf8_lossy(&s).into_owned()))
    })?;
    check_sha256(&archive, &published)?;
    let binary = extract_sgw(&archive)?;
    install(&binary, &exe)?;
    let new_version = std::process::Command::new(&exe)
        .arg("--version")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    println!(
        "{}",
        tf(
            "sgw.selfupdate.done",
            &[
                ("old", super::update::VERSION),
                ("new", &new_version),
                ("path", &exe.display().to_string())
            ]
        )
    );
    Ok(0)
}

/// Runs this command line again as the binary now at `exe`, in place of this process.
/// `SGW_SELF_UPDATED` marks the second run, so it never updates again.
pub fn reexec(exe: &Path) -> anyhow::Error {
    use std::os::unix::process::CommandExt;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let e = std::process::Command::new(exe)
        .args(&args)
        .env("SGW_SELF_UPDATED", "1")
        .exec();
    anyhow::anyhow!("could not run the new sgw at {}: {e}", exe.display())
}

/// Whether this process is already the re-run after a self-update.
pub fn already_updated() -> bool {
    std::env::var_os("SGW_SELF_UPDATED").is_some()
}

pub fn current_exe() -> anyhow::Result<PathBuf> {
    std::env::current_exe().context("where this sgw runs from")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-member tar.gz the way the release workflow writes it (`tar czf … sgw`).
    pub fn archive_with(name: &str, body: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut header = vec![0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..107].copy_from_slice(b"0000755");
        header[124..135].copy_from_slice(format!("{:011o}", body.len()).as_bytes());
        header[156] = b'0';
        // the checksum field is spaces while summing
        header[148..156].copy_from_slice(b"        ");
        let sum: u32 = header.iter().map(|b| *b as u32).sum();
        header[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        let mut tar = header;
        tar.extend_from_slice(body);
        tar.resize(512 + body.len().div_ceil(512) * 512, 0);
        tar.extend_from_slice(&[0u8; 1024]);
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar).unwrap();
        gz.finish().unwrap()
    }

    #[test]
    fn the_asset_url_is_the_one_install_sh_takes() {
        let base = "https://github.com/Amakata/sekimore-gw/releases";
        assert_eq!(
            asset_url(base, None, "aarch64-apple-darwin"),
            format!("{base}/latest/download/sgw-aarch64-apple-darwin.tar.gz")
        );
        assert_eq!(
            asset_url(base, Some("v0.2.56"), "x86_64-unknown-linux-musl"),
            format!("{base}/download/v0.2.56/sgw-x86_64-unknown-linux-musl.tar.gz")
        );
        assert_eq!(
            asset_url(base, Some("0.2.56"), "x86_64-unknown-linux-musl"),
            format!("{base}/download/v0.2.56/sgw-x86_64-unknown-linux-musl.tar.gz")
        );
    }

    #[test]
    fn the_digest_is_the_first_word_and_a_wrong_one_is_refused() {
        use sha2::Digest;
        let archive = b"hello";
        let sum = hex::encode(sha2::Sha256::digest(archive));
        check_sha256(archive, &format!("{sum}  sgw-x.tar.gz\n")).unwrap();
        check_sha256(archive, &sum.to_uppercase()).unwrap();
        let wrong = format!("{}  sgw-x.tar.gz", "0".repeat(64));
        assert!(check_sha256(archive, &wrong)
            .unwrap_err()
            .to_string()
            .contains("mismatch"));
        assert!(check_sha256(archive, "not a digest").is_err());
    }

    #[test]
    fn sgw_is_taken_out_of_the_archive_and_nothing_else_will_do() {
        let body = b"#!/bin/sh\necho fake\n";
        assert_eq!(extract_sgw(&archive_with("sgw", body)).unwrap(), body);
        assert_eq!(extract_sgw(&archive_with("./sgw", body)).unwrap(), body);
        let err = extract_sgw(&archive_with("README", body)).unwrap_err();
        assert!(err.to_string().contains("holds no `sgw`"), "{err}");
        assert!(extract_sgw(b"not gzip at all").is_err());
    }

    #[test]
    fn install_writes_beside_and_renames_over() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("sgw");
        std::fs::write(&exe, b"old").unwrap();
        install(b"new", &exe).unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"new");
        assert_eq!(
            std::fs::metadata(&exe).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert!(
            std::fs::read_dir(dir.path()).unwrap().count() == 1,
            "no .sgw.new left behind"
        );
        // a directory this user cannot write: the old binary stays, the script is named
        if unsafe { libc::geteuid() } != 0 {
            let ro = dir.path().join("ro");
            std::fs::create_dir(&ro).unwrap();
            let target = ro.join("sgw");
            std::fs::write(&target, b"old").unwrap();
            std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o555)).unwrap();
            let err = install(b"new", &target).unwrap_err().to_string();
            std::fs::set_permissions(&ro, std::fs::Permissions::from_mode(0o755)).unwrap();
            assert!(err.contains("install.sh"), "{err}");
            assert_eq!(std::fs::read(&target).unwrap(), b"old");
        }
    }
}

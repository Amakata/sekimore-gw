//! Step 10: the proxy environment (#212). The gateway says at `GET /api/proxy-env` whether an
//! upstream proxy is configured; `/etc/profile.d/sekimore-proxy.sh` and a marked block in
//! `/etc/environment` follow, and both go when the answer is no.

use std::path::Path;
use std::time::Duration;

use serde::Deserialize;

use super::files::{ensure_dir, read_or_empty, write_atomic, MarkedBlock};

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
pub struct ProxyEnv {
    pub configured: bool,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub no_proxy: Vec<String>,
    #[serde(default)]
    pub direct_egress: String,
}

pub const MARK: MarkedBlock = MarkedBlock {
    begin: "# sekimore-proxy begin",
    end: "# sekimore-proxy end",
};

/// Asks the gateway, retrying for about ten seconds: postStart can run before the Web UI listens.
pub async fn fetch(gw: &str, port: u16) -> Option<ProxyEnv> {
    let http = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .ok()?;
    for i in 0..5 {
        if i > 0 {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        if let Ok(r) = http
            .get(format!("http://{gw}:{port}/api/proxy-env"))
            .send()
            .await
        {
            if r.status().is_success() {
                if let Ok(v) = r.json::<ProxyEnv>().await {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Writes or removes both files under `root` (`/` in a container; a temp dir in tests).
pub fn apply(env: &ProxyEnv, gw: &str, root: &Path) -> anyhow::Result<()> {
    let profile = root.join("etc/profile.d/sekimore-proxy.sh");
    let envfile = root.join("etc/environment");
    if !env.configured {
        let _ = std::fs::remove_file(&profile);
        if envfile.is_file() {
            write_atomic(&envfile, &MARK.remove(&read_or_empty(&envfile)), 0o644)?;
        }
        println!("[agent] proxy: no upstream proxy configured; HTTP_PROXY not set");
        return Ok(());
    }
    let port = if env.port == 0 { 3128 } else { env.port };
    let url = format!("http://{gw}:{port}");
    let no_proxy = env.no_proxy.join(",");
    ensure_dir(profile.parent().unwrap(), 0o755)?;
    let body = format!(
        "# Written by sgw-agent setup. Edits are lost on the next container start;\n\
         # change proxy.upstream_proxy / proxy.no_proxy in the gateway's config.yml instead.\n\
         export HTTP_PROXY=\"{url}\"\nexport HTTPS_PROXY=\"{url}\"\nexport http_proxy=\"{url}\"\nexport https_proxy=\"{url}\"\n\
         export NO_PROXY=\"{no_proxy}\"\nexport no_proxy=\"{no_proxy}\"\n"
    );
    write_atomic(&profile, &MARK.replace("", &body), 0o644)?;
    // /etc/environment is read by PAM and by anything that is not a login shell: the same six
    // assignments, without `export` (it is not a script). Replaced, never appended twice.
    ensure_dir(envfile.parent().unwrap(), 0o755)?;
    let block = format!(
        "HTTP_PROXY=\"{url}\"\nHTTPS_PROXY=\"{url}\"\nhttp_proxy=\"{url}\"\nhttps_proxy=\"{url}\"\nNO_PROXY=\"{no_proxy}\"\nno_proxy=\"{no_proxy}\"\n"
    );
    write_atomic(
        &envfile,
        &MARK.replace(&read_or_empty(&envfile), &block),
        0o644,
    )?;
    let egress = if env.direct_egress.is_empty() {
        "allow"
    } else {
        &env.direct_egress
    };
    println!("[agent] proxy: HTTP_PROXY={url}, NO_PROXY={no_proxy} (direct_egress: {egress})");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn configured() -> ProxyEnv {
        ProxyEnv {
            configured: true,
            port: 3128,
            no_proxy: vec!["api.github.com".into(), "localhost".into()],
            direct_egress: "deny".into(),
        }
    }

    #[test]
    fn both_files_are_written_replaced_and_removed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        std::fs::create_dir_all(root.join("etc")).unwrap();
        std::fs::write(root.join("etc/environment"), "PATH=/usr/bin\n").unwrap();
        apply(&configured(), "10.100.0.2", root).unwrap();
        let profile =
            std::fs::read_to_string(root.join("etc/profile.d/sekimore-proxy.sh")).unwrap();
        assert!(
            profile.contains("export HTTP_PROXY=\"http://10.100.0.2:3128\""),
            "{profile}"
        );
        assert!(
            profile.contains("export NO_PROXY=\"api.github.com,localhost\""),
            "{profile}"
        );
        let env = std::fs::read_to_string(root.join("etc/environment")).unwrap();
        assert!(
            env.starts_with("PATH=/usr/bin\n# sekimore-proxy begin\n"),
            "{env}"
        );
        assert_eq!(env.matches("HTTP_PROXY=").count(), 1);
        // a second start with another gateway address replaces, never appends
        apply(&configured(), "10.100.0.9", root).unwrap();
        let env = std::fs::read_to_string(root.join("etc/environment")).unwrap();
        assert_eq!(env.matches("# sekimore-proxy begin").count(), 1, "{env}");
        assert!(
            env.contains("10.100.0.9") && !env.contains("10.100.0.2"),
            "{env}"
        );
        assert!(env.starts_with("PATH=/usr/bin\n"));
        // and no proxy any more: both go, the rest of /etc/environment stays
        apply(&ProxyEnv::default(), "10.100.0.9", root).unwrap();
        assert!(!root.join("etc/profile.d/sekimore-proxy.sh").exists());
        assert_eq!(
            std::fs::read_to_string(root.join("etc/environment")).unwrap(),
            "PATH=/usr/bin\n"
        );
    }
}

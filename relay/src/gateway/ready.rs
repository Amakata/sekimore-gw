//! `sekimore-relay ready`: exits 0 when the Web UI answers `GET /api/config` on
//! `127.0.0.1:8080` within three seconds with a 2xx, 1 otherwise.
//!
//! What `sgw recreate` waits on. It used to run `python -c "urllib.request.urlopen(…)"` in the
//! gateway, which has no curl; the gateway is losing Python (0.3.0 plan, "α5"), and the relay's
//! binary is in every gateway image. The probe is the same request with the same timeout, and the
//! same answer counts as ready (urllib raised for anything but 2xx, after following redirects).

use std::time::Duration;

/// The address `sgw` has always probed.
pub const URL: &str = "http://127.0.0.1:8080/api/config";

pub async fn run() -> anyhow::Result<i32> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .no_proxy()
        .build()?;
    Ok(match client.get(URL).send().await {
        Ok(r) if r.status().is_success() => 0,
        _ => 1,
    })
}

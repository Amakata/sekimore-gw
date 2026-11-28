//! `sekimore-relay gateway`: the gateway's own process, apart from `serve` (0.3.0 plan, "α5").
//!
//! In this step it holds the two log followers that were tasks of the Python orchestrator
//! (`src/firewall_monitor.py`, `src/proxy_monitor.py`); the core — DNS, the firewall, Squid's
//! management, start-up and reload — joins it in the next step and the orchestrator goes. It is a
//! process of its own, never part of `serve`: the relay and the Web UI can fail without taking the
//! gateway's own work with them (S8), and the other way round.
//!
//! `entrypoint.sh` starts it in the background, beside the orchestrator, through
//! `scripts/start-gateway.sh`, which starts it again if it exits. The followers read what
//! the orchestrator read: `database_path` and `proxy.enabled` from `config.yml`, once, at the
//! start (a reload never changed them), with the same reading (`crate::settings`). The proxy
//! follower runs only when the proxy is enabled, as before.
//!
//! Also here, for the operator: `maint` (`src/maint.py`: the reload window and the log database)
//! and `ready` (does the Web UI answer; what `sgw` waits on after a recreate).

#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

pub mod firewall_log;
pub mod logdb;
pub mod maint;
pub mod proxy_log;
pub mod pyfmt;
pub mod pytext;
pub mod ready;
pub mod reload_window;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// `time.time()`.
pub fn now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Runs the gateway's process until it is told to stop (SIGTERM / SIGINT).
pub async fn run(config: &Path) -> anyhow::Result<i32> {
    let settings = crate::settings::load(config)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", config.display()))?;
    let db = PathBuf::from(&settings.database_path);
    let stop = Arc::new(AtomicBool::new(false));

    let mut threads = Vec::new();
    threads.push(spawn("firewall-log", {
        let (db, stop) = (db.clone(), stop.clone());
        move || {
            let mut conn = match logdb::open(&db).and_then(|c| {
                logdb::init_firewall(&c)?;
                Ok(c)
            }) {
                Ok(c) => c,
                Err(e) => {
                    // Python: init_db raised and the monitor's task ended with it
                    log::error!("Firewall monitor: cannot open {}: {e}", db.display());
                    return;
                }
            };
            log::info!(
                "Firewall monitor database initialized db_path={}",
                db.display()
            );
            firewall_log::follow(&mut conn, &firewall_log::ulog_path(), &|| {
                stop.load(Ordering::SeqCst)
            });
        }
    })?);
    if settings.proxy.enabled {
        threads.push(spawn("proxy-log", {
            let (db, stop) = (db.clone(), stop.clone());
            move || {
                let mut conn = match logdb::open(&db).and_then(|mut c| {
                    if let Some(n) = logdb::init_proxy(&mut c)? {
                        log::info!("Migrated proxy_blocks to proxy_logs count={n}");
                    }
                    Ok(c)
                }) {
                    Ok(c) => c,
                    Err(e) => {
                        log::error!("Proxy monitor: cannot open {}: {e}", db.display());
                        return;
                    }
                };
                log::info!(
                    "Proxy monitor database initialized db_path={}",
                    db.display()
                );
                proxy_log::follow(&mut conn, Path::new(proxy_log::ACCESS_LOG), &|| {
                    stop.load(Ordering::SeqCst)
                });
            }
        })?);
    }
    log::info!(
        "gateway {} running: firewall log{}",
        env!("CARGO_PKG_VERSION"),
        if settings.proxy.enabled {
            ", proxy log"
        } else {
            ""
        }
    );

    wait_for_signal().await;
    stop.store(true, Ordering::SeqCst);
    // The followers block in reads; they are not waited for. The process ends here, and the
    // database is left as every committed row left it.
    drop(threads);
    Ok(0)
}

fn spawn(
    name: &str,
    f: impl FnOnce() + Send + 'static,
) -> anyhow::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name(name.into())
        .spawn(f)
        .map_err(|e| anyhow::anyhow!("cannot start the {name} thread: {e}"))
}

async fn wait_for_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    match signal(SignalKind::terminate()) {
        Ok(mut term) => {
            tokio::select! {
                _ = term.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
        }
        Err(_) => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

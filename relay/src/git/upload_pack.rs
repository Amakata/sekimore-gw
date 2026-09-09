//! `git-upload-pack`（clone / fetch / pull）: 双方向の素通し。解釈しない。

use tokio::io::AsyncWriteExt;

use super::{copy_touch, exit_code_of, GitContext, GitIo, RelayOutcome, UpstreamProcess, Watchdog};

pub async fn relay_upload_pack(
    io: &mut GitIo<'_>,
    mut proc: UpstreamProcess,
    ctx: &GitContext,
) -> RelayOutcome {
    let wd = Watchdog::new(ctx.limits.idle_timeout);
    wd.touch();
    let stderr_task = proc.stderr.take().map(|mut es| {
        let w = wd.clone();
        // 上流の stderr は素通し（relay 自身の行は "sekimore: " 接頭辞で区別できる）
        async move {
            let mut sink = Vec::new();
            let r = copy_touch(&mut es, &mut sink, &w, false).await;
            (sink, r)
        }
    });

    let in_fut = copy_touch(&mut io.stdin, &mut proc.stdin, &wd, true);
    let out_fut = copy_touch(&mut proc.stdout, &mut io.stdout, &wd, false);
    let (bytes_in, bytes_out, note) = tokio::select! {
        r = async { tokio::join!(in_fut, out_fut) } => {
            let (i, o) = r;
            (i.unwrap_or(0), o.unwrap_or(0), None)
        }
        _ = wd.expired() => {
            let _ = proc.child.start_kill();
            (0, 0, Some("idle_timeout".to_string()))
        }
    };
    let status = match proc.child.wait().await {
        Ok(s) => exit_code_of(s),
        Err(_) => 1,
    };
    if let Some(t) = stderr_task {
        let (sink, _) = t.await;
        if !sink.is_empty() {
            let _ = io.stderr.write_all(&sink).await;
        }
    }
    if status == 255 {
        let _ = io
            .stderr
            .write_all(b"sekimore: upstream ssh connection failed (see the ssh error above)\n")
            .await;
    }
    let _ = io.stderr.flush().await;
    RelayOutcome {
        status: if status == 255 { 1 } else { status },
        bytes_in,
        bytes_out,
        note,
    }
}

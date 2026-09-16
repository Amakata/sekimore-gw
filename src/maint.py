"""運用コマンド: ログ DB（SQLite）の状態確認・削除・リセット（0.2.3）.

記録は既定で削除しない（永続化）。増えても遅くならないように索引と WAL を使う。
掃除やリセットは操作者がこのコマンドを明示的に打ったときだけ行う。稼働中の gateway に対して実行してよい
（WAL なので書き込みと衝突しない。削除後も DNS / firewall / proxy の記録はそのまま続く）。

    python -m src.maint db-stats [--json]
    python -m src.maint db-prune --before-days 90 --yes [--vacuum]
    python -m src.maint db-reset --yes
    python -m src.maint db-vacuum

Dev Containers 構成では mise の gw:db-stats / gw:db-prune / gw:db-reset から呼ぶ。
relay の監査（/data/relay/audit.jsonl）は別ファイルなので、ここでは触らない。
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import i18n

# ログを溜めるテーブル（記録系）。cache_stats は DNS キャッシュの統計で、reset のときだけ空にする
LOG_TABLES = ("dns_queries", "firewall_blocks", "proxy_logs")
RESET_ONLY_TABLES = ("cache_stats",)


def default_db_path(config_path: str = "/etc/sekimore/config.yml") -> str:
    """config.yml の database_path（無ければ /data/security_gateway.db）."""
    try:
        import yaml  # 実行時にだけ要る

        with open(config_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        value = data.get("database_path") if isinstance(data, dict) else None
        if isinstance(value, str) and value:
            return value
    except Exception:
        pass
    return "/data/security_gateway.db"


def _connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=30)
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def _existing_tables(conn: sqlite3.Connection, names: tuple[str, ...]) -> list[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    have = {r[0] for r in rows}
    return [n for n in names if n in have]


def _fmt_ts(ts: float | None) -> str:
    if ts is None:
        return "-"
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GiB"


def stats(db_path: str) -> dict[str, Any]:
    """件数・期間・ファイルサイズ・journal_mode・索引."""
    out: dict[str, Any] = {"db_path": db_path, "exists": os.path.exists(db_path), "tables": {}}
    if not out["exists"]:
        return out
    size = os.path.getsize(db_path)
    wal = Path(db_path + "-wal")
    out["size_bytes"] = size
    out["wal_bytes"] = wal.stat().st_size if wal.exists() else 0
    conn = _connect(db_path)
    try:
        out["journal_mode"] = conn.execute("PRAGMA journal_mode").fetchone()[0]
        out["page_size"] = conn.execute("PRAGMA page_size").fetchone()[0]
        out["freelist_pages"] = conn.execute("PRAGMA freelist_count").fetchone()[0]
        for table in _existing_tables(conn, LOG_TABLES + RESET_ONLY_TABLES):
            count = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            info: dict[str, Any] = {"rows": count}
            if table in LOG_TABLES:
                row = conn.execute(f"SELECT MIN(timestamp), MAX(timestamp) FROM {table}").fetchone()
                info["oldest"] = row[0]
                info["newest"] = row[1]
                idx = conn.execute(f"PRAGMA index_list({table})").fetchall()
                info["indexes"] = sorted(r[1] for r in idx)
            out["tables"][table] = info
    finally:
        conn.close()
    return out


def prune(db_path: str, before_days: float, vacuum: bool = False) -> dict[str, int]:
    """before_days 日より古い記録を LOG_TABLES から削除する（明示操作）."""
    if before_days <= 0:
        raise ValueError("--before-days must be positive")
    cutoff = time.time() - before_days * 86400
    deleted: dict[str, int] = {}
    conn = _connect(db_path)
    try:
        for table in _existing_tables(conn, LOG_TABLES):
            cur = conn.execute(f"DELETE FROM {table} WHERE timestamp < ?", (cutoff,))
            deleted[table] = cur.rowcount
        conn.commit()
        if vacuum:
            conn.execute("VACUUM")
    finally:
        conn.close()
    return deleted


def reset(db_path: str) -> dict[str, int]:
    """記録を全て消して VACUUM する（明示操作）。テーブルと索引は残るので gateway は動き続ける."""
    deleted: dict[str, int] = {}
    conn = _connect(db_path)
    try:
        for table in _existing_tables(conn, LOG_TABLES + RESET_ONLY_TABLES):
            cur = conn.execute(f"DELETE FROM {table}")
            deleted[table] = cur.rowcount
        conn.commit()
        conn.execute("VACUUM")
    finally:
        conn.close()
    return deleted


def vacuum(db_path: str) -> tuple[int, int]:
    """VACUUM してファイルサイズの前後を返す."""
    before = os.path.getsize(db_path)
    conn = _connect(db_path)
    try:
        conn.execute("VACUUM")
    finally:
        conn.close()
    return before, os.path.getsize(db_path)


def _print_stats(s: dict[str, Any], lang: str) -> None:
    def tr(key: str, **vars: Any) -> str:
        return i18n.t(key, lang, **vars)

    print(f"{tr('maint.stats.db'):<15}{s['db_path']}")
    if not s.get("exists"):
        print(f"{'':<15}{tr('maint.stats.not_found')}")
        return
    print(
        f"{tr('maint.stats.size'):<15}{_fmt_bytes(s['size_bytes'])} (+ wal {_fmt_bytes(s['wal_bytes'])})"
    )
    print(
        f"{tr('maint.stats.journal'):<15}{s['journal_mode']}   {tr('maint.stats.free_pages')} {s['freelist_pages']} x {s['page_size']} B"
    )
    print(tr("maint.stats.tables"))
    for table, info in s["tables"].items():
        line = f"  {table:<18} {info['rows']:>10} {tr('maint.stats.rows')}"
        if "oldest" in info:
            line += f"   {_fmt_ts(info['oldest'])} .. {_fmt_ts(info['newest'])}"
            line += f"   {tr('maint.stats.indexes')} {', '.join(info['indexes']) or '-'}"
        print(line)


def main(argv: list[str] | None = None, lang: str | None = None) -> int:
    lang = lang or i18n.env_lang()

    def tr(key: str, **vars: Any) -> str:
        return i18n.t(key, lang, **vars)

    parser = argparse.ArgumentParser(
        prog="python -m src.maint", description=tr("maint.description")
    )
    parser.add_argument("--db", default=None, help=tr("maint.db"))
    parser.add_argument("--config", default="/etc/sekimore/config.yml", help=tr("maint.config"))
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_stats = sub.add_parser("db-stats", help=tr("maint.stats"))
    p_stats.add_argument("--json", action="store_true", help=tr("maint.json"))
    p_prune = sub.add_parser("db-prune", help=tr("maint.prune"))
    p_prune.add_argument("--before-days", type=float, required=True, help=tr("maint.before_days"))
    p_prune.add_argument("--vacuum", action="store_true", help=tr("maint.vacuum_opt"))
    p_prune.add_argument("--yes", action="store_true", help=tr("maint.yes"))
    p_reset = sub.add_parser("db-reset", help=tr("maint.reset"))
    p_reset.add_argument("--yes", action="store_true", help=tr("maint.yes"))
    sub.add_parser("db-vacuum", help=tr("maint.vacuum"))
    args = parser.parse_args(argv)

    db_path = args.db or default_db_path(args.config)
    if args.cmd == "db-stats":
        s = stats(db_path)
        if args.json:
            print(json.dumps(s, ensure_ascii=False, indent=2))
        else:
            _print_stats(s, lang)
        return 0
    if not os.path.exists(db_path):
        print(tr("maint.not_found", db=db_path), file=sys.stderr)
        return 1
    if args.cmd in ("db-prune", "db-reset") and not args.yes:
        what = (
            tr("maint.confirm_prune_what", days=f"{args.before_days:g}")
            if args.cmd == "db-prune"
            else tr("maint.confirm_reset_what")
        )
        print(tr("maint.confirm", what=what, db=db_path))
        print(tr("maint.rerun"))
        return 2
    if args.cmd == "db-prune":
        deleted = prune(db_path, args.before_days, vacuum=args.vacuum)
        for table, n in deleted.items():
            print(tr("maint.deleted", table=f"{table:<18}", n=n))
        print(tr("maint.vacuumed") if args.vacuum else tr("maint.not_vacuumed"))
        return 0
    if args.cmd == "db-reset":
        deleted = reset(db_path)
        for table, n in deleted.items():
            print(tr("maint.deleted", table=f"{table:<18}", n=n))
        print(tr("maint.reset_done", db=db_path, size=_fmt_bytes(os.path.getsize(db_path))))
        return 0
    if args.cmd == "db-vacuum":
        before, after = vacuum(db_path)
        print(tr("maint.vacuum_result", before=_fmt_bytes(before), after=_fmt_bytes(after)))
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())

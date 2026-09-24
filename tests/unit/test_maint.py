"""The src.maint operations command (inspect, prune, and reset the DB).

Every `maint.main` call here pins `lang="en"`. Its output has been localized since 0.2.4, and
without a language the CLI takes one from the environment (`SEKIMORE_LANG`, then `LC_ALL`,
`LC_MESSAGES`, `LANG`), so assertions on English prose passed only where none of those said
otherwise — CI, but not a dev container that sets `SEKIMORE_LANG=ja` (#160).
"""

import sqlite3
import time

from src import maint


def _make_db(path, rows_per_table=5, age_days=0.0):
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE dns_queries (timestamp REAL, client_ip TEXT, query_domain TEXT, response_ips TEXT, ttl INTEGER, query_type TEXT, status TEXT)"
    )
    conn.execute("CREATE INDEX idx_dns_timestamp ON dns_queries(timestamp)")
    conn.execute(
        "CREATE TABLE firewall_blocks (timestamp REAL, src_ip TEXT, dst_ip TEXT, dst_port INTEGER, protocol TEXT, action TEXT)"
    )
    conn.execute(
        "CREATE TABLE proxy_logs (timestamp REAL, client_ip TEXT, method TEXT, url TEXT, status_code INTEGER, squid_result TEXT, action TEXT)"
    )
    conn.execute("CREATE TABLE cache_stats (hits INTEGER, misses INTEGER)")
    base = time.time() - age_days * 86400
    for i in range(rows_per_table):
        conn.execute(
            "INSERT INTO dns_queries VALUES (?, '10.0.0.2', 'example.com', '1.2.3.4', 60, 'A', 'allowed')",
            (base + i,),
        )
        conn.execute(
            "INSERT INTO firewall_blocks VALUES (?, '10.0.0.2', '9.9.9.9', 22, 'TCP', 'blocked')",
            (base + i,),
        )
        conn.execute(
            "INSERT INTO proxy_logs VALUES (?, '10.0.0.2', 'GET', 'https://x/', 200, 'TCP_MISS', 'allowed')",
            (base + i,),
        )
    conn.execute("INSERT INTO cache_stats VALUES (1, 2)")
    conn.commit()
    conn.close()


def describe_db_stats():
    def it_reports_rows_range_indexes_and_size(tmp_path):
        db = tmp_path / "gw.db"
        _make_db(str(db), rows_per_table=3)
        s = maint.stats(str(db))
        assert s["exists"] is True and s["size_bytes"] > 0
        assert s["tables"]["dns_queries"]["rows"] == 3
        assert "idx_dns_timestamp" in s["tables"]["dns_queries"]["indexes"]
        assert s["tables"]["dns_queries"]["oldest"] <= s["tables"]["dns_queries"]["newest"]
        assert s["tables"]["cache_stats"] == {"rows": 1}
        assert s["journal_mode"] in ("delete", "wal")

    def it_handles_a_missing_file(tmp_path):
        s = maint.stats(str(tmp_path / "none.db"))
        assert s["exists"] is False and s["tables"] == {}

    def it_prints_and_returns_zero(tmp_path, capsys):
        db = tmp_path / "gw.db"
        _make_db(str(db), rows_per_table=2)
        assert maint.main(["--db", str(db), "db-stats"], lang="en") == 0
        out = capsys.readouterr().out
        assert "dns_queries" in out and "2 rows" in out
        assert maint.main(["--db", str(db), "db-stats", "--json"], lang="en") == 0
        assert '"rows": 2' in capsys.readouterr().out


def describe_db_prune_and_reset():
    def it_prunes_only_old_records_and_keeps_tables(tmp_path):
        db = tmp_path / "gw.db"
        _make_db(str(db), rows_per_table=4, age_days=100)
        conn = sqlite3.connect(str(db))
        conn.execute(
            "INSERT INTO dns_queries VALUES (?, '10.0.0.3', 'new.example', '', 60, 'A', 'allowed')",
            (time.time(),),
        )
        conn.commit()
        conn.close()
        deleted = maint.prune(str(db), before_days=30, vacuum=True)
        assert deleted == {"dns_queries": 4, "firewall_blocks": 4, "proxy_logs": 4}
        s = maint.stats(str(db))
        assert s["tables"]["dns_queries"]["rows"] == 1  # The one recent row survives
        assert s["tables"]["cache_stats"]["rows"] == 1  # prune leaves cache_stats alone

    def it_requires_yes_for_destructive_commands(tmp_path, capsys):
        db = tmp_path / "gw.db"
        _make_db(str(db), rows_per_table=1)
        assert maint.main(["--db", str(db), "db-prune", "--before-days", "1"], lang="en") == 2
        assert "--yes" in capsys.readouterr().out
        assert maint.main(["--db", str(db), "db-reset"], lang="en") == 2
        assert maint.stats(str(db))["tables"]["dns_queries"]["rows"] == 1  # Nothing was deleted

    def it_resets_everything_and_vacuums(tmp_path, capsys):
        db = tmp_path / "gw.db"
        _make_db(str(db), rows_per_table=50)
        assert maint.main(["--db", str(db), "db-reset", "--yes"], lang="en") == 0
        out = capsys.readouterr().out
        assert "dns_queries" in out and "deleted 50 rows" in out and "vacuumed" in out
        s = maint.stats(str(db))
        assert all(info["rows"] == 0 for info in s["tables"].values())
        # Tables and indexes survive, so the gateway keeps running
        assert "idx_dns_timestamp" in s["tables"]["dns_queries"]["indexes"]

    def it_fails_cleanly_when_the_db_is_missing(tmp_path):
        assert maint.main(["--db", str(tmp_path / "none.db"), "db-reset", "--yes"], lang="en") == 1

    def it_reads_the_db_path_from_config(tmp_path):
        cfg = tmp_path / "config.yml"
        cfg.write_text("database_path: /tmp/x/gw.db\n")
        assert maint.default_db_path(str(cfg)) == "/tmp/x/gw.db"
        assert maint.default_db_path(str(tmp_path / "missing.yml")) == "/data/security_gateway.db"

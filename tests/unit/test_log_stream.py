"""The Web UI log streaming poller (0.2.3): snapshot, new rows via the rowid cursor, batched delivery, and stopping with no clients."""

import asyncio
import time

import aiosqlite
import pytest

from src.web_ui.log_stream import LogStreamer, parse_client_message


async def _make_db(path):
    async with aiosqlite.connect(path) as db:
        await db.execute(
            "CREATE TABLE dns_queries (timestamp REAL, client_ip TEXT, query_domain TEXT, response_ips TEXT, status TEXT)"
        )
        await db.execute(
            "CREATE TABLE firewall_blocks (timestamp REAL, src_ip TEXT, dst_ip TEXT, dst_port INTEGER, protocol TEXT)"
        )
        await db.execute(
            "CREATE TABLE proxy_logs (timestamp REAL, client_ip TEXT, method TEXT, url TEXT, status_code INTEGER, squid_result TEXT, action TEXT)"
        )
        now = time.time()
        await db.execute(
            "INSERT INTO dns_queries VALUES (?, '10.0.0.2', 'example.com', '1.2.3.4', 'allowed')",
            (now - 30,),
        )
        await db.execute(
            "INSERT INTO dns_queries VALUES (?, '10.0.0.2', 'telemetry.example', '', 'ignored')",
            (now - 20,),
        )
        await db.execute(
            "INSERT INTO firewall_blocks VALUES (?, '10.0.0.2', '9.9.9.9', 22, 'TCP')", (now - 10,)
        )
        await db.execute(
            "INSERT INTO proxy_logs VALUES (?, '10.0.0.2', 'GET', 'https://x/', 200, 'TCP_MISS', 'allowed')",
            (now - 5,),
        )
        await db.commit()


def describe_log_streamer():
    @pytest.mark.asyncio
    async def it_builds_a_sorted_snapshot_without_ignored_dns(tmp_path):
        db = str(tmp_path / "gw.db")
        await _make_db(db)
        s = LogStreamer(db, broadcast=None, has_clients=lambda: False)
        snap = await s.snapshot(limit=50)
        assert snap["type"] == "snapshot"
        comps = [e["component"] for e in snap["entries"]]
        assert comps == ["DNS", "FIREWALL", "PROXY"]  # Ascending; ignored is excluded
        fw = snap["entries"][1]
        assert fw["action"] == "BLOCKED" and fw["dst_port"] == 22 and "TCP" in fw["reason"]
        assert snap["entries"][2]["reason"] == "GET via proxy (TCP_MISS)"

    @pytest.mark.asyncio
    async def it_streams_only_new_rows_as_one_batch(tmp_path):
        db = str(tmp_path / "gw.db")
        await _make_db(db)
        sent = []

        async def broadcast(msg):
            sent.append(msg)

        clients = {"n": 1}
        s = LogStreamer(db, broadcast=broadcast, has_clients=lambda: clients["n"] > 0)
        s.poll_interval = 0.05
        s.start()
        await asyncio.sleep(0.15)
        assert sent == []  # Rows older than startup are not streamed (the snapshot covers those)
        async with aiosqlite.connect(db) as w:
            now = time.time()
            await w.execute(
                "INSERT INTO dns_queries VALUES (?, '10.0.0.5', 'new.example', '5.6.7.8', 'blocked')",
                (now,),
            )
            await w.execute(
                "INSERT INTO firewall_blocks VALUES (?, '10.0.0.5', '8.8.8.8', 53, 'UDP')",
                (now + 0.001,),
            )
            await w.execute(
                "INSERT INTO dns_queries VALUES (?, '10.0.0.5', 'skip.example', '', 'ignored')",
                (now + 0.002,),
            )
            await w.commit()
        await asyncio.sleep(0.3)
        assert len(sent) == 1, sent  # New rows within one poll cycle arrive as a single message
        msg = sent[0]
        assert msg["type"] == "logs"
        assert [(e["component"], e["action"]) for e in msg["entries"]] == [
            ("DNS", "BLOCKED"),
            ("FIREWALL", "BLOCKED"),
        ]
        assert (
            msg["entries"][0]["domain"] == "new.example"
            and msg["entries"][0]["dst_ip"] == "5.6.7.8"
        )
        # The poller stops once the last client goes away
        clients["n"] = 0
        await asyncio.sleep(0.2)
        assert not s.running
        await s.stop()

    @pytest.mark.asyncio
    async def it_survives_missing_tables(tmp_path):
        db = str(tmp_path / "gw.db")
        async with aiosqlite.connect(db) as w:
            await w.execute(
                "CREATE TABLE dns_queries (timestamp REAL, client_ip TEXT, query_domain TEXT, response_ips TEXT, status TEXT)"
            )
            await w.commit()
        s = LogStreamer(db, broadcast=None, has_clients=lambda: False)
        snap = await s.snapshot()
        assert snap["entries"] == []
        async with aiosqlite.connect(db) as r:
            assert await s.poll_once(r) == []

    def it_parses_client_messages():
        assert parse_client_message('{"type": "resync"}') == "resync"
        assert parse_client_message("not json") is None
        assert parse_client_message('{"type": 1}') is None
        assert parse_client_message("[]") is None

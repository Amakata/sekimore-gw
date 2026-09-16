"""WebSocket エンドポイントの統合テスト（0.2.3 の配信形式: snapshot / logs の配列）.

websocket_endpoint を偽の WebSocket で直接動かす。receive_text はキューで待たせ、切断は WebSocketDisconnect で伝える。
"""

import asyncio
import contextlib
import time

import aiosqlite
import pytest
from fastapi import WebSocketDisconnect


async def _create_db(db_path):
    async with aiosqlite.connect(str(db_path)) as db:
        await db.execute(
            "CREATE TABLE dns_queries (timestamp REAL, client_ip TEXT, query_domain TEXT, response_ips TEXT, status TEXT)"
        )
        await db.execute(
            "CREATE TABLE firewall_blocks (timestamp REAL, src_ip TEXT, dst_ip TEXT, dst_port INTEGER, protocol TEXT)"
        )
        await db.execute(
            "CREATE TABLE proxy_logs (timestamp REAL, client_ip TEXT, method TEXT, url TEXT, status_code INTEGER, squid_result TEXT, action TEXT DEFAULT 'allowed')"
        )
        await db.commit()


class FakeWebSocket:
    """send_json を記録し、receive_text はキューで待つ。close() で WebSocketDisconnect を起こす."""

    def __init__(self):
        self.sent = []
        self.incoming: asyncio.Queue = asyncio.Queue()
        self.accepted = False

    async def accept(self):
        self.accepted = True

    async def send_json(self, data):
        self.sent.append(data)

    async def receive_text(self):
        item = await self.incoming.get()
        if item is None:
            raise WebSocketDisconnect(code=1000)
        return item

    def close(self):
        self.incoming.put_nowait(None)


@contextlib.asynccontextmanager
async def _endpoint(db_path):
    import src.web_ui.app as web_app_module
    import src.web_ui.log_stream as log_stream
    from src.web_ui.app import websocket_endpoint

    original = web_app_module.DB_PATH
    original_interval = log_stream.POLL_INTERVAL
    web_app_module.DB_PATH = str(db_path)
    web_app_module._streamer = None
    # ポーラの周期はインスタンス生成時に固定されるので、endpoint を起動する前に短くする
    log_stream.POLL_INTERVAL = 0.05
    ws = FakeWebSocket()
    task = asyncio.create_task(websocket_endpoint(ws))
    try:
        yield ws
    finally:
        ws.close()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await asyncio.wait_for(task, timeout=2)
        web_app_module.DB_PATH = original
        web_app_module._streamer = None
        log_stream.POLL_INTERVAL = original_interval


def describe_websocket_integration():
    @pytest.mark.asyncio
    async def it_sends_a_sorted_snapshot_on_connect(tmp_path):
        db_path = tmp_path / "test.db"
        await _create_db(db_path)
        now = time.time()
        async with aiosqlite.connect(str(db_path)) as db:
            await db.execute(
                "INSERT INTO dns_queries VALUES (?, ?, ?, ?, ?)",
                (now - 100, "192.168.1.1", "example.com", "93.184.216.34", "allowed"),
            )
            await db.execute(
                "INSERT INTO dns_queries VALUES (?, ?, ?, ?, ?)",
                (now - 50, "192.168.1.2", "malware.com", "", "blocked"),
            )
            await db.execute(
                "INSERT INTO dns_queries VALUES (?, ?, ?, ?, ?)",
                (now - 40, "192.168.1.2", "telemetry.example", "", "ignored"),
            )
            await db.execute(
                "INSERT INTO firewall_blocks VALUES (?, ?, ?, ?, ?)",
                (now - 75, "192.168.1.100", "8.8.8.8", 53, "UDP"),
            )
            await db.commit()
        async with _endpoint(db_path) as ws:
            await asyncio.sleep(0.3)
            assert ws.accepted
            assert len(ws.sent) == 1 and ws.sent[0]["type"] == "snapshot"
            entries = ws.sent[0]["entries"]
            assert [e["component"] for e in entries] == [
                "DNS",
                "FIREWALL",
                "DNS",
            ]  # 時刻の昇順、ignored は出ない
            assert entries[0]["domain"] == "example.com" and entries[0]["action"] == "ALLOWED"
            assert (
                entries[1]["src_ip"] == "192.168.1.100"
                and entries[1]["dst_port"] == 53
                and "UDP" in entries[1]["reason"]
            )
            assert entries[2]["domain"] == "malware.com" and entries[2]["action"] == "BLOCKED"

    @pytest.mark.asyncio
    async def it_batches_new_logs_into_one_message_per_tick(tmp_path):
        db_path = tmp_path / "test.db"
        await _create_db(db_path)
        async with _endpoint(db_path) as ws:
            await asyncio.sleep(0.3)
            assert ws.sent[0]["type"] == "snapshot" and ws.sent[0]["entries"] == []
            async with aiosqlite.connect(str(db_path)) as db:
                now = time.time()
                for i in range(5):
                    await db.execute(
                        "INSERT INTO dns_queries VALUES (?, ?, ?, ?, ?)",
                        (now + i * 0.001, "192.168.1.5", f"d{i}.example", "1.1.1.1", "allowed"),
                    )
                await db.execute(
                    "INSERT INTO proxy_logs VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        now + 0.01,
                        "192.168.1.5",
                        "CONNECT",
                        "https://blocked.example/",
                        403,
                        "TCP_DENIED",
                        "blocked",
                    ),
                )
                await db.commit()
            await asyncio.sleep(0.4)
            batches = [m for m in ws.sent if m["type"] == "logs"]
            assert len(batches) == 1, ws.sent  # 同じ周期の 6 件は 1 メッセージ
            entries = batches[0]["entries"]
            assert len(entries) == 6
            assert [e["domain"] for e in entries[:5]] == [f"d{i}.example" for i in range(5)]
            assert entries[5]["component"] == "PROXY" and entries[5]["action"] == "BLOCKED"
            assert "TCP_DENIED" in entries[5]["reason"]

    @pytest.mark.asyncio
    async def it_resends_a_snapshot_on_resync(tmp_path):
        db_path = tmp_path / "test.db"
        await _create_db(db_path)
        async with _endpoint(db_path) as ws:
            await asyncio.sleep(0.2)
            async with aiosqlite.connect(str(db_path)) as db:
                await db.execute(
                    "INSERT INTO dns_queries VALUES (?, ?, ?, ?, ?)",
                    (time.time(), "192.168.1.9", "late.example", "", "allowed"),
                )
                await db.commit()
            await asyncio.sleep(0.3)
            ws.incoming.put_nowait('{"type": "resync"}')
            ws.incoming.put_nowait("garbage")  # 壊れたメッセージは無視
            await asyncio.sleep(0.2)
            snapshots = [m for m in ws.sent if m["type"] == "snapshot"]
            assert len(snapshots) == 2
            assert snapshots[1]["entries"][-1]["domain"] == "late.example"

    @pytest.mark.asyncio
    async def it_limits_the_snapshot_to_50_newest(tmp_path):
        db_path = tmp_path / "test.db"
        await _create_db(db_path)
        now = time.time()
        async with aiosqlite.connect(str(db_path)) as db:
            for i in range(80):
                await db.execute(
                    "INSERT INTO dns_queries VALUES (?, ?, ?, ?, ?)",
                    (now - 1000 + i, "192.168.1.1", f"q{i}.example", "1.1.1.1", "allowed"),
                )
            await db.commit()
        async with _endpoint(db_path) as ws:
            await asyncio.sleep(0.3)
            entries = ws.sent[0]["entries"]
            assert len(entries) == 50
            assert entries[0]["domain"] == "q30.example" and entries[-1]["domain"] == "q79.example"
            timestamps = [e["timestamp"] for e in entries]
            assert timestamps == sorted(timestamps)

    @pytest.mark.asyncio
    async def it_stops_the_poller_when_the_last_client_leaves(tmp_path):
        import src.web_ui.app as web_app_module

        db_path = tmp_path / "test.db"
        await _create_db(db_path)
        async with _endpoint(db_path):
            await asyncio.sleep(0.2)
            assert web_app_module._streamer is not None and web_app_module._streamer.running
            streamer = web_app_module._streamer
        await asyncio.sleep(0.1)
        assert not streamer.running
        assert web_app_module.manager.active_connections == []

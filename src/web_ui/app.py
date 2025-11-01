"""FastAPI Webアプリケーション - リアルタイム監視ダッシュボード."""

import asyncio
import contextlib
import time
from pathlib import Path

import aiosqlite
import yaml
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from .. import constants
from ..logger import ComponentType, log_error, log_system_event


class DomainRequest(BaseModel):
    """ドメイン追加/削除リクエスト."""

    domain: str


class StatsResponse(BaseModel):
    """統計レスポンス."""

    total: int
    allowed: int
    blocked: int
    unique_domains: int
    firewall_blocked: int  # iptablesでブロックされた数
    proxy_blocked: int  # Squidプロキシでブロックされた数


class CacheStatsResponse(BaseModel):
    """DNSキャッシュ統計レスポンス."""

    enabled: bool
    size: int = 0
    hits: int = 0
    misses: int = 0
    hit_rate: float = 0.0


class LogEntry(BaseModel):
    """ログエントリ."""

    timestamp: float
    component: str
    action: str
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    domain: str | None = None
    reason: str | None = None


class DomainInfo(BaseModel):
    """ドメイン情報."""

    domain: str
    query_count: int
    allowed_count: int
    blocked_count: int
    last_access: float
    status: str  # 過去の履歴: "allowed", "blocked", "mixed"
    current_rule: str  # 現在のルール: "allowed", "blocked_explicit", "blocked_default"
    resolved_ips: list[str] | None = None  # 解決されたIPアドレスのリスト


class BlockedIPInfo(BaseModel):
    """ブロックされたIPアドレスの情報."""

    ip_address: str
    block_count: int
    last_blocked: float
    ports: list[int]
    protocols: list[str]


class ConnectionManager:
    """WebSocket接続管理."""

    def __init__(self) -> None:
        """初期化."""
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        """WebSocket接続を受け入れ.

        Args:
            websocket: WebSocketインスタンス
        """
        await websocket.accept()
        self.active_connections.append(websocket)
        log_system_event("WebSocket client connected", count=str(len(self.active_connections)))

    def disconnect(self, websocket: WebSocket) -> None:
        """WebSocket接続を切断.

        Args:
            websocket: WebSocketインスタンス
        """
        self.active_connections.remove(websocket)
        log_system_event("WebSocket client disconnected", count=str(len(self.active_connections)))

    async def broadcast(self, message: dict) -> None:
        """すべてのクライアントにメッセージを配信.

        Args:
            message: 配信するメッセージ
        """
        disconnected = []

        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                # 接続エラーは後でクリーンアップ
                disconnected.append(connection)

        # 切断されたクライアントを削除
        for conn in disconnected:
            if conn in self.active_connections:
                self.active_connections.remove(conn)


# FastAPIアプリケーション
app = FastAPI(
    title="AI Security Gateway Dashboard",
    version="0.2.0",
    description="リアルタイム監視ダッシュボード",
)

# 接続マネージャー
manager = ConnectionManager()

# データベースパス（環境変数から取得可能に）
DB_PATH = constants.DB_PATH
CONFIG_PATH = constants.CONFIG_PATH


async def get_db() -> aiosqlite.Connection:
    """データベース接続を取得.

    Returns:
        aiosqlite接続
    """
    db = await aiosqlite.connect(DB_PATH)
    db.row_factory = aiosqlite.Row
    return db


def load_config() -> dict:
    """設定ファイルを読み込み.

    Returns:
        設定辞書
    """
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception as e:
        log_error(ComponentType.SYSTEM, f"Failed to load config: {e}")
        return {"allow_domains": [], "block_domains": []}


def get_current_rule(domain: str, config: dict) -> str:
    """ドメインの現在のルールを判定.

    Args:
        domain: ドメイン名
        config: 設定辞書

    Returns:
        現在のルール: "allowed", "blocked_explicit", "blocked_default"
    """
    domain_lower = domain.lower().rstrip(".")
    allow_domains = config.get("allow_domains", [])
    block_domains = config.get("block_domains", [])

    # ブロックリストチェック（優先）
    for blocked in block_domains:
        # 完全一致
        if blocked == domain_lower:
            return "blocked_explicit"
        # ワイルドカード（.example.com形式）
        if blocked.startswith(".") and (
            domain_lower.endswith(blocked) or domain_lower.endswith(blocked[1:])
        ):
            return "blocked_explicit"

    # 許可リストチェック
    for allowed in allow_domains:
        # 完全一致
        if allowed == domain_lower:
            return "allowed"
        # ワイルドカード（.example.com形式）
        if allowed.startswith(".") and (
            domain_lower.endswith(allowed) or domain_lower.endswith(allowed[1:])
        ):
            return "allowed"

    # どちらにも該当しない場合（デフォルト拒否）
    return "blocked_default"


@app.get("/", response_class=HTMLResponse)
async def index() -> HTMLResponse:
    """ダッシュボードメイン画面.

    Returns:
        HTMLレスポンス
    """
    html_path = Path(__file__).parent / "templates" / "dashboard.html"

    if not html_path.exists():
        return HTMLResponse("<h1>Dashboard template not found</h1>", status_code=500)

    with open(html_path, encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/api/stats", response_model=StatsResponse)
async def get_stats() -> StatsResponse:
    """統計情報API（過去24時間）.

    Returns:
        統計情報
    """
    db = await get_db()

    # 過去24時間のタイムスタンプ
    one_day_ago = time.time() - 86400

    try:
        # 総アクセス数
        cursor = await db.execute(
            "SELECT COUNT(*) FROM dns_queries WHERE timestamp > ?",
            (one_day_ago,),
        )
        row = await cursor.fetchone()
        total = row[0] if row else 0

        # 許可数
        cursor = await db.execute(
            "SELECT COUNT(*) FROM dns_queries WHERE timestamp > ? AND status = 'allowed'",
            (one_day_ago,),
        )
        row = await cursor.fetchone()
        allowed = row[0] if row else 0

        # ブロック数
        cursor = await db.execute(
            "SELECT COUNT(*) FROM dns_queries WHERE timestamp > ? AND status = 'blocked'",
            (one_day_ago,),
        )
        row = await cursor.fetchone()
        blocked = row[0] if row else 0

        # ユニークドメイン数
        cursor = await db.execute(
            "SELECT COUNT(DISTINCT query_domain) FROM dns_queries WHERE timestamp > ?",
            (one_day_ago,),
        )
        row = await cursor.fetchone()
        unique_domains = row[0] if row else 0

        # ファイアウォールブロック数
        cursor = await db.execute(
            "SELECT COUNT(*) FROM firewall_blocks WHERE timestamp > ?",
            (one_day_ago,),
        )
        row = await cursor.fetchone()
        firewall_blocked = row[0] if row else 0

        # プロキシブロック数
        cursor = await db.execute(
            "SELECT COUNT(*) FROM proxy_blocks WHERE timestamp > ?",
            (one_day_ago,),
        )
        row = await cursor.fetchone()
        proxy_blocked = row[0] if row else 0

        return StatsResponse(
            total=total,
            allowed=allowed,
            blocked=blocked,
            unique_domains=unique_domains,
            firewall_blocked=firewall_blocked,
            proxy_blocked=proxy_blocked,
        )

    finally:
        await db.close()


@app.get("/api/cache-stats", response_model=CacheStatsResponse)
async def get_cache_stats() -> CacheStatsResponse:
    """DNSキャッシュ統計API.

    Returns:
        キャッシュ統計情報
    """
    db = await get_db()

    try:
        # cache_statsテーブルから最新の統計を取得
        cursor = await db.execute(
            "SELECT size, hits, misses, hit_rate FROM cache_stats WHERE id = 1"
        )
        row = await cursor.fetchone()

        if row:
            return CacheStatsResponse(
                enabled=True,
                size=row[0],
                hits=row[1],
                misses=row[2],
                hit_rate=row[3],
            )

        # キャッシュ統計がDBに存在しない場合は無効
        return CacheStatsResponse(enabled=False)

    except Exception:
        # テーブルが存在しない場合など
        return CacheStatsResponse(enabled=False)
    finally:
        await db.close()


@app.get("/api/logs", response_model=list[LogEntry])
async def get_logs(limit: int = 100) -> list[LogEntry]:
    """最近のログを取得.

    Args:
        limit: 取得件数

    Returns:
        ログエントリのリスト
    """
    db = await get_db()

    try:
        cursor = await db.execute(
            """
            SELECT timestamp, client_ip, query_domain, response_ips, status
            FROM dns_queries
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        )

        logs = []
        async for row in cursor:
            status = row[4] if len(row) > 4 else "allowed"
            logs.append(
                LogEntry(
                    timestamp=row[0],
                    component="DNS",
                    action="ALLOWED" if status == "allowed" else "BLOCKED",
                    src_ip=row[1],
                    domain=row[2],
                    dst_ip=row[3].split(",")[0] if row[3] else None,
                )
            )

        return logs

    finally:
        await db.close()


@app.get("/api/firewall-blocks", response_model=list[LogEntry])
async def get_firewall_blocks(limit: int = 100) -> list[LogEntry]:
    """最近のファイアウォールブロックログを取得.

    Args:
        limit: 取得件数

    Returns:
        ログエントリのリスト
    """
    db = await get_db()

    try:
        cursor = await db.execute(
            """
            SELECT timestamp, src_ip, dst_ip, dst_port, protocol
            FROM firewall_blocks
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        )

        logs = []
        async for row in cursor:
            # Docker環境ではログ詳細が取得できないため、カウンターモード表示
            src_ip = row[1] if row[1] and row[1] != "blocked" else None
            dst_ip = row[2] if row[2] and row[2] != "blocked" else None
            protocol = row[4] if row[4] and row[4] != "IP" else "IP"

            # 詳細情報が取得できている場合とそうでない場合で表示を分ける
            if src_ip and dst_ip:
                reason = f"{protocol} traffic blocked by firewall"
            else:
                reason = "Traffic blocked by firewall (counter-based detection)"

            logs.append(
                LogEntry(
                    timestamp=row[0],
                    component="FIREWALL",
                    action="BLOCKED",
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=row[3],
                    reason=reason,
                )
            )

        return logs

    finally:
        await db.close()


@app.get("/api/proxy-blocks", response_model=list[LogEntry])
async def get_proxy_blocks(limit: int = 100) -> list[LogEntry]:
    """最近のプロキシブロックログを取得.

    Args:
        limit: 取得件数

    Returns:
        ログエントリのリスト
    """
    db = await get_db()

    try:
        cursor = await db.execute(
            """
            SELECT timestamp, client_ip, method, url, status_code
            FROM proxy_blocks
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,),
        )

        logs = []
        async for row in cursor:
            logs.append(
                LogEntry(
                    timestamp=row[0],
                    component="PROXY",
                    action="BLOCKED",
                    src_ip=row[1],
                    domain=row[3],  # URL
                    reason=f"{row[2]} request blocked by proxy (status: {row[4]})",
                )
            )

        return logs

    finally:
        await db.close()


@app.get("/api/blocked-ips", response_model=list[BlockedIPInfo])
async def get_blocked_ips(limit: int = 100) -> list[BlockedIPInfo]:
    """ブロックされたIPアドレスの統計情報を取得.

    Args:
        limit: 取得件数

    Returns:
        ブロックされたIPアドレス情報のリスト
    """
    db = await get_db()

    try:
        cursor = await db.execute(
            """
            SELECT
                dst_ip,
                COUNT(*) as block_count,
                MAX(timestamp) as last_blocked,
                GROUP_CONCAT(DISTINCT dst_port) as ports,
                GROUP_CONCAT(DISTINCT protocol) as protocols
            FROM firewall_blocks
            WHERE dst_ip IS NOT NULL
                AND dst_ip != 'blocked'
                AND dst_ip != 'unknown'
                AND dst_ip != ''
            GROUP BY dst_ip
            ORDER BY block_count DESC
            LIMIT ?
            """,
            (limit,),
        )

        blocked_ips = []
        async for row in cursor:
            # ポートのリストを作成（Noneを除外）
            ports = []
            if row["ports"]:
                for port_str in row["ports"].split(","):
                    port_str = port_str.strip()
                    if port_str and port_str != "None":
                        with contextlib.suppress(ValueError):
                            ports.append(int(port_str))

            # プロトコルのリストを作成
            protocols = []
            if row["protocols"]:
                for proto in row["protocols"].split(","):
                    proto = proto.strip()
                    if proto and proto not in ("unknown", "IP"):
                        protocols.append(proto)

            blocked_ips.append(
                BlockedIPInfo(
                    ip_address=row["dst_ip"],
                    block_count=row["block_count"],
                    last_blocked=row["last_blocked"],
                    ports=sorted(set(ports)),
                    protocols=sorted(set(protocols)),
                )
            )

        return blocked_ips

    finally:
        await db.close()


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """WebSocketエンドポイント - リアルタイムログ配信（DNS + Firewall）.

    Args:
        websocket: WebSocketインスタンス
    """
    await manager.connect(websocket)
    last_timestamp = 0.0

    try:
        # 最近のDNSログを送信
        try:
            dns_logs = await get_logs(limit=25)
            # 最近のファイアウォールブロックログを送信
            fw_logs = await get_firewall_blocks(limit=25)

            # 統合してタイムスタンプ順にソート（昇順）
            # フロントエンドで先頭に追加していくと降順になる
            all_logs = sorted(dns_logs + fw_logs, key=lambda x: x.timestamp, reverse=False)

            for log in all_logs[:50]:  # 最新50件に制限
                await websocket.send_json(log.model_dump())
                if log.timestamp > last_timestamp:
                    last_timestamp = log.timestamp
        except Exception as e:
            # 初期ログ送信エラーは無視して接続を継続
            print(f"Warning: Failed to send initial logs: {e}")

        # 新しいログを定期的にポーリング
        while True:
            try:
                # 1秒ごとに新しいログをチェック
                await asyncio.sleep(1)

                # 最後のタイムスタンプより新しいログを取得
                db = await get_db()
                try:
                    # DNSクエリログ
                    cursor = await db.execute(
                        """
                        SELECT timestamp, client_ip, query_domain, response_ips, status
                        FROM dns_queries
                        WHERE timestamp > ?
                        ORDER BY timestamp ASC
                        """,
                        (last_timestamp,),
                    )

                    new_logs = []
                    async for row in cursor:
                        status = row[4] if len(row) > 4 else "allowed"
                        log_entry = LogEntry(
                            timestamp=row[0],
                            component="DNS",
                            action="ALLOWED" if status == "allowed" else "BLOCKED",
                            src_ip=row[1],
                            domain=row[2],
                            dst_ip=row[3].split(",")[0] if row[3] else None,
                        )
                        new_logs.append(log_entry)
                        if row[0] > last_timestamp:
                            last_timestamp = row[0]

                    # ファイアウォールブロックログ
                    cursor = await db.execute(
                        """
                        SELECT timestamp, src_ip, dst_ip, dst_port, protocol
                        FROM firewall_blocks
                        WHERE timestamp > ?
                        ORDER BY timestamp ASC
                        """,
                        (last_timestamp,),
                    )

                    async for row in cursor:
                        # Docker環境ではログ詳細が取得できないため、カウンターモード表示
                        src_ip = row[1] if row[1] and row[1] != "blocked" else None
                        dst_ip = row[2] if row[2] and row[2] != "blocked" else None
                        protocol = row[4] if row[4] and row[4] != "IP" else "IP"

                        # 詳細情報が取得できている場合とそうでない場合で表示を分ける
                        if src_ip and dst_ip:
                            reason = f"{protocol} traffic blocked by firewall"
                        else:
                            reason = "Traffic blocked by firewall (counter-based detection)"

                        log_entry = LogEntry(
                            timestamp=row[0],
                            component="FIREWALL",
                            action="BLOCKED",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            dst_port=row[3],
                            reason=reason,
                        )
                        new_logs.append(log_entry)
                        if row[0] > last_timestamp:
                            last_timestamp = row[0]

                    # タイムスタンプ順にソートして送信
                    new_logs.sort(key=lambda x: x.timestamp)
                    for log in new_logs:
                        await websocket.send_json(log.model_dump())

                finally:
                    await db.close()

            except TimeoutError:
                continue
            except Exception as e:
                # ポーリング中のエラーは継続
                print(f"Warning: WebSocket polling error: {e}")
                continue

    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        print(f"Error: WebSocket connection error: {e}")
        manager.disconnect(websocket)


@app.get("/api/domains/allowed", response_model=list[str])
async def get_allowed_domains() -> list[str]:
    """許可ドメイン一覧を取得.

    Returns:
        許可ドメインのリスト
    """
    config = load_config()
    return config.get("allow_domains", [])


@app.get("/api/domains/blocked", response_model=list[str])
async def get_blocked_domains() -> list[str]:
    """ブロックドメイン設定一覧を取得（config.yml）.

    Returns:
        ブロックドメインのリスト
    """
    config = load_config()
    return config.get("block_domains", [])


class BlockedDomainInfo(BaseModel):
    """ブロックされたドメイン情報."""

    domain: str
    block_type: str  # "explicit" or "default"
    query_count: int
    last_access: float


@app.get("/api/domains/blocked-actual", response_model=list[BlockedDomainInfo])
async def get_blocked_actual_domains() -> list[BlockedDomainInfo]:
    """実際にブロックされたドメイン一覧を取得（アクセス履歴から）.

    Returns:
        ブロックされたドメイン情報のリスト
    """
    db = await get_db()
    config = load_config()

    try:
        # ブロックされたクエリを取得
        cursor = await db.execute(
            """
            SELECT
                query_domain,
                COUNT(*) as query_count,
                MAX(timestamp) as last_access
            FROM dns_queries
            WHERE status = 'blocked'
            GROUP BY query_domain
            ORDER BY query_count DESC
            """
        )

        blocked_domains = []
        async for row in cursor:
            domain = row[0]
            # 現在のルールを判定
            current_rule = get_current_rule(domain, config)

            # blocked_explicit または blocked_default のドメインのみ
            if current_rule in ["blocked_explicit", "blocked_default"]:
                block_type = "explicit" if current_rule == "blocked_explicit" else "default"
                blocked_domains.append(
                    BlockedDomainInfo(
                        domain=domain,
                        block_type=block_type,
                        query_count=row[1],
                        last_access=row[2],
                    )
                )

        return blocked_domains

    finally:
        await db.close()


@app.get("/api/domains/unique", response_model=list[DomainInfo])
async def get_unique_domains() -> list[DomainInfo]:
    """ユニークドメイン一覧を取得（アクセス統計付き）.

    Returns:
        ドメイン情報のリスト
    """
    db = await get_db()
    config = load_config()

    try:
        cursor = await db.execute(
            """
            SELECT
                query_domain,
                COUNT(*) as query_count,
                SUM(CASE WHEN status = 'allowed' THEN 1 ELSE 0 END) as allowed_count,
                SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked_count,
                MAX(timestamp) as last_access,
                GROUP_CONCAT(DISTINCT response_ips) as all_response_ips
            FROM dns_queries
            GROUP BY query_domain
            ORDER BY query_count DESC
            """
        )

        domains = []
        async for row in cursor:
            allowed_count = row["allowed_count"] or 0
            blocked_count = row["blocked_count"] or 0

            # 過去の履歴ステータスを判定
            if allowed_count > 0 and blocked_count == 0:
                historical_status = "allowed"
            elif blocked_count > 0 and allowed_count == 0:
                historical_status = "blocked"
            else:
                historical_status = "mixed"

            # 現在のルールを判定
            current_rule = get_current_rule(row["query_domain"], config)

            # IPアドレスのリストを作成（重複を除去）
            resolved_ips = []
            all_response_ips = row["all_response_ips"]
            if all_response_ips:
                # GROUP_CONCATで結合されたカンマ区切りのIPアドレスを分割して重複除去
                ip_set = set()
                for ip in all_response_ips.split(","):
                    ip = ip.strip()
                    if ip:
                        ip_set.add(ip)
                resolved_ips = sorted(ip_set)

            domains.append(
                DomainInfo(
                    domain=row["query_domain"],
                    query_count=row["query_count"],
                    allowed_count=allowed_count,
                    blocked_count=blocked_count,
                    last_access=row["last_access"],
                    status=historical_status,
                    current_rule=current_rule,
                    resolved_ips=resolved_ips if resolved_ips else None,
                )
            )

        return domains

    finally:
        await db.close()


@app.post("/api/domains/allow")
async def add_allowed_domain(request: DomainRequest) -> dict:
    """許可ドメインを追加（設定ファイル更新）.

    Args:
        request: ドメインリクエスト

    Returns:
        成功レスポンス
    """
    # 実装時は設定ファイルを更新してオーケストレータに通知
    log_system_event("Domain whitelist add request", domain=request.domain)

    return {"success": True, "domain": request.domain}


@app.delete("/api/domains/allow/{domain}")
async def remove_allowed_domain(domain: str) -> dict:
    """許可ドメインを削除.

    Args:
        domain: ドメイン名

    Returns:
        成功レスポンス
    """
    log_system_event("Domain whitelist remove request", domain=domain)

    return {"success": True, "domain": domain}


@app.post("/api/domains/block")
async def add_blocked_domain(request: DomainRequest) -> dict:
    """拒否ドメインを追加.

    Args:
        request: ドメインリクエスト

    Returns:
        成功レスポンス
    """
    log_system_event("Domain blocklist add request", domain=request.domain)

    return {"success": True, "domain": request.domain}


# 新しいログのブロードキャスト用関数（オーケストレータから呼び出し）
async def broadcast_log(log_entry: LogEntry) -> None:
    """新しいログをすべてのWebSocketクライアントに配信.

    Args:
        log_entry: ログエントリ
    """
    await manager.broadcast(log_entry.model_dump())


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8080)

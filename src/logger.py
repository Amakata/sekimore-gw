"""統合ログシステム - DNS、iptables、Proxyのログを統一フォーマットで出力."""

import logging
import sys
from enum import Enum

import structlog


class LogLevel(str, Enum):
    """ログレベル."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ComponentType(str, Enum):
    """コンポーネント種別."""

    DNS = "DNS"
    FIREWALL = "FIREWALL"
    PROXY = "PROXY"
    ORCHESTRATOR = "ORCHESTRATOR"
    SYSTEM = "SYSTEM"


def setup_logging(log_level: str = "INFO") -> None:
    """ログシステムの初期化."""
    # Pythonの標準loggingモジュールの設定
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.upper()),
    )

    # structlogの設定
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.dev.ConsoleRenderer(colors=True),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(component: ComponentType) -> structlog.BoundLogger:
    """コンポーネント別ロガーを取得."""
    logger = structlog.get_logger()
    return logger.bind(component=component.value)


def log_dns_query(client_ip: str, query_domain: str, response_ips: list[str], ttl: int) -> None:
    """DNS クエリログ."""
    logger = get_logger(ComponentType.DNS)
    logger.info(
        "DNS query",
        client_ip=client_ip,
        query_domain=query_domain,
        response_ips=response_ips,
        ttl=ttl,
    )


def log_firewall_action(
    action: str,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    domain: str | None = None,
    reason: str | None = None,
) -> None:
    """iptables アクションログ."""
    logger = get_logger(ComponentType.FIREWALL)

    emoji = "✅" if action == "ALLOWED" else "❌"
    msg = f"{emoji} {action}: {src_ip} → "

    if domain:
        msg += f"{domain} ({dst_ip}:{dst_port})"
    else:
        msg += f"{dst_ip}:{dst_port}"

    log_data = {
        "action": action,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
    }

    if domain:
        log_data["domain"] = domain
    if reason:
        log_data["reason"] = reason

    if action == "ALLOWED":
        logger.info(msg, **log_data)
    else:
        logger.warning(msg, **log_data)


def log_system_event(event: str, **kwargs: str) -> None:
    """システムイベントログ."""
    logger = get_logger(ComponentType.SYSTEM)
    logger.info(event, **kwargs)


def log_error(component: ComponentType, error: str, **kwargs: str) -> None:
    """エラーログ."""
    logger = get_logger(component)
    logger.error(error, **kwargs)

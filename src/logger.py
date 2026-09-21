"""Unified logging - emits DNS, iptables and proxy logs in a single format."""

import logging
import sys
from enum import StrEnum

import structlog


class ComponentType(StrEnum):
    """Component type."""

    DNS = "DNS"
    FIREWALL = "FIREWALL"
    PROXY = "PROXY"
    ORCHESTRATOR = "ORCHESTRATOR"
    SYSTEM = "SYSTEM"


def setup_logging(log_level: str = "INFO") -> None:
    """Initialize the logging system."""
    # Configure Python's standard logging module
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.upper()),
    )

    # Configure structlog
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
    """Return a logger bound to the given component."""
    logger = structlog.get_logger()
    return logger.bind(component=component.value)  # type: ignore[no-any-return]


def log_dns_query(
    client_ip: str,
    query_domain: str,
    response_ips: list[str],
    ttl: int,
    status: str = "allowed",
) -> None:
    """Log a DNS query."""
    logger = get_logger(ComponentType.DNS)
    logger.info(
        "DNS query",
        client_ip=client_ip,
        query_domain=query_domain,
        response_ips=response_ips,
        ttl=ttl,
        status=status,
    )


def log_firewall_action(
    action: str,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    domain: str | None = None,
    reason: str | None = None,
) -> None:
    """Log an iptables action."""
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
    """Log a system event."""
    logger = get_logger(ComponentType.SYSTEM)
    logger.info(event, **kwargs)


def log_error(component: ComponentType, error: str, **kwargs: str) -> None:
    """Log an error."""
    logger = get_logger(component)
    logger.error(error, **kwargs)

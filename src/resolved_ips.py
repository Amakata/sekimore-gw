"""Whether a resolved address may be reached, shared by everything that acts on one.

#178: an allowed name is not an allowed destination. The allowlist says which *names* an agent
may use; the address behind a name is chosen by whoever controls its DNS. Without this check,
one allowlisted domain answering `169.254.169.254` opens the cloud metadata service — which
serves credentials — and one answering `10.0.0.5` opens a host on the internal network that
nothing ever allowed.

Lives on its own, like `domains.py`, so that the DNS path, the firewall, Squid and the relay
cannot drift apart: a rule enforced at one layer and not another is a way around, not a rule.
"""

import ipaddress

# Denied by default. Each is a range no allowlisted public name has a reason to point at, and
# each is reachable from the dev container if it is allowed by mistake.
DEFAULT_DENY_CIDRS: tuple[str, ...] = (
    "169.254.0.0/16",  # link-local, and the cloud metadata service at 169.254.169.254
    "127.0.0.0/8",  # loopback
    "10.0.0.0/8",  # RFC1918
    "172.16.0.0/12",  # RFC1918
    "192.168.0.0/16",  # RFC1918
    "0.0.0.0/8",  # "this network": 0.0.0.0 is the local host to a connect(2)
    "100.64.0.0/10",  # carrier-grade NAT, routable inside some estates
    "::1/128",  # IPv6 loopback
    "fe80::/10",  # IPv6 link-local
    "fc00::/7",  # IPv6 unique-local (covers fd00::/8)
)
# IPv4-mapped IPv6 (::ffff:a.b.c.d) is deliberately *not* denied as a range: it is a shape, not
# a destination, and denying it outright would refuse ::ffff:140.82.114.4 — an ordinary public
# address. `is_denied_address` unwraps it and judges the IPv4 address inside instead.


def _networks(cidrs: "tuple[str, ...] | list[str]") -> list[ipaddress._BaseNetwork]:
    out: list[ipaddress._BaseNetwork] = []
    for c in cidrs:
        text = str(c).strip()
        if not text:
            continue
        try:
            out.append(ipaddress.ip_network(text, strict=False))
        except ValueError:
            # A malformed entry must not quietly widen what is allowed. Dropping it leaves the
            # default denials in place; config validation reports it separately.
            continue
    return out


def is_denied_address(
    ip: str,
    deny_cidrs: "tuple[str, ...] | list[str]" = DEFAULT_DENY_CIDRS,
    allow_cidrs: "tuple[str, ...] | list[str] | None" = None,
) -> bool:
    """Whether `ip` is a destination the gateway refuses to open.

    `allow_cidrs` wins over `deny_cidrs`: it carries the gateway's own network — which is RFC1918
    itself, so denying RFC1918 outright would break the gateway — and whatever a project has said
    it reaches on purpose, such as an internal mirror.

    An address that cannot be parsed is denied. It reached here as an answer to be acted on, and
    acting on something unreadable is the one outcome with no safe reading.
    """
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return True

    # ::ffff:a.b.c.d is an IPv4 destination wearing an IPv6 shape. Unwrap it first and judge the
    # address inside, so that ::ffff:169.254.169.254 is refused by a list written in IPv4 and
    # ::ffff:140.82.114.4 is still allowed.
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        return is_denied_address(str(mapped), deny_cidrs, allow_cidrs)

    for net in _networks(allow_cidrs or ()):
        if addr.version == net.version and addr in net:
            return False

    return any(addr.version == net.version and addr in net for net in _networks(deny_cidrs))


def filter_addresses(
    ips: list[str],
    deny_cidrs: "tuple[str, ...] | list[str]" = DEFAULT_DENY_CIDRS,
    allow_cidrs: "tuple[str, ...] | list[str] | None" = None,
) -> tuple[list[str], list[str]]:
    """Split `ips` into the ones that may be reached and the ones refused.

    Both halves are returned because the refused ones are worth auditing: "the gateway refused"
    and "the name did not resolve" are different facts, and only the first says someone pointed
    an allowed name somewhere it should not go.
    """
    kept: list[str] = []
    refused: list[str] = []
    for ip in ips:
        (refused if is_denied_address(ip, deny_cidrs, allow_cidrs) else kept).append(ip)
    return kept, refused

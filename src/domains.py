"""Domain matching, shared by everything that reads a domain list.

Lives on its own so the allow, block, ignore and handler lists cannot drift apart, and so
`config.py` can use it during validation without importing the DNS server.
"""


def domain_matches(domain: str, patterns: list[str]) -> bool:
    """Whether `domain` is covered by any entry in `patterns`.

    An entry is an exact name, or `.example.com` / `*.example.com` for a name and everything
    under it. The match is on label boundaries: `.github.com` covers `sub.github.com` and
    `github.com`, and does not cover `evilgithub.com` — a name anyone can register, which a
    plain suffix comparison would have accepted.
    """
    d = domain.lower().rstrip(".")
    for entry in patterns:
        p = entry.lower().rstrip(".").strip()
        if not p:
            continue
        if p.startswith("*."):
            p = p[1:]
        elif p.startswith("*"):
            # `*github.io` with no dot would mean "anything ending in github.io", which takes
            # in evilgithub.io — a name anyone can register. Read it as the exact name, the
            # same conservative reading a label-boundary wildcard gets.
            p = p[1:]
        if p.startswith("."):
            base = p[1:]
            if d == base or d.endswith(p):
                return True
        elif d == p:
            return True
    return False

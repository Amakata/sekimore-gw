"""#178: an allowed name is not an allowed destination.

The allowlist says which names an agent may use. The address behind a name is chosen by whoever
controls its DNS, so an allowlisted domain answering 169.254.169.254 would open the metadata
service — which serves credentials — and one answering 10.0.0.5 would open a host on the
internal network that nothing ever allowed.

The cases here are the ones just outside the boundary, not far from it: an attacker picks the
address, so the question is never "is 8.8.8.8 allowed" but "which shapes of a denied address
walk past the check".
"""

from src.resolved_ips import DEFAULT_DENY_CIDRS, filter_addresses, is_denied_address


def describe_denied_destinations():
    def it_refuses_the_metadata_service():
        # The address this whole check exists for: on EC2/GCE it serves credentials
        assert is_denied_address("169.254.169.254") is True

    def it_refuses_the_rest_of_link_local():
        # Not only the one well-known address: the range is reachable and serves other things
        assert is_denied_address("169.254.0.1") is True
        assert is_denied_address("169.254.255.254") is True

    def it_refuses_loopback_and_this_network():
        assert is_denied_address("127.0.0.1") is True
        # 127.x is a /8, not a single address
        assert is_denied_address("127.1.2.3") is True
        # connect(2) reads 0.0.0.0 as the local host
        assert is_denied_address("0.0.0.0") is True

    def it_refuses_the_private_ranges():
        for ip in ("10.0.0.5", "172.16.0.1", "172.31.255.254", "192.168.1.1"):
            assert is_denied_address(ip) is True, ip

    def it_allows_ordinary_public_addresses():
        # The check must not refuse the traffic the gateway exists to carry
        for ip in ("140.82.114.4", "8.8.8.8", "1.1.1.1", "93.184.216.34"):
            assert is_denied_address(ip) is False, ip

    def it_allows_the_addresses_just_outside_each_denied_range():
        # One past the boundary in each direction. A range written slightly too wide would
        # refuse real traffic, and one written too narrow would let the denied case through.
        for ip in (
            "169.253.255.255",  # just below 169.254.0.0/16
            "169.255.0.0",  # just above it
            "126.255.255.255",  # just below 127.0.0.0/8
            "128.0.0.0",  # just above it
            "9.255.255.255",  # just below 10.0.0.0/8
            "11.0.0.0",  # just above it
            "172.15.255.255",  # just below 172.16.0.0/12
            "172.32.0.0",  # just above it
            "192.167.255.255",  # just below 192.168.0.0/16
            "192.169.0.0",  # just above it
        ):
            assert is_denied_address(ip) is False, ip


def describe_shapes_that_would_walk_past_the_check():
    def it_refuses_an_ipv4_address_wearing_an_ipv6_shape():
        # ::ffff:169.254.169.254 is the same destination. A list written in IPv4 alone would
        # not match it, and the answer would be served.
        assert is_denied_address("::ffff:169.254.169.254") is True
        assert is_denied_address("::ffff:10.0.0.5") is True
        # And the same shape carrying a public address is still allowed
        assert is_denied_address("::ffff:140.82.114.4") is False

    def it_refuses_the_ipv6_equivalents():
        assert is_denied_address("::1") is True  # loopback
        assert is_denied_address("fe80::1") is True  # link-local
        assert is_denied_address("fd00::1") is True  # unique-local
        # A public IPv6 address is not refused
        assert is_denied_address("2606:4700::1111") is False

    def it_refuses_what_it_cannot_read():
        # This arrives as an answer to be acted on. Acting on something unparseable is the one
        # outcome with no safe reading, so it is denied rather than passed through.
        for junk in ("", "not-an-ip", "999.999.999.999", "169.254.169.254.5"):
            assert is_denied_address(junk) is True, junk


def describe_exceptions():
    def it_lets_an_allowed_range_win_over_the_denial():
        # The gateway's own network is RFC1918, so without this the deny would break the
        # gateway itself; a project reaching an internal mirror says so the same way.
        assert is_denied_address("10.0.0.5", allow_cidrs=["10.0.0.0/8"]) is False
        # …and the exception is only as wide as it was written
        assert is_denied_address("10.0.0.5", allow_cidrs=["10.1.0.0/16"]) is True

    def it_does_not_let_an_exception_open_everything_else():
        # Allowing the gateway's own subnet must not also allow the metadata service
        assert is_denied_address("169.254.169.254", allow_cidrs=["172.20.0.0/16"]) is True

    def it_ignores_a_malformed_entry_rather_than_widening_what_is_allowed():
        # A typo in the config must not turn into "allow everything". The default denials
        # stay in place and the bad entry is dropped.
        assert is_denied_address("169.254.169.254", allow_cidrs=["not-a-cidr"]) is True
        # A malformed deny entry likewise does not disable the ones that parse
        assert is_denied_address("127.0.0.1", deny_cidrs=["nonsense", "127.0.0.0/8"]) is True


def describe_filter_addresses():
    def it_keeps_the_good_and_reports_the_refused():
        # A name that answers with both is the interesting case: the public address stays
        # usable, and the refused one is named so it can be audited.
        kept, refused = filter_addresses(["140.82.114.4", "169.254.169.254", "10.0.0.5"])
        assert kept == ["140.82.114.4"]
        assert refused == ["169.254.169.254", "10.0.0.5"]

    def it_reports_everything_refused_when_a_name_resolves_only_into_denied_space():
        kept, refused = filter_addresses(["169.254.169.254"])
        assert kept == []
        assert refused == ["169.254.169.254"]

    def it_leaves_an_ordinary_answer_untouched():
        kept, refused = filter_addresses(["140.82.114.4", "140.82.114.5"])
        assert kept == ["140.82.114.4", "140.82.114.5"]
        assert refused == []

    def it_defaults_to_the_shipped_denials():
        # The default list is what protects a project that configured nothing
        assert "169.254.0.0/16" in DEFAULT_DENY_CIDRS
        assert "127.0.0.0/8" in DEFAULT_DENY_CIDRS

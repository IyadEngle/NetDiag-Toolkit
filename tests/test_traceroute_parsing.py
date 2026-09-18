# Copyright (c) 2026 Iyad Engle. All rights reserved.

from netdiag.core.traceroute import _parse_windows_tracert, _parse_linux_traceroute


class TestWindowsParsing:
    def test_parse_typical_output_with_plain_ms(self):
        """Windows tracert outputs '1 ms' without < or = prefix."""
        output = (
            "Tracing route to example.com [93.184.216.34]\n"
            "over a maximum of 30 hops:\n"
            "\n"
            "  1     1 ms     1 ms     1 ms  192.168.1.1\n"
            "  2     5 ms     5 ms     4 ms  10.0.0.1\n"
            "  3    10 ms     9 ms    11 ms  93.184.216.34\n"
            "\n"
            "Trace complete.\n"
        )
        hops = _parse_windows_tracert(output)
        assert len(hops) == 3
        assert hops[0].hop_number == 1
        assert hops[0].ip == "192.168.1.1"
        assert hops[0].latencies_ms == [1, 1, 1]
        assert hops[2].ip == "93.184.216.34"
        assert hops[2].latencies_ms == [10, 9, 11]

    def test_parse_with_less_than_prefix(self):
        """Windows tracert can output 'time<1ms' for very fast hops."""
        output = "  1    <1 ms    <1 ms    <1 ms  192.168.1.1"
        hops = _parse_windows_tracert(output)
        assert len(hops) == 1
        assert hops[0].ip == "192.168.1.1"
        assert hops[0].latencies_ms == [1, 1, 1]

    def test_parse_timeout_hops(self):
        output = (
            "  1     1 ms     1 ms     1 ms  192.168.1.1\n"
            "  2     *        *        *     Request timed out.\n"
            "  3    10 ms     9 ms    11 ms  93.184.216.34\n"
        )
        hops = _parse_windows_tracert(output)
        # Hop 2 may not parse due to no IP
        reachable = [h for h in hops if h.ip]
        assert len(reachable) >= 2


class TestLinuxParsing:
    def test_parse_typical(self):
        output = (
            "traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets\n"
            " 1  192.168.1.1 (192.168.1.1)  1.045 ms  1.023 ms  1.012 ms\n"
            " 2  10.0.0.1 (10.0.0.1)  5.234 ms  5.123 ms  5.456 ms\n"
        )
        hops = _parse_linux_traceroute(output)
        assert len(hops) == 2
        assert hops[0].ip == "192.168.1.1"
        assert len(hops[0].latencies_ms) == 3

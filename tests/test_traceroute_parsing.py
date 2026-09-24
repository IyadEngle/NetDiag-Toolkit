# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

import importlib
from unittest.mock import MagicMock, patch

from netdiag.core.traceroute import _parse_linux_traceroute, _parse_windows_tracert, traceroute
from netdiag.utils.models import Status

# `netdiag.core` re-exports the `traceroute` function, which shadows the module
# for patch("netdiag.core.traceroute.x") on Python 3.10.
traceroute_module = importlib.import_module("netdiag.core.traceroute")


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


class TestHostnameParsing:
    def test_linux_numeric_output_has_no_hostname(self):
        hops = _parse_linux_traceroute(" 1  192.168.1.1  1.045 ms  1.023 ms  1.012 ms")
        assert hops[0].ip == "192.168.1.1"
        assert hops[0].hostname == ""

    def test_linux_named_hop(self):
        hops = _parse_linux_traceroute(" 1  router.lan (192.168.1.1)  1.045 ms  1.023 ms  1.012 ms")
        assert hops[0].hostname == "router.lan"
        assert hops[0].ip == "192.168.1.1"

    def test_linux_ip_in_parentheses_is_not_a_hostname(self):
        hops = _parse_linux_traceroute(" 1  192.168.1.1 (192.168.1.1)  1.045 ms  1.023 ms  1.012 ms")
        assert hops[0].hostname == ""

    def test_linux_timeout_hop(self):
        hops = _parse_linux_traceroute(" 2  * * *")
        assert hops[0].ip == "" and hops[0].hostname == ""

    def test_windows_numeric_output_has_no_hostname(self):
        for line in ("  1    <1 ms    <1 ms    <1 ms  192.168.1.1",
                     "  2     5 ms     5 ms     4 ms  10.0.0.1"):
            assert _parse_windows_tracert(line)[0].hostname == ""

    def test_windows_named_hop(self):
        hops = _parse_windows_tracert("  1    <1 ms    <1 ms    <1 ms  router.lan [192.168.1.1]")
        assert hops[0].hostname == "router.lan"
        assert hops[0].ip == "192.168.1.1"


LINUX_REACHED = (
    "traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets\n"
    " 1  192.168.1.1  1.045 ms  1.023 ms  1.012 ms\n"
    " 2  93.184.216.34  9.1 ms  9.2 ms  9.3 ms\n"
)
LINUX_NOT_REACHED = (
    "traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets\n"
    " 1  192.168.1.1  1.045 ms  1.023 ms  1.012 ms\n"
    " 2  10.0.0.1  5.1 ms  5.2 ms  5.3 ms\n"
    " 3  * * *\n"
)
WINDOWS_REACHED_IP_TARGET = (
    "Tracing route to 1.1.1.1 over a maximum of 30 hops\n"
    "\n"
    "  1    <1 ms    <1 ms    <1 ms  192.168.1.1\n"
    "  2    10 ms     9 ms    11 ms  1.1.1.1\n"
    "\n"
    "Trace complete.\n"
)


def _run_trace(os_name: str, output: str, target: str):
    with patch.object(traceroute_module.platform, "system", return_value=os_name), \
         patch.object(traceroute_module.process, "run", return_value=MagicMock(stdout=output)):
        return traceroute(target)


class TestDestinationReached:
    def test_linux_destination_reached_is_pass(self):
        result = _run_trace("Linux", LINUX_REACHED, "example.com")
        assert result.status == Status.PASS
        assert result.details["destination_ip"] == "93.184.216.34"
        assert result.details["destination_reached"] is True

    def test_linux_destination_not_reached_is_warn(self):
        result = _run_trace("Linux", LINUX_NOT_REACHED, "example.com")
        assert result.status == Status.WARN
        assert result.details["destination_reached"] is False
        assert "10.0.0.1" in result.evidence

    def test_windows_ip_target_header_without_brackets(self):
        result = _run_trace("Windows", WINDOWS_REACHED_IP_TARGET, "1.1.1.1")
        assert result.status == Status.PASS
        assert result.details["destination_ip"] == "1.1.1.1"

    def test_unknown_destination_is_not_pass(self):
        # No header and a hostname target: reaching the destination cannot be confirmed.
        output = " 1  192.168.1.1  1.0 ms  1.0 ms  1.0 ms\n"
        assert _run_trace("Linux", output, "example.com").status == Status.WARN

    def test_no_hops_is_fail(self):
        output = "traceroute to example.com (93.184.216.34), 30 hops max\n 1  * * *\n"
        assert _run_trace("Linux", output, "example.com").status == Status.FAIL

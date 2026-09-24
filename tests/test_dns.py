# Copyright (c) 2026 Iyad Engle. All rights reserved.

from unittest.mock import MagicMock, patch

from netdiag.core.dns import _parse_nslookup_answers, compare_dns_servers, resolve_hostname


class TestDNSResolution:
    def test_resolve_localhost(self):
        assert resolve_hostname("localhost").status.value == "PASS"

    def test_resolve_invalid(self):
        assert resolve_hostname("this-does-not-exist-12345.invalid").status.value == "FAIL"


NSLOOKUP_HEADER = (
    "Server:  dns.google\n"
    "Address:  8.8.8.8\n"
    "\n"
    "Non-authoritative answer:\n"
)


class TestNslookupParsing:
    def test_single_ipv4(self):
        output = NSLOOKUP_HEADER + "Name:    example.com\nAddress:  93.184.216.34\n"
        assert _parse_nslookup_answers(output, "8.8.8.8") == ["93.184.216.34"]

    def test_single_ipv6_is_not_truncated(self):
        output = NSLOOKUP_HEADER + "Name:    one.one.one.one\nAddress:  2606:4700:4700::1111\n"
        assert _parse_nslookup_answers(output, "8.8.8.8") == ["2606:4700:4700::1111"]

    def test_multi_address_block_with_ipv6_and_ipv4(self):
        output = NSLOOKUP_HEADER + (
            "Name:    google.com\n"
            "Addresses:  2607:f8b0:4004:c07::71\n"
            "          142.250.1.100\n"
            "          142.250.1.101\n"
        )
        assert _parse_nslookup_answers(output, "8.8.8.8") == [
            "2607:f8b0:4004:c07::71", "142.250.1.100", "142.250.1.101",
        ]

    def test_server_address_and_aliases_are_excluded(self):
        output = NSLOOKUP_HEADER + (
            "Name:    example.net\n"
            "Address:  198.51.100.7\n"
            "Aliases:  www.example.net\n"
            "          alias.example.net\n"
        )
        assert _parse_nslookup_answers(output, "8.8.8.8") == ["198.51.100.7"]

    def test_no_answer(self):
        output = NSLOOKUP_HEADER + "*** dns.google can't find nope.invalid: Non-existent domain\n"
        assert _parse_nslookup_answers(output, "8.8.8.8") == []

    @patch("platform.system", return_value="Windows")
    @patch("netdiag.core.dns.subprocess.run")
    def test_compare_uses_parser_on_windows(self, mock_run, _os):
        mock_run.return_value = MagicMock(
            stdout=NSLOOKUP_HEADER + "Name:    one.one.one.one\nAddress:  2606:4700:4700::1111\n")
        with patch("netdiag.core.dns.resolve_hostname") as mock_resolve:
            mock_resolve.return_value = MagicMock(test_name="")
            results = compare_dns_servers("one.one.one.one")
        google = next(r for r in results if r.test_name == "dns_comparison_google")
        assert google.details["resolved_ips"] == ["2606:4700:4700::1111"]

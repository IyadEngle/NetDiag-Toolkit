# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

"""GUI tests that require NO Qt: validation, styling logic, version consistency."""

import netdiag
from netdiag.gui.styles import PALETTES, build_stylesheet, status_colors
from netdiag.gui.validation import validate_target


class TestTargetValidation:
    def test_valid_hostname(self):
        ok, value = validate_target("example.com")
        assert ok and value == "example.com"

    def test_valid_subdomain(self):
        ok, value = validate_target("www.sub.example.co.uk")
        assert ok and value == "www.sub.example.co.uk"

    def test_valid_ipv4(self):
        ok, value = validate_target("192.168.1.1")
        assert ok and value == "192.168.1.1"

    def test_strips_whitespace(self):
        ok, value = validate_target("  example.com  ")
        assert ok and value == "example.com"

    def test_empty_rejected(self):
        ok, _ = validate_target("")
        assert not ok
        ok, _ = validate_target("   ")
        assert not ok

    def test_scheme_rejected(self):
        ok, msg = validate_target("https://example.com")
        assert not ok
        assert "scheme" in msg.lower()

    def test_whitespace_rejected(self):
        assert not validate_target("exa mple.com")[0]

    def test_path_rejected(self):
        assert not validate_target("example.com/path")[0]

    def test_trailing_dash_rejected(self):
        assert not validate_target("example-.com")[0]

    def test_ipv6_rejected_with_message(self):
        ok, msg = validate_target("::1")
        assert not ok
        assert "ipv6" in msg.lower()

    def test_loopback_ipv4_accepted(self):
        ok, _ = validate_target("127.0.0.1")
        assert ok


class TestStatusColors:
    def test_pass_is_green_family(self):
        fg, _ = status_colors("PASS", "dark")
        assert fg == PALETTES["dark"]["green"]

    def test_fail_and_error_are_red(self):
        for status in ("FAIL", "ERROR"):
            fg, _ = status_colors(status, "dark")
            assert fg == PALETTES["dark"]["red"]

    def test_observation_is_amber(self):
        fg, _ = status_colors("OBSERVATION", "dark")
        assert fg == PALETTES["dark"]["amber"]

    def test_skip_and_inconclusive_are_gray(self):
        for status in ("SKIP", "INCONCLUSIVE"):
            fg, _ = status_colors(status, "dark")
            assert fg == PALETTES["dark"]["gray"]

    def test_pending_is_muted(self):
        fg, _ = status_colors("PENDING", "dark")
        assert fg == PALETTES["dark"]["text_muted"]

    def test_unknown_status_falls_back_to_pending(self):
        fg, _ = status_colors("NOT_A_STATUS", "dark")
        assert fg == PALETTES["dark"]["text_muted"]

    def test_light_theme_uses_light_palette(self):
        fg, _ = status_colors("PASS", "light")
        assert fg == PALETTES["light"]["green"]


class TestStylesheet:
    def test_dark_stylesheet_contains_widgets(self):
        css = build_stylesheet("dark")
        assert "QMainWindow" in css
        assert "QTableWidget" in css

    def test_light_stylesheet_contains_widgets(self):
        css = build_stylesheet("light")
        assert "QMainWindow" in css

    def test_unknown_theme_raises(self):
        try:
            build_stylesheet("solarized")
        except KeyError:
            pass
        else:
            raise AssertionError("Unknown theme should raise KeyError")


class TestCLIGuiSeparation:
    def test_version_is_0_5_beta(self):
        assert netdiag.__version__ == "0.5.0b0"

    def test_scan_report_uses_package_version(self):
        from netdiag.utils.models import ScanReport
        assert ScanReport(target="x").tool_version == netdiag.__version__


class TestGuiResources:
    def test_app_icon_files_exist(self):
        from pathlib import Path
        resources = Path(__file__).resolve().parents[1] / "netdiag" / "gui" / "resources"
        assert (resources / "app.ico").is_file()
        assert (resources / "app.png").is_file()
        assert (resources / "app.ico").stat().st_size > 0
        assert (resources / "app.png").stat().st_size > 0


class TestSharedValidationInGui:
    def test_invalid_ipv4_rejected(self):
        ok, msg = validate_target("1.2.3.999")
        assert not ok and "IPv4" in msg

    def test_bracketed_ipv6_rejected_as_not_yet_supported(self):
        ok, msg = validate_target("[2001:db8::1]")
        assert not ok and "not supported yet" in msg

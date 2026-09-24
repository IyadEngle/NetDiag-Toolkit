# Copyright (c) 2026 Iyad Engle. All rights reserved.
# Licensed under the MIT License. See LICENSE file for details.

"""
DNS security checks. Uses dnspython as primary, dig as fallback.
DNSSEC not detected → OBSERVATION. Open resolver → FAIL (security condition).
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import subprocess

from netdiag.utils import process
from netdiag.utils.models import Confidence, SecurityFinding, SecurityStatus, Severity

logger = logging.getLogger("netdiag.security.dns_security")


_DNSSEC_RESOLVER = "8.8.8.8"


def _find_zone_apex(target: str, timeout: int = 10) -> str | None:
    """Return the zone apex (e.g. "example.com") that contains `target`, or None."""
    import dns.name
    import dns.resolver

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [_DNSSEC_RESOLVER]
    resolver.timeout = timeout
    resolver.lifetime = timeout
    try:
        zone = dns.resolver.zone_for_name(target, resolver=resolver)
    except Exception as e:
        logger.debug("zone apex lookup for %s failed: %s", target, e)
        return None
    if zone == dns.name.root:
        return None
    return zone.to_text(omit_final_dot=True)


def _dnssec_check_dnspython(target: str, timeout: int = 10) -> tuple[str, str]:
    """DNSKEY lookup for `target`; DNSKEY records only exist at a zone apex,
    so a name without them is re-checked at the apex of its enclosing zone."""
    status, evidence = _dnskey_query(target, timeout)
    if status != "NOT_DETECTED":
        return status, evidence

    apex = _find_zone_apex(target, timeout)
    if apex is None:
        return "INCONCLUSIVE", f"{evidence}; could not determine the zone apex for {target}"
    if apex.rstrip(".").lower() == target.rstrip(".").lower():
        return status, evidence

    apex_status, apex_evidence = _dnskey_query(apex, timeout)
    return apex_status, f"{target} is in zone {apex}: {apex_evidence}"


def _dnskey_query(target: str, timeout: int = 10) -> tuple[str, str]:
    import dns.exception
    import dns.message
    import dns.name
    import dns.query
    import dns.rcode
    import dns.rdataclass
    import dns.rdatatype

    try:
        query = dns.message.make_query(target, dns.rdatatype.DNSKEY, dns.rdataclass.IN, want_dnssec=True)
        response = dns.query.udp(query, _DNSSEC_RESOLVER, timeout=timeout)
        rcode = response.rcode()

        if rcode == dns.rcode.NOERROR:
            try:
                target_name = dns.name.from_text(target)
                dnskey_rrset = response.get_rrset(response.answer, target_name, dns.rdataclass.IN, dns.rdatatype.DNSKEY)
                if dnskey_rrset:
                    return "KEYS_DETECTED", f"Found {len(dnskey_rrset)} DNSKEY record(s) for {target}"
                return "NOT_DETECTED", f"NOERROR but no DNSKEY records for {target}"
            except KeyError:
                return "NOT_DETECTED", f"NOERROR but no DNSKEY RRset for {target}"
        elif rcode == dns.rcode.SERVFAIL:
            return "INCONCLUSIVE", f"SERVFAIL response for DNSKEY query to {target}"
        elif rcode == dns.rcode.NXDOMAIN:
            return "INCONCLUSIVE", f"NXDOMAIN - domain {target} does not exist"
        return "INCONCLUSIVE", f"Unexpected DNS RCODE: {dns.rcode.to_text(rcode)}"

    except dns.exception.Timeout:
        return "INCONCLUSIVE", f"DNS query timed out after {timeout}s"
    except ConnectionRefusedError:
        return "INCONCLUSIVE", "Connection refused by DNS resolver"
    except OSError as e:
        return "ERROR", f"Network error: {e}"
    except Exception as e:
        return "ERROR", f"DNS query failed: {e}"


def _dnssec_check_dig(target: str, timeout: int = 10) -> tuple[str, str]:
    try:
        result = process.run(["dig", "DNSKEY", target, "+short"], capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            if result.stdout.strip():
                return "KEYS_DETECTED", f"Found DNSKEY records for {target}"
            return "NOT_DETECTED", f"NOERROR but no DNSKEY records for {target}"
        return "INCONCLUSIVE", f"dig returned exit code {result.returncode}"
    except subprocess.TimeoutExpired:
        return "INCONCLUSIVE", f"dig timed out after {timeout}s"
    except FileNotFoundError:
        return "TOOL_UNAVAILABLE", "dig command not found and dnspython unavailable"
    except Exception as e:
        return "ERROR", f"dig failed: {e}"


def check_dnssec(target: str, timeout: int = 10) -> list[SecurityFinding]:
    findings = []
    status, evidence = None, ""

    try:
        status, evidence = _dnssec_check_dnspython(target, timeout)
    except ImportError:
        logger.debug("dnspython not available, falling back to dig")
        status, evidence = _dnssec_check_dig(target, timeout)
    except Exception as e:
        status, evidence = "ERROR", f"Check failed unexpectedly: {e}"

    if status == "NOT_DETECTED":
        findings.append(SecurityFinding(
            test_name="dns_dnssec", status=SecurityStatus.OBSERVATION,
            severity=Severity.INFO, title="DNSSEC Not Detected",
            description=(f"No DNSKEY record found for {target}. DNSSEC does not appear to be configured. "
                         "This is an informational observation about DNS configuration, not a vulnerability."),
            evidence=evidence, recommendation="Consider enabling DNSSEC for DNS response integrity.",
            confidence=Confidence.CONFIRMED,
        ))
    elif status == "INCONCLUSIVE":
        findings.append(SecurityFinding(
            test_name="dns_dnssec", status=SecurityStatus.INCONCLUSIVE,
            severity=Severity.INFO, title="DNSSEC Check Inconclusive",
            description=f"Could not conclusively determine DNSSEC status for {target}.",
            evidence=evidence, recommendation=f"Retry or verify manually: dig DNSKEY {target}",
            confidence=Confidence.INCONCLUSIVE,
        ))
    elif status == "TOOL_UNAVAILABLE":
        findings.append(SecurityFinding(
            test_name="dns_dnssec", status=SecurityStatus.SKIP,
            severity=Severity.INFO, title="DNSSEC Check Unavailable",
            description="Both dnspython and dig are unavailable.",
            evidence=evidence, recommendation="Install dnspython: pip install dnspython",
            confidence=Confidence.INCONCLUSIVE,
        ))
    elif status == "ERROR":
        findings.append(SecurityFinding(
            test_name="dns_dnssec", status=SecurityStatus.ERROR,
            severity=Severity.INFO, title="DNSSEC Check Error",
            description="An error occurred during DNSSEC check.",
            evidence=evidence, recommendation="Review logs for details.",
            confidence=Confidence.INCONCLUSIVE,
        ))

    return findings


def _resolve_server_ip(target: str) -> str | None:
    """dnspython needs a nameserver IP: return `target` if it is one, else resolve it."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(target, 53, socket.AF_INET, socket.SOCK_DGRAM)
    except (socket.gaierror, UnicodeError):
        return None
    for info in infos:
        address = info[4][0]
        if isinstance(address, str):
            return address
    return None


def _open_resolver_check_dnspython(target: str, timeout: int = 5) -> tuple:
    import dns.exception
    import dns.resolver

    try:
        server_ip = _resolve_server_ip(target)
        if server_ip is None:
            return None, f"Could not resolve {target} to an IPv4 address"
        if server_ip != target:
            target = f"{target} ({server_ip})"
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [server_ip]
        resolver.timeout = timeout
        resolver.lifetime = timeout
        try:
            answer = resolver.resolve("example.com", "A")
            ips = [str(r) for r in answer]
            return True, f"Server at {target} resolved example.com to {ips}"
        except dns.resolver.NXDOMAIN:
            return True, f"Server at {target} returned NXDOMAIN (recursive query accepted)"
        except dns.resolver.NoAnswer:
            return True, f"Server at {target} returned no answer (recursive query accepted)"
        except dns.resolver.NoNameservers:
            return False, f"Server at {target} did not respond"
        except dns.exception.Timeout:
            return False, f"Server at {target} timed out after {timeout}s"
        except ConnectionRefusedError:
            return False, f"Connection refused by {target}"
        except OSError as e:
            return None, f"Network error: {e}"
    except Exception as e:
        return None, f"Error: {e}"


def _open_resolver_check_dig(target: str, timeout: int = 5) -> tuple:
    try:
        result = process.run(["dig", f"@{target}", "example.com", "+time=3", "+tries=1"],
                             capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0 and "ANSWER SECTION" in result.stdout:
            return True, f"dig @{target} returned ANSWER SECTION"
        return False, f"Server did not return an answer (exit code: {result.returncode})"
    except subprocess.TimeoutExpired:
        return False, f"dig timed out after {timeout}s"
    except FileNotFoundError:
        return None, "dig not found and dnspython unavailable"
    except Exception as e:
        return None, f"dig failed: {e}"


def check_open_resolver(target: str, timeout: int = 5) -> list[SecurityFinding]:
    findings = []
    accepted, evidence = None, ""

    try:
        accepted, evidence = _open_resolver_check_dnspython(target, timeout)
    except ImportError:
        accepted, evidence = _open_resolver_check_dig(target, timeout)
    except Exception as e:
        accepted, evidence = None, f"Unexpected error: {e}"

    if accepted is True:
        findings.append(SecurityFinding(
            test_name="dns_open_resolver", status=SecurityStatus.FAIL,
            severity=Severity.MEDIUM,
            title="Recursive DNS Query Accepted from This Network Position",
            description=(f"The DNS server at {target} accepted and resolved a recursive query "
                         f"from this network position. NOTE: This observation is from a single "
                         f"vantage point and does NOT prove that the resolver is globally accessible. "
                         f"If confirmed as globally open, this could be abused for DNS amplification."),
            evidence=evidence,
            recommendation=("Verify whether this resolver should accept recursive queries from "
                            "external networks. Configure recursion ACLs if restricted."),
            confidence=Confidence.CONFIRMED,
        ))
    elif accepted is None:
        findings.append(SecurityFinding(
            test_name="dns_open_resolver", status=SecurityStatus.INCONCLUSIVE,
            severity=Severity.INFO, title="Open Resolver Check Inconclusive",
            description=f"Could not determine if {target} accepts recursive queries.",
            evidence=evidence, recommendation="Retry the check or verify manually.",
            confidence=Confidence.INCONCLUSIVE,
        ))

    return findings

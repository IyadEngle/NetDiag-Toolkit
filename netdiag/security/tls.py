# Copyright (c) 2026 Iyad Engle
# SPDX-License-Identifier: GPL-3.0-or-later

"""
TLS/SSL security audit. All SSL errors during protocol version testing are
classified as INCONCLUSIVE. Certificate self-signed status is verified
cryptographically. Connection failures produce SKIP/ERROR, never FAIL.
"""

from __future__ import annotations

import enum
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone

from netdiag.utils.execution import cached, cached_value, connect_host
from netdiag.utils.models import Confidence, SecurityFinding, SecurityStatus, Severity


class TLSProtocolStatus(str, enum.Enum):
    SUPPORTED = "SUPPORTED"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNAVAILABLE = "UNAVAILABLE"


def _get_tls_version_constant(version_name: str) -> ssl.TLSVersion | None:
    return {
        "SSLv3": getattr(ssl.TLSVersion, "SSLv3", None),
        "TLSv1.0": getattr(ssl.TLSVersion, "TLSv1", None),
        "TLSv1.1": getattr(ssl.TLSVersion, "TLSv1_1", None),
        "TLSv1.2": getattr(ssl.TLSVersion, "TLSv1_2", None),
        "TLSv1.3": getattr(ssl.TLSVersion, "TLSv1_3", None),
    }.get(version_name)


def _classify_ssl_error_for_protocol(error: ssl.SSLError) -> TLSProtocolStatus:
    """ALL SSL errors are classified as INCONCLUSIVE. No single SSL error
    reliably proves server-side protocol rejection."""
    return TLSProtocolStatus.INCONCLUSIVE


def _probe_tls_service(host: str, port: int, timeout: int = 10) -> tuple[bool, str]:
    negotiated = _cached_negotiated_version(host, port)
    if negotiated in ("TLSv1.3", "TLSv1.2"):
        # A certificate handshake earlier in this scan already negotiated TLS 1.2/1.3.
        return True, f"Confirmed TLS service: negotiated {negotiated} on {host}:{port}"
    for version_name in ("TLSv1.3", "TLSv1.2"):
        constant = _get_tls_version_constant(version_name)
        if constant is None:
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = constant
            ctx.maximum_version = constant
            with socket.create_connection((connect_host(host), port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    negotiated = ssock.version()
            return True, f"Confirmed TLS service: negotiated {negotiated} on {host}:{port}"
        except Exception:
            continue
    return False, f"Could not confirm TLS service on {host}:{port}"


def _test_tls_version(
    host: str, port: int, version_name: str,
    tls_version: ssl.TLSVersion, timeout: int = 10,
) -> tuple[TLSProtocolStatus, str]:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = tls_version
        ctx.maximum_version = tls_version
    except (ValueError, ssl.SSLError, OverflowError, AttributeError) as e:
        return TLSProtocolStatus.INCONCLUSIVE, f"Local build cannot create context for {version_name}: {e}"

    if _cached_negotiated_version(host, port) == version_name:
        # The cached handshake already negotiated exactly this version.
        return TLSProtocolStatus.SUPPORTED, f"Negotiated {version_name} with {host}:{port}"

    try:
        with socket.create_connection((connect_host(host), port), timeout=timeout) as sock:
            try:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    negotiated = ssock.version()
                return TLSProtocolStatus.SUPPORTED, f"Negotiated {negotiated} with {host}:{port}"
            except ssl.SSLError as e:
                return TLSProtocolStatus.INCONCLUSIVE, \
                    f"SSL error during {version_name} negotiation: {e}. Cannot determine cause."
    except (TimeoutError, ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return TLSProtocolStatus.UNAVAILABLE, f"Network error: {e}"


def check_tls_protocol_versions(host: str, port: int = 443, timeout: int = 10) -> list[SecurityFinding]:
    findings = []
    is_tls, probe_evidence = _probe_tls_service(host, port, timeout)
    if not is_tls:
        findings.append(SecurityFinding(
            test_name="tls_protocol_versions", status=SecurityStatus.SKIP,
            severity=Severity.INFO,
            title="TLS Protocol Check: Could Not Confirm TLS Service",
            description=f"Could not establish TLS connection to {host}:{port}.",
            evidence=probe_evidence,
            recommendation="Verify target is reachable and serving TLS.",
            confidence=Confidence.INCONCLUSIVE,
        ))
        return findings

    versions_to_test = [
        ("SSLv3", "SSLv3 is deprecated (POODLE, RFC 7568).", "Disable SSLv3. Use TLS 1.2+ only."),
        ("TLSv1.0", "TLS 1.0 is deprecated per RFC 8996 (2021).", "Disable TLS 1.0. Use TLS 1.2+ minimum."),
        ("TLSv1.1", "TLS 1.1 is deprecated per RFC 8996 (2021).", "Disable TLS 1.1. Use TLS 1.2+ minimum."),
        ("TLSv1.2", "TLS 1.2 is the current minimum recommended.", "TLS 1.2 is supported (informational)."),
        ("TLSv1.3", "TLS 1.3 is the latest recommended standard.", "TLS 1.3 is supported (informational)."),
    ]

    for version_name, description, recommendation in versions_to_test:
        constant = _get_tls_version_constant(version_name)
        if constant is None:
            findings.append(SecurityFinding(
                test_name="tls_protocol_versions", status=SecurityStatus.INCONCLUSIVE,
                severity=Severity.INFO,
                title=f"TLS {version_name}: Local Build Cannot Test",
                description=f"Local build does not support testing {version_name}.",
                evidence=f"ssl.TLSVersion constant for {version_name} not available.",
                recommendation="Use a Python build with compatible OpenSSL.",
                confidence=Confidence.INCONCLUSIVE,
            ))
            continue

        status, evidence = _test_tls_version(host, port, version_name, constant, timeout)

        if status == TLSProtocolStatus.SUPPORTED and version_name in ("SSLv3", "TLSv1.0", "TLSv1.1"):
            severity = Severity.HIGH if version_name == "SSLv3" else Severity.MEDIUM
            findings.append(SecurityFinding(
                test_name="tls_protocol_versions", status=SecurityStatus.FAIL,
                severity=severity, title=f"Deprecated TLS Protocol Supported: {version_name}",
                description=description, evidence=evidence, recommendation=recommendation,
                confidence=Confidence.CONFIRMED,
            ))
        elif status == TLSProtocolStatus.INCONCLUSIVE:
            findings.append(SecurityFinding(
                test_name="tls_protocol_versions", status=SecurityStatus.INCONCLUSIVE,
                severity=Severity.INFO,
                title=f"TLS {version_name}: Result Inconclusive",
                description=f"Could not conclusively determine server support for {version_name}.",
                evidence=evidence,
                recommendation=f"Manually verify with openssl s_client -connect {host}:{port}",
                confidence=Confidence.INCONCLUSIVE,
            ))
        elif status == TLSProtocolStatus.UNAVAILABLE:
            findings.append(SecurityFinding(
                test_name="tls_protocol_versions", status=SecurityStatus.ERROR,
                severity=Severity.INFO,
                title=f"TLS {version_name}: Connection Failed",
                description=f"Network error while testing {version_name}.",
                evidence=evidence, recommendation="Verify target reachability.",
                confidence=Confidence.INCONCLUSIVE,
            ))

    return findings


@dataclass
class CertificateInfo:
    subject_cn: str = ""
    issuer_cn: str = ""
    not_before: str = ""
    not_after: str = ""
    days_until_expiry: int = 0
    is_self_signed: bool = False
    is_self_issued: bool = False
    sans: list[str] = field(default_factory=list)
    serial_hex: str = ""


def _cryptographic_self_signed_check(cert) -> bool | None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
    from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
    from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

    public_key = cert.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes, PKCS1v15(), cert.signature_hash_algorithm)
            return True
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes, ECDSA(cert.signature_hash_algorithm))
            return True
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(cert.signature, cert.tbs_certificate_bytes)
            return True
        return None
    except InvalidSignature:
        return False
    except Exception:
        return None


# Handshake outcomes worth reusing within a scan: the TLS handshake completed.
# CONNECTION_FAILED is not cached, so a later check retries the connection.
_REUSABLE_HANDSHAKE_STATUSES = ("OK", "PARSE_FAILED", "CRYPTOGRAPHY_UNAVAILABLE")


def _handshake_cache_key(host: str, port: int) -> tuple[str, str, int]:
    return ("tls.handshake", host.lower(), port)


def _cached_negotiated_version(host: str, port: int) -> str | None:
    """TLS version negotiated by a certificate handshake cached earlier in this scan."""
    entry = cached_value(_handshake_cache_key(host, port))
    if isinstance(entry, tuple) and len(entry) == 4 and entry[2] in _REUSABLE_HANDSHAKE_STATUSES:
        negotiated = entry[1]
        return negotiated if isinstance(negotiated, str) else None
    return None


def _retrieve_certificate(host: str, port: int = 443, timeout: int = 10) -> tuple:
    """Certificate handshake, performed once per (host, port) within a scan.

    Outside a scan every call performs a new handshake.
    """
    return cached(
        _handshake_cache_key(host, port),
        lambda: _fetch_certificate(host, port, timeout),
        cache_if=lambda result: result[2] in _REUSABLE_HANDSHAKE_STATUSES,
    )


def _fetch_certificate(host: str, port: int = 443, timeout: int = 10) -> tuple:
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((connect_host(host), port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                negotiated = ssock.version()

        if not der_cert:
            return None, negotiated, "PARSE_FAILED", "Server did not return certificate data."

        try:
            from cryptography import x509
            from cryptography.x509.oid import NameOID

            cert = x509.load_der_x509_certificate(der_cert)
            info = CertificateInfo()

            try:
                cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if cn:
                    value = cn[0].value
                    info.subject_cn = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
            except Exception:
                pass
            try:
                icn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
                if icn:
                    value = icn[0].value
                    info.issuer_cn = value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
            except Exception:
                pass

            info.is_self_issued = (cert.subject == cert.issuer)
            crypto_result = _cryptographic_self_signed_check(cert)
            info.is_self_signed = crypto_result is True

            info.serial_hex = format(cert.serial_number, "x")

            try:
                nb_dt = cert.not_valid_before_utc
                na_dt = cert.not_valid_after_utc
            except AttributeError:
                nb_dt = cert.not_valid_before.replace(tzinfo=timezone.utc)
                na_dt = cert.not_valid_after.replace(tzinfo=timezone.utc)

            info.not_before = nb_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            info.not_after = na_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            info.days_until_expiry = (na_dt - datetime.now(timezone.utc)).days

            try:
                san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                info.sans = san_ext.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                pass

            return info, negotiated, "OK", None

        except ImportError:
            return None, negotiated, "CRYPTOGRAPHY_UNAVAILABLE", \
                "The 'cryptography' package is required for certificate inspection."
        except Exception as e:
            return None, negotiated, "PARSE_FAILED", f"Failed to parse certificate: {e}"

    except (TimeoutError, ConnectionRefusedError, ConnectionResetError, OSError) as e:
        return None, None, "CONNECTION_FAILED", f"Could not connect to {host}:{port}: {e}"
    except Exception as e:
        return None, None, "CONNECTION_FAILED", f"Unexpected error: {e}"


def check_certificate_expiry(host: str, port: int = 443, timeout: int = 10) -> list[SecurityFinding]:
    findings = []
    cert, _, status, error_msg = _retrieve_certificate(host, port, timeout)

    if status == "CONNECTION_FAILED":
        findings.append(SecurityFinding(
            test_name="tls_cert_expiry", status=SecurityStatus.SKIP, severity=Severity.INFO,
            title="TLS Certificate Check: Connection Failed",
            description=f"Could not connect to {host}:{port}. Connectivity issue, not a security finding.",
            evidence=error_msg or "Unknown connection error.",
            recommendation="Verify target is reachable and serving HTTPS.",
            confidence=Confidence.INCONCLUSIVE,
        ))
    elif status == "CRYPTOGRAPHY_UNAVAILABLE":
        findings.append(SecurityFinding(
            test_name="tls_cert_expiry", status=SecurityStatus.SKIP, severity=Severity.INFO,
            title="TLS Certificate Check: Cryptography Library Not Available",
            description="The 'cryptography' package is required to parse certificates.",
            evidence=error_msg or "cryptography not installed.",
            recommendation="Install: pip install cryptography",
            confidence=Confidence.INCONCLUSIVE,
        ))
    elif status == "PARSE_FAILED":
        findings.append(SecurityFinding(
            test_name="tls_cert_expiry", status=SecurityStatus.ERROR, severity=Severity.INFO,
            title="TLS Certificate Check: Parse Failed",
            description="Certificate retrieved but could not be parsed.",
            evidence=error_msg or "Unknown parsing error.",
            recommendation="Inspect manually with openssl s_client.",
            confidence=Confidence.INCONCLUSIVE,
        ))
    else:
        assert cert is not None
        if cert.days_until_expiry < 0:
            findings.append(SecurityFinding(
                test_name="tls_cert_expiry", status=SecurityStatus.FAIL, severity=Severity.HIGH,
                title="TLS Certificate Has Expired",
                description=f"The TLS certificate for {host} expired {abs(cert.days_until_expiry)} days ago.",
                evidence=f"notAfter: {cert.not_after} ({cert.days_until_expiry} days).",
                recommendation="Renew the TLS certificate immediately.",
                confidence=Confidence.CONFIRMED,
            ))
        elif cert.days_until_expiry < 14:
            findings.append(SecurityFinding(
                test_name="tls_cert_expiry", status=SecurityStatus.FAIL, severity=Severity.MEDIUM,
                title="TLS Certificate Expiring Soon",
                description=f"The TLS certificate for {host} expires in {cert.days_until_expiry} days.",
                evidence=f"notAfter: {cert.not_after} ({cert.days_until_expiry} days).",
                recommendation="Renew the TLS certificate before expiry.",
                confidence=Confidence.CONFIRMED,
            ))
        else:
            findings.append(SecurityFinding(
                test_name="tls_cert_expiry", status=SecurityStatus.PASS, severity=Severity.INFO,
                title="TLS Certificate Expiry: OK",
                description=f"Certificate valid for {cert.days_until_expiry} more days.",
                evidence=f"notAfter: {cert.not_after} ({cert.days_until_expiry} days).",
                recommendation="No action needed.",
                confidence=Confidence.CONFIRMED,
            ))

    return findings


# OpenSSL X509 verification error codes (stable across OpenSSL 1.1 and 3.x).
_X509_V_ERR_CERT_HAS_EXPIRED = 10
_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT = 18
_X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN = 19
_X509_V_ERR_HOSTNAME_MISMATCH = 62


def _classify_verification_error(error: ssl.SSLCertVerificationError) -> str:
    """Classify a verification failure as hostname_mismatch, self_signed, expired or other.

    Prefers the numeric verify_code. Falls back to message text, accepting both
    OpenSSL 1.1 ("self signed") and OpenSSL 3 ("self-signed") wording.
    """
    code = getattr(error, "verify_code", None)
    if code == _X509_V_ERR_HOSTNAME_MISMATCH:
        return "hostname_mismatch"
    if code in (_X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, _X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN):
        return "self_signed"
    if code == _X509_V_ERR_CERT_HAS_EXPIRED:
        return "expired"

    message = f"{getattr(error, 'verify_message', '') or ''} {error}".lower()
    if "hostname mismatch" in message:
        return "hostname_mismatch"
    if "self signed" in message or "self-signed" in message:
        return "self_signed"
    if "expired" in message:
        return "expired"
    return "other"


def check_certificate_hostname(host: str, port: int = 443, timeout: int = 10) -> list[SecurityFinding]:
    findings = []
    try:
        context = ssl.create_default_context()
        with socket.create_connection((connect_host(host), port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                pass
        findings.append(SecurityFinding(
            test_name="tls_cert_hostname", status=SecurityStatus.PASS, severity=Severity.INFO,
            title="TLS Certificate Hostname: Valid",
            description=f"Certificate hostname validation succeeded for {host}.",
            evidence="SSL handshake with hostname verification completed.",
            recommendation="No action needed.", confidence=Confidence.CONFIRMED,
        ))
    except ssl.SSLCertVerificationError as e:
        kind = _classify_verification_error(e)
        if kind == "hostname_mismatch":
            findings.append(SecurityFinding(
                test_name="tls_cert_hostname", status=SecurityStatus.FAIL, severity=Severity.HIGH,
                title="TLS Certificate Hostname Mismatch",
                description=f"The certificate served by {host} does not match the requested hostname.",
                evidence=f"SSL verification error: {e}",
                recommendation="Ensure the certificate includes the correct hostname in SAN or CN.",
                confidence=Confidence.CONFIRMED,
            ))
        elif kind == "self_signed":
            cert_info, _, ret_status, _ = _retrieve_certificate(host, port, timeout)
            if ret_status == "OK" and cert_info is not None:
                if cert_info.is_self_signed:
                    title = "Self-Signed TLS Certificate (Cryptographically Verified)"
                    desc = (f"The certificate served by {host} is self-signed: its signature "
                            f"was cryptographically verified against its own public key.")
                else:
                    title = "Self-Issued TLS Certificate"
                    desc = (f"The certificate served by {host} has matching subject and issuer DNs "
                            f"(self-issued), but cryptographic signature verification was inconclusive.")
            else:
                title = "Self-Signed or Self-Issued TLS Certificate"
                desc = f"The certificate served by {host} appears to be self-signed or self-issued."

            findings.append(SecurityFinding(
                test_name="tls_cert_hostname", status=SecurityStatus.FAIL, severity=Severity.MEDIUM,
                title=title, description=desc,
                evidence=f"SSL verification error: {e}",
                recommendation="Use a certificate from a trusted Certificate Authority.",
                confidence=Confidence.CONFIRMED,
            ))
        elif kind == "expired":
            pass
        else:
            findings.append(SecurityFinding(
                test_name="tls_cert_hostname", status=SecurityStatus.FAIL, severity=Severity.MEDIUM,
                title="TLS Certificate Verification Failed",
                description=f"Certificate verification failed for {host}.",
                evidence=f"SSL verification error: {e}",
                recommendation="Review the TLS certificate configuration.",
                confidence=Confidence.CONFIRMED,
            ))
    except (TimeoutError, ConnectionRefusedError, ConnectionResetError, OSError) as e:
        findings.append(SecurityFinding(
            test_name="tls_cert_hostname", status=SecurityStatus.SKIP, severity=Severity.INFO,
            title="TLS Certificate Hostname Check: Connection Failed",
            description=f"Could not connect to {host}:{port}.",
            evidence=str(e), recommendation="Verify target is reachable.",
            confidence=Confidence.INCONCLUSIVE,
        ))
    except Exception as e:
        findings.append(SecurityFinding(
            test_name="tls_cert_hostname", status=SecurityStatus.ERROR, severity=Severity.INFO,
            title="TLS Certificate Hostname Check: Unexpected Error",
            description="Unexpected error during hostname verification.",
            evidence=str(e), recommendation="Review logs.",
            confidence=Confidence.INCONCLUSIVE,
        ))

    return findings

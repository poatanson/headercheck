"""TLS collection (blocking ssl/socket, run in a thread) and analysis."""
from __future__ import annotations

import socket
import ssl
import warnings
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from .cipherprobe import VERSIONS as RAW_VERSIONS
from .cipherprobe import WEAK_SUITES, ServerHello, probe_suites, probe_version
from .models import CertInfo, CheckResult, Status, TlsResult

CATEGORY = "tls"

PROTOCOLS: dict[str, ssl.TLSVersion] = {
    "TLSv1.0": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}

# Weak cipher groups live in cipherprobe.WEAK_SUITES (probed with a raw ClientHello).
# TLS 1.3 suites are all AEAD and cannot be weakened, so they are not probed.
# Score when the server accepts the group (lower = worse)
WEAK_CIPHER_SCORES = {
    "NULL": 0, "Anonymous (aNULL)": 0, "EXPORT": 0, "RC4": 0, "DES": 0,
    "3DES": 40, "RSA key exchange (no PFS)": 70,
}

# OpenSSL reasons that mean "*our* side cannot even offer this", not a server answer.
_LOCAL_UNSUPPORTED = ("NO_PROTOCOLS_AVAILABLE", "NO_CIPHERS_AVAILABLE", "UNSUPPORTED_PROTOCOL",
                      "NO CIPHER MATCH", "NO_CIPHER_MATCH")


class ConnectError(Exception):
    """TCP-level failure (DNS, refused, timeout) - nothing TLS-related can be measured."""


# --------------------------------------------------------------------------- #
# Collection
# --------------------------------------------------------------------------- #
def collect_tls(host: str, port: int = 443, timeout: float = 5.0) -> TlsResult:
    """Run every TLS probe sequentially against one host. Never raises.

    Order: (1) certificate via a verified `ssl` handshake, (2) protocol probes
    via `ssl` with a raw-ClientHello fallback for TLS <= 1.2, (3) weak cipher
    probes via raw ClientHello. If `ssl` cannot handshake at all (e.g. the
    server only speaks RC4, which local OpenSSL lacks) the certificate is taken
    from a raw handshake instead.
    """
    result = TlsResult(host=host, port=port)
    ssl_failure: str | None = None
    try:
        result.cert, result.negotiated = get_certificate(host, port, timeout)
    except ConnectError as exc:
        result.error = str(exc)
        return result
    except ssl.SSLError as exc:
        ssl_failure = f"TLS 핸드셰이크 실패: {_ssl_reason(exc)}"
    except OSError as exc:
        ssl_failure = f"TLS 연결 실패: {exc.__class__.__name__}: {exc}"

    raw_cert: bytes | None = None
    for name, version in PROTOCOLS.items():
        accepted = probe_protocol(host, port, version, timeout)
        if not accepted and name in RAW_VERSIONS:
            hello = _raw(probe_version, host, port, RAW_VERSIONS[name], timeout)
            if isinstance(hello, ServerHello):
                accepted = True
                raw_cert = raw_cert or hello.cert_der
                if ssl_failure:
                    result.notes.append(f"{name}: ssl 모듈 실패, raw ClientHello로 확인 ({hello.suite_name})")
            elif hello is None:
                accepted = False  # server explicitly refused this version
        result.protocols[name] = accepted

    if not any(result.protocols.values()):
        result.error = ssl_failure or "지원하는 TLS 프로토콜 없음 (모든 핸드셰이크 실패)"
        return result

    for group, suites in WEAK_SUITES.items():
        hello = _raw(probe_suites, host, port, suites, timeout)
        if isinstance(hello, ServerHello):
            result.weak_ciphers[group] = hello.suite_name
            raw_cert = raw_cert or hello.cert_der
        else:
            result.weak_ciphers[group] = None if hello is _UNTESTABLE else False

    if result.cert is None:
        result.notes.append(ssl_failure or "ssl 핸드셰이크 실패")
        if raw_cert:
            try:
                result.cert = parse_certificate(
                    raw_cert, verified=None,
                    verify_error="로컬 OpenSSL과 공통 cipher가 없어 체인 검증 불가 (raw 핸드셰이크로 인증서만 수집)")
            except ValueError:
                pass
    return result


_UNTESTABLE = object()


def _raw(fn, *args):
    """Run a cipherprobe function; TCP-level failures become the _UNTESTABLE sentinel."""
    try:
        return fn(*args)
    except OSError:
        return _UNTESTABLE


def _connect(host: str, port: int, timeout: float) -> socket.socket:
    try:
        return socket.create_connection((host, port), timeout=timeout)
    except socket.gaierror as exc:
        raise ConnectError(f"DNS 조회 실패: {host} ({exc.strerror or exc})") from exc
    except TimeoutError as exc:
        raise ConnectError(f"TCP 연결 타임아웃 ({timeout:g}s): {host}:{port}") from exc
    except ConnectionRefusedError as exc:
        raise ConnectError(f"연결 거부: {host}:{port}") from exc
    except OSError as exc:
        raise ConnectError(f"TCP 연결 실패: {host}:{port} ({exc})") from exc


def _handshake(host: str, port: int, ctx: ssl.SSLContext, timeout: float) -> ssl.SSLSocket:
    sock = _connect(host, port, timeout)
    try:
        return ctx.wrap_socket(sock, server_hostname=host)
    except BaseException:
        sock.close()
        raise


def get_certificate(host: str, port: int, timeout: float) -> tuple[CertInfo, str | None]:
    """Verified handshake first; on a verification error fall back to fetching the
    certificate unverified (ssl.get_server_certificate) so it can still be parsed."""
    ctx = ssl.create_default_context()
    try:
        with _handshake(host, port, ctx, timeout) as s:
            der = s.getpeercert(binary_form=True)
            negotiated = f"{s.version()} / {s.cipher()[0]}"
        return parse_certificate(der, verified=True), negotiated
    except ssl.SSLCertVerificationError as exc:
        verify_error = exc.verify_message or _ssl_reason(exc)
        if exc.verify_code == 62 or "hostname" in str(exc).lower():
            verify_error = f"호스트명 불일치: {verify_error}"
    pem = ssl.get_server_certificate((host, port), timeout=timeout)
    der = ssl.PEM_cert_to_DER_cert(pem)
    return parse_certificate(der, verified=False, verify_error=verify_error), None


def parse_certificate(der: bytes, *, verified: bool | None, verify_error: str | None = None,
                      now: datetime | None = None) -> CertInfo:
    cert = x509.load_der_x509_certificate(der)
    now = now or datetime.now(timezone.utc)
    not_after = cert.not_valid_after_utc
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        san_names = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        san_names = []
    org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    key = cert.public_key()
    key_type, key_bits = _key_info(key)
    try:
        sig = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except Exception:  # unsupported algorithm
        sig = None
    return CertInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        issuer_org=str(org[0].value) if org else None,
        not_before=cert.not_valid_before_utc.isoformat(),
        not_after=not_after.isoformat(),
        days_left=(not_after - now).days,
        san=san_names,
        signature_algorithm=sig,
        key_type=key_type,
        key_bits=key_bits,
        verified=verified,
        verify_error=verify_error,
    )


def _key_info(key) -> tuple[str, int | None]:
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"EC ({key.curve.name})", key.key_size
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", key.key_size
    if isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        return key.__class__.__name__.replace("PublicKey", ""), None
    return key.__class__.__name__, None


def _probe_context(min_v: ssl.TLSVersion, max_v: ssl.TLSVersion) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():  # probing deprecated TLS 1.0/1.1 is the whole point
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = min_v
        ctx.maximum_version = max_v
    return ctx


def probe_protocol(host: str, port: int, version: ssl.TLSVersion, timeout: float) -> bool | None:
    """True = server accepted, False = server rejected, None = untestable from this client."""
    try:
        ctx = _probe_context(version, version)
        if version <= ssl.TLSVersion.TLSv1_1:
            ctx.set_ciphers("ALL:@SECLEVEL=0")  # modern OpenSSL hides old protocols at SECLEVEL>=1
    except (ValueError, ssl.SSLError):
        return None
    return _try(host, port, ctx, timeout)


def _try(host: str, port: int, ctx: ssl.SSLContext, timeout: float) -> bool | None:
    try:
        with _handshake(host, port, ctx, timeout):
            return True
    except ssl.SSLError as exc:
        reason = _ssl_reason(exc).upper()
        if any(r in reason for r in _LOCAL_UNSUPPORTED) and "ALERT" not in reason:
            return None
        return False
    except ConnectError:
        return None
    except (ConnectionResetError, ConnectionAbortedError, TimeoutError):
        return False  # many servers just drop the connection on an unsupported hello
    except OSError:
        return None


def _ssl_reason(exc: ssl.SSLError) -> str:
    return getattr(exc, "reason", None) or exc.strerror or str(exc)


# --------------------------------------------------------------------------- #
# Analysis (pure)
# --------------------------------------------------------------------------- #
def analyze_tls(tls: TlsResult) -> list[CheckResult]:
    if tls.cert is None and not any(tls.protocols.values()):
        msg = tls.error or "TLS 정보를 수집하지 못함"
        return [CheckResult.error(cid, name, CATEGORY, msg) for cid, name in (
            ("protocols", "지원 프로토콜"), ("ciphers", "취약 Cipher"),
            ("cert_expiry", "인증서 만료"), ("cert_trust", "인증서 신뢰/발급기관"))]
    return [check_protocols(tls), check_weak_ciphers(tls), check_cert_expiry(tls), check_cert_trust(tls)]


def check_protocols(tls: TlsResult) -> CheckResult:
    name = "지원 프로토콜"
    p = tls.protocols
    if not p or all(v is None for v in p.values()):
        return CheckResult.error("protocols", name, CATEGORY, "프로토콜 프로브 불가")
    enabled = [k for k, v in p.items() if v]
    untestable = [k for k, v in p.items() if v is None]
    value = ", ".join(enabled) or "없음"
    if not (p.get("TLSv1.2") or p.get("TLSv1.3")):
        score, detail = 0, "TLS 1.2/1.3 미지원"
    elif p.get("TLSv1.0"):
        score, detail = 30, "TLS 1.0 허용 (폐기된 프로토콜)"
    elif p.get("TLSv1.1"):
        score, detail = 50, "TLS 1.1 허용 (폐기된 프로토콜)"
    elif p.get("TLSv1.3"):
        score, detail = 100, "양호"
    else:
        score, detail = 90, "TLS 1.3 미지원"
    if untestable:
        detail += f" (로컬 OpenSSL에서 측정 불가: {', '.join(untestable)})"
    return CheckResult.scored("protocols", name, CATEGORY, score, value, detail)


def check_weak_ciphers(tls: TlsResult) -> CheckResult:
    name = "취약 Cipher"
    w = tls.weak_ciphers
    if not w or all(v is None for v in w.values()):
        if tls.protocols and not any(tls.protocols.get(k) for k in ("TLSv1.0", "TLSv1.1", "TLSv1.2")):
            return CheckResult.scored("ciphers", name, CATEGORY, 100, "TLS 1.3 전용",
                                      "TLS 1.3만 지원 → 취약 cipher 사용 불가")
        return CheckResult.error("ciphers", name, CATEGORY, "cipher 프로브 불가")
    accepted = [g for g, v in w.items() if v]
    untestable = [g for g, v in w.items() if v is None]
    score = min((WEAK_CIPHER_SCORES[g] for g in accepted), default=100)
    detail = ("수락됨: " + ", ".join(f"{g} ({w[g]})" for g in accepted)) if accepted else "취약 cipher 미수락"
    if untestable:
        detail += f" (로컬에서 측정 불가: {', '.join(untestable)})"
    return CheckResult.scored("ciphers", name, CATEGORY, score, ", ".join(accepted) or "없음", detail)


def check_cert_expiry(tls: TlsResult) -> CheckResult:
    name = "인증서 만료"
    c = tls.cert
    if c is None:
        return CheckResult.error("cert_expiry", name, CATEGORY, tls.error or "인증서 없음")
    d = c.days_left
    if d < 0:
        score, detail = 0, f"만료됨 ({-d}일 경과)"
    elif d < 15:
        score, detail = 40, f"{d}일 남음 (곧 만료)"
    elif d <= 30:
        score, detail = 70, f"{d}일 남음"
    else:
        score, detail = 100, f"{d}일 남음"
    return CheckResult.scored("cert_expiry", name, CATEGORY, score, c.not_after[:10], detail)


def check_cert_trust(tls: TlsResult) -> CheckResult:
    name = "인증서 신뢰/발급기관"
    c = tls.cert
    if c is None:
        return CheckResult.error("cert_trust", name, CATEGORY, tls.error or "인증서 없음")
    issuer = c.issuer_org or c.issuer
    if c.verified is None:
        return CheckResult(id="cert_trust", name=name, category=CATEGORY, score=None,
                           status=Status.ERROR, value=issuer, detail=c.verify_error or "검증 불가")
    if not c.verified:
        return CheckResult.scored("cert_trust", name, CATEGORY, 0, issuer,
                                  f"검증 실패: {c.verify_error}")
    score, notes = 100, []
    if c.key_type == "RSA" and c.key_bits and c.key_bits < 2048:
        score -= 50
        notes.append(f"RSA {c.key_bits}bit (<2048)")
    if c.signature_algorithm in ("sha1", "md5"):
        score -= 50
        notes.append(f"취약 서명 알고리즘 {c.signature_algorithm}")
    key = f"{c.key_type} {c.key_bits}" if c.key_bits else c.key_type
    return CheckResult.scored("cert_trust", name, CATEGORY, score, issuer,
                              "; ".join(notes) or f"신뢰됨 ({key}, {c.signature_algorithm})")

import datetime as dt
import socket
import ssl
import struct

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from headercheck import cipherprobe, tls
from headercheck.models import Status, TlsResult

NOW = dt.datetime(2026, 10, 15, tzinfo=dt.timezone.utc)


def make_cert(days_left=90, key=None, hash_alg=hashes.SHA256(), org="Test CA") -> bytes:
    key = key or ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")])
    issuer = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                        x509.NameAttribute(NameOID.COMMON_NAME, "Test Issuing CA")])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(NOW - dt.timedelta(days=30))
            .not_valid_after(NOW + dt.timedelta(days=days_left, hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.test")]), False)
            .sign(key, hash_alg))
    return cert.public_bytes(Encoding.DER)


# ---------------------------------------------------------------- certificate
def test_parse_certificate_fields():
    info = tls.parse_certificate(make_cert(90), verified=True, now=NOW)
    assert info.days_left == 90
    assert info.issuer_org == "Test CA"
    assert info.san == ["example.test"]
    assert info.key_type.startswith("EC") and info.key_bits == 256
    assert info.signature_algorithm == "sha256"


@pytest.mark.parametrize("days,score", [(90, 100), (30, 70), (10, 40), (-1, 0)])
def test_cert_expiry_scores(days, score):
    r = TlsResult("h", 443, cert=tls.parse_certificate(make_cert(days), verified=True, now=NOW))
    assert tls.check_cert_expiry(r).score == score


def test_cert_trust_untrusted_and_weak_key():
    bad = TlsResult("h", 443, cert=tls.parse_certificate(make_cert(), verified=False,
                                                         verify_error="self-signed certificate", now=NOW))
    assert tls.check_cert_trust(bad).score == 0
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    r = TlsResult("h", 443, cert=tls.parse_certificate(make_cert(key=weak), verified=True, now=NOW))
    assert tls.check_cert_trust(r).score == 50


def test_cert_trust_unverifiable_is_error():
    r = TlsResult("h", 443, cert=tls.parse_certificate(make_cert(), verified=None, now=NOW))
    assert tls.check_cert_trust(r).status is Status.ERROR


# ---------------------------------------------------------------- protocols / ciphers
@pytest.mark.parametrize("protos,score", [
    ({"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": True}, 100),
    ({"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": True, "TLSv1.3": False}, 90),
    ({"TLSv1.0": False, "TLSv1.1": True, "TLSv1.2": True, "TLSv1.3": True}, 50),
    ({"TLSv1.0": True, "TLSv1.1": True, "TLSv1.2": True, "TLSv1.3": False}, 30),
    ({"TLSv1.0": True, "TLSv1.1": False, "TLSv1.2": False, "TLSv1.3": False}, 0),
])
def test_protocol_scores(protos, score):
    assert tls.check_protocols(TlsResult("h", 443, protocols=protos)).score == score


def test_cipher_scores():
    base = {g: False for g in cipherprobe.WEAK_SUITES}
    assert tls.check_weak_ciphers(TlsResult("h", 443, weak_ciphers=base)).score == 100
    assert tls.check_weak_ciphers(TlsResult("h", 443, weak_ciphers={**base, "3DES": "X"})).score == 40
    r = tls.check_weak_ciphers(TlsResult("h", 443, weak_ciphers={**base, "3DES": "X", "RC4": "Y"}))
    assert r.score == 0 and "RC4" in r.value


def test_tls13_only_server_needs_no_cipher_probe():
    r = TlsResult("h", 443, protocols={"TLSv1.0": False, "TLSv1.1": False, "TLSv1.2": False, "TLSv1.3": True},
                  weak_ciphers={g: None for g in cipherprobe.WEAK_SUITES})
    assert tls.check_weak_ciphers(r).score == 100


def test_analyze_tls_all_error_when_nothing_collected():
    results = tls.analyze_tls(TlsResult("h", 443, error="DNS 조회 실패"))
    assert {c.status for c in results} == {Status.ERROR}
    assert all("DNS" in c.detail for c in results)


# ---------------------------------------------------------------- raw ClientHello
def test_client_hello_structure():
    hello = cipherprobe.build_client_hello("example.com", [0x0005, 0x000A], version=0x0302)
    assert hello[0] == 0x16 and hello[5] == 0x01
    assert struct.unpack("!H", hello[3:5])[0] == len(hello) - 5
    assert hello[9:11] == b"\x03\x02"
    assert b"example.com" in hello
    # cipher list sits after random(32) + session id length(1)
    p = 11 + 32 + 1
    assert hello[p:p + 2] == b"\x00\x04" and hello[p + 2:p + 6] == b"\x00\x05\x00\x0a"


def _server_flight(version: int, suite: int, cert: bytes) -> bytes:
    sh_body = struct.pack("!H", version) + b"\x00" * 32 + b"\x00" + struct.pack("!H", suite) + b"\x00"
    cert_list = len(cert).to_bytes(3, "big") + cert
    cert_body = len(cert_list).to_bytes(3, "big") + cert_list
    msgs = b"".join(t.to_bytes(1, "big") + len(b).to_bytes(3, "big") + b
                    for t, b in ((0x02, sh_body), (0x0B, cert_body), (0x0E, b"")))
    return b"\x16\x03\x03" + struct.pack("!H", len(msgs)) + msgs


class FakeSock:
    def __init__(self, data: bytes):
        self.data, self.sent = data, b""

    def sendall(self, b):
        self.sent += b

    def recv(self, n):
        out, self.data = self.data[:n], self.data[n:]
        return out

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_probe_suites_detects_accepted_weak_suite_and_cert():
    der = make_cert()
    sock = FakeSock(_server_flight(0x0303, 0x0005, der))
    hello = cipherprobe.probe_suites("h", 443, cipherprobe.WEAK_SUITES["RC4"], 5,
                                     connect=lambda *a, **k: sock)
    assert hello.suite_name == "TLS_RSA_WITH_RC4_128_SHA" and hello.cert_der == der


def test_probe_suites_alert_means_rejected():
    alert = b"\x15\x03\x03\x00\x02\x02\x28"  # fatal handshake_failure
    sock = FakeSock(alert)
    assert cipherprobe.probe_suites("h", 443, cipherprobe.WEAK_SUITES["RC4"], 5,
                                    connect=lambda *a, **k: sock) is None


def test_probe_version_requires_exact_version():
    sock = FakeSock(_server_flight(0x0303, 0xC02F, make_cert()))  # server answers TLS1.2 to a 1.0 hello
    assert cipherprobe.probe_version("h", 443, 0x0301, 5, connect=lambda *a, **k: sock) is None


# ---------------------------------------------------------------- collect_tls error paths (mocked network)
def test_collect_tls_dns_failure(monkeypatch):
    def boom(*a, **k):
        raise socket.gaierror(11001, "getaddrinfo failed")
    monkeypatch.setattr(tls.socket, "create_connection", boom)
    r = tls.collect_tls("nope.invalid")
    assert r.error.startswith("DNS 조회 실패") and r.cert is None


def test_collect_tls_handshake_failure(monkeypatch):
    def handshake_fail(*a, **k):
        raise ssl.SSLError(1, "[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] handshake failure")
    monkeypatch.setattr(tls, "_handshake", handshake_fail)
    monkeypatch.setattr(tls, "probe_version", lambda *a, **k: None)   # raw probe: server refuses too
    r = tls.collect_tls("h")
    assert r.error.startswith("TLS 핸드셰이크 실패")
    assert not any(r.protocols.values())

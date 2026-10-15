"""Raw TLS ClientHello probe (socket only, no OpenSSL involved).

Modern OpenSSL builds (3.x) ship without RC4/DES/3DES/EXPORT, so the `ssl`
module cannot even *offer* those suites. Instead we hand-build a TLS <= 1.2
ClientHello that offers only the suites of interest and read the server's
answer: a ServerHello means one of them was selected, an alert or a closed
connection means none was acceptable. The handshake is never completed, but
the server's Certificate message (plaintext in TLS <= 1.2) is captured so a
certificate can be reported even when `ssl` cannot handshake at all.
"""
from __future__ import annotations

import os
import socket
import struct
from dataclasses import dataclass

# IANA cipher suite ids grouped by weakness
WEAK_SUITES: dict[str, dict[int, str]] = {
    "NULL": {
        0x0001: "TLS_RSA_WITH_NULL_MD5", 0x0002: "TLS_RSA_WITH_NULL_SHA",
        0x003B: "TLS_RSA_WITH_NULL_SHA256", 0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
        0xC010: "TLS_ECDHE_RSA_WITH_NULL_SHA",
    },
    "Anonymous (aNULL)": {
        0x0018: "TLS_DH_anon_WITH_RC4_128_MD5", 0x001B: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
        0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA", 0x003A: "TLS_DH_anon_WITH_AES_256_CBC_SHA",
        0x00A6: "TLS_DH_anon_WITH_AES_128_GCM_SHA256", 0xC018: "TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
        0xC019: "TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
    },
    "EXPORT": {
        0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5", 0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
        0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", 0x0014: "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
        0x0062: "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA", 0x0064: "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
    },
    "RC4": {
        0x0004: "TLS_RSA_WITH_RC4_128_MD5", 0x0005: "TLS_RSA_WITH_RC4_128_SHA",
        0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", 0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    },
    "DES": {
        0x0009: "TLS_RSA_WITH_DES_CBC_SHA", 0x0012: "TLS_DHE_DSS_WITH_DES_CBC_SHA",
        0x0015: "TLS_DHE_RSA_WITH_DES_CBC_SHA",
    },
    "3DES": {
        0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x0013: "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
        0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", 0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
        0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    },
    "RSA key exchange (no PFS)": {
        0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA", 0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
        0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256", 0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
        0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    },
}

STRONG_SUITES: dict[int, str] = {
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
}

# Every suite we know: used for raw protocol-version probing
ALL_SUITES: dict[int, str] = {**STRONG_SUITES, **{k: v for g in WEAK_SUITES.values() for k, v in g.items()}}

VERSIONS = {"TLSv1.0": 0x0301, "TLSv1.1": 0x0302, "TLSv1.2": 0x0303}

_MAX_READ = 64 * 1024


@dataclass
class ServerHello:
    version: int
    suite_id: int
    suite_name: str | None
    cert_der: bytes | None = None


def build_client_hello(host: str, suites: list[int], version: int = 0x0303) -> bytes:
    def ext(ext_type: int, data: bytes) -> bytes:
        return struct.pack("!HH", ext_type, len(data)) + data

    exts = []
    try:
        name = host.encode("ascii")
        exts.append(ext(0x0000, struct.pack("!HBH", len(name) + 3, 0, len(name)) + name))
    except UnicodeEncodeError:
        pass
    groups = [0x001D, 0x0017, 0x0018, 0x0019]  # x25519, secp256r1, secp384r1, secp521r1
    sig_algs = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201]
    exts += [
        ext(0x000A, struct.pack("!H", 2 * len(groups)) + b"".join(struct.pack("!H", g) for g in groups)),
        ext(0x000B, b"\x01\x00"),  # ec_point_formats: uncompressed
        ext(0x000D, struct.pack("!H", 2 * len(sig_algs)) + b"".join(struct.pack("!H", s) for s in sig_algs)),
        ext(0xFF01, b"\x00"),  # renegotiation_info
    ]
    extensions = b"".join(exts)
    cipher_bytes = b"".join(struct.pack("!H", s) for s in suites)
    body = (
        struct.pack("!H", version) + os.urandom(32) + b"\x00"  # version, random, empty session id
        + struct.pack("!H", len(cipher_bytes)) + cipher_bytes
        + b"\x01\x00"  # compression: null
        + struct.pack("!H", len(extensions)) + extensions
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def parse_handshake_messages(buf: bytes) -> list[tuple[int, bytes]]:
    """Split concatenated handshake-record payloads into (type, body) messages."""
    msgs, p = [], 0
    while p + 4 <= len(buf):
        mtype, mlen = buf[p], int.from_bytes(buf[p + 1:p + 4], "big")
        if p + 4 + mlen > len(buf):
            break
        msgs.append((mtype, buf[p + 4:p + 4 + mlen]))
        p += 4 + mlen
    return msgs


def parse_server_hello(body: bytes) -> tuple[int, int] | None:
    """ServerHello body -> (server_version, cipher_suite)."""
    p = 2 + 32
    if len(body) < p + 1:
        return None
    p += 1 + body[p]  # session id
    if len(body) < p + 2:
        return None
    return struct.unpack("!H", body[:2])[0], struct.unpack("!H", body[p:p + 2])[0]


def parse_first_certificate(body: bytes) -> bytes | None:
    """Certificate message body (TLS <= 1.2) -> leaf certificate DER."""
    if len(body) < 6:
        return None
    first_len = int.from_bytes(body[3:6], "big")
    der = body[6:6 + first_len]
    return der if len(der) == first_len else None


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def read_server_flight(sock: socket.socket) -> ServerHello | None:
    """Read records until ServerHelloDone / alert / EOF. None if no ServerHello."""
    hs_buf, hello, cert, total = b"", None, None, 0
    while total < _MAX_READ:
        try:
            header = _recv_exact(sock, 5)
            if len(header) < 5:
                break
            ctype, length = header[0], struct.unpack("!H", header[3:5])[0]
            payload = _recv_exact(sock, length)
        except (ConnectionResetError, ConnectionAbortedError, TimeoutError, socket.timeout):
            break
        total += 5 + len(payload)
        if ctype != 0x16:  # alert or anything else: stop
            break
        hs_buf += payload
        done = False
        for mtype, body in parse_handshake_messages(hs_buf):
            if mtype == 0x02 and hello is None:
                hello = parse_server_hello(body)
            elif mtype == 0x0B and cert is None:
                cert = parse_first_certificate(body)
            elif mtype == 0x0E:  # ServerHelloDone
                done = True
        if hello is None and len(hs_buf) > 4 and hs_buf[0] != 0x02:
            break
        if done or (hello and cert):
            break
    if hello is None:
        return None
    return ServerHello(version=hello[0], suite_id=hello[1], suite_name=ALL_SUITES.get(hello[1]), cert_der=cert)


def raw_handshake(host: str, port: int, suites: dict[int, str], timeout: float, version: int = 0x0303,
                  connect=socket.create_connection) -> ServerHello | None:
    """Send one ClientHello. Raises OSError on TCP-level failure (caller marks untestable)."""
    with connect((host, port), timeout=timeout) as sock:
        sock.sendall(build_client_hello(host, list(suites), version))
        return read_server_flight(sock)


def probe_suites(host: str, port: int, suites: dict[int, str], timeout: float,
                 connect=socket.create_connection) -> ServerHello | None:
    """ServerHello if the server selected one of `suites`, else None."""
    hello = raw_handshake(host, port, suites, timeout, connect=connect)
    if hello is None or hello.suite_id not in suites:
        return None
    return hello


def probe_version(host: str, port: int, version: int, timeout: float,
                  connect=socket.create_connection) -> ServerHello | None:
    """ServerHello if the server accepted exactly `version` (TLS 1.0-1.2)."""
    hello = raw_handshake(host, port, ALL_SUITES, timeout, version, connect=connect)
    if hello is None or hello.version != version:
        return None
    return hello

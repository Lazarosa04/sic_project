from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from common.cert_utils import parse_and_validate_peer_certificate


def _canonical_json_bytes(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


@dataclass
class PeerIdentity:
    nid: str
    cert: x509.Certificate
    is_sink: bool


@dataclass
class E2ESession:
    peer_nid: str
    client_id: int
    key: bytes  # 32 bytes
    send_seq: int = 0
    recv_max_seq: int = -1


# =====================
# Handshake (DTLS-like)
# =====================


def build_e2e_hello1(
    our_cert_pem: bytes,
    our_private_key: ec.EllipticCurvePrivateKey,
    client_id: int,
) -> Tuple[Dict[str, Any], ec.EllipticCurvePrivateKey, bytes]:
    """ClientHello equivalent.

    Signed proof-of-possession over (eph_pub, nonce, client_id).
    """
    eph_priv = ec.generate_private_key(ec.SECP521R1())
    eph_pub = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    nonce_a = os.urandom(16)

    to_sign = b"SIC-E2E-HELLO1" + eph_pub + nonce_a + int(client_id).to_bytes(4, "big")
    sig = our_private_key.sign(to_sign, ec.ECDSA(hashes.SHA256()))

    msg = {
        "type": "E2E_HELLO1",
        "client_id": int(client_id),
        "cert_pem_b64": _b64e(our_cert_pem),
        "eph_pub_b64": _b64e(eph_pub),
        "nonce_b64": _b64e(nonce_a),
        "sig_b64": _b64e(sig),
    }
    return msg, eph_priv, nonce_a


def build_e2e_hello2(
    our_cert_pem: bytes,
    our_private_key: ec.EllipticCurvePrivateKey,
    client_id: int,
    peer_eph_pub: bytes,
    peer_nonce: bytes,
) -> Tuple[Dict[str, Any], ec.EllipticCurvePrivateKey, bytes]:
    """ServerHello equivalent."""
    eph_priv = ec.generate_private_key(ec.SECP521R1())
    eph_pub = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    nonce_b = os.urandom(16)

    to_sign = (
        b"SIC-E2E-HELLO2"
        + peer_eph_pub
        + peer_nonce
        + eph_pub
        + nonce_b
        + int(client_id).to_bytes(4, "big")
    )
    sig = our_private_key.sign(to_sign, ec.ECDSA(hashes.SHA256()))

    msg = {
        "type": "E2E_HELLO2",
        "client_id": int(client_id),
        "cert_pem_b64": _b64e(our_cert_pem),
        "eph_pub_b64": _b64e(eph_pub),
        "nonce_b64": _b64e(nonce_b),
        "sig_b64": _b64e(sig),
    }
    return msg, eph_priv, nonce_b


def _parse_handshake_fields(msg: Dict[str, Any]) -> Optional[Tuple[int, bytes, bytes, bytes, bytes]]:
    try:
        client_id = int(msg["client_id"])
        cert_pem = _b64d(msg["cert_pem_b64"])
        eph_pub = _b64d(msg["eph_pub_b64"])
        nonce = _b64d(msg["nonce_b64"])
        sig = _b64d(msg["sig_b64"])
        return client_id, cert_pem, eph_pub, nonce, sig
    except Exception:
        return None


def validate_hello1(msg: Dict[str, Any], ca_cert: x509.Certificate) -> Optional[Tuple[str, int, bytes, bytes]]:
    if msg.get("type") != "E2E_HELLO1":
        return None
    parsed = _parse_handshake_fields(msg)
    if not parsed:
        return None
    client_id, cert_pem, eph_pub, nonce_a, sig = parsed

    peer = parse_and_validate_peer_certificate(cert_pem, ca_cert)
    if not peer:
        return None

    peer_pub = peer.cert.public_key()
    if not isinstance(peer_pub, ec.EllipticCurvePublicKey):
        return None

    try:
        to_verify = b"SIC-E2E-HELLO1" + eph_pub + nonce_a + int(client_id).to_bytes(4, "big")
        peer_pub.verify(sig, to_verify, ec.ECDSA(hashes.SHA256()))
    except Exception:
        return None

    return peer.nid, client_id, eph_pub, nonce_a


def validate_hello2(
    msg: Dict[str, Any],
    ca_cert: x509.Certificate,
    expected_client_id: int,
    expected_peer_eph_pub: bytes,
    expected_peer_nonce: bytes,
) -> Optional[Tuple[str, int, bytes, bytes]]:
    if msg.get("type") != "E2E_HELLO2":
        return None
    parsed = _parse_handshake_fields(msg)
    if not parsed:
        return None
    client_id, cert_pem, eph_pub_b, nonce_b, sig = parsed

    if int(client_id) != int(expected_client_id):
        return None

    peer = parse_and_validate_peer_certificate(cert_pem, ca_cert)
    if not peer:
        return None

    peer_pub = peer.cert.public_key()
    if not isinstance(peer_pub, ec.EllipticCurvePublicKey):
        return None

    try:
        to_verify = (
            b"SIC-E2E-HELLO2"
            + expected_peer_eph_pub
            + expected_peer_nonce
            + eph_pub_b
            + nonce_b
            + int(client_id).to_bytes(4, "big")
        )
        peer_pub.verify(sig, to_verify, ec.ECDSA(hashes.SHA256()))
    except Exception:
        return None

    return peer.nid, client_id, eph_pub_b, nonce_b


def derive_e2e_key(
    our_eph_priv: ec.EllipticCurvePrivateKey,
    peer_eph_pub_bytes: bytes,
    nonce_a: bytes,
    nonce_b: bytes,
    client_id: int,
) -> bytes:
    peer_eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP521R1(), peer_eph_pub_bytes)
    shared = our_eph_priv.exchange(ec.ECDH(), peer_eph_pub)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=nonce_a + nonce_b,
        info=b"SIC-E2E-SESSION-KEY" + int(client_id).to_bytes(4, "big"),
    )
    return hkdf.derive(shared)


# =====================
# Record layer (AEAD)
# =====================


def wrap_e2e_record(session: E2ESession, plaintext_obj: Dict[str, Any]) -> Dict[str, Any]:
    session.send_seq += 1
    seq = session.send_seq

    plaintext = _canonical_json_bytes(plaintext_obj)
    nonce = os.urandom(12)

    aad = _canonical_json_bytes({"client_id": session.client_id, "seq": seq})
    aesgcm = AESGCM(session.key)
    ct = aesgcm.encrypt(nonce, plaintext, aad)

    return {
        "type": "E2E_RECORD",
        "client_id": int(session.client_id),
        "seq": int(seq),
        "nonce_b64": _b64e(nonce),
        "ct_b64": _b64e(ct),
    }


def unwrap_e2e_record(session: E2ESession, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if record.get("type") != "E2E_RECORD":
        return None

    try:
        client_id = int(record["client_id"])
        seq = int(record["seq"])
        nonce = _b64d(record["nonce_b64"])
        ct = _b64d(record["ct_b64"])
    except Exception:
        return None

    if client_id != int(session.client_id):
        return None

    if seq <= session.recv_max_seq:
        return None

    aad = _canonical_json_bytes({"client_id": client_id, "seq": seq})

    try:
        aesgcm = AESGCM(session.key)
        pt = aesgcm.decrypt(nonce, ct, aad)
    except Exception:
        return None

    try:
        obj = json.loads(pt.decode("utf-8"))
        if not isinstance(obj, dict):
            return None
    except Exception:
        return None

    session.recv_max_seq = seq
    return obj

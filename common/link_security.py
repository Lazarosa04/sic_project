from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from common.cert_utils import parse_and_validate_peer_certificate


def _canonical_json_bytes(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


@dataclass
class LinkSession:
    peer_nid: str
    key: bytes  # 32 bytes
    send_seq: int = 0
    recv_max_seq: int = -1


# =====================
# Mutual authentication
# =====================


def build_link_auth1(our_cert_pem: bytes, our_private_key: ec.EllipticCurvePrivateKey) -> Tuple[Dict[str, Any], ec.EllipticCurvePrivateKey, bytes]:
    """Create AUTH1 message + ephemeral key + nonce.

    The receiver validates the certificate with CA and verifies signature proof-of-possession.
    """
    eph_priv = ec.generate_private_key(ec.SECP521R1())
    eph_pub = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    nonce_a = os.urandom(16)

    to_sign = b"SIC-LINK-AUTH1" + eph_pub + nonce_a
    sig = our_private_key.sign(to_sign, ec.ECDSA(hashes.SHA256()))

    msg = {
        "type": "LINK_AUTH1",
        "cert_pem_b64": _b64e(our_cert_pem),
        "eph_pub_b64": _b64e(eph_pub),
        "nonce_b64": _b64e(nonce_a),
        "sig_b64": _b64e(sig),
    }
    return msg, eph_priv, nonce_a


def build_link_auth2(
    our_cert_pem: bytes,
    our_private_key: ec.EllipticCurvePrivateKey,
    peer_eph_pub: bytes,
    peer_nonce: bytes,
) -> Tuple[Dict[str, Any], ec.EllipticCurvePrivateKey, bytes]:
    eph_priv = ec.generate_private_key(ec.SECP521R1())
    eph_pub = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )
    nonce_b = os.urandom(16)

    to_sign = b"SIC-LINK-AUTH2" + peer_eph_pub + peer_nonce + eph_pub + nonce_b
    sig = our_private_key.sign(to_sign, ec.ECDSA(hashes.SHA256()))

    msg = {
        "type": "LINK_AUTH2",
        "cert_pem_b64": _b64e(our_cert_pem),
        "eph_pub_b64": _b64e(eph_pub),
        "nonce_b64": _b64e(nonce_b),
        "sig_b64": _b64e(sig),
    }
    return msg, eph_priv, nonce_b


def _parse_auth_message_fields(msg: Dict[str, Any]) -> Optional[Tuple[bytes, bytes, bytes, bytes]]:
    try:
        cert_pem = _b64d(msg["cert_pem_b64"])
        eph_pub = _b64d(msg["eph_pub_b64"])
        nonce = _b64d(msg["nonce_b64"])
        sig = _b64d(msg["sig_b64"])
        return cert_pem, eph_pub, nonce, sig
    except Exception:
        return None


def validate_auth1(msg: Dict[str, Any], ca_cert: x509.Certificate) -> Optional[Tuple[str, ec.EllipticCurvePublicKey, bytes, bytes]]:
    if msg.get("type") != "LINK_AUTH1":
        return None
    parsed = _parse_auth_message_fields(msg)
    if not parsed:
        return None
    cert_pem, eph_pub, nonce_a, sig = parsed

    peer = parse_and_validate_peer_certificate(cert_pem, ca_cert)
    if not peer:
        return None

    peer_pub = peer.cert.public_key()
    if not isinstance(peer_pub, ec.EllipticCurvePublicKey):
        return None

    try:
        to_verify = b"SIC-LINK-AUTH1" + eph_pub + nonce_a
        peer_pub.verify(sig, to_verify, ec.ECDSA(hashes.SHA256()))
    except Exception:
        return None

    return peer.nid, peer_pub, eph_pub, nonce_a


def validate_auth2(
    msg: Dict[str, Any],
    ca_cert: x509.Certificate,
    expected_peer_eph_pub: bytes,
    expected_peer_nonce: bytes,
) -> Optional[Tuple[str, ec.EllipticCurvePublicKey, bytes, bytes]]:
    if msg.get("type") != "LINK_AUTH2":
        return None
    parsed = _parse_auth_message_fields(msg)
    if not parsed:
        return None
    cert_pem, eph_pub_b, nonce_b, sig = parsed

    peer = parse_and_validate_peer_certificate(cert_pem, ca_cert)
    if not peer:
        return None

    peer_pub = peer.cert.public_key()
    if not isinstance(peer_pub, ec.EllipticCurvePublicKey):
        return None

    try:
        to_verify = b"SIC-LINK-AUTH2" + expected_peer_eph_pub + expected_peer_nonce + eph_pub_b + nonce_b
        peer_pub.verify(sig, to_verify, ec.ECDSA(hashes.SHA256()))
    except Exception:
        return None

    return peer.nid, peer_pub, eph_pub_b, nonce_b


def derive_link_key(our_eph_priv: ec.EllipticCurvePrivateKey, peer_eph_pub_bytes: bytes, nonce_a: bytes, nonce_b: bytes) -> bytes:
    peer_eph_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP521R1(), peer_eph_pub_bytes)
    shared = our_eph_priv.exchange(ec.ECDH(), peer_eph_pub)

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=nonce_a + nonce_b,
        info=b"SIC-LINK-SESSION-KEY",
    )
    return hkdf.derive(shared)


# =====================
# Link MAC + anti-replay
# =====================


def wrap_link_secure(session: LinkSession, link_sender_nid: str, inner_message: Dict[str, Any]) -> Dict[str, Any]:
    session.send_seq += 1
    seq = session.send_seq

    payload_bytes = _canonical_json_bytes(inner_message)

    header = {
        "type": "LINK_SECURE",
        "link_sender_nid": link_sender_nid,
        "seq": seq,
        "payload_b64": _b64e(payload_bytes),
    }

    mac = hmac.HMAC(session.key, hashes.SHA256())
    mac.update(_canonical_json_bytes(header))
    tag = mac.finalize()

    header["mac_b64"] = _b64e(tag)
    return header


def unwrap_link_secure(session: LinkSession, secure_msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if secure_msg.get("type") != "LINK_SECURE":
        return None

    try:
        seq = int(secure_msg["seq"])
        payload_bytes = _b64d(secure_msg["payload_b64"])
        tag = _b64d(secure_msg["mac_b64"])
    except Exception:
        return None

    # Replay protection: strictly increasing per direction (simplest strategy).
    if seq <= session.recv_max_seq:
        return None

    header_for_mac = {
        "type": "LINK_SECURE",
        "link_sender_nid": secure_msg.get("link_sender_nid"),
        "seq": seq,
        "payload_b64": secure_msg.get("payload_b64"),
    }

    try:
        mac = hmac.HMAC(session.key, hashes.SHA256())
        mac.update(_canonical_json_bytes(header_for_mac))
        mac.verify(tag)
    except Exception:
        return None

    try:
        inner = json.loads(payload_bytes.decode("utf-8"))
        if not isinstance(inner, dict):
            return None
    except Exception:
        return None

    session.recv_max_seq = seq
    return inner

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


@dataclass(frozen=True)
class ParsedPeerCertificate:
    cert: x509.Certificate
    nid: str
    is_sink: bool


def extract_nid_from_certificate(cert: x509.Certificate) -> Optional[str]:
    try:
        nid_attribute = cert.subject.get_attributes_for_oid(NameOID.USER_ID)[-1]
        nid_value = nid_attribute.value
        if isinstance(nid_value, str) and nid_value:
            return nid_value
    except Exception:
        return None
    return None


def certificate_subject_ou(cert: x509.Certificate) -> Optional[str]:
    try:
        ou = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)[-1]
        return ou.value
    except Exception:
        return None


def is_sink_certificate(cert: x509.Certificate) -> bool:
    # Minimal interpretation of the statement's “Sink-identifying subject field”:
    # treat OU == "Sink" as the sink marker.
    return certificate_subject_ou(cert) == "Sink"


def verify_certificate_signed_by_ca(cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
    """Best-effort CA signature verification.

    This validates that `cert` was issued by `ca_cert` by verifying the signature.
    It does not implement full PKIX path validation.
    """
    try:
        if cert.issuer != ca_cert.subject:
            return False

        ca_public_key = ca_cert.public_key()
        # CA and leaf keys are expected to be EC keys in this project.
        if not isinstance(ca_public_key, ec.EllipticCurvePublicKey):
            return False

        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            ec.ECDSA(cert.signature_hash_algorithm),
        )
        return True
    except Exception:
        return False


def parse_and_validate_peer_certificate(pem_bytes: bytes, ca_cert: x509.Certificate) -> Optional[ParsedPeerCertificate]:
    try:
        cert = x509.load_pem_x509_certificate(pem_bytes)
    except Exception:
        return None

    nid = extract_nid_from_certificate(cert)
    if not nid:
        return None

    if not verify_certificate_signed_by_ca(cert, ca_cert):
        return None

    return ParsedPeerCertificate(cert=cert, nid=nid, is_sink=is_sink_certificate(cert))

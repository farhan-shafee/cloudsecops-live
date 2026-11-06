"""Fixed AWS CloudTrail RSA verification with independently pinned supplied keys."""

from __future__ import annotations

import re
from hashlib import sha256

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from cloudsecops_live.errors import EvidenceError
from cloudsecops_live.integrations.aws_cloudtrail.signed.contracts import SuppliedKey
from cloudsecops_live.integrations.aws_cloudtrail.signed.parsing import Digest, hex_text, utc


def key_bundle(
    keys: tuple[SuppliedKey, ...], region: str
) -> dict[str, tuple[SuppliedKey, rsa.RSAPublicKey]]:
    if type(keys) is not tuple or not 1 <= len(keys) <= 16:
        raise EvidenceError("AWS4B_KEY")
    result: dict[str, tuple[SuppliedKey, rsa.RSAPublicKey]] = {}
    for key in keys:
        if (
            type(key) is not SuppliedKey
            or not isinstance(key.fingerprint, str)
            or re.fullmatch(r"[0-9a-f]{16,128}", key.fingerprint) is None
            or key.fingerprint in result
            or key.region != region
            or not utc(key.valid_from) < utc(key.valid_until)
            or type(key.der) is not bytes
            or not 128 <= len(key.der) <= 2048
            or sha256(key.der).hexdigest() != hex_text(key.der_sha256)
        ):
            raise EvidenceError("AWS4B_KEY")
        try:
            public = serialization.load_der_public_key(key.der)
        except (ValueError, UnsupportedAlgorithm):
            raise EvidenceError("AWS4B_KEY") from None
        if (
            not isinstance(public, rsa.RSAPublicKey)
            or public.key_size not in (2048, 3072, 4096)
            or public.public_numbers().e != 65537
        ):
            raise EvidenceError("AWS4B_KEY")
        # Exact DER custody supports AWS PKCS#1 and documented SPKI examples, not
        # a permissive decoder accepting ignored trailing bytes or private keys.
        encodings = (
            public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1),
            public.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            ),
        )
        if key.der not in encodings:
            raise EvidenceError("AWS4B_KEY")
        result[key.fingerprint] = key, public
    return result


def verify_signature(digest: Digest, keys: dict[str, tuple[SuppliedKey, rsa.RSAPublicKey]]) -> None:
    selected = keys.get(digest.fingerprint)
    if selected is None:
        raise EvidenceError("AWS4B_KEY")
    key, public = selected
    if not key.valid_from <= digest.key_time <= key.valid_until:
        raise EvidenceError("AWS4B_KEY_VALIDITY")
    previous = digest.previous[3] if digest.previous is not None else "null"
    data = (
        digest.end_text
        + "\n"
        + digest.obj.reference.bucket
        + "/"
        + digest.obj.reference.key
        + "\n"
        + digest.content_sha256
        + "\n"
        + previous
    ).encode("utf-8")
    signature = bytes.fromhex(digest.signature)
    if len(signature) != public.key_size // 8:
        raise EvidenceError("AWS4B_SIGNATURE")
    try:
        # SHA256withRSA hashes the exact signing bytes once, then PKCS#1 v1.5.
        public.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise EvidenceError("AWS4B_SIGNATURE") from None

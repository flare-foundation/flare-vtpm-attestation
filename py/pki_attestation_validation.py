import base64
import hashlib
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.exceptions import ExpiredSignatureError
from OpenSSL.crypto import X509, X509Store, X509StoreContext, X509StoreContextError

from utils import AttestationToken, get_unverified_token

# ——— Configuration & Logging ———
# Leeway is added to prevent certificate expiration issues
# This is FOR TESTING ONLY
# In prod, this will be set to 0 or a very small value
LEEWAY: Final[timedelta] = timedelta(days=365)
AUD: Final[str] = "https://sts.google.com"
REQUIRED_ALGO: Final[str] = "RS256"
REQUIRED_HASH: Final[str] = "sha256"
REQUIRED_CERT_COUNT: Final[int] = 3

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger(__name__)


# ——— Exceptions ———
class PKIValidationError(Exception):
    pass


class CertificateParsingError(PKIValidationError):
    pass


class SignatureValidationError(PKIValidationError):
    pass


class ChainValidationError(PKIValidationError):
    pass


# ——— Data Model ———
@dataclass(frozen=True)
class PKICertificates:
    leaf: x509.Certificate
    intermediate: x509.Certificate
    root: x509.Certificate


# ——— Validator ———
class PKIValidator:
    def __init__(self, trusted_root: x509.Certificate) -> None:
        self.trusted_root = trusted_root

    def validate(self, token: str) -> dict[str, Any]:
        unverified_token = get_unverified_token(token)
        self._print_token(unverified_token)
        certs = self._load_certs(unverified_token.header.x5c)
        self._check_validity(certs)
        self._verify_chain(certs)
        return self._verify_signature(token, certs.leaf)

    def _print_token(self, token: AttestationToken) -> None:
        log.info("=== Unverified Token ===")
        log.info("===== Header =====")
        print(token.header.model_dump_json(indent=2))
        log.info("===== Payload =====")
        print(token.payload.model_dump_json(indent=2))
        log.info("===== Signature =====")
        print(token.signature)

    def _load_certs(self, x5c_list: list[str] | None) -> PKICertificates:
        if not isinstance(x5c_list, list) or len(x5c_list) != REQUIRED_CERT_COUNT:
            raise CertificateParsingError(
                f"x5c must be list of {REQUIRED_CERT_COUNT} certs"
            )
        try:
            decoded = [self._decode_der(cert) for cert in x5c_list]
            return PKICertificates(*decoded)
        except Exception as e:
            raise CertificateParsingError(f"Failed to parse x5c: {e}") from e

    @staticmethod
    def _decode_der(pem_b64: str) -> x509.Certificate:
        b64 = re.sub(
            r"-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+", "", pem_b64
        )
        der = base64.b64decode(b64)
        return x509.load_der_x509_certificate(der)

    def _check_validity(self, certs: PKICertificates) -> None:
        now = datetime.now(UTC)
        for name, cert in (
            ("leaf", certs.leaf),
            ("intermediate", certs.intermediate),
            ("root", certs.root),
        ):
            # Use UTC aware properties
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
            if now < not_before:
                log.exception(
                    f"{name.capitalize()} cert not valid until {not_before.isoformat()}"
                )
            if now > not_after:
                log.exception(
                    f"{name.capitalize()} cert expired at {not_after.isoformat()}"
                )

            # Additional leaf checks
            if name == "leaf":
                algo = cert.signature_hash_algorithm
                if not isinstance(cert.public_key(), rsa.RSAPublicKey):
                    raise SignatureValidationError("Leaf public key is not RSA")
                if algo is None or algo.name != REQUIRED_HASH:
                    raise SignatureValidationError(
                        f"Leaf signed with {algo.name if algo else None},"
                        f"expected {REQUIRED_HASH}"
                    )

    def _verify_chain(self, certs: PKICertificates) -> None:
        store = X509Store()
        store.add_cert(X509.from_cryptography(self.trusted_root))
        store.add_cert(X509.from_cryptography(certs.intermediate))
        ctx = X509StoreContext(store, X509.from_cryptography(certs.leaf))
        try:
            ctx.verify_certificate()
        except X509StoreContextError as err:
            log.error("Certificate chain verification failed: %s", err.errors[2]) # noqa: TRY400

        # Fingerprint match
        fp_prov = hashlib.sha256(certs.root.tbs_certificate_bytes).digest()
        fp_trust = hashlib.sha256(self.trusted_root.tbs_certificate_bytes).digest()
        if fp_prov != fp_trust:
            log.error("Root certificate fingerprint mismatch")

    def _verify_signature(self, token: str, leaf: x509.Certificate) -> dict[str, Any]:
        pubkey = leaf.public_key()
        pem = pubkey.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        try:
            return jwt.decode(
                token, key=pem, algorithms=[REQUIRED_ALGO], leeway=LEEWAY, audience=AUD
            )
        except ExpiredSignatureError as e:
            msg = "Signature verification failed"
            raise SignatureValidationError(msg) from e


# ——— CLI Entrypoint ———
def main(token_file: Path, root_file: Path) -> None:
    root = x509.load_pem_x509_certificate(root_file.read_bytes())
    validator = PKIValidator(root)
    token = token_file.read_text().strip()

    try:
        validator.validate(token)
        log.info("Validation complete.")
    except PKIValidationError as e:
        log.exception("Validation failed: %s")
        raise SystemExit(1) from e


if __name__ == "__main__":
    import sys

    tpath = Path(sys.argv[1] if len(sys.argv) > 1 else "data/pki.txt")
    rpath = Path(sys.argv[2] if len(sys.argv) > 2 else "data/root_cert.pem")
    main(tpath, rpath)

"""Ed25519 signing for enterprise audit integrity.

Optional feature — requires the 'signing' extra:
    pip install antihero[signing]

Provides non-repudiation for audit events via Ed25519 signatures.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass


class Signer:
    """Ed25519 signer for audit events.

    Args:
        seed: Optional 32-byte seed for deterministic key generation.
              If None, a random key is generated.
    """

    def __init__(self, seed: bytes | None = None) -> None:
        try:
            from nacl.signing import SigningKey
        except ImportError as exc:
            raise ImportError(
                "Ed25519 signing requires the 'signing' extra: "
                "pip install antihero[signing]"
            ) from exc

        self._signing_key = SigningKey(seed) if seed else SigningKey.generate()

    @property
    def public_key_hex(self) -> str:
        """Hex-encoded Ed25519 public key."""
        return bytes(self._signing_key.verify_key).hex()

    def sign(self, message: bytes) -> str:
        """Sign a message. Returns hex-encoded signature."""
        signed = self._signing_key.sign(message)
        return signed.signature.hex()


class Verifier:
    """Ed25519 signature verifier.

    Args:
        public_key_hex: Hex-encoded Ed25519 public key.
    """

    def __init__(self, public_key_hex: str) -> None:
        try:
            from nacl.signing import VerifyKey
        except ImportError as exc:
            raise ImportError(
                "Ed25519 verification requires the 'signing' extra: "
                "pip install antihero[signing]"
            ) from exc

        self._verify_key = VerifyKey(bytes.fromhex(public_key_hex))

    def verify(self, message: bytes, signature_hex: str) -> bool:
        """Verify a signature. Returns True if valid, False if invalid."""
        try:
            self._verify_key.verify(message, bytes.fromhex(signature_hex))
            return True
        except Exception:
            return False

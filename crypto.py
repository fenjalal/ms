"""
crypto.py

All cryptographic primitives for the application.

Design notes (deliberately conservative):

* No hand-rolled cryptography. Everything here is a thin wrapper over
  libsodium via PyNaCl, which is a well-reviewed implementation.
* Message confidentiality + sender authentication come from NaCl's `Box`
  (X25519 key exchange + XSalsa20-Poly1305 AEAD). Because Box is
  authenticated, a successfully decrypted message proves it was produced by
  the holder of the sender's private key - there is no separate signature to
  get wrong.
* Local storage is encrypted with `SecretBox` using a key derived from the
  user's passphrase with Argon2id, so an attacker with the disk file still
  needs the passphrase.
* Tor onion services already provide an encrypted, authenticated transport.
  This layer sits on top of it so that a compromised or malicious Tor
  relay - or a future flaw in the transport - still cannot read message
  contents. Defence in depth, not a replacement for Tor.
"""

from __future__ import annotations

import base64
import hashlib

from nacl import pwhash, secret, utils
from nacl.exceptions import CryptoError
from nacl.public import Box, PrivateKey, PublicKey


class DecryptionError(Exception):
    """Raised when a payload cannot be decrypted or fails authentication."""


# --------------------------------------------------------------------------- #
# Encoding helpers
# --------------------------------------------------------------------------- #

def b64encode(raw: bytes) -> str:
    """URL-safe base64 without padding, so keys stay copy-paste friendly."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + padding)


# --------------------------------------------------------------------------- #
# Identity keys
# --------------------------------------------------------------------------- #

def fingerprint(public_key_b64: str) -> str:
    """
    A short, human-readable fingerprint of a public key.

    Two people compare this out of band - read it aloud on a call, or check it
    in person - to confirm they hold each other's real key and not an
    attacker's. Comparing 20 hex characters is realistic for humans; comparing
    a full 43-character base64 key is not, and people skip it.

    80 bits of SHA-256 output. Finding two keys with the same fingerprint
    needs roughly 2^40 work, which is far beyond what a man-in-the-middle can
    do while a conversation is being set up.
    """
    raw = b64decode(public_key_b64)
    digest = hashlib.sha256(raw).digest()[:10]  # 80 bits
    hex_digest = digest.hex().upper()
    return " ".join(hex_digest[i:i + 4] for i in range(0, len(hex_digest), 4))


def onion_short_id(onion: str) -> str:
    """
    A short, non-reversible identifier derived from an onion address, for
    log lines and diagnostics where the full onion must never appear.

    This is a one-way hash truncated to 8 hex characters - it lets repeated
    events from the same peer look the same in a log ("peer=A1B2C3D4" shows
    up twice), which is useful for correlating activity, without the log
    itself ever containing something that identifies where to connect. Not
    the same thing as a contact's public-key fingerprint (see
    vault.short_id): that one exists to be read aloud and compared by two
    people; this one exists purely so the onion never has to be logged.
    """
    digest = hashlib.sha256(onion.encode("utf-8")).hexdigest().upper()
    return digest[:8]


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a new X25519 keypair. Returns (private_bytes, public_bytes)."""
    private = PrivateKey.generate()
    return bytes(private), bytes(private.public_key)


def public_key_from_private(private_bytes: bytes) -> bytes:
    return bytes(PrivateKey(private_bytes).public_key)


# --------------------------------------------------------------------------- #
# Message encryption (to/from a contact)
# --------------------------------------------------------------------------- #

def encrypt_for(plaintext: bytes, my_private: bytes, their_public: bytes) -> bytes:
    """
    Encrypt a message so only the holder of `their_public`'s private key can
    read it, authenticated as coming from `my_private`.
    """
    box = Box(PrivateKey(my_private), PublicKey(their_public))
    return box.encrypt(plaintext)


def decrypt_from(ciphertext: bytes, my_private: bytes, their_public: bytes) -> bytes:
    """
    Decrypt a message from `their_public`. Raises DecryptionError if the
    message was tampered with or was not produced by that sender.
    """
    box = Box(PrivateKey(my_private), PublicKey(their_public))
    try:
        return box.decrypt(ciphertext)
    except CryptoError as exc:
        raise DecryptionError("Message failed authentication or could not be decrypted.") from exc


# --------------------------------------------------------------------------- #
# Local storage encryption (passphrase based)
# --------------------------------------------------------------------------- #

# Argon2id parameters. "moderate" is a sensible desktop default: strong enough
# to make brute forcing a passphrase expensive without a multi-second unlock.
_KDF_OPS = pwhash.argon2id.OPSLIMIT_MODERATE
_KDF_MEM = pwhash.argon2id.MEMLIMIT_MODERATE
_SALT_BYTES = pwhash.argon2id.SALTBYTES


def new_salt() -> bytes:
    return utils.random(_SALT_BYTES)


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 32-byte storage key from a passphrase using Argon2id."""
    return pwhash.argon2id.kdf(
        secret.SecretBox.KEY_SIZE,
        passphrase.encode("utf-8"),
        salt,
        opslimit=_KDF_OPS,
        memlimit=_KDF_MEM,
    )


def encrypt_blob(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt local data at rest with a derived key."""
    return secret.SecretBox(key).encrypt(plaintext)


def decrypt_blob(ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt local data. Raises DecryptionError on a wrong passphrase or if the
    file has been modified.
    """
    try:
        return secret.SecretBox(key).decrypt(ciphertext)
    except CryptoError as exc:
        raise DecryptionError("Wrong passphrase, or the data file has been altered.") from exc

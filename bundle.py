"""
bundle.py

The shareable contact bundle: "P2PMSG1:<encoded signed payload>".

What this is: a way to share your onion address, public key, and
fingerprint as one opaque, copy/paste- and QR-friendly string, instead of
the plaintext "onionmsg:<onion>:<public key>" address the app also still
understands. The bundle is signed (Ed25519, via nacl.signing) so a
recipient can detect if a single byte of it - onion, public key, or
fingerprint - was tampered with in transit.

What this is NOT: encryption for confidentiality. A first-contact bundle
has to work for a recipient the sender has no relationship with yet, which
means there is no recipient key to encrypt to and no shared secret at
share time. Anyone who has the raw bundle text (screenshots the QR,
intercepts a copied string) can base64-decode it and read the onion,
public key, and fingerprint inside - exactly what they could already read
from today's plaintext "onionmsg:..." address. What the bundle format
actually buys:

  * the onion is not printed in the clear next to a name in the normal
    UI, so casual exposure (shoulder-surfing a contact card, a screenshot
    of the contact list, an accidental paste into the wrong window) no
    longer shows a recognizable ".onion" string at a glance
  * a bundle cannot be silently modified - flipping any byte of the onion,
    public key, or fingerprint invalidates the Ed25519 signature, so a
    tampered bundle is rejected outright rather than quietly installing a
    wrong endpoint
  * the fingerprint inside a bundle is never trusted as claimed text - the
    receiving side always recomputes it from the decoded public key, so a
    bundle cannot assert a fingerprint that does not match its own key

No custom cryptography: signing uses nacl.signing.SigningKey/VerifyKey
exactly as documented upstream (the same primitive SSH, age, and TLS
certificates use for this purpose), and the identity's existing X25519 Box
keypair and the wire message protocol are both completely untouched by
this module.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

import crypto
from transport import is_valid_onion

PREFIX = "P2PMSG1:"
VERSION = 1

# A bundle is small by nature (an onion, two 32-byte keys, a fingerprint,
# some JSON overhead). Bounded generously above realistic size so a bloated
# or adversarially-padded bundle is rejected before any parsing work -
# mirrors transport.MAX_FRAME_BYTES's role for wire frames, sized down to
# match what this payload actually needs.
MAX_BUNDLE_BYTES = 4096

_EXPECTED_KEYS = {"version", "onion", "public_key", "fingerprint", "signing_public_key"}


class BundleError(Exception):
    """Raised when a contact bundle cannot be built or is not valid.

    Deliberately one exception type for every failure mode (bad prefix,
    oversized, malformed base64/JSON, wrong key lengths, invalid onion
    shape, bad signature, unknown version) - callers only ever need to
    know "this bundle cannot be trusted," not which specific check failed,
    the same way transport.py's TransportError collapses its failure
    modes for callers.
    """


@dataclass
class BundleContact:
    """A parsed, signature-verified bundle. Not yet a vault.Contact - the
    caller still has to decide whether to accept it, same as any other
    first-contact request."""

    onion: str
    public_key: str  # base64
    fingerprint: str  # recomputed from public_key, never trusted as claimed
    signing_public_key: str  # base64


def build_bundle(
    onion: str,
    public_key_b64: str,
    signing_public_key_b64: str,
    signing_private_key_b64: str,
) -> str:
    """
    Build a shareable bundle for this identity, signed with its own signing
    key. Raises BundleError if `onion` is not a valid onion address - a
    bundle is never built around a malformed or clearnet-shaped endpoint.
    """
    if not is_valid_onion(onion):
        raise BundleError("Cannot build a bundle around an invalid onion address.")

    payload = {
        "version": VERSION,
        "onion": onion,
        "public_key": public_key_b64,
        "fingerprint": crypto.fingerprint(public_key_b64),
        "signing_public_key": signing_public_key_b64,
    }
    message = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")

    signing_key = SigningKey(crypto.b64decode(signing_private_key_b64))
    signed = signing_key.sign(message)  # SignedMessage: signature || message

    return PREFIX + crypto.b64encode(bytes(signed))


def parse_bundle(text: str) -> BundleContact:
    """
    Parse and verify a bundle produced by build_bundle().

    Raises BundleError on anything that is not a well-formed, correctly
    signed, version-1 bundle around a valid onion address - never lets a
    malformed or hostile bundle propagate an unhandled exception, and
    never returns a partially-trusted result.
    """
    text = text.strip()
    if len(text) > MAX_BUNDLE_BYTES:
        raise BundleError("Bundle is too large.")
    if not text.startswith(PREFIX):
        raise BundleError("Not a recognized contact bundle.")

    encoded = text[len(PREFIX):]
    if len(encoded) > MAX_BUNDLE_BYTES:
        raise BundleError("Bundle is too large.")

    try:
        signed_bytes = crypto.b64decode(encoded)
    except Exception as exc:
        raise BundleError("Bundle is not valid base64.") from exc

    if len(signed_bytes) > MAX_BUNDLE_BYTES:
        raise BundleError("Bundle is too large.")
    if len(signed_bytes) <= 64:  # shorter than a bare Ed25519 signature
        raise BundleError("Bundle is too short to be valid.")

    # The signing public key has to come from somewhere to verify with, and
    # a first-contact bundle is - by definition - from someone the app does
    # not know yet, so it cannot look the key up. The payload is
    # self-describing (carries its own signing_public_key), so verification
    # here is: parse the outer JSON *without trusting it*, extract the
    # claimed signing key, then verify the signature actually matches the
    # message using that key. This does not weaken anything: if the
    # signature does not verify, the parse below is discarded entirely -
    # an attacker gains nothing by putting an arbitrary signing key in an
    # unsigned or wrongly-signed blob, because verify() will simply reject
    # it. What this construction avoids is a chicken-and-egg problem, not a
    # trust decision - the actual trust decision ("do I believe this
    # identity") remains the user's, via the existing accept/block flow.
    try:
        unverified_message = signed_bytes[64:]
        unverified_payload = json.loads(unverified_message.decode("utf-8"))
    except Exception as exc:
        raise BundleError("Bundle is malformed.") from exc

    if not isinstance(unverified_payload, dict):
        raise BundleError("Bundle is malformed.")
    if set(unverified_payload.keys()) != _EXPECTED_KEYS:
        raise BundleError("Bundle has unexpected fields.")
    if unverified_payload.get("version") != VERSION:
        raise BundleError("Unsupported bundle version.")

    claimed_signing_key_b64 = unverified_payload.get("signing_public_key")
    if not isinstance(claimed_signing_key_b64, str):
        raise BundleError("Bundle is malformed.")
    try:
        signing_key_raw = crypto.b64decode(claimed_signing_key_b64)
    except Exception as exc:
        raise BundleError("Bundle signing key is not valid base64.") from exc
    if len(signing_key_raw) != 32:
        raise BundleError("Bundle signing key is the wrong length.")

    try:
        verify_key = VerifyKey(signing_key_raw)
        verified_message = verify_key.verify(signed_bytes)
    except BadSignatureError as exc:
        raise BundleError("Bundle signature does not verify - it may have been tampered with.") from exc
    except Exception as exc:
        raise BundleError("Bundle signature could not be checked.") from exc

    # Re-parse from the now-verified bytes rather than trusting the
    # unverified parse above for anything but locating the signing key -
    # everything used from here on is covered by the signature.
    payload = json.loads(verified_message.decode("utf-8"))

    onion = payload.get("onion")
    public_key_b64 = payload.get("public_key")
    if not isinstance(onion, str) or not isinstance(public_key_b64, str):
        raise BundleError("Bundle is malformed.")

    if not is_valid_onion(onion):
        raise BundleError("Bundle contains an invalid or non-Tor endpoint.")

    try:
        public_key_raw = crypto.b64decode(public_key_b64)
    except Exception as exc:
        raise BundleError("Bundle public key is not valid base64.") from exc
    if len(public_key_raw) != 32:
        raise BundleError("Bundle public key is the wrong length.")

    # The fingerprint inside the payload is never trusted as claimed text -
    # always recomputed from the verified public key, so a bundle cannot
    # assert a fingerprint that does not match its own key.
    fingerprint = crypto.fingerprint(public_key_b64)

    return BundleContact(
        onion=onion,
        public_key=public_key_b64,
        fingerprint=fingerprint,
        signing_public_key=claimed_signing_key_b64,
    )

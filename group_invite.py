"""
group_invite.py

The shareable group invitation: "P2PGRP1:<encoded signed payload>".

Models bundle.py's contact-bundle format almost exactly (same signature
scheme, same "parse untrusted, verify, then re-parse from verified bytes"
sequence, same one-exception-type discipline) - see that module's docstring
for the full rationale, which applies here unchanged. The one thing this
format adds beyond a contact bundle: a random one-time "code" and an
"expires" timestamp, because a group invitation - unlike a contact bundle,
which just introduces an identity - is meant to grant a specific, bounded
permission (join this one group) that should not remain valid forever or
be reusable an unlimited number of times.

What this buys, and what it does not (read together with vault.py's
Group.issued_invites / Vault.redeem_group_invite_locally docstrings):

  * the signature proves the invite really was issued by the group's owner
    (signed with the owner's existing Ed25519 identity key, the same key
    bundle.py already uses) - a forged or tampered invite is rejected
    outright, exactly like a tampered contact bundle
  * the "expires" timestamp is checked locally by whoever redeems the
    invite (see vault.py) - an invite past its expiry is refused
  * the "code" is what makes an invite single-use, but ONLY in the sense
    that matters given this app has no server: the group OWNER's own
    vault is the sole authority that tracks which codes it has already
    redeemed (Vault.redeem_group_invite_locally). Nothing stops someone
    from copying the raw invite text to a second person before the first
    person uses it - the owner's vault, not the invite text itself, is
    what refuses the second redemption attempt. This module only builds
    and verifies the signed envelope; it does not and cannot enforce
    single-use on its own, the same "locally-enforced, not
    cryptographically provable to others" honesty already applied to
    Contact.verified and Identity.accept_from_anyone elsewhere in this
    codebase.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

import crypto
from transport import is_valid_onion

PREFIX = "P2PGRP1:"
VERSION = 1

# Same reasoning as bundle.MAX_BUNDLE_BYTES, sized for this payload's
# slightly larger field set (adds gid/gname/code/expires to what a contact
# bundle already carries).
MAX_INVITE_BYTES = 4096

# Random enough that guessing a valid code is infeasible (128 bits), short
# enough to stay well within MAX_INVITE_BYTES alongside everything else.
CODE_BYTES = 16

_EXPECTED_KEYS = {
    "version", "gid", "gname", "code", "expires",
    "owner_onion", "owner_public_key", "owner_signing_public_key",
}


class GroupInviteError(Exception):
    """Raised when a group invite cannot be built or is not valid.

    One exception type for every failure mode, same discipline as
    bundle.BundleError - callers only need to know "this invite cannot be
    trusted," not which specific check failed.
    """


@dataclass
class GroupInvite:
    """A parsed, signature-verified invite. Not yet a vault.Group
    membership - the caller (vault.py) still has to check expiry and, on
    the owner's side, single-use redemption; this dataclass only carries
    what the signature actually covers."""

    gid: str
    gname: str
    code: str
    expires: str  # ISO-8601 UTC timestamp
    owner_onion: str
    owner_public_key: str  # base64
    owner_signing_public_key: str  # base64


def new_invite_code() -> str:
    """A fresh, unguessable one-time code for a new invite. Exposed
    separately from build_invite so callers (vault.py) can store the exact
    same code in Group.issued_invites before/while building the wire
    text, rather than parsing it back out of the built string."""
    return secrets.token_urlsafe(CODE_BYTES)


def build_invite(
    gid: str,
    gname: str,
    code: str,
    expires: str,
    owner_onion: str,
    owner_public_key_b64: str,
    owner_signing_public_key_b64: str,
    owner_signing_private_key_b64: str,
) -> str:
    """
    Build a shareable, signed invitation to group `gid`, signed with the
    owner's own identity signing key (the same key bundle.build_bundle
    already signs contact bundles with - no separate key material).

    Raises GroupInviteError if `owner_onion` is not a valid onion address -
    an invite is never built around a malformed or clearnet-shaped
    endpoint, same rule bundle.build_bundle applies.
    """
    if not is_valid_onion(owner_onion):
        raise GroupInviteError("Cannot build an invite around an invalid onion address.")

    payload = {
        "version": VERSION,
        "gid": gid,
        "gname": gname,
        "code": code,
        "expires": expires,
        "owner_onion": owner_onion,
        "owner_public_key": owner_public_key_b64,
        "owner_signing_public_key": owner_signing_public_key_b64,
    }
    message = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")

    signing_key = SigningKey(crypto.b64decode(owner_signing_private_key_b64))
    signed = signing_key.sign(message)  # SignedMessage: signature || message

    return PREFIX + crypto.b64encode(bytes(signed))


def parse_invite(text: str) -> GroupInvite:
    """
    Parse and verify an invite produced by build_invite().

    Raises GroupInviteError on anything that is not a well-formed,
    correctly signed, version-1 invite around a valid onion address -
    never lets a malformed or hostile invite propagate an unhandled
    exception, and never returns a partially-trusted result. Mirrors
    bundle.parse_bundle()'s exact verify-then-reparse sequence - see that
    function's comments for why parsing the unverified payload once, just
    to locate the signing key, does not weaken anything.

    Deliberately does NOT check `expires` or attempt any redemption/reuse
    tracking here - this module only proves who signed the invite and
    that it has not been tampered with. Expiry and single-use are checked
    by the caller (vault.py), which is the only place with access to the
    local clock and this vault's own record of which codes it has already
    redeemed.
    """
    text = text.strip()
    if len(text) > MAX_INVITE_BYTES:
        raise GroupInviteError("Invite is too large.")
    if not text.startswith(PREFIX):
        raise GroupInviteError("Not a recognized group invite.")

    encoded = text[len(PREFIX):]
    if len(encoded) > MAX_INVITE_BYTES:
        raise GroupInviteError("Invite is too large.")

    try:
        signed_bytes = crypto.b64decode(encoded)
    except Exception as exc:
        raise GroupInviteError("Invite is not valid base64.") from exc

    if len(signed_bytes) > MAX_INVITE_BYTES:
        raise GroupInviteError("Invite is too large.")
    if len(signed_bytes) <= 64:  # shorter than a bare Ed25519 signature
        raise GroupInviteError("Invite is too short to be valid.")

    try:
        unverified_message = signed_bytes[64:]
        unverified_payload = json.loads(unverified_message.decode("utf-8"))
    except Exception as exc:
        raise GroupInviteError("Invite is malformed.") from exc

    if not isinstance(unverified_payload, dict):
        raise GroupInviteError("Invite is malformed.")
    if set(unverified_payload.keys()) != _EXPECTED_KEYS:
        raise GroupInviteError("Invite has unexpected fields.")
    if unverified_payload.get("version") != VERSION:
        raise GroupInviteError("Unsupported invite version.")

    claimed_signing_key_b64 = unverified_payload.get("owner_signing_public_key")
    if not isinstance(claimed_signing_key_b64, str):
        raise GroupInviteError("Invite is malformed.")
    try:
        signing_key_raw = crypto.b64decode(claimed_signing_key_b64)
    except Exception as exc:
        raise GroupInviteError("Invite signing key is not valid base64.") from exc
    if len(signing_key_raw) != 32:
        raise GroupInviteError("Invite signing key is the wrong length.")

    try:
        verify_key = VerifyKey(signing_key_raw)
        verified_message = verify_key.verify(signed_bytes)
    except BadSignatureError as exc:
        raise GroupInviteError("Invite signature does not verify - it may have been tampered with.") from exc
    except Exception as exc:
        raise GroupInviteError("Invite signature could not be checked.") from exc

    # Re-parse from the now-verified bytes rather than trusting the
    # unverified parse above for anything but locating the signing key.
    payload = json.loads(verified_message.decode("utf-8"))

    gid = payload.get("gid")
    gname = payload.get("gname")
    code = payload.get("code")
    expires = payload.get("expires")
    owner_onion = payload.get("owner_onion")
    owner_public_key_b64 = payload.get("owner_public_key")

    if not all(isinstance(v, str) for v in (gid, gname, code, expires, owner_onion, owner_public_key_b64)):
        raise GroupInviteError("Invite is malformed.")
    if not gid or not code or not expires:
        raise GroupInviteError("Invite is malformed.")

    if not is_valid_onion(owner_onion):
        raise GroupInviteError("Invite contains an invalid or non-Tor endpoint.")

    try:
        public_key_raw = crypto.b64decode(owner_public_key_b64)
    except Exception as exc:
        raise GroupInviteError("Invite owner public key is not valid base64.") from exc
    if len(public_key_raw) != 32:
        raise GroupInviteError("Invite owner public key is the wrong length.")

    return GroupInvite(
        gid=gid,
        gname=gname,
        code=code,
        expires=expires,
        owner_onion=owner_onion,
        owner_public_key=owner_public_key_b64,
        owner_signing_public_key=claimed_signing_key_b64,
    )

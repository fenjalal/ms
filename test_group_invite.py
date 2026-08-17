"""
Tests for the shareable group invite (group_invite.py).

Mirrors test_bundle.py's structure closely, since group_invite.py mirrors
bundle.py's format and verification sequence almost exactly (see both
modules' docstrings) - same signature scheme, same tamper detection, same
one-exception-type discipline. The two properties unique to an invite
(expiry timestamp, one-time code) are NOT checked by group_invite.py itself
- they're checked by the caller (vault.py, not tested here) - so these
tests only verify that the fields round-trip correctly and that
group_invite.py refuses to invent, drop, or silently accept a tampered
expires/code field, the same way it already refuses a tampered onion/key.
"""

from __future__ import annotations

import json

import crypto
from nacl.signing import SigningKey

import group_invite as gi


results: list[tuple[str, bool]] = []


def check(label: str, condition: bool) -> None:
    results.append((label, condition))
    print(f"  {'PASS' if condition else 'FAIL'}  {label}")


def make_owner_material():
    """A fresh (onion, public_key_b64, signing_pub_b64, signing_priv_b64, SigningKey)."""
    _, pub = crypto.generate_keypair()
    pub_b64 = crypto.b64encode(pub)
    sk = SigningKey.generate()
    signing_pub_b64 = crypto.b64encode(bytes(sk.verify_key))
    signing_priv_b64 = crypto.b64encode(bytes(sk))
    onion = "".join("a" for _ in range(56)) + ".onion"
    return onion, pub_b64, signing_pub_b64, signing_priv_b64, sk


def build_raw_invite(sk: SigningKey, payload: dict) -> str:
    """Build an invite from an arbitrary payload dict, signed by `sk` -
    bypasses build_invite()'s own onion validation, for constructing
    otherwise-validly-signed invites with a bad payload."""
    message = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    signed = sk.sign(message)
    return gi.PREFIX + crypto.b64encode(bytes(signed))


def main() -> None:
    onion, pub_b64, signing_pub_b64, signing_priv_b64, sk = make_owner_material()
    gid = "11111111-1111-1111-1111-111111111111"
    gname = "Weekend Trip"
    code = gi.new_invite_code()
    expires = "2099-01-01T00:00:00+00:00"

    good_invite = gi.build_invite(
        gid, gname, code, expires, onion, pub_b64, signing_pub_b64, signing_priv_b64,
    )

    print("\nNo plaintext onion in the invite:")
    check("invite text contains no '.onion' substring", ".onion" not in good_invite)
    check("invite starts with the versioned prefix", good_invite.startswith(gi.PREFIX))

    print("\nRandom codes are actually random:")
    codes = {gi.new_invite_code() for _ in range(50)}
    check("50 generated codes are all distinct", len(codes) == 50)

    print("\nValid invite round-trips:")
    parsed = gi.parse_invite(good_invite)
    check("gid recovered exactly", parsed.gid == gid)
    check("gname recovered exactly", parsed.gname == gname)
    check("code recovered exactly", parsed.code == code)
    check("expires recovered exactly", parsed.expires == expires)
    check("owner_onion recovered exactly", parsed.owner_onion == onion)
    check("owner_public_key recovered exactly", parsed.owner_public_key == pub_b64)
    check("owner_signing_public_key recovered exactly", parsed.owner_signing_public_key == signing_pub_b64)

    print("\nTamper detection (gid substitution - stealing an invite for a different group):")
    decoded = crypto.b64decode(good_invite[len(gi.PREFIX):])
    message = decoded[64:]
    payload = json.loads(message.decode("utf-8"))
    tampered_payload = dict(payload)
    tampered_payload["gid"] = "22222222-2222-2222-2222-222222222222"
    new_message = json.dumps(tampered_payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    forged_bytes = decoded[:64] + new_message  # old signature, new message
    forged = gi.PREFIX + crypto.b64encode(forged_bytes)
    try:
        gi.parse_invite(forged)
        check("gid substitution detected", False)
    except gi.GroupInviteError:
        check("gid substitution detected", True)

    print("\nTamper detection (expiry extension - trying to make an expired invite last forever):")
    tampered_expiry = dict(payload)
    tampered_expiry["expires"] = "2999-01-01T00:00:00+00:00"
    new_message = json.dumps(tampered_expiry, sort_keys=True, ensure_ascii=False).encode("utf-8")
    forged_bytes = decoded[:64] + new_message
    forged = gi.PREFIX + crypto.b64encode(forged_bytes)
    try:
        gi.parse_invite(forged)
        check("expiry-extension tamper detected", False)
    except gi.GroupInviteError:
        check("expiry-extension tamper detected", True)

    print("\nTamper detection (code substitution - trying to reuse someone else's redeemed code):")
    tampered_code = dict(payload)
    tampered_code["code"] = gi.new_invite_code()
    new_message = json.dumps(tampered_code, sort_keys=True, ensure_ascii=False).encode("utf-8")
    forged_bytes = decoded[:64] + new_message
    forged = gi.PREFIX + crypto.b64encode(forged_bytes)
    try:
        gi.parse_invite(forged)
        check("code-substitution tamper detected", False)
    except gi.GroupInviteError:
        check("code-substitution tamper detected", True)

    print("\nGeneric single-byte flip anywhere in the encoded invite is never silently accepted:")
    raw = bytearray(crypto.b64decode(good_invite[len(gi.PREFIX):]))
    raw[20] ^= 0xFF
    single_flip = gi.PREFIX + crypto.b64encode(bytes(raw))
    try:
        gi.parse_invite(single_flip)
        check("single-byte-flip tamper rejected", False)
    except gi.GroupInviteError:
        check("single-byte-flip tamper rejected", True)

    print("\nForged signature (signed with the wrong key):")
    other_sk = SigningKey.generate()
    forged_sig = build_raw_invite(other_sk, dict(payload))
    try:
        gi.parse_invite(forged_sig)
        check("invite signed by the wrong key rejected", False)
    except gi.GroupInviteError:
        check("invite signed by the wrong key rejected", True)

    print("\nMalformed invite handled safely (no partial trust):")
    for label, text in [
        ("garbage base64", gi.PREFIX + "!!!not-base64!!!"),
        ("truncated invite", good_invite[: len(good_invite) // 2]),
        ("empty string", ""),
        ("only the prefix", gi.PREFIX),
        ("wrong prefix entirely (a contact bundle, not an invite)", "P2PMSG1:" + good_invite[len(gi.PREFIX):]),
    ]:
        try:
            gi.parse_invite(text)
            check(f"{label} rejected", False)
        except gi.GroupInviteError:
            check(f"{label} rejected", True)
        except Exception as exc:  # noqa: BLE001
            check(f"{label} rejected (wrong exception type {type(exc).__name__})", False)

    print("\nMissing/extra fields rejected:")
    missing_field = dict(payload)
    del missing_field["expires"]
    b = build_raw_invite(sk, missing_field)
    try:
        gi.parse_invite(b)
        check("invite missing 'expires' rejected", False)
    except gi.GroupInviteError:
        check("invite missing 'expires' rejected", True)

    extra_field = dict(payload)
    extra_field["role"] = "admin"  # an attacker trying to smuggle an extra claim in
    b = build_raw_invite(sk, extra_field)
    try:
        gi.parse_invite(b)
        check("invite with an unexpected extra field rejected", False)
    except gi.GroupInviteError:
        check("invite with an unexpected extra field rejected", True)

    print("\nEmpty gid/code/expires rejected even with a valid signature:")
    for field in ("gid", "code", "expires"):
        empty_field = dict(payload)
        empty_field[field] = ""
        b = build_raw_invite(sk, empty_field)
        try:
            gi.parse_invite(b)
            check(f"invite with empty '{field}' rejected", False)
        except gi.GroupInviteError:
            check(f"invite with empty '{field}' rejected", True)

    print("\nMalformed owner onion in an otherwise validly-signed invite:")
    for label, bad_onion in [
        ("wrong length", "short.onion"),
        ("missing .onion suffix", "a" * 56),
        ("empty onion", ""),
    ]:
        bad_payload = dict(payload)
        bad_payload["owner_onion"] = bad_onion
        b = build_raw_invite(sk, bad_payload)
        try:
            gi.parse_invite(b)
            check(f"owner onion {label} rejected", False)
        except gi.GroupInviteError:
            check(f"owner onion {label} rejected", True)

    print("\nUnsupported version rejected:")
    bad_version = dict(payload)
    bad_version["version"] = 2
    b = build_raw_invite(sk, bad_version)
    try:
        gi.parse_invite(b)
        check("unsupported version rejected", False)
    except gi.GroupInviteError:
        check("unsupported version rejected", True)

    print("\nOversized invite rejected before any parsing work:")
    huge = gi.PREFIX + "A" * (gi.MAX_INVITE_BYTES + 1)
    try:
        gi.parse_invite(huge)
        check("oversized invite rejected", False)
    except gi.GroupInviteError:
        check("oversized invite rejected", True)

    print("\nbuild_invite() refuses an invalid owner onion:")
    try:
        gi.build_invite(gid, gname, code, expires, "not-an-onion", pub_b64, signing_pub_b64, signing_priv_b64)
        check("build_invite rejects a malformed onion", False)
    except gi.GroupInviteError:
        check("build_invite rejects a malformed onion", True)

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n{passed}/{total} checks passed")
    if passed != total:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

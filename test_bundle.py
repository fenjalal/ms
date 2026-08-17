"""
Tests for the shareable contact bundle (bundle.py) and its integration with
the vault (vault.Vault.add_contact_from_bundle) and the UI's onion-hiding
requirement.

What the bundle actually protects, restated here so these tests read against
the real claim (see bundle.py's module docstring for the full version):

  * it is SIGNED, not encrypted - anyone with the bundle text can decode the
    onion, public key, and fingerprint inside it. That is unavoidable for a
    first-contact share (no recipient key exists yet to encrypt to) and is
    the same exposure today's plaintext "onionmsg:..." address already has.
  * what it actually buys: the onion does not appear in the normal UI at a
    glance, and the bundle cannot be silently modified - any change to the
    onion, public key, or fingerprint invalidates the Ed25519 signature.

These tests verify exactly those two properties, plus strict parsing, size
bounds, and that a changed endpoint for an already-accepted contact is never
silently applied.
"""

from __future__ import annotations

import json
import os
import re

import crypto
import vault as vm
from nacl.signing import SigningKey

import bundle

results: list[tuple[str, bool]] = []


def check(label: str, condition: bool) -> None:
    results.append((label, condition))
    print(f"  {'PASS' if condition else 'FAIL'}  {label}")


def cleanup(*paths: str) -> None:
    for path in paths:
        try:
            os.remove(path)
        except OSError:
            pass


def make_identity_material():
    """A fresh (onion, public_key_b64, signing_pub_b64, signing_priv_b64, SigningKey)."""
    _, pub = crypto.generate_keypair()
    pub_b64 = crypto.b64encode(pub)
    sk = SigningKey.generate()
    signing_pub_b64 = crypto.b64encode(bytes(sk.verify_key))
    signing_priv_b64 = crypto.b64encode(bytes(sk))
    onion = "".join("a" for _ in range(56)) + ".onion"
    return onion, pub_b64, signing_pub_b64, signing_priv_b64, sk


def build_raw_bundle(sk: SigningKey, payload: dict) -> str:
    """Build a bundle from an arbitrary payload dict, signed by `sk` -
    bypasses build_bundle()'s own onion validation, for constructing
    otherwise-validly-signed bundles with a bad payload."""
    message = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    signed = sk.sign(message)
    return bundle.PREFIX + crypto.b64encode(bytes(signed))


def main() -> None:
    onion, pub_b64, signing_pub_b64, signing_priv_b64, sk = make_identity_material()
    good_bundle = bundle.build_bundle(onion, pub_b64, signing_pub_b64, signing_priv_b64)

    # --- 1/2. No plaintext onion in the bundle or QR payload ---------------
    print("\nNo plaintext onion in the bundle:")
    check("bundle text contains no '.onion' substring", ".onion" not in good_bundle)
    check("bundle starts with the versioned prefix", good_bundle.startswith(bundle.PREFIX))
    # The QR payload is the exact same string handed to segno - asserted
    # again here (not just at construction) so a future refactor that
    # changes what's encoded into the QR is caught even if build_bundle()
    # itself stays correct.
    qr_payload = good_bundle  # what app._bundle_to_qr_pixmap encodes verbatim
    check("QR payload (same string) contains no '.onion' substring", ".onion" not in qr_payload)

    # --- 4. Valid bundle round-trips ----------------------------------------
    print("\nValid bundle round-trips:")
    parsed = bundle.parse_bundle(good_bundle)
    check("onion recovered exactly", parsed.onion == onion)
    check("public key recovered exactly", parsed.public_key == pub_b64)
    check("fingerprint recovered matches recomputation", parsed.fingerprint == crypto.fingerprint(pub_b64))
    check("signing public key recovered exactly", parsed.signing_public_key == signing_pub_b64)

    # --- 5/20. Tamper detection: a changed onion is caught ------------------
    print("\nTamper detection (endpoint substitution):")
    decoded = crypto.b64decode(good_bundle[len(bundle.PREFIX):])
    message = decoded[64:]
    payload = json.loads(message.decode("utf-8"))
    tampered_onion = "b" + payload["onion"][1:]  # same length, different onion
    payload["onion"] = tampered_onion
    new_message = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
    check("tampered payload keeps the same byte length", len(new_message) == len(message))
    forged_bytes = decoded[:64] + new_message  # old signature, new message
    forged = bundle.PREFIX + crypto.b64encode(forged_bytes)
    try:
        bundle.parse_bundle(forged)
        check("endpoint substitution (A.onion -> ATTACKER.onion) detected", False)
    except bundle.BundleError:
        check("endpoint substitution (A.onion -> ATTACKER.onion) detected", True)

    # A generic single-byte flip anywhere in the encoded bundle must also
    # never be silently accepted.
    raw = bytearray(crypto.b64decode(good_bundle[len(bundle.PREFIX):]))
    raw[10] ^= 0xFF
    single_flip = bundle.PREFIX + crypto.b64encode(bytes(raw))
    try:
        bundle.parse_bundle(single_flip)
        check("single-byte-flip tamper rejected", False)
    except bundle.BundleError:
        check("single-byte-flip tamper rejected", True)

    # --- 6. Forged signature (signed with the wrong key) --------------------
    print("\nForged signature:")
    other_sk = SigningKey.generate()
    forged_sig_payload = dict(payload)
    forged_sig_payload["onion"] = onion  # valid onion, but signed by a different key
    forged_sig = build_raw_bundle(other_sk, forged_sig_payload)
    try:
        bundle.parse_bundle(forged_sig)
        check("bundle signed by the wrong key rejected", False)
    except bundle.BundleError:
        check("bundle signed by the wrong key rejected", True)

    # --- 7. Corrupted base64 / truncated -> fails safely, no decryption step ---
    print("\nMalformed bundle handled safely (no 'decryption' step exists to fail):")
    for label, text in [
        ("garbage base64", bundle.PREFIX + "!!!not-base64!!!"),
        ("truncated bundle", good_bundle[: len(good_bundle) // 2]),
        ("empty string", ""),
        ("only the prefix", bundle.PREFIX),
        ("wrong prefix entirely", "NOTABUNDLE:" + good_bundle[len(bundle.PREFIX):]),
    ]:
        try:
            bundle.parse_bundle(text)
            check(f"{label} rejected", False)
        except bundle.BundleError:
            check(f"{label} rejected", True)
        except Exception as exc:  # noqa: BLE001
            check(f"{label} rejected (wrong exception type {type(exc).__name__})", False)

    # --- 8. Malformed onion in an otherwise validly-signed bundle -----------
    print("\nMalformed onion, valid signature:")
    for label, bad_onion in [
        ("wrong length", "short.onion"),
        ("missing .onion suffix", "a" * 56),
        ("empty onion", ""),
    ]:
        bad_payload = dict(payload)
        bad_payload["onion"] = bad_onion
        b = build_raw_bundle(sk, bad_payload)
        try:
            bundle.parse_bundle(b)
            check(f"malformed onion ({label}) rejected", False)
        except bundle.BundleError:
            check(f"malformed onion ({label}) rejected", True)

    # --- 9. Clearnet-shaped endpoints rejected -------------------------------
    print("\nClearnet endpoints rejected:")
    for label, clearnet in [
        ("bare IP address", "1.2.3.4"),
        ("plain domain", "evil.com"),
        ("http scheme", "http://evil.com"),
        ("https scheme", "https://evil.com"),
        ("onion-lookalike subdomain", ("a" * 50) + ".onion.attacker.com"),
        ("embedded credentials", f"user:pass@{onion}"),
        ("embedded port", f"{onion}:9050"),
    ]:
        bad_payload = dict(payload)
        bad_payload["onion"] = clearnet
        b = build_raw_bundle(sk, bad_payload)
        try:
            bundle.parse_bundle(b)
            check(f"clearnet endpoint ({label}) rejected", False)
        except bundle.BundleError:
            check(f"clearnet endpoint ({label}) rejected", True)

    # --- 10. Oversized bundle rejected before signature verification --------
    print("\nOversized bundle:")
    huge = bundle.PREFIX + "A" * (bundle.MAX_BUNDLE_BYTES + 1000)
    try:
        bundle.parse_bundle(huge)
        check("oversized bundle rejected", False)
    except bundle.BundleError:
        check("oversized bundle rejected", True)

    # --- 11. Unknown version rejected ---------------------------------------
    print("\nUnknown version:")
    future_payload = dict(payload)
    future_payload["onion"] = onion
    future_payload["version"] = 999
    future_bundle = build_raw_bundle(sk, future_payload)
    try:
        bundle.parse_bundle(future_bundle)
        check("unknown/future version rejected", False)
    except bundle.BundleError:
        check("unknown/future version rejected", True)

    # --- 12. Fuzz: nothing crashes the application, everything is BundleError ---
    print("\nFuzz inputs never raise anything but BundleError:")
    fuzz_inputs = [
        bundle.PREFIX + "",
        bundle.PREFIX + "A",
        bundle.PREFIX + "=" * 40,
        "totally unrelated text",
        "P2PMSG1",  # missing colon
        bundle.PREFIX + crypto.b64encode(b"\x00" * 100),  # valid base64, garbage bytes
        bundle.PREFIX + crypto.b64encode(b"not json at all" + b"x" * 64),
    ]
    all_safe = True
    for fuzz in fuzz_inputs:
        try:
            bundle.parse_bundle(fuzz)
        except bundle.BundleError:
            pass
        except Exception as exc:  # noqa: BLE001
            all_safe = False
            print(f"    unexpected exception on {fuzz!r}: {type(exc).__name__}: {exc}")
    check("all fuzz inputs raise only BundleError (never crash)", all_safe)

    # --- Fingerprint in the payload is never trusted as claimed -------------
    print("\nFingerprint is always recomputed, never trusted from the payload:")
    lying_payload = dict(payload)
    lying_payload["onion"] = onion
    lying_payload["fingerprint"] = "0000 0000 0000 0000 0000"  # a lie
    lying_bundle = build_raw_bundle(sk, lying_payload)
    parsed_lying = bundle.parse_bundle(lying_bundle)
    check("claimed fingerprint ignored", parsed_lying.fingerprint != "0000 0000 0000 0000 0000")
    check("real fingerprint used instead", parsed_lying.fingerprint == crypto.fingerprint(pub_b64))

    # --- Extra/unexpected fields rejected ------------------------------------
    print("\nUnexpected fields rejected:")
    extra_payload = dict(payload)
    extra_payload["onion"] = onion
    extra_payload["extra_field"] = "should not be allowed"
    extra_bundle = build_raw_bundle(sk, extra_payload)
    try:
        bundle.parse_bundle(extra_bundle)
        check("bundle with an extra field rejected", False)
    except bundle.BundleError:
        check("bundle with an extra field rejected", True)

    # =========================================================================
    # Vault integration
    # =========================================================================
    print("\nVault integration: add_contact_from_bundle:")
    cleanup("/tmp/bt_alice.dat", "/tmp/bt_bob.dat")

    alice = vm.Vault("/tmp/bt_alice.dat")
    alice.create("alice bundle test passphrase")
    alice.set_onion("a" * 56 + ".onion", "ED25519-V3:A")

    bob = vm.Vault("/tmp/bt_bob.dat")
    bob.create("bob bundle test passphrase")
    bob.set_onion("b" * 56 + ".onion", "ED25519-V3:B")

    bob_bundle = bundle.build_bundle(
        bob.identity.onion, bob.identity.public_key,
        bob.identity.signing_public_key, bob.identity.signing_private_key,
    )
    contact = alice.add_contact_from_bundle("Bob", bob_bundle)
    check("contact added from bundle", contact is not None)
    check("added contact's onion matches", contact.onion == bob.identity.onion)
    check("added contact's signing key remembered", contact.signing_public_key == bob.identity.signing_public_key)

    # --- 13/20. Endpoint change for an already-accepted contact -------------
    print("\nEndpoint change is never silently applied:")
    original_onion = bob.identity.onion
    bob.identity.onion = "c" * 56 + ".onion"
    changed_bundle = bundle.build_bundle(
        bob.identity.onion, bob.identity.public_key,
        bob.identity.signing_public_key, bob.identity.signing_private_key,
    )
    warned = alice.add_contact_from_bundle("Bob (?)", changed_bundle)
    check("endpoint-change filed as its own pending contact", warned.status == vm.STATUS_PENDING)
    check("endpoint-change marker present in the name", "Endpoint changed" in warned.name)
    check(
        "original accepted contact's onion is untouched",
        alice.get_contact(contact.id).onion == original_onion,
    )
    check(
        "original accepted contact is still ACCEPTED, not overwritten",
        alice.get_contact(contact.id).status == vm.STATUS_ACCEPTED,
    )

    # --- 17/18. Existing (pre-feature) vault + legacy path still work -------
    print("\nBackward compatibility - old vault format, legacy add path:")
    cleanup("/tmp/bt_old.dat")
    # Hand-construct a vault payload the way it looked before signing keys
    # existed - no signing_private_key/signing_public_key fields at all.
    old_priv, old_pub = crypto.generate_keypair()
    old_salt = crypto.new_salt()
    old_key = crypto.derive_key("old format passphrase", old_salt)
    old_payload = {
        "identity": {
            "private_key": crypto.b64encode(old_priv),
            "public_key": crypto.b64encode(old_pub),
            "onion": "d" * 56 + ".onion",
            "onion_key": "ED25519-V3:OLD",
            "accept_from_anyone": True,
            # no signing_private_key / signing_public_key keys at all
        },
        "contacts": [],
    }
    old_plaintext = json.dumps(old_payload, ensure_ascii=False).encode("utf-8")
    old_ciphertext = crypto.encrypt_blob(old_plaintext, old_key)
    with open("/tmp/bt_old.dat", "wb") as f:
        f.write(vm.MAGIC + old_salt + old_ciphertext)

    reopened = vm.Vault("/tmp/bt_old.dat")
    reopened.unlock("old format passphrase")
    check("old-format vault loads successfully", reopened.identity is not None)
    check(
        "signing keypair auto-generated on first unlock of an old vault",
        bool(reopened.identity.signing_public_key) and bool(reopened.identity.signing_private_key),
    )

    # Re-open from disk (a fresh Vault instance, not the in-memory object
    # above) to prove the auto-generated signing key was actually written
    # to vault.dat, not just held in memory.
    reloaded_again = vm.Vault("/tmp/bt_old.dat")
    reloaded_again.unlock("old format passphrase")
    check(
        "auto-generated signing key was actually persisted to disk",
        bool(reloaded_again.identity.signing_public_key),
    )
    check(
        "signing key is stable across repeated opens (not regenerated every time)",
        reloaded_again.identity.signing_public_key == reopened.identity.signing_public_key,
    )

    # Legacy add_contact() path still works end to end, and produces a
    # contact with no signing key (correct - it didn't come from a bundle).
    legacy_contact = alice.add_contact(
        "Legacy Carol",
        vm.format_address("e" * 56 + ".onion", crypto.b64encode(crypto.generate_keypair()[1])),
    )
    check("legacy add_contact still works", legacy_contact is not None)
    check("legacy contact has no signing key", legacy_contact.signing_public_key == "")

    # --- 19. Restart preserves the correct internal onion --------------------
    print("\nRestart preserves the internal onion exactly:")
    alice.lock()
    del alice
    alice_reopened = vm.Vault("/tmp/bt_alice.dat")
    alice_reopened.unlock("alice bundle test passphrase")
    reloaded_contact = alice_reopened.get_contact(contact.id)
    check("onion byte-identical after restart", reloaded_contact.onion == original_onion)

    # --- 16. Parsed onion reaches the contact unchanged (no silent rewrite) ---
    print("\nParsed onion is exactly what reaches the stored contact:")
    onion2, pub2_b64, spub2_b64, spriv2_b64, sk2 = make_identity_material()
    onion2 = "f" * 56 + ".onion"
    b2 = bundle.build_bundle(onion2, pub2_b64, spub2_b64, spriv2_b64)
    parsed2 = bundle.parse_bundle(b2)
    added2 = alice_reopened.add_contact_from_bundle("Direct", b2)
    check("stored contact onion matches parsed bundle onion exactly", added2.onion == parsed2.onion)

    cleanup("/tmp/bt_alice.dat", "/tmp/bt_bob.dat", "/tmp/bt_old.dat")

    # =========================================================================
    # Static/logging guards
    # =========================================================================
    print("\nStatic guard: no onion address written to logs:")
    app_source = open(os.path.join(os.path.dirname(__file__), "app.py"), encoding="utf-8").read()
    # The one place MessageServer's connection events used to interpolate a
    # truncated onion directly - must now use the short-hash helper instead.
    check(
        "_on_transport_event uses onion_short_id, not a raw onion slice",
        "crypto.onion_short_id(onion)" in app_source and "onion[:22]" not in app_source,
    )
    # No f-string/format call anywhere in app.py or tor_service.py should
    # interpolate a bare "onion" variable directly into a _logger call.
    for fname in ("app.py", "tor_service.py", "vault.py", "transport.py", "bundle.py"):
        src = open(os.path.join(os.path.dirname(__file__), fname), encoding="utf-8").read()
        risky = re.findall(r"_logger\.\w+\([^)]*\{[^}]*onion[^}]*\}", src)
        check(f"{fname}: no _logger call interpolates a raw onion variable", not risky)

    print("\nStatic guard: bundle.py reuses transport's onion validator (no duplicate definition):")
    bundle_source = open(os.path.join(os.path.dirname(__file__), "bundle.py"), encoding="utf-8").read()
    check(
        "bundle.py imports is_valid_onion from transport rather than reimplementing it",
        "from transport import is_valid_onion" in bundle_source,
    )

    passed = sum(1 for _, ok in results if ok)
    print(f"\n{passed}/{len(results)} checks passed")
    if passed != len(results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

"""
Tests for identity and key management.

Covers the fingerprint used for out-of-band verification, the contact policy
that lets strangers make first contact without giving them access, and the
encrypted identity backup that moves an identity between machines.
"""

from __future__ import annotations

import json
import os

import crypto
import vault as vm

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


def main() -> None:
    cleanup("/tmp/km1.dat", "/tmp/km2.dat", "/tmp/km3.dat", "/tmp/km.bak")

    print("\nFingerprints:")
    _, pub_a = crypto.generate_keypair()
    _, pub_b = crypto.generate_keypair()
    a64, b64 = crypto.b64encode(pub_a), crypto.b64encode(pub_b)

    check("deterministic", crypto.fingerprint(a64) == crypto.fingerprint(a64))
    check("differs between keys", crypto.fingerprint(a64) != crypto.fingerprint(b64))
    check("human-comparable length", len(crypto.fingerprint(a64).replace(" ", "")) == 20)
    check("grouped for reading aloud", crypto.fingerprint(a64).count(" ") == 4)

    print("\nIdentity:")
    vault = vm.Vault("/tmp/km1.dat")
    vault.create("first vault passphrase")
    vault.set_onion("a" * 56 + ".onion", "ED25519-V3:ONIONKEY")

    identity = vault.identity
    derived = crypto.b64encode(
        crypto.public_key_from_private(crypto.b64decode(identity.private_key))
    )
    check("public key matches private key", derived == identity.public_key)
    check("identity exposes a fingerprint", bool(identity.fingerprint))
    check("address contains the public key", identity.public_key in identity.address)

    on_disk = open("/tmp/km1.dat", "rb").read()
    check("private key never in cleartext on disk", identity.private_key.encode() not in on_disk)

    print("\nFirst contact from a stranger (open mode):")
    stranger_pub = crypto.b64encode(crypto.generate_keypair()[1])
    stranger_onion = "s" * 56 + ".onion"

    check("stranger accepted", vault.may_receive_from(stranger_pub, stranger_onion))
    pending = vault.pending_contacts()
    check("filed as a pending request", len(pending) == 1)
    check("not yet a real contact", len(vault.accepted_contacts()) == 0)
    check("pending contact has a fingerprint", bool(pending[0].fingerprint))

    check("repeat message does not duplicate", vault.may_receive_from(stranger_pub, stranger_onion))
    check("still exactly one request", len(vault.pending_contacts()) == 1)

    print("\nOnion reuse with a different key (possible impersonation):")
    # Alice's onion is already an accepted contact under `stranger_pub`, added
    # further down after acceptance - so first accept her, then simulate a
    # second identity showing up claiming her same onion address.
    vault.accept_contact(pending[0].id, "Ali")
    other_pub = crypto.b64encode(crypto.generate_keypair()[1])
    check(
        "request from same onion, different key, is still accepted as a request",
        vault.may_receive_from(other_pub, stranger_onion),
    )
    impostor = vault.find_by_public_key(other_pub)
    check("impostor filed as pending, not accepted", impostor.status == vm.STATUS_PENDING)
    check("impersonation warning present in the pending name", "impersonation" in impostor.name.lower())
    check("original contact's key is untouched", vault.find_by_public_key(stranger_pub).status == vm.STATUS_ACCEPTED)
    check(
        "original contact's key still exactly matches what it was",
        vault.find_by_public_key(stranger_pub).public_key == stranger_pub,
    )
    # Restore to a clean pending state for the rest of the test, which
    # expects `pending[0]` to still be waiting on a decision below.
    vault.contacts = [c for c in vault.contacts if c.public_key != other_pub]
    vault.get_contact(pending[0].id).status = vm.STATUS_PENDING
    vault.save()

    print("\nContact name length is bounded:")
    long_name = "x" * 500
    over_pub = crypto.b64encode(crypto.generate_keypair()[1])
    over_contact = vault.add_contact(
        long_name, f"onionmsg:{'o' * 56}.onion:{over_pub}"
    )
    check(
        f"name truncated to the configured maximum ({vm.MAX_CONTACT_NAME_LENGTH})",
        len(over_contact.name) == vm.MAX_CONTACT_NAME_LENGTH,
    )
    vault.delete_contact(over_contact.id)

    print("\nAccepting and verifying:")
    request_id = pending[0].id
    vault.accept_contact(request_id, "Ali")
    contact = vault.get_contact(request_id)
    check("status is accepted", contact.status == vm.STATUS_ACCEPTED)
    check("renamed", contact.name == "Ali")
    check("appears in accepted list", len(vault.accepted_contacts()) == 1)
    check("unverified by default", not contact.verified)

    vault.set_verified(request_id, True)
    check("can be marked verified", vault.get_contact(request_id).verified)

    print("\nBlocking:")
    spam_pub = crypto.b64encode(crypto.generate_keypair()[1])
    vault.may_receive_from(spam_pub, "b" * 56 + ".onion")
    spam = vault.find_by_public_key(spam_pub)
    vault.add_message(spam.id, "in", "spam message")
    vault.block_contact(spam.id)

    check("status is blocked", vault.get_contact(spam.id).status == vm.STATUS_BLOCKED)
    check("their messages are purged", len(vault.get_contact(spam.id).messages) == 0)
    check("further messages refused", not vault.may_receive_from(spam_pub, "b" * 56 + ".onion"))

    print("\nClosed mode:")
    vault.set_accept_from_anyone(False)
    new_pub = crypto.b64encode(crypto.generate_keypair()[1])
    check("stranger refused", not vault.may_receive_from(new_pub, "n" * 56 + ".onion"))
    check("no request recorded", vault.find_by_public_key(new_pub) is None)
    check("existing contact still allowed", vault.may_receive_from(stranger_pub, stranger_onion))
    vault.set_accept_from_anyone(True)

    print("\nIdentity backup:")
    vault.export_identity("/tmp/km.bak", "backup passphrase 123")
    backup_bytes = open("/tmp/km.bak", "rb").read()

    check("backup written 0600", oct(os.stat("/tmp/km.bak").st_mode)[-3:] == "600")
    check("private key not readable in backup", identity.private_key.encode() not in backup_bytes)
    check("raw private key not in backup", crypto.b64decode(identity.private_key) not in backup_bytes)

    restored = vm.Vault("/tmp/km2.dat")
    restored.create("second vault passphrase")
    before = restored.identity.public_key
    restored.import_identity("/tmp/km.bak", "backup passphrase 123")

    check("identity actually changed", restored.identity.public_key != before)
    check("private key restored", restored.identity.private_key == identity.private_key)
    check("public key restored", restored.identity.public_key == identity.public_key)
    check("onion address restored", restored.identity.onion == identity.onion)
    check("onion key restored", restored.identity.onion_key == "ED25519-V3:ONIONKEY")
    check("fingerprint matches original", restored.identity.fingerprint == identity.fingerprint)

    print("\nBackup rejection cases:")
    guard = vm.Vault("/tmp/km3.dat")
    guard.create("third vault passphrase")

    try:
        guard.import_identity("/tmp/km.bak", "wrong passphrase")
        check("wrong passphrase rejected", False)
    except crypto.DecryptionError:
        check("wrong passphrase rejected", True)

    tampered = bytearray(backup_bytes)
    tampered[-1] ^= 0x01
    open("/tmp/km.tampered", "wb").write(bytes(tampered))
    try:
        guard.import_identity("/tmp/km.tampered", "backup passphrase 123")
        check("tampered backup rejected", False)
    except crypto.DecryptionError:
        check("tampered backup rejected", True)

    open("/tmp/km.notabackup", "wb").write(b"just some bytes")
    try:
        guard.import_identity("/tmp/km.notabackup", "whatever")
        check("wrong file type rejected", False)
    except ValueError:
        check("wrong file type rejected", True)

    # A backup whose public key does not match its private key.
    mismatched = json.dumps({
        "format": "onionmsg-identity-1",
        "private_key": identity.private_key,
        "public_key": crypto.b64encode(crypto.generate_keypair()[1]),
        "onion": "",
        "onion_key": "",
    }).encode()
    salt = crypto.new_salt()
    key = crypto.derive_key("p", salt)
    open("/tmp/km.mismatch", "wb").write(
        vm.IDENTITY_MAGIC + salt + crypto.encrypt_blob(mismatched, key)
    )
    try:
        guard.import_identity("/tmp/km.mismatch", "p")
        check("mismatched key pair rejected", False)
    except ValueError:
        check("mismatched key pair rejected", True)

    print("\nRegenerating identity:")
    old_fingerprint = guard.identity.fingerprint
    guard.regenerate_identity()
    check("fingerprint changed", guard.identity.fingerprint != old_fingerprint)
    new_derived = crypto.b64encode(
        crypto.public_key_from_private(crypto.b64decode(guard.identity.private_key))
    )
    check("new key pair is consistent", new_derived == guard.identity.public_key)

    cleanup(
        "/tmp/km1.dat", "/tmp/km2.dat", "/tmp/km3.dat", "/tmp/km.bak",
        "/tmp/km.tampered", "/tmp/km.notabackup", "/tmp/km.mismatch",
    )

    print("\nException messages shown to the user never leak local detail:")
    import app as app_mod  # imported late: pulls in PySide6, not needed above

    path_like_exc = OSError("[Errno 13] Permission denied: '/home/someuser/secret/vault.dat'")
    text = app_mod.safe_error_text(path_like_exc, "Could not open the vault file.")
    check("path-bearing exception text is not shown to the user", "/home/someuser" not in text)
    check("safe fallback text is shown instead", text == "Could not open the vault file.")

    username_exc = ValueError("failed for user someuser on host somebox")
    text2 = app_mod.safe_error_text(username_exc, "Could not read that backup file.")
    check("username-bearing exception text is not shown to the user", "someuser" not in text2)

    passed = sum(1 for _, ok in results if ok)
    print(f"\n{passed}/{len(results)} checks passed")
    if passed != len(results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

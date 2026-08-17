"""
Tests for offline delivery.

The scenario: you send a message while the other person has the app closed.
Nothing is lost - the message is queued, encrypted, in your own vault, and the
delivery worker keeps retrying until their onion service answers.

Tor is replaced by direct localhost sockets here; everything above the
transport is the real code path.
"""

from __future__ import annotations

import os
import socket
import time

import crypto
import transport
import vault as vm
from transport import MessageServer, _recv_frame, _send_frame

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


def deliver(sender_vault, contact, port: int, message) -> bool:
    """Attempt one delivery over localhost, standing in for Tor."""
    identity = sender_vault.identity
    ciphertext = crypto.encrypt_for(
        message.body.encode(),
        sender_vault.private_key_raw(),
        crypto.b64decode(contact.public_key),
    )
    frame = {
        "v": transport.PROTOCOL_VERSION,
        "from_onion": identity.onion,
        "from_pub": identity.public_key,
        "payload": crypto.b64encode(ciphertext),
    }
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    except OSError:
        sender_vault.mark_message(contact.id, message.id, vm.QUEUED, "offline")
        return False

    try:
        _send_frame(sock, frame)
        reply = _recv_frame(sock)
        ok = reply.get("status") == "ok"
        sender_vault.mark_message(
            contact.id, message.id,
            vm.SENT if ok else vm.QUEUED,
            "" if ok else reply.get("error", ""),
        )
        return ok
    finally:
        sock.close()


def main() -> None:
    cleanup("/tmp/off_sender.dat", "/tmp/off_recipient.dat")

    # --- Identities -------------------------------------------------------
    sender = vm.Vault("/tmp/off_sender.dat")
    sender.create("sender passphrase here")
    sender.set_onion("s" * 56 + ".onion", "ED25519-V3:S")

    recipient = vm.Vault("/tmp/off_recipient.dat")
    recipient.create("recipient passphrase here")
    recipient.set_onion("r" * 56 + ".onion", "ED25519-V3:R")

    contact = sender.add_contact("Ali", recipient.identity.address)
    sender_as_contact = recipient.add_contact("Tamer", sender.identity.address)

    print("\nRecipient offline:")
    # Nothing is listening: their app is closed.
    dead_port = 1  # guaranteed refused
    message = sender.add_message(
        contact.id, "out", "رسالة وهو مقفّل التطبيق", delivered=False, status=vm.QUEUED
    )
    check("message stored despite failure", message is not None)
    check("marked as queued", sender.get_contact(contact.id).messages[0].status == vm.QUEUED)

    ok = deliver(sender, contact, dead_port, message)
    check("delivery attempt failed", not ok)
    check("still queued after failure", sender.queued_count() == 1)
    check("message body preserved", sender.queued_messages()[0][1].body == "رسالة وهو مقفّل التطبيق")
    check("attempt counted", sender.queued_messages()[0][1].attempts >= 1)

    # Queue more while they are still away.
    for i in range(2):
        extra = sender.add_message(
            contact.id, "out", f"رسالة إضافية {i + 1}", delivered=False, status=vm.QUEUED
        )
        deliver(sender, contact, dead_port, extra)
    check("multiple messages queue up", sender.queued_count() == 3)

    print("\nQueue survives a restart:")
    reopened = vm.Vault("/tmp/off_sender.dat")
    reopened.unlock("sender passphrase here")
    check("queue persisted", reopened.queued_count() == 3)
    check("order preserved", reopened.queued_messages()[0][1].body == "رسالة وهو مقفّل التطبيق")

    on_disk = open("/tmp/off_sender.dat", "rb").read()
    check("queued text encrypted at rest", "رسالة إضافية 1".encode() not in on_disk)

    print("\nRecipient comes back online:")
    received: list = []

    def store_incoming(message):
        """Mirrors what MainWindow does when a message arrives."""
        received.append(message)
        known = recipient.find_by_public_key(message.from_pub)
        if known is not None:
            recipient.add_message(known.id, "in", message.body)

    server = MessageServer(
        on_message=store_incoming,
        resolve_key=lambda pub, onion: recipient.may_receive_from(pub, onion),
        my_private=recipient.private_key_raw(),
    )
    port = server.bind()
    server.start()
    time.sleep(0.4)

    contact_now = reopened.get_contact(contact.id)
    delivered_count = 0
    for _, queued_message in list(reopened.queued_messages()):
        if deliver(reopened, contact_now, port, queued_message):
            delivered_count += 1
        time.sleep(0.15)

    check("all queued messages delivered", delivered_count == 3)
    check("queue is now empty", reopened.queued_count() == 0)
    time.sleep(0.4)
    check("recipient received all three", len(received) == 3)

    bodies = [m.body for m in received]
    check("first message arrived intact", "رسالة وهو مقفّل التطبيق" in bodies)
    check("later messages arrived intact", "رسالة إضافية 2" in bodies)

    stored = recipient.get_contact(sender_as_contact.id).messages
    check("stored in recipient's vault", len(stored) == 3)
    check("marked as incoming", all(m.direction == "in" for m in stored))

    print("\nPresence detection:")
    check("running service is reachable", _probe(port))
    server.stop()
    server.join(timeout=3)
    time.sleep(0.5)
    check("stopped service is unreachable", not _probe(port))

    cleanup("/tmp/off_sender.dat", "/tmp/off_recipient.dat")

    passed = sum(1 for _, ok in results if ok)
    print(f"\n{passed}/{len(results)} checks passed")
    if passed != len(results):
        raise SystemExit(1)


def _probe(port: int) -> bool:
    """Local stand-in for transport.check_reachable, which goes via Tor."""
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=2)
        sock.close()
        return True
    except OSError:
        return False


if __name__ == "__main__":
    main()

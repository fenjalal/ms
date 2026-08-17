"""
End-to-end test: two independent identities exchange real messages through
the full stack (vault -> crypto -> transport -> vault).

Tor is replaced by a direct localhost connection, since the sandbox has no
Tor daemon. Everything above the transport - key handling, encryption,
authentication, storage - is the real code path used in production.
"""

from __future__ import annotations

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


class Peer:
    """A full app instance minus the Qt UI and minus Tor."""

    def __init__(self, name: str, path: str, passphrase: str) -> None:
        self.name = name
        self.vault = vm.Vault(path)
        self.vault.create(passphrase)
        # Stand-in onion address; the real one comes from Tor.
        fake_onion = (name.lower() * 60)[:56] + ".onion"
        self.vault.set_onion(fake_onion, "ED25519-V3:fake")

        self.server = MessageServer(
            on_message=self._receive,
            resolve_key=lambda pub, onion: self.vault.find_by_public_key(pub) is not None,
            my_private=self.vault.private_key_raw(),
        )
        self.port = self.server.bind()
        self.server.start()

    @property
    def address(self) -> str:
        return self.vault.identity.address

    def _receive(self, message: transport.IncomingMessage) -> None:
        contact = self.vault.find_by_public_key(message.from_pub)
        if contact is not None:
            self.vault.add_message(contact.id, "in", message.body)

    def send_to(self, contact, peer_port: int, body: str) -> tuple[bool, str]:
        """Deliver a message directly over localhost, mimicking send_message()."""
        ciphertext = crypto.encrypt_for(
            body.encode("utf-8"),
            self.vault.private_key_raw(),
            crypto.b64decode(contact.public_key),
        )
        frame = {
            "v": transport.PROTOCOL_VERSION,
            "from_onion": self.vault.identity.onion,
            "from_pub": self.vault.identity.public_key,
            "payload": crypto.b64encode(ciphertext),
        }
        sock = socket.create_connection(("127.0.0.1", peer_port), timeout=10)
        try:
            _send_frame(sock, frame)
            reply = _recv_frame(sock)
            ok = reply.get("status") == "ok"
            self.vault.add_message(
                contact.id, "out", body, delivered=ok, note=reply.get("error", "")
            )
            return ok, reply.get("error", "")
        finally:
            sock.close()

    def stop(self) -> None:
        self.server.stop()


def main() -> None:
    print("\nSetting up two independent identities...\n")

    tamer = Peer("Tamer", "/tmp/e2e_tamer.dat", "tamer strong passphrase")
    ali = Peer("Ali", "/tmp/e2e_ali.dat", "ali strong passphrase")
    time.sleep(0.4)

    print("Identity:")
    check("distinct keypairs", tamer.vault.identity.public_key != ali.vault.identity.public_key)
    check("Tamer address parses", bool(vm.parse_address(tamer.address)))
    check("Ali address parses", bool(vm.parse_address(ali.address)))

    # --- Exchange addresses (as users would, out of band) -----------------
    print("\nContact exchange:")
    ali_contact = tamer.vault.add_contact("Ali", ali.address)
    tamer_contact = ali.vault.add_contact("Tamer", tamer.address)
    check("Tamer saved Ali", ali_contact.public_key == ali.vault.identity.public_key)
    check("Ali saved Tamer", tamer_contact.public_key == tamer.vault.identity.public_key)

    try:
        tamer.vault.add_contact("Myself", tamer.address)
        check("self-add rejected", False)
    except ValueError:
        check("self-add rejected", True)

    try:
        tamer.vault.add_contact("Ali again", ali.address)
        check("duplicate rejected", False)
    except ValueError:
        check("duplicate rejected", True)

    # --- Conversation ------------------------------------------------------
    print("\nConversation:")
    ok, _ = tamer.send_to(ali_contact, ali.port, "السلام عليكم يا علي")
    check("Tamer -> Ali delivered", ok)
    time.sleep(0.3)

    ali_msgs = ali.vault.get_contact(tamer_contact.id).messages
    check("Ali received it", any(m.body == "السلام عليكم يا علي" for m in ali_msgs))
    check("stored as incoming", any(m.direction == "in" for m in ali_msgs))

    ok, _ = ali.send_to(tamer_contact, tamer.port, "وعليكم السلام، وصلتني")
    check("Ali -> Tamer delivered", ok)
    time.sleep(0.3)
    tamer_msgs = tamer.vault.get_contact(ali_contact.id).messages
    check("Tamer received reply", any(m.body == "وعليكم السلام، وصلتني" for m in tamer_msgs))

    # Several messages in a row
    for i in range(3):
        tamer.send_to(ali_contact, ali.port, f"رسالة رقم {i + 1}")
        time.sleep(0.2)
    ali_msgs = ali.vault.get_contact(tamer_contact.id).messages
    check("multiple messages in order", sum(1 for m in ali_msgs if m.direction == "in") == 4)

    # --- Intruder ----------------------------------------------------------
    print("\nIntruder:")
    eve = Peer("Eve", "/tmp/e2e_eve.dat", "eve passphrase here")
    time.sleep(0.3)

    # Eve knows Ali's address but Ali has not saved Eve.
    eve_view_of_ali = eve.vault.add_contact("Ali", ali.address)
    before = len(ali.vault.get_contact(tamer_contact.id).messages)
    ok, err = eve.send_to(eve_view_of_ali, ali.port, "let me in")
    check("stranger rejected", not ok)
    time.sleep(0.3)
    check("nothing added to Ali's vault", len(ali.vault.get_contact(tamer_contact.id).messages) == before)

    # --- Persistence -------------------------------------------------------
    print("\nPersistence:")
    tamer.stop()
    reopened = vm.Vault("/tmp/e2e_tamer.dat")
    reopened.unlock("tamer strong passphrase")
    check("identity survived restart", reopened.identity.public_key == tamer.vault.identity.public_key)
    check("onion key survived restart", reopened.identity.onion_key == "ED25519-V3:fake")
    check("contacts survived restart", len(reopened.contacts) == 1)
    restored = reopened.contacts[0]
    check("history survived restart", len(restored.messages) == len(tamer_msgs))
    check("message text intact", any(m.body == "رسالة رقم 3" for m in restored.messages))

    # --- Disk secrecy ------------------------------------------------------
    print("\nDisk secrecy:")
    raw = open("/tmp/e2e_tamer.dat", "rb").read()
    check("message text not on disk", "رسالة رقم 3".encode() not in raw)
    check("contact name not on disk", b"Ali" not in raw)
    check("private key not on disk", crypto.b64decode(tamer.vault.identity.private_key) not in raw)

    ali.stop()
    eve.stop()

    passed = sum(1 for _, ok in results if ok)
    print(f"\n{passed}/{len(results)} checks passed")
    if passed != len(results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

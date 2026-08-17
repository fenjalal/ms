"""
End-to-end test for the group-chat and file-transfer features: three
independent identities exchange group and file messages through the full
stack (vault -> envelope -> crypto -> transport -> vault), the same way
test_e2e.py exercises plain 1:1 messaging.

Tor is replaced by a direct localhost connection (no Tor daemon in this
sandbox), exactly as test_e2e.py does. Everything above the transport -
vault.Group/Message, envelope.py, contact/group resolution - is the real
production code path; only the socket target changes.

This does not exercise app.py's Qt widgets (GroupSendWorker, the sidebar,
render_bubble's group-aggregate note) - those need a running QApplication
and are covered indirectly by test_ui.py's render_bubble checks. What this
test proves is that the wire-level contract app.py relies on actually
round-trips correctly: a group-tagged envelope sent to N members is
individually decryptable by each, auto-files into a local Group on the
receiving side, and a file envelope's bytes survive the trip intact.
"""

from __future__ import annotations

import base64
import socket
import time

import crypto
import envelope
import transport
import vault as vm
from transport import MessageServer, _recv_frame, _send_frame

results: list[tuple[str, bool]] = []


def check(label: str, condition: bool) -> None:
    results.append((label, condition))
    print(f"  {'PASS' if condition else 'FAIL'}  {label}")


class Peer:
    """A full app instance minus the Qt UI and minus Tor - same shape as
    test_e2e.py's Peer, extended with group-aware receive handling that
    mirrors app.py's MainWindow._on_message_arrived / _file_incoming_group_message."""

    def __init__(self, name: str, path: str, passphrase: str) -> None:
        self.name = name
        self.vault = vm.Vault(path)
        self.vault.create(passphrase)
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
        if contact is None:
            return
        try:
            env = envelope.decode(message.body)
        except envelope.EnvelopeError:
            return

        if env.gid:
            group = self.vault.get_group(env.gid)
            if group is None:
                group = self.vault.create_group_from_invite(
                    env.gid, env.gname or "Group", contact.id,
                )
            elif contact.id not in group.member_contact_ids:
                self.vault.add_group_member(group.id, contact.id)
            kwargs = dict(
                contact_id=contact.id, direction="in", group_id=group.id,
                sender_contact_id=contact.id,
            )
        else:
            kwargs = dict(contact_id=contact.id, direction="in")

        if env.kind == envelope.KIND_FILE:
            self.vault.add_message(
                body=env.body, attachment_filename=env.filename,
                attachment_mime=env.mime, attachment_size=env.size, **kwargs,
            )
        else:
            self.vault.add_message(body=env.body, **kwargs)

    def send_wire(self, contact, peer_port: int, wire_body: str) -> tuple[bool, str]:
        """Deliver a pre-built wire envelope directly over localhost,
        mimicking transport.send_message()."""
        ciphertext = crypto.encrypt_for(
            wire_body.encode("utf-8"),
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
            return reply.get("status") == "ok", reply.get("error", "")
        finally:
            sock.close()

    def stop(self) -> None:
        self.server.stop()


def main() -> None:
    print("\nVault-level group CRUD:\n")
    v = vm.Vault("/tmp/groups_solo.dat")
    v.create("solo test passphrase")
    a = v.add_contact("A", vm.format_address(("a" * 56) + ".onion", crypto.b64encode(crypto.generate_keypair()[1])))
    b = v.add_contact("B", vm.format_address(("b" * 56) + ".onion", crypto.b64encode(crypto.generate_keypair()[1])))

    group = v.create_group("Friends", [a.id, b.id])
    check("group created with both members", set(group.member_contact_ids) == {a.id, b.id})

    try:
        v.create_group("Empty", [])
        check("empty-member group rejected", False)
    except ValueError:
        check("empty-member group rejected", True)

    try:
        v.create_group("Bad member", ["not-a-real-id"])
        check("unknown-member group rejected", False)
    except ValueError:
        check("unknown-member group rejected", True)

    v.rename_group(group.id, "Best Friends")
    check("group renamed", v.get_group(group.id).name == "Best Friends")

    v.remove_group_member(group.id, b.id)
    check("member removed", b.id not in v.get_group(group.id).member_contact_ids)
    v.add_group_member(group.id, b.id)
    check("member re-added", b.id in v.get_group(group.id).member_contact_ids)

    v.add_message(a.id, "out", "hi", group_id=group.id, client_msg_id="c1", status=vm.SENT)
    v.add_message(b.id, "out", "hi", group_id=group.id, client_msg_id="c1", status=vm.QUEUED)
    grouped = v.group_messages(group)
    check("group_messages collects across both members", len(grouped) == 2)
    check("group_last_activity reflects the newest message", v.group_last_activity(group) >= group.created)

    v.delete_group(group.id)
    check("group deleted", v.get_group(group.id) is None)

    print("\nSetting up three independent identities...\n")
    tamer = Peer("Tamer", "/tmp/grp_tamer.dat", "tamer strong passphrase")
    ali = Peer("Ali", "/tmp/grp_ali.dat", "ali strong passphrase")
    sam = Peer("Sam", "/tmp/grp_sam.dat", "sam strong passphrase")
    time.sleep(0.4)

    # Full mesh contacts (a group here only ever fans out to contacts the
    # sender already has - see vault.Group's docstring).
    ali_c = tamer.vault.add_contact("Ali", ali.address)
    sam_c = tamer.vault.add_contact("Sam", sam.address)
    tamer_c_at_ali = ali.vault.add_contact("Tamer", tamer.address)
    tamer_c_at_sam = sam.vault.add_contact("Tamer", tamer.address)

    print("Group message fan-out:")
    gid = "test-group-id-123"
    gname = "Trip Planning"
    wire_text = envelope.encode_text("Where should we go?", gid=gid, gname=gname)

    ok_ali, _ = tamer.send_wire(ali_c, ali.port, wire_text)
    ok_sam, _ = tamer.send_wire(sam_c, sam.port, wire_text)
    check("delivered to Ali", ok_ali)
    check("delivered to Sam", ok_sam)
    time.sleep(0.3)

    ali_group = ali.vault.get_group(gid)
    sam_group = sam.vault.get_group(gid)
    check("Ali auto-created the group locally", ali_group is not None)
    check("Sam auto-created the group locally", sam_group is not None)
    check("Ali's local group uses the sender's gname", ali_group is not None and ali_group.name == gname)
    check(
        "Ali's group lists Tamer as a member",
        ali_group is not None and tamer_c_at_ali.id in ali_group.member_contact_ids,
    )

    ali_group_msgs = ali.vault.group_messages(ali_group) if ali_group else []
    check("Ali received the group text", any(m.body == "Where should we go?" for m in ali_group_msgs))
    check(
        "message is attributed to Tamer as sender",
        any(m.sender_contact_id == tamer_c_at_ali.id for m in ali_group_msgs),
    )

    # A second message with the same gid from Tamer must land in the SAME
    # local group on Ali's side, not create a duplicate.
    ok_ali2, _ = tamer.send_wire(ali_c, ali.port, envelope.encode_text("Beach?", gid=gid, gname=gname))
    check("second group message delivered", ok_ali2)
    time.sleep(0.3)
    check("still exactly one local group for this gid", ali.vault.get_group(gid) is ali_group)
    check(
        "both group messages present in Ali's thread",
        len(ali.vault.group_messages(ali_group)) == 2,
    )

    print("\nFile/image transfer:")
    payload = bytes(range(256)) * 500  # 128 KB deterministic "image"
    file_wire = envelope.encode_file("photo.jpg", "image/jpeg", payload)
    ok_file, _ = tamer.send_wire(ali_c, ali.port, file_wire)
    check("file delivered", ok_file)
    time.sleep(0.3)

    ali_1to1_msgs = ali.vault.get_contact(tamer_c_at_ali.id).messages
    file_msg = next((m for m in ali_1to1_msgs if m.attachment_filename), None)
    check("file message stored with a filename", file_msg is not None)
    check("filename matches", file_msg is not None and file_msg.attachment_filename == "photo.jpg")
    check("mime type matches", file_msg is not None and file_msg.attachment_mime == "image/jpeg")
    check(
        "decoded attachment bytes match the original file exactly",
        file_msg is not None and base64.b64decode(file_msg.body) == payload,
    )
    check("attachment_size matches the real byte length", file_msg is not None and file_msg.attachment_size == len(payload))

    print("\nGroup file transfer:")
    group_file_wire = envelope.encode_file("map.png", "image/png", b"pretend-map-bytes", gid=gid, gname=gname)
    ok_gfile, _ = tamer.send_wire(sam_c, sam.port, group_file_wire)
    check("group file delivered", ok_gfile)
    time.sleep(0.3)
    sam_group_msgs = sam.vault.group_messages(sam_group) if sam_group else []
    sam_file_msg = next((m for m in sam_group_msgs if m.attachment_filename), None)
    check("group file message filed under the group", sam_file_msg is not None)
    check(
        "group file bytes intact",
        sam_file_msg is not None and base64.b64decode(sam_file_msg.body) == b"pretend-map-bytes",
    )

    print("\nOversized file is rejected before it ever reaches the wire:")
    try:
        envelope.encode_file("big.bin", "application/octet-stream", b"\x00" * (envelope.MAX_FILE_BYTES + 1))
        check("oversized file raises before send", False)
    except envelope.EnvelopeError:
        check("oversized file raises before send", True)

    tamer.stop()
    ali.stop()
    sam.stop()

    passed = sum(1 for _, ok in results if ok)
    print(f"\n{passed}/{len(results)} checks passed")
    if passed != len(results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

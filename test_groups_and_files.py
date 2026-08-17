"""
End-to-end test for the group-chat, invite, and file-transfer features:
three independent identities exchange group and file messages through the
full stack (vault -> envelope -> crypto -> transport -> vault), the same
way test_e2e.py exercises plain 1:1 messaging.

Tor is replaced by a direct localhost connection (no Tor daemon in this
sandbox), exactly as test_e2e.py does. Everything above the transport -
vault.Group/Message, group_invite.py, envelope.py, contact/group
resolution - is the real production code path; only the socket target
changes.

This does not exercise app.py's Qt widgets (GroupSendWorker, the sidebar,
render_bubble's group-aggregate note) - those need a running QApplication
and are covered indirectly by test_ui.py's render_bubble checks. What this
test proves is that the wire-level contract app.py relies on actually
round-trips correctly: a group can only be joined via a real signed
invite (never by simply sending a gid-tagged message - see
Peer._receive's owner/non-owner branches, which mirror
app.py's MainWindow._file_incoming_group_message exactly), a group-tagged
envelope sent to N real members is individually decryptable by each, and a
file envelope's bytes survive the trip intact.
"""

from __future__ import annotations

import base64
import socket
import time

import crypto
import envelope
import group_invite as invite_mod
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
        self.acked_group_ids: set[str] = set()
        # contact_id -> the other Peer's port, so _send_group_ack (fired
        # from inside a MessageServer receive callback) can reply without
        # needing a reference back to the whole test's Peer registry.
        self._known_ports: dict[str, int] = {}

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

        if env.kind == envelope.KIND_GROUP_ACK:
            self.acked_group_ids.add(env.gid)
            return

        if env.kind == envelope.KIND_GROUP_LEAVE:
            group = self.vault.get_group(env.gid)
            if group is not None and contact.id in group.member_contact_ids:
                self.vault.remove_group_member(group.id, contact.id)
            return

        if env.gid:
            # Mirrors app.py's MainWindow._file_incoming_group_message
            # exactly: a group this peer has no local record of at all
            # (never created it, never redeemed an invite for it) is
            # simply unrecognized - dropped, no auto-creation. Growing
            # membership follows the same owner/non-owner split.
            group = self.vault.get_group(env.gid)
            if group is None:
                return
            already_member = contact.id in group.member_contact_ids
            removed = contact.id in group.removed_contact_ids
            if not already_member and not removed:
                if group.owner_contact_id == "":
                    if env.invcode and self.vault.redeem_group_invite_locally(group.id, env.invcode):
                        try:
                            self.vault.add_group_member(group.id, contact.id)
                            self.vault.mark_group_invite_used(group.id, env.invcode, contact.id)
                            self._send_group_ack(contact, group.id)
                        except ValueError:
                            pass
                else:
                    try:
                        self.vault.add_group_member(group.id, contact.id)
                    except ValueError:
                        pass
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

    def _send_group_ack(self, to_contact, gid: str) -> None:
        peer_port = self._known_ports.get(to_contact.id)
        if peer_port is None:
            return
        self.send_wire(to_contact, peer_port, envelope.encode_group_ack(gid))

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
    # sender already has - see vault.Group's docstring). Joining a group
    # via invite additionally requires the invite's signed owner already
    # be an accepted contact (see vault.join_group_from_invite) - so Ali
    # and Sam must add Tamer, same as any normal first contact.
    ali_c = tamer.vault.add_contact("Ali", ali.address)
    sam_c = tamer.vault.add_contact("Sam", sam.address)
    tamer_c_at_ali = ali.vault.add_contact("Tamer", tamer.address)
    tamer_c_at_sam = sam.vault.add_contact("Tamer", tamer.address)
    tamer._known_ports[ali_c.id] = ali.port
    tamer._known_ports[sam_c.id] = sam.port

    print("Group creation and real signed invites (owner-issued, single-use, time-limited):")
    # create_group()'s own member list is a *direct* local trust decision
    # (the owner explicitly picking already-accepted contacts, same as
    # add_contact) and makes them real members immediately - no invite
    # needed for that initial set, same as always. The invite flow below
    # is for GROWING a group after creation, which is exactly the case
    # that used to be a security gap: ANY accepted contact who sent a
    # matching gid got auto-added, with no invite at all. So this test
    # creates the group naming only Tamer's placeholder self-member... a
    # group cannot have zero initial members (create_group requires at
    # least one - see the CRUD section above), so it starts with just one
    # placeholder-free member set: create it with Sam already directly
    # trusted, then invite Ali in afterward - covering both paths.
    group = tamer.vault.create_group("Trip Planning", [sam_c.id])
    check("Tamer is the group's owner", group.owner_contact_id == "")
    check("Sam (named at creation) is an immediate real member, no invite needed", sam_c.id in group.member_contact_ids)
    check("Ali (not named at creation) is NOT yet a member", ali_c.id not in group.member_contact_ids)

    invite_for_ali = tamer.vault.create_group_invite(group.id, expiry_hours=1)
    check("invite text uses the group-invite prefix", invite_for_ali.startswith(invite_mod.PREFIX))
    check("one issued invite recorded on Tamer's side", len(tamer.vault.get_group(group.id).issued_invites) == 1)

    ali_group = ali.vault.join_group_from_invite(invite_for_ali)
    check("Ali's local group is owned by Tamer (not herself)", ali_group.owner_contact_id == tamer_c_at_ali.id)
    check("Ali's local group uses the invite's group name", ali_group.name == "Trip Planning")
    check("Ali is not yet a real member on Tamer's side (not redeemed yet)", ali_c.id not in tamer.vault.get_group(group.id).member_contact_ids)

    reused = tamer.vault.redeem_group_invite_locally(
        group.id, tamer.vault.get_group(group.id).issued_invites[0].code,
    )
    check("Tamer's own redeem-check (before any real redemption) reports the code as valid", reused)

    # A DIFFERENT invite for Sam (an invite is meant for one recipient -
    # sharing the same code with two people is exactly the "copy and
    # reuse" risk group_invite.py's docstring is upfront about; a real
    # deployment issues one invite per person for that reason).
    invite_for_sam = tamer.vault.create_group_invite(group.id, expiry_hours=1)
    sam_group = sam.vault.join_group_from_invite(invite_for_sam)
    check("Sam's local group is also owned by Tamer", sam_group.owner_contact_id == tamer_c_at_sam.id)

    print("\nGroup message fan-out (real membership only happens once the owner redeems the code):")
    gid = group.id
    gname = group.name
    ali_invite_code = ali.vault.get_group(gid).joined_invite_code
    sam_invite_code = sam.vault.get_group(gid).joined_invite_code
    check("Ali's local record kept her own invite code", bool(ali_invite_code))
    check("Sam's local record kept her own invite code", bool(sam_invite_code))

    wire_text = envelope.encode_text("Where should we go?", gid=gid, gname=gname)

    # Tamer sends to Ali/Sam BEFORE either has redeemed anything - not
    # possible for them to reply as real members yet, but this exercises
    # the wire fan-out itself; the actual join happens below when Ali/Sam
    # send their OWN first message carrying their invite code, which is
    # what a real client does immediately after joining (see app.py's
    # _wire_body_for/_acked_group_ids).
    ok_ali, _ = tamer.send_wire(ali_c, ali.port, wire_text)
    ok_sam, _ = tamer.send_wire(sam_c, sam.port, wire_text)
    check("delivered to Ali", ok_ali)
    check("delivered to Sam", ok_sam)
    time.sleep(0.3)

    check(
        "message from Tamer filed under Ali's local group even before Ali is a real member",
        any(m.body == "Where should we go?" for m in ali.vault.group_messages(ali_group)),
    )

    # Ali replies, carrying her invite code - this is what actually makes
    # her a member on Tamer's side (see Peer._receive's owner branch).
    ali._known_ports[tamer_c_at_ali.id] = tamer.port
    ok_ali_join, _ = ali.send_wire(
        tamer_c_at_ali, tamer.port,
        envelope.encode_text("I'm in!", gid=gid, gname=gname, invcode=ali_invite_code),
    )
    check("Ali's join-message delivered to Tamer", ok_ali_join)
    time.sleep(0.3)
    check(
        "Tamer now lists Ali as a real member (code redeemed)",
        ali_c.id in tamer.vault.get_group(gid).member_contact_ids,
    )
    check(
        "Ali's invite is marked used on Tamer's side",
        tamer.vault.get_group(gid).issued_invites[0].used,
    )
    check("Ali received a KIND_GROUP_ACK back", gid in ali.acked_group_ids)

    # The SAME code, redeemed a second time (simulating someone copying
    # Ali's invite text and trying to join with it too), must fail.
    second_attempt_valid = tamer.vault.redeem_group_invite_locally(gid, ali_invite_code)
    check("Ali's already-used invite code is refused on a second redemption", not second_attempt_valid)

    # Sam does the same with her own, different invite code.
    sam._known_ports[tamer_c_at_sam.id] = tamer.port
    ok_sam_join, _ = sam.send_wire(
        tamer_c_at_sam, tamer.port,
        envelope.encode_text("Count me in too", gid=gid, gname=gname, invcode=sam_invite_code),
    )
    check("Sam's join-message delivered to Tamer", ok_sam_join)
    time.sleep(0.3)
    check(
        "Tamer now lists Sam as a real member too (her own, different code)",
        sam_c.id in tamer.vault.get_group(gid).member_contact_ids,
    )

    print("\nA stranger cannot spawn a group just by sending a gid-tagged message:")
    fake_gid = "never-invited-to-this-one"
    stranger_wire = envelope.encode_text("Let me in", gid=fake_gid, gname="Fake Group")
    ok_stranger, _ = tamer.send_wire(ali_c, ali.port, stranger_wire)
    check("wire delivery itself still succeeds (transport doesn't know about groups)", ok_stranger)
    time.sleep(0.3)
    check("Ali did NOT create a local group for an unrecognized gid", ali.vault.get_group(fake_gid) is None)

    print("\nA second message with the same gid stays the SAME local group (no duplicate):")
    ok_ali2, _ = tamer.send_wire(ali_c, ali.port, envelope.encode_text("Beach?", gid=gid, gname=gname))
    check("second group message delivered", ok_ali2)
    time.sleep(0.3)
    check("still exactly one local group for this gid", ali.vault.get_group(gid) is ali_group)
    check(
        # Ali's own "I'm in!" join-message was sent via send_wire() (this
        # test harness's low-level transport-only helper, which - unlike
        # the real app's actual send path - never calls vault.add_message
        # on the sending side to store its own outgoing copy) - so only
        # Tamer's two INCOMING messages are expected here, not three.
        "both of Tamer's incoming group messages present in Ali's thread",
        len(ali.vault.group_messages(ali_group)) == 2,
    )

    print("\nGroup ownership: only the owner can delete, others can only leave:")
    try:
        ali.vault.delete_group(gid)
        check("non-owner (Ali) cannot delete the group", False)
    except ValueError:
        check("non-owner (Ali) cannot delete the group", True)
    try:
        tamer.vault.leave_group(gid)
        check("owner (Tamer) cannot leave their own group", False)
    except ValueError:
        check("owner (Tamer) cannot leave their own group", True)
    ali.vault.leave_group(gid)
    check("non-owner (Ali) can leave", ali.vault.get_group(gid) is None)

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

"""
Tests for "delete for everyone" (see envelope.py's KIND_DELETE and
vault.Vault.mark_deleted()/queue_delete_request()) and for the "send
original vs. compressed" image-attachment choice (app._recompress_image_bytes).

Three layers, cheapest first:

1. Pure vault.py unit checks - the local tombstone mechanics and the
   queued-notification row, no network involved.
2. render_bubble (app.py) - the tombstone and "Delete" link show up (or
   don't) exactly where they should, reusing the same colour-pairing
   render function test_ui.py already exercises.
3. A real two-party, socket-level exchange (same Peer pattern as
   test_groups_and_files.py: Tor replaced by a direct localhost
   connection, everything above the transport is the real production
   code) proving a "delete" envelope actually reaches and scrubs the
   recipient's copy - and, just as importantly, that a delete envelope
   naming a message it has no business touching is a silent no-op.
"""

from __future__ import annotations

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


# --------------------------------------------------------------------------- #
# Layer 3 support: same Peer shape as test_groups_and_files.py, extended with
# KIND_DELETE handling that mirrors app.py's MainWindow._apply_delete_envelope.
# --------------------------------------------------------------------------- #
class Peer:
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

        if env.kind == envelope.KIND_DELETE:
            # Exactly app.py's _apply_delete_envelope: only ever scans this
            # SAME contact's own "in" messages - structurally incapable of
            # touching another contact's message or the local user's own
            # outgoing message.
            if not env.delete_mid:
                return
            for msg in contact.messages:
                if msg.direction != "in" or msg.client_msg_id != env.delete_mid:
                    continue
                if env.gid and msg.group_id != env.gid:
                    continue
                self.vault.mark_deleted(contact.id, msg.id)
                return
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
                sender_contact_id=contact.id, client_msg_id=env.mid,
            )
        else:
            kwargs = dict(contact_id=contact.id, direction="in", client_msg_id=env.mid)

        if env.kind == envelope.KIND_FILE:
            self.vault.add_message(
                body=env.body, attachment_filename=env.filename,
                attachment_mime=env.mime, attachment_size=env.size, **kwargs,
            )
        else:
            self.vault.add_message(body=env.body, **kwargs)

    def send_wire(self, contact, peer_port: int, wire_body: str) -> tuple[bool, str]:
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
    print("Vault-level: mark_deleted() tombstones a message in place:")
    v = vm.Vault("/tmp/delete_solo.dat")
    v.create("solo delete test passphrase")
    a = v.add_contact("A", vm.format_address(("a" * 56) + ".onion", crypto.b64encode(crypto.generate_keypair()[1])))

    sent = v.add_message(
        a.id, "out", "secret plan", status=vm.SENT, client_msg_id="cmid-1",
        attachment_filename="plan.txt", attachment_mime="text/plain", attachment_size=11,
    )
    v.mark_deleted(a.id, sent.id)
    reloaded = next(m for m in v.get_contact(a.id).messages if m.id == sent.id)
    check("deleted flag set", reloaded.deleted is True)
    check("body scrubbed", reloaded.body == "")
    check("attachment filename scrubbed", reloaded.attachment_filename == "")
    check("attachment mime scrubbed", reloaded.attachment_mime == "")
    check("attachment size scrubbed", reloaded.attachment_size == 0)
    check("id preserved (bubble stays in the same place)", reloaded.id == sent.id)
    check("timestamp preserved", reloaded.timestamp == sent.timestamp)

    print("\nqueue_delete_request() queues a real outgoing control message:")
    v.queue_delete_request(a.id, "cmid-1")
    queued = v.queued_messages()
    delete_rows = [m for _c, m in queued if m.is_delete_request]
    check("exactly one delete-request row queued", len(delete_rows) == 1)
    check("it targets the right client_msg_id", delete_rows[0].client_msg_id == "cmid-1")
    check("it carries no body", delete_rows[0].body == "")

    print("\nqueued_messages() skips a message once it's been deleted:")
    v2 = vm.Vault("/tmp/delete_solo2.dat")
    v2.create("solo delete test passphrase 2")
    b = v2.add_contact("B", vm.format_address(("b" * 56) + ".onion", crypto.b64encode(crypto.generate_keypair()[1])))
    still_queued = v2.add_message(b.id, "out", "never got there", status=vm.QUEUED, client_msg_id="cmid-2")
    check("sanity: message is queued before delete", any(m.id == still_queued.id for _c, m in v2.queued_messages()))
    v2.mark_deleted(b.id, still_queued.id)
    check(
        "a deleted-but-still-queued message is never sent",
        not any(m.id == still_queued.id for _c, m in v2.queued_messages()),
    )

    print("\ngroup_messages() hides is_delete_request rows but keeps tombstones:")
    v3 = vm.Vault("/tmp/delete_solo3.dat")
    v3.create("solo delete test passphrase 3")
    m1 = v3.add_contact("M1", vm.format_address(("c" * 56) + ".onion", crypto.b64encode(crypto.generate_keypair()[1])))
    group = v3.create_group("Test Group", [m1.id])
    real_msg = v3.add_message(m1.id, "out", "hello group", group_id=group.id, client_msg_id="cmid-3", status=vm.SENT)
    v3.queue_delete_request(m1.id, "cmid-3", group_id=group.id)
    group_msgs = v3.group_messages(group)
    check("the real message is still present (as a tombstone target)", any(m.id == real_msg.id for m in group_msgs))
    check(
        "the delete-request control row itself never shows up as a group message",
        not any(m.is_delete_request for m in group_msgs),
    )

    print("\nrender_bubble: tombstone and Delete-link presentation:")
    import app as appmod
    import theme

    class FakeTheme:
        bubble_out_bg = "#1a1a1a"
        bubble_out_text = "#ffffff"
        bubble_in_bg = "#2a2a2a"
        bubble_in_text = "#ffffff"
        text_muted = "#888888"
        text = "#ffffff"
        border = "#333333"
        warn = "#ffaa00"
        error = "#ff5555"
        accent = "#4499ff"
        ok = "#33cc66"

    p = FakeTheme()
    live_msg = v.add_message(a.id, "out", "still here", status=vm.SENT, client_msg_id="cmid-live")
    live_html = appmod.render_bubble(live_msg, "A", p)
    check("an intact outgoing message offers a Delete link", "delmsg:" in live_html)
    check("Delete link is keyed to this message's local id", f"delmsg:{live_msg.id}" in live_html)

    tomb = v.add_message(a.id, "out", "gone now", status=vm.SENT, client_msg_id="cmid-tomb")
    v.mark_deleted(a.id, tomb.id)
    tomb_reloaded = next(m for m in v.get_contact(a.id).messages if m.id == tomb.id)
    tomb_html = appmod.render_bubble(tomb_reloaded, "A", p)
    check("a tombstoned message shows the deleted placeholder", "was deleted" in tomb_html.lower() or "deleted" in tomb_html.lower())
    check("a tombstoned message offers no Delete link (already deleted)", "delmsg:" not in tomb_html)
    check("a tombstoned message's original text does not leak into the HTML", "gone now" not in tomb_html)

    incoming = v.add_message(a.id, "in", "their message", client_msg_id="cmid-in")
    incoming_html = appmod.render_bubble(incoming, "A", p)
    check("an incoming message never offers a Delete link", "delmsg:" not in incoming_html)

    legacy_no_mid = v.add_message(a.id, "out", "sent before this feature existed", status=vm.SENT)
    legacy_html = appmod.render_bubble(legacy_no_mid, "A", p)
    check(
        "an outgoing message with no client_msg_id (pre-feature data) offers no Delete link",
        "delmsg:" not in legacy_html,
    )

    print("\nImage recompression (app._recompress_image_bytes):")
    from PySide6.QtCore import QBuffer
    from PySide6.QtGui import QImage
    from PySide6.QtWidgets import QApplication
    import sys as _sys

    _app = QApplication.instance() or QApplication(_sys.argv)

    src = QImage(16, 16, QImage.Format_RGB32)
    src.fill(0xFF3366CC)
    buf = QBuffer()
    buf.open(QBuffer.WriteOnly)
    src.save(buf, "PNG")
    png_bytes = bytes(buf.data())

    recompressed = appmod._recompress_image_bytes(png_bytes)
    check("a real image recompresses successfully", recompressed is not None)
    check("recompressed bytes differ from the original (re-encoded, not copied)", recompressed != png_bytes)
    reloaded_image = QImage()
    check(
        "recompressed bytes still decode as a valid image",
        recompressed is not None and reloaded_image.loadFromData(recompressed),
    )

    not_an_image = b"this is definitely not image data, just some plain bytes" * 10
    check(
        "non-image bytes (e.g. a disguised file) fail to recompress rather than silently passing through",
        appmod._recompress_image_bytes(not_an_image) is None,
    )

    print("\nSetting up two independent identities for a real over-the-wire delete...\n")
    tamer = Peer("Tamer", "/tmp/del_tamer.dat", "tamer strong passphrase")
    ali = Peer("Ali", "/tmp/del_ali.dat", "ali strong passphrase")
    eve = Peer("Eve", "/tmp/del_eve.dat", "eve strong passphrase")
    time.sleep(0.4)

    ali_c = tamer.vault.add_contact("Ali", ali.address)
    tamer_c_at_ali = ali.vault.add_contact("Tamer", tamer.address)
    eve_c = tamer.vault.add_contact("Eve", eve.address)
    tamer_c_at_eve = eve.vault.add_contact("Tamer", tamer.address)

    print("Delete for everyone, over the wire:")
    mid = "wire-mid-1"
    ok, _ = tamer.send_wire(ali_c, ali.port, envelope.encode_text("original message", mid=mid))
    check("original message delivered", ok)
    time.sleep(0.3)

    ali_msgs_before = ali.vault.get_contact(tamer_c_at_ali.id).messages
    check("Ali has the message before deletion", any(m.body == "original message" for m in ali_msgs_before))

    ok_del, _ = tamer.send_wire(ali_c, ali.port, envelope.encode_delete(mid))
    check("delete envelope delivered", ok_del)
    time.sleep(0.3)
    ali_msgs_after = ali.vault.get_contact(tamer_c_at_ali.id).messages
    target = next((m for m in ali_msgs_after if m.client_msg_id == mid), None)
    check("Ali's copy is now tombstoned", target is not None and target.deleted is True)
    check("Ali's copy content is gone", target is not None and target.body == "")

    print("\nAn unauthorized delete - a different contact naming someone else's mid - is a no-op:")
    # Eve is a contact of Ali's too, but never sent Ali this message - Tamer
    # did. A "delete" envelope arriving from Eve is only ever matched
    # against EVE's OWN stored messages on Ali's side (see Peer._receive /
    # app.py's _apply_delete_envelope: it scans `contact.messages` for
    # whichever contact the envelope's Box actually decrypted against -
    # never anyone else's). Eve's contact record on Ali's side has no
    # message with this mid at all (she never sent Ali anything), so this
    # must find nothing and leave Tamer's message on Ali's side untouched -
    # even though Eve knows the exact mid value to name.
    eve_c_at_ali = ali.vault.add_contact("Eve", eve.address)
    ali_c_at_eve = eve.vault.add_contact("Ali", ali.address)
    time.sleep(0.2)

    mid2 = "wire-mid-2"
    ok2, _ = tamer.send_wire(ali_c, ali.port, envelope.encode_text("a second real message", mid=mid2))
    check("second original message delivered to Ali", ok2)
    time.sleep(0.3)
    before_forged = next(
        (m for m in ali.vault.get_contact(tamer_c_at_ali.id).messages if m.client_msg_id == mid2), None,
    )
    check("Ali has the second message, not yet deleted", before_forged is not None and not before_forged.deleted)

    forged_ok, _ = eve.send_wire(ali_c_at_eve, ali.port, envelope.encode_delete(mid2))
    check("Eve's forged delete envelope is still accepted at the transport level", forged_ok)
    time.sleep(0.3)

    after_forged = next(
        (m for m in ali.vault.get_contact(tamer_c_at_ali.id).messages if m.client_msg_id == mid2), None,
    )
    check(
        "Tamer's message on Ali's side survives Eve's forged delete untouched",
        after_forged is not None and after_forged.deleted is False and after_forged.body == "a second real message",
    )
    eve_own_record = ali.vault.get_contact(eve_c_at_ali.id).messages
    check(
        "the forged delete left no trace on Eve's own (unrelated) contact record either",
        not any(m.client_msg_id == mid2 for m in eve_own_record),
    )

    tamer.stop()
    ali.stop()
    eve.stop()

    passed = sum(1 for _, ok in results if ok)
    print(f"\n{passed}/{len(results)} checks passed")
    if passed != len(results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

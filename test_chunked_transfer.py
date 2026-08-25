"""
Tests for large-file chunked transfer with resumable, progress-reporting
sends: envelope.py's KIND_FILE_START/KIND_FILE_CHUNK, vault.py's
FileTransfer tracking, and app.py's ChunkedSendWorker/receive-side
handling (_on_file_start/_on_file_chunk).

The bug this exists to prevent: before chunking, a file over
envelope.MAX_FILE_BYTES (8 MiB) could not be sent at all, and there was no
way to show upload/download progress for anything - the UI just showed
"Sending..." until an all-or-nothing send finished. This also exercises
the resumability property explicitly requested by the user: an
interrupted transfer must continue from the last acknowledged chunk on
retry, not restart from zero.

Exercises the real app.py code paths directly (MainWindow._start_contact_chunked_send,
_on_file_start, _on_file_chunk, _on_chunk_progress, _on_chunked_send_done)
with ChunkedSendWorker's actual network call (transport.send_message)
stubbed out to a direct, in-process hand-off to the receiving MainWindow's
_on_message_arrived - same "no real Tor/socket needed, call the real
higher-level methods directly" approach test_group_onboarding.py already
established for GroupSendWorker.
"""

from __future__ import annotations

import os
import sys

from PySide6.QtWidgets import QApplication

import crypto
import envelope
import vault as vm

results: list[tuple[str, bool]] = []


def check(label: str, condition: bool) -> None:
    results.append((label, condition))
    print(f"  {'PASS' if condition else 'FAIL'}  {label}")


def main() -> None:
    app = QApplication.instance() or QApplication(sys.argv)

    import app as appmod

    appmod.MainWindow._start_network = lambda self: None

    sender_path = "/tmp/chunked_sender_test.dat"
    receiver_path = "/tmp/chunked_receiver_test.dat"
    test_file_path = "/tmp/chunked_test_source_file.bin"
    for p in (sender_path, receiver_path, test_file_path):
        try:
            os.remove(p)
        except OSError:
            pass

    # A deterministic ~3.5 MiB file - large enough to need 4 chunks at
    # envelope.CHUNK_SIZE (1 MiB), with the last chunk partial, so the
    # "ceiling division" chunk-count math and the last-chunk-smaller-than-
    # CHUNK_SIZE path both get exercised.
    file_size = int(3.5 * 1024 * 1024)
    file_data = bytes((i % 256) for i in range(file_size))
    with open(test_file_path, "wb") as f:
        f.write(file_data)

    sender_store = vm.Vault(sender_path)
    sender_store.create("sender test passphrase")
    sender_store.set_onion("s" * 56 + ".onion", "ED25519-V3:K")

    receiver_store = vm.Vault(receiver_path)
    receiver_store.create("receiver test passphrase")
    receiver_store.set_onion("r" * 56 + ".onion", "ED25519-V3:K")

    receiver_contact = sender_store.add_contact(
        "Receiver", vm.format_address(receiver_store.identity.onion, receiver_store.identity.public_key),
    )
    sender_contact = receiver_store.add_contact(
        "Sender", vm.format_address(sender_store.identity.onion, sender_store.identity.public_key),
    )

    sender_window = appmod.MainWindow(sender_store)
    receiver_window = appmod.MainWindow(receiver_store)

    # Stub ChunkedSendWorker to hand wire bytes directly to the receiver's
    # real _on_message_arrived, synchronously, instead of opening a real
    # socket - mirrors test_group_onboarding.py's GroupSendWorker stub.
    # Captures every chunk sent so tests can assert on ordering/count
    # without depending on timing.
    sent_log: list[tuple[str, int]] = []  # (transfer_id, index)

    class FakeChunkedSendWorker:
        def __init__(
            self, transfer_id, file_path, chunk_count, already_done,
            onion, their_public_b64, my_private, my_public_b64, my_onion,
            socks_port, gid="", gname="", start_wire=None,
        ):
            self._transfer_id = transfer_id
            self._file_path = file_path
            self._chunk_count = chunk_count
            self._already_done = already_done
            self._start_wire = start_wire
            self.progress = _FakeSignal()
            self.done = _FakeSignal()
            self.finished = _FakeSignal()
            self._fail_at_index: int | None = None

        def start(self):
            success = True
            error = ""
            if self._start_wire is not None:
                receiver_window._on_message_arrived(sender_store.identity.public_key, self._start_wire)
            with open(self._file_path, "rb") as f:
                for index in range(self._chunk_count):
                    if index in self._already_done:
                        continue
                    if self._fail_at_index is not None and index >= self._fail_at_index:
                        success = False
                        error = "simulated offline"
                        break
                    f.seek(index * envelope.CHUNK_SIZE)
                    chunk = f.read(envelope.CHUNK_SIZE)
                    wire = envelope.encode_file_chunk(self._transfer_id, index, self._chunk_count, chunk)
                    sent_log.append((self._transfer_id, index))
                    receiver_window._on_message_arrived(sender_store.identity.public_key, wire)
                    self._already_done.add(index)
                    for cb in self.progress._callbacks:
                        cb(self._transfer_id, index)
            for cb in self.done._callbacks:
                cb(self._transfer_id, success, error)
            for cb in self.finished._callbacks:
                cb()

        def isRunning(self):
            return False

        def deleteLater(self):
            pass

    class _FakeSignal:
        def __init__(self):
            self._callbacks = []

        def connect(self, cb):
            self._callbacks.append(cb)

    appmod.ChunkedSendWorker = FakeChunkedSendWorker

    print("Basic chunked send/receive round-trip:")
    sender_window._start_contact_chunked_send(receiver_contact, test_file_path, "application/octet-stream", file_size)

    check("4 chunks were sent (3 full + 1 partial, ceiling division)", len(sent_log) == 4)
    check("chunks sent in order", [i for _, i in sent_log] == [0, 1, 2, 3])

    sender_transfer = sender_store.file_transfers[0] if sender_store.file_transfers else None
    check("sender's transfer marked completed and discarded", sender_transfer is None)

    receiver_msgs = receiver_store.get_contact(sender_contact.id).messages
    file_msg = next((m for m in receiver_msgs if m.attachment_filename), None)
    check("receiver got a message with an attachment", file_msg is not None)
    if file_msg is not None:
        import base64 as b64mod
        received_bytes = b64mod.b64decode(file_msg.body)
        check("received bytes match the original file exactly", received_bytes == file_data)
        check("attachment_size matches the real byte length", file_msg.attachment_size == file_size)
        check(
            # A non-image (application/octet-stream) attachment keeps its
            # real filename - only images get a random one (see app.py's
            # _random_image_filename). This one round-trips unchanged.
            "a non-image attachment's real filename round-trips unchanged",
            file_msg.attachment_filename == os.path.basename(test_file_path),
        )

    sender_contact_msgs = sender_store.get_contact(receiver_contact.id).messages
    sent_msg = next((m for m in sender_contact_msgs if m.attachment_filename), None)
    check("sender's own copy marked SENT", sent_msg is not None and sent_msg.status == vm.SENT)

    print("\nInterrupted transfer resumes from the last acknowledged chunk, not from zero:")
    sent_log.clear()
    test_file_path2 = "/tmp/chunked_test_source_file2.bin"
    try:
        os.remove(test_file_path2)
    except OSError:
        pass
    file_size2 = int(4.2 * 1024 * 1024)
    file_data2 = bytes((i * 7 % 256) for i in range(file_size2))
    with open(test_file_path2, "wb") as f:
        f.write(file_data2)

    # Simulate an interruption: fail starting at chunk index 2 (of 5).
    original_init = FakeChunkedSendWorker.__init__

    def init_with_failure(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        self._fail_at_index = 2

    FakeChunkedSendWorker.__init__ = init_with_failure
    sender_window._start_contact_chunked_send(receiver_contact, test_file_path2, "application/octet-stream", file_size2)
    FakeChunkedSendWorker.__init__ = original_init

    check("first attempt sent exactly chunks 0 and 1 before failing", [i for _, i in sent_log] == [0, 1])
    interrupted_transfer = next(
        (t for t in sender_store.file_transfers if t.total_size == file_size2), None,
    )
    check("transfer NOT discarded after a failure (kept for resume)", interrupted_transfer is not None)
    if interrupted_transfer is not None:
        check("chunks 0,1 marked done, 2-4 not yet", interrupted_transfer.chunks_done == [True, True, False, False, False])
        check("source_path persisted for resume", interrupted_transfer.source_path == test_file_path2)

        # Resume: relaunch exactly like _on_resume_transfer does.
        sent_log.clear()
        sender_window._launch_chunked_send_worker(
            interrupted_transfer, receiver_contact, interrupted_transfer.source_path,
        )
        check("resume sent ONLY the missing chunks (2, 3, 4), not 0/1 again", [i for _, i in sent_log] == [2, 3, 4])

        receiver_msgs2 = receiver_store.get_contact(sender_contact.id).messages
        file_msg2 = next((m for m in receiver_msgs2 if m.attachment_size == file_size2), None)
        check("receiver eventually got the complete, correct file after resume", file_msg2 is not None)
        if file_msg2 is not None:
            import base64 as b64mod
            check(
                "resumed transfer's bytes match exactly (no corruption from split send)",
                b64mod.b64decode(file_msg2.body) == file_data2,
            )

    print("\nA transfer over MAX_TRANSFER_BYTES is refused before any chunk is accepted:")
    huge_tid = "huge-transfer-id"
    try:
        bad_start = envelope.encode_file_start(
            huge_tid, "huge.bin", "application/octet-stream",
            envelope.MAX_TRANSFER_BYTES, envelope.MAX_TRANSFER_BYTES // envelope.CHUNK_SIZE + 1,
        )
        check("oversized file_start rejected at encode time", False)
    except envelope.EnvelopeError:
        check("oversized file_start rejected at encode time", True)

    print("\nMAX_ATTACHMENT_BYTES_PER_CONTACT is enforced BEFORE accepting a chunked transfer:")
    # Fill the receiver's per-contact attachment budget close to the cap
    # via a direct vault call (cheaper than actually sending hundreds of
    # MB through the fake worker), accounting for the real attachment
    # bytes this contact already accumulated from the round-trip/resume
    # tests above (~7.7 MiB combined) - the filler itself must stay
    # UNDER the cap on its own (add_message() enforces the same cap on
    # every individual add, including this one), then a second,
    # separate KIND_FILE_START that would push the TOTAL over the cap is
    # what this section actually tests.
    existing_before_filler = sum(
        m.attachment_size for m in receiver_store.get_contact(sender_contact.id).messages
        if m.direction == "in" and m.attachment_filename and not m.deleted
    )
    filler_size = vm.MAX_ATTACHMENT_BYTES_PER_CONTACT - existing_before_filler - 1024
    receiver_store.add_message(
        sender_contact.id, direction="in", body="x", attachment_filename="filler.bin",
        attachment_mime="application/octet-stream", attachment_size=filler_size,
    )
    over_cap_start = envelope.encode_file_start(
        "over-cap-transfer", "toobig.bin", "application/octet-stream",
        2 * 1024 * 1024, 2,
    )
    over_cap_env = envelope.decode(over_cap_start)
    transfer_count_before = len(receiver_store.file_transfers)
    receiver_window._on_file_start(sender_contact, over_cap_env)
    check(
        "transfer over the per-contact cap was NOT started",
        len(receiver_store.file_transfers) == transfer_count_before,
    )

    print("\nAn out-of-order chunk is dropped, not corrupting the assembled file:")
    # A fresh contact/identity, not sender_contact - that one's per-contact
    # attachment budget was deliberately exhausted by the cap test just
    # above, which would make every KIND_FILE_START here refused for the
    # wrong reason (budget, not ordering) rather than testing what this
    # section is actually about.
    _, ooo_pub = crypto.generate_keypair()
    ooo_onion = "o" * 56 + ".onion"
    ooo_sender_contact = receiver_store.add_contact("OOO Sender", vm.format_address(ooo_onion, crypto.b64encode(ooo_pub)))

    ooo_tid = "out-of-order-test"
    ooo_start = envelope.encode_file_start(ooo_tid, "ooo.bin", "application/octet-stream", 3 * 1024 * 1024, 3)
    receiver_window._on_file_start(ooo_sender_contact, envelope.decode(ooo_start))
    chunk1 = envelope.encode_file_chunk(ooo_tid, 1, 3, b"B" * 1024 * 1024)  # index 1 before index 0
    receiver_window._on_file_chunk(ooo_sender_contact, envelope.decode(chunk1))
    ooo_transfer = receiver_store.get_file_transfer(ooo_tid)
    check("out-of-order chunk (index 1 before 0) was dropped", ooo_transfer is not None and ooo_transfer.chunks_done == [False, False, False])
    chunk0 = envelope.encode_file_chunk(ooo_tid, 0, 3, b"A" * 1024 * 1024)
    receiver_window._on_file_chunk(ooo_sender_contact, envelope.decode(chunk0))
    ooo_transfer = receiver_store.get_file_transfer(ooo_tid)
    check("in-order chunk (index 0) accepted normally afterward", ooo_transfer is not None and ooo_transfer.chunks_done[0] is True)
    receiver_store.discard_file_transfer(ooo_tid)

    sender_window.close()
    receiver_window.close()
    for p in (sender_path, receiver_path, test_file_path, test_file_path2):
        try:
            os.remove(p)
        except OSError:
            pass

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n{passed}/{total} checks passed")
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    main()

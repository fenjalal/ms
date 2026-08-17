"""
Tests for automatic group-invite onboarding: MainWindow._start_group_send's
handling of Group.pending_onboard_contact_ids.

The bug this exists to prevent: a member added directly via
vault.create_group()/the "Add/remove members" UI (not through a pasted
invite) has no local Group record at all - unlike an invite-redeeming
joiner, they never ran join_group_from_invite(). Without an automatic
onboarding send, the owner's very first message to them would be silently
dropped on their side (app.py's _file_incoming_group_message refuses to
auto-create a Group for an unrecognized gid - that refusal is the whole
point of closing the old "any accepted contact auto-joins" gap), leaving a
directly-added member permanently unable to receive anything.

These tests exercise MainWindow._start_group_send directly (no real Tor/
network - GroupSendWorker.run is stubbed to capture what it WOULD have
sent, mirroring test_ui.py's build_window() pattern of stubbing
_start_network) and assert:
  * a directly-added member's first send carries their own,
    individually-minted invite code, not the plain shared envelope
  * that member is removed from pending_onboard_contact_ids afterward
  * a SECOND send to the same (now-onboarded) member no longer carries
    any invite code
  * two directly-added members in the same send each get a DIFFERENT
    code (never the same one reused - that would defeat single-use)
  * the per-member Message row's pending_invcode is stored, so a retry
    (DeliveryWorker, via _wire_body_for) can reconstruct the exact same
    onboarding envelope rather than losing the code or minting a new one
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

    # Capture what GroupSendWorker WOULD send, without any real network -
    # same "stub the thread, inspect what it was built with" approach as
    # every other worker-construction test in this codebase.
    captured_sends: list[list[tuple[str, str, str, str]]] = []

    class FakeGroupSendWorker:
        def __init__(self, members, my_private, my_public_b64, my_onion, socks_port):
            captured_sends.append(list(members))
            self.per_result = _FakeSignal()
            self.finished_all = _FakeSignal()
            self.finished = _FakeSignal()

        def start(self):
            pass

        def isRunning(self):
            return False

    class _FakeSignal:
        def connect(self, *_a, **_k):
            pass

    appmod.GroupSendWorker = FakeGroupSendWorker

    path = "/tmp/group_onboarding_test.dat"
    try:
        os.remove(path)
    except OSError:
        pass

    store = vm.Vault(path)
    store.create("onboarding test passphrase")
    store.set_onion("o" * 56 + ".onion", "ED25519-V3:K")

    _, pub_a = crypto.generate_keypair()
    _, pub_b = crypto.generate_keypair()
    member_a = store.add_contact("Alpha", vm.format_address("a" * 56 + ".onion", crypto.b64encode(pub_a)))
    member_b = store.add_contact("Beta", vm.format_address("b" * 56 + ".onion", crypto.b64encode(pub_b)))

    group = store.create_group("Test Group", [member_a.id, member_b.id])

    print("Directly-added members start pending onboarding:")
    check("both members marked pending_onboard", set(group.pending_onboard_contact_ids) == {member_a.id, member_b.id})

    window = appmod.MainWindow(store)
    window._start_group_send(group, text_body="Hello everyone")

    check("exactly one GroupSendWorker batch was constructed", len(captured_sends) == 1)
    batch = captured_sends[0]
    bodies_by_contact = {contact_id: wire_body for contact_id, _onion, _pub, wire_body in batch}

    print("\nEach onboarding member gets their own individually-invite-bearing envelope:")
    env_a = envelope.decode(bodies_by_contact[member_a.id])
    env_b = envelope.decode(bodies_by_contact[member_b.id])
    check("Alpha's envelope carries a non-empty invite code", bool(env_a.invcode))
    check("Beta's envelope carries a non-empty invite code", bool(env_b.invcode))
    check("Alpha and Beta got DIFFERENT codes (never reused)", env_a.invcode != env_b.invcode)
    check("both envelopes carry the same gid", env_a.gid == env_b.gid == group.id)
    check("both envelopes carry the same message text", env_a.body == env_b.body == "Hello everyone")

    print("\nOnboarding is cleared after the send:")
    reloaded = store.get_group(group.id)
    check("pending_onboard_contact_ids is now empty", reloaded.pending_onboard_contact_ids == [])

    print("\nEach invite code is genuinely redeemable exactly once, on the owner's own vault:")
    valid_a = store.redeem_group_invite_locally(group.id, env_a.invcode)
    check("Alpha's code redeems successfully the first time", valid_a)
    store.mark_group_invite_used(group.id, env_a.invcode, member_a.id)
    valid_a_again = store.redeem_group_invite_locally(group.id, env_a.invcode)
    check("Alpha's code is refused on a second redemption", not valid_a_again)
    valid_b = store.redeem_group_invite_locally(group.id, env_b.invcode)
    check("Beta's code is unaffected by Alpha's redemption (still valid)", valid_b)

    print("\nThe per-member Message row remembers its own invite code (for retries):")
    alpha_contact = store.get_contact(member_a.id)
    alpha_msg = next(m for m in alpha_contact.messages if m.group_id == group.id)
    check("Alpha's stored Message.pending_invcode matches what was actually sent", alpha_msg.pending_invcode == env_a.invcode)
    beta_contact = store.get_contact(member_b.id)
    beta_msg = next(m for m in beta_contact.messages if m.group_id == group.id)
    check("Beta's stored Message.pending_invcode matches what was actually sent", beta_msg.pending_invcode == env_b.invcode)

    print("\n_wire_body_for reconstructs the SAME onboarding envelope on a simulated retry:")
    rebuilt_a = appmod._wire_body_for(store, alpha_msg)
    rebuilt_env_a = envelope.decode(rebuilt_a)
    check("retry rebuilds with the identical invite code (not a fresh one)", rebuilt_env_a.invcode == env_a.invcode)

    print("\nA second send to the SAME (now-onboarded) members carries no invite code at all:")
    captured_sends.clear()
    window._start_group_send(group, text_body="Second message")
    check("a second batch was constructed", len(captured_sends) == 1)
    second_batch = captured_sends[0]
    second_bodies = {contact_id: wire_body for contact_id, _onion, _pub, wire_body in second_batch}
    second_env_a = envelope.decode(second_bodies[member_a.id])
    second_env_b = envelope.decode(second_bodies[member_b.id])
    check("Alpha's second envelope has no invite code", second_env_a.invcode == "")
    check("Beta's second envelope has no invite code", second_env_b.invcode == "")
    check(
        "both members now got the exact SAME shared envelope (no more per-member split)",
        second_bodies[member_a.id] == second_bodies[member_b.id],
    )

    window.close()
    try:
        os.remove(path)
    except OSError:
        pass

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n{passed}/{total} checks passed")
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    main()

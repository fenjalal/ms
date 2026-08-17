"""
Concurrency tests for the vault.

vault.py is called from several threads at once in the real app: the Qt UI
thread, DeliveryWorker, and MessageServer's per-connection handlers. This
file hammers a single Vault from many threads at once and checks that the
result is exactly what a correctly-serialized version of the same work would
produce - no lost writes, no duplicated contacts, no corrupted vault.dat.
"""

from __future__ import annotations

import os
import threading

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


def run_threads(count: int, target) -> None:
    threads = [threading.Thread(target=target, args=(i,)) for i in range(count)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)


def main() -> None:
    cleanup("/tmp/vc1.dat", "/tmp/vc2.dat")

    print("\nConcurrent add_message from many threads:")
    vault = vm.Vault("/tmp/vc1.dat")
    vault.create("concurrency test passphrase")
    contact = vault.add_contact("Peer", "onionmsg:" + "a" * 56 + ".onion:" + crypto.b64encode(crypto.generate_keypair()[1]))

    THREAD_COUNT = 40
    MESSAGES_PER_THREAD = 5

    def add_many(thread_index: int) -> None:
        for i in range(MESSAGES_PER_THREAD):
            vault.add_message(contact.id, "out", f"t{thread_index}-m{i}")

    run_threads(THREAD_COUNT, add_many)

    expected_total = THREAD_COUNT * MESSAGES_PER_THREAD
    stored = vault.get_contact(contact.id).messages
    check(f"no messages lost or duplicated ({len(stored)}/{expected_total})", len(stored) == expected_total)
    check("all message ids unique", len({m.id for m in stored}) == expected_total)

    print("\nVault survives concurrent writes intact:")
    reopened = vm.Vault("/tmp/vc1.dat")
    reopened.unlock("concurrency test passphrase")
    check("vault reloads without error after concurrent saves", reopened.identity is not None)
    check(
        "reloaded message count matches",
        len(reopened.get_contact(contact.id).messages) == expected_total,
    )

    print("\nConcurrent may_receive_from from the same unknown key:")
    vault2 = vm.Vault("/tmp/vc2.dat")
    vault2.create("second concurrency passphrase")
    stranger_pub = crypto.b64encode(crypto.generate_keypair()[1])
    stranger_onion = "s" * 56 + ".onion"

    def knock(_thread_index: int) -> None:
        vault2.may_receive_from(stranger_pub, stranger_onion)

    run_threads(30, knock)

    matching = [c for c in vault2.contacts if c.public_key == stranger_pub]
    check("exactly one pending contact created, not one per thread", len(matching) == 1)

    print("\nConcurrent mark_message does not corrupt delivery state:")
    vault3 = vm.Vault("/tmp/vc3.dat")
    vault3.create("third concurrency passphrase")
    contact3 = vault3.add_contact(
        "Peer3", "onionmsg:" + "b" * 56 + ".onion:" + crypto.b64encode(crypto.generate_keypair()[1])
    )
    msg = vault3.add_message(contact3.id, "out", "will be marked repeatedly", status=vm.QUEUED)

    def mark_many(_thread_index: int) -> None:
        for _ in range(10):
            vault3.mark_message(contact3.id, msg.id, vm.SENT, "")

    run_threads(20, mark_many)
    final = vault3.get_contact(contact3.id).messages[0]
    check("exactly one message remains (no duplication)", len(vault3.get_contact(contact3.id).messages) == 1)
    check("final status is consistent", final.status == vm.SENT)
    check("attempts counted without loss", final.attempts == 200)

    print("\nAtomic save leaves no temp file and correct permissions:")
    vault.add_message(contact.id, "out", "one more save")
    check("no leftover .tmp file after save", not os.path.exists("/tmp/vc1.dat.tmp"))
    check("vault file mode is 0600", oct(os.stat("/tmp/vc1.dat").st_mode)[-3:] == "600")

    cleanup("/tmp/vc1.dat", "/tmp/vc2.dat", "/tmp/vc3.dat")

    passed = sum(1 for _, ok in results if ok)
    print(f"\n{passed}/{len(results)} checks passed")
    if passed != len(results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

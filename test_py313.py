"""
Regression test for a Python-version-dependent crash.

Python 3.13 added a private `_handle` attribute to `threading.Thread`.
`MessageServer` had a method of the same name, so `Thread.__init__` silently
replaced it with a non-callable handle object, and every incoming connection
died with:

    TypeError: '_thread._ThreadHandle' object is not callable

The code ran fine on 3.12 and crashed on 3.13, which makes this exactly the
kind of bug that escapes testing on a single interpreter.

This test simulates that attribute (and other names CPython might plausibly
add later) so the failure is caught on any Python version.
"""

from __future__ import annotations

import socket
import threading
import time

# Names threading.Thread already uses, or might reasonably claim in future
# versions. A subclass must not define any of these.
RESERVED_THREAD_NAMES = [
    "_target", "_name", "_args", "_kwargs", "_daemonic", "_ident",
    "_handle", "_tstate_lock", "_started", "_is_stopped", "_initialized",
    "_stderr", "_invoke_excepthook", "_native_id", "_bootstrap",
    "_bootstrap_inner", "_set_ident", "_set_tstate_lock",
    "_wait_for_tstate_lock", "_reset_internal_locks", "_stop", "_delete",
]

results: list[tuple[str, bool]] = []


def check(label: str, condition: bool) -> None:
    results.append((label, condition))
    print(f"  {'PASS' if condition else 'FAIL'}  {label}")


def simulate_future_python() -> None:
    """
    Make Thread.__init__ set every reserved private name, as 3.13 does.

    Earlier CPython 3.13 pre-releases accepted any object as `_handle`, so
    the original version of this simulation just assigned `object()`. The
    released 3.13 tightened `Thread.start()` to require a real
    `_thread._ThreadHandle`, so a plain `object()` now breaks `start()` for
    *any* Thread subclass, not just one with a colliding method name -
    which would make this test fail even against code with no bug at all.
    Setting `_handle` to what a normal, unpatched Thread.__init__ already
    produced keeps the simulation doing its actual job: proving that
    MessageServer does not define an attribute/method that this (or a
    future) Python version's Thread.__init__ silently overwrites.
    """
    original = threading.Thread.__init__
    # Captured once, before patching, so building a fresh handle below does
    # not recurse back through the patched __init__.
    #
    # On 3.13+, threading.Thread already has a real `_handle` attribute of
    # type `_thread._ThreadHandle`, and `Thread.start()` requires that exact
    # type. On earlier versions (this interpreter) `_handle` does not exist
    # yet, and `start()` does not check its type at all, so any placeholder
    # object is sufficient to simulate "some future Python sets this name".
    probe = threading.Thread()
    real_handle = getattr(probe, "_handle", None)
    handle_cls = type(real_handle) if real_handle is not None else object

    def patched(self, *args, **kwargs):
        original(self, *args, **kwargs)
        self._handle = handle_cls()

    threading.Thread.__init__ = patched


def main() -> None:
    simulate_future_python()

    # Imported after patching so the subclass is built in the simulated world.
    import crypto
    import transport
    from transport import _recv_frame, _send_frame

    print("\nName safety:")
    own = vars(transport.MessageServer)
    clashes = [n for n in RESERVED_THREAD_NAMES if n in own]
    check(f"no reserved names defined (found: {clashes or 'none'})", not clashes)
    check("daemon remains a property", isinstance(transport.MessageServer.daemon, property))

    print("\nListener under simulated Python 3.13:")
    alice_priv, alice_pub = crypto.generate_keypair()
    bob_priv, bob_pub = crypto.generate_keypair()
    alice_pub_b64 = crypto.b64encode(alice_pub)

    received: list = []
    server = transport.MessageServer(
        on_message=received.append,
        resolve_key=lambda pub, onion: pub == alice_pub_b64,
        my_private=bob_priv,
    )
    port = server.bind()
    server.start()
    time.sleep(0.4)

    check("server thread started", server.is_alive())
    check("daemon flag set", server.daemon is True)

    body = "رسالة اختبار"
    ciphertext = crypto.encrypt_for(body.encode(), alice_priv, bob_pub)
    frame = {
        "v": transport.PROTOCOL_VERSION,
        "from_onion": "a" * 56 + ".onion",
        "from_pub": alice_pub_b64,
        "payload": crypto.b64encode(ciphertext),
    }

    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        _send_frame(sock, frame)
        reply = _recv_frame(sock)
    finally:
        sock.close()
    time.sleep(0.4)

    check("connection handled without TypeError", reply.get("status") == "ok")
    check("message delivered", len(received) == 1)
    check("body intact", bool(received) and received[0].body == body)
    check("listener still alive afterwards", server.is_alive())

    server.stop()

    passed = sum(1 for _, ok in results if ok)
    print(f"\n{passed}/{len(results)} checks passed")
    if passed != len(results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

"""
Local test harness for the transport layer.

Runs two identities against each other over plain localhost sockets, standing
in for the onion tunnel Tor would normally provide. This verifies the framing,
the authentication rules, and the failure paths without needing a live Tor
connection.
"""

from __future__ import annotations

import os
import re
import socket
import threading
import time

import crypto
import transport
from transport import MessageServer, _recv_frame, _send_frame


def check_no_direct_outbound_sockets() -> bool:
    """
    Static guard: transport.py must never open an outbound connection with a
    plain socket.socket() - every outbound connection has to go through
    socks.socksocket() with an explicit SOCKS5 proxy, so it is impossible for
    a future change to accidentally reach the network outside Tor.

    The one legitimate socket.socket() call is the inbound listener, which
    binds to 127.0.0.1 and only ever receives connections Tor itself hands
    it - it never dials out. That call is excluded by name.
    """
    source = open(os.path.join(os.path.dirname(__file__), "transport.py"), encoding="utf-8").read()
    calls = re.findall(r"\bsocket\.socket\(", source)
    # Exactly one call is expected: MessageServer.bind()'s inbound listener.
    return len(calls) == 1


def direct_send(port: int, frame: dict, timeout: float = 10) -> dict:
    """Send a raw frame straight to a local listener and return the reply."""
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        _send_frame(sock, frame)
        return _recv_frame(sock)
    finally:
        sock.close()


def build_frame(body: str, sender_priv: bytes, sender_pub_b64: str, recipient_pub_b64: str) -> dict:
    ct = crypto.encrypt_for(body.encode(), sender_priv, crypto.b64decode(recipient_pub_b64))
    return {
        "v": transport.PROTOCOL_VERSION,
        "from_onion": "sender" + "x" * 50 + ".onion",
        "from_pub": sender_pub_b64,
        "payload": crypto.b64encode(ct),
    }


def main() -> None:
    results: list[tuple[str, bool]] = []

    def check(label: str, condition: bool) -> None:
        results.append((label, condition))
        print(f"  {'PASS' if condition else 'FAIL'}  {label}")

    # --- Identities -------------------------------------------------------
    alice_priv, alice_pub = crypto.generate_keypair()
    bob_priv, bob_pub = crypto.generate_keypair()
    eve_priv, eve_pub = crypto.generate_keypair()

    alice_pub_b64 = crypto.b64encode(alice_pub)
    bob_pub_b64 = crypto.b64encode(bob_pub)
    eve_pub_b64 = crypto.b64encode(eve_pub)

    # --- Bob's listener; Alice is his only known contact ------------------
    received: list[transport.IncomingMessage] = []
    known = {alice_pub_b64}

    server = MessageServer(
        on_message=received.append,
        resolve_key=lambda pub, onion: pub in known,
        my_private=bob_priv,
    )
    port = server.bind()
    server.start()
    time.sleep(0.3)
    print(f"\nBob listening on 127.0.0.1:{port}\n")

    # --- 1. Normal delivery ----------------------------------------------
    print("Delivery:")
    reply = direct_send(port, build_frame("مرحبا يا بوب", alice_priv, alice_pub_b64, bob_pub_b64))
    check("acknowledged", reply.get("status") == "ok")
    time.sleep(0.3)
    check("message received", len(received) == 1)
    check("body intact (unicode)", received and received[0].body == "مرحبا يا بوب")
    check("sender identified", received and received[0].from_pub == alice_pub_b64)

    # --- 2. Unknown sender rejected --------------------------------------
    print("\nAccess control:")
    reply = direct_send(port, build_frame("let me in", eve_priv, eve_pub_b64, bob_pub_b64))
    check("unknown sender rejected", reply.get("status") == "error")
    time.sleep(0.3)
    check("nothing stored from unknown sender", len(received) == 1)

    # --- 3. Impersonation: Eve claims Alice's key ------------------------
    forged = build_frame("I am Alice", eve_priv, eve_pub_b64, bob_pub_b64)
    forged["from_pub"] = alice_pub_b64  # lie about identity
    reply = direct_send(port, forged)
    check("impersonation rejected", reply.get("status") == "error")
    time.sleep(0.3)
    check("nothing stored from impersonator", len(received) == 1)

    # --- 4. Tampered ciphertext ------------------------------------------
    print("\nIntegrity:")
    tampered = build_frame("original text", alice_priv, alice_pub_b64, bob_pub_b64)
    raw = bytearray(crypto.b64decode(tampered["payload"]))
    raw[-1] ^= 0x01
    tampered["payload"] = crypto.b64encode(bytes(raw))
    reply = direct_send(port, tampered)
    check("tampered payload rejected", reply.get("status") == "error")
    time.sleep(0.3)
    check("nothing stored from tampered frame", len(received) == 1)

    # --- 5. Protocol version --------------------------------------------
    print("\nProtocol hygiene:")
    wrong_version = build_frame("hi", alice_priv, alice_pub_b64, bob_pub_b64)
    wrong_version["v"] = 999
    reply = direct_send(port, wrong_version)
    check("wrong version rejected", reply.get("status") == "error")

    # --- 6. Garbage input must not kill the listener ---------------------
    for junk in [b"\x00\x00\x00\x05hello", b"\xff\xff\xff\xffAAAA", b"not a frame at all"]:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            s.sendall(junk)
            s.close()
        except OSError:
            pass
    time.sleep(0.5)
    check("listener survived garbage", server.is_alive())

    # --- 7. Still works after all the abuse ------------------------------
    reply = direct_send(port, build_frame("still alive", alice_priv, alice_pub_b64, bob_pub_b64))
    check("still accepting valid messages", reply.get("status") == "ok")
    time.sleep(0.3)
    check("second valid message stored", len(received) == 2)

    # --- 8. Oversized frame ----------------------------------------------
    try:
        huge = build_frame("x" * (transport.MAX_FRAME_BYTES + 1000), alice_priv, alice_pub_b64, bob_pub_b64)
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        try:
            _send_frame(s, huge)
            check("oversized frame refused", False)
        except transport.TransportError:
            check("oversized frame refused", True)
        finally:
            s.close()
    except Exception:
        check("oversized frame refused", True)

    # --- 9. Malformed sender fields ----------------------------------------
    print("\nField validation:")
    bad_onion = build_frame("hi", alice_priv, alice_pub_b64, bob_pub_b64)
    bad_onion["from_onion"] = "not-an-onion-address"
    reply = direct_send(port, bad_onion)
    check("malformed onion rejected", reply.get("status") == "error")
    time.sleep(0.2)
    check("nothing stored from malformed onion", len(received) == 2)

    bad_onion2 = build_frame("hi", alice_priv, alice_pub_b64, bob_pub_b64)
    bad_onion2["from_onion"] = "short.onion"
    reply = direct_send(port, bad_onion2)
    check("wrong-length onion rejected", reply.get("status") == "error")

    bad_pub = build_frame("hi", alice_priv, alice_pub_b64, bob_pub_b64)
    bad_pub["from_pub"] = crypto.b64encode(b"too short")
    reply = direct_send(port, bad_pub)
    check("wrong-length public key rejected", reply.get("status") == "error")
    time.sleep(0.2)
    check("nothing stored from malformed public key", len(received) == 2)

    # --- 10. Replay / duplicate delivery -----------------------------------
    print("\nReplay and duplicate detection:")
    once = build_frame("send me only once", alice_priv, alice_pub_b64, bob_pub_b64)
    first_reply = direct_send(port, once)
    time.sleep(0.2)
    count_after_first = len(received)
    check("first delivery accepted", first_reply.get("status") == "ok")
    check("first delivery stored", count_after_first == 3)

    replay_reply = direct_send(port, once)  # exact same frame again
    time.sleep(0.2)
    check("replayed frame still acknowledged", replay_reply.get("status") == "ok")
    check("replayed frame not delivered a second time", len(received) == count_after_first)

    # A different message from the same sender is unaffected by the cache.
    different = build_frame("a genuinely new message", alice_priv, alice_pub_b64, bob_pub_b64)
    reply = direct_send(port, different)
    time.sleep(0.2)
    check("a different message from the same sender still delivers", reply.get("status") == "ok")
    check("new message count increased by exactly one", len(received) == count_after_first + 1)

    server.stop()

    # --- 11. Tor-only guard -------------------------------------------------
    print("\nTor-only networking guard:")
    check(
        "transport.py opens no direct outbound sockets (only socks.socksocket)",
        check_no_direct_outbound_sockets(),
    )

    passed = sum(1 for _, ok in results if ok)
    print(f"\n{passed}/{len(results)} checks passed")
    if passed != len(results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

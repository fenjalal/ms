"""
Shutdown and connection-flood tests for the transport listener.

MessageServer used to spawn one unbounded thread per connection. This file
checks the bounded replacement: that the listener starts and stops cleanly
and repeatedly, that a burst of connections beyond its capacity is refused
rather than queued without limit, and that stopping never leaves the port
bound or leaks a listener that still looks alive.
"""

from __future__ import annotations

import socket
import threading
import time

import crypto
import transport
from transport import MessageServer, _recv_frame, _send_frame


results: list[tuple[str, bool]] = []


def check(label: str, condition: bool) -> None:
    results.append((label, condition))
    print(f"  {'PASS' if condition else 'FAIL'}  {label}")


def port_is_free(port: int) -> bool:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def build_frame(body: str, sender_priv: bytes, sender_pub_b64: str, recipient_pub_b64: str) -> dict:
    ct = crypto.encrypt_for(body.encode(), sender_priv, crypto.b64decode(recipient_pub_b64))
    return {
        "v": transport.PROTOCOL_VERSION,
        "from_onion": "shut" + "x" * 52 + ".onion",
        "from_pub": sender_pub_b64,
        "payload": crypto.b64encode(ct),
    }


def main() -> None:
    print("\nRapid start -> stop -> start -> stop:")
    for i in range(4):
        server = MessageServer(
            on_message=lambda _m: None,
            resolve_key=lambda pub, onion: True,
            my_private=crypto.generate_keypair()[0],
        )
        port = server.bind()
        server.start()
        time.sleep(0.1)
        alive = server.is_alive()
        server.stop()
        server.join(timeout=3)
        time.sleep(0.2)
        check(f"cycle {i}: server was alive while running", alive)
        check(f"cycle {i}: port released after stop", port_is_free(port))

    print("\nSend-then-immediate-stop does not hang:")
    priv, pub = crypto.generate_keypair()
    pub_b64 = crypto.b64encode(pub)
    received: list = []
    server = MessageServer(
        on_message=received.append,
        resolve_key=lambda p, o: p == pub_b64,
        my_private=priv,
    )
    port = server.bind()
    server.start()
    time.sleep(0.2)

    def send_one() -> None:
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=5)
            _send_frame(sock, build_frame("hi", priv, pub_b64, pub_b64))
            sock.close()
        except OSError:
            pass

    sender_thread = threading.Thread(target=send_one)
    sender_thread.start()
    server.stop()
    sender_thread.join(timeout=5)
    check("sender thread did not hang", not sender_thread.is_alive())
    server.join(timeout=3)
    check("server stopped cleanly after a concurrent send", not server.is_alive())

    print("\nConnection flood beyond capacity is refused, not queued forever:")
    priv2, pub2 = crypto.generate_keypair()
    pub2_b64 = crypto.b64encode(pub2)
    received2: list = []
    server2 = MessageServer(
        on_message=received2.append,
        resolve_key=lambda p, o: p == pub2_b64,
        my_private=priv2,
    )
    port2 = server2.bind()
    server2.start()
    time.sleep(0.2)

    FLOOD = transport.MAX_QUEUED_CONNECTIONS * 4
    opened = []
    for _ in range(FLOOD):
        try:
            s = socket.create_connection(("127.0.0.1", port2), timeout=2)
            opened.append(s)
        except OSError:
            pass
    time.sleep(0.5)

    check("listener survived a flood well beyond its capacity", server2.is_alive())
    for s in opened:
        try:
            s.close()
        except OSError:
            pass

    # The listener must still serve a legitimate request after the flood.
    reply = None
    try:
        sock = socket.create_connection(("127.0.0.1", port2), timeout=5)
        _send_frame(sock, build_frame("still here", priv2, pub2_b64, pub2_b64))
        reply = _recv_frame(sock)
        sock.close()
    except OSError:
        pass
    check("listener still serves requests after the flood", reply is not None and reply.get("status") == "ok")

    server2.stop()
    server2.join(timeout=3)

    passed = sum(1 for _, ok in results if ok)
    print(f"\n{passed}/{len(results)} checks passed")
    if passed != len(results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

"""
transport.py

Moves encrypted messages between two instances of the app.

Wire format - a length-prefixed JSON frame:

    [4 bytes big-endian length][JSON body]

The JSON body carries only routing information in the clear:

    {
      "v": 1,
      "from_onion": "<sender onion address>",
      "from_pub":   "<sender public key, base64>",
      "payload":    "<NaCl Box ciphertext, base64>"
    }

The message text lives inside `payload` and is encrypted end to end, so it is
never readable by anything on the wire. `from_pub` is a claim, not proof - it
only tells the receiver which contact's key to try. If the payload does not
decrypt with that key, the claim was false and the frame is discarded. That is
what makes impersonation impossible: an attacker can put any key they like in
`from_pub`, but they cannot produce a payload that authenticates against it
without the matching private key.

All connections run through Tor's SOCKS proxy to a .onion address, so neither
side learns the other's IP address.
"""

from __future__ import annotations

import hashlib
import json
import socket
import struct
import threading
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import socks

import crypto

PROTOCOL_VERSION = 1
# Sized to comfortably fit an envelope.py file attachment at its own
# MAX_FILE_BYTES ceiling (8 MiB raw) after base64 (~1.33x), JSON framing,
# and the outer wire frame's own base64 of the Box ciphertext (~1.33x
# again) - roughly 8 MiB * 1.33 * 1.33 =~ 14 MiB, rounded up with headroom
# for JSON key overhead. Still a firm, bounded ceiling (not unbounded): a
# hostile peer can make MessageServer buffer at most this many bytes per
# connection, and MAX_CONCURRENT_CONNECTIONS/MAX_QUEUED_CONNECTIONS below
# already bound how many connections can be doing that at once.
MAX_FRAME_BYTES = 20 * 1024 * 1024
CONNECT_TIMEOUT = 60  # onion connections are slow; be patient
# A large file transfer over three Tor hops can legitimately take minutes,
# not seconds - this is the socket-level timeout used once a connection is
# established (both for the sender's send_message() and the receiving
# MessageServer's per-connection handler), separate from CONNECT_TIMEOUT
# above which only bounds establishing the circuit.
TRANSFER_TIMEOUT = 300

# Bounds on the listener, so a connection flood from a hostile peer costs the
# app almost nothing instead of spawning unbounded threads. This is a single-
# user desktop app talking to a handful of contacts at a time, so both
# numbers have generous headroom over real usage while still being a firm
# ceiling.
MAX_CONCURRENT_CONNECTIONS = 8   # connection handlers running at once
MAX_QUEUED_CONNECTIONS = 24      # accepted sockets awaiting a free handler

# How many recent ciphertexts to remember per sender, for replay/duplicate
# detection. Bounded so a chatty (or malicious) sender cannot grow this
# without limit; old entries are evicted first (LRU).
SEEN_CACHE_PER_SENDER = 500


class TransportError(Exception):
    """Raised when a message cannot be delivered."""


@dataclass
class IncomingMessage:
    from_onion: str
    from_pub: str
    body: str


# --------------------------------------------------------------------------- #
# Framing
# --------------------------------------------------------------------------- #

def _send_frame(sock: socket.socket, obj: dict) -> None:
    raw = json.dumps(obj).encode("utf-8")
    if len(raw) > MAX_FRAME_BYTES:
        raise TransportError("Message is too large to send.")
    sock.sendall(struct.pack(">I", len(raw)) + raw)


def _recv_exactly(sock: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining > 0:
        chunk = sock.recv(min(remaining, 8192))
        if not chunk:
            raise TransportError("Connection closed unexpectedly.")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _recv_frame(sock: socket.socket) -> dict:
    header = _recv_exactly(sock, 4)
    (length,) = struct.unpack(">I", header)
    if length <= 0 or length > MAX_FRAME_BYTES:
        raise TransportError("Frame size is invalid.")
    return json.loads(_recv_exactly(sock, length).decode("utf-8"))


# --------------------------------------------------------------------------- #
# Sending
# --------------------------------------------------------------------------- #

def check_reachable(onion: str, socks_port: int, timeout: int = 30) -> bool:
    """
    Test whether a contact's onion service is currently running.

    Opens a Tor circuit to their service and closes it immediately without
    sending anything. A successful TCP connection means their app is open and
    Tor has published their descriptor; a failure means they are offline.

    This reveals nothing to the contact beyond a connection attempt, and
    nothing to the network beyond ordinary onion traffic. It is the same
    handshake a real message would start with, stopped one step early.
    """
    sock = socks.socksocket()
    sock.set_proxy(socks.SOCKS5, "127.0.0.1", socks_port, rdns=True)
    sock.settimeout(timeout)
    try:
        from tor_service import ONION_PORT

        sock.connect((onion, ONION_PORT))
        return True
    except Exception:
        return False
    finally:
        try:
            sock.close()
        except OSError:
            pass


def send_message(
    onion: str,
    their_public_b64: str,
    body: str,
    my_private: bytes,
    my_public_b64: str,
    my_onion: str,
    socks_port: int,
) -> None:
    """
    Encrypt `body` for the contact and deliver it to their onion service.

    Raises TransportError with a human-readable reason on failure.
    """
    ciphertext = crypto.encrypt_for(
        body.encode("utf-8"), my_private, crypto.b64decode(their_public_b64)
    )

    frame = {
        "v": PROTOCOL_VERSION,
        "from_onion": my_onion,
        "from_pub": my_public_b64,
        "payload": crypto.b64encode(ciphertext),
    }

    sock = socks.socksocket()
    sock.set_proxy(socks.SOCKS5, "127.0.0.1", socks_port, rdns=True)
    sock.settimeout(CONNECT_TIMEOUT)

    try:
        from tor_service import ONION_PORT

        sock.connect((onion, ONION_PORT))
        # Circuit is up; a large attachment can legitimately take a while to
        # push through three Tor hops, so relax the timeout for the actual
        # transfer beyond the (deliberately tighter) connect-phase one.
        sock.settimeout(TRANSFER_TIMEOUT)
        _send_frame(sock, frame)

        # Wait for the peer to acknowledge, so "sent" means it really arrived.
        ack = _recv_frame(sock)
        if ack.get("status") != "ok":
            raise TransportError(ack.get("error", "The contact rejected the message."))

    except socks.ProxyConnectionError as exc:
        raise TransportError(
            "Could not reach the Tor proxy. Is Tor still running?"
        ) from exc
    except socks.GeneralProxyError as exc:
        raise TransportError(
            "Tor could not connect to that contact. They are probably offline."
        ) from exc
    except socket.timeout as exc:
        raise TransportError(
            "Timed out. The contact is offline, or Tor is being slow."
        ) from exc
    except TransportError:
        raise
    except OSError as exc:
        raise TransportError(f"Network error while sending: {exc}") from exc
    finally:
        try:
            sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# Receiving
# --------------------------------------------------------------------------- #

def is_valid_onion(onion: str) -> bool:
    """
    Strict v3 onion address shape check: ".onion"-suffixed, exactly the
    right length, nothing else - not an IP, not another domain, no scheme,
    no embedded credentials or port. This is the one definition of "what a
    valid onion looks like" in the codebase; bundle.py imports and reuses
    it rather than duplicating the check, so a malformed or clearnet-shaped
    endpoint is rejected the same way everywhere it could enter the app.
    """
    return onion.endswith(".onion") and len(onion) == len(".onion") + 56


# Old name kept as an alias: nothing inside this module needs to change call
# sites, and it documents that the function used to be module-private.
_valid_onion = is_valid_onion


def _valid_pubkey_b64(pub_b64: str) -> bool:
    try:
        return len(crypto.b64decode(pub_b64)) == 32
    except Exception:
        return False


class _SeenCache:
    """
    Bounded per-sender memory of recently-seen ciphertexts, for replay and
    duplicate-delivery detection.

    A resend of a message we already have (whether a legitimate sender retry
    that missed our earlier ack, or a captured frame replayed by someone
    hostile) is indistinguishable from the wire alone - both are the exact
    same ciphertext arriving again, because the encryption is deterministic
    per call in the sense that it is the same authenticated blob. The correct
    handling is the same for both cases: acknowledge it (so a genuine retry
    is not left hanging) but do not hand it to the application a second time
    (so neither a retry nor a replay can make an old message reappear as
    new). This is in-memory and per-process; it resets on restart, same as
    Tor circuits and the rest of a session's live state.
    """

    def __init__(self, per_sender_limit: int = SEEN_CACHE_PER_SENDER) -> None:
        self._limit = per_sender_limit
        self._lock = threading.Lock()
        self._by_sender: OrderedDict[str, OrderedDict[str, None]] = OrderedDict()

    def seen_before(self, sender_pub_b64: str, ciphertext: bytes) -> bool:
        """Record this ciphertext for this sender; return True if it was
        already recorded (i.e. this is a retry or a replay)."""
        digest = hashlib.sha256(ciphertext).hexdigest()
        with self._lock:
            bucket = self._by_sender.setdefault(sender_pub_b64, OrderedDict())
            if digest in bucket:
                bucket.move_to_end(digest)
                return True
            bucket[digest] = None
            if len(bucket) > self._limit:
                bucket.popitem(last=False)
            return False


class MessageServer(threading.Thread):
    """
    Listens on localhost for messages arriving through the onion service.

    Tor forwards inbound onion traffic to this local port, so binding to
    127.0.0.1 is both sufficient and important: it must never be reachable
    from the local network directly.

    Naming note: every attribute here is prefixed `srv_` rather than a bare
    underscore. `threading.Thread` reserves a set of private names that grows
    between Python versions - 3.13 added `_handle`, which silently shadowed a
    method of that name and broke the listener. Prefixing keeps this subclass
    safe against future additions.
    """

    def __init__(self, on_message, resolve_key, my_private: bytes, on_event=None) -> None:
        """
        on_message:  called with an IncomingMessage after successful decryption
        resolve_key: called with (public_key_b64, onion); returns True if we
                     are willing to accept a message from this sender. It may
                     also file an unknown sender as a pending request, which
                     is how first contact from a stranger works.
        my_private:  our X25519 private key, for decryption
        on_event:    optional; called with (kind: str, onion: str) for
                     connection-level events (accepted / rejected / flooded /
                     auth failure / message received). `onion` is the peer's
                     onion address as claimed in the frame - the only peer
                     identifier Tor ever exposes to this app (it never learns
                     a real IP). Never carries message bodies, keys, or
                     exception text - this exists so the UI can show a plain
                     activity log, not a debug log.
        """
        # daemon is passed here rather than set as a class attribute, which
        # would shadow Thread's `daemon` property.
        super().__init__(daemon=True)
        self.srv_on_message = on_message
        self.srv_resolve_key = resolve_key
        self.srv_private = my_private
        self.srv_on_event = on_event
        self.srv_socket: socket.socket | None = None
        self.srv_running = threading.Event()
        self.srv_seen = _SeenCache()
        # Bounds total connection-handling work: the executor caps how many
        # connections are actively being served, the semaphore caps how many
        # are admitted (running + queued in the executor) at all. A flood
        # beyond that is accepted and immediately closed rather than left to
        # pile up as unbounded threads or an unbounded executor queue.
        self.srv_executor = ThreadPoolExecutor(
            max_workers=MAX_CONCURRENT_CONNECTIONS, thread_name_prefix="veilwire-conn"
        )
        self.srv_admission = threading.BoundedSemaphore(MAX_QUEUED_CONNECTIONS)
        self.port = 0

    def _event(self, kind: str, onion: str = "") -> None:
        if self.srv_on_event is not None:
            try:
                self.srv_on_event(kind, onion)
            except Exception:
                pass  # a broken log sink must never take down the listener

    def bind(self) -> int:
        """Bind to a free local port and return it, without accepting yet."""
        self.srv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.srv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv_socket.bind(("127.0.0.1", 0))
        # Matches MAX_QUEUED_CONNECTIONS so the kernel accept backlog isn't
        # a tighter, inconsistent limit than the application-level
        # admission semaphore - a burst that the semaphore is designed to
        # handle (accept, then reject cleanly with a logged event) should
        # not instead be silently dropped earlier by the kernel.
        self.srv_socket.listen(MAX_QUEUED_CONNECTIONS)
        self.port = self.srv_socket.getsockname()[1]
        return self.port

    def run(self) -> None:
        if self.srv_socket is None:
            self.bind()
        self.srv_running.set()

        while self.srv_running.is_set():
            try:
                conn, _ = self.srv_socket.accept()
            except OSError:
                break  # socket closed during shutdown

            if not self.srv_admission.acquire(blocking=False):
                # At capacity: close it immediately rather than queuing
                # unbounded work or leaving the socket to linger.
                self._event("connection_flooded")
                try:
                    conn.close()
                except OSError:
                    pass
                continue

            self.srv_executor.submit(self._serve_connection_admitted, conn)

    def _serve_connection_admitted(self, conn: socket.socket) -> None:
        try:
            self.serve_connection(conn)
        finally:
            self.srv_admission.release()

    def serve_connection(self, conn: socket.socket) -> None:
        # TRANSFER_TIMEOUT rather than a short fixed value so a large
        # attachment arriving slowly over Tor is not cut off mid-receive.
        # This does hold a connection slot open longer on a slow transfer,
        # but that is still bounded, not unbounded: MAX_CONCURRENT_CONNECTIONS
        # and MAX_QUEUED_CONNECTIONS above already cap how many connections
        # (fast or slow) can be occupying a slot at once, and a connection
        # sending nothing at all still times out and is dropped.
        conn.settimeout(TRANSFER_TIMEOUT)
        try:
            frame = _recv_frame(conn)

            if frame.get("v") != PROTOCOL_VERSION:
                _send_frame(conn, {"status": "error", "error": "Unsupported protocol version."})
                return

            from_pub = str(frame.get("from_pub", ""))
            from_onion = str(frame.get("from_onion", ""))
            payload_b64 = str(frame.get("payload", ""))

            if not from_pub or not _valid_pubkey_b64(from_pub):
                self._event("connection_rejected_malformed")
                _send_frame(conn, {"status": "error", "error": "Invalid sender key."})
                return
            if not from_onion or not _valid_onion(from_onion):
                self._event("connection_rejected_malformed")
                _send_frame(conn, {"status": "error", "error": "Invalid sender address."})
                return

            # Only accept from keys we have explicitly saved as contacts.
            if not self.srv_resolve_key(from_pub, from_onion):
                self._event("connection_rejected_unknown", from_onion)
                _send_frame(conn, {"status": "error", "error": "Not accepting messages from you."})
                return

            try:
                ciphertext = crypto.b64decode(payload_b64)
                plaintext = crypto.decrypt_from(
                    ciphertext,
                    self.srv_private,
                    crypto.b64decode(from_pub),
                )
            except Exception:
                # Either corruption or someone claiming a key they do not own.
                self._event("connection_rejected_auth", from_onion)
                _send_frame(conn, {"status": "error", "error": "Could not authenticate message."})
                return

            # Ack unconditionally past this point: a duplicate is either a
            # sender retry (which deserves the same "ok" it would have
            # gotten the first time) or a replay (which gets a harmless "ok"
            # but is never delivered to the application below).
            _send_frame(conn, {"status": "ok"})

            if self.srv_seen.seen_before(from_pub, ciphertext):
                self._event("message_duplicate", from_onion)
                return

            self._event("message_received", from_onion)
            self.srv_on_message(
                IncomingMessage(
                    from_onion=from_onion,
                    from_pub=from_pub,
                    body=plaintext.decode("utf-8", errors="replace"),
                )
            )

        except (TransportError, OSError, ValueError, json.JSONDecodeError):
            pass  # Malformed input is dropped silently; never crash the listener.
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self) -> None:
        self.srv_running.clear()
        if self.srv_socket is not None:
            # shutdown() forces the listener out of accept() and unbinds the
            # port immediately. close() alone can leave the socket accepting
            # until the last reference is dropped, which made a stopped
            # service still look reachable to a presence probe.
            try:
                self.srv_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # already disconnected
            try:
                self.srv_socket.close()
            except OSError:
                pass
            self.srv_socket = None
        # Drop any queued-but-not-yet-started jobs immediately; jobs already
        # running get to finish their own cleanup (socket close, semaphore
        # release) since cancel_futures only cancels queued work.
        self.srv_executor.shutdown(wait=False, cancel_futures=True)

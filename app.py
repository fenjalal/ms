"""
app.py

Desktop UI for Veilwire - peer-to-peer encrypted messaging over Tor.

There is no server and no account. Starting the app publishes a Tor onion
service on this machine; that address plus your public key is your identity.
Contacts connect straight to it through Tor, so neither side ever learns the
other's IP address, and there is no third party in the middle that could read
messages or be compelled to hand over records.
"""

from __future__ import annotations

import base64
import hashlib
import io
import logging
import os
import mimetypes
import secrets
import sys
import threading
import uuid
from datetime import datetime

import segno
from PySide6.QtCore import QBuffer, QByteArray, QPoint, QSize, Qt, QThread, QUrl, Signal
from PySide6.QtGui import (
    QColor,
    QDesktopServices,
    QFont,
    QGuiApplication,
    QIcon,
    QImage,
    QPainter,
    QPixmap,
    QTransform,
)
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSplitter,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

import bundle as bundle_mod
import crypto
import envelope
import group_invite as invite_mod
import i18n
import paths
import theme
import tor_service
import transport
import vault as vault_mod
import version
from transport import MessageServer

APP_NAME = version.APP_NAME


def format_timestamp(iso_timestamp: str) -> str:
    try:
        return datetime.fromisoformat(iso_timestamp).astimezone().strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return iso_timestamp


def escape_html(text: str) -> str:
    import html

    return html.escape(text)


def _is_endpoint_change_warning(contact_name: str) -> bool:
    """
    True if this pending contact's name carries the endpoint-changed marker
    vault._file_endpoint_change() attaches (see vault.py). Checked by
    prefix rather than a dedicated Contact field, matching how the
    impersonation-detection marker from the previous hardening pass is
    already carried in the display name - no vault schema change needed to
    add this UI distinction.
    """
    return contact_name.startswith("⚠ Endpoint changed for")


# Detailed exception info (tracebacks, exception messages that may contain
# local paths or usernames) goes here - stderr, the same place it would
# already be visible to anyone running the app from a terminal. Nothing new
# is exposed beyond that, and no log file is created: a persistent file is
# more metadata surface than the problem being solved, and this app already
# keeps its only durable state in vault.dat/tor-data.
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
_logger = logging.getLogger("veilwire")


def safe_error_text(exc: BaseException, fallback: str) -> str:
    """
    User-facing text for an exception.

    Never returns str(exc) - that can contain filesystem paths (which reveal
    the local username), socket/host details, or other internal state that
    has no business in a dialog box. The real detail is logged separately
    via _logger.exception() at the call site, not returned here.
    """
    return fallback


# --------------------------------------------------------------------------- #
# Connection state (the only technical-sounding text the UI is allowed to
# show, and even this is a fixed, closed vocabulary - see
# MainWindow._set_connection_state)
# --------------------------------------------------------------------------- #

STATE_STARTING = "starting"
STATE_CONNECTING = "connecting"
STATE_READY = "ready"
STATE_OFFLINE = "offline"
STATE_RECONNECTING = "reconnecting"

# (displayed word, color level) - the complete set of strings the
# persistent connection indicator can ever show. No Tor/onion/relay/
# circuit/bootstrap/SOCKS/listener language anywhere in this table by
# design; the underlying mechanism keeps working exactly as before, this
# only controls what a normal user sees.
_CONNECTION_STATES = {
    STATE_STARTING: ("Starting", "info"),
    STATE_CONNECTING: ("Connecting…", "info"),
    STATE_READY: ("Ready", "ok"),
    STATE_OFFLINE: ("Offline", "error"),
    STATE_RECONNECTING: ("Reconnecting…", "warn"),
}

# --------------------------------------------------------------------------- #
# Conversation list item kind (contact vs. group), stored alongside the id
# already carried in Qt.UserRole so the sidebar can hold both in one merged,
# recency-sorted list.
# --------------------------------------------------------------------------- #
_ITEM_KIND_ROLE = Qt.UserRole + 1
_KIND_CONTACT = "contact"
_KIND_GROUP = "group"


def _wire_body_for(
    vault: "vault_mod.Vault", message: "vault_mod.Message", acked_group_ids: set[str] | None = None,
) -> str:
    """
    The exact plaintext to hand to transport.send_message for this outgoing
    message, whether it is being sent for the first time or retried by
    DeliveryWorker.

    Verbatim message.body for an ordinary 1:1 text message - unchanged from
    before group/file support existed, the common and most-tested path. A
    group tag and/or a file attachment needs a fresh envelope.py envelope
    instead, since transport.py itself has no notion of either, and a
    retried send needs that context exactly as much as the original send
    did (a receiver that only saw the raw text on retry would lose the
    group/file framing entirely).

    A message with is_delete_request=True is not a displayed message at all
    - it is the queued notification half of "delete for everyone" (see
    vault.Vault.queue_delete_request()) - so it always encodes as a "delete"
    control envelope naming the message it wants deleted (its client_msg_id,
    not its own local id), never as "text"/"file".

    `acked_group_ids` (MainWindow._acked_group_ids): a group this vault
    joined via invite (group.joined_invite_code is non-empty) keeps
    attaching that code to every message sent to it until its gid appears
    here - the owner's vault is the only place that can validate the code
    (see vault.redeem_group_invite_locally), so every send/retry has to
    keep proving invitation until that owner-side confirmation lands.
    Never attached for a group this vault owns (joined_invite_code is
    always "" there - an owner never redeems its own invite).
    """
    if message.is_delete_request:
        gname = ""
        if message.group_id:
            group = vault.get_group(message.group_id)
            gname = group.name if group is not None else ""
        return envelope.encode_delete(message.client_msg_id, gid=message.group_id, gname=gname)

    invcode = message.pending_invcode  # a directly-added member's own onboarding code, if any
    if not invcode and message.group_id:
        group = vault.get_group(message.group_id)
        if (
            group is not None and group.joined_invite_code
            and (acked_group_ids is None or group.id not in acked_group_ids)
        ):
            invcode = group.joined_invite_code

    if message.attachment_filename:
        try:
            data = base64.b64decode(message.body)
        except Exception:
            data = b""
        gname = ""
        if message.group_id:
            group = vault.get_group(message.group_id)
            gname = group.name if group is not None else ""
        return envelope.encode_file(
            message.attachment_filename, message.attachment_mime, data,
            gid=message.group_id, gname=gname, mid=message.client_msg_id, invcode=invcode,
        )
    if message.group_id:
        group = vault.get_group(message.group_id)
        gname = group.name if group is not None else ""
        return envelope.encode_text(
            message.body, gid=message.group_id, gname=gname,
            mid=message.client_msg_id, invcode=invcode,
        )
    return envelope.encode_text(message.body, mid=message.client_msg_id)


def _on_transport_event(kind: str, onion: str) -> None:
    """
    MessageServer callback - runs on a network thread. Diagnostic-only:
    logs to stderr (via _logger, already the app's one non-UI detail
    channel) and never touches a widget or reaches the UI in any way.

    Never logs the onion address itself - only a short, one-way hash of it
    (crypto.onion_short_id), so repeated events from the same peer are
    visibly connected in the log without the log ever containing something
    that identifies where to connect.
    """
    detail = f" peer={crypto.onion_short_id(onion)}" if onion else ""
    _logger.info("transport event: %s%s", kind, detail)


# --------------------------------------------------------------------------- #
# Unlock / create vault
# --------------------------------------------------------------------------- #

class UnlockDialog(QDialog):
    """Asks for the passphrase that protects the local vault."""

    def __init__(self, is_new: bool, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.is_new = is_new
        self.passphrase = ""

        self.setWindowTitle(self.tr("Create Identity") if is_new else self.tr("Unlock"))
        self.setMinimumWidth(420)

        layout = QVBoxLayout(self)

        if is_new:
            intro = QLabel(
                self.tr(
                    "Choose a passphrase to protect your identity and message history "
                    "on this computer.\n\n"
                    "There is no recovery. If you forget it, your identity and all "
                    "messages are permanently lost."
                )
            )
        else:
            intro = QLabel(self.tr("Enter your passphrase to unlock."))
        intro.setWordWrap(True)
        layout.addWidget(intro)

        form = QFormLayout()
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.Password)
        form.addRow(self.tr("Passphrase"), self.pass_input)

        self.confirm_input: QLineEdit | None = None
        if is_new:
            self.confirm_input = QLineEdit()
            self.confirm_input.setEchoMode(QLineEdit.Password)
            form.addRow(self.tr("Confirm"), self.confirm_input)
        layout.addLayout(form)

        self.error_label = QLabel("")
        self.error_label.setStyleSheet(f"color: {theme.detect_palette(QApplication.instance()).error};")
        self.error_label.setWordWrap(True)
        layout.addWidget(self.error_label)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.pass_input.returnPressed.connect(self._on_accept)

    def _on_accept(self) -> None:
        value = self.pass_input.text()

        if self.is_new:
            if len(value) < 8:
                self.error_label.setText(self.tr("Use at least 8 characters."))
                return
            if self.confirm_input is not None and value != self.confirm_input.text():
                self.error_label.setText(self.tr("The two passphrases do not match."))
                return

        if not value:
            self.error_label.setText(self.tr("Enter your passphrase."))
            return

        self.passphrase = value
        self.accept()


# --------------------------------------------------------------------------- #
# Background workers
# --------------------------------------------------------------------------- #

class TorStartWorker(QThread):
    """Starts Tor and publishes the onion service without blocking the UI."""

    progress = Signal(str)
    finished_ok = Signal(str, str)  # onion, onion_key
    failed = Signal(str)

    def __init__(self, manager: tor_service.TorManager, local_port: int, onion_key: str) -> None:
        super().__init__()
        self._manager = manager
        self._local_port = local_port
        self._onion_key = onion_key

    def run(self) -> None:
        try:
            self.progress.emit("Starting Tor...")
            self._manager.start(progress=lambda line: self.progress.emit(line))
            self.progress.emit("Publishing your onion service...")
            service = self._manager.publish(self._local_port, self._onion_key)
            self.finished_ok.emit(service.onion, service.private_key)
        except tor_service.TorError as exc:
            self.failed.emit(str(exc))
        except Exception as exc:  # noqa: BLE001
            _logger.exception("Unexpected error starting Tor")
            self.failed.emit(safe_error_text(exc, self.tr("An unexpected error occurred while starting Tor.")))


class SendWorker(QThread):
    """Delivers one message over Tor."""

    done = Signal(bool, str)

    def __init__(self, **kwargs) -> None:
        super().__init__()
        self._kwargs = kwargs

    def run(self) -> None:
        try:
            transport.send_message(**self._kwargs)
            self.done.emit(True, "")
        except transport.TransportError as exc:
            self.done.emit(False, str(exc))
        except Exception as exc:  # noqa: BLE001
            _logger.exception("Unexpected error sending a message")
            self.done.emit(False, safe_error_text(exc, self.tr("An unexpected error occurred while sending.")))


class ChunkedSendWorker(QThread):
    """
    Sends a large file (over envelope.MAX_FILE_BYTES) as a sequence of
    KIND_FILE_CHUNK envelopes - one transport.send_message() call per
    chunk, sequentially (same one-connection-per-message model as every
    other send in this app - see transport.py's own docstring on why
    that was kept simple rather than reusing one Tor connection across
    the whole transfer).

    Reads chunk bytes from the ORIGINAL file on disk on demand - never
    loads the whole file into memory at once, which is the entire point
    of chunking a multi-GB transfer. Only sends chunks whose index is
    NOT YET in `already_done` (the transfer's vault.FileTransfer.chunks_done
    bitmap at the time this worker was started) - this is what makes a
    resumed transfer (see DeliveryWorker's resume branch) skip
    already-acknowledged chunks instead of resending the whole file.

    Stops (does not loop retrying) the first time a chunk's
    transport.send_message() raises TransportError - e.g. the contact
    went offline mid-transfer. The chunks already sent stay marked done
    (vault.Vault.mark_chunk_done was already called for each one as it
    succeeded), so the NEXT attempt (a manual retry or DeliveryWorker's
    sweep) only needs to send what's left, never restarting from zero.

    `start_wire`, when given, is a pre-built KIND_FILE_START envelope
    sent once, before the first chunk - the initial send's announcement.
    Sent from THIS background thread (not synchronously on the UI thread
    from _start_contact_chunked_send) so a slow/stalled connection to a
    just-gone-offline contact cannot block the UI for up to
    transport.CONNECT_TIMEOUT seconds, the same reasoning every other
    network call in this app already routes through a QThread for. Left
    unset (None) on a resume (see DeliveryWorker.resume_transfer) - the
    receiver already has this transfer's FileTransfer record from the
    first attempt, so re-announcing it is unnecessary. A start_wire send
    failure is caught and logged the same as a chunk's, and does NOT
    stop the chunk loop from being attempted anyway - the receiver's
    _on_file_chunk tolerates a chunk with no prior file_start by
    starting the transfer implicitly (see that method's docstring).
    """

    # transfer_id, chunk_index_just_sent
    progress = Signal(str, int)
    # transfer_id, success, error
    done = Signal(str, bool, str)

    def __init__(
        self, transfer_id: str, file_path: str, chunk_count: int,
        already_done: set[int], onion: str, their_public_b64: str,
        my_private: bytes, my_public_b64: str, my_onion: str, socks_port: int,
        gid: str = "", gname: str = "", start_wire: str | None = None,
    ) -> None:
        super().__init__()
        self._transfer_id = transfer_id
        self._file_path = file_path
        self._chunk_count = chunk_count
        self._already_done = already_done
        self._onion = onion
        self._their_public_b64 = their_public_b64
        self._my_private = my_private
        self._my_public_b64 = my_public_b64
        self._my_onion = my_onion
        self._socks_port = socks_port
        self._gid = gid
        self._gname = gname
        self._start_wire = start_wire

    def _send(self, wire_body: str) -> None:
        transport.send_message(
            onion=self._onion,
            their_public_b64=self._their_public_b64,
            body=wire_body,
            my_private=self._my_private,
            my_public_b64=self._my_public_b64,
            my_onion=self._my_onion,
            socks_port=self._socks_port,
        )

    def run(self) -> None:
        try:
            if self._start_wire is not None:
                try:
                    self._send(self._start_wire)
                except transport.TransportError:
                    pass  # see docstring: chunks are still attempted; receiver tolerates a missing file_start
            with open(self._file_path, "rb") as f:
                for index in range(self._chunk_count):
                    if index in self._already_done:
                        continue
                    f.seek(index * envelope.CHUNK_SIZE)
                    chunk = f.read(envelope.CHUNK_SIZE)
                    wire_body = envelope.encode_file_chunk(
                        self._transfer_id, index, self._chunk_count, chunk,
                    )
                    self._send(wire_body)
                    self._already_done.add(index)
                    self.progress.emit(self._transfer_id, index)
        except OSError as exc:
            _logger.exception("Could not read file during chunked send")
            self.done.emit(
                self._transfer_id, False,
                safe_error_text(exc, self.tr("Could not read that file.")),
            )
            return
        except transport.TransportError as exc:
            self.done.emit(self._transfer_id, False, str(exc))
            return
        except Exception as exc:  # noqa: BLE001
            _logger.exception("Unexpected error during chunked send")
            self.done.emit(
                self._transfer_id, False,
                safe_error_text(exc, self.tr("An unexpected error occurred while sending.")),
            )
            return
        self.done.emit(self._transfer_id, True, "")


class GroupSendWorker(QThread):
    """
    Delivers one group message: an individually Box-encrypted, individually
    Tor-delivered send to every current member, sequentially.

    There is no fan-out at the network layer to parallelize (each send is
    its own Tor circuit through a shared SOCKS proxy) - sequential keeps
    this simple and avoids hammering the local Tor SOCKS port with several
    connections at once for what, in realistic group sizes, is still a
    handful of sends. A member who is offline or unreachable fails that one
    send only; per_result is emitted for every member regardless, so the
    caller can save a QUEUED Message for the ones that failed exactly like
    a 1:1 send does, and DeliveryWorker's existing retry sweep (see
    _wire_body_for) picks those back up the same way it retries any other
    queued message.
    """

    # member_contact_id, success, error
    per_result = Signal(str, bool, str)
    finished_all = Signal()

    def __init__(
        self, members: list[tuple[str, str, str, str]],
        my_private: bytes, my_public_b64: str, my_onion: str, socks_port: int,
    ) -> None:
        """members: list of (contact_id, onion, public_key_b64, wire_body)
        - resolved by the caller before starting the thread, so this class
        never touches the Vault itself (same "workers do network I/O, the
        UI thread owns vault state" split every other worker here
        follows). wire_body is per-member, not shared, because a
        brand-new member's envelope carries their own individually-minted
        invite code (see _start_group_send) - reusing one shared code
        across multiple new members would let only the first of them
        actually redeem it, exactly the single-use property this is
        supposed to have."""
        super().__init__()
        self._members = members
        self._my_private = my_private
        self._my_public_b64 = my_public_b64
        self._my_onion = my_onion
        self._socks_port = socks_port

    def run(self) -> None:
        for contact_id, onion, public_key_b64, wire_body in self._members:
            try:
                transport.send_message(
                    onion=onion,
                    their_public_b64=public_key_b64,
                    body=wire_body,
                    my_private=self._my_private,
                    my_public_b64=self._my_public_b64,
                    my_onion=self._my_onion,
                    socks_port=self._socks_port,
                )
                self.per_result.emit(contact_id, True, "")
            except transport.TransportError as exc:
                self.per_result.emit(contact_id, False, str(exc))
            except Exception as exc:  # noqa: BLE001
                _logger.exception("Unexpected error sending a group message to one member")
                self.per_result.emit(
                    contact_id, False,
                    safe_error_text(exc, self.tr("An unexpected error occurred while sending.")),
                )
        self.finished_all.emit()


# --------------------------------------------------------------------------- #
# Main window
# --------------------------------------------------------------------------- #

class HealthMonitor(QThread):
    """
    Continuously verifies that we are actually reachable, and repairs what it
    can.

    Tor can look fine while the onion service is silently gone - an ephemeral
    service disappears if Tor restarts or the control connection drops, and
    nothing tells you. Without this, the app would sit there showing "Online"
    while no contact could reach you.

    Checks, cheapest first:
      1. control connection alive
      2. circuits established
      3. our onion service still registered  -> republished automatically
      4. local listener still accepting
    """

    status = Signal(str, str)  # level ("ok"/"warn"/"error"), human text
    republished = Signal()

    CHECK_INTERVAL = 20  # seconds

    def __init__(self, manager, server, parent=None) -> None:
        super().__init__(parent)
        self._manager = manager
        self._server = server
        self._stop = threading.Event()
        self._check_now = threading.Event()

    def request_check(self) -> None:
        """Trigger an immediate check instead of waiting for the next tick."""
        self._check_now.set()

    def stop(self) -> None:
        self._stop.set()
        self._check_now.set()

    def run(self) -> None:
        while not self._stop.is_set():
            self._check_now.wait(self.CHECK_INTERVAL)
            self._check_now.clear()
            if self._stop.is_set():
                return
            try:
                self._run_checks()
            except Exception as exc:  # noqa: BLE001 - never kill the monitor
                _logger.exception("Health check failed")
                # This text is diagnostic-only: _on_health_status (app.py)
                # only ever reads the level ("error"/"warn"/"ok") from this
                # signal and discards the accompanying string, so it is
                # never shown to the user and does not need translation -
                # matches every other internal-only detail string here.
                self.status.emit("error", safe_error_text(exc, "Health check failed."))

    def _run_checks(self) -> None:
        if not self._manager.is_controller_alive():
            self.status.emit("error", "Lost the connection to Tor.")
            return

        if not self._manager.circuit_established():
            self.status.emit("warn", "Tor is connected but has no circuits yet.")
            return

        if self._server is not None and not self._server.is_alive():
            self.status.emit("error", "The local listener stopped. Restart the app.")
            return

        if not self._manager.is_service_published():
            self.status.emit("warn", "Your onion service vanished. Republishing...")
            try:
                port = self._server.port if self._server is not None else 0
                self._manager.republish(port)
                self.status.emit("ok", "Onion service republished. Same address.")
                self.republished.emit()
            except Exception as exc:  # noqa: BLE001
                _logger.exception("Could not republish onion service")
                self.status.emit("error", safe_error_text(exc, "Could not republish your onion service."))
            return

        self.status.emit("ok", "Online and reachable.")


def _copy_icon(color: str) -> QIcon:
    """
    A small "copy" glyph (two overlapping rounded rectangles), drawn with
    QPainter rather than taken from a Unicode character. A text glyph
    (clipboard emoji, or any of several "copy" symbol-block characters)
    was tried first and rejected: whether a given Unicode code point
    actually has a visible glyph depends entirely on which fonts happen
    to be installed, and this was verified empirically to render as an
    unrecognizable placeholder/tofu box on a real test system - drawing
    the icon directly guarantees the same correct appearance everywhere,
    with no font-fallback dependency at all.
    """
    size = 16
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    pen = painter.pen()
    pen.setColor(QColor(color))
    pen.setWidth(1)
    painter.setPen(pen)
    painter.setBrush(Qt.NoBrush)
    # Back rectangle (partially hidden behind the front one) then the
    # front rectangle, offset down-right - the standard "duplicate" icon
    # shape used across most desktop icon sets.
    painter.drawRoundedRect(2, 2, 10, 10, 2, 2)
    painter.drawRoundedRect(5, 5, 10, 10, 2, 2)
    painter.end()
    return QIcon(pixmap)


def _chevron_icon(color: str, pointing_left: bool) -> QIcon:
    """
    A simple "‹"/"›" chevron, drawn with QPainter rather than taken from
    a Unicode character - same reasoning and same font-fallback failure
    mode already documented on _copy_icon above (verified empirically:
    those exact glyphs rendered as an empty box on this system's default
    button font). Used for the sidebar collapse/expand toggle.
    """
    size = 16
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    pen = painter.pen()
    pen.setColor(QColor(color))
    pen.setWidth(2)
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    painter.setPen(pen)
    if pointing_left:
        points = [(10, 3), (5, 8), (10, 13)]
    else:
        points = [(6, 3), (11, 8), (6, 13)]
    painter.drawPolyline([QPoint(x, y) for x, y in points])
    painter.end()
    return QIcon(pixmap)


class SelfTestWorker(QThread):
    """Connects to our own onion address through Tor to prove reachability."""

    done = Signal(bool, str)

    def __init__(self, manager, parent=None) -> None:
        super().__init__(parent)
        self._manager = manager

    def run(self) -> None:
        ok, message = self._manager.self_test()
        self.done.emit(ok, message)


class IdentityDialog(QDialog):
    """
    Key management.

    Shows what is safe to share (address, public key, fingerprint), lets the
    user back up what must never be shared (the private key, encrypted), and
    controls whether strangers may make first contact.
    """

    def __init__(self, vault, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.vault = vault
        self.setWindowTitle(self.tr("My Identity & Keys"))
        # A sensible starting size, not a fixed one - the dialog is freely
        # resizable so a long key/fingerprint always has room to actually
        # be read, on any screen size, rather than being squeezed into a
        # fixed-width field.
        self.resize(620, 560)
        self.setMinimumWidth(480)
        self.setSizeGripEnabled(True)

        layout = QVBoxLayout(self)
        identity = vault.identity

        bold = QFont()
        bold.setBold(True)

        mono_font = QFont("monospace")
        mono_font.setPointSize(11)

        # --- Shareable ---
        share_title = QLabel(self.tr("Safe to share"))
        share_title.setFont(bold)
        layout.addWidget(share_title)

        form = QFormLayout()
        form.setFieldGrowthPolicy(QFormLayout.AllNonFixedFieldsGrow)

        # Each field sits in its own row with a small icon-only copy
        # button right next to it, matched to the field's own height -
        # replaces the old separate "Copy public key"/"Copy fingerprint"
        # text buttons underneath, which repeated words already on
        # screen (the field's own label) for no benefit. Uses _copy_icon()
        # (a drawn vector icon) rather than a Unicode glyph - see that
        # function's docstring for why: a text glyph's actual appearance
        # depends on which fonts happen to be installed, and this was
        # verified to render as an unrecognizable placeholder on a real
        # test system for every Unicode "copy" candidate tried.
        copy_icon = _copy_icon(theme.detect_palette(QApplication.instance()).text)

        def _field_with_copy_button(field: QLineEdit, value: str, copied_text: str) -> QWidget:
            row = QWidget()
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(0, 0, 0, 0)
            row_layout.setSpacing(4)
            row_layout.addWidget(field)
            copy_btn = QPushButton()
            copy_btn.setIcon(copy_icon)
            copy_btn.setFixedSize(field.sizeHint().height(), field.sizeHint().height())
            copy_btn.setToolTip(self.tr("Copy"))
            copy_btn.clicked.connect(lambda: self._copy(value, copied_text))
            row_layout.addWidget(copy_btn)
            return row

        self.pubkey_field = QLineEdit(identity.public_key)
        self.pubkey_field.setReadOnly(True)
        # Monospace so every character of a base64 key renders at the same
        # width - a proportional font makes long random-looking strings
        # harder to scan and more prone to looking visually "jumbled".
        self.pubkey_field.setFont(mono_font)
        self.pubkey_field.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.pubkey_field.setMinimumWidth(0)
        # Without this, Qt leaves the cursor at the end of the text after
        # setText(), so a long value (a 43-char base64 key) shows its tail
        # instead of its start - looks like the field is showing garbage
        # or cut off. Same fix already applied to my_address elsewhere.
        self.pubkey_field.setCursorPosition(0)
        self.pubkey_field.setToolTip(
            self.tr(
                "For verification only - this alone is not enough for someone "
                "to add you. Use Share Contact to actually let someone connect."
            )
        )
        form.addRow(
            self.tr("Public key"),
            _field_with_copy_button(self.pubkey_field, identity.public_key, self.tr("Public key copied.")),
        )

        fingerprint_font = QFont("monospace")
        fingerprint_font.setBold(True)
        fingerprint_font.setPointSize(12)
        self.fingerprint_field = QLineEdit(identity.fingerprint)
        self.fingerprint_field.setReadOnly(True)
        self.fingerprint_field.setFont(fingerprint_font)
        self.fingerprint_field.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.fingerprint_field.setMinimumWidth(0)
        self.fingerprint_field.setCursorPosition(0)
        form.addRow(
            self.tr("Fingerprint"),
            _field_with_copy_button(self.fingerprint_field, identity.fingerprint, self.tr("Fingerprint copied.")),
        )

        layout.addLayout(form)

        hint = QLabel(
            self.tr(
                "Anyone holding your contact bundle can send you a first message. "
                "Read your fingerprint aloud to a contact so they can confirm "
                "they have the real you and not an impostor. Your exact connection "
                "details stay internal to the app and are never shown directly - "
                "share your contact instead."
            )
        )
        hint.setWordWrap(True)
        hint.setObjectName("muted")
        layout.addWidget(hint)

        share_button = QPushButton(self.tr("Share Contact..."))
        share_button.setObjectName("primary")
        share_button.setToolTip(
            self.tr(
                "Shows a QR code and a copyable bundle a contact can scan or "
                "paste to add you - without exposing your connection details."
            )
        )
        share_button.clicked.connect(self._on_share)
        layout.addWidget(share_button)

        # --- Private ---
        private_header = QHBoxLayout()
        shield_pixmap = _load_brand_pixmap("veilwire-shield.png", 28)
        if shield_pixmap is not None:
            shield_label = QLabel()
            shield_label.setPixmap(shield_pixmap)
            private_header.addWidget(shield_label)
        private_title = QLabel(self.tr("Private - never share"))
        private_title.setFont(bold)
        private_title.setStyleSheet(f"color: {theme.detect_palette(QApplication.instance()).error};")
        private_header.addWidget(private_title)
        private_header.addStretch(1)
        layout.addLayout(private_header)

        warning = QLabel(
            self.tr(
                "Your private key stays in the encrypted vault on this computer "
                "and is never transmitted. A backup lets you restore this same "
                "identity on another machine. Anyone who gets both the backup "
                "file and its passphrase can impersonate you."
            )
        )
        warning.setWordWrap(True)
        warning.setObjectName("muted")
        layout.addWidget(warning)

        backup_row = QHBoxLayout()
        export_button = QPushButton(self.tr("Back up identity..."))
        export_button.clicked.connect(self._on_export)
        backup_row.addWidget(export_button)

        import_button = QPushButton(self.tr("Restore from backup..."))
        import_button.clicked.connect(self._on_import)
        backup_row.addWidget(import_button)
        layout.addLayout(backup_row)

        # --- Danger ---
        # "Who can reach me" (accept-from-anyone toggle) lives in
        # SettingsDialog now, not here - Keys stays focused on sharing/
        # backup, Settings is the one place for app-wide preferences
        # (language, privacy policy toggles).
        regenerate = QPushButton(self.tr("Create a completely new identity..."))
        regenerate.setObjectName("danger")
        regenerate.clicked.connect(self._on_regenerate)
        layout.addWidget(regenerate)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

    def _copy(self, text: str, message: str) -> None:
        if not text:
            QMessageBox.information(self, self.tr("Not ready"), self.tr("Not published yet."))
            return
        QGuiApplication.clipboard().setText(text)
        QMessageBox.information(self, self.tr("Copied"), message)

    def _on_share(self) -> None:
        identity = self.vault.identity
        if identity is None or not identity.onion:
            QMessageBox.information(self, self.tr("Not ready"), self.tr("Not published yet."))
            return
        try:
            bundle_text = bundle_mod.build_bundle(
                identity.onion,
                identity.public_key,
                identity.signing_public_key,
                identity.signing_private_key,
            )
        except bundle_mod.BundleError as exc:
            QMessageBox.critical(self, self.tr("Could not build contact bundle"), str(exc))
            return
        ShareDialog(bundle_text, identity.fingerprint, self).exec()

    def _on_export(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, self.tr("Save identity backup"), "veilwire-identity.bak"
        )
        if not path:
            return

        passphrase, ok = QInputDialog.getText(
            self,
            self.tr("Backup passphrase"),
            self.tr("Passphrase to protect this backup (at least 8 characters):"),
            QLineEdit.Password,
        )
        if not ok:
            return
        if len(passphrase) < 8:
            QMessageBox.warning(self, self.tr("Too short"), self.tr("Use at least 8 characters."))
            return

        try:
            self.vault.export_identity(path, passphrase)
        except OSError as exc:
            _logger.exception("export_identity failed")
            QMessageBox.critical(
                self,
                self.tr("Could not save"),
                safe_error_text(
                    exc, self.tr("Could not write the backup file. Check the destination and try again.")
                ),
            )
            return

        QMessageBox.information(
            self,
            self.tr("Backed up"),
            i18n.fmt(
                self.tr(
                    "Identity saved to:\n%(path)s\n\nKeep this file somewhere safe. "
                    "Anyone with it and its passphrase can become you."
                ),
                path=path,
            ),
        )

    def _on_import(self) -> None:
        confirm = QMessageBox.warning(
            self,
            self.tr("Replace identity?"),
            self.tr(
                "Restoring a backup replaces your current identity and connection "
                "details.\n\nIf you have not backed the current one up, it will be "
                "lost permanently and your contacts will no longer reach you.\n\n"
                "Continue?"
            ),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        path, _ = QFileDialog.getOpenFileName(self, self.tr("Open identity backup"))
        if not path:
            return

        passphrase, ok = QInputDialog.getText(
            self, self.tr("Backup passphrase"), self.tr("Passphrase for this backup:"), QLineEdit.Password
        )
        if not ok:
            return

        try:
            self.vault.import_identity(path, passphrase)
        except crypto.DecryptionError:
            QMessageBox.warning(
                self, self.tr("Wrong passphrase"), self.tr("That passphrase did not open the backup.")
            )
            return
        except (ValueError, OSError, KeyError) as exc:
            _logger.exception("import_identity failed")
            QMessageBox.critical(
                self,
                self.tr("Could not restore"),
                safe_error_text(exc, self.tr("Could not read that backup file.")),
            )
            return

        QMessageBox.information(
            self,
            self.tr("Restored"),
            self.tr(
                "Identity restored. Restart the app to reconnect under the "
                "restored identity."
            ),
        )
        self.accept()

    def _on_regenerate(self) -> None:
        confirm = QMessageBox.warning(
            self,
            self.tr("New identity?"),
            self.tr(
                "This creates a brand new identity and connection address.\n\n"
                "Your current identity is destroyed, and every contact will have "
                "to add your new contact info before they can reach you. Existing "
                "conversations become unreadable to them.\n\nThis cannot be undone."
            ),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        self.vault.regenerate_identity()
        QMessageBox.information(
            self,
            self.tr("New identity created"),
            self.tr("Restart the app to connect with your new identity."),
        )
        self.accept()


QR_DISPLAY_SIZE = 260  # on-screen pixel size, independent of the QR's module count


def _bundle_to_qr_pixmap(bundle_text: str) -> QPixmap:
    """
    Render a bundle string to a QPixmap via segno, entirely in memory - no
    image file is ever written to disk.

    A signed bundle is a fairly long string, so the raw QR (scale=6, a
    generous module size chosen for crisp scanning at the source
    resolution) can come out at 300-400+ px per side depending on the
    bundle's length - shown at that native size in a QLabel with no cap,
    it visually dominates the dialog. Scaling down to a fixed on-screen
    size keeps the dialog compact regardless of how long any given bundle
    happens to be, while FastTransformation preserves the crisp
    black/white edges a QR scanner needs (smooth/anti-aliased scaling
    would blur module boundaries, which can make a real phone camera
    struggle to read it).
    """
    qr = segno.make(bundle_text, error="m")
    buf = io.BytesIO()
    qr.save(buf, kind="png", scale=6, border=2)
    pixmap = QPixmap()
    pixmap.loadFromData(buf.getvalue(), "PNG")
    return pixmap.scaled(
        QR_DISPLAY_SIZE, QR_DISPLAY_SIZE, Qt.KeepAspectRatio, Qt.FastTransformation
    )


class SettingsDialog(QDialog):
    """
    App-wide preferences: display language and who is allowed to send a
    first message. Everything else identity-related (fingerprint, backup,
    Share Contact) stays in IdentityDialog - this is the one place for
    preferences that aren't about a specific identity/contact.
    """

    def __init__(self, vault, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.vault = vault
        self.setWindowTitle(self.tr("Settings"))
        self.setMinimumWidth(420)
        # Set by _on_restart_clicked; MainWindow._on_settings checks this
        # after exec() returns and performs the actual restart - a QDialog
        # closing itself is not the right place to tear down Tor/the vault
        # and re-exec the process, that has to happen in MainWindow, which
        # owns all of that state (see MainWindow._restart_app).
        self.restart_requested = False

        layout = QVBoxLayout(self)

        bold = QFont()
        bold.setBold(True)

        # --- Language ---
        language_title = QLabel(self.tr("Language"))
        language_title.setFont(bold)
        layout.addWidget(language_title)

        language_hint = QLabel(self.tr("Choose your preferred language."))
        language_hint.setWordWrap(True)
        language_hint.setObjectName("muted")
        layout.addWidget(language_hint)

        self.language_combo = QComboBox()
        self._language_codes: list[str] = []
        current = i18n.current_language()
        for code, native_name in i18n.SUPPORTED_LANGUAGES.items():
            self.language_combo.addItem(native_name)
            self._language_codes.append(code)
            if code == current:
                self.language_combo.setCurrentIndex(len(self._language_codes) - 1)
        self.language_combo.currentIndexChanged.connect(self._on_language_changed)
        layout.addWidget(self.language_combo)

        self.restart_notice = QLabel(self.tr("Restart Veilwire to apply the new language."))
        self.restart_notice.setObjectName("muted")
        self.restart_notice.setWordWrap(True)
        self.restart_notice.setVisible(False)
        layout.addWidget(self.restart_notice)

        self.restart_button = QPushButton(self.tr("Restart Now"))
        self.restart_button.setCursor(Qt.PointingHandCursor)
        self.restart_button.setVisible(False)
        self.restart_button.clicked.connect(self._on_restart_clicked)
        layout.addWidget(self.restart_button)

        # --- Who can reach me ---
        policy_title = QLabel(self.tr("Who can reach me"))
        policy_title.setFont(bold)
        layout.addWidget(policy_title)

        identity = vault.identity
        self.open_mode = QCheckBox(self.tr("Let anyone with my address send a first message"))
        self.open_mode.setChecked(bool(identity is not None and identity.accept_from_anyone))
        self.open_mode.toggled.connect(self.vault.set_accept_from_anyone)
        layout.addWidget(self.open_mode)

        policy_hint = QLabel(
            self.tr(
                "When off, only contacts you already added can message you - "
                "anyone else's first message is silently ignored instead of "
                "showing up as a request."
            )
        )
        policy_hint.setWordWrap(True)
        policy_hint.setObjectName("muted")
        layout.addWidget(policy_hint)

        layout.addStretch(1)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

    def _on_language_changed(self, index: int) -> None:
        code = self._language_codes[index]
        i18n.set_language(code)
        # Shown for any change, including picking the language already
        # active in this running session - the persisted choice only takes
        # effect on the next launch, so the notice's job is just to say
        # "this needs a restart," not to track whether it truly differs.
        self.restart_notice.setVisible(True)
        self.restart_button.setVisible(True)

    def _on_restart_clicked(self) -> None:
        self.restart_requested = True
        # accept(), not a bare close - Close still means "keep the setting,
        # restart later on your own" (the button box below), Restart Now
        # means "apply it right now." Either way the language choice itself
        # is already persisted by _on_language_changed, so this is purely
        # about when the running process picks it up.
        self.accept()


class ShareDialog(QDialog):
    """
    Shows a contact bundle ready to share: a QR code and copyable text.

    Deliberately does not show the onion address anywhere in this dialog -
    it is encoded inside the bundle (see bundle.py), not printed next to
    it. The bundle is signed, not encrypted: anyone who has this QR code or
    copied text can decode the onion inside it, the same as they could read
    today's plaintext address - what this dialog changes is that the onion
    no longer appears in the UI at a glance, and the bundle cannot be
    silently modified without the signature failing to verify.
    """

    def __init__(
        self,
        bundle_text: str,
        fingerprint: str,
        parent: QWidget | None = None,
        *,
        title: str | None = None,
        secondary_label: str | None = None,
        note_text: str | None = None,
        copy_button_text: str | None = None,
        copied_message: str | None = None,
    ) -> None:
        """
        `fingerprint`/`secondary_label`: exactly one of these is shown as
        the bold monospace line under the QR code - `fingerprint` for the
        normal contact-share case, or `secondary_label` (e.g. an invite's
        expiry time) for a caller sharing something else bundle-shaped
        (see app.py's "Create invite" flow, which passes secondary_label
        instead of a fingerprint - an invite has no fingerprint of its
        own to show). `title`/`note_text`/`copy_button_text`/
        `copied_message` default to the original contact-bundle wording
        when omitted, so both existing call sites (Share Contact) need no
        changes.
        """
        super().__init__(parent)
        self.setWindowTitle(title or self.tr("Share Contact"))
        self.resize(420, 520)
        self.setSizeGripEnabled(True)

        layout = QVBoxLayout(self)

        qr_label = QLabel()
        qr_label.setPixmap(_bundle_to_qr_pixmap(bundle_text))
        qr_label.setAlignment(Qt.AlignCenter)
        # Fixed to the QR's actual on-screen size (not Expanding) so the
        # layout never stretches it larger than QR_DISPLAY_SIZE - the
        # surrounding stretch/spacing does the rest of the layout work.
        qr_label.setFixedSize(QR_DISPLAY_SIZE, QR_DISPLAY_SIZE)
        layout.addWidget(qr_label, alignment=Qt.AlignCenter)
        layout.addStretch(1)

        fp_font = QFont("monospace")
        fp_font.setBold(True)
        fp_font.setPointSize(12)
        fp_label = QLabel(secondary_label if secondary_label is not None else fingerprint)
        fp_label.setFont(fp_font)
        fp_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(fp_label)

        note = QLabel(
            note_text if note_text is not None else self.tr(
                "This bundle is signed, not encrypted: it proves it came from "
                "this identity and cannot be modified without detection, but "
                "anyone who has it can read what's inside - same as sharing an "
                "address today. Send it only to people you intend to give your "
                "contact information to."
            )
        )
        note.setWordWrap(True)
        note.setObjectName("muted")
        layout.addWidget(note)

        copy_button = QPushButton(copy_button_text or self.tr("Copy bundle"))
        copy_button.setObjectName("primary")
        copy_button.clicked.connect(
            lambda: self._copy_bundle(bundle_text, copied_message)
        )
        layout.addWidget(copy_button)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

    def _copy_bundle(self, bundle_text: str, copied_message: str | None) -> None:
        QGuiApplication.clipboard().setText(bundle_text)
        QMessageBox.information(
            self, self.tr("Copied"), copied_message or self.tr("Contact bundle copied.")
        )


class NewGroupDialog(QDialog):
    """
    Create a group by naming it and checking off members from the
    already-added, accepted contacts list.

    There is nothing to reach out to here (unlike Add Contact) - a group
    can only be built from people already in the address book, since
    membership is local-only (see vault.Group's docstring) and a message
    still has to be individually Tor-delivered to each member's own onion
    address, which this app only ever has for an existing contact.
    """

    def __init__(self, contacts: list[vault_mod.Contact], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(self.tr("New Group"))
        self.resize(380, 440)
        self.setSizeGripEnabled(True)
        self.group_name = ""
        self.selected_contact_ids: list[str] = []
        self._contacts = contacts

        layout = QVBoxLayout(self)

        form = QFormLayout()
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText(self.tr("e.g. Friends"))
        form.addRow(self.tr("Group name"), self.name_input)
        layout.addLayout(form)

        layout.addWidget(QLabel(self.tr("Members:")))
        self.member_list = QListWidget()
        for contact in contacts:
            item = QListWidgetItem(contact.name)
            item.setData(Qt.UserRole, contact.id)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Unchecked)
            self.member_list.addItem(item)
        # Qt.ItemIsUserCheckable alone does NOT make a single click
        # anywhere on the row toggle the box - by itself it only makes
        # the indicator paint and become clickable in the few exact
        # pixels of the glyph itself, and even there Qt does not
        # auto-toggle on click without this handler (verified
        # empirically: clicking directly on the checkbox glyph did
        # nothing until this was added). Without this, the box exists
        # and paints correctly but is inert - which reads exactly like
        # "the checkmark doesn't appear" from a user's side, since
        # clicking the row (the obvious thing to do) visibly does
        # nothing at all.
        self.member_list.itemClicked.connect(self._on_member_item_clicked)
        layout.addWidget(self.member_list, stretch=1)

        self.error_label = QLabel("")
        self.error_label.setObjectName("danger-text")
        self.error_label.setWordWrap(True)
        layout.addWidget(self.error_label)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _on_member_item_clicked(self, item: QListWidgetItem) -> None:
        item.setCheckState(
            Qt.Unchecked if item.checkState() == Qt.Checked else Qt.Checked
        )

    def _on_accept(self) -> None:
        name = self.name_input.text().strip()
        if not name:
            self.error_label.setText(self.tr("Enter a name for the group."))
            return

        selected = []
        for row in range(self.member_list.count()):
            item = self.member_list.item(row)
            if item.checkState() == Qt.Checked:
                selected.append(item.data(Qt.UserRole))
        if not selected:
            self.error_label.setText(self.tr("Select at least one member."))
            return

        self.group_name = name
        self.selected_contact_ids = selected
        self.accept()


class DeliveryWorker(QThread):
    """
    Retries queued messages and tracks which contacts are online.

    There is no server holding undelivered messages, so instead of the
    recipient collecting from a mailbox, the sender keeps trying. A queued
    message stays encrypted in the sender's own vault and goes out the moment
    the recipient's onion service answers.

    That covers the common case - the other person opens the app later the
    same day - without adding any infrastructure, and without the permanent
    public record a shared ledger would create. It does require the sender's
    app to be open at some point while the recipient is also online.
    """

    presence_changed = Signal(str, bool)   # contact_id, online
    message_sent = Signal(str, str)        # contact_id, message_id
    message_failed = Signal(str, str, str)  # contact_id, message_id, reason
    activity = Signal(str, str)            # level, text
    # transfer_id - a chunked transfer to a now-online contact still has
    # unsent chunks. This worker only DETECTS that (see _sweep below) - it
    # cannot launch a ChunkedSendWorker itself (that's a QThread and must
    # be started from the UI thread, which also owns
    # MainWindow._chunked_send_workers), so it hands off via this signal
    # instead, the same "worker detects/reports, MainWindow acts" split
    # already used for presence_changed/message_sent/message_failed.
    resume_transfer = Signal(str)

    INTERVAL = 45  # seconds between sweeps

    def __init__(self, vault, manager, parent=None) -> None:
        super().__init__(parent)
        self._vault = vault
        self._manager = manager
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._online: dict[str, bool] = {}

    def wake(self) -> None:
        """Run a sweep immediately rather than waiting for the next tick."""
        self._wake.set()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def is_online(self, contact_id: str) -> bool | None:
        return self._online.get(contact_id)

    def run(self) -> None:
        while not self._stop.is_set():
            self._wake.wait(self.INTERVAL)
            self._wake.clear()
            if self._stop.is_set():
                return
            try:
                self._sweep()
            except Exception as exc:  # noqa: BLE001 - never kill the worker
                _logger.exception("Delivery sweep failed")
                self.activity.emit("error", safe_error_text(exc, "Delivery sweep failed."))

    def _sweep(self) -> None:
        if self._manager.service is None:
            return  # Tor is not up; nothing can be delivered yet.

        socks_port = self._manager.socks_port

        # Presence first, so the UI updates even with an empty queue.
        for contact in self._vault.accepted_contacts():
            if self._stop.is_set():
                return
            online = transport.check_reachable(contact.onion, socks_port)
            was_offline = self._online.get(contact.id) is False
            if self._online.get(contact.id) != online:
                self._online[contact.id] = online
                self.presence_changed.emit(contact.id, online)
            # Resume any interrupted chunked transfer the moment this
            # contact is seen online again - see FileTransfer's docstring
            # on resumability. Only fires on an offline->online edge (not
            # every sweep while already online) so a transfer already
            # being actively sent by ChunkedSendWorker is not re-launched
            # in parallel with itself every 45 seconds.
            if online and was_offline:
                for transfer in self._vault.incomplete_transfers_for_contact(contact.id):
                    self.resume_transfer.emit(transfer.id)

        queued = self._vault.queued_messages()
        if not queued:
            return

        identity = self._vault.identity
        if identity is None:
            return

        delivered = 0
        for contact, message in queued:
            if self._stop.is_set():
                return

            # Skip contacts we just saw as offline; retrying would only stall.
            if self._online.get(contact.id) is False:
                continue

            try:
                transport.send_message(
                    onion=contact.onion,
                    their_public_b64=contact.public_key,
                    body=_wire_body_for(self._vault, message),
                    my_private=self._vault.private_key_raw(),
                    my_public_b64=identity.public_key,
                    my_onion=identity.onion,
                    socks_port=socks_port,
                )
            except transport.TransportError as exc:
                self._vault.mark_message(
                    contact.id, message.id, vault_mod.QUEUED, str(exc)
                )
                self.message_failed.emit(contact.id, message.id, str(exc))
                continue

            self._vault.mark_message(contact.id, message.id, vault_mod.SENT, "")
            self.message_sent.emit(contact.id, message.id)
            delivered += 1

        if delivered:
            # Like HealthMonitor's status text, _on_health_status (app.py)
            # only reads the "ok"/"warn"/"error" level from this signal and
            # discards the accompanying string - not shown to the user.
            # Still built correctly (via i18n's numerus support) rather
            # than the hardcoded-English "s"-suffix pluralization this
            # replaced, which was wrong for every other supported language
            # regardless of whether the string is currently displayed.
            self.activity.emit(
                "ok",
                i18n.tr("Delivered %n queued message(s).", n=delivered),
            )


class MainWindow(QMainWindow):
    message_arrived = Signal(str, str)  # from_pub, body

    def __init__(self, vault: vault_mod.Vault) -> None:
        super().__init__()
        self.vault = vault
        self._active_contact_id: str | None = None
        # Non-None exactly when the sidebar selection is a group rather
        # than a contact - at most one of _active_contact_id /
        # _active_group_id is set at a time (see _on_contact_selected).
        self._active_group_id: str | None = None
        # Group ids this identity has received a KIND_GROUP_ACK for - see
        # _wire_body_for, which keeps attaching this vault's invite code
        # to every group send until the owning vault confirms real
        # membership. In-memory only (not persisted): a restart just
        # means a couple of harmless extra invcode-bearing sends before
        # the next ack arrives, not a security issue - the owner's own
        # redeem_group_invite_locally() is idempotent-safe either way
        # (an already-used code is simply refused again, same result).
        self._acked_group_ids: set[str] = set()
        self._group_send_worker: "GroupSendWorker | None" = None
        self._group_send_message_ids: dict[str, str] = {}
        self._send_worker: SendWorker | None = None
        self._tor_worker: TorStartWorker | None = None
        self.monitor: HealthMonitor | None = None
        self.delivery: DeliveryWorker | None = None
        self._self_test: SelfTestWorker | None = None
        self._pending_body = ""
        self._pending_client_msg_id = ""
        self._pending_file_message_id: str | None = None
        # The contact a message was actually sent to, captured at send time.
        # _active_contact_id can change while a send is still in flight (the
        # user is free to click another contact while waiting on the network
        # thread) - using _active_contact_id in _on_send_done instead of this
        # would file the send result under whichever contact happens to be
        # selected when the worker finishes, not the one it was sent to.
        self._pending_contact_id: str | None = None
        # Keyed by transfer_id (vault.FileTransfer.id), not a single
        # slot like _send_worker - more than one chunked transfer can be
        # in flight at once (e.g. a user-initiated send to one contact
        # while DeliveryWorker resumes an interrupted transfer to
        # another), so each needs its own worker reference to avoid one
        # overwriting/orphaning another's `finished` cleanup.
        self._chunked_send_workers: dict[str, "ChunkedSendWorker"] = {}

        self.tor = tor_service.TorManager(data_dir=os.path.join(paths.data_dir(), "tor-data"))
        self.server: MessageServer | None = None

        self.palette_colors = theme.detect_palette(QApplication.instance())

        # Deliberately just the version, not "Veilwire v1.0.0" - the app
        # name is already supplied once via QApplication.setApplicationDisplayName
        # in main(), and some window managers append that display name to
        # whatever setWindowTitle() already contains, which produced a
        # visible duplicate ("Veilwire v1.0.0 - Veilwire") in the title bar
        # when both were set here.
        self.setWindowTitle(version.version_string())
        self.setMinimumSize(760, 500)
        self.resize(1040, 700)

        self._build_ui()
        self._refresh_identity_display()
        self._reload_contacts()

        # Incoming messages arrive on a network thread; this signal hops them
        # onto the UI thread, which is the only place Qt widgets may be touched.
        self.message_arrived.connect(self._on_message_arrived)

        self._start_network()

    # -- UI ---------------------------------------------------------------- #
    def _build_menu_bar(self) -> None:
        """
        A VSCode-style top menu bar - real dropdown menus, using this
        app's own action names (Contact/Group/etc, not a literal
        File/Edit/View borrowed from a text editor). This is now the ONLY
        way to reach Share/Keys/Settings/Add/Remove/New Group/Join Group -
        the sidebar used to also have buttons for these, but once every
        action had a menu-bar home, keeping both was pure duplication, so
        the sidebar buttons were removed (see _build_sidebar) in favor of
        this being the one place they live.

        QMainWindow already owns exactly one QMenuBar (self.menuBar()
        creates it on first call) - no manual QMenuBar()/setMenuBar()
        needed. Native styling keeps each top-level entry to its
        platform's own compact padding rather than anything set here.
        """
        menu_bar = self.menuBar()

        contact_menu = menu_bar.addMenu(self.tr("Contact"))
        contact_menu.addAction(self.tr("Add…"), self._on_add_contact)
        contact_menu.addSeparator()
        contact_menu.addAction(self.tr("Remove"), self._on_remove_contact)

        group_menu = menu_bar.addMenu(self.tr("Group"))
        group_menu.addAction(self.tr("New Group…"), self._on_new_group)
        group_menu.addAction(self.tr("Join Group…"), self._on_join_group)

        share_menu = menu_bar.addMenu(self.tr("Share"))
        # Kept as self.share_action (not a local var) - _refresh_identity_display
        # disables it until this identity is actually published/reachable,
        # same rule the old sidebar Share button enforced.
        self.share_action = share_menu.addAction(self.tr("Share Contact…"), self._on_share_contact)

        keys_menu = menu_bar.addMenu(self.tr("Keys"))
        keys_menu.addAction(self.tr("View Keys…"), self._on_identity)

        settings_menu = menu_bar.addMenu(self.tr("Settings"))
        settings_menu.addAction(self.tr("Preferences…"), self._on_settings)
        settings_menu.addSeparator()
        settings_menu.addAction(self.tr("Check Connection"), self._on_check_now)

        help_menu = menu_bar.addMenu(self.tr("Help"))
        about_text = i18n.fmt(self.tr("About %(name)s…"), name=version.version_string())
        help_menu.addAction(about_text, self._on_about)

    def _build_ui(self) -> None:
        central = QWidget(self)
        self.setCentralWidget(central)

        self._build_menu_bar()

        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self._build_sidebar())
        splitter.addWidget(self._build_conversation_panel())
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([340, 760])
        root.addWidget(splitter, stretch=1)

        # --- Status bar: colored dot + text + manual check ---
        status_bar = QWidget()
        status_bar.setStyleSheet(
            f"background-color: {self.palette_colors.surface};"
            f"border-top: 1px solid {self.palette_colors.border};"
        )
        status_layout = QHBoxLayout(status_bar)
        status_layout.setContentsMargins(12, 6, 12, 6)
        status_layout.setSpacing(8)

        self.status_dot = QLabel("\u25cf")
        self.status_dot.setStyleSheet(
            f"color: {self.palette_colors.text_muted}; background: transparent;"
        )
        status_layout.addWidget(self.status_dot)

        # Text set via _set_connection_state (called right after _build_ui
        # returns, and again whenever the state actually changes) rather
        # than a hardcoded literal here, so there is exactly one place
        # that ever writes text into this label - and it always goes
        # through the same translation step.
        self.status_label = QLabel()
        self.status_label.setStyleSheet(
            f"color: {self.palette_colors.text_muted}; background: transparent;"
        )
        status_layout.addWidget(self.status_label, stretch=1)

        self.check_button = QPushButton(self.tr("Check connection"))
        self.check_button.setMinimumHeight(28)
        self.check_button.setCursor(Qt.PointingHandCursor)
        self.check_button.setToolTip(self.tr("Verify that you're reachable right now."))
        self.check_button.clicked.connect(self._on_check_now)
        self.check_button.setEnabled(False)
        status_layout.addWidget(self.check_button)

        self.version_label = QLabel(version.version_string())
        self.version_label.setToolTip(version.full_version())
        self.version_label.setCursor(Qt.PointingHandCursor)
        self.version_label.mousePressEvent = lambda _event: self._on_about()
        self.version_label.setStyleSheet(
            f"color: {self.palette_colors.text_muted}; background: transparent;"
        )
        status_layout.addWidget(self.version_label)

        root.addWidget(status_bar)

    def _build_sidebar(self) -> QWidget:
        panel = QWidget()
        self._sidebar_panel = panel
        # This is the EXPANDED width - wide enough for a contact row's
        # name/count/queued-state text (e.g. "Alice  (12)  [2 queued]")
        # and the monospace fingerprint line without wrapping awkwardly.
        # Collapsed width is _sidebar_collapsed_width below (see
        # _on_toggle_sidebar) - just enough for a 36px avatar icon plus
        # list-item padding, no text at all.
        self._sidebar_expanded_width = 290
        # Measured empirically, not hand-calculated: QListWidget's own
        # sizeHintForColumn(0) with only icon-only (no text) rows loaded -
        # which already accounts for Fusion style's real frame width,
        # item padding/margin, and the row's selection-ring border (see
        # theme.py's QListWidget[collapsed="true"]::item:selected) - plus
        # this panel's own 12+6 left/right margins. Two earlier smaller
        # guesses (56px, then 74px) both clipped the avatar's right edge
        # in a real screenshot before landing on this value.
        self._sidebar_collapsed_width = 120
        self._sidebar_collapsed = False
        panel.setMinimumWidth(self._sidebar_expanded_width)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(12, 12, 6, 12)
        layout.setSpacing(8)

        # Toggle sits above everything else and is the one element that
        # stays visible in both collapsed and expanded states - closing
        # the sidebar must never also hide the control that reopens it.
        toggle_row = QHBoxLayout()
        self.sidebar_toggle = QPushButton()
        self.sidebar_toggle.setIcon(_chevron_icon(self.palette_colors.text, pointing_left=True))
        self.sidebar_toggle.setFixedSize(28, 28)
        self.sidebar_toggle.setToolTip(self.tr("Collapse sidebar"))
        self.sidebar_toggle.setCursor(Qt.PointingHandCursor)
        self.sidebar_toggle.clicked.connect(self._on_toggle_sidebar)
        toggle_row.addWidget(self.sidebar_toggle)
        toggle_row.addStretch(1)
        layout.addLayout(toggle_row)

        # Everything below is only shown expanded - collapsed, the sidebar
        # is icons only (the toggle above, and contact_list's own icons -
        # see _on_toggle_sidebar/_reload_contacts). Grouped into one
        # container so showing/hiding the whole expanded view is a single
        # setVisible() call rather than toggling each widget separately.
        self._sidebar_expanded = QWidget()
        expanded_layout = QVBoxLayout(self._sidebar_expanded)
        expanded_layout.setContentsMargins(0, 0, 0, 0)
        expanded_layout.setSpacing(8)
        layout.addWidget(self._sidebar_expanded)

        title = QLabel(self.tr("You"))
        bold = QFont()
        bold.setBold(True)
        title.setFont(bold)
        expanded_layout.addWidget(title)

        # No raw onion address shown here - it is an internal transport
        # detail, not a normal user-facing identity field, and no mention
        # of Tor by name either - just a plain security/readiness state.
        # The fingerprint below is what a contact actually verifies you by.
        self.my_status_label = QLabel()
        expanded_layout.addWidget(self.my_status_label)

        # Share/Keys/Settings used to be buttons here - they now live only
        # in the top menu bar (see _build_menu_bar), so this sidebar is
        # purely status display plus the contact/group list, nothing
        # actionable duplicated in two places.
        self.fingerprint_label = QLabel("")
        self.fingerprint_label.setStyleSheet(
            f"color: {self.palette_colors.text_muted}; font-family: monospace;"
        )
        # Word-wrap rather than the default single-line clip - a
        # monospace fingerprint ("FP: XXXX XXXX XXXX XXXX XXXX") is
        # wider than the sidebar's minimum width can show on one line,
        # and silently truncating a value the user is meant to read
        # aloud to verify a contact is worse than wrapping it onto a
        # second line.
        self.fingerprint_label.setWordWrap(True)
        self.fingerprint_label.setToolTip(
            self.tr("Your fingerprint. Read it to a contact so they can verify you.")
        )
        expanded_layout.addWidget(self.fingerprint_label)

        contacts_title = QLabel(self.tr("Contacts"))
        contacts_title.setFont(bold)
        expanded_layout.addWidget(contacts_title)

        # contact_list itself is NOT inside _sidebar_expanded - it stays
        # visible in both states, since collapsed mode still shows every
        # contact/group, just as an icon-only column (see
        # _on_toggle_sidebar/_reload_contacts) rather than disappearing
        # entirely the way the buttons and labels above do.
        self.contact_list = QListWidget()
        self.contact_list.setIconSize(QSize(36, 36))
        self.contact_list.currentItemChanged.connect(self._on_contact_selected)
        self.contact_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.contact_list.customContextMenuRequested.connect(self._on_contact_menu)
        # Collapsed mode narrows this list to just past its icon's width
        # (see _sidebar_collapsed_width) - without this, Qt's default
        # (unstyled - theme.py only styles the vertical scrollbar)
        # horizontal scrollbar appeared at the bottom of the icon column,
        # which read as a stray, out-of-place UI artifact rather than a
        # real scrollbar for content that never actually needs horizontal
        # scrolling in the first place (row text always wraps/elides, never
        # scrolls sideways).
        self.contact_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.contact_list.setProperty("collapsed", False)
        layout.addWidget(self.contact_list, stretch=1)

        return panel

    def _build_conversation_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(6, 12, 12, 12)
        layout.setSpacing(8)

        header_row = QHBoxLayout()
        header_row.setSpacing(10)

        self.conversation_avatar = QLabel()
        self.conversation_avatar.setFixedSize(34, 34)
        self.conversation_avatar.setVisible(False)
        header_row.addWidget(self.conversation_avatar)

        self.conversation_header = QLabel(self.tr("Select or add a contact"))
        header_font = QFont()
        header_font.setBold(True)
        header_font.setPointSize(11)
        self.conversation_header.setFont(header_font)
        header_row.addWidget(self.conversation_header, stretch=1)

        layout.addLayout(header_row)

        self.thread_view = QTextBrowser()
        self.thread_view.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        # Links inside the thread are never real navigation (there is no
        # browser here) - just the "Save As..." attachment affordance (see
        # _attachment_html/_on_thread_link_clicked) - so autonomous opening
        # is turned off in favor of handling every click ourselves.
        self.thread_view.setOpenLinks(False)
        self.thread_view.anchorClicked.connect(self._on_thread_link_clicked)
        self.thread_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.thread_view.customContextMenuRequested.connect(self._on_thread_context_menu)
        layout.addWidget(self.thread_view, stretch=3)
        # message id -> Message, refreshed every _render_conversation() call,
        # so _on_thread_link_clicked can resolve an "attach:<id>" href back
        # to the real Message (and its full attachment bytes) without
        # having to re-search every contact/group on each click.
        self._rendered_messages: dict[str, vault_mod.Message] = {}

        # Shown only for pending requests.
        self.request_bar = QWidget()
        request_layout = QHBoxLayout(self.request_bar)
        request_layout.setContentsMargins(0, 0, 0, 0)

        self.accept_button = QPushButton(self.tr("Accept contact"))
        self.accept_button.setObjectName("primary")
        self.accept_button.setCursor(Qt.PointingHandCursor)
        self.accept_button.clicked.connect(self._on_accept_request)
        request_layout.addWidget(self.accept_button)

        self.block_button = QPushButton(self.tr("Block"))
        self.block_button.setObjectName("danger")
        self.block_button.setCursor(Qt.PointingHandCursor)
        self.block_button.clicked.connect(self._on_block_request)
        request_layout.addWidget(self.block_button)
        request_layout.addStretch(1)

        self.request_bar.setVisible(False)
        layout.addWidget(self.request_bar)

        self.message_input = QTextEdit()
        self.message_input.setPlaceholderText(self.tr("Write a message..."))
        self.message_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout.addWidget(self.message_input, stretch=1)

        composer_row = QHBoxLayout()

        # Icon-only, like the round send button - the tooltip carries the
        # actual description rather than a wide "Attach..." label. Not
        # wrapped in self.tr(): same reason as the lock emoji in
        # A real PNG (icons/ui/attach.png), not the U+1F4CE paperclip
        # emoji this used to be - the emoji depends on which font/emoji
        # set happens to be installed to render as an actual paperclip at
        # all (the same font-fallback unreliability already found and
        # fixed for the copy-icon and sidebar-collapse chevron elsewhere
        # in this file - see _copy_icon's docstring), and separately,
        # pyside6-lupdate corrupts non-BMP (astral-plane) characters like
        # it when extracting from Python source (U+1F4CE gets truncated
        # to U+F4CE, a private-use codepoint, in the generated .ts) -
        # neither problem exists for a real image asset.
        self.attach_button = QPushButton()
        attach_icon = ui_icon("attach.png", None, 20)
        if attach_icon is not None:
            self.attach_button.setIcon(attach_icon)
            self.attach_button.setIconSize(QSize(20, 20))
        self.attach_button.setObjectName("attachButton")
        self.attach_button.setCursor(Qt.PointingHandCursor)
        self.attach_button.setToolTip(
            i18n.fmt(
                self.tr("Send a file or image (up to %(mb)s MB)"),
                mb=envelope.MAX_FILE_BYTES // (1024 * 1024),
            )
        )
        self.attach_button.clicked.connect(self._on_send_file)
        composer_row.addWidget(self.attach_button)

        # A round, icon-only send button on the trailing edge - the
        # familiar "paper plane in a circle" shape most chat apps use -
        # rather than a wide rectangular button with a text label. Falls
        # back to a labeled rectangular button (objectName "primary", the
        # same styling every other call-to-action button in the app uses)
        # if the icon asset cannot be found for any reason, so the control
        # stays usable/discoverable either way.
        self.send_button = QPushButton()
        self.send_button.setCursor(Qt.PointingHandCursor)
        send_icon_path = brand_image_path("veilwire-send.png")
        if send_icon_path:
            send_icon = QPixmap(send_icon_path)
            if QApplication.layoutDirection() == Qt.RightToLeft:
                # The send icon is a directional paper-plane graphic - under
                # RTL it must point toward the trailing edge (left, in RTL)
                # like every other "forward action" affordance, so it's
                # flipped at runtime rather than shipping a second asset
                # file (keeps the "brand assets are never duplicated/
                # modified" discipline from the branding work intact).
                send_icon = send_icon.transformed(QTransform().scale(-1, 1))
            self.send_button.setObjectName("sendButton")
            self.send_button.setIcon(QIcon(send_icon))
            self.send_button.setIconSize(QSize(20, 20))
            self.send_button.setToolTip(self.tr("Send"))
            self._send_button_has_icon = True
        else:
            self.send_button.setObjectName("primary")
            self.send_button.setText(self.tr(" Send"))
            self._send_button_has_icon = False
        self.send_button.clicked.connect(self._on_send)
        composer_row.addStretch(1)
        composer_row.addWidget(self.send_button)

        layout.addLayout(composer_row)

        self._set_composer_enabled(False)
        return panel

    # -- Network startup ---------------------------------------------------- #
    def _start_network(self) -> None:
        identity = self.vault.identity
        assert identity is not None

        self.server = MessageServer(
            on_message=self._on_incoming,
            resolve_key=self.vault.may_receive_from,
            my_private=self.vault.private_key_raw(),
            on_event=_on_transport_event,
        )
        local_port = self.server.bind()
        self.server.start()

        self._set_connection_state(STATE_STARTING)

        self._tor_worker = TorStartWorker(self.tor, local_port, identity.onion_key)
        # TorStartWorker.progress carries real bootstrap detail (percentage,
        # relay/circuit phase) for diagnostics - deliberately not connected
        # to anything UI-facing any more. The persistent indicator only
        # ever shows STATE_CONNECTING while this is in flight.
        self._tor_worker.progress.connect(lambda _text: self._set_connection_state(STATE_CONNECTING))
        self._tor_worker.finished_ok.connect(self._on_tor_ready)
        self._tor_worker.failed.connect(self._on_tor_failed)
        self._tor_worker.start()

    def _on_tor_ready(self, onion: str, onion_key: str) -> None:
        self.vault.set_onion(onion, onion_key)
        self._refresh_identity_display()
        self._set_connection_state(STATE_READY)
        self.check_button.setEnabled(True)

        if self._active_contact_id:
            self._set_composer_enabled(True)

        # Keep verifying reachability for as long as the app is open.
        self.monitor = HealthMonitor(self.tor, self.server, parent=self)
        self.monitor.status.connect(self._on_health_status)
        self.monitor.republished.connect(self._on_republished)
        self.monitor.start()

        # Retries anything queued while contacts were offline.
        self.delivery = DeliveryWorker(self.vault, self.tor, parent=self)
        self.delivery.presence_changed.connect(self._on_presence_changed)
        self.delivery.message_sent.connect(self._on_queued_sent)
        self.delivery.activity.connect(self._on_health_status)
        self.delivery.resume_transfer.connect(self._on_resume_transfer)
        self.delivery.start()
        self.delivery.wake()   # deliver anything left over from last session

    def _on_tor_failed(self, error: str) -> None:
        # `error` (a sanitized TorError message - see tor_service.py) is
        # logged for diagnostics only; the user sees plain, jargon-free
        # text that still accurately describes real behavior (messages are
        # queued and retried automatically, nothing here overclaims).
        _logger.info("Secure connection could not start: %s", error)
        self._set_connection_state(STATE_OFFLINE)
        QMessageBox.critical(
            self,
            self.tr("Unable to connect"),
            self.tr(
                "Unable to establish a secure connection.\n\n"
                "You can still read past messages. Sending and receiving will "
                "resume automatically once the connection is ready."
            ),
        )

    # -- Sidebar collapse ---------------------------------------------------- #
    def _on_toggle_sidebar(self) -> None:
        """
        Collapses the sidebar to a narrow icon-only strip pinned to the
        left, or expands it back to the normal view - everything it
        already showed (status, fingerprint) reappears exactly as it
        was, nothing is moved or removed permanently. The toggle button
        itself (self.sidebar_toggle) is the one thing that stays visible
        in both states, so collapsing never hides the only way back.
        """
        self._sidebar_collapsed = not self._sidebar_collapsed
        collapsed = self._sidebar_collapsed

        self._sidebar_expanded.setVisible(not collapsed)

        # Right-pointing chevron = "expand me"; left-pointing = "collapse
        # me" - the arrow always shows the direction the *action* moves
        # the sidebar's edge, matching the convention in VSCode and most
        # other docked-panel UIs, not the direction the panel currently
        # points.
        self.sidebar_toggle.setIcon(
            _chevron_icon(self.palette_colors.text, pointing_left=not collapsed)
        )
        self.sidebar_toggle.setToolTip(
            self.tr("Expand sidebar") if collapsed else self.tr("Collapse sidebar")
        )

        width = self._sidebar_collapsed_width if collapsed else self._sidebar_expanded_width
        self._sidebar_panel.setMinimumWidth(width)
        self._sidebar_panel.setMaximumWidth(width if collapsed else 16777215)

        splitter = self._sidebar_panel.parentWidget()
        if isinstance(splitter, QSplitter):
            total = sum(splitter.sizes()) or (width + 760)
            splitter.setSizes([width, max(total - width, 200)])

        # Icon-only rows have no text for the normal filled-rectangle
        # selection highlight (theme.py's QListWidget::item:selected) to
        # sit next to - on a round avatar with nothing beside it, that
        # same highlight instead reads as a jarring purple square stamped
        # behind a circle. The "collapsed" dynamic property switches to a
        # slimmer ring-style highlight instead (see theme.py's
        # QListWidget[collapsed="true"]::item:selected rule) -
        # setProperty() alone does not repaint anything on its own; the
        # unpolish/polish pair forces Qt to actually re-evaluate which
        # stylesheet rules apply to this widget right now.
        self.contact_list.setProperty("collapsed", collapsed)
        self.contact_list.style().unpolish(self.contact_list)
        self.contact_list.style().polish(self.contact_list)

        # Collapsed rows show only the avatar icon (no name/count text) -
        # re-run the same render path used for a normal reload rather than
        # hand-editing each QListWidgetItem's text, so there is exactly
        # one place that ever decides what a row's label says.
        self._reload_contacts(select_id=self._active_contact_id or self._active_group_id)

    # -- Contacts ----------------------------------------------------------- #
    def _reload_contacts(self, select_id: str | None = None) -> None:
        self.contact_list.blockSignals(True)
        self.contact_list.clear()

        # One combined, recency-sorted list of contacts and groups, like an
        # ordinary messenger's conversation list - built as (sort_key, kind,
        # id, label, tooltip, avatar_name, verified) tuples first so the
        # two kinds can be merged and sorted together rather than shown as
        # two separate blocks.
        rows: list[tuple[str, str, str, str, str, str, bool]] = []

        for contact in self.vault.sorted_contacts():
            if contact.status == vault_mod.STATUS_BLOCKED:
                continue  # blocked contacts stay hidden

            # Both counts below are scoped to this contact's own direct (non-
            # group) messages only - contact.messages also holds this
            # contact's copies of GROUP messages (see vault.group_messages()'s
            # docstring), and folding those into the 1:1 row's "(N)"/"queued"
            # counts would misreport group activity as DM activity, the same
            # class of DM/group mixing bug fixed in _render_conversation.
            direct_messages = [m for m in contact.messages if not m.group_id]
            count = len(direct_messages)
            tooltip = ""
            if contact.status == vault_mod.STATUS_PENDING:
                label = self.tr("[request] %(name)s") % {"name": contact.name}
                tooltip = self.tr("Wants to message you. Select to accept or block.")
            else:
                # Presence: filled dot online, hollow offline, nothing if unknown.
                # The verified checkmark itself is no longer text here - it
                # is composited onto the avatar icon's corner instead (see
                # _avatar_icon's `verified` argument below), since a real
                # icon reads more clearly than a Unicode checkmark whose
                # actual on-screen appearance depends on which fonts
                # happen to be installed (verified empirically to be
                # unreliable - see _copy_icon's docstring for the same
                # finding elsewhere in this file).
                online = self.delivery.is_online(contact.id) if self.delivery else None
                presence = "" if online is None else ("\u25cf " if online else "\u25cb ")
                queued = sum(
                    1 for m in direct_messages
                    if m.direction == "out" and m.status == vault_mod.QUEUED
                )
                suffix = self.tr("  (%(count)s)") % {"count": count} if count else ""
                if queued:
                    suffix += self.tr("  [%(queued)s queued]") % {"queued": queued}
                label = f"{presence}{contact.name}{suffix}"

            rows.append((
                contact.last_activity, _KIND_CONTACT, contact.id, label, tooltip,
                contact.name, contact.verified,
            ))

        for group in self.vault.groups:
            messages = self.vault.group_messages(group)
            queued = sum(
                1 for m in messages
                if m.direction == "out" and m.status == vault_mod.QUEUED and not m.sender_contact_id
            )
            member_count = len(group.member_contact_ids)
            # Kept short - "N members" plus a separate message count made
            # this row overflow the sidebar's width for anything but a
            # tiny group; the message count is still one tap away (open
            # the conversation) so dropping it from the row loses nothing
            # essential, while "queued" is worth keeping since it is the
            # one state that needs the user's attention from the sidebar.
            suffix = self.tr("  [%(queued)s queued]") % {"queued": queued} if queued else ""
            label = self.tr("\u25c8 %(name)s \u00b7 %(members)s members%(suffix)s") % {
                "name": group.name, "members": member_count, "suffix": suffix,
            }
            rows.append((
                self.vault.group_last_activity(group), _KIND_GROUP, group.id, label,
                self.tr("Group of %(members)s") % {"members": member_count}, group.name, False,
            ))

        rows.sort(key=lambda r: r[0], reverse=True)

        collapsed = getattr(self, "_sidebar_collapsed", False)
        for _sort_key, kind, item_id, label, tooltip, avatar_name, verified in rows:
            # Collapsed: icon only, no text - the row's name/count/queued
            # label moves entirely into the tooltip so it's still
            # discoverable on hover, matching how a collapsed VSCode
            # activity-bar icon still shows its name as a tooltip rather
            # than losing it outright.
            item = QListWidgetItem(
                _avatar_icon(avatar_name, kind=kind, verified=verified),
                "" if collapsed else label,
            )
            item.setData(Qt.UserRole, item_id)
            item.setData(_ITEM_KIND_ROLE, kind)
            item.setToolTip(tooltip or (label if collapsed else ""))
            self.contact_list.addItem(item)

        self.contact_list.blockSignals(False)

        target = select_id or self._active_contact_id or self._active_group_id
        if target and self._select_contact(target):
            return
        if self.contact_list.count():
            self.contact_list.setCurrentRow(0)
        else:
            self._active_contact_id = None
            self._active_group_id = None
            self._render_conversation(None)

    def _select_contact(self, contact_id: str) -> bool:
        for row in range(self.contact_list.count()):
            if self.contact_list.item(row).data(Qt.UserRole) == contact_id:
                self.contact_list.setCurrentRow(row)
                return True
        return False

    def _on_contact_selected(self, current: QListWidgetItem | None, _previous) -> None:
        if current is None:
            self._active_contact_id = None
            self._active_group_id = None
            self._render_conversation(None)
            return
        item_id = current.data(Qt.UserRole)
        kind = current.data(_ITEM_KIND_ROLE)
        if kind == _KIND_GROUP:
            self._active_contact_id = None
            self._active_group_id = item_id
            self._render_conversation(None, group=self.vault.get_group(item_id))
        else:
            self._active_contact_id = item_id
            self._active_group_id = None
            self._render_conversation(self.vault.get_contact(self._active_contact_id))

    def _on_add_contact(self) -> None:
        text, ok = QInputDialog.getText(
            self,
            self.tr("Add Contact"),
            self.tr("Paste their contact bundle (P2PMSG1:...) or address:"),
        )
        if not ok or not text.strip():
            return
        text = text.strip()

        name, ok = QInputDialog.getText(
            self, self.tr("Add Contact"), self.tr("Name for this contact:")
        )
        if not ok:
            return

        # Both formats are accepted from the same paste box: the new signed
        # bundle (does not print an onion at a glance) and the legacy plain
        # "onionmsg:onion:pubkey" address, so anyone who was given an old
        # style address can still add it.
        try:
            if text.startswith(bundle_mod.PREFIX):
                contact = self.vault.add_contact_from_bundle(name, text)
            else:
                contact = self.vault.add_contact(name, text)
        except (ValueError, bundle_mod.BundleError) as exc:
            # str(exc) here is one of our own hand-written validation
            # messages (bad bundle signature, malformed address, etc.) -
            # not a raw system/filesystem exception, so unlike
            # safe_error_text() sites elsewhere it's fine to show directly.
            # It is not translated: it originates as a plain Python
            # exception message, not a Qt-translatable literal.
            QMessageBox.warning(self, self.tr("Could not add contact"), str(exc))
            return

        self._reload_contacts(select_id=contact.id)

    def _on_remove_contact(self) -> None:
        item = self.contact_list.currentItem()
        if item is None:
            return

        if item.data(_ITEM_KIND_ROLE) == _KIND_GROUP:
            self._on_delete_group(item.data(Qt.UserRole))
            return

        contact = self.vault.get_contact(item.data(Qt.UserRole))
        if contact is None:
            return

        confirm = QMessageBox.question(
            self,
            self.tr("Remove Contact"),
            i18n.fmt(
                self.tr(
                    "Remove %(name)s and all %(count)s saved message(s)?\n\n"
                    "They will no longer be able to send you messages."
                ),
                name=escape_html(contact.name),
                count=len(contact.messages),
            ),
            QMessageBox.Yes | QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        self.vault.delete_contact(contact.id)
        self._active_contact_id = None
        self._reload_contacts()

    def _on_delete_group(self, group_id: str) -> None:
        group = self.vault.get_group(group_id)
        if group is None:
            return
        confirm = QMessageBox.question(
            self,
            self.tr("Delete Group"),
            i18n.fmt(
                self.tr(
                    "Delete the group “%(name)s”?\n\n"
                    "This only removes it from your own device - other members keep "
                    "their own copy of the group and its messages."
                ),
                name=escape_html(group.name),
            ),
            QMessageBox.Yes | QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        try:
            self.vault.delete_group(group_id)
        except ValueError as exc:
            # Only reachable if the menu construction below somehow let a
            # non-owner reach this action - vault.py's own check is the
            # real boundary (defense-in-depth), this is just surfacing it.
            QMessageBox.warning(self, self.tr("Could not delete group"), str(exc))
            return
        if self._active_group_id == group_id:
            self._active_group_id = None
        self._reload_contacts()

    def _on_leave_group(self, group_id: str) -> None:
        group = self.vault.get_group(group_id)
        if group is None:
            return
        confirm = QMessageBox.question(
            self,
            self.tr("Leave Group"),
            i18n.fmt(
                self.tr(
                    "Leave the group “%(name)s”? The other members will be notified "
                    "that you left."
                ),
                name=escape_html(group.name),
            ),
            QMessageBox.Yes | QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        self._send_group_control(group, envelope.encode_group_leave(group.id))
        try:
            self.vault.leave_group(group_id)
        except ValueError as exc:
            QMessageBox.warning(self, self.tr("Could not leave group"), str(exc))
            return
        if self._active_group_id == group_id:
            self._active_group_id = None
        self._reload_contacts()

    def _send_group_control(self, group: vault_mod.Group, wire_body: str) -> None:
        """
        Fire-and-forget a control envelope (group_ack/group_leave) to
        every CURRENT member this vault has for `group`, best-effort - a
        member who is offline simply does not get it; unlike an ordinary
        message this is not queued for retry (see envelope.py's
        KIND_GROUP_ACK/KIND_GROUP_LEAVE docstrings: these are advisory
        notices, not content, so a missed one is not something the
        recipient is left waiting to receive - a leave, for instance, is
        also implied the next time that member simply stops seeing new
        group messages from this identity).
        """
        identity = self.vault.identity
        if identity is None or self.tor.service is None:
            return
        for member_id in group.member_contact_ids:
            member = self.vault.get_contact(member_id)
            if member is None or member.status != vault_mod.STATUS_ACCEPTED:
                continue
            try:
                transport.send_message(
                    onion=member.onion,
                    their_public_b64=member.public_key,
                    body=wire_body,
                    my_private=self.vault.private_key_raw(),
                    my_public_b64=identity.public_key,
                    my_onion=identity.onion,
                    socks_port=self.tor.socks_port,
                )
            except transport.TransportError:
                pass  # best-effort, see docstring above

    def _on_create_group_invite(self, group: vault_mod.Group) -> None:
        choices = [
            (self.tr("1 hour"), 1),
            (self.tr("24 hours"), 24),
            (self.tr("7 days"), 24 * 7),
        ]
        labels = [label for label, _ in choices]
        chosen_label, ok = QInputDialog.getItem(
            self, self.tr("Create Invite"), self.tr("This invite expires after:"),
            labels, 0, False,
        )
        if not ok:
            return
        expiry_hours = dict(choices)[chosen_label]

        try:
            invite_text = self.vault.create_group_invite(group.id, expiry_hours)
        except (ValueError, vault_mod.VaultLocked) as exc:
            QMessageBox.warning(self, self.tr("Could not create invite"), str(exc))
            return

        expires_label = i18n.fmt(
            self.tr("Expires in %(hours)s hour(s)"), hours=expiry_hours,
        )
        ShareDialog(
            invite_text, "", self,
            title=self.tr("Group Invite"),
            secondary_label=expires_label,
            note_text=self.tr(
                "This invite is signed and works only once, for this one group. "
                "Send it only to the person you want to add - anyone who redeems "
                "it before they do will use it up."
            ),
            copy_button_text=self.tr("Copy invite"),
            copied_message=self.tr("Group invite copied."),
        ).exec()

    def _on_join_group(self) -> None:
        text, ok = QInputDialog.getText(
            self, self.tr("Join Group"),
            self.tr("Paste the group invite (P2PGRP1:...) someone sent you:"),
        )
        if not ok or not text.strip():
            return

        try:
            group = self.vault.join_group_from_invite(text.strip())
        except (invite_mod.GroupInviteError, ValueError) as exc:
            QMessageBox.warning(self, self.tr("Could not join group"), str(exc))
            return

        self._reload_contacts(select_id=group.id)

    def _on_new_group(self) -> None:
        accepted = self.vault.accepted_contacts()
        if not accepted:
            QMessageBox.information(
                self, self.tr("No contacts yet"),
                self.tr("Add at least one contact before creating a group - group members "
                        "have to already be contacts you have added and verified."),
            )
            return

        dialog = NewGroupDialog(accepted, self)
        if dialog.exec() != QDialog.Accepted:
            return

        try:
            group = self.vault.create_group(dialog.group_name, dialog.selected_contact_ids)
        except ValueError as exc:
            QMessageBox.warning(self, self.tr("Could not create group"), str(exc))
            return

        self._reload_contacts(select_id=group.id)

    def _on_group_menu(self, group_id: str, position) -> None:
        group = self.vault.get_group(group_id)
        if group is None:
            return
        is_owner = group.owner_contact_id == ""

        menu = QMenu(self)
        rename = menu.addAction(self.tr("Rename group"))
        # Membership is now invite-gated and owner-authoritative (see
        # vault.join_group_from_invite/redeem_group_invite_locally) - a
        # non-owner's local add/remove would only diverge from what the
        # real owner's vault thinks membership is, so both member
        # management and invite creation are owner-only. A non-owner can
        # still Rename their own local copy (cosmetic, local-only, same
        # as it always was) and Leave.
        manage = menu.addAction(self.tr("Add/remove members")) if is_owner else None
        create_invite = menu.addAction(self.tr("Create invite...")) if is_owner else None
        delete = menu.addAction(self.tr("Delete group")) if is_owner else None
        leave = menu.addAction(self.tr("Leave group")) if not is_owner else None
        chosen = menu.exec(self.contact_list.mapToGlobal(position))

        if chosen == rename:
            name, ok = QInputDialog.getText(
                self, self.tr("Rename group"), self.tr("New name:"), text=group.name
            )
            if ok and name.strip():
                self.vault.rename_group(group.id, name)
                self._reload_contacts(select_id=group.id)
        elif manage is not None and chosen == manage:
            self._on_manage_group_members(group)
        elif create_invite is not None and chosen == create_invite:
            self._on_create_group_invite(group)
        elif delete is not None and chosen == delete:
            self._on_delete_group(group.id)
        elif leave is not None and chosen == leave:
            self._on_leave_group(group.id)

    def _on_manage_group_members(self, group: vault_mod.Group) -> None:
        accepted = self.vault.accepted_contacts()
        dialog = NewGroupDialog(accepted, self)
        dialog.setWindowTitle(self.tr("Add/Remove Members"))
        dialog.name_input.setText(group.name)
        for row in range(dialog.member_list.count()):
            item = dialog.member_list.item(row)
            if item.data(Qt.UserRole) in group.member_contact_ids:
                item.setCheckState(Qt.Checked)

        if dialog.exec() != QDialog.Accepted:
            return

        self.vault.rename_group(group.id, dialog.group_name)
        new_members = set(dialog.selected_contact_ids)
        current_members = set(group.member_contact_ids)
        for contact_id in new_members - current_members:
            try:
                self.vault.add_group_member(group.id, contact_id)
            except ValueError as exc:
                QMessageBox.warning(self, self.tr("Could not add member"), str(exc))
        for contact_id in current_members - new_members:
            self.vault.remove_group_member(group.id, contact_id)

        self._reload_contacts(select_id=group.id)

    def _on_accept_request(self) -> None:
        if self._active_contact_id is None:
            return
        contact = self.vault.get_contact(self._active_contact_id)
        if contact is None:
            return

        name, ok = QInputDialog.getText(
            self, self.tr("Accept contact"), self.tr("Name for this contact:"), text=contact.name
        )
        if not ok:
            return
        self.vault.accept_contact(contact.id, name)
        self._reload_contacts(select_id=contact.id)
        # The contact moving out of the pending/request view and into the
        # normal list is confirmation enough on its own - no extra status
        # announcement needed, the same way a normal messenger doesn't pop
        # up a banner after you tap "Accept".

    def _on_block_request(self) -> None:
        if self._active_contact_id is None:
            return
        contact = self.vault.get_contact(self._active_contact_id)
        if contact is None:
            return

        confirm = QMessageBox.question(
            self,
            self.tr("Block"),
            i18n.fmt(
                self.tr("Block %(name)s? They will not reach you again."),
                name=escape_html(contact.name),
            ),
            QMessageBox.Yes | QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        self.vault.block_contact(contact.id)
        self._active_contact_id = None
        self._reload_contacts()

    def _on_presence_changed(self, contact_id: str, online: bool) -> None:
        self._reload_contacts(select_id=self._active_contact_id)
        if self._active_contact_id == contact_id:
            self._render_conversation(self.vault.get_contact(contact_id))

    def _on_queued_sent(self, contact_id: str, _message_id: str) -> None:
        self._reload_contacts(select_id=self._active_contact_id)
        if self._active_contact_id == contact_id:
            self._render_conversation(self.vault.get_contact(contact_id))

    def _on_about(self) -> None:
        AboutDialog(self.palette_colors, self).exec()

    def _on_identity(self) -> None:
        dialog = IdentityDialog(self.vault, self)
        dialog.exec()
        self._refresh_identity_display()

    def _on_settings(self) -> None:
        dialog = SettingsDialog(self.vault, self)
        dialog.exec()
        if dialog.restart_requested:
            self._restart_app()

    def _refresh_identity_display(self) -> None:
        identity = self.vault.identity
        if identity is None:
            return
        published = bool(identity.onion)
        # The lock emoji is kept out of the translatable string itself and
        # concatenated at runtime: pyside6-lupdate corrupts non-BMP
        # (astral-plane) characters like this one when extracting from
        # Python source (U+1F512 gets truncated to U+F512, a private-use
        # codepoint, in the generated .ts), and the glyph itself needs no
        # per-language translation anyway.
        text = self.tr("Secure - ready") if published else self.tr("Secure - starting")
        status = f"\U0001f512 {text}"
        self.my_status_label.setText(status)
        self.share_action.setEnabled(published)
        self.fingerprint_label.setText(
            i18n.fmt(self.tr("FP: %(fp)s"), fp=identity.fingerprint)
        )

    def _on_contact_menu(self, position) -> None:
        item = self.contact_list.itemAt(position)
        if item is None:
            return

        if item.data(_ITEM_KIND_ROLE) == _KIND_GROUP:
            self._on_group_menu(item.data(Qt.UserRole), position)
            return

        contact = self.vault.get_contact(item.data(Qt.UserRole))
        if contact is None:
            return

        menu = QMenu(self)
        rename = menu.addAction(self.tr("Rename"))
        show = menu.addAction(self.tr("Show fingerprint"))
        verify = menu.addAction(
            self.tr("Mark as unverified") if contact.verified else self.tr("Mark as verified")
        )
        block = menu.addAction(self.tr("Block"))
        remove = menu.addAction(self.tr("Remove"))
        chosen = menu.exec(self.contact_list.mapToGlobal(position))

        if chosen == rename:
            name, ok = QInputDialog.getText(
                self, self.tr("Rename"), self.tr("New name:"), text=contact.name
            )
            if ok:
                self.vault.rename_contact(contact.id, name)
                self._reload_contacts(select_id=contact.id)
        elif chosen == show:
            # No onion address shown here - the fingerprint is what a
            # contact is actually verified by.
            QMessageBox.information(
                self,
                contact.name,  # window title - not markup-interpreted, no escaping needed
                i18n.fmt(
                    self.tr(
                        "Fingerprint:\n%(fp)s\n\n"
                        "Compare this fingerprint with them over a channel you trust."
                    ),
                    fp=escape_html(contact.fingerprint),
                ),
            )
        elif chosen == verify:
            self.vault.set_verified(contact.id, not contact.verified)
            self._reload_contacts(select_id=contact.id)
        elif chosen == block:
            self.contact_list.setCurrentItem(item)
            self._on_block_request()
        elif chosen == remove:
            self.contact_list.setCurrentItem(item)
            self._on_remove_contact()

    # -- Conversation ------------------------------------------------------- #
    def _transfer_progress_note(self, msg: vault_mod.Message) -> str | None:
        """
        For a message that is one half of an in-progress chunked file
        transfer (see vault.FileTransfer/ChunkedSendWorker), returns the
        "Uploading... 42%"/"Receiving... 42%" note to show in place of
        the normal delivered/queued note - None for every other message
        (render_bubble's note_override=None means "use the normal
        delivered/queued logic", so this only overrides display for the
        specific messages actually mid-transfer).

        Looked up by client_msg_id, not stored as its own Message field -
        FileTransfer.client_msg_id is exactly this Message's own
        client_msg_id for the message that started the transfer (see
        _start_contact_chunked_send/the receive-side KIND_FILE_START
        handling), so this join is a plain linear scan over
        self.vault.file_transfers, which is small (only ever the
        currently-in-flight transfers, not history).
        """
        client_msg_id = getattr(msg, "client_msg_id", "")
        if not client_msg_id:
            return None
        for transfer in self.vault.file_transfers:
            if transfer.client_msg_id != client_msg_id or transfer.completed:
                continue
            percent = int(100 * transfer.chunks_done_count / transfer.chunk_count) if transfer.chunk_count else 0
            p = self.palette_colors
            if transfer.direction == "out":
                text = i18n.fmt(self.tr("Uploading… %(percent)s%%"), percent=percent)
            else:
                text = i18n.fmt(self.tr("Receiving… %(percent)s%%"), percent=percent)
            return f"<div style='color:{p.text_muted};font-size:11px;'>{text}</div>"
        return None

    def _render_conversation(
        self, contact: vault_mod.Contact | None, group: vault_mod.Group | None = None,
    ) -> None:
        self._rendered_messages = {}

        if group is not None:
            self._render_group_conversation(group)
            return

        if contact is None:
            self.conversation_avatar.setVisible(False)
            self.conversation_header.setText(self.tr("Select or add a contact"))
            empty_image = f"<div style='text-align:center;'>{_brand_image_html('veilwire-chat.png', 160)}</div>"
            self.thread_view.setHtml(
                empty_image +
                f"<p style='color:{self.palette_colors.text_muted};text-align:center;'>"
                + self.tr("No contact selected. Use <b>Add</b> and paste the contact someone shared with you.")
                + "</p>"
            )
            self._set_composer_enabled(False)
            self.request_bar.setVisible(False)
            return

        # A pending request: show who it is and let the user decide. The
        # onion address is never shown here - only the fingerprint, which
        # is the thing meant to be compared out of band. This applies to
        # every pending request, not only the endpoint-changed case: the
        # onion is an internal transport detail, not a normal user-facing
        # identity field, anywhere in the UI.
        if contact.status == vault_mod.STATUS_PENDING:
            self.conversation_avatar.setVisible(False)
            if _is_endpoint_change_warning(contact.name):
                self.conversation_header.setText(self.tr("\u26a0 Identity / Endpoint Changed"))
                self.thread_view.setHtml(
                    "<p><b>" + self.tr("\u26a0 Identity / Endpoint Changed") + "</b></p>"
                    "<p>" + self.tr("This contact's connection information has changed.") + "</p>"
                    f"<p style='color:{self.palette_colors.text_muted};'>"
                    + self.tr("Fingerprint:") + "<br>"
                    f"<code style='font-size:15px;color:{self.palette_colors.text};'>"
                    f"{escape_html(contact.fingerprint)}</code></p>"
                    "<p>" + self.tr(
                        "The app will not automatically trust the new connection "
                        "information. Confirm the fingerprint with them over a channel "
                        "you already trust before continuing - if it does not match "
                        "what you verified before, reject this."
                    ) + "</p>"
                )
                self.accept_button.setText(self.tr("Review"))
                self.block_button.setText(self.tr("Reject"))
            else:
                self.conversation_header.setText(
                    i18n.fmt(self.tr("Request from %(name)s"), name=escape_html(contact.name))
                )
                self.thread_view.setHtml(
                    "<p><b>" + self.tr("Someone you have not added is trying to message you.") + "</b></p>"
                    f"<p style='color:{self.palette_colors.text_muted};'>"
                    + self.tr("Fingerprint:") + "<br>"
                    f"<code style='font-size:15px;color:{self.palette_colors.text};'>"
                    f"{escape_html(contact.fingerprint)}</code></p>"
                    f"<p style='color:{self.palette_colors.text_muted};'>"
                    + self.tr(
                        "Confirm this fingerprint with them over a channel you already "
                        "trust before accepting. Anyone can claim to be anyone until you check."
                    ) + "</p>"
                )
                self.accept_button.setText(self.tr("Accept contact"))
                self.block_button.setText(self.tr("Block"))
            self._set_composer_enabled(False)
            self.request_bar.setVisible(True)
            return

        self.request_bar.setVisible(False)

        verified_mark = f" {_verified_badge_html()}" if contact.verified else ""
        online = self.delivery.is_online(contact.id) if self.delivery else None
        if online is True:
            presence_text = self.tr(" \u2014 online")
        elif online is False:
            presence_text = self.tr(" \u2014 offline")
        else:
            presence_text = ""
        self.conversation_header.setText(
            f"{escape_html(contact.name)}{verified_mark}{presence_text}"
        )
        self.conversation_avatar.setPixmap(_avatar_pixmap(contact.name, 34, kind=_KIND_CONTACT))
        self.conversation_avatar.setVisible(True)
        self._set_composer_enabled(self.tor.service is not None)

        if not contact.messages:
            self.thread_view.setHtml(
                f"<p style='color:{self.palette_colors.text_muted};'>"
                + self.tr(
                    "No messages yet. Both of you need the app running at the same "
                    "time for a message to go through."
                )
                + "</p>"
                f"<p style='color:{self.palette_colors.text_muted};'>"
                + self.tr("Their fingerprint:") + " "
                f"<code style='color:{self.palette_colors.text};'>"
                f"{escape_html(contact.fingerprint)}</code></p>"
            )
            return

        p = self.palette_colors
        # is_delete_request rows are the queued "delete for everyone"
        # notification itself (see vault.Vault.queue_delete_request()), not
        # a displayed message - never rendered as a bubble. group_id rows
        # are a copy of a GROUP message stored on this same contact's
        # message list (see vault.Vault.group_messages()'s docstring - a
        # group message is stored once per member, on that member's own
        # Contact.messages, tagged with group_id) - without this filter a
        # message sent/received inside a group conversation with this
        # contact would also render in their private 1:1 DM thread, which
        # would be a real privacy bug (mixing a group's contents into what
        # looks like a private conversation). Only this contact's own
        # direct (non-group) messages belong in this view; group messages
        # belong exclusively in _render_group_conversation().
        ordered = sorted(
            (m for m in contact.messages if not m.is_delete_request and not m.group_id),
            key=lambda m: m.timestamp,
        )
        for msg in ordered:
            self._rendered_messages[msg.id] = msg
        blocks = [
            render_bubble(msg, contact.name, p, note_override=self._transfer_progress_note(msg))
            for msg in ordered
        ]

        self.thread_view.setHtml("".join(blocks))
        bar = self.thread_view.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _render_group_conversation(self, group: vault_mod.Group) -> None:
        p = self.palette_colors
        self.request_bar.setVisible(False)

        member_names = [
            c.name for c in (self.vault.get_contact(mid) for mid in group.member_contact_ids)
            if c is not None
        ]
        # self.tr("no members") computed as its own statement, not inline
        # inside the f-string below - see the comment above the group note
        # translations in this same method for why (pyside6-lupdate does
        # not reliably extract a .tr(...) call nested inside an f-string's
        # {...} expression).
        no_members_text = self.tr("no members")
        joined_members = escape_html(", ".join(member_names)) or no_members_text
        self.conversation_header.setText(
            i18n.fmt(
                self.tr("◈ %(name)s"), name=escape_html(group.name),
            ) + f"  ·  {joined_members}"
        )
        self.conversation_avatar.setPixmap(_avatar_pixmap(group.name, 34, kind=_KIND_GROUP))
        self.conversation_avatar.setVisible(True)
        self._set_composer_enabled(self.tor.service is not None and bool(group.member_contact_ids))

        messages = self.vault.group_messages(group)
        if not messages:
            self.thread_view.setHtml(
                f"<p style='color:{p.text_muted};'>"
                + self.tr(
                    "No messages yet. Every member needs the app running at the "
                    "same time as you for a group message to reach them."
                )
                + "</p>"
            )
            return

        # Outgoing messages are stored as one Message per member (see
        # vault.Message.client_msg_id's docstring) - collapse each set of
        # sibling copies into a single bubble with an aggregate delivery
        # count, rather than showing the same text N times.
        blocks: list[tuple[str, str]] = []  # (timestamp, html), for a stable final sort
        seen_client_ids: set[str] = set()

        for msg in messages:
            if msg.direction == "out":
                cid = msg.client_msg_id
                if cid and cid in seen_client_ids:
                    continue
                copies = [m for m in messages if m.client_msg_id == cid] if cid else [msg]
                seen_client_ids.add(cid)
                sent_count = sum(1 for m in copies if m.status == vault_mod.SENT)
                total = len(copies)
                # self.tr()/i18n.fmt() here, not the free-function i18n.tr()/
                # trf() - self is available (this is a MainWindow method), so
                # this follows the same convention every other in-class
                # translated string in this file uses (see i18n.py's
                # trf()/fmt() docstrings for why fmt(self.tr(...), ...) is
                # the right pairing inside a class). This also happens to
                # matter functionally, not just stylistically: trf()'s own
                # keyword-only `n` parameter (the Qt numerus selector) would
                # swallow a caller's `n=total` meant for %(n)s substitution
                # instead of passing it through to %-formatting - fmt() has
                # no such reserved name and does not have this trap.
                #
                # Each self.tr(...) call is its own statement, computed
                # BEFORE the f-string that uses it, never inline inside an
                # f-string's {...} expression - pyside6-lupdate's Python
                # string extraction does not reliably find a call nested
                # that way (verified empirically: it silently extracts
                # nothing, leaving the string untranslated in every
                # language forever with no error anywhere). See
                # _attachment_html's save_as_text comment for the same rule
                # applied to a free function.
                if sent_count == total:
                    delivered_text = self.tr("Delivered")
                    note = (
                        f"<div style='color:{p.text_muted};font-size:11px;'>"
                        f"{delivered_text}</div>"
                    )
                elif sent_count == 0:
                    waiting_text = i18n.fmt(self.tr("Waiting for %(n)s member(s)…"), n=total)
                    note = (
                        f"<div style='color:{p.warn};font-size:11px;'>"
                        f"{waiting_text}</div>"
                    )
                else:
                    partial_text = i18n.fmt(
                        self.tr("Delivered to %(sent)s of %(total)s"),
                        sent=sent_count, total=total,
                    )
                    note = (
                        f"<div style='color:{p.warn};font-size:11px;'>"
                        f"{partial_text}"
                        f"</div>"
                    )
                self._rendered_messages[msg.id] = msg
                blocks.append((msg.timestamp, render_bubble(msg, group.name, p, note_override=note)))
            else:
                sender = self.vault.get_contact(msg.sender_contact_id)
                sender_name = sender.name if sender is not None else self.tr("Unknown member")
                self._rendered_messages[msg.id] = msg
                blocks.append((msg.timestamp, render_bubble(msg, sender_name, p)))

        blocks.sort(key=lambda pair: pair[0])
        self.thread_view.setHtml("".join(html for _ts, html in blocks))
        bar = self.thread_view.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _on_thread_link_clicked(self, url) -> None:
        """
        Handles a left-click on a link inside a message bubble. Three
        kinds: "attach:<id>" (Save As..., see _attachment_html), "open:
        <id>" (Open - only shown once a saved copy still exists on disk,
        see _attachment_html/Message.saved_path), and "msg:<id>", the
        invisible whole-bubble anchor render_bubble wraps every message
        in purely so _on_thread_context_menu can resolve a right-click
        position back to a Message; a left-click on it does nothing
        (Delete now lives only in that right-click menu, not as an
        always-visible link - see _on_thread_context_menu).
        setOpenLinks(False) above stops Qt from doing anything with any
        of these on its own.
        """
        href = url.toString()
        if href.startswith("open:"):
            message_id = href[len("open:"):]
            msg = self._rendered_messages.get(message_id)
            saved_path = getattr(msg, "saved_path", "") if msg is not None else ""
            # Re-checked here, not just trusted from the link having been
            # shown at all - the file could have been moved/deleted in
            # the time between rendering the bubble and this click.
            if saved_path and os.path.isfile(saved_path):
                QDesktopServices.openUrl(QUrl.fromLocalFile(saved_path))
            return
        if not href.startswith("attach:"):
            return
        message_id = href[len("attach:"):]
        msg = self._rendered_messages.get(message_id)
        if msg is None or not msg.attachment_filename:
            return

        try:
            data = base64.b64decode(msg.body)
        except Exception:
            QMessageBox.warning(self, self.tr("Could not save file"), self.tr("The attachment is corrupted."))
            return

        target_path, _filter = QFileDialog.getSaveFileName(
            self, self.tr("Save Attachment"), msg.attachment_filename,
        )
        if not target_path:
            return
        try:
            with open(target_path, "wb") as f:
                f.write(data)
            os.chmod(target_path, 0o600)
        except OSError as exc:
            _logger.exception("Could not save attachment")
            QMessageBox.warning(
                self, self.tr("Could not save file"),
                safe_error_text(exc, self.tr("Could not write the file to that location.")),
            )
            return

        # Remembered so future visits to this same message can offer
        # "Open" directly (see _on_thread_context_menu) instead of asking
        # "Save As..." every single time - the recipient already chose a
        # location once; there is no need to make them repeat that choice
        # just to look at a file they already have on disk. Not affected
        # by "delete for everyone" - see Message.saved_path's docstring on
        # why a saved copy is the recipient's own, independent of this
        # vault's in-app copy. msg.contact_id is the right lookup key even
        # for a group message - add_message() always stores a Message
        # under its own contact_id's list regardless of group_id (see
        # vault.Message's sender_contact_id docstring).
        self.vault.mark_attachment_saved(msg.contact_id, msg.id, target_path)
        msg.saved_path = target_path

        # Never opened automatically - this is a deliberate second action
        # by the user, after they already chose to save it (see
        # _attachment_html's docstring on why nothing about an attachment
        # is auto-rendered/auto-opened on receipt). QDesktopServices hands
        # the file off to the OS's own registered default application for
        # its type - this app never executes it directly or shells out to
        # anything itself.
        open_now = QMessageBox.question(
            self, self.tr("Saved"),
            i18n.fmt(
                self.tr("Saved to:\n%(path)s\n\nOpen it now?"), path=target_path,
            ),
            QMessageBox.Yes | QMessageBox.No,
        )
        if open_now == QMessageBox.Yes:
            QDesktopServices.openUrl(QUrl.fromLocalFile(target_path))

    def _on_thread_context_menu(self, position) -> None:
        """
        Right-click menu for a single message bubble - replaces the old
        always-visible inline "Delete" link (see render_bubble) with an
        on-demand menu, matching how _on_contact_menu already offers
        actions for a sidebar row instead of showing them all inline.

        anchorAt(position) resolves which bubble was clicked via the
        invisible "msg:<id>" anchor render_bubble wraps every row in -
        the same technique already used for the real "attach:<id>" link,
        just covering the whole bubble instead of one word of text, so a
        right-click anywhere on a message (not only exactly on a link)
        still finds the right Message.
        """
        href = self.thread_view.anchorAt(position)
        if not href.startswith("msg:"):
            return
        message_id = href[len("msg:"):]
        msg = self._rendered_messages.get(message_id)
        if msg is None:
            return

        menu = QMenu(self)
        copy_action = None
        open_action = None
        save_action = None
        delete_action = None

        if not getattr(msg, "deleted", False):
            if getattr(msg, "attachment_filename", ""):
                # "Open" only offered once a saved copy actually exists at
                # a path that's still real right now - checked here, at
                # menu-build time, not trusted from the stored path alone
                # (the user could have moved/renamed/deleted it since
                # saving, entirely outside this app's knowledge). "Save
                # As..." stays available even when "Open" is - saving a
                # second copy elsewhere is still a normal thing to want.
                saved_path = getattr(msg, "saved_path", "")
                if saved_path and os.path.isfile(saved_path):
                    open_action = menu.addAction(self.tr("Open"))
                save_action = menu.addAction(self.tr("Save As…"))
            else:
                copy_action = menu.addAction(self.tr("Copy text"))

        if msg.direction == "out" and not getattr(msg, "deleted", False) and getattr(msg, "client_msg_id", ""):
            if not menu.isEmpty():
                menu.addSeparator()
            delete_action = menu.addAction(self.tr("Delete"))

        if menu.isEmpty():
            return

        chosen = menu.exec(self.thread_view.viewport().mapToGlobal(position))
        if chosen is None:
            return
        if chosen == copy_action:
            QApplication.clipboard().setText(msg.body)
        elif chosen == open_action:
            QDesktopServices.openUrl(QUrl.fromLocalFile(msg.saved_path))
        elif chosen == save_action:
            self._on_thread_link_clicked(QUrl(f"attach:{msg.id}"))
        elif chosen == delete_action:
            self._on_delete_message(msg)

    def _on_delete_message(self, msg: vault_mod.Message) -> None:
        """
        "Delete for everyone" for a message the local user sent (only ever
        reachable via render_bubble's "Delete" link, which is only ever
        shown on the user's own outgoing bubbles - see its docstring - so
        msg.direction == "out" here in every real UI path; checked again
        below anyway since this also doubles as the one place that could
        enforce it if that ever changed).

        Two things happen, both already-hardened, existing machinery rather
        than a new delivery mechanism:

        1. mark_deleted() scrubs this vault's own copy (or copies, for a
           group message - see below) right away, locally.
        2. queue_delete_request() queues a "delete" envelope (see
           envelope.py) to whoever originally received the message, reusing
           the exact same queued-Message/DeliveryWorker retry path every
           other outgoing message already goes through - no separate
           mechanism, no server, no CDN: if the recipient is offline right
           now, this keeps retrying exactly like a queued text message would,
           entirely over Tor to their hidden service, until it gets through.

        Deleting still applies regardless of whether the original message
        was ever confirmed delivered - undoing it locally and queuing the
        notification does not depend on that message's own delivery state
        at all.

        A group message was originally stored as one Message per member,
        sharing client_msg_id (see vault.Message's docstring) - all of those
        sibling copies are found and deleted/notified together here, so
        "delete for everyone" in a group really means everyone, not just
        the one member row the clicked bubble happened to represent.
        """
        if msg.direction != "out" or not msg.client_msg_id:
            return

        confirm = QMessageBox.question(
            self,
            self.tr("Delete message"),
            self.tr(
                "Delete this message for everyone? This cannot be undone, and "
                "removes it from the other side too - whether or not it has been "
                "delivered yet."
            ),
            QMessageBox.Yes | QMessageBox.Cancel,
            QMessageBox.Cancel,
        )
        if confirm != QMessageBox.Yes:
            return

        if msg.group_id:
            # Find every sibling per-member copy of this same outgoing group
            # message (see vault.Message.client_msg_id's docstring) by
            # scanning every contact's own messages list directly, rather
            # than only the group's *current* members - this still finds
            # (and deletes/notifies) a copy sent to a member who has since
            # left the group, whose message row lives on unaffected by that.
            seen_ids: set[str] = set()
            copies = []
            for contact in self.vault.contacts:
                for m in contact.messages:
                    if (
                        m.direction == "out"
                        and m.client_msg_id == msg.client_msg_id
                        and m.id not in seen_ids
                    ):
                        copies.append(m)
                        seen_ids.add(m.id)
            for copy in copies:
                self.vault.mark_deleted(copy.contact_id, copy.id)
                self.vault.queue_delete_request(
                    copy.contact_id, copy.client_msg_id, group_id=msg.group_id
                )
        else:
            self.vault.mark_deleted(msg.contact_id, msg.id)
            self.vault.queue_delete_request(msg.contact_id, msg.client_msg_id)

        if self.delivery is not None:
            self.delivery.wake()

        self._reload_contacts(select_id=self._active_contact_id or self._active_group_id)
        if msg.group_id:
            group = self.vault.get_group(msg.group_id)
            if group is not None and self._active_group_id == msg.group_id:
                self._render_conversation(None, group=group)
        else:
            contact = self.vault.get_contact(msg.contact_id)
            if contact is not None and self._active_contact_id == msg.contact_id:
                self._render_conversation(contact)

    def _set_composer_enabled(self, enabled: bool) -> None:
        self.message_input.setEnabled(enabled)
        self.send_button.setEnabled(enabled)
        self.attach_button.setEnabled(enabled)

    # -- Sending ------------------------------------------------------------ #
    def _on_send(self) -> None:
        if self._active_group_id is not None:
            self._on_send_group_text()
            return

        if self._send_worker is not None and self._send_worker.isRunning():
            return
        if self._active_contact_id is None:
            return

        contact = self.vault.get_contact(self._active_contact_id)
        if contact is None:
            return

        body = self.message_input.toPlainText().strip()
        if not body:
            return

        if self.tor.service is None:
            QMessageBox.warning(
                self, self.tr("Not ready"), self.tr("Still getting ready. Try again in a moment.")
            )
            return

        identity = self.vault.identity
        assert identity is not None

        # A fresh shared id for this message (see envelope.py's module
        # docstring on "mid"), sent on the wire and stored locally as this
        # Message's client_msg_id, so a later "delete for everyone" (see
        # _on_delete_message) has something stable to name - independent of
        # this message's local vault.Message.id, which the recipient's copy
        # will never share.
        client_msg_id = str(uuid.uuid4())

        self._pending_body = body
        self._pending_client_msg_id = client_msg_id
        self._pending_contact_id = contact.id
        self.send_button.setDisabled(True)
        self.send_button.setToolTip(self.tr("Sending…"))
        # Also block a file send starting concurrently and racing this one
        # over the shared self._send_worker/self._pending_contact_id fields.
        self.attach_button.setDisabled(True)

        self._send_worker = SendWorker(
            onion=contact.onion,
            their_public_b64=contact.public_key,
            body=envelope.encode_text(body, mid=client_msg_id),
            my_private=self.vault.private_key_raw(),
            my_public_b64=identity.public_key,
            my_onion=identity.onion,
            socks_port=self.tor.socks_port,
        )
        self._send_worker.done.connect(self._on_send_done)
        self._send_worker.finished.connect(self._release_send_worker)
        self._send_worker.start()

    def _on_send_done(self, success: bool, error: str) -> None:
        self.send_button.setDisabled(False)
        if self._send_button_has_icon:
            self.send_button.setToolTip(self.tr("Send"))
        else:
            self.send_button.setText(self.tr(" Send"))
        self.attach_button.setDisabled(False)

        # Always the contact this specific send was actually addressed to -
        # never self._active_contact_id, which may have changed if the user
        # switched to a different conversation while this send was still in
        # flight on the network thread. Using the live selection here would
        # file the message (and its delivered/queued outcome) under whatever
        # contact happens to be on screen when the worker finishes, not the
        # one it was sent to.
        sent_to_id = self._pending_contact_id
        if sent_to_id:
            # A failed send is queued, not lost. The delivery worker keeps
            # retrying until the contact's onion service answers.
            self.vault.add_message(
                sent_to_id,
                direction="out",
                body=self._pending_body,
                delivered=success,
                note="" if success else error,
                status=vault_mod.SENT if success else vault_mod.QUEUED,
                client_msg_id=self._pending_client_msg_id,
            )
        self._pending_contact_id = None
        self._pending_client_msg_id = ""

        # No status-bar announcement here - the message itself appears in
        # the thread below with its own delivery state (see render_bubble),
        # exactly like a normal messenger: you see "Delivered" or
        # "User offline - message queued" on the message, not in a banner.
        if not success and self.delivery is not None:
            self.delivery.wake()

        # Reload the sidebar regardless (the sent-to contact's last-activity
        # time changed and may need to re-sort) but keep whatever contact is
        # currently selected - it may no longer be sent_to_id.
        self._reload_contacts(select_id=self._active_contact_id)

        # Only touch the composer and the visible conversation if the user
        # is still looking at the conversation this message was sent to.
        # Otherwise this would wipe out a draft the user has since started
        # typing to someone else, or flash their conversation to a message
        # that was not sent to that person.
        if self._active_contact_id == sent_to_id:
            self.message_input.clear()
            self._render_conversation(self.vault.get_contact(sent_to_id))

    def _release_send_worker(self) -> None:
        if self._send_worker is not None:
            self._send_worker.deleteLater()
            self._send_worker = None

    # -- Group sending -------------------------------------------------------- #
    def _on_send_group_text(self) -> None:
        if self._group_send_worker is not None and self._group_send_worker.isRunning():
            return
        if self._active_group_id is None:
            return
        group = self.vault.get_group(self._active_group_id)
        if group is None:
            return

        body = self.message_input.toPlainText().strip()
        if not body:
            return

        if self.tor.service is None:
            QMessageBox.warning(
                self, self.tr("Not ready"), self.tr("Still getting ready. Try again in a moment.")
            )
            return
        if not group.member_contact_ids:
            QMessageBox.warning(
                self, self.tr("No members"), self.tr("This group has no members to send to.")
            )
            return

        self._start_group_send(group, text_body=body)

    def _start_group_send(
        self, group: vault_mod.Group, *, text_body: str = "",
        file_path: str = "", file_data: bytes = b"", file_mime: str = "",
    ) -> None:
        """
        Common path for both a typed group message and a group file/image
        send.

        Creates one QUEUED outgoing Message per member up front (so
        vault.Vault.queued_messages()/DeliveryWorker's existing, already-
        hardened retry sweep picks up any member this attempt fails for,
        with zero changes to that code - see _wire_body_for), then starts
        one GroupSendWorker to actually attempt delivery to everyone.

        Members in group.pending_onboard_contact_ids (added directly via
        create_group()/the "Add/remove members" UI, never through an
        invite) get their OWN individually-minted, single-use invite
        embedded in their copy of this message instead of the plain
        shared envelope everyone else gets - see
        Group.pending_onboard_contact_ids's docstring for why this is the
        only way they can ever learn the group exists at all. Each
        onboarding member's invite is distinct (never the same code
        reused across members - group_invite.py's whole single-use
        property depends on that).
        """
        identity = self.vault.identity
        assert identity is not None
        is_file = bool(file_path)

        members: list[tuple[str, str, str]] = []
        for member_id in group.member_contact_ids:
            member = self.vault.get_contact(member_id)
            if member is not None:
                members.append((member.id, member.onion, member.public_key))
        if not members:
            return

        client_msg_id = str(uuid.uuid4())

        # See _wire_body_for's docstring on acked_group_ids: keep proving
        # invitation on every send to a group this vault joined via
        # invite until the owner's KIND_GROUP_ACK confirms membership.
        # Never set for a group this vault owns.
        shared_invcode = (
            group.joined_invite_code
            if group.joined_invite_code and group.id not in self._acked_group_ids
            else ""
        )

        # Computed once, reused for both the shared body below and every
        # per-member onboarding body further down - computed once rather
        # than per-call so every member sees the SAME filename for the
        # same attachment, exactly as they would have all seen the same
        # real filename. An IMAGE gets a random, unguessable name (see
        # _random_image_filename's docstring), generated HERE rather than
        # trusted to already be random in file_path - this method is
        # called directly (see _on_send_file), and an implicit "the
        # caller already randomized it" contract is exactly the kind of
        # assumption that silently breaks the moment a new caller doesn't
        # know about it (verified concretely: this exact bug was caught
        # by a direct-call test - see test_delete.py). Any other file
        # type keeps its own real name (sanitized of path components by
        # envelope.py) - a recipient usually needs to actually know what
        # a document/archive/etc. is called, unlike a photo.
        wire_filename = (
            (_random_image_filename(file_mime) if file_mime.startswith("image/") else os.path.basename(file_path))
            if is_file else ""
        )

        def build_body(invcode: str) -> str:
            if is_file:
                return envelope.encode_file(
                    wire_filename, file_mime, file_data,
                    gid=group.id, gname=group.name, mid=client_msg_id, invcode=invcode,
                )
            return envelope.encode_text(
                text_body, gid=group.id, gname=group.name, mid=client_msg_id, invcode=invcode,
            )

        # Build the shared envelope first (it sanitizes the filename - see
        # envelope.py), then decode it straight back so the locally-stored
        # Message rows use the exact same sanitized filename/mime that will
        # actually go out on the wire, rather than re-deriving them
        # separately and risking the two falling out of sync. Onboarding
        # members' individually-invite-bearing bodies below re-derive
        # from the SAME sanitized filename/mime (via the decoded `sent`
        # values), not by re-sanitizing the raw path a second time, so
        # the stored Message row is identical either way.
        shared_wire_body = build_body(shared_invcode)
        sent = envelope.decode(shared_wire_body)
        if is_file:
            stored_body = sent.body  # already base64, matches envelope's own encoding
            attachment_filename, attachment_mime, attachment_size = sent.filename, sent.mime, sent.size
        else:
            stored_body = text_body
            attachment_filename = attachment_mime = ""
            attachment_size = 0

        onboarding_ids = set(group.pending_onboard_contact_ids)
        per_member_bodies: dict[str, str] = {}
        per_member_invcodes: dict[str, str] = {}
        for member_id in onboarding_ids:
            if member_id not in {m[0] for m in members}:
                continue
            try:
                personal_invite = self.vault.create_group_invite(
                    group.id, vault_mod.INVITE_EXPIRY_CHOICES_HOURS[-1],
                )
            except (ValueError, vault_mod.VaultLocked):
                continue  # not the owner, or identity not ready - falls back to the shared body
            personal_code = invite_mod.parse_invite(personal_invite).code
            # `invite` carries the FULL signed invite text (not just its
            # bare code, unlike invcode) - this is what lets the
            # recipient's own app call join_group_from_invite()
            # automatically the moment this envelope arrives, closing the
            # gap where a directly-added member's app previously had no
            # way to learn the group existed at all short of the owner
            # separately doing "Create invite..." and the member manually
            # pasting it via "Join Group...". invcode is still attached
            # too - unchanged - since it's what the OWNER's side needs
            # back (via redeem_group_invite_locally) once the member's
            # app starts sending; the two fields serve the two different
            # directions of this same handshake.
            per_member_bodies[member_id] = (
                envelope.encode_file(
                    wire_filename, file_mime, file_data,
                    gid=group.id, gname=group.name, mid=client_msg_id,
                    invcode=personal_code, invite=personal_invite,
                ) if is_file else
                envelope.encode_text(
                    text_body, gid=group.id, gname=group.name,
                    mid=client_msg_id, invcode=personal_code, invite=personal_invite,
                )
            )
            per_member_invcodes[member_id] = personal_code
            self.vault.clear_group_onboarding(group.id, member_id)

        message_ids: dict[str, str] = {}
        for member_id, _onion, _pub in members:
            msg = self.vault.add_message(
                member_id, direction="out", body=stored_body, delivered=False,
                status=vault_mod.QUEUED, group_id=group.id, client_msg_id=client_msg_id,
                attachment_filename=attachment_filename, attachment_mime=attachment_mime,
                attachment_size=attachment_size,
                pending_invcode=per_member_invcodes.get(member_id, ""),
            )
            if msg is not None:
                message_ids[member_id] = msg.id
        self._group_send_message_ids = message_ids

        self.message_input.clear()
        self._reload_contacts(select_id=self._active_group_id)
        if self._active_group_id == group.id:
            self._render_conversation(None, group=group)

        self.send_button.setDisabled(True)
        self.attach_button.setDisabled(True)
        worker_members = [
            (member_id, onion, pub, per_member_bodies.get(member_id, shared_wire_body))
            for member_id, onion, pub in members
        ]
        self._group_send_worker = GroupSendWorker(
            members=worker_members,
            my_private=self.vault.private_key_raw(),
            my_public_b64=identity.public_key,
            my_onion=identity.onion,
            socks_port=self.tor.socks_port,
        )
        self._group_send_worker.per_result.connect(self._on_group_send_result)
        self._group_send_worker.finished_all.connect(self._on_group_send_finished)
        self._group_send_worker.finished.connect(self._release_group_send_worker)
        self._group_send_worker.start()

    def _on_group_send_result(self, contact_id: str, success: bool, error: str) -> None:
        message_id = self._group_send_message_ids.get(contact_id)
        if message_id is None:
            return
        self.vault.mark_message(
            contact_id, message_id, vault_mod.SENT if success else vault_mod.QUEUED,
            "" if success else error,
        )

    def _on_group_send_finished(self) -> None:
        self.send_button.setDisabled(False)
        self.attach_button.setDisabled(False)
        self._group_send_message_ids = {}

        # Any per-member failure just recorded above is now an ordinary
        # QUEUED message like any other - wake the existing delivery
        # worker so it starts retrying without waiting for its next
        # scheduled sweep.
        if self.delivery is not None:
            self.delivery.wake()

        self._reload_contacts(select_id=self._active_contact_id or self._active_group_id)
        if self._active_group_id:
            group = self.vault.get_group(self._active_group_id)
            if group is not None:
                self._render_conversation(None, group=group)

    def _release_group_send_worker(self) -> None:
        if self._group_send_worker is not None:
            self._group_send_worker.deleteLater()
            self._group_send_worker = None

    # -- File / image sending ------------------------------------------------ #
    def _on_send_file(self) -> None:
        """Attach... button: works for either a 1:1 contact or a group,
        whichever is currently selected."""
        target_group: vault_mod.Group | None = None
        target_contact: vault_mod.Contact | None = None

        if self._active_group_id is not None:
            target_group = self.vault.get_group(self._active_group_id)
            if target_group is None:
                return
            if not target_group.member_contact_ids:
                QMessageBox.warning(
                    self, self.tr("No members"), self.tr("This group has no members to send to.")
                )
                return
            if self._group_send_worker is not None and self._group_send_worker.isRunning():
                return
        else:
            if self._active_contact_id is None:
                return
            target_contact = self.vault.get_contact(self._active_contact_id)
            if target_contact is None:
                return
            if self._send_worker is not None and self._send_worker.isRunning():
                return

        if self.tor.service is None:
            QMessageBox.warning(
                self, self.tr("Not ready"), self.tr("Still getting ready. Try again in a moment.")
            )
            return

        path, _filter = QFileDialog.getOpenFileName(self, self.tr("Send File"))
        if not path:
            return

        try:
            size = os.path.getsize(path)
        except OSError as exc:
            _logger.exception("Could not stat file to send")
            QMessageBox.warning(
                self, self.tr("Could not read file"),
                safe_error_text(exc, self.tr("Could not read that file.")),
            )
            return
        if size > envelope.MAX_TRANSFER_BYTES:
            QMessageBox.warning(
                self, self.tr("File is too large"),
                i18n.fmt(
                    self.tr("Files are limited to %(mb)s MB."),
                    mb=envelope.MAX_TRANSFER_BYTES // (1024 * 1024),
                ),
            )
            return

        mime, _encoding = mimetypes.guess_type(path)
        mime = mime or "application/octet-stream"

        # A file over MAX_FILE_BYTES always goes out chunked (see
        # ChunkedSendWorker) - never read fully into memory up front for
        # that path (a multi-GB file would otherwise be loaded whole
        # before a single byte goes out, exactly the memory-use problem
        # chunking exists to avoid). The image-recompression prompt
        # below only applies to the small, single-shot path - a large
        # image is sent as-is, chunked, with no recompression choice
        # (recompressing would require decoding the whole thing into
        # memory anyway, defeating the point).
        if size > envelope.MAX_FILE_BYTES:
            if target_group is not None:
                self._start_group_chunked_send(target_group, path, mime, size)
            elif target_contact is not None:
                self._start_contact_chunked_send(target_contact, path, mime, size)
            return

        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as exc:
            _logger.exception("Could not read file to send")
            QMessageBox.warning(
                self, self.tr("Could not read file"),
                safe_error_text(exc, self.tr("Could not read that file.")),
            )
            return

        if mime.startswith("image/"):
            # Always re-encoded, no dialog, no "send original" choice -
            # see _recompress_image_bytes's own docstring for exactly
            # what this strips (EXIF/GPS/thumbnails/comments, plus any
            # non-image bytes hidden in a file merely disguised as one).
            # Previously this was a per-send prompt defaulting to
            # compressed but allowing "Send Original" - removed entirely
            # so there is no way, deliberate or accidental, to leak the
            # original file's metadata to a recipient.
            recompressed = _recompress_image_bytes(data)
            if recompressed is None:
                QMessageBox.warning(
                    self,
                    self.tr("Could not read image"),
                    self.tr(
                        "This file could not be decoded as an image, so it cannot be "
                        "sent safely. It may not actually be an image, or may be "
                        "corrupted."
                    ),
                )
                return
            # Recompressed to JPEG. `path` itself is left as the original
            # filesystem path - it is no longer used to derive the
            # attachment's wire filename at all for an image (the send
            # helpers below - _start_group_send/_start_contact_file_send/
            # _start_contact_chunked_send - each generate their own fresh
            # _random_image_filename() whenever file_mime is an image, so
            # there is exactly one place per send path that decides the
            # wire filename, rather than this method pre-computing one
            # that a callee would then have to trust was already random).
            data, mime = recompressed, "image/jpeg"

        if target_group is not None:
            self._start_group_send(target_group, file_path=path, file_data=data, file_mime=mime)
        elif target_contact is not None:
            self._start_contact_file_send(target_contact, path, data, mime)

    def _start_contact_file_send(
        self, contact: vault_mod.Contact, file_path: str, file_data: bytes, file_mime: str,
    ) -> None:
        client_msg_id = str(uuid.uuid4())
        # An image gets a random, unguessable name (see
        # _random_image_filename's docstring) - generated HERE, not
        # trusted to already be random in file_path, so this holds no
        # matter what the caller passed in (this method is called
        # directly from more than one place - see _on_send_file - and an
        # implicit "the caller already randomized it" contract is exactly
        # the kind of assumption that silently breaks the moment a new
        # caller doesn't know about it). Any other file type keeps its
        # own real name (still sanitized of any path components by
        # envelope.py) - a recipient usually needs to know what a
        # document/archive/etc. actually is, unlike a photo.
        wire_filename = (
            _random_image_filename(file_mime) if file_mime.startswith("image/")
            else os.path.basename(file_path)
        )
        wire_body = envelope.encode_file(
            wire_filename, file_mime, file_data, mid=client_msg_id,
        )
        sent = envelope.decode(wire_body)  # sanitized filename/mime, matches what is actually sent

        msg = self.vault.add_message(
            contact.id, direction="out", body=sent.body, delivered=False, status=vault_mod.QUEUED,
            attachment_filename=sent.filename, attachment_mime=sent.mime, attachment_size=sent.size,
            client_msg_id=client_msg_id,
        )
        self._pending_file_message_id = msg.id if msg is not None else None
        self._pending_contact_id = contact.id

        self._reload_contacts(select_id=self._active_contact_id)
        if self._active_contact_id == contact.id:
            self._render_conversation(self.vault.get_contact(contact.id))

        identity = self.vault.identity
        assert identity is not None
        self.send_button.setDisabled(True)
        self.attach_button.setDisabled(True)
        self._send_worker = SendWorker(
            onion=contact.onion,
            their_public_b64=contact.public_key,
            body=wire_body,
            my_private=self.vault.private_key_raw(),
            my_public_b64=identity.public_key,
            my_onion=identity.onion,
            socks_port=self.tor.socks_port,
        )
        self._send_worker.done.connect(self._on_file_send_done)
        self._send_worker.finished.connect(self._release_send_worker)
        self._send_worker.start()

    def _on_file_send_done(self, success: bool, error: str) -> None:
        self.send_button.setDisabled(False)
        self.attach_button.setDisabled(False)

        message_id = self._pending_file_message_id
        sent_to_id = self._pending_contact_id
        self._pending_file_message_id = None
        self._pending_contact_id = None

        if sent_to_id and message_id:
            self.vault.mark_message(
                sent_to_id, message_id, vault_mod.SENT if success else vault_mod.QUEUED,
                "" if success else error,
            )
        if not success and self.delivery is not None:
            self.delivery.wake()

        self._reload_contacts(select_id=self._active_contact_id)
        if self._active_contact_id == sent_to_id:
            self._render_conversation(self.vault.get_contact(sent_to_id))

    def _start_contact_chunked_send(
        self, contact: vault_mod.Contact, file_path: str, mime: str, total_size: int,
    ) -> None:
        """
        Large-file (over envelope.MAX_FILE_BYTES) counterpart to
        _start_contact_file_send - see ChunkedSendWorker's docstring for
        the actual chunk-by-chunk send mechanics. Shows a placeholder
        attachment bubble immediately (same "appears right away, fills
        in as it goes" pattern the group-invite onboarding flow already
        established), then launches the worker for every chunk this
        transfer doesn't already have marked done (empty set for a
        brand-new send - see DeliveryWorker's resume path for the
        non-empty case).
        """
        chunk_count = -(-total_size // envelope.CHUNK_SIZE)  # ceiling division
        client_msg_id = str(uuid.uuid4())
        # Generated ONCE and reused for both the wire announcement and
        # the local FileTransfer record below - these must be the exact
        # same id, since every chunk (sent using the LOCAL record's id,
        # see _launch_chunked_send_worker) has to match what
        # KIND_FILE_START told the receiver to expect. Two independently
        # generated ids here (one baked into the wire message, a
        # different one used locally) would mean the receiver's
        # KIND_FILE_START-created transfer and the chunks that actually
        # arrive tagged with the OTHER id never line up - each chunk
        # would then look like it belongs to an unrecognized transfer and
        # get handled by _on_file_chunk's own implicit-start fallback
        # instead, creating a second, separate (and wrongly-named)
        # Message/FileTransfer alongside the first.
        transfer_id = str(uuid.uuid4())

        # An image gets a random, unguessable name (see
        # _random_image_filename's docstring) - same rule the small-file
        # send path (_start_contact_file_send/_start_group_send) applies.
        # Any other file type keeps its own real name. Chunked sends
        # never recompress (would need loading the whole large file into
        # memory, defeating the point of chunking it in the first place -
        # see _on_send_file's own comment on this), so an image sent this
        # way still carries its original bytes/metadata; the filename
        # itself is the one piece of this still worth scrubbing here.
        wire_filename = (
            _random_image_filename(mime) if mime.startswith("image/")
            else os.path.basename(file_path)
        )
        try:
            start_wire = envelope.encode_file_start(
                transfer_id, wire_filename, mime, total_size, chunk_count,
                mid=client_msg_id,
            )
        except envelope.EnvelopeError as exc:
            QMessageBox.warning(self, self.tr("Could not send file"), str(exc))
            return
        start_env = envelope.decode(start_wire)  # sanitized filename/mime, matches what is actually sent

        transfer = self.vault.start_file_transfer(
            contact.id, "out", start_env.filename, start_env.mime, total_size, chunk_count,
            group_id="", client_msg_id=client_msg_id, source_path=file_path, transfer_id=transfer_id,
        )

        msg = self.vault.add_message(
            contact.id, direction="out", body="", delivered=False, status=vault_mod.QUEUED,
            attachment_filename=start_env.filename, attachment_mime=start_env.mime,
            attachment_size=total_size, client_msg_id=client_msg_id,
        )
        self._pending_file_message_id = msg.id if msg is not None else None

        self._reload_contacts(select_id=self._active_contact_id)
        if self._active_contact_id == contact.id:
            self._render_conversation(self.vault.get_contact(contact.id))

        # start_wire is sent from inside ChunkedSendWorker's background
        # thread (see its docstring), not synchronously here on the UI
        # thread - a stalled connection to a contact who just went
        # offline could otherwise block the UI for up to
        # transport.CONNECT_TIMEOUT seconds on every single large-file
        # send, which is worse than the same risk for the rare
        # group-leave/ack control sends that already accept it.
        self._launch_chunked_send_worker(transfer, contact, file_path, start_wire=start_wire)

    def _launch_chunked_send_worker(
        self, transfer: vault_mod.FileTransfer, contact: vault_mod.Contact, file_path: str,
        start_wire: str | None = None,
    ) -> None:
        identity = self.vault.identity
        assert identity is not None
        already_done = {i for i, done in enumerate(transfer.chunks_done) if done}
        worker = ChunkedSendWorker(
            transfer_id=transfer.id, file_path=file_path, chunk_count=transfer.chunk_count,
            already_done=already_done, onion=contact.onion, their_public_b64=contact.public_key,
            my_private=self.vault.private_key_raw(), my_public_b64=identity.public_key,
            my_onion=identity.onion, socks_port=self.tor.socks_port, start_wire=start_wire,
        )
        self._chunked_send_workers[transfer.id] = worker
        worker.progress.connect(self._on_chunk_progress)
        worker.done.connect(self._on_chunked_send_done)
        worker.finished.connect(lambda: self._release_chunked_send_worker(transfer.id))
        worker.start()

    def _on_chunk_progress(self, transfer_id: str, chunk_index: int) -> None:
        self.vault.mark_chunk_done(transfer_id, chunk_index)
        transfer = self.vault.get_file_transfer(transfer_id)
        if transfer is None:
            return
        if self._active_contact_id == transfer.contact_id:
            self._render_conversation(self.vault.get_contact(transfer.contact_id))
        elif self._active_group_id == transfer.group_id and transfer.group_id:
            group = self.vault.get_group(transfer.group_id)
            if group is not None:
                self._render_conversation(None, group=group)

    def _on_chunked_send_done(self, transfer_id: str, success: bool, error: str) -> None:
        transfer = self.vault.get_file_transfer(transfer_id)
        if transfer is None:
            return
        contact = self.vault.get_contact(transfer.contact_id)
        if success and transfer.completed:
            # Fold the completed attachment into the placeholder Message
            # exactly like the single-shot KIND_FILE path already does -
            # the finished-attachment storage model (base64 inside an
            # encrypted Message) is unchanged; only how the bytes got
            # here is new. The outgoing side already has the full file on
            # disk at its original path throughout, so re-reading it here
            # (rather than the .part-file path used on the receiving
            # side) is correct and simpler.
            for msg in (contact.messages if contact else []):
                if msg.client_msg_id == transfer.client_msg_id and msg.direction == "out":
                    self.vault.mark_message(transfer.contact_id, msg.id, vault_mod.SENT, "")
                    break
            self.vault.discard_file_transfer(transfer_id)
        elif not success:
            if self.delivery is not None:
                self.delivery.wake()  # DeliveryWorker resumes the remaining chunks once back online

        if contact is not None:
            self._reload_contacts(select_id=self._active_contact_id)
            if self._active_contact_id == transfer.contact_id:
                self._render_conversation(self.vault.get_contact(transfer.contact_id))

    def _release_chunked_send_worker(self, transfer_id: str) -> None:
        worker = self._chunked_send_workers.pop(transfer_id, None)
        if worker is not None:
            worker.deleteLater()

    def _on_resume_transfer(self, transfer_id: str) -> None:
        """
        DeliveryWorker detected an incomplete outgoing transfer to a
        contact who just came back online (see DeliveryWorker.resume_transfer's
        docstring) - relaunch ChunkedSendWorker for just the remaining
        chunks. A transfer already being actively sent (still in
        self._chunked_send_workers) is left alone rather than launching
        a second worker for the same transfer in parallel.
        """
        if transfer_id in self._chunked_send_workers:
            return
        transfer = self.vault.get_file_transfer(transfer_id)
        if transfer is None or transfer.completed or transfer.direction != "out":
            return
        if not transfer.source_path or not os.path.exists(transfer.source_path):
            return  # the original file moved/was deleted - nothing to resume with
        contact = self.vault.get_contact(transfer.contact_id)
        if contact is None:
            return
        self._launch_chunked_send_worker(transfer, contact, transfer.source_path)

    # -- Receiving ---------------------------------------------------------- #
    def _on_incoming(self, message: transport.IncomingMessage) -> None:
        """Called on a network thread - hand off to the UI thread immediately."""
        self.message_arrived.emit(message.from_pub, message.body)

    def _on_message_arrived(self, from_pub: str, body: str) -> None:
        contact = self.vault.find_by_public_key(from_pub)
        if contact is None:
            return  # Sender was removed between acceptance and delivery.

        if contact.status == vault_mod.STATUS_BLOCKED:
            return  # Blocked after acceptance but before delivery.

        if contact.status == vault_mod.STATUS_PENDING:
            # A stranger's first message still needs its envelope peeled
            # off before display - `body` is real wire JSON (see
            # envelope.py: kind/mid/gid/the padding field, etc.) for every
            # sender now, not just accepted ones, so storing it verbatim
            # here used to leak that raw JSON straight into the request
            # preview/thread instead of the actual text. Only plain
            # display text is ever taken from it: group/file/delete/
            # invite framing is NOT trusted or acted on until the user
            # has actually accepted this sender as a contact - a pending
            # sender does not get to auto-join a group or land a real
            # "file" bubble in the UI before that decision is made
            # (contact.name already carries any impersonation warning
            # _add_pending attached - see vault.py). A KIND_FILE's body
            # is base64 file bytes, not text - shown as a neutral
            # placeholder rather than dumping raw base64 into the thread,
            # since nothing here decodes or stores the actual attachment
            # before acceptance either.
            try:
                env = envelope.decode(body)
            except envelope.EnvelopeError:
                display_text = ""
            else:
                if env.kind == envelope.KIND_TEXT:
                    display_text = env.body
                elif env.kind in (envelope.KIND_FILE, envelope.KIND_FILE_START):
                    display_text = self.tr("[Sent a file - accept this contact to view it]")
                elif env.kind == envelope.KIND_FILE_CHUNK:
                    return  # one chunk of an already-refused transfer - nothing new to show
                else:
                    display_text = ""  # a delete/ack/leave control envelope has nothing to show
            self.vault.add_message(contact.id, direction="in", body=display_text)
            self._reload_contacts(select_id=self._active_contact_id)
            return

        try:
            env = envelope.decode(body)
        except envelope.EnvelopeError:
            # Shaped like an envelope but fails validation (e.g. corrupted
            # or hostile base64/JSON) - dropped rather than shown as a
            # garbled bubble. Genuinely malformed input elsewhere in the
            # pipeline is already dropped silently the same way (see
            # transport.py); this is that same rule applied one layer up.
            _logger.warning("Discarding a malformed message envelope")
            return

        if env.kind == envelope.KIND_DELETE:
            group = self._apply_delete_envelope(contact, env)
            self._reload_contacts(select_id=self._active_contact_id or self._active_group_id)
            if group is not None:
                if self._active_group_id == group.id:
                    self._render_conversation(None, group=group)
            elif self._active_contact_id == contact.id:
                self._render_conversation(self.vault.get_contact(contact.id))
            return

        if env.kind == envelope.KIND_GROUP_ACK:
            # Confirms this contact's vault just accepted us as a real
            # member of env.gid (see vault.redeem_group_invite_locally on
            # their side) - nothing to store, just stop attaching invcode
            # to future sends for this group (see _wire_body_for).
            group = self.vault.get_group(env.gid)
            if group is not None:
                self._acked_group_ids.add(group.id)
            return

        if env.kind == envelope.KIND_GROUP_LEAVE:
            group = self.vault.get_group(env.gid)
            if group is not None and contact.id in group.member_contact_ids:
                self.vault.remove_group_member(group.id, contact.id)
                self._reload_contacts(select_id=self._active_contact_id or self._active_group_id)
                if self._active_group_id == group.id:
                    self._render_conversation(None, group=group)
            return

        if env.kind == envelope.KIND_FILE_START:
            self._on_file_start(contact, env)
            self._reload_contacts(select_id=self._active_contact_id or self._active_group_id)
            if self._active_contact_id == contact.id:
                self._render_conversation(self.vault.get_contact(contact.id))
            return

        if env.kind == envelope.KIND_FILE_CHUNK:
            self._on_file_chunk(contact, env)
            if self._active_contact_id == contact.id:
                self._render_conversation(self.vault.get_contact(contact.id))
            return

        if env.gid:
            group = self._file_incoming_group_message(contact, env)
            if group is None:
                return  # Unrecognized group (never created/joined here) - dropped.
        else:
            group = None
            if env.kind == envelope.KIND_FILE:
                self.vault.add_message(
                    contact.id, direction="in", body=env.body,
                    attachment_filename=env.filename, attachment_mime=env.mime,
                    attachment_size=env.size, client_msg_id=env.mid,
                )
            else:
                self.vault.add_message(
                    contact.id, direction="in", body=env.body, client_msg_id=env.mid,
                )

        self._reload_contacts(select_id=self._active_contact_id or self._active_group_id)

        if group is not None:
            if self._active_group_id == group.id:
                self._render_conversation(None, group=group)
        elif self._active_contact_id == contact.id:
            # The message appears in the open thread below - that is the
            # notification, exactly like a normal messenger. No redundant
            # banner needed.
            self._render_conversation(self.vault.get_contact(contact.id))

    def _apply_delete_envelope(
        self, contact: vault_mod.Contact, env: envelope.Envelope,
    ) -> vault_mod.Group | None:
        """
        Handle an incoming "delete" control envelope (see envelope.py):
        find and tombstone (vault.Vault.mark_deleted()) the local copy of
        the message it names, if we have one.

        Authorization is enforced structurally here, not by an extra check:
        `contact` is already the specific contact this envelope's Box was
        proven to be encrypted by (see transport.py/_on_message_arrived's
        find_by_public_key lookup, above) - so only scanning *that
        contact's own* `messages` list, filtered to `direction == "in"`,
        makes it impossible for this to ever touch a message some other
        contact sent, or a message the local user sent themselves. That is
        true for a 1:1 message and for a group message alike, because an
        incoming group message is stored on its actual sender's own contact
        record (see _file_incoming_group_message above) - so "the contact
        this envelope came from" and "the sender to check the deleted
        message's sender_contact_id against" are simply the same check.
        A delete_mid this contact never actually sent us matches nothing
        and is silently a no-op, same as any other message id that does not
        exist.
        """
        if not env.delete_mid:
            return None
        for message in contact.messages:
            if message.direction != "in" or message.client_msg_id != env.delete_mid:
                continue
            if env.gid and message.group_id != env.gid:
                continue
            self.vault.mark_deleted(contact.id, message.id)
            if message.group_id:
                return self.vault.get_group(message.group_id)
            return None
        return None

    def _on_file_start(self, contact: vault_mod.Contact, env: envelope.Envelope) -> None:
        """
        A sender announced a chunked transfer (see envelope.KIND_FILE_START).
        Creates the FileTransfer record and an immediately-visible
        placeholder Message bubble ("Receiving... 0%") - the same
        "appears right away, fills in as it goes" pattern the sending
        side uses. Idempotent: a duplicate/retried KIND_FILE_START for a
        transfer_id already on file (e.g. the sender's own retry logic
        resent it) is a no-op, not a second transfer.

        Enforces MAX_ATTACHMENT_BYTES_PER_CONTACT up front, before a
        single chunk is accepted - cheap to check now (env.size is
        already internally cross-checked against chunk_count by
        envelope.decode(), though still just a CLAIMED total; the real
        enforcement that bounds actual bytes accepted is unchanged and
        happens in vault.add_message() once the transfer completes, this
        is purely an early-reject optimization so this vault does not
        spend bandwidth/disk on a transfer it will refuse to store
        anyway).
        """
        if self.vault.get_file_transfer(env.transfer_id) is not None:
            return
        existing = sum(
            m.attachment_size for m in contact.messages
            if m.direction == "in" and m.attachment_filename and not m.deleted
        )
        if existing + env.size > vault_mod.MAX_ATTACHMENT_BYTES_PER_CONTACT:
            _logger.warning(
                "Refusing an incoming chunked transfer: contact %s would exceed "
                "the per-contact attachment cap", contact.id,
            )
            return

        client_msg_id = env.mid or str(uuid.uuid4())
        transfer = self.vault.start_incoming_file_transfer(
            env.transfer_id, contact.id, env.filename, env.mime,
            env.size, env.chunk_count, client_msg_id,
        )
        if transfer is None:
            return

        self.vault.add_message(
            contact.id, direction="in", body="", attachment_filename=env.filename,
            attachment_mime=env.mime, attachment_size=env.size, client_msg_id=transfer.client_msg_id,
        )

    def _on_file_chunk(self, contact: vault_mod.Contact, env: envelope.Envelope) -> None:
        """
        One chunk of a transfer (see envelope.KIND_FILE_CHUNK). Tolerates
        a chunk arriving with no prior KIND_FILE_START on file (lost/
        reordered network delivery, or simply a peer running code that
        never sends file_start) by starting the transfer implicitly on
        the first chunk seen for an unrecognized transfer_id - filename
        is unknown in that case (env carries none), so a generic
        placeholder name is used; MAX_ATTACHMENT_BYTES_PER_CONTACT is
        still enforced, using chunk_count * CHUNK_SIZE as the size
        estimate since no claimed total exists yet.

        Chunks are only accepted in order (index == the next expected
        one) - an out-of-order chunk is dropped, since
        Vault.append_incoming_chunk() can only append to the end of the
        .part file, and would silently corrupt the assembled file if
        chunks landed in the wrong sequence. Not a correctness gap in
        practice: transport.py delivers over a single ordered TCP stream
        per connection, and ChunkedSendWorker sends strictly in index
        order - out-of-order arrival would mean something is already
        badly wrong (a forged/replayed chunk, or a peer not following
        this protocol), so dropping it is the safe response, same as any
        other malformed/unexpected input in this codebase.
        """
        transfer = self.vault.get_file_transfer(env.transfer_id)
        if transfer is None:
            existing = sum(
                m.attachment_size for m in contact.messages
                if m.direction == "in" and m.attachment_filename and not m.deleted
            )
            estimated_size = env.chunk_count * envelope.CHUNK_SIZE
            if existing + estimated_size > vault_mod.MAX_ATTACHMENT_BYTES_PER_CONTACT:
                _logger.warning(
                    "Refusing an incoming chunked transfer with no file_start: "
                    "contact %s would exceed the per-contact attachment cap", contact.id,
                )
                return
            transfer = self.vault.start_incoming_file_transfer(
                env.transfer_id, contact.id, self.tr("file"), "application/octet-stream",
                estimated_size, env.chunk_count, str(uuid.uuid4()),
            )
            if transfer is None:
                return
            self.vault.add_message(
                contact.id, direction="in", body="", attachment_filename=transfer.filename,
                attachment_mime=transfer.mime, attachment_size=transfer.total_size,
                client_msg_id=transfer.client_msg_id,
            )

        if transfer.contact_id != contact.id or transfer.direction != "in":
            return  # a chunk claiming a transfer_id that belongs to someone else - dropped
        if transfer.chunk_count != env.chunk_count or env.chunk_index >= transfer.chunk_count:
            return
        if transfer.chunks_done[env.chunk_index]:
            return  # already have this one (a resent/duplicate chunk) - no-op, not an error

        next_expected = transfer.chunks_done_count
        if env.chunk_index != next_expected:
            return  # out of order - see docstring above on why this is dropped, not buffered

        try:
            chunk_bytes = base64.b64decode(env.body)
        except Exception:
            return

        self.vault.append_incoming_chunk(transfer.id, chunk_bytes)
        self.vault.mark_chunk_done(transfer.id, env.chunk_index)

        transfer = self.vault.get_file_transfer(transfer.id)
        if transfer is not None and transfer.completed:
            self.vault.complete_incoming_transfer(transfer.id)

    def _file_incoming_group_message(
        self, sender: vault_mod.Contact, env: envelope.Envelope,
    ) -> vault_mod.Group | None:
        """
        Store an incoming group-tagged message, if this vault is willing
        to recognize the group at all.

        Unlike the old "any accepted contact who sends a gid auto-starts
        a group" behavior, a group can now only ever be created locally
        by two paths: create_group() (the local user's own action) or
        join_group_from_invite() (an explicit, signed, single-use,
        time-limited invite - see vault.py and group_invite.py). This
        method NEVER creates a Group - only vault.Group() construction
        via those two entry points does. A gid this vault has no local
        Group for at all is simply unrecognized and the message is
        dropped (returns None) - there is no invite-less path into a
        group conversation any more.

        Two different membership-growth rules depending on which side of
        ownership this vault is on:

        * This vault OWNS the group (owner_contact_id == ""): a sender
          not yet a member is only added if their message carries a
          currently valid (unused, unexpired) invcode - checked via
          redeem_group_invite_locally(), the actual single-use
          enforcement point. A valid redemption also sends KIND_GROUP_ACK
          back so the new member's UI can stop attaching invcode to
          future sends. An invalid/missing code means the message is
          still filed (so the sender can see it was "sent", consistent
          with the existing over-capacity fallback) but membership is
          refused.
        * This vault does NOT own the group (joined via invite itself):
          it has no authority to redeem anyone's invite - only the real
          owner's vault can. A never-seen sender is added as a member
          here only if they are already one of this vault's own accepted
          contacts (the same "you must already trust this identity"
          boundary used everywhere else in this app - see
          Identity.accept_from_anyone's docstring) - this is what lets
          messages from fellow members you already know arrive normally
          without needing to re-verify an invite you were never issued.
          A stranger (not an accepted contact) sending a message tagged
          with this gid is not added as a member, though - like the
          owner-side invalid-code case - their message is still filed.

        Deliberately does NOT auto-re-add a sender in
        group.removed_contact_ids (a removed/left member) under either
        rule above - see that field's docstring.
        """
        group = self.vault.get_group(env.gid)
        if group is None:
            # No local Group for this gid yet - but if this envelope
            # carries a full signed invite (env.invite, only ever
            # attached by the OWNER's side onboarding a newly-added
            # member - see _start_group_send), redeem it automatically
            # here, exactly as if the user had pasted it into "Join
            # Group..." themselves (see _on_join_group). This is what
            # actually closes the loop GUIDE.md already promises
            # ("Veilwire automatically sends each of them a one-time
            # invite behind the scenes so their own app learns the group
            # exists") - previously the invite code WAS sent, but nothing
            # on the receiving side ever consumed it, so a directly-added
            # member's app silently dropped every group message forever
            # unless they separately went through the fully manual
            # invite-text copy/paste flow.
            #
            # join_group_from_invite() itself still enforces every real
            # trust boundary before creating anything (see its own
            # docstring): the invite's signature must verify, it must not
            # be expired, and the signed owner identity must already be
            # one of THIS vault's own accepted contacts - a forged or
            # tampered invite, or one from someone not yet trusted, is
            # rejected the same way a manually-pasted one would be. This
            # is purely automating the paste step for the one case where
            # the invite arrived attached to a message already proven to
            # come from an accepted contact (the Box decryption that got
            # us this far already establishes that), not loosening who
            # gets trusted.
            if not env.invite:
                return None
            try:
                group = self.vault.join_group_from_invite(env.invite)
            except (invite_mod.GroupInviteError, ValueError, vault_mod.VaultLocked):
                return None

        is_owner = group.owner_contact_id == ""
        already_member = sender.id in group.member_contact_ids
        removed = sender.id in group.removed_contact_ids

        if not already_member and not removed:
            if is_owner:
                if env.invcode and self.vault.redeem_group_invite_locally(group.id, env.invcode):
                    try:
                        # needs_onboarding=False: this sender already has
                        # their own local Group record (created via
                        # join_group_from_invite on their side when they
                        # redeemed this same code) - they do not need a
                        # second, redundant auto-invite from us.
                        self.vault.add_group_member(group.id, sender.id, needs_onboarding=False)
                        self.vault.mark_group_invite_used(group.id, env.invcode, sender.id)
                        self._send_group_control(group, envelope.encode_group_ack(group.id))
                    except ValueError:
                        pass  # MAX_GROUP_MEMBERS reached; message still filed below
            else:
                try:
                    # needs_onboarding=False: this vault is not the
                    # group's owner and cannot issue invites for it at
                    # all (see create_group_invite's owner-only check) -
                    # pending_onboard_contact_ids is meaningless here.
                    self.vault.add_group_member(group.id, sender.id, needs_onboarding=False)
                except ValueError:
                    pass  # not an accepted contact, or MAX_GROUP_MEMBERS reached

        if env.kind == envelope.KIND_FILE:
            self.vault.add_message(
                sender.id, direction="in", body=env.body, group_id=group.id,
                sender_contact_id=sender.id, attachment_filename=env.filename,
                attachment_mime=env.mime, attachment_size=env.size, client_msg_id=env.mid,
            )
        else:
            self.vault.add_message(
                sender.id, direction="in", body=env.body, group_id=group.id,
                sender_contact_id=sender.id, client_msg_id=env.mid,
            )
        return group

    # -- Misc --------------------------------------------------------------- #
    def _on_share_contact(self) -> None:
        identity = self.vault.identity
        if identity is None or not identity.onion:
            QMessageBox.information(
                self, self.tr("Not ready"), self.tr("Still getting ready. Try again in a moment.")
            )
            return
        try:
            bundle_text = bundle_mod.build_bundle(
                identity.onion,
                identity.public_key,
                identity.signing_public_key,
                identity.signing_private_key,
            )
        except bundle_mod.BundleError as exc:
            # str(exc) is one of our own hand-written BundleError messages
            # (see bundle.py), not a raw system exception - same rationale
            # as _on_add_contact above. Not translated: it's a plain Python
            # exception message, not a Qt-translatable literal.
            QMessageBox.critical(self, self.tr("Could not build contact bundle"), str(exc))
            return
        ShareDialog(bundle_text, identity.fingerprint, self).exec()

    def _set_connection_state(self, state: str) -> None:
        """
        Update the persistent connection-state indicator.

        Deliberately closed over a fixed vocabulary (STATE_* constants)
        rather than accepting arbitrary text: this is what stops a future
        call site from ever being able to leak a raw technical string
        (Tor bootstrap percentages, relay/circuit language, exception
        text) into the UI - there is no code path from here to the label
        that isn't one of the five words below.

        The English source word is translated HERE, at read-time via
        self.tr(), rather than inside the _CONNECTION_STATES dict literal
        (which is built once at module-import time, before any translator
        could possibly be installed) - this is what makes the fixed-
        vocabulary security property survive translation: the dict of
        allowed states stays closed and unchanged, only its displayed word
        is localized each time this method runs.
        """
        source_word, level = _CONNECTION_STATES[state]
        word = self.tr(source_word)
        p = self.palette_colors
        colors = {"ok": p.ok, "warn": p.warn, "error": p.error, "info": p.text_muted}
        self.status_dot.setStyleSheet(
            f"color: {colors.get(level, p.text_muted)}; background: transparent;"
        )
        self.status_label.setText(word)

    def _on_check_now(self) -> None:
        """Run the full reachability test on demand."""
        if self.tor.service is None:
            self._set_connection_state(STATE_STARTING)
            return

        self.check_button.setEnabled(False)
        self.check_button.setText(self.tr("Checking..."))
        self._set_connection_state(STATE_CONNECTING)

        if self.monitor is not None:
            self.monitor.request_check()

        self._self_test = SelfTestWorker(self.tor)
        self._self_test.done.connect(self._on_self_test_done)
        self._self_test.finished.connect(self._self_test.deleteLater)
        self._self_test.start()

    def _on_self_test_done(self, ok: bool, message: str) -> None:
        self.check_button.setEnabled(True)
        self.check_button.setText(self.tr("Check connection"))
        self._set_connection_state(STATE_READY if ok else STATE_OFFLINE)

    def _on_health_status(self, level: str, _text: str) -> None:
        # HealthMonitor emits a human-readable detail string alongside its
        # level, meant for logs/diagnostics - deliberately not displayed
        # here. Only `level` maps to the fixed connection-state vocabulary;
        # the underlying detail text never reaches the UI.
        if level == "ok":
            self._set_connection_state(STATE_READY)
        elif level == "warn":
            self._set_connection_state(STATE_RECONNECTING)
        else:
            self._set_connection_state(STATE_OFFLINE)

    def _on_republished(self) -> None:
        identity = self.vault.identity
        if identity is not None and self.tor.service is not None:
            self.vault.set_onion(self.tor.service.onion, self.tor.service.private_key)
            self._refresh_identity_display()

    def _shutdown_network(self) -> None:
        """
        Everything that must happen before this process can safely exit (or
        re-exec itself - see _restart_app): cancel a still-bootstrapping
        Tor startup, stop every background thread, tear down the local
        listener and Tor controller, and lock the vault.

        Factored out of closeEvent so a restart can run the exact same
        shutdown sequence a normal quit does - a restart that skipped any
        of this could leave an orphaned Tor process behind, or hand off to
        the new process while the old one still holds the vault file.
        """
        # Cancel a still-bootstrapping Tor startup *before* waiting on its
        # thread and tearing the controller down - otherwise a close during
        # startup can leave TorStartWorker blocked in its own bootstrap
        # timeout while stop() below is already pulling the controller out
        # from under it.
        self.tor.cancel()

        if self.delivery is not None:
            self.delivery.stop()
            self.delivery.wait(3000)
        if self.monitor is not None:
            self.monitor.stop()
            self.monitor.wait(3000)
        if self._self_test is not None and self._self_test.isRunning():
            self._self_test.wait(3000)
        if self._send_worker is not None and self._send_worker.isRunning():
            self._send_worker.wait(5000)
        if self._group_send_worker is not None and self._group_send_worker.isRunning():
            self._group_send_worker.wait(5000)
        if self._tor_worker is not None and self._tor_worker.isRunning():
            self._tor_worker.wait(5000)
        if self.server is not None:
            self.server.stop()
        self.tor.stop()
        self.vault.lock()

    def closeEvent(self, event) -> None:
        self._shutdown_network()
        super().closeEvent(event)

    def _restart_app(self) -> None:
        """
        Relaunch the application in a fresh process - used after a language
        change (see SettingsDialog), which only takes effect on the next
        launch since Qt's translators are installed once at startup.

        Shuts everything down exactly as a normal quit does (_shutdown_network),
        then re-executes the same interpreter with the same arguments
        (os.execv replaces this process image in place - there is no
        intermediate state where neither the old nor the new instance is
        running, and no window ever briefly appears half-closed). This
        works the same way whether launched via `python3 app.py`, the
        installed `veilwire` launcher (sys.executable is always the actual
        running interpreter, never the shell launcher script itself), or
        an AppImage's bundled venv - none of that matters here since
        sys.executable/sys.argv already describe exactly how *this*
        process was started.
        """
        _logger.info("Restarting to apply the new language...")
        self._shutdown_network()
        os.execv(sys.executable, [sys.executable] + sys.argv)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

# A fixed set of pleasant, high-contrast-on-white fill colours for the
# round initial avatars in the sidebar and conversation header - picked by
# hashing the display name so the same contact/group keeps the same
# colour across restarts with nothing to store for it, the same
# "recognize people by consistent colour" cue Telegram/Signal-style
# messengers use in place of an actual photo (this app never has one -
# there is no profile picture feature, and there will not be one: a
# photo is exactly the kind of identifying metadata a peer-to-peer,
# no-server, hide-your-IP messenger should not be encouraging people to
# exchange in the clear-ish contact bundle).
_AVATAR_COLORS = (
    "#e17076", "#eda86c", "#a695e7", "#7bc862", "#6ec9cb",
    "#65aadd", "#ee7aae", "#faa774", "#60c7a5", "#8e85ee",
)


def _avatar_pixmap(name: str, size: int = 36, kind: str = _KIND_CONTACT, verified: bool = False) -> QPixmap:
    """
    A round avatar showing a generic person/group glyph (icons/ui/
    person.png or icons/ui/group.png) - transparent inside, with just a
    coloured stroke/outline circle, not a filled background. The outline
    colour is still derived from the contact's or group's own display
    name (never uploaded, stored as an image, or exchanged with anyone),
    so different contacts/groups still get a consistent, distinguishable
    colour even though the glyph itself is the same for everyone of that
    kind (a deliberate simplification over the previous per-name-letter
    avatar - see the app's own "recognize people by consistent colour"
    design note below on _AVATAR_COLORS, which still applies to the
    outline). Used as the QListWidgetItem icon in the sidebar (native
    icon+text items keep the existing QListWidget::item:selected styling
    "for free" - no custom item widget/selection-repaint logic needed)
    and in the conversation header.

    `verified`, when True, composites the verified badge
    (icons/ui/verified.png) onto the avatar's bottom-right corner - the
    sidebar's QListWidgetItem text has no rich-text/inline-image support
    (unlike the conversation header, a QLabel, which instead gets an
    inline <img> - see _verified_badge_html()), so this is that surface's
    only way to show the badge at all.
    """
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)

    digest = hashlib.sha256((name or "?").encode("utf-8")).digest()
    color = _AVATAR_COLORS[digest[0] % len(_AVATAR_COLORS)]

    # Stroke only, no fill - the circle itself stays transparent (shows
    # whatever's behind it) rather than a solid coloured disc. Line width
    # scales gently with size so a small collapsed-sidebar icon doesn't
    # get a disproportionately thick ring.
    stroke_width = max(1, round(size / 18))
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    pen = painter.pen()
    pen.setColor(QColor(color))
    pen.setWidth(stroke_width)
    painter.setPen(pen)
    painter.setBrush(Qt.NoBrush)
    inset = stroke_width // 2
    painter.drawEllipse(inset, inset, size - 2 * inset - 1, size - 2 * inset - 1)
    painter.end()

    # Both recolored to match this avatar's own outline colour (not
    # white/native-toned, now that the circle behind them is transparent
    # rather than a solid fill they needed to contrast against) so the
    # glyph and its ring read as one consistent coloured mark. group.png
    # is naturally a dark, multi-tone illustration - on a transparent
    # background (no more solid colour disc behind it) its own dark tones
    # were nearly invisible against the app's own dark theme; flattening
    # it to one colour like person.png fixes that the same way.
    glyph_file = "group.png" if kind == _KIND_GROUP else "person.png"
    glyph_color = color
    glyph_size = max(10, int(size * 0.6))
    glyph_icon = ui_icon(glyph_file, glyph_color, glyph_size)
    if glyph_icon is not None:
        glyph_pixmap = glyph_icon.pixmap(glyph_size, glyph_size)
        painter = QPainter(pixmap)
        painter.setRenderHint(QPainter.Antialiasing)
        offset = (size - glyph_size) // 2
        painter.drawPixmap(offset, offset, glyph_pixmap)
        painter.end()

    if verified:
        badge_size = max(10, int(size * 0.42))
        # verified.png is already the intended blue - loaded unrecolored
        # (color=None), not flattened to a hardcoded hex, so it always
        # matches the actual icon file rather than a second, possibly
        # drifting colour value maintained here.
        badge_icon = ui_icon("verified.png", None, badge_size)
        if badge_icon is not None:
            badge_pixmap = badge_icon.pixmap(badge_size, badge_size)
            painter = QPainter(pixmap)
            painter.setRenderHint(QPainter.Antialiasing)
            # Bottom-right corner, matching the badge placement convention
            # most messaging apps use - a small white ring behind it so
            # the badge stays legible over the avatar's own colour and
            # over whatever glyph is directly behind it.
            bx, by = size - badge_size, size - badge_size
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor("#ffffff"))
            painter.drawEllipse(bx - 1, by - 1, badge_size + 2, badge_size + 2)
            painter.drawPixmap(bx, by, badge_pixmap)
            painter.end()

    return pixmap


_avatar_icon_cache: dict[tuple[str, str, bool], QIcon] = {}


def _avatar_icon(name: str, kind: str = _KIND_CONTACT, verified: bool = False) -> QIcon:
    """Cached QIcon wrapper around _avatar_pixmap - the sidebar rebuilds
    every row on every reload (a new message, a presence change, ...), so
    this avoids repainting the same handful of contacts'/groups' avatars
    from scratch dozens of times a session."""
    cache_key = (name, kind, verified)
    icon = _avatar_icon_cache.get(cache_key)
    if icon is None:
        icon = QIcon(_avatar_pixmap(name, kind=kind, verified=verified))
        _avatar_icon_cache[cache_key] = icon
    return icon


def _format_file_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


def _random_image_filename(mime: str) -> str:
    """
    An unguessable, unique random filename for an outgoing IMAGE
    attachment - e.g. "a1b2c3d4e5f6a7b8.jpg" - never the sender's real
    filename.

    A photo's original filename routinely carries information that has
    nothing to do with the picture's actual content - a phone's default
    naming pattern, an embedded date, sometimes a person's name (e.g. a
    screenshot named after the window it captured) - none of which the
    sender necessarily means to share just by sending the picture. Random
    rather than a predictable counter (this app previously used
    "file"/"file2"/"file3", incrementing by one each time): a counted
    sequence is guessable/correlatable across a conversation (a recipient
    - or anyone who later sees several such names - can tell how many
    images were sent in total, and in what order, purely from the names
    themselves, and two different peoples' generic names could even
    collide if compared) in a way a long random token is not. Generated
    with `secrets.token_hex` (a CSPRNG, the same quality of randomness
    group_invite.py's own invite codes already use - see
    new_invite_code()), not any counter or timestamp - nothing about the
    resulting name is derived from or correlated with anything else this
    app sends.
    """
    ext = mimetypes.guess_extension(mime) or ".jpg"
    return f"{secrets.token_hex(16)}{ext}"


def _recompress_image_bytes(data: bytes) -> bytes | None:
    """
    Fully decode an image and re-encode it as a fresh JPEG, discarding
    everything about the original file except the decoded pixels.

    This is offered as the "compressed" choice when sending an image (see
    MainWindow._resolve_image_send_choice) as a real, if partial, mitigation
    against a booby-trapped image file: a file that merely *claims* to be a
    JPEG/PNG/etc. but is actually something else (an exploit targeting a
    different parser, a polyglot file, an embedded script, extra bytes
    appended after the real image data) will either fail this decode step
    outright, or - if it does decode - has none of that surrounding data
    survive the round trip, because only the decoded pixel grid is used to
    build the new file; nothing from the original byte stream is copied
    through. It also strips any embedded metadata (EXIF, GPS location,
    thumbnails, comments).

    Honest caveat, not overstated: this does not make receiving images from
    an untrusted contact perfectly safe - a flaw in the image *decoder*
    itself (Qt's, on the sending side; the recipient's own viewer, on the
    receiving side) is a different, deeper class of risk that recompression
    cannot fix, and Qt's QImage decoder is exactly what is used here, on
    both this app's own send path and (implicitly) whatever eventually
    displays the image. What it does concretely rule out is any of the
    *original file's raw bytes* - beyond the decoded picture itself -
    reaching the recipient at all.

    Returns None if the data could not be decoded as an image at all -
    the caller treats that as a signal worth surfacing to the user rather
    than silently sending the original bytes.
    """
    image = QImage()
    if not image.loadFromData(data):
        return None
    buffer = QBuffer()
    buffer.open(QBuffer.WriteOnly)
    # JPEG has no metadata/text-chunk fields of the kind PNG allows, and
    # re-encoding to it is a lossy full pixel round-trip - simple and
    # sufficient for this feature's purpose (a photo/image attachment),
    # not a general lossless-format-preserving converter.
    if not image.save(buffer, "JPEG", 85):
        return None
    return bytes(buffer.data())


def _attachment_html(msg, p) -> str:
    """
    HTML for a file/image attachment carried on a message (see
    Message.attachment_filename in vault.py and envelope.py's KIND_FILE).

    Deliberately NEVER renders an inline <img> preview, for an image or
    anything else - every attachment, image included, shows only a
    filename/size and a "Save As..." link, exactly like a generic file.
    The user has to explicitly choose to save (and then open) it before
    ever seeing its actual content, the same "download before you view
    it" model Telegram/Signal-style messengers use rather than
    auto-decoding and displaying arbitrary contact-supplied bytes the
    moment a message arrives. This is also a real, not just cosmetic,
    security narrowing: Qt's rich-text renderer is not a hardened image
    decoder, and an attacker-controlled image is exactly the kind of
    input a decoder vulnerability would be triggered by - not
    auto-decoding it removes that from the "happens automatically on
    receipt" path entirely, moving it behind a deliberate user action.
    The "Save As..." href is a stable `attach:<message id>` anchor that
    MainWindow._on_thread_link_clicked resolves back to the real Message
    to write out, rather than embedding the bytes in the href itself.
    """
    if not getattr(msg, "attachment_filename", ""):
        return ""

    filename = escape_html(msg.attachment_filename)
    size_text = _format_file_size(getattr(msg, "attachment_size", 0))
    # Translated first, into a plain local variable, rather than calling
    # i18n.tr() directly inside the f-string's {...} expression below:
    # pyside6-lupdate's Python string extraction does not reliably find a
    # single-quoted i18n.tr('...') call nested inside a double-quoted
    # f-string (verified empirically - it silently extracts nothing, so the
    # string would stay untranslated in every language forever with no
    # error anywhere). Computing it as a separate statement first sidesteps
    # that entirely, matching how every OTHER free-function translation in
    # this file that lupdate does pick up (e.g. render_bubble's `who =
    # i18n.tr("You") if ...`) is already written: never inside an f-string.
    save_as_text = i18n.tr("Save As…")
    save_link = (
        f"<a href='attach:{escape_html(msg.id)}' "
        f"style='color:{p.accent};text-decoration:none;'>{save_as_text}</a>"
    )

    # "Open" only shown once a saved copy actually exists at a path
    # that's still real right now - checked here, at render time, not
    # trusted from the stored path alone (the user could have moved/
    # renamed/deleted it since saving - see Message.saved_path's
    # docstring). Shown alongside "Save As...", not instead of it - saving
    # a second copy elsewhere is still a normal thing to want even after
    # already saving once.
    open_link = ""
    saved_path = getattr(msg, "saved_path", "")
    if saved_path and os.path.isfile(saved_path):
        open_text = i18n.tr("Open")
        open_link = (
            f"<a href='open:{escape_html(msg.id)}' "
            f"style='color:{p.accent};text-decoration:none;'>{open_text}</a> &middot; "
        )

    # A real image (icons/ui/attach.png), not the U+1F4CE paperclip emoji
    # this used to be - see the attach_button's own comment in
    # _build_conversation_panel for why: font-glyph-fallback unreliability
    # for that specific codepoint, verified empirically elsewhere in this
    # file, plus pyside6-lupdate corrupting non-BMP characters extracted
    # from Python source.
    paperclip = _ui_icon_html("attach.png", None, 14)
    return (
        f"<div style='margin-top:4px;padding:6px;border:1px solid {p.border};"
        f"border-radius:6px;'>"
        f"<div style='color:{p.text};font-size:12px;'>{paperclip} {filename}</div>"
        f"<div style='color:{p.text_muted};font-size:11px;'>{size_text} &middot; {open_link}{save_link}</div>"
        f"</div>"
    )


def render_bubble(msg, contact_name: str, p, note_override: str | None = None) -> str:
    """
    Build the HTML for one message bubble.

    Kept as a standalone function so the colour pairing can be asserted
    directly in tests. Qt's toHtml() does not round-trip table styles, so
    inspecting the widget afterwards cannot prove the text colour was set -
    but that pairing is exactly what stops messages being invisible on a dark
    desktop, so it has to be verifiable.

    `contact_name` is who to attribute an *incoming* message to - for a 1:1
    thread that's always the same contact, but a group thread passes the
    actual sender's name per-message (see MainWindow._render_conversation),
    so this function does not need its own notion of "which conversation".

    `note_override`, when given, replaces the normal delivered/queued note
    entirely. Used for a collapsed group-outgoing bubble, whose delivery
    state is an aggregate across several per-member sends rather than the
    single status field an ordinary Message carries.
    """
    outgoing = msg.direction == "out"
    who = i18n.tr("You") if outgoing else escape_html(contact_name)

    # Background and text colour are always chosen together, never inherited.
    background = p.bubble_out_bg if outgoing else p.bubble_in_bg
    foreground = p.bubble_out_text if outgoing else p.bubble_in_text

    deleted = bool(getattr(msg, "deleted", False))
    is_attachment = bool(getattr(msg, "attachment_filename", ""))
    if deleted:
        # Tombstone: content is gone (vault.Vault.mark_deleted() already
        # scrubbed body/attachment_* - this is just how it's displayed),
        # but the bubble stays in place so the thread still shows that a
        # message was here rather than a silent gap or reordering.
        #
        # Translated into a local variable first, not inline inside the
        # f-string below - see _attachment_html's save_as_text comment for
        # why: pyside6-lupdate does not extract a single-quoted i18n.tr(...)
        # call nested inside an f-string's {...} expression.
        deleted_text = i18n.tr("This message was deleted")
        body = (
            f"<span style='color:{p.text_muted};font-style:italic;'>"
            f"{deleted_text}</span>"
        )
    elif is_attachment:
        body = _attachment_html(msg, p)
    else:
        body = escape_html(msg.body).replace("\n", "<br>")

    # This mapping is deliberately built from data the app already tracks
    # honestly (Message.status/.delivered/.attempts, set only when
    # transport.send_message got a real cryptographic acknowledgment from
    # the recipient - see transport.py/DeliveryWorker). "Delivered" is
    # only ever shown for a message that actually went through that path -
    # never merely because the local app accepted the send.
    note = ""
    status = getattr(msg, "status", "sent")
    if note_override is not None:
        note = note_override
    elif outgoing:
        if status == "queued":
            attempts = getattr(msg, "attempts", 0)
            text = i18n.tr("Waiting for user…") if attempts > 1 else i18n.tr("User offline - message queued")
            note = f"<div style='color:{p.warn};font-size:11px;'>{text}</div>"
        elif not msg.delivered:
            waiting_text = i18n.tr("Waiting…")  # see save_as_text's comment above on why this is not inline
            note = f"<div style='color:{p.error};font-size:11px;'>{waiting_text}</div>"
        else:
            delivered_text = i18n.tr("Delivered")
            note = f"<div style='color:{p.text_muted};font-size:11px;'>{delivered_text}</div>"

    # Qt's rich text engine ignores display:inline-block, so a plain div
    # stretches the full width and stops looking like a bubble. Nested tables
    # are part of the subset Qt does support, and give a bubble that hugs its
    # text and sits on the correct side.
    # border-radius on a table/cell is outside Qt rich text's officially
    # documented CSS subset, but it degrades harmlessly where unsupported
    # (square corners, same as before) rather than breaking anything -
    # worth trying for the rounder, more chat-bubble look most messengers
    # use, without risking the layout on interpreters where it's ignored.
    bubble = (
        f"<table cellpadding='9' cellspacing='0' "
        f"style='background-color:{background};border-radius:14px;'>"
        f"<tr><td style='color:{foreground};border-radius:14px;'>{body}</td></tr></table>"
    )

    meta = (
        f"<div style='color:{p.text_muted};font-size:11px;'>"
        f"{who} &middot; {format_timestamp(msg.timestamp)}</div>"
    )

    # Qt's rich-text engine does not auto-mirror raw HTML align='left'/
    # 'right' attributes the way widget layouts auto-mirror under
    # setLayoutDirection(RightToLeft) - so the physical side has to be
    # chosen here explicitly. An outgoing message must always sit on the
    # *trailing* edge (right in LTR, left in RTL) so "my messages on my
    # side" still holds regardless of language direction.
    is_rtl = QApplication.layoutDirection() == Qt.RightToLeft
    trailing, leading = ("left", "right") if is_rtl else ("right", "left")

    if outgoing:
        cells = (
            "<td width='25%'></td>"
            f"<td width='75%' align='{trailing}'>{meta}{bubble}{note}</td>"
        )
    else:
        cells = (
            f"<td width='75%' align='{leading}'>{meta}{bubble}{note}</td>"
            "<td width='25%'></td>"
        )

    # Every row is wrapped in an invisible "msg:<id>" anchor (styled to
    # never look like a link - no color/underline override) purely so
    # MainWindow._on_thread_context_menu can resolve a right-click
    # position back to which Message it landed on, via QTextBrowser's own
    # anchorAt(pos) - the same mechanism already used for left-clicks on
    # the real "attach:<id>" link, just covering the whole bubble instead
    # of one small piece of text inside it.
    dir_attr = "rtl" if is_rtl else "ltr"
    return (
        f"<a href='msg:{escape_html(msg.id)}' style='text-decoration:none;color:inherit;'>"
        f"<table width='100%' cellpadding='0' cellspacing='0' dir='{dir_attr}' "
        f"style='margin-bottom:10px;'><tr>{cells}</tr></table>"
        f"</a>"
    )


def _wrappable_text(text: str, chunk: int = 8) -> str:
    """
    Insert zero-width space break points every `chunk` characters into a
    single unbroken token (a crypto address, a key - anything with no
    spaces at all).

    QLabel's word wrap only breaks at existing word boundaries; a string
    with no whitespace anywhere is treated as one unbreakable word and
    simply overflows its container instead of wrapping, regardless of
    setWordWrap(True) or any size policy. A zero-width space (U+200B) is
    invisible and copies/selects as nothing extra, but gives the text
    layout real places to break - safe to use here because these labels
    are for on-screen display only; the actual value users copy comes from
    the *original* string via the Copy button, not by selecting this label's
    text, so no invisible characters ever leak into a pasted value.
    """
    if " " in text or len(text) <= chunk:
        return text
    return "​".join(text[i:i + chunk] for i in range(0, len(text), chunk))


def _wrapping_label(text: str) -> QLabel:
    """
    A QLabel that actually wraps to fit its container's width, rather than
    reporting its unwrapped text width as its size hint (QLabel's default
    behavior, which - inside a layout that doesn't otherwise clamp it, such
    as a QScrollArea's content widget - forces the whole container wider
    instead of letting the text wrap). setWordWrap(True) alone is not
    enough: the size policy also needs Ignored horizontally (so the label
    doesn't dictate the container's width) AND heightForWidth enabled (so
    the layout recomputes the label's height from its *wrapped* width,
    otherwise a long single-line label gets word-wrapped visually but is
    still allocated only one line's worth of vertical space, clipping the
    rest) AND, for text with no spaces at all (an address/key), explicit
    break points via _wrappable_text - see that function's docstring.
    """
    label = QLabel(_wrappable_text(text))
    label.setWordWrap(True)
    policy = QSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
    policy.setHeightForWidth(True)
    label.setSizePolicy(policy)
    return label


class AboutDialog(QDialog):
    """Version, licence, links, and what the app does."""

    def __init__(self, palette, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(i18n.fmt(self.tr("About %(name)s"), name=version.APP_NAME))
        self.resize(440, 620)
        self.setMinimumSize(360, 320)
        self.setSizeGripEnabled(True)

        outer = QVBoxLayout(self)

        # Scrollable content area - the dialog is freely resizable (down to
        # setMinimumSize above), and at a small height the description +
        # illustration + links + support section would otherwise get cut
        # off with no way to reach the Close button. Everything above the
        # footer scrolls; the footer (credit + Close) always stays visible.
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        # Only ever scrolls vertically - content should always wrap to fit
        # the dialog's width, never spill sideways. Combined with the
        # Ignored size policy on the long text/address labels below, this
        # is what actually enforces that (setWidgetResizable alone is not
        # enough when a child label's sizeHint reports its unwrapped width).
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        content = QWidget()
        layout = QVBoxLayout(content)

        # --- Identity: one icon, one title, one version line -------------
        icon_path = icon_file()
        if icon_path:
            image = QLabel()
            image.setPixmap(QIcon(icon_path).pixmap(72, 72))
            image.setAlignment(Qt.AlignCenter)
            layout.addWidget(image)

        title = QLabel(version.APP_NAME)
        title.setObjectName("heading")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel(
            i18n.fmt(
                self.tr("%(version)s - open source (%(license)s)"),
                version=version.version_string(),
                license=version.LICENSE,
            )
        )
        subtitle.setObjectName("muted")
        subtitle.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle)

        description = _wrapping_label(
            i18n.fmt(self.tr("%(tagline)s."), tagline=version.APP_TAGLINE)
            + "\n\n"
            + self.tr(
                "No servers, no accounts, no phone numbers. Your public key and "
                "fingerprint are your whole identity. Messages are end-to-end "
                "encrypted, and every connection is routed anonymously through "
                "the Tor network, so no one - not even Veilwire - can see who "
                "you're talking to."
            )
            + "\n\n"
            + self.tr(
                "This is not audited software. If your safety depends on it, use "
                "Ricochet Refresh or Cwtch instead."
            )
        )
        description.setObjectName("muted")
        layout.addWidget(description)

        # --- Supporting illustration: separate section, own space --------
        network_pixmap = _load_brand_pixmap("veilwire-network.png", max_size=120)
        if network_pixmap is not None:
            network_label = QLabel()
            network_label.setPixmap(network_pixmap)
            network_label.setAlignment(Qt.AlignCenter)
            layout.addWidget(network_label)

        # --- Project links -------------------------------------------------
        links_title = QLabel(self.tr("Project"))
        bold = QFont()
        bold.setBold(True)
        links_title.setFont(bold)
        layout.addWidget(links_title)

        repo_link = QLabel(f"<a href='{version.REPOSITORY}'>{version.REPOSITORY}</a>")
        repo_link.setOpenExternalLinks(True)
        repo_link.setTextInteractionFlags(Qt.TextBrowserInteraction)
        layout.addWidget(repo_link)

        # --- Support the project: optional, clearly separate from identity ---
        support_title = QLabel(self.tr("Support the project"))
        support_title.setFont(bold)
        layout.addWidget(support_title)

        support_hint = QLabel(
            self.tr(
                "Veilwire is free and has no accounts, ads, or paid tiers. If "
                "you'd like to support development, you can send Monero (XMR) "
                "to the address below. This is entirely optional and unrelated "
                "to your identity or security in the app."
            )
        )
        support_hint.setWordWrap(True)
        support_hint.setObjectName("muted")
        layout.addWidget(support_hint)

        xmr_font = QFont("monospace")
        xmr_font.setPointSize(10)
        # A QLabel, not a QLineEdit: a single-line edit box cannot wrap
        # text, which is exactly why a long address looked "extended"/cut
        # off before - it just scrolled horizontally inside a fixed-width
        # field instead of wrapping onto a second line like normal text.
        # See _wrapping_label's docstring for why setWordWrap(True) alone
        # is not sufficient to make that actually happen.
        xmr_label = _wrapping_label(version.XMR_DONATION_ADDRESS)
        xmr_label.setFont(xmr_font)
        xmr_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(xmr_label)

        copy_xmr = QPushButton(self.tr("Copy"))
        copy_xmr.setToolTip(self.tr("Copy the Monero address"))
        copy_xmr.setMaximumWidth(90)
        copy_xmr.clicked.connect(self._copy_xmr_address)
        # Qt.AlignLeading (not Qt.AlignLeft) so this auto-flips to the
        # trailing edge under RTL instead of staying pinned to the
        # physical left when the rest of the dialog mirrors under Arabic.
        layout.addWidget(copy_xmr, alignment=Qt.AlignLeading)

        # --- Verify our identity: public key + fingerprint only ------------
        # Deliberately NOT a "contact us" flow - a bare public key/fingerprint
        # is not enough on its own to add as a contact in this app (Add
        # Contact needs a full bundle or onion+public key pair, since the
        # onion is never shown here, matching the app's own rule everywhere
        # else). This section exists so anyone who already has our contact
        # bundle from elsewhere can verify it matches this project's real
        # identity - not a working "add us" shortcut. Regular users still
        # contact each other entirely through their own Share Contact / Add
        # Contact flow, unrelated to this section.
        identity_title = QLabel(self.tr("Verify our identity"))
        identity_title.setFont(bold)
        layout.addWidget(identity_title)

        identity_hint = QLabel(
            self.tr(
                "If you already have our contact bundle from elsewhere, you can "
                "confirm it's genuinely ours by checking it matches this public "
                "key and fingerprint."
            )
        )
        identity_hint.setWordWrap(True)
        identity_hint.setObjectName("muted")
        layout.addWidget(identity_hint)

        pubkey_label = _wrapping_label(version.CONTACT_PUBLIC_KEY)
        pubkey_label.setFont(xmr_font)
        pubkey_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(pubkey_label)

        fp_font = QFont("monospace")
        fp_font.setBold(True)
        fp_font.setPointSize(11)
        fingerprint_label = QLabel(version.CONTACT_FINGERPRINT)
        fingerprint_label.setFont(fp_font)
        fingerprint_label.setWordWrap(True)
        fingerprint_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(fingerprint_label)

        copy_pubkey = QPushButton(self.tr("Copy"))
        copy_pubkey.setToolTip(self.tr("Copy the public key"))
        copy_pubkey.setMaximumWidth(90)
        copy_pubkey.clicked.connect(self._copy_contact_pubkey)
        layout.addWidget(copy_pubkey, alignment=Qt.AlignLeading)

        scroll.setWidget(content)
        outer.addWidget(scroll, stretch=1)

        # Footer stays outside the scroll area - always visible regardless
        # of dialog height, left-aligned credit alongside the Close button.
        footer_row = QHBoxLayout()
        team_label = QLabel(self.tr("Developed by Freedom Team"))
        team_label.setObjectName("muted")
        team_label.setToolTip(self.tr("Anonymous"))
        team_label.setCursor(Qt.WhatsThisCursor)
        footer_row.addWidget(team_label, alignment=Qt.AlignLeading)
        footer_row.addStretch(1)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        footer_row.addWidget(buttons)
        outer.addLayout(footer_row)

    def _copy_xmr_address(self) -> None:
        QGuiApplication.clipboard().setText(version.XMR_DONATION_ADDRESS)
        QMessageBox.information(self, self.tr("Copied"), self.tr("Monero address copied."))

    def _copy_contact_pubkey(self) -> None:
        QGuiApplication.clipboard().setText(version.CONTACT_PUBLIC_KEY)
        QMessageBox.information(self, self.tr("Copied"), self.tr("Public key copied."))


def icon_file() -> str | None:
    """
    Locate the application icon.

    Checked in order: next to this script (a source checkout, or an
    installed copy under /usr/lib/veilwire where this file's own directory
    IS the installed location - os.path.dirname(__file__) resolves
    correctly either way, no packaging-specific branch needed for that
    case) first, then the standard installed-icon-theme location a .deb/
    .rpm/Arch package puts icons in. First match wins; this list only
    needs a second entry for the rare case those two locations differ.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base_dir, "icons", "veilwire.png"),
        os.path.join(base_dir, "icons", "veilwire-256.png"),
        os.path.join(base_dir, "icons", "veilwire-128.png"),
        "/usr/share/icons/hicolor/256x256/apps/veilwire.png",
        "/usr/share/icons/hicolor/128x128/apps/veilwire.png",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


def brand_image_path(filename: str) -> str | None:
    """
    Locate one of the four independent Veilwire brand illustrations
    (veilwire-chat.png / veilwire-shield.png / veilwire-send.png /
    veilwire-network.png) under icons/brand/. Returns None if not found,
    so every call site can degrade gracefully (skip the image) rather than
    crash - these are decorative, never load-bearing UI.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(base_dir, "icons", "brand", filename)
    return path if os.path.exists(path) else None


def ui_icon_path(filename: str) -> str | None:
    """
    Locate a small functional UI icon (verified badge, person/group
    avatar glyph) under icons/ui/ - separate from icons/brand/'s
    decorative illustrations, since these are load-bearing (used to mean
    something specific: "this contact is verified", "this row is a
    group") rather than purely cosmetic. Returns None if not found so
    call sites can fall back to plain text, matching brand_image_path's
    graceful-degradation convention.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(base_dir, "icons", "ui", filename)
    return path if os.path.exists(path) else None


_ui_icon_cache: dict[tuple[str, str | None, int], QIcon] = {}


def ui_icon(filename: str, color: str | None, size: int = 16) -> QIcon | None:
    """
    Load one of icons/ui/'s PNGs, scaled to `size`x`size`, as a QIcon -
    used for the verified badge and the person/group row glyphs.

    PNG, not SVG: an SVG version of these icons was tried first and
    dropped - QSvgRenderer needs the optional PySide6.QtSvg module, which
    is not guaranteed present in every environment this app runs in
    (verified empirically: missing entirely from at least one real
    install here), so a missing-module failure silently blanked every
    glyph down to just the plain coloured circle behind it, with no error
    surfaced anywhere. A PNG has no such optional-module dependency.

    `color`, when given, recolors every opaque pixel to that flat colour
    while preserving each pixel's own alpha - appropriate for a
    single-colour glyph like person.png, which needs to show up in white
    against a coloured avatar circle regardless of what colour it was
    drawn in. `color=None` loads the PNG's own original pixels unchanged -
    used for group.png and verified.png, which are already the intended
    final colour (a multi-tone illustration and the brand's own blue,
    respectively) and would lose their real appearance if flattened to
    one colour.

    Cached per (filename, color, size) since the sidebar rebuilds its
    rows (and therefore would otherwise re-render the same icon) every
    time contacts/groups reload.
    """
    cache_key = (filename, color, size)
    cached = _ui_icon_cache.get(cache_key)
    if cached is not None:
        return cached

    path = ui_icon_path(filename)
    if path is None:
        return None

    source = QPixmap(path)
    if source.isNull():
        return None
    source = source.scaled(
        size, size, Qt.KeepAspectRatio, Qt.SmoothTransformation
    )

    if color is not None:
        recolored = QPixmap(source.size())
        recolored.fill(Qt.transparent)
        painter = QPainter(recolored)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.drawPixmap(0, 0, source)
        # SourceIn keeps the destination's existing alpha (the glyph's own
        # silhouette, just painted) and replaces its colour - the
        # standard "recolor a solid glyph while keeping its transparency"
        # QPainter composition trick, avoiding a slower per-pixel loop.
        painter.setCompositionMode(QPainter.CompositionMode_SourceIn)
        painter.fillRect(recolored.rect(), QColor(color))
        painter.end()
        pixmap = recolored
    else:
        pixmap = source

    icon = QIcon(pixmap)
    _ui_icon_cache[cache_key] = icon
    return icon


def _load_brand_pixmap(filename: str, max_size: int) -> QPixmap | None:
    """
    Load one of the brand illustrations, scaled to fit within a
    max_size x max_size box.

    Qt.KeepAspectRatio preserves the source aspect ratio (these are not
    square images) and Qt.SmoothTransformation preserves the alpha channel
    correctly during scaling - no manual alpha handling needed, and no
    background is ever composited in: the images are used exactly as
    provided, transparent areas stay transparent.
    """
    path = brand_image_path(filename)
    if path is None:
        return None
    pixmap = QPixmap(path)
    if pixmap.isNull():
        return None
    return pixmap.scaled(
        max_size, max_size, Qt.KeepAspectRatio, Qt.SmoothTransformation
    )


def _ui_icon_html(filename: str, color: str | None, size: int) -> str:
    """
    An inline <img> tag embedding one of icons/ui/'s PNGs as a base64
    data: URI, for use inside QTextBrowser/QLabel rich text - the only
    way to place a real image inline in Qt rich text, as opposed to a
    QIcon on an actual QPushButton/QListWidgetItem widget. Returns "" if
    the icon can't be loaded, so a missing asset never breaks the
    surrounding HTML.
    """
    icon = ui_icon(filename, color, size)
    if icon is None:
        return ""
    pixmap = icon.pixmap(size, size)
    byte_array = QByteArray()
    buf = QBuffer(byte_array)
    buf.open(QBuffer.WriteOnly)
    pixmap.save(buf, "PNG")
    buf.close()
    b64 = bytes(byte_array.toBase64()).decode("ascii")
    return f"<img src='data:image/png;base64,{b64}' width='{size}' height='{size}'>"


def _verified_badge_html(size: int = 14) -> str:
    """
    An inline <img> tag for the verified checkmark (icons/ui/verified.png),
    for use inside a QLabel's auto-detected rich text (the conversation
    header) - the sidebar's QListWidgetItem text has no rich-text/inline-
    image support (plain QListWidget item text), so that surface instead
    composites the same badge onto the corner of the avatar icon itself
    (see _avatar_pixmap's caller in _reload_contacts) - two different
    techniques for the same visual, chosen per what each specific widget
    actually supports, not a stylistic inconsistency.
    """
    return _ui_icon_html("verified.png", None, size)


def _brand_image_html(filename: str, max_size: int) -> str:
    """
    An <img> tag embedding a brand illustration as a data: URI, for use
    inside QTextBrowser HTML (the conversation panel is rich text, not a
    layout of separate widgets, so images placed there go through HTML
    rather than a QLabel/QPixmap). Returns "" if the asset isn't found, so
    a missing decorative image never breaks the surrounding layout.
    """
    pixmap = _load_brand_pixmap(filename, max_size)
    if pixmap is None:
        return ""
    byte_array = QByteArray()
    buf = QBuffer(byte_array)
    buf.open(QBuffer.WriteOnly)
    pixmap.save(buf, "PNG")
    buf.close()
    b64 = bytes(byte_array.toBase64()).decode("ascii")
    return f"<p><img src='data:image/png;base64,{b64}'></p>"


def main() -> None:
    app = QApplication(sys.argv)

    # Force Qt's built-in "Fusion" style rather than inheriting whatever
    # native style plugin the current desktop provides (Breeze on KDE,
    # Kvantum, Adwaita-Qt on GNOME via qt5ct/qt6ct, etc.). Those native
    # styles each apply their own padding/margins/hover behavior to
    # standard widgets (QListWidget::item, QMenuBar, QPushButton...) on
    # top of - and sometimes in place of - anything set in theme.py's
    # stylesheet, which is how the exact same UI can look meaningfully
    # different (or visibly broken: oversized list rows, doubled-up
    # selection highlighting) across desktops despite identical code and
    # an identical stylesheet. Fusion is always available (built into Qt
    # itself, no external plugin/package needed) and applies no desktop-
    # specific chrome of its own, so theme.py's stylesheet is the only
    # thing controlling appearance - identical look on every Linux
    # desktop environment (KDE, GNOME, XFCE; Kali, Fedora, Arch, ...).
    # Must run before any QWidget is constructed, same requirement as the
    # language installer below.
    #
    # theme.detect_palette() (called further down) works by inspecting
    # app.palette()'s actual Window colour to decide light vs. dark - that
    # colour is normally supplied by the desktop's native style (Breeze
    # reads Plasma's colour scheme, Adwaita-Qt reads GNOME's, etc.).
    # Fusion does NOT read the desktop theme the same way and may reset
    # the palette to its own light-grey default the moment setStyle()
    # runs - captured here BEFORE switching, and explicitly restored
    # after, so "which style draws the widgets" and "which colours
    # detect_palette sees" stay independent: switching style can never
    # silently break dark-mode detection.
    original_palette = app.palette()
    app.setStyle("Fusion")
    app.setPalette(original_palette)

    app.setApplicationName(version.APP_NAME)
    app.setApplicationDisplayName(version.APP_NAME)
    app.setApplicationVersion(version.__version__)
    app.setDesktopFileName(version.APP_NAME)

    # Must run before any QWidget is constructed: QWidget reads the
    # application's layout direction at construction time, and a
    # translator installed later would miss every string already built
    # into an existing widget.
    i18n.install_language(app, i18n.current_language())

    icon_path = icon_file()
    if icon_path:
        app.setWindowIcon(QIcon(icon_path))

    # Match the desktop's light/dark setting so text is never invisible.
    palette = theme.detect_palette(app)
    app.setStyleSheet(theme.stylesheet(palette))

    store = vault_mod.Vault()
    is_new = not store.exists()

    while True:
        dialog = UnlockDialog(is_new=is_new)
        if icon_path:
            dialog.setWindowIcon(QIcon(icon_path))
        if dialog.exec() != QDialog.Accepted:
            return

        try:
            if is_new:
                store.create(dialog.passphrase)
            else:
                store.unlock(dialog.passphrase)
            break
        except crypto.DecryptionError:
            QMessageBox.warning(
                None, i18n.tr("Wrong passphrase"), i18n.tr("That passphrase did not work.")
            )
        except (ValueError, OSError) as exc:
            _logger.exception("Could not open vault")
            QMessageBox.critical(
                None,
                i18n.tr("Could not open vault"),
                safe_error_text(
                    exc,
                    i18n.tr("Could not open the vault file. It may be missing, corrupted, or unreadable."),
                ),
            )
            return

    try:
        window = MainWindow(store)
    except vault_mod.VaultLocked:
        # Defensive: by this point store.create()/unlock() has already
        # succeeded in the loop above, so the vault should always be
        # unlocked here. This exists only to turn a violation of that
        # invariant into a clean dialog instead of an unhandled traceback
        # if a future code path ever reaches MainWindow() without it.
        _logger.exception("Vault was unexpectedly locked at startup")
        QMessageBox.critical(
            None,
            i18n.tr("Could not start"),
            i18n.tr("The vault was unexpectedly locked. Please restart the app."),
        )
        return
    if icon_path:
        window.setWindowIcon(QIcon(icon_path))
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()

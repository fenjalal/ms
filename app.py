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
import sys
import threading
import uuid
from datetime import datetime

import segno
from PySide6.QtCore import QBuffer, QByteArray, QSize, Qt, QThread, QUrl, Signal
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
        form.addRow(self.tr("Public key"), self.pubkey_field)

        fingerprint_font = QFont("monospace")
        fingerprint_font.setBold(True)
        fingerprint_font.setPointSize(12)
        self.fingerprint_field = QLineEdit(identity.fingerprint)
        self.fingerprint_field.setReadOnly(True)
        self.fingerprint_field.setFont(fingerprint_font)
        self.fingerprint_field.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.fingerprint_field.setMinimumWidth(0)
        self.fingerprint_field.setCursorPosition(0)
        form.addRow(self.tr("Fingerprint"), self.fingerprint_field)

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

        copy_row = QHBoxLayout()
        copy_key = QPushButton(self.tr("Copy public key"))
        copy_key.clicked.connect(
            lambda: self._copy(identity.public_key, self.tr("Public key copied."))
        )
        copy_row.addWidget(copy_key)

        copy_fp = QPushButton(self.tr("Copy fingerprint"))
        copy_fp.clicked.connect(
            lambda: self._copy(identity.fingerprint, self.tr("Fingerprint copied."))
        )
        copy_row.addWidget(copy_fp)
        layout.addLayout(copy_row)

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
        layout.addWidget(self.member_list, stretch=1)

        self.error_label = QLabel("")
        self.error_label.setObjectName("danger-text")
        self.error_label.setWordWrap(True)
        layout.addWidget(self.error_label)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

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
    def _build_ui(self) -> None:
        central = QWidget(self)
        self.setCentralWidget(central)

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
        # 290, not 240: three QPushButtons ("Share"/"Keys"/"Settings",
        # already shortened to their minimum practical labels - see the
        # button_row comment below) need ~274px on their own even at
        # Qt's default per-button padding, before the panel's own left/
        # right margins (12 + 6) are added - 240 clipped "Settings" to
        # "etting" at the sidebar's documented minimum width. Verified
        # empirically (QWidget.sizeHint() on the real button row), not
        # just estimated, before picking this number.
        panel.setMinimumWidth(290)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(12, 12, 6, 12)
        layout.setSpacing(8)

        title = QLabel(self.tr("You"))
        bold = QFont()
        bold.setBold(True)
        title.setFont(bold)
        layout.addWidget(title)

        # No raw onion address shown here - it is an internal transport
        # detail, not a normal user-facing identity field, and no mention
        # of Tor by name either - just a plain security/readiness state.
        # The fingerprint below is what a contact actually verifies you by.
        self.my_status_label = QLabel()
        layout.addWidget(self.my_status_label)

        # Short labels (the full description lives in each button's
        # tooltip) so all three comfortably fit the sidebar's width without
        # clipping - "Share Contact...", "Keys...", "Settings..." routinely
        # overflowed a narrow sidebar and got visually truncated.
        button_row = QHBoxLayout()
        self.share_button = QPushButton(self.tr("Share"))
        self.share_button.setToolTip(
            self.tr(
                "Share Contact: QR code and copyable bundle a contact can scan or "
                "paste to add you - never your onion address in the clear."
            )
        )
        self.share_button.clicked.connect(self._on_share_contact)
        button_row.addWidget(self.share_button)

        identity_button = QPushButton(self.tr("Keys"))
        identity_button.setToolTip(self.tr("Fingerprint, backup, and identity"))
        identity_button.clicked.connect(self._on_identity)
        button_row.addWidget(identity_button)

        settings_button = QPushButton(self.tr("Settings"))
        settings_button.setToolTip(self.tr("Language and who can reach you"))
        settings_button.clicked.connect(self._on_settings)
        button_row.addWidget(settings_button)
        layout.addLayout(button_row)

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
        layout.addWidget(self.fingerprint_label)

        contacts_title = QLabel(self.tr("Contacts"))
        contacts_title.setFont(bold)
        layout.addWidget(contacts_title)

        self.contact_list = QListWidget()
        self.contact_list.setIconSize(QSize(36, 36))
        self.contact_list.currentItemChanged.connect(self._on_contact_selected)
        self.contact_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.contact_list.customContextMenuRequested.connect(self._on_contact_menu)
        layout.addWidget(self.contact_list, stretch=1)

        # Two rows, not one - four buttons ("Add"/"New Group"/"Join Group"/
        # "Remove") in a single QHBoxLayout at the sidebar's default width
        # (340px, 240px minimum - see the splitter setup) clipped the
        # later buttons' text under several languages, most visibly
        # "Join Group"/"New Group" together. Splitting into contact
        # actions (Add/Remove) and group actions (New/Join) keeps each
        # row to two buttons, which fits comfortably down to the sidebar's
        # actual minimum width instead of only at a wide window size.
        contact_row = QHBoxLayout()
        add_button = QPushButton(self.tr("Add"))
        add_button.clicked.connect(self._on_add_contact)
        contact_row.addWidget(add_button)

        remove_button = QPushButton(self.tr("Remove"))
        remove_button.clicked.connect(self._on_remove_contact)
        contact_row.addWidget(remove_button)
        layout.addLayout(contact_row)

        group_row = QHBoxLayout()
        new_group_button = QPushButton(self.tr("New Group"))
        new_group_button.clicked.connect(self._on_new_group)
        group_row.addWidget(new_group_button)

        join_group_button = QPushButton(self.tr("Join Group"))
        join_group_button.setToolTip(
            self.tr("Paste an invite someone sent you to join their group.")
        )
        join_group_button.clicked.connect(self._on_join_group)
        group_row.addWidget(join_group_button)
        layout.addLayout(group_row)

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
        # _refresh_identity_display - pyside6-lupdate corrupts non-BMP
        # (astral-plane) characters like this paperclip when extracting
        # from Python source (U+1F4CE gets truncated to U+F4CE, a private-
        # use codepoint, in the generated .ts), and a glyph needs no
        # per-language translation anyway.
        self.attach_button = QPushButton("\U0001F4CE")
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

    # -- Contacts ----------------------------------------------------------- #
    def _reload_contacts(self, select_id: str | None = None) -> None:
        self.contact_list.blockSignals(True)
        self.contact_list.clear()

        # One combined, recency-sorted list of contacts and groups, like an
        # ordinary messenger's conversation list - built as (sort_key, kind,
        # id, label, tooltip) tuples first so the two kinds can be merged
        # and sorted together rather than shown as two separate blocks.
        rows: list[tuple[str, str, str, str, str]] = []

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
                marker = "\u2713 " if contact.verified else ""
                # Presence: filled dot online, hollow offline, nothing if unknown.
                online = self.delivery.is_online(contact.id) if self.delivery else None
                presence = "" if online is None else ("\u25cf " if online else "\u25cb ")
                queued = sum(
                    1 for m in direct_messages
                    if m.direction == "out" and m.status == vault_mod.QUEUED
                )
                suffix = self.tr("  (%(count)s)") % {"count": count} if count else ""
                if queued:
                    suffix += self.tr("  [%(queued)s queued]") % {"queued": queued}
                label = f"{presence}{marker}{contact.name}{suffix}"

            rows.append((contact.last_activity, _KIND_CONTACT, contact.id, label, tooltip, contact.name))

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
                self.tr("Group of %(members)s") % {"members": member_count}, group.name,
            ))

        rows.sort(key=lambda r: r[0], reverse=True)

        for _sort_key, kind, item_id, label, tooltip, avatar_name in rows:
            item = QListWidgetItem(_avatar_icon(avatar_name), label)
            item.setData(Qt.UserRole, item_id)
            item.setData(_ITEM_KIND_ROLE, kind)
            if tooltip:
                item.setToolTip(tooltip)
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
        self.share_button.setEnabled(published)
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

        verified_mark = self.tr(" \u2713 verified") if contact.verified else ""
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
        self.conversation_avatar.setPixmap(_avatar_pixmap(contact.name, 34))
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
        self.conversation_avatar.setPixmap(_avatar_pixmap(group.name, 34))
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
        Handles a click on a link inside a message bubble - either
        "attach:<id>" (Save As..., see _attachment_html) or "delmsg:<id>"
        (Delete, see render_bubble) - the only two kinds of link the thread
        view ever contains (setOpenLinks(False) above stops Qt from doing
        anything with either on its own).
        """
        href = url.toString()
        if href.startswith("delmsg:"):
            message_id = href[len("delmsg:"):]
            msg = self._rendered_messages.get(message_id)
            if msg is not None:
                self._on_delete_message(msg)
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

        def build_body(invcode: str) -> str:
            if is_file:
                return envelope.encode_file(
                    os.path.basename(file_path), file_mime, file_data,
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
            per_member_bodies[member_id] = (
                envelope.encode_file(
                    os.path.basename(file_path), file_mime, file_data,
                    gid=group.id, gname=group.name, mid=client_msg_id, invcode=personal_code,
                ) if is_file else
                envelope.encode_text(
                    text_body, gid=group.id, gname=group.name,
                    mid=client_msg_id, invcode=personal_code,
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
            original_mime = mime
            data, mime = self._resolve_image_send_choice(data, mime)
            if data is None:
                return  # user cancelled
            if mime != original_mime:
                # Recompressed to JPEG - rename so the extension the
                # recipient sees actually matches the bytes being sent,
                # rather than e.g. still claiming ".png" for JPEG content.
                base, _ext = os.path.splitext(os.path.basename(path))
                path = f"{base}.jpg"

        if target_group is not None:
            self._start_group_send(target_group, file_path=path, file_data=data, file_mime=mime)
        elif target_contact is not None:
            self._start_contact_file_send(target_contact, path, data, mime)

    def _resolve_image_send_choice(
        self, data: bytes, mime: str
    ) -> tuple[bytes | None, str]:
        """
        Ask the user whether to send an image attachment as-is or
        re-encoded (see _recompress_image_bytes) before it goes out.

        Framed for the user as a security choice, not a quality/size one:
        a file that is merely disguised as an image (or an image file with
        something extra appended or embedded in it) is a real way to smuggle
        an unwanted payload to a contact, and re-encoding strips all of that
        - at the cost of re-compressing the picture itself and stripping its
        metadata (including anything like embedded location data, which some
        people want gone anyway). Sending the original stays available for
        when fidelity matters and the file is trusted (e.g. a photo the user
        just took themselves).

        Returns (None, "") if the user cancelled the send entirely - the
        caller must treat that as "do not send anything". Returns the
        original (data, mime) unchanged if the user chose "Send Original",
        or (recompressed bytes, "image/jpeg") if they chose "Send
        Compressed".
        """
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Question)
        box.setWindowTitle(self.tr("Send image"))
        box.setText(
            self.tr(
                "Send this image as-is, or re-encoded first?\n\n"
                "Re-encoding fully decodes the image and rebuilds it from "
                "scratch, discarding anything hidden in the original file "
                "(and its metadata, such as location data) - recommended "
                "unless you need the exact original file, e.g. for quality "
                "or provenance."
            )
        )
        compressed_button = box.addButton(self.tr("Send Compressed"), QMessageBox.AcceptRole)
        original_button = box.addButton(self.tr("Send Original"), QMessageBox.DestructiveRole)
        box.addButton(QMessageBox.Cancel)
        box.setDefaultButton(compressed_button)
        box.exec()
        clicked = box.clickedButton()

        if clicked is original_button:
            return data, mime
        if clicked is not compressed_button:
            return None, ""  # Cancel, or the dialog was dismissed

        recompressed = _recompress_image_bytes(data)
        if recompressed is None:
            QMessageBox.warning(
                self,
                self.tr("Could not read image"),
                self.tr(
                    "This file could not be decoded as an image, so it cannot be "
                    "safely re-encoded. It may not actually be an image, or may be "
                    "corrupted - sending it as-is is not recommended."
                ),
            )
            return None, ""
        return recompressed, "image/jpeg"

    def _start_contact_file_send(
        self, contact: vault_mod.Contact, file_path: str, file_data: bytes, file_mime: str,
    ) -> None:
        client_msg_id = str(uuid.uuid4())
        wire_body = envelope.encode_file(
            os.path.basename(file_path), file_mime, file_data, mid=client_msg_id,
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

        try:
            start_wire = envelope.encode_file_start(
                transfer_id, os.path.basename(file_path), mime, total_size, chunk_count,
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


def _avatar_pixmap(name: str, size: int = 36) -> QPixmap:
    """
    A round, coloured avatar bearing the name's first letter - decorative
    only, generated on the fly from text already in the vault (a contact's
    or group's own display name), never uploaded, stored as an image, or
    exchanged with anyone. Used as the QListWidgetItem icon in the sidebar
    (native icon+text items keep the existing QListWidget::item:selected
    styling "for free" - no custom item widget/selection-repaint logic
    needed) and in the conversation header.
    """
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)

    letter = (name.strip()[:1] or "?").upper()
    digest = hashlib.sha256((name or "?").encode("utf-8")).digest()
    color = _AVATAR_COLORS[digest[0] % len(_AVATAR_COLORS)]

    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor(color))
    painter.drawEllipse(0, 0, size, size)

    font = QFont()
    font.setPixelSize(max(10, int(size * 0.44)))
    font.setBold(True)
    painter.setFont(font)
    painter.setPen(QColor("#ffffff"))
    painter.drawText(pixmap.rect(), Qt.AlignCenter, letter)
    painter.end()

    return pixmap


_avatar_icon_cache: dict[str, QIcon] = {}


def _avatar_icon(name: str) -> QIcon:
    """Cached QIcon wrapper around _avatar_pixmap - the sidebar rebuilds
    every row on every reload (a new message, a presence change, ...), so
    this avoids repainting the same handful of contacts'/groups' avatars
    from scratch dozens of times a session."""
    icon = _avatar_icon_cache.get(name)
    if icon is None:
        icon = QIcon(_avatar_pixmap(name))
        _avatar_icon_cache[name] = icon
    return icon


def _format_file_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} GB"


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

    return (
        f"<div style='margin-top:4px;padding:6px;border:1px solid {p.border};"
        f"border-radius:6px;'>"
        f"<div style='color:{p.text};font-size:12px;'>\U0001F4CE {filename}</div>"
        f"<div style='color:{p.text_muted};font-size:11px;'>{size_text} &middot; {save_link}</div>"
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

    # A "Delete" link is offered only on the sender's own, still-intact,
    # outgoing bubbles - never on an incoming message (see
    # MainWindow._on_delete_message: only the original sender may ever
    # delete a message, matching how the receiving side independently
    # verifies this over the wire, in vault.py/app.py's KIND_DELETE
    # handling, not just in this display-only check here).
    delete_link = ""
    if outgoing and not deleted and getattr(msg, "client_msg_id", ""):
        delete_text = i18n.tr("Delete")  # see save_as_text's comment above on why this is not inline
        delete_link = (
            f" &middot; <a href='delmsg:{escape_html(msg.id)}' "
            f"style='color:{p.text_muted};text-decoration:none;'>{delete_text}</a>"
        )

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
        f"{who} &middot; {format_timestamp(msg.timestamp)}{delete_link}</div>"
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

    dir_attr = "rtl" if is_rtl else "ltr"
    return (
        f"<table width='100%' cellpadding='0' cellspacing='0' dir='{dir_attr}' "
        f"style='margin-bottom:10px;'><tr>{cells}</tr></table>"
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

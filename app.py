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

import io
import logging
import os
import sys
import threading
from datetime import datetime

import segno
from PySide6.QtCore import QBuffer, QByteArray, Qt, QThread, Signal
from PySide6.QtGui import QFont, QGuiApplication, QIcon, QPixmap, QTransform
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

    def __init__(self, bundle_text: str, fingerprint: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(self.tr("Share Contact"))
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
        fp_label = QLabel(fingerprint)
        fp_label.setFont(fp_font)
        fp_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(fp_label)

        note = QLabel(
            self.tr(
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

        copy_button = QPushButton(self.tr("Copy bundle"))
        copy_button.setObjectName("primary")
        copy_button.clicked.connect(lambda: self._copy_bundle(bundle_text))
        layout.addWidget(copy_button)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        buttons.accepted.connect(self.accept)
        layout.addWidget(buttons)

    def _copy_bundle(self, bundle_text: str) -> None:
        QGuiApplication.clipboard().setText(bundle_text)
        QMessageBox.information(self, self.tr("Copied"), self.tr("Contact bundle copied."))


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
            if self._online.get(contact.id) != online:
                self._online[contact.id] = online
                self.presence_changed.emit(contact.id, online)

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
                    body=message.body,
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
        self._send_worker: SendWorker | None = None
        self._tor_worker: TorStartWorker | None = None
        self.monitor: HealthMonitor | None = None
        self.delivery: DeliveryWorker | None = None
        self._self_test: SelfTestWorker | None = None
        self._pending_body = ""

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
        splitter.setSizes([300, 740])
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
        panel.setMinimumWidth(240)
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

        button_row = QHBoxLayout()
        self.share_button = QPushButton(self.tr("Share Contact..."))
        self.share_button.setToolTip(
            self.tr(
                "QR code and copyable bundle a contact can scan or paste to add "
                "you - never your onion address in the clear."
            )
        )
        self.share_button.clicked.connect(self._on_share_contact)
        button_row.addWidget(self.share_button)

        identity_button = QPushButton(self.tr("Keys..."))
        identity_button.setToolTip(self.tr("Fingerprint, backup, and identity"))
        identity_button.clicked.connect(self._on_identity)
        button_row.addWidget(identity_button)

        settings_button = QPushButton(self.tr("Settings..."))
        settings_button.setToolTip(self.tr("Language and who can reach you"))
        settings_button.clicked.connect(self._on_settings)
        button_row.addWidget(settings_button)
        layout.addLayout(button_row)

        self.fingerprint_label = QLabel("")
        self.fingerprint_label.setStyleSheet(
            f"color: {self.palette_colors.text_muted}; font-family: monospace;"
        )
        self.fingerprint_label.setToolTip(
            self.tr("Your fingerprint. Read it to a contact so they can verify you.")
        )
        layout.addWidget(self.fingerprint_label)

        contacts_title = QLabel(self.tr("Contacts"))
        contacts_title.setFont(bold)
        layout.addWidget(contacts_title)

        self.contact_list = QListWidget()
        self.contact_list.currentItemChanged.connect(self._on_contact_selected)
        self.contact_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.contact_list.customContextMenuRequested.connect(self._on_contact_menu)
        layout.addWidget(self.contact_list, stretch=1)

        row = QHBoxLayout()
        add_button = QPushButton(self.tr("Add"))
        add_button.clicked.connect(self._on_add_contact)
        row.addWidget(add_button)

        remove_button = QPushButton(self.tr("Remove"))
        remove_button.clicked.connect(self._on_remove_contact)
        row.addWidget(remove_button)
        layout.addLayout(row)

        return panel

    def _build_conversation_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(6, 12, 12, 12)
        layout.setSpacing(8)

        self.conversation_header = QLabel(self.tr("Select or add a contact"))
        header_font = QFont()
        header_font.setBold(True)
        header_font.setPointSize(11)
        self.conversation_header.setFont(header_font)
        layout.addWidget(self.conversation_header)

        self.thread_view = QTextBrowser()
        self.thread_view.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        layout.addWidget(self.thread_view, stretch=3)

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

        self.send_button = QPushButton(self.tr(" Send"))
        self.send_button.setObjectName("primary")   # styled as the main action
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
            self.send_button.setIcon(QIcon(send_icon))
        self.send_button.clicked.connect(self._on_send)
        layout.addWidget(self.send_button)

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

        for contact in self.vault.sorted_contacts():
            if contact.status == vault_mod.STATUS_BLOCKED:
                continue  # blocked contacts stay hidden

            count = len(contact.messages)
            if contact.status == vault_mod.STATUS_PENDING:
                label = self.tr("[request] %(name)s") % {"name": contact.name}
            else:
                marker = "\u2713 " if contact.verified else ""
                # Presence: filled dot online, hollow offline, nothing if unknown.
                online = self.delivery.is_online(contact.id) if self.delivery else None
                presence = "" if online is None else ("\u25cf " if online else "\u25cb ")
                queued = sum(
                    1 for m in contact.messages
                    if m.direction == "out" and m.status == vault_mod.QUEUED
                )
                suffix = self.tr("  (%(count)s)") % {"count": count} if count else ""
                if queued:
                    suffix += self.tr("  [%(queued)s queued]") % {"queued": queued}
                label = f"{presence}{marker}{contact.name}{suffix}"

            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, contact.id)
            if contact.status == vault_mod.STATUS_PENDING:
                item.setToolTip(self.tr("Wants to message you. Select to accept or block."))
            self.contact_list.addItem(item)

        self.contact_list.blockSignals(False)

        target = select_id or self._active_contact_id
        if target and self._select_contact(target):
            return
        if self.contact_list.count():
            self.contact_list.setCurrentRow(0)
        else:
            self._active_contact_id = None
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
            self._render_conversation(None)
            return
        self._active_contact_id = current.data(Qt.UserRole)
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
        SettingsDialog(self.vault, self).exec()

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
    def _render_conversation(self, contact: vault_mod.Contact | None) -> None:
        if contact is None:
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
        blocks = [
            render_bubble(msg, contact.name, p)
            for msg in sorted(contact.messages, key=lambda m: m.timestamp)
        ]

        self.thread_view.setHtml("".join(blocks))
        bar = self.thread_view.verticalScrollBar()
        bar.setValue(bar.maximum())

    def _set_composer_enabled(self, enabled: bool) -> None:
        self.message_input.setEnabled(enabled)
        self.send_button.setEnabled(enabled)

    # -- Sending ------------------------------------------------------------ #
    def _on_send(self) -> None:
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

        self._pending_body = body
        self.send_button.setDisabled(True)
        self.send_button.setText(self.tr("Sending…"))

        self._send_worker = SendWorker(
            onion=contact.onion,
            their_public_b64=contact.public_key,
            body=body,
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
        self.send_button.setText(self.tr(" Send"))

        if self._active_contact_id:
            # A failed send is queued, not lost. The delivery worker keeps
            # retrying until the contact's onion service answers.
            self.vault.add_message(
                self._active_contact_id,
                direction="out",
                body=self._pending_body,
                delivered=success,
                note="" if success else error,
                status=vault_mod.SENT if success else vault_mod.QUEUED,
            )

        self.message_input.clear()

        # No status-bar announcement here - the message itself appears in
        # the thread below with its own delivery state (see render_bubble),
        # exactly like a normal messenger: you see "Delivered" or
        # "User offline - message queued" on the message, not in a banner.
        if not success and self.delivery is not None:
            self.delivery.wake()

        self._reload_contacts(select_id=self._active_contact_id)
        self._render_conversation(self.vault.get_contact(self._active_contact_id or ""))

    def _release_send_worker(self) -> None:
        if self._send_worker is not None:
            self._send_worker.deleteLater()
            self._send_worker = None

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

        self.vault.add_message(contact.id, direction="in", body=body)
        self._reload_contacts(select_id=self._active_contact_id)

        if contact.status == vault_mod.STATUS_PENDING:
            # contact.name carries any impersonation warning _add_pending
            # attached (see vault.py). The sidebar's [request]-prefixed row
            # (already rendered by _reload_contacts above) is the surface
            # for this - no separate status-bar announcement, same as any
            # other pending-request arrival.
            return

        if self._active_contact_id == contact.id:
            # The message appears in the open thread below - that is the
            # notification, exactly like a normal messenger. No redundant
            # banner needed.
            self._render_conversation(self.vault.get_contact(contact.id))

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

    def closeEvent(self, event) -> None:
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
        if self._tor_worker is not None and self._tor_worker.isRunning():
            self._tor_worker.wait(5000)
        if self.server is not None:
            self.server.stop()
        self.tor.stop()
        self.vault.lock()
        super().closeEvent(event)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #

def render_bubble(msg, contact_name: str, p) -> str:
    """
    Build the HTML for one message bubble.

    Kept as a standalone function so the colour pairing can be asserted
    directly in tests. Qt's toHtml() does not round-trip table styles, so
    inspecting the widget afterwards cannot prove the text colour was set -
    but that pairing is exactly what stops messages being invisible on a dark
    desktop, so it has to be verifiable.
    """
    outgoing = msg.direction == "out"
    who = i18n.tr("You") if outgoing else escape_html(contact_name)

    # Background and text colour are always chosen together, never inherited.
    background = p.bubble_out_bg if outgoing else p.bubble_in_bg
    foreground = p.bubble_out_text if outgoing else p.bubble_in_text

    body = escape_html(msg.body).replace("\n", "<br>")

    # This mapping is deliberately built from data the app already tracks
    # honestly (Message.status/.delivered/.attempts, set only when
    # transport.send_message got a real cryptographic acknowledgment from
    # the recipient - see transport.py/DeliveryWorker). "Delivered" is
    # only ever shown for a message that actually went through that path -
    # never merely because the local app accepted the send.
    note = ""
    status = getattr(msg, "status", "sent")
    if outgoing:
        if status == "queued":
            attempts = getattr(msg, "attempts", 0)
            text = i18n.tr("Waiting for user…") if attempts > 1 else i18n.tr("User offline - message queued")
            note = f"<div style='color:{p.warn};font-size:11px;'>{text}</div>"
        elif not msg.delivered:
            note = f"<div style='color:{p.error};font-size:11px;'>{i18n.tr('Waiting…')}</div>"
        else:
            note = f"<div style='color:{p.text_muted};font-size:11px;'>{i18n.tr('Delivered')}</div>"

    # Qt's rich text engine ignores display:inline-block, so a plain div
    # stretches the full width and stops looking like a bubble. Nested tables
    # are part of the subset Qt does support, and give a bubble that hugs its
    # text and sits on the correct side.
    bubble = (
        f"<table cellpadding='7' cellspacing='0' "
        f"style='background-color:{background};'>"
        f"<tr><td style='color:{foreground};'>{body}</td></tr></table>"
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

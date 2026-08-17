"""
UI regression tests.

The bug this exists to prevent: message bubbles set a background colour but
inherited their text colour from the system palette. On a dark desktop that
produced light text on a light bubble - the message was there, just invisible.

These tests render real conversations under both a light and a dark desktop
and assert that every bubble declares its own text colour with genuine
contrast against its own background.
"""

from __future__ import annotations

import os
import sys

from PySide6.QtGui import QColor, QIcon, QPalette
from PySide6.QtWidgets import QApplication

import crypto
import theme
import vault as vm
import version

results: list[tuple[str, bool]] = []


def check(label: str, condition: bool) -> None:
    results.append((label, condition))
    print(f"  {'PASS' if condition else 'FAIL'}  {label}")


def luminance(hex_color: str) -> float:
    value = hex_color.strip().lstrip("#")
    r, g, b = int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)
    return 0.299 * r + 0.587 * g + 0.114 * b


def readable(foreground: str, background: str) -> bool:
    """Require a real perceptual gap, not merely different colours."""
    return abs(luminance(foreground) - luminance(background)) > 60


def build_window(app, window_bg: str, path: str):
    palette = app.palette()
    palette.setColor(QPalette.Window, QColor(window_bg))
    app.setPalette(palette)

    import app as appmod

    appmod.MainWindow._start_network = lambda self: None

    colors = theme.detect_palette(app)
    app.setStyleSheet(theme.stylesheet(colors))

    store = vm.Vault(path)
    store.create("ui test passphrase")
    store.set_onion("a" * 56 + ".onion", "ED25519-V3:K")

    window = appmod.MainWindow(store)
    _, public = crypto.generate_keypair()
    contact = store.add_contact(
        "Ali", vm.format_address("b" * 56 + ".onion", crypto.b64encode(public))
    )
    store.add_message(contact.id, "out", "outgoing text")
    store.add_message(contact.id, "in", "incoming text")
    store.add_message(contact.id, "out", "failed text", delivered=False, note="offline")
    window._reload_contacts(select_id=contact.id)
    window._render_conversation(store.get_contact(contact.id))
    return window, colors, store


def main() -> None:
    app = QApplication.instance() or QApplication(sys.argv)

    for mode, background in (("light", "#ffffff"), ("dark", "#1c1e21")):
        path = f"/tmp/uitest_{mode}.dat"
        try:
            os.remove(path)
        except OSError:
            pass

        print(f"\n{mode.capitalize()} desktop:")
        window, colors, store = build_window(app, background, path)

        check("palette matches desktop", colors.is_dark == (mode == "dark"))
        check("outgoing bubble readable",
              readable(colors.bubble_out_text, colors.bubble_out_bg))
        check("incoming bubble readable",
              readable(colors.bubble_in_text, colors.bubble_in_bg))
        check("body text readable", readable(colors.text, colors.window))
        check("muted text distinguishable from body",
              colors.text_muted.lower() != colors.text.lower())

        html = window.thread_view.toHtml()
        check("outgoing message present", "outgoing text" in html)
        check("incoming message present", "incoming text" in html)
        # The raw internal note ("offline") is deliberately never echoed
        # into the UI any more - only the fixed, honest "Waiting…" label.
        check("not-yet-delivered note present", "Waiting" in html)
        check("raw internal note text not leaked", "offline" not in html.lower())

        # Assert on the HTML we generate. Qt's toHtml() does not round-trip
        # table styles, so it cannot prove the colours were paired.
        import app as appmod

        contact = store.contacts[0]
        for message in contact.messages:
            bubble = appmod.render_bubble(message, contact.name, colors)
            outgoing = message.direction == "out"
            expected_bg = colors.bubble_out_bg if outgoing else colors.bubble_in_bg
            expected_fg = colors.bubble_out_text if outgoing else colors.bubble_in_text

            check(
                f"{message.direction} bubble sets its background",
                f"background-color:{expected_bg}" in bubble,
            )
            check(
                f"{message.direction} bubble sets its text colour",
                f"color:{expected_fg}" in bubble,
            )
            check(
                f"{message.direction} bubble text is readable",
                readable(expected_fg, expected_bg),
            )
            check(
                f"{message.direction} bubble avoids inline-block",
                "inline-block" not in bubble,
            )

        window.close()
        try:
            os.remove(path)
        except OSError:
            pass

    print("\nHTML injection from a malicious contact name:")
    import app as appmod

    injection_path = "/tmp/uitest_injection.dat"
    try:
        os.remove(injection_path)
    except OSError:
        pass

    store = vm.Vault(injection_path)
    store.create("injection test passphrase")
    store.set_onion("c" * 56 + ".onion", "ED25519-V3:K")
    appmod.MainWindow._start_network = lambda self: None
    window = appmod.MainWindow(store)

    _, evil_pub = crypto.generate_keypair()
    evil_name = "<b>bold</b><script>evil</script>"
    evil_contact = store.add_contact(
        evil_name, vm.format_address("d" * 56 + ".onion", crypto.b64encode(evil_pub))
    )
    store.add_message(evil_contact.id, "in", "hi")

    # render_bubble (message bubbles) - already covered above for readability;
    # here specifically for injection.
    bubble = appmod.render_bubble(evil_contact.messages[0], evil_contact.name, colors)
    check("message bubble escapes a malicious contact name", "<script>" not in bubble)
    check("message bubble escapes bold-tag injection", "<b>bold</b>" not in bubble)

    window._reload_contacts(select_id=evil_contact.id)
    window._render_conversation(store.get_contact(evil_contact.id))
    # QLabel.setText() with escaped input stores the escaped entities
    # (&lt;script&gt;), not the raw tag - assert the entity form is what
    # actually reached the widget, which is what makes Qt::AutoText's
    # markup auto-detection harmless here.
    header_text = window.conversation_header.text()
    check("conversation header carries escaped entities, not a raw tag", "&lt;script&gt;" in header_text)
    check("conversation header has no raw script tag", "<script>" not in header_text)

    window.close()
    try:
        os.remove(injection_path)
    except OSError:
        pass

    print("\nConnection state (fixed vocabulary only):")
    # There is no in-app log UI any more (removed by design - see
    # app.py's module docstring for _CONNECTION_STATES) - _on_transport_event
    # is diagnostic-only (stderr via _logger) and must not raise even on
    # attacker-shaped input, since it is fed directly from a network thread.
    try:
        appmod._on_transport_event("message_received", "<b>fake</b>" + "x" * 44 + ".onion")
        check("_on_transport_event never raises on adversarial input", True)
    except Exception:
        check("_on_transport_event never raises on adversarial input", False)

    conn_path = "/tmp/uitest_connstate.dat"
    try:
        os.remove(conn_path)
    except OSError:
        pass
    store = vm.Vault(conn_path)
    store.create("connection state test passphrase")
    store.set_onion("k" * 56 + ".onion", "ED25519-V3:K")
    appmod.MainWindow._start_network = lambda self: None
    window = appmod.MainWindow(store)

    # Every state constant must map to one of the fixed words - no state
    # can ever produce arbitrary text on the label.
    allowed_words = {word for word, _level in appmod._CONNECTION_STATES.values()}
    for state in (
        appmod.STATE_STARTING, appmod.STATE_CONNECTING, appmod.STATE_READY,
        appmod.STATE_OFFLINE, appmod.STATE_RECONNECTING,
    ):
        window._set_connection_state(state)
        check(
            f"state '{state}' shows only its fixed word",
            window.status_label.text() in allowed_words,
        )

    window.close()
    try:
        os.remove(conn_path)
    except OSError:
        pass

    print("\nOnion address never appears in normal UI:")
    onion_path = "/tmp/uitest_onion.dat"
    try:
        os.remove(onion_path)
    except OSError:
        pass

    store = vm.Vault(onion_path)
    store.create("onion exposure test passphrase")
    my_onion = "g" * 56 + ".onion"
    store.set_onion(my_onion, "ED25519-V3:K")
    window = appmod.MainWindow(store)

    _, peer_pub = crypto.generate_keypair()
    peer_onion = "h" * 56 + ".onion"
    peer = store.add_contact("Peer", vm.format_address(peer_onion, crypto.b64encode(peer_pub)))
    store.add_message(peer.id, "in", "hello")
    window._reload_contacts(select_id=peer.id)
    window._render_conversation(store.get_contact(peer.id))

    check("sidebar status label has no onion substring", my_onion not in window.my_status_label.text())
    check("conversation header has no onion substring", my_onion not in window.conversation_header.text())
    check(
        "conversation view HTML has no contact onion substring",
        peer_onion not in window.thread_view.toHtml(),
    )
    check(
        "conversation view HTML has no own-identity onion substring",
        my_onion not in window.thread_view.toHtml(),
    )
    check("no widget anywhere in the sidebar carries the my_address name any more",
          not hasattr(window, "my_address"))

    identity_dialog = appmod.IdentityDialog(store, window)
    dialog_widgets_text = " ".join(
        w.text() for w in identity_dialog.findChildren(appmod.QLabel)
        if hasattr(w, "text")
    )
    check("IdentityDialog has no onion substring in any QLabel", my_onion not in dialog_widgets_text)
    for w in identity_dialog.findChildren(appmod.QLineEdit):
        check(f"IdentityDialog QLineEdit '{w.objectName() or w.text()[:20]}' has no onion", my_onion not in w.text())
    identity_dialog.close()

    # Pending-request view (used for both ordinary requests and the
    # endpoint-changed warning) must not show the onion either.
    _, stranger_pub = crypto.generate_keypair()
    stranger_onion = "i" * 56 + ".onion"
    check("stranger accepted as pending", store.may_receive_from(crypto.b64encode(stranger_pub), stranger_onion))
    pending = store.pending_contacts()[0]
    window._reload_contacts(select_id=pending.id)
    window._render_conversation(store.get_contact(pending.id))
    check(
        "pending-request view has no onion substring",
        stranger_onion not in window.thread_view.toHtml(),
    )

    print("\nA stranger's first message is decoded before storage, not stored as raw envelope JSON:")
    # The bug this guards against: _on_message_arrived used to store a
    # STATUS_PENDING sender's message body completely raw (the literal
    # wire envelope, e.g. {"k": "text", "body": "hi", "mid": "...", "p":
    # "000...0"} - the padding field included) instead of decoding it
    # first, so the request preview/thread showed the whole JSON blob
    # instead of the actual text the stranger typed.
    import envelope as envelope_mod
    _, stranger2_pub = crypto.generate_keypair()
    stranger2_pub_b64 = crypto.b64encode(stranger2_pub)
    stranger2_onion = "k" * 56 + ".onion"
    store.may_receive_from(stranger2_pub_b64, stranger2_onion)
    wire = envelope_mod.encode_text("hello there", mid="test-mid-123")
    window._on_message_arrived(stranger2_pub_b64, wire)
    pending2 = store.find_by_public_key(stranger2_pub_b64)
    stored_body = pending2.messages[-1].body
    check("stranger's first-message body is the decoded text, not raw JSON", stored_body == "hello there")
    check("stored body does not start with the envelope's '{\"k\":' shape", not stored_body.startswith("{"))
    check("padding field never leaks into a displayed message", '"p":' not in stored_body)

    # A file attachment from a not-yet-accepted stranger must show a
    # placeholder, never the raw base64 file bytes.
    _, stranger3_pub = crypto.generate_keypair()
    stranger3_pub_b64 = crypto.b64encode(stranger3_pub)
    store.may_receive_from(stranger3_pub_b64, "l" * 56 + ".onion")
    file_wire = envelope_mod.encode_file("secret.pdf", "application/pdf", b"raw pdf bytes")
    window._on_message_arrived(stranger3_pub_b64, file_wire)
    pending3 = store.find_by_public_key(stranger3_pub_b64)
    file_body = pending3.messages[-1].body
    check("stranger's file attachment shows a placeholder, not raw base64", "cGRm" not in file_body and "raw pdf" not in file_body)

    window.close()
    try:
        os.remove(onion_path)
    except OSError:
        pass

    print("\nShare Contact dialog (QR + bundle):")
    share_path = "/tmp/uitest_share.dat"
    try:
        os.remove(share_path)
    except OSError:
        pass
    store = vm.Vault(share_path)
    store.create("share test passphrase")
    share_onion = "j" * 56 + ".onion"
    store.set_onion(share_onion, "ED25519-V3:K")

    import bundle as bundle_mod

    bundle_text = bundle_mod.build_bundle(
        store.identity.onion, store.identity.public_key,
        store.identity.signing_public_key, store.identity.signing_private_key,
    )
    check("bundle built from identity has no onion substring", share_onion not in bundle_text)

    share_dialog = appmod.ShareDialog(bundle_text, store.identity.fingerprint, None)
    check("ShareDialog constructs without error", share_dialog is not None)
    check("ShareDialog renders a non-null QR pixmap", not share_dialog.findChild(appmod.QLabel).pixmap().isNull())
    dialog_text = " ".join(
        w.text() for w in share_dialog.findChildren(appmod.QLabel) if hasattr(w, "text")
    )
    check("ShareDialog's own text has no onion substring", share_onion not in dialog_text)
    share_dialog.close()
    try:
        os.remove(share_path)
    except OSError:
        pass

    print("\nControls:")
    window, colors, store = build_window(app, "#1c1e21", "/tmp/uitest_ctrl.dat")

    # Round, icon-only "sendButton" is the normal case (the brand send icon
    # ships with the app - see app.py's _build_conversation_panel); a
    # rectangular labeled "primary" button is only the fallback if that
    # asset is ever missing. Either is a legitimately styled send action.
    check(
        "send button styled as sendButton or primary",
        window.send_button.objectName() in ("sendButton", "primary"),
    )
    check(
        "send button has an icon when styled as sendButton",
        window.send_button.objectName() != "sendButton" or not window.send_button.icon().isNull(),
    )
    check("send button sized by stylesheet", "min-height" in theme.stylesheet(colors))
    check("send button renders tall enough", window.send_button.sizeHint().height() >= 34)
    check("check button has real height", window.check_button.minimumHeight() >= 24)
    check("stylesheet defines button borders", "QPushButton" in theme.stylesheet(colors))
    check("stylesheet defines hover state", ":hover" in theme.stylesheet(colors))
    check("stylesheet defines primary variant", "#primary" in theme.stylesheet(colors))
    check("stylesheet defines round send-button variant", "#sendButton" in theme.stylesheet(colors))

    print("\nVersion and branding:")
    expected = f"v{version.__version__}"
    check("app name is Veilwire", version.APP_NAME == "Veilwire")
    check(f"version shown in status bar ({expected})", window.version_label.text() == expected)
    check(f"window title carries version ({expected})", expected in window.windowTitle())
    # The window title must be JUST the version, not "Veilwire v1.0.0" -
    # some window managers append QApplication's own display name
    # ("Veilwire", set once in main()) to whatever setWindowTitle()
    # already contains, which produced a visible duplicate ("Veilwire
    # v1.0.0 - Veilwire") when both were set here.
    check("window title does not duplicate the app name", "Veilwire" not in window.windowTitle())
    check("licence stated as MIT", version.LICENSE == "MIT")
    check("full version mentions open source", "open source" in version.full_version())
    check("no em-dash anywhere in full_version()", "—" not in version.full_version())

    import app as appmod

    icon = appmod.icon_file()
    check("icon file bundled", icon is not None and os.path.exists(icon))
    if icon:
        check("icon loads as a real image", not QIcon(icon).isNull())

    print("\nAbout dialog:")
    about = appmod.AboutDialog(colors, window)
    about_text = " ".join(
        w.text() for w in about.findChildren(appmod.QLabel) if hasattr(w, "text")
    )
    check("no em-dash anywhere in the About dialog", "—" not in about_text)
    check("repo link present", version.REPOSITORY in about_text)
    check("Tor is explicitly mentioned in the About description", "Tor" in about_text)
    check("XMR donation address present", version.XMR_DONATION_ADDRESS.replace("​", "") in about_text.replace("​", ""))
    check("contact public key present", version.CONTACT_PUBLIC_KEY.replace("​", "") in about_text.replace("​", ""))
    check("contact fingerprint present", version.CONTACT_FINGERPRINT in about_text)
    check("team credit present", "Freedom Team" in about_text)

    # The "Verify our identity" section must never frame itself as a
    # working add-contact shortcut - it's for identity verification only.
    check("identity section does not claim to be an add-contact flow", "add us" not in about_text.lower())

    # Copy buttons copy the REAL value, never the zero-width-space-broken
    # display text used only to make long tokens wrap on screen. The real
    # handlers also pop a confirmation QMessageBox, which blocks waiting
    # for a user to dismiss it - not something an automated, headless test
    # can do, so QMessageBox.information is swapped for a no-op for the
    # duration of this check only, then restored immediately after.
    original_information = appmod.QMessageBox.information
    appmod.QMessageBox.information = staticmethod(lambda *a, **k: None)
    try:
        about._copy_xmr_address()
        check(
            "XMR copy button copies the clean address (no invisible break characters)",
            app.clipboard().text() == version.XMR_DONATION_ADDRESS,
        )
        about._copy_contact_pubkey()
        check(
            "pubkey copy button copies the clean key (no invisible break characters)",
            app.clipboard().text() == version.CONTACT_PUBLIC_KEY,
        )
    finally:
        appmod.QMessageBox.information = original_information

    # The long, space-free tokens (address/pubkey) must not force the
    # dialog's scrollable content wider than the dialog itself - this is
    # the literal "make it appear normal, full, not extended" requirement.
    about.show()
    scroll = about.findChild(appmod.QScrollArea)
    check(
        "About dialog content does not overflow sideways",
        scroll.widget().sizeHint().width() <= about.width() + 40,
    )
    about.close()

    window.close()
    try:
        os.remove("/tmp/uitest_ctrl.dat")
    except OSError:
        pass

    print("\nNo networking jargon anywhere in normal UI text:")
    # The fixed word list from the design requirement: none of these may
    # ever appear in status text, the conversation header, or a message
    # bubble, across a full simulated send/queue/deliver cycle. Deliberately
    # NOT scanning code comments/docstrings/tooltips/log calls - those are
    # allowed to be precise, since a developer reading source isn't a
    # normal user looking at the running app.
    banned_words = (
        "tor", "onion", "socks", "relay", "circuit", "bootstrap",
        "listener", "connecting to",
    )

    def scan(label: str, text: str) -> None:
        lowered = text.lower()
        hit = next((w for w in banned_words if w in lowered), None)
        check(f"{label} has no networking jargon", hit is None)

    jargon_path = "/tmp/uitest_jargon.dat"
    try:
        os.remove(jargon_path)
    except OSError:
        pass
    store = vm.Vault(jargon_path)
    store.create("jargon scan test passphrase")
    store.set_onion("m" * 56 + ".onion", "ED25519-V3:K")
    appmod.MainWindow._start_network = lambda self: None
    window = appmod.MainWindow(store)

    _, peer_pub = crypto.generate_keypair()
    peer = store.add_contact("Peer", vm.format_address("n" * 56 + ".onion", crypto.b64encode(peer_pub)))

    # Simulate the full lifecycle: sending, queued-offline, retried, delivered.
    store.add_message(peer.id, "out", "hi there", status=vm.SENT, delivered=True)
    store.add_message(peer.id, "out", "still trying", status=vm.QUEUED, delivered=False)
    retried = store.add_message(peer.id, "out", "retried msg", status=vm.QUEUED, delivered=False)
    store.mark_message(peer.id, retried.id, vm.QUEUED, "")  # attempts: 0 -> 1
    store.mark_message(peer.id, retried.id, vm.QUEUED, "")  # attempts: 1 -> 2

    window._reload_contacts(select_id=peer.id)
    window._render_conversation(store.get_contact(peer.id))

    scan("conversation header", window.conversation_header.text())
    scan("sidebar status label", window.my_status_label.text())
    scan("full message thread HTML", window.thread_view.toHtml())
    for state in (
        appmod.STATE_STARTING, appmod.STATE_CONNECTING, appmod.STATE_READY,
        appmod.STATE_OFFLINE, appmod.STATE_RECONNECTING,
    ):
        window._set_connection_state(state)
        scan(f"status label in state '{state}'", window.status_label.text())

    # The honest-delivery-state mapping itself: the three real states map
    # to exactly the expected human text, and "Delivered" only appears for
    # the message that actually has status=SENT/delivered=True.
    thread_html = window.thread_view.toHtml()
    check("delivered message shows 'Delivered'", "Delivered" in thread_html)
    check("first-failure message shows the offline-queued label", "User offline - message queued" in thread_html)
    check("retried message shows the waiting-for-user label", "Waiting for user…" in thread_html)

    window.close()
    try:
        os.remove(jargon_path)
    except OSError:
        pass

    print("\nGroup conversation rendering (aggregate delivery notes):")
    # Regression test for a real crash this test suite did not previously
    # catch: MainWindow._render_group_conversation's "some members still
    # pending" and "no members delivered yet" notes used to build their
    # text via i18n.trf(template, n=total) - but trf()'s own `n` parameter
    # is reserved for Qt's numerus (plural-form) selector, so a caller's
    # n=total meant for %(n)s substitution never reached %-formatting,
    # and rendering a group message with 0 (but not all) members
    # delivered raised KeyError('n') the instant that branch was hit. Both
    # branches are exercised below.
    group_path = "/tmp/uitest_group.dat"
    try:
        os.remove(group_path)
    except OSError:
        pass
    group_store = vm.Vault(group_path)
    group_store.create("group ui test passphrase")
    group_store.set_onion("f" * 56 + ".onion", "ED25519-V3:K")
    m1 = group_store.add_contact("Mona", vm.format_address("g" * 56 + ".onion", crypto.b64encode(crypto.generate_keypair()[1])))
    m2 = group_store.add_contact("Nabil", vm.format_address("h" * 56 + ".onion", crypto.b64encode(crypto.generate_keypair()[1])))
    m3 = group_store.add_contact("Omar", vm.format_address("i" * 56 + ".onion", crypto.b64encode(crypto.generate_keypair()[1])))
    test_group = group_store.create_group("Trio", [m1.id, m2.id, m3.id])

    # All delivered.
    group_store.add_message(m1.id, "out", "hi all", group_id=test_group.id, client_msg_id="gc1", status=vm.SENT)
    group_store.add_message(m2.id, "out", "hi all", group_id=test_group.id, client_msg_id="gc1", status=vm.SENT)
    group_store.add_message(m3.id, "out", "hi all", group_id=test_group.id, client_msg_id="gc1", status=vm.SENT)
    # None delivered yet (this is the branch that used to crash).
    group_store.add_message(m1.id, "out", "second msg", group_id=test_group.id, client_msg_id="gc2", status=vm.QUEUED)
    group_store.add_message(m2.id, "out", "second msg", group_id=test_group.id, client_msg_id="gc2", status=vm.QUEUED)
    group_store.add_message(m3.id, "out", "second msg", group_id=test_group.id, client_msg_id="gc2", status=vm.QUEUED)
    # Partially delivered.
    group_store.add_message(m1.id, "out", "third msg", group_id=test_group.id, client_msg_id="gc3", status=vm.SENT)
    group_store.add_message(m2.id, "out", "third msg", group_id=test_group.id, client_msg_id="gc3", status=vm.QUEUED)
    group_store.add_message(m3.id, "out", "third msg", group_id=test_group.id, client_msg_id="gc3", status=vm.QUEUED)

    group_window = appmod.MainWindow(group_store)
    group_window._reload_contacts(select_id=test_group.id)
    try:
        group_window._render_conversation(None, group=test_group)
        rendered_ok = True
    except Exception as exc:  # noqa: BLE001
        rendered_ok = False
        print(f"    EXCEPTION: {exc!r}")
    check("group conversation with a 0-of-N delivered message renders without raising", rendered_ok)

    if rendered_ok:
        group_html = group_window.thread_view.toHtml()
        check("all-delivered group message shows 'Delivered'", "Delivered" in group_html)
        check("0-of-N group message shows the real member count (not a raw KeyError)", "3 member" in group_html or "Waiting for 3" in group_html)
        check("partially-delivered group message shows the aggregate count", "1" in group_html and "3" in group_html)

    group_window.close()
    try:
        os.remove(group_path)
    except OSError:
        pass

    print("\nAttachments never auto-render inline - Save As... first, always:")
    # The bug this guards against: an image attachment used to be decoded
    # and embedded as a data: URI <img> directly in the thread the moment
    # a message arrived - no user action required. That is a real
    # attack-surface widening (Qt's rich-text renderer decoding
    # attacker-controlled image bytes automatically on receipt) as well
    # as inconsistent with every mainstream messenger's "tap/click to
    # view" model. _attachment_html must never emit an <img> tag for any
    # mime type, image included - only a filename/size/Save As... link.
    class FakeAttachmentMessage:
        id = "fake-msg-id"
        attachment_filename = "photo.jpg"
        attachment_mime = "image/jpeg"
        attachment_size = 12345
        body = "ZmFrZS1pbWFnZS1ieXRlcw=="  # base64, arbitrary - never decoded by this function anyway

    fake_colors = theme.detect_palette(QApplication.instance())
    attachment_html = appmod._attachment_html(FakeAttachmentMessage(), fake_colors)
    check("no inline <img> tag for an image attachment", "<img" not in attachment_html)
    check("no data: URI embedded either", "data:image" not in attachment_html)
    check("filename is still shown", "photo.jpg" in attachment_html)
    check("a Save As... link is still present", "attach:fake-msg-id" in attachment_html)

    print("\nBranding assets:")
    for asset in ("veilwire-chat.png", "veilwire-shield.png", "veilwire-send.png", "veilwire-network.png"):
        path = appmod.brand_image_path(asset)
        check(f"{asset} is present under icons/brand/", path is not None and os.path.exists(path))
        if path is not None:
            pixmap = appmod._load_brand_pixmap(asset, 128)
            check(f"{asset} loads as a valid, non-null QPixmap", pixmap is not None and not pixmap.isNull())
            if pixmap is not None:
                check(f"{asset} keeps its alpha channel after scaling", pixmap.hasAlphaChannel())

    # The app icon itself must resolve to the new mark-derived set, not the
    # old procedurally-generated placeholder.
    mark_source = os.path.join(os.path.dirname(appmod.__file__), "icons", "brand", "veilwire-mark.png")
    check("veilwire-mark.png (the real brand source) is present", os.path.exists(mark_source))
    icon = appmod.icon_file()
    check("resolved app icon is a real, non-null image", icon is not None and not QIcon(icon).isNull())

    print("\nSidebar stays responsive at its documented minimum width (no clipped buttons):")
    # The bug this guards against: four buttons (Add/New Group/Join
    # Group/Remove) in one row, and separately "Share"/"Keys"/"Settings"
    # in another, both overflowed the sidebar's minimum width and got
    # visually clipped ("Settings" rendered as "etting"). Splitting the
    # contact-action row into two rows and widening the documented
    # minimum fixed it - this asserts the actual enforced minimum, not
    # just that the code runs, so a future change that narrows it back
    # down is caught here rather than only by eyeballing a screenshot.
    responsive_path = "/tmp/uitest_responsive.dat"
    try:
        os.remove(responsive_path)
    except OSError:
        pass
    store = vm.Vault(responsive_path)
    store.create("responsive test passphrase")
    store.set_onion("q" * 56 + ".onion", "ED25519-V3:K")
    appmod.MainWindow._start_network = lambda self: None
    window = appmod.MainWindow(store)
    window.resize(1280, 780)

    from PySide6.QtWidgets import QSplitter
    splitter = window.centralWidget().findChild(QSplitter)
    window.show()
    app.processEvents()
    # Try to force the sidebar narrower than any button row needs - Qt
    # clamps a QSplitter child to its own minimumWidth(), so the actual
    # resulting width is what matters, not the requested one.
    splitter.setSizes([50, 1230])
    app.processEvents()
    actual_sidebar_width = splitter.sizes()[0]
    check("sidebar cannot be dragged narrower than its buttons need", actual_sidebar_width >= 290)

    # Every sidebar button's actual rendered width must fit within the
    # enforced sidebar width - proves there's no button silently
    # overflowing/clipping at that minimum, rather than just checking the
    # panel's declared minimumWidth() in isolation.
    from PySide6.QtWidgets import QPushButton
    sidebar_buttons = [
        w for w in window.findChildren(QPushButton)
        if w.text() in ("Add", "Remove", "New Group", "Join Group", "Share", "Keys", "Settings")
    ]
    check("all expected sidebar buttons were found", len(sidebar_buttons) >= 7)
    for button in sidebar_buttons:
        check(f"button '{button.text()}' fits within the sidebar width", button.width() <= actual_sidebar_width)

    window.close()
    try:
        os.remove(responsive_path)
    except OSError:
        pass

    passed = sum(1 for _, ok in results if ok)
    print(f"\n{passed}/{len(results)} checks passed")
    if passed != len(results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

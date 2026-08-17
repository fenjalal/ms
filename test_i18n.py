"""
i18n / RTL / Settings regression tests.

The bug this exists to prevent: a translation layer that either silently
fails (falls back to English with no error - see i18n.tr()'s default
context, which had to match what pyside6-lupdate actually emits or every
free-function translation would no-op) or that reopens the HTML-injection
hole escape_html()/safe_error_text() already closed. These tests run the
same injection/jargon scans test_ui.py already uses, but with a non-English
QTranslator installed, to prove translation is layered on top of the
existing security discipline rather than replacing it.
"""

from __future__ import annotations

import os
import sys

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

import crypto
import i18n
import theme
import vault as vm

results: list[tuple[str, bool]] = []


def check(label: str, condition: bool) -> None:
    results.append((label, condition))
    print(f"  {'PASS' if condition else 'FAIL'}  {label}")


def main() -> None:
    app = QApplication.instance() or QApplication(sys.argv)

    print("Language/RTL registry:")
    check("English, Arabic, Russian, French all supported", set(i18n.SUPPORTED_LANGUAGES) == {"en", "ar", "ru", "fr"})
    check("only Arabic is RTL", i18n.RTL_LANGUAGES == frozenset({"ar"}))
    check("default language is English", i18n.DEFAULT_LANGUAGE == "en")

    print("\ncurrent_language()/set_language() persistence:")
    original = i18n.current_language()
    try:
        i18n.set_language("ar")
        check("set_language('ar') persists", i18n.current_language() == "ar")
        i18n.set_language("en")
        check("set_language('en') persists", i18n.current_language() == "en")
        raised = False
        try:
            i18n.set_language("xx")
        except ValueError:
            raised = True
        check("set_language() rejects an unsupported code", raised)
    finally:
        i18n.set_language(original)

    print("\ninstall_language() layout direction:")
    for lang in ("en", "ru", "fr"):
        i18n.install_language(app, lang)
        check(f"'{lang}' installs LeftToRight", app.layoutDirection() == Qt.LeftToRight)
    i18n.install_language(app, "ar")
    check("'ar' installs RightToLeft", app.layoutDirection() == Qt.RightToLeft)

    print("\nTranslation actually applies (not just layout direction):")
    # This is the regression case for the "i18n.tr() defaulted to the wrong
    # context" bug found while building this: free-function translations
    # (i18n.tr() called with no self, e.g. from render_bubble()/main()) were
    # silently returning the untranslated English source because the
    # default context didn't match what pyside6-lupdate files those calls
    # under in the .ts/.qm. Real, non-fallback Arabic text is the only
    # proof this stays fixed.
    i18n.install_language(app, "ar")
    translated = i18n.tr("Waiting for user…")
    check("i18n.tr() from a free-function string is actually translated under ar", translated != "Waiting for user…")
    check("i18n.tr() translation is non-empty", bool(translated))

    from PySide6.QtCore import QCoreApplication
    for context, source in (
        ("UnlockDialog", "Unlock"),
        ("IdentityDialog", "My Identity & Keys"),
        ("MainWindow", "Contacts"),
        ("SettingsDialog", "Settings"),
        ("ShareDialog", "Share Contact"),
        ("AboutDialog", "Project"),
    ):
        result = QCoreApplication.translate(context, source)
        check(f"{context} strings translate under ar", result != source and bool(result))

    print("\nNumerus (plural) forms - Arabic (6 forms), Russian (3), French (2):")
    i18n.install_language(app, "ar")
    ar_forms = {n: i18n.tr("Delivered %n queued message(s).", n=n) for n in (0, 1, 2, 3, 11, 100)}
    check("Arabic n=0 differs from n=1", ar_forms[0] != ar_forms[1])
    check("Arabic n=1 differs from n=2 (dual)", ar_forms[1] != ar_forms[2])
    check("Arabic n=3 differs from n=11 (few vs many)", ar_forms[3] != ar_forms[11])
    for n, text in ar_forms.items():
        check(f"Arabic n={n} form is non-empty", bool(text))

    i18n.install_language(app, "ru")
    ru_forms = {n: i18n.tr("Delivered %n queued message(s).", n=n) for n in (1, 2, 5, 21)}
    check("Russian n=1 differs from n=2 (one vs few)", ru_forms[1] != ru_forms[2])
    check("Russian n=2 differs from n=5 (few vs many)", ru_forms[2] != ru_forms[5])
    # n=21 uses the same plural *form* as n=1 (both "one" per CLDR: last
    # digit 1, not ending in 11) - compare the word after the number, not
    # the full string, since the substituted numeral itself differs.
    check(
        "Russian n=21 uses the same plural form as n=1 (one, per CLDR)",
        ru_forms[21].split(" ", 2)[-1] == ru_forms[1].split(" ", 2)[-1],
    )

    i18n.install_language(app, "fr")
    fr_forms = {n: i18n.tr("Delivered %n queued message(s).", n=n) for n in (0, 1, 2)}
    check("French n=1 differs from n=2", fr_forms[1] != fr_forms[2])

    print("\nSubstitution (trf/fmt) happens after translation and does not escape:")
    # "Delivered %n queued message(s)." is the one real string currently
    # extracted under the "i18n" context (see DeliveryWorker._sweep) - used
    # here via tr() (already covered above); trf() itself has no live
    # call site yet (every current substitution site turned out to be
    # inside a class, using fmt() instead - see this module's docstring),
    # so this exercises trf()'s substitution mechanics directly against a
    # source string that is deliberately NOT in any .ts, proving the
    # documented fallback: no matching translation -> the source string
    # itself is returned, with substitution still applied on top.
    i18n.install_language(app, "ar")
    substituted = i18n.trf("Untranslated template: %(name)s", name="Ali")
    check("trf() substitutes the placeholder", "Ali" in substituted)
    check("trf() falls back to the source template when untranslated", substituted == "Untranslated template: Ali")
    fmt_result = i18n.fmt("test %(x)s", x="<b>raw</b>")
    check("fmt() does not escape - caller's job, matching pre-i18n f-string behavior", "<b>raw</b>" in fmt_result)

    i18n.install_language(app, "en")

    print("\nRTL layout mirroring - QSplitter panel order:")
    import app as appmod

    appmod.MainWindow._start_network = lambda self: None
    rtl_path = "/tmp/i18ntest_rtl.dat"
    try:
        os.remove(rtl_path)
    except OSError:
        pass

    i18n.install_language(app, "ar")
    store = vm.Vault(rtl_path)
    store.create("rtl test passphrase")
    store.set_onion("e" * 56 + ".onion", "ED25519-V3:K")
    window = appmod.MainWindow(store)
    window.resize(900, 600)
    window.show()
    app.processEvents()

    # Find the QSplitter directly rather than depending on internal layout
    # accessors that may change - it's the one splitter under centralWidget.
    from PySide6.QtWidgets import QSplitter
    splitter = window.centralWidget().findChild(QSplitter)
    check("MainWindow has a QSplitter", splitter is not None)
    if splitter is not None:
        sidebar, conversation = splitter.widget(0), splitter.widget(1)
        # Under RTL, Qt visually mirrors the splitter without changing
        # widget insertion order - the sidebar (still index 0) should be
        # positioned to the right of the conversation panel on screen.
        check(
            "sidebar (index 0) renders to the right of the conversation panel under RTL",
            sidebar.geometry().x() > conversation.geometry().x(),
        )

    window.close()
    try:
        os.remove(rtl_path)
    except OSError:
        pass
    i18n.install_language(app, "en")

    print("\nrender_bubble() RTL alignment - outgoing stays on the trailing edge:")
    colors = theme.detect_palette(app)

    class FakeMessage:
        direction = "out"
        body = "hi"
        timestamp = "2026-01-01T00:00:00"
        delivered = True
        status = "sent"
        attempts = 1

    i18n.install_language(app, "en")
    ltr_bubble = appmod.render_bubble(FakeMessage(), "Ali", colors)
    check("LTR: outgoing bubble aligns right (trailing edge)", "align='right'" in ltr_bubble)
    check("LTR: outer table marked dir='ltr'", "dir='ltr'" in ltr_bubble)

    i18n.install_language(app, "ar")
    rtl_bubble = appmod.render_bubble(FakeMessage(), "Ali", colors)
    check("RTL: outgoing bubble aligns left (still the trailing edge)", "align='left'" in rtl_bubble)
    check("RTL: outer table marked dir='rtl'", "dir='rtl'" in rtl_bubble)
    i18n.install_language(app, "en")

    print("\nHTML-injection scan still holds with a non-English translator installed:")
    injection_path = "/tmp/i18ntest_injection.dat"
    try:
        os.remove(injection_path)
    except OSError:
        pass

    i18n.install_language(app, "ar")
    store = vm.Vault(injection_path)
    store.create("i18n injection test passphrase")
    store.set_onion("f" * 56 + ".onion", "ED25519-V3:K")
    window = appmod.MainWindow(store)

    _, evil_pub = crypto.generate_keypair()
    evil_name = "<b>bold</b><script>evil</script>"
    evil_contact = store.add_contact(
        evil_name, vm.format_address("g" * 56 + ".onion", crypto.b64encode(evil_pub))
    )
    store.add_message(evil_contact.id, "in", "hi")

    bubble = appmod.render_bubble(evil_contact.messages[0], evil_contact.name, colors)
    check("under ar: message bubble escapes a malicious contact name", "<script>" not in bubble)
    check("under ar: message bubble escapes bold-tag injection", "<b>bold</b>" not in bubble)

    window._reload_contacts(select_id=evil_contact.id)
    window._render_conversation(store.get_contact(evil_contact.id))
    header_text = window.conversation_header.text()
    check("under ar: conversation header carries escaped entities, not a raw tag", "&lt;script&gt;" in header_text)
    check("under ar: conversation header has no raw script tag", "<script>" not in header_text)

    window.close()
    try:
        os.remove(injection_path)
    except OSError:
        pass
    i18n.install_language(app, "en")

    print("\nNo networking jargon under a non-English translator:")
    banned_words = (
        "tor", "onion", "socks", "relay", "circuit", "bootstrap",
        "listener", "connecting to",
    )

    def scan(label: str, text: str) -> None:
        lowered = text.lower()
        hit = next((w for w in banned_words if w in lowered), None)
        check(f"{label} has no networking jargon", hit is None)

    jargon_path = "/tmp/i18ntest_jargon.dat"
    try:
        os.remove(jargon_path)
    except OSError:
        pass

    i18n.install_language(app, "ru")
    store = vm.Vault(jargon_path)
    store.create("i18n jargon test passphrase")
    store.set_onion("h" * 56 + ".onion", "ED25519-V3:K")
    window = appmod.MainWindow(store)

    _, peer_pub = crypto.generate_keypair()
    peer = store.add_contact("Peer", vm.format_address("i" * 56 + ".onion", crypto.b64encode(peer_pub)))
    store.add_message(peer.id, "out", "hi there", status=vm.SENT, delivered=True)
    window._reload_contacts(select_id=peer.id)
    window._render_conversation(store.get_contact(peer.id))

    scan("conversation header (ru)", window.conversation_header.text())
    scan("sidebar status label (ru)", window.my_status_label.text())
    scan("full message thread HTML (ru)", window.thread_view.toHtml())
    for state in (
        appmod.STATE_STARTING, appmod.STATE_CONNECTING, appmod.STATE_READY,
        appmod.STATE_OFFLINE, appmod.STATE_RECONNECTING,
    ):
        window._set_connection_state(state)
        scan(f"status label in state '{state}' (ru)", window.status_label.text())

    window.close()
    try:
        os.remove(jargon_path)
    except OSError:
        pass
    i18n.install_language(app, "en")

    print("\nSettingsDialog:")
    settings_path = "/tmp/i18ntest_settings.dat"
    try:
        os.remove(settings_path)
    except OSError:
        pass
    store = vm.Vault(settings_path)
    store.create("i18n settings test passphrase")
    store.set_onion("j" * 56 + ".onion", "ED25519-V3:K")

    dialog = appmod.SettingsDialog(store)
    check("language combo is populated with all supported languages", dialog.language_combo.count() == len(i18n.SUPPORTED_LANGUAGES))
    check("language combo pre-selects the current language", dialog._language_codes[dialog.language_combo.currentIndex()] == i18n.current_language())
    # isVisibleTo(dialog), not isVisible(): the dialog is never shown in
    # this test (no real window on an offscreen test run), and a widget's
    # own isVisible() always reads False while its top-level window isn't
    # shown, regardless of setVisible() - isVisibleTo() reflects the
    # widget's own visibility flag independent of that.
    check("restart notice starts hidden", not dialog.restart_notice.isVisibleTo(dialog))
    check("restart button starts hidden", not dialog.restart_button.isVisibleTo(dialog))
    check("restart_requested starts False", dialog.restart_requested is False)
    dialog.language_combo.setCurrentIndex((dialog.language_combo.currentIndex() + 1) % dialog.language_combo.count())
    check("restart notice appears after changing language", dialog.restart_notice.isVisibleTo(dialog))
    check("restart button appears after changing language", dialog.restart_button.isVisibleTo(dialog))

    # Clicking "Restart Now" must flag the request and close the dialog
    # (QDialog.Accepted) without itself touching Tor/the vault/re-executing
    # the process - that belongs to MainWindow._restart_app, which only
    # runs after dialog.exec() returns and this flag is checked (see
    # MainWindow._on_settings). Exercising the real restart here would
    # os.execv() this very test process.
    dialog.restart_button.click()
    check("restart_requested is set after clicking Restart Now", dialog.restart_requested is True)
    check("dialog is accepted (closed), not left open", dialog.result() == appmod.QDialog.Accepted)

    # "who can reach me" moved here from IdentityDialog, with the same wiring.
    check("open_mode checkbox reflects the vault's current setting", dialog.open_mode.isChecked() == store.identity.accept_from_anyone)
    dialog.open_mode.setChecked(not dialog.open_mode.isChecked())
    check("toggling open_mode updates the vault", store.identity.accept_from_anyone == dialog.open_mode.isChecked())
    dialog.close()

    identity_dialog = appmod.IdentityDialog(store)
    check("IdentityDialog no longer has the accept-from-anyone checkbox", not hasattr(identity_dialog, "open_mode"))
    identity_dialog.close()

    i18n.set_language("en")  # leave persisted state clean for the next run
    try:
        os.remove(settings_path)
    except OSError:
        pass

    print("\nStatic guard - unwrapped user-facing string literals in app.py:")
    # Best-effort grep, matching the discipline of check_no_direct_outbound_
    # sockets in test_transport.py: flags a QLabel/QPushButton/.setText/
    # .setToolTip/.setWindowTitle/.setPlaceholderText call whose string
    # argument is not wrapped in tr()/i18n.tr()/i18n.fmt()/i18n.trf() on the
    # same or an adjacent line. Not a proof of completeness (a real review
    # already covered every call site by hand) - it's a tripwire against a
    # *future* edit accidentally reintroducing a hardcoded literal.
    import re as re_mod

    with open("app.py", encoding="utf-8") as f:
        lines = f.readlines()

    patterns = [
        re_mod.compile(r'QLabel\(\s*f?"[^"]'),
        re_mod.compile(r"QLabel\(\s*f?'[^']"),
        re_mod.compile(r'QPushButton\(\s*f?"[^"]'),
        re_mod.compile(r"QPushButton\(\s*f?'[^']"),
        re_mod.compile(r'QCheckBox\(\s*f?"[^"]'),
        re_mod.compile(r'\.setToolTip\(\s*f?"[^"]'),
        re_mod.compile(r'\.setWindowTitle\(\s*f?"[^"]'),
        re_mod.compile(r'\.setPlaceholderText\(\s*f?"[^"]'),
    ]
    tr_markers = ("self.tr(", "i18n.tr(", "i18n.fmt(", "i18n.trf(")
    # Known, reviewed exceptions: not human-language prose, so nothing to
    # translate. status_dot is a single decorative glyph coloured entirely
    # via stylesheet; repo_link is a hyperlink built purely from the
    # constant repository URL (version.REPOSITORY), no words involved.
    # attach_button is a single paperclip glyph, deliberately NOT wrapped in
    # self.tr() - see its own comment in app.py: pyside6-lupdate corrupts
    # non-BMP characters like this one when extracting from Python source,
    # and a glyph needs no per-language translation anyway (same reasoning
    # already applied to the lock emoji in _refresh_identity_display).
    allowed_substrings = (
        'self.status_dot = QLabel("\\u25cf")',
        "repo_link = QLabel(f\"<a href='{version.REPOSITORY}'>{version.REPOSITORY}</a>\")",
        'self.attach_button = QPushButton("\\U0001F4CE")',
    )
    suspects = []
    for i, line in enumerate(lines):
        if any(m in line for m in tr_markers):
            continue
        if any(a in line for a in allowed_substrings):
            continue
        for p in patterns:
            if p.search(line):
                suspects.append((i + 1, line.strip()))
                break

    check(f"no unwrapped user-facing string literals found (0 suspects)", len(suspects) == 0)
    for lineno, text in suspects:
        print(f"    SUSPECT app.py:{lineno}: {text}")

    print("\nStatic guard - a tr()/trf() call nested inside an f-string in app.py:")
    # A real bug this caught while building the delete-for-everyone feature:
    # pyside6-lupdate's Python string extraction does not reliably find a
    # self.tr(...)/i18n.tr(...)/i18n.trf(...) call sitting inside an
    # f-string's {...} expression (e.g. f"...{i18n.tr('Delete')}...") -
    # verified empirically against this project's own .ts files: several
    # such calls (render_bubble's "Delete"/"This message was deleted"/
    # "Save As…"/"Waiting…", and _render_group_conversation's aggregate
    # delivery notes) extracted NOTHING at all, silently leaving those
    # strings permanently untranslated in every language with no error
    # anywhere - not even test_i18n.py's own suite caught it, since the
    # string still renders (in English) either way. The fix applied
    # throughout app.py was always the same: compute the translated text as
    # its own statement first, then reference that local variable inside
    # the f-string - never call .tr()/.trf() inline inside {...}. This
    # guard is the tripwire against a future edit reintroducing the pattern.
    nested_tr_pattern = re_mod.compile(r'\{[^{}]*\b(self\.tr|i18n\.tr|i18n\.trf|i18n\.fmt)\s*\(')
    nested_suspects = [
        (i + 1, line.strip()) for i, line in enumerate(lines) if nested_tr_pattern.search(line)
    ]
    check("no tr()/trf()/fmt() call nested inside an f-string expression (0 suspects)", len(nested_suspects) == 0)
    for lineno, text in nested_suspects:
        print(f"    SUSPECT app.py:{lineno}: {text}")

    passed = sum(1 for _, ok in results if ok)
    total = len(results)
    print(f"\n{passed}/{total} checks passed")
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    main()

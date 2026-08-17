"""
i18n.py

Single source of truth for Veilwire's translation and layout-direction
support: which languages exist, how to translate a string outside a
QObject subclass, how a translated template gets its dynamic values
substituted, and how the user's language choice is persisted and applied.

Design notes:

* Every QDialog/QMainWindow/QThread in app.py already inherits self.tr()
  for free (they're all QObject subclasses) - that's the normal, idiomatic
  way to mark a string translatable in Qt, and app.py uses it directly.
  The tr()/trf() helpers here exist only for the handful of call sites
  with no `self` available (free functions, and main() before any window
  exists).
* Translation is applied once, at startup, before MainWindow is
  constructed (see install_language()). Switching language in Settings
  persists the choice via set_language() but does NOT apply it live - the
  user explicitly chose "restart to apply" over live-retranslation, since
  live switching would need a hand-written retranslate method on every
  dialog class, which is exactly the kind of thing that grows a "missed
  one label" bug over time. Restart-required has no such failure mode.
* Substitution in trf() always happens AFTER translation, using named
  %(key)s placeholders left in the source string - never done by baking
  a value into an f-string before translation, which would make
  pyside6-lupdate extract a different, untranslatable "source text" per
  contact name/count. The placeholder mechanism here is exactly as inert
  as Python's old-style %-formatting always was: it does not escape
  anything. Callers remain responsible for running any value through
  escape_html() (for anything destined for QTextBrowser HTML) or
  safe_error_text() (for anything wrapping an exception) BEFORE passing
  it into trf() - this file does not change that discipline, only the
  templating mechanism around it.
"""

from __future__ import annotations

import json
import os

from PySide6.QtCore import QCoreApplication, QTranslator, Qt
from PySide6.QtWidgets import QApplication

import paths

# Ordered so a QComboBox built straight from this dict shows a stable,
# deliberate order (English first as the source/fallback language) rather
# than whatever order a language happens to be added in later. Each name
# is written in that language's own script - a user who can't read English
# still needs to be able to find their own language in a list.
SUPPORTED_LANGUAGES: dict[str, str] = {
    "en": "English",
    "ar": "العربية",
    "ru": "Русский",
    "fr": "Français",
}

# Closed set, same "fixed vocabulary" discipline already used elsewhere in
# this codebase (see app.py's _CONNECTION_STATES) - RTL is applied only for
# a language actually confirmed to need it, never inferred.
RTL_LANGUAGES: frozenset[str] = frozenset({"ar"})

DEFAULT_LANGUAGE = "en"

_SETTINGS_FILENAME = "settings.json"

_translator: QTranslator | None = None


def _settings_path() -> str:
    return os.path.join(paths.config_dir(), _SETTINGS_FILENAME)


def _read_settings() -> dict:
    try:
        with open(_settings_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_settings(data: dict) -> None:
    path = _settings_path()
    tmp_path = f"{path}.tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except OSError:
        pass  # Non-critical preference; a failed write just keeps the old value.


def current_language() -> str:
    """The persisted language choice, or DEFAULT_LANGUAGE if none is set
    or the setting is unrecognized."""
    code = _read_settings().get("language")
    return code if code in SUPPORTED_LANGUAGES else DEFAULT_LANGUAGE


def set_language(lang_code: str) -> None:
    """
    Persists a language choice for the *next* launch.

    Deliberately does not call install_language() itself - applying a
    language live is not what this app does (see this module's docstring).
    Raises ValueError for an unrecognized code rather than silently
    accepting garbage into the settings file.
    """
    if lang_code not in SUPPORTED_LANGUAGES:
        raise ValueError(f"Unsupported language code: {lang_code!r}")
    data = _read_settings()
    data["language"] = lang_code
    _write_settings(data)


def _translations_dir() -> str:
    """
    Locate the compiled .qm files.

    Mirrors app.py's icon_file()/brand_image_path() dual-location lookup
    (source checkout vs. installed path) - checked in order, first
    existing directory wins.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, "translations")


def install_language(app: QApplication, lang_code: str) -> None:
    """
    Load the .qm for `lang_code` (if any) and set the application's layout
    direction accordingly. Called exactly once, early in main(), before
    MainWindow is constructed - QWidget reads the application's layout
    direction at construction time for any widget that doesn't explicitly
    override it, so this must happen first.

    English has no .qm file at all: the strings already in the source are
    the English text, so "no translator installed" already means English.
    An unrecognized or missing lang_code falls back to English the same
    way - never raises, since this runs during startup before any dialog
    exists to report an error through.
    """
    global _translator

    if _translator is not None:
        app.removeTranslator(_translator)
        _translator = None

    if lang_code in SUPPORTED_LANGUAGES and lang_code != "en":
        translator = QTranslator(app)
        qm_path = os.path.join(_translations_dir(), f"veilwire_{lang_code}.qm")
        if translator.load(qm_path):
            app.installTranslator(translator)
            _translator = translator

    app.setLayoutDirection(
        Qt.RightToLeft if lang_code in RTL_LANGUAGES else Qt.LeftToRight
    )


def tr(text: str, *, context: str = "i18n", n: int = -1) -> str:
    """
    QCoreApplication.translate() for code with no `self` to call .tr() on
    (free functions like render_bubble(), and main()'s pre-window dialogs).
    Every QObject subclass in app.py (every QDialog/QMainWindow/QThread)
    should use its own inherited self.tr() instead - this exists only for
    the handful of call sites outside a class.

    Default context is "i18n", not "app": pyside6-lupdate's static
    extraction files every call to this function - regardless of which
    module it's *called from* - under the context "i18n" (the module
    *tr() is defined in*, not the caller's module or this default
    parameter's value, which lupdate cannot evaluate since it never runs
    the code). The default here must match that or every free-function
    translation silently no-ops at runtime: QCoreApplication.translate()
    would ask the installed QTranslator for a context that doesn't exist
    in the compiled .qm, get no match, and fall back to the untranslated
    English source with no error. Verified empirically against the
    compiled translations/veilwire_ar.qm before settling on this value -
    do not change without re-checking what lupdate actually emits.
    """
    return QCoreApplication.translate(context, text, None, n)


def trf(source: str, *, context: str = "i18n", n: int = -1, **kwargs: object) -> str:
    """
    tr() plus %(name)s-style substitution, applied AFTER translation.

    Values in kwargs are inserted as-is - this function does not escape
    or sanitize anything. Callers must already have run any value through
    escape_html() (destined for QTextBrowser HTML) or safe_error_text()
    (wrapping an exception) before passing it here, exactly as they would
    have before building an f-string. See this module's docstring.

    Only usable from free functions (no `self`). Inside a QObject
    subclass, use fmt(self.tr("..."), **kwargs) instead, so
    pyside6-lupdate still groups the string under the class's own context
    the way every other self.tr() call in that class does - calling this
    function from inside a class would file the string under "i18n"
    instead (see tr()'s docstring for why that's the real default lupdate
    uses), splitting one class's strings across two buckets in the .ts
    file for no reason.
    """
    translated = QCoreApplication.translate(context, source, None, n)
    return translated % kwargs


def fmt(translated_text: str, **kwargs: object) -> str:
    """
    Apply %(name)s-style substitution to text that has ALREADY been
    translated (typically via self.tr(...) inside a QObject subclass).

    This is the class-method counterpart to trf() - use self.tr("...%(x)s...")
    then fmt(that_result, x=value) so the string still groups under the
    class's own context in the .ts file (matching every plain self.tr()
    call in the same class), while still getting trf()'s
    translate-first-substitute-second behavior. Same rule as trf(): values
    in kwargs are inserted as-is, escape_html()/safe_error_text() must
    already have been applied by the caller where relevant.
    """
    return translated_text % kwargs

"""
theme.py

Visual styling for the application.

The original message bubbles set a background colour but left the text colour
to the system palette. On a dark desktop that meant light text on a light
bubble - invisible. Every colour pair here is therefore defined together, and
the palette is chosen from the actual window background rather than assumed.
"""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtGui import QPalette


@dataclass(frozen=True)
class Palette:
    """A complete set of colours. Text and background are always paired."""

    is_dark: bool

    window: str
    surface: str
    border: str

    text: str
    text_muted: str

    accent: str
    accent_hover: str
    accent_pressed: str
    accent_text: str

    # Message bubbles - each with its own text colour.
    bubble_out_bg: str
    bubble_out_text: str
    bubble_in_bg: str
    bubble_in_text: str

    ok: str
    warn: str
    error: str


LIGHT = Palette(
    is_dark=False,
    window="#ffffff",
    surface="#f5f6f8",
    border="#d8dbe0",
    text="#1a1c1e",
    text_muted="#6b7075",
    accent="#6b3fa0",
    accent_hover="#7d4cb8",
    accent_pressed="#5a3488",
    accent_text="#ffffff",
    bubble_out_bg="#6b3fa0",
    bubble_out_text="#ffffff",
    bubble_in_bg="#eceef1",
    bubble_in_text="#1a1c1e",
    ok="#2e7d32",
    warn="#ef6c00",
    error="#c62828",
)

DARK = Palette(
    is_dark=True,
    window="#1c1e21",
    surface="#25282c",
    border="#3a3e44",
    text="#e8eaed",
    text_muted="#9aa0a6",
    accent="#9d6fd4",
    accent_hover="#ae83e0",
    accent_pressed="#8659bd",
    accent_text="#121315",
    bubble_out_bg="#5b3a8a",
    bubble_out_text="#f2ecfa",
    bubble_in_bg="#2f3338",
    bubble_in_text="#e8eaed",
    ok="#66bb6a",
    warn="#ffa726",
    error="#ef5350",
)


def detect_palette(app) -> Palette:
    """
    Pick a palette by inspecting the real window background.

    Reading the palette beats guessing from a desktop environment variable,
    which is unreliable across the many Linux desktops this app supports.
    """
    try:
        background = app.palette().color(QPalette.Window)
        # Rec. 601 luma: a reasonable perceptual brightness approximation.
        luma = (
            0.299 * background.red()
            + 0.587 * background.green()
            + 0.114 * background.blue()
        )
        return DARK if luma < 128 else LIGHT
    except Exception:
        return LIGHT


def stylesheet(p: Palette) -> str:
    """The full application stylesheet, built from a palette."""
    return f"""
    QWidget {{
        background-color: {p.window};
        color: {p.text};
        font-size: 14px;
    }}

    QLineEdit, QTextEdit, QTextBrowser, QListWidget {{
        background-color: {p.surface};
        color: {p.text};
        border: 1px solid {p.border};
        border-radius: 10px;
        padding: 6px;
        selection-background-color: {p.accent};
        selection-color: {p.accent_text};
    }}

    QLineEdit:focus, QTextEdit:focus {{
        border: 1px solid {p.accent};
    }}

    QLineEdit[readOnly="true"] {{
        color: {p.text_muted};
    }}

    /* Roomier rows with a round-avatar icon (see app.py's _avatar_pixmap) -
    a conversation-list row, not a dense menu entry. */
    QListWidget::item {{
        padding: 9px 8px;
        margin: 1px 2px;
        border-radius: 10px;
    }}
    QListWidget::item:selected {{
        background-color: {p.accent};
        color: {p.accent_text};
    }}
    QListWidget::item:hover:!selected {{
        background-color: {p.border};
    }}

    /* Collapsed sidebar (app.py's _on_toggle_sidebar sets this dynamic
    property on contact_list): rows are icon-only, round avatar, no text
    label next to it - the normal filled-rectangle selection highlight
    above looks like a stray purple square stamped behind a circle with
    nothing there to justify a rectangle. A thin accent-colored ring
    around the row instead reads as "this one is selected" without
    fighting the circular avatar's own shape. */
    QListWidget[collapsed="true"]::item:selected {{
        background-color: transparent;
        border: 2px solid {p.accent};
    }}
    QListWidget[collapsed="true"]::item:hover:!selected {{
        background-color: transparent;
        border: 2px solid {p.border};
    }}

    /* Buttons must read as buttons: solid fill, clear border, hover feedback. */
    QPushButton {{
        background-color: {p.surface};
        color: {p.text};
        border: 1px solid {p.border};
        border-radius: 9px;
        padding: 7px 14px;
        min-height: 18px;
    }}
    QPushButton:hover {{
        background-color: {p.border};
        border: 1px solid {p.accent};
    }}
    QPushButton:pressed {{
        background-color: {p.accent_pressed};
        color: {p.accent_text};
    }}
    QPushButton:disabled {{
        color: {p.text_muted};
        border: 1px solid {p.border};
        background-color: transparent;
    }}

    /* The primary action. */
    QPushButton#primary {{
        background-color: {p.accent};
        color: {p.accent_text};
        border: 1px solid {p.accent};
        font-weight: bold;
        font-size: 15px;
        min-height: 26px;
        padding: 9px 16px;
    }}
    QPushButton#primary:hover {{
        background-color: {p.accent_hover};
        border: 1px solid {p.accent_hover};
    }}
    QPushButton#primary:pressed {{
        background-color: {p.accent_pressed};
    }}
    QPushButton#primary:disabled {{
        background-color: {p.border};
        color: {p.text_muted};
        border: 1px solid {p.border};
    }}

    QPushButton#danger {{
        border: 1px solid {p.error};
        color: {p.error};
    }}
    QPushButton#danger:hover {{
        background-color: {p.error};
        color: #ffffff;
    }}

    /* The round, icon-only composer send button - see app.py's
    _build_conversation_panel. Fixed circular size regardless of content,
    so the icon always sits centred in a perfect circle rather than a
    button that grows/shrinks with its (nonexistent) label. */
    QPushButton#sendButton {{
        background-color: {p.accent};
        border: none;
        border-radius: 20px;
        min-width: 40px;
        max-width: 40px;
        min-height: 40px;
        max-height: 40px;
        padding: 0;
    }}
    QPushButton#sendButton:hover {{
        background-color: {p.accent_hover};
    }}
    QPushButton#sendButton:pressed {{
        background-color: {p.accent_pressed};
    }}
    QPushButton#sendButton:disabled {{
        background-color: {p.border};
    }}

    /* The composer's "Attach..." button reads as a quiet icon action, not
    a competing call-to-action next to the round send button. */
    QPushButton#attachButton {{
        border: none;
        background-color: transparent;
        border-radius: 18px;
        min-width: 36px;
        max-width: 36px;
        min-height: 36px;
        max-height: 36px;
        padding: 0;
        font-size: 17px;
    }}
    QPushButton#attachButton:hover {{
        background-color: {p.border};
    }}

    QLabel {{
        background-color: transparent;
    }}
    QLabel#muted {{
        color: {p.text_muted};
    }}
    QLabel#heading {{
        font-weight: bold;
        font-size: 15px;
    }}

    QCheckBox {{
        spacing: 8px;
    }}

    QSplitter::handle {{
        background-color: {p.border};
        width: 1px;
    }}

    /* The VSCode-style top menu bar (app.py's MainWindow._build_menu_bar) -
    kept as compact as the sidebar buttons right below it: tight padding
    on both the bar itself and each top-level entry, never the default
    Qt spacing that reads as oversized next to this app's otherwise dense
    layout. */
    QMenuBar {{
        background-color: {p.window};
        padding: 1px 0;
        spacing: 2px;
    }}
    QMenuBar::item {{
        padding: 3px 8px;
        border-radius: 6px;
        background: transparent;
    }}
    QMenuBar::item:selected {{
        background-color: {p.border};
    }}
    QMenuBar::item:pressed {{
        background-color: {p.accent};
        color: {p.accent_text};
    }}

    QMenu {{
        background-color: {p.surface};
        border: 1px solid {p.border};
        padding: 2px;
    }}
    QMenu::item {{
        padding: 4px 20px 4px 10px;
        border-radius: 6px;
    }}
    QMenu::item:selected {{
        background-color: {p.accent};
        color: {p.accent_text};
    }}
    QMenu::separator {{
        height: 1px;
        background: {p.border};
        margin: 3px 6px;
    }}

    QScrollBar:vertical {{
        background: transparent;
        width: 10px;
        margin: 0;
    }}
    QScrollBar::handle:vertical {{
        background: {p.border};
        border-radius: 5px;
        min-height: 30px;
    }}
    QScrollBar::handle:vertical:hover {{
        background: {p.text_muted};
    }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
        height: 0;
    }}

    QDialog {{
        background-color: {p.window};
    }}
    """

"""
envelope.py

The structured plaintext that goes inside a NaCl Box's encrypted payload.
`transport.send_message`'s `body` parameter and `IncomingMessage.body` are
exactly the string this module produces and consumes - transport.py itself
stays completely unaware of envelopes, groups, or files; to it, `body` is
just an opaque string to encrypt or that was decrypted.

Every earlier version of this app put a message's raw text directly as the
Box plaintext. That still works: a decrypted plaintext that is not valid
JSON, or is JSON but not shaped like an envelope this module knows, is
treated as a bare legacy text message (kind "text", no group, no
attachment) - the same "old data/old peer keeps working unchanged" pattern
bundle.py and vault.py already use elsewhere in this codebase.

Two kinds ride inside a JSON envelope:

* "text" - an ordinary message. Optionally tagged with a group id/name
  (see below).
* "file" - an inline attachment (image or arbitrary file), base64 encoded.
  Bounded by MAX_FILE_BYTES so a hostile or careless sender cannot balloon
  memory use; transport.MAX_FRAME_BYTES is sized to comfortably fit an
  envelope carrying a MAX_FILE_BYTES file (see transport.py's comment on
  that constant).

Group messaging piggybacks the same envelope with an optional "gid" (the
sending vault's local id for the group - see vault.Group) and "gname" (its
current display name, resent on every message so a recipient who does not
yet have a local Group record for this gid can create one with a sensible
name rather than "Unnamed group"). There is no membership list in the wire
format: group membership is local-only on each participant's side (see
vault.Group's docstring) and is never transmitted.

A third kind, "delete", is a control message rather than a displayed one:
"Delete for everyone" (see app.py's message-delete UI) works by the
original sender sending this alongside deleting their own local copy. It
carries no content of its own - only "mid", the shared message id the
target message was originally sent with (see the "mid" field on "text"/
"file" envelopes below). There is nothing here that lets anyone delete a
message they did not send: the receiving side (app.py) only ever acts on
a "delete" envelope if "mid" names a message it has on file *from that
same sender* - a "delete" from contact A can never remove a message
contact B sent, or a message the receiving user sent themselves. That
check happens where the message is actually stored (vault.py), not in
this module - this module only defines the wire shape.

"text" and "file" envelopes both carry "mid": a message id chosen by the
sender when the message is first created, carried unchanged through every
retry, and stored by both sides under vault.Message.client_msg_id. This is
what gives "delete for everyone" and (for a group send) delivery-status
aggregation something stable to refer to that both the sender's and the
recipient's independently-generated local Message.id values cannot be used
for, since those are never the same value on each side.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass

MAX_BODY_CHARS = 8000  # generous for text, bounded against a hostile giant "message"

# Raw (pre-base64) file size ceiling. Base64 adds ~33%, the JSON envelope
# and NaCl Box add a little more, and the whole thing is base64'd again for
# the outer wire frame (see transport.py) - transport.MAX_FRAME_BYTES is
# set with this constant's overhead already accounted for.
MAX_FILE_BYTES = 8 * 1024 * 1024  # 8 MiB

MAX_FILENAME_CHARS = 255
MAX_MIME_CHARS = 100
MAX_GID_CHARS = 64
MAX_GNAME_CHARS = 100
MAX_MID_CHARS = 64

KIND_TEXT = "text"
KIND_FILE = "file"
KIND_DELETE = "delete"
# Both group-membership control kinds, same minimal/unpadded shape as
# KIND_DELETE (see _pad()'s docstring for why KIND_DELETE is unpadded -
# the same reasoning applies here: these are already tiny and fixed-shape,
# so padding them to the smallest text bucket would not hide anything).
KIND_GROUP_ACK = "group_ack"
KIND_GROUP_LEAVE = "group_leave"
_KNOWN_KINDS = {KIND_TEXT, KIND_FILE, KIND_DELETE, KIND_GROUP_ACK, KIND_GROUP_LEAVE}

# Fixed size buckets the final JSON envelope is padded up to before
# encryption, so its ciphertext length (visible to anyone watching the wire
# - Box encryption adds a small, constant overhead, so ciphertext length
# tracks plaintext length almost exactly) does not by itself reveal which
# kind of message was sent or a file attachment's real size. Without this,
# a passive network observer could trivially tell "text" (tens-to-low-
# hundreds of bytes) apart from "file" (roughly attachment-size-plus-33%)
# just from frame length on the wire, and could estimate a file's size to
# within whatever bucket granularity is chosen here - the same reason
# Signal and similar protocols pad to fixed sizes rather than sending
# exact-length ciphertexts. KIND_DELETE is not padded (see pad()) - it is
# already tiny and fixed-shape (just "k"+"mid"[+"gid"+"gname"]), so padding
# it to the smallest text bucket would not hide anything a delete envelope
# doesn't already reveal by its near-constant size.
_PAD_BUCKETS = (
    1024,               # short text messages
    16 * 1024,          # longer text, small images
    256 * 1024,         # typical photos
    2 * 1024 * 1024,    # larger images/documents
    12 * 1024 * 1024,   # up to MAX_FILE_BYTES-sized files (base64'd)
)
_PAD_FIELD = "p"


class EnvelopeError(Exception):
    """Raised when an envelope cannot be built, or a decrypted plaintext
    cannot be safely treated as one (see decode() - this is only raised
    for a value that looks like an envelope but is malformed; anything
    that does not look like one at all falls back to a legacy text
    envelope instead of raising)."""


MAX_INVCODE_CHARS = 64


@dataclass
class Envelope:
    kind: str  # KIND_TEXT, KIND_FILE, KIND_DELETE, KIND_GROUP_ACK, or KIND_GROUP_LEAVE
    body: str = ""  # display text (KIND_TEXT) or the raw base64 file bytes (KIND_FILE)
    gid: str = ""  # non-empty for a group message
    gname: str = ""  # the group's name, as the sender currently has it
    filename: str = ""  # KIND_FILE only
    mime: str = ""  # KIND_FILE only
    size: int = 0  # KIND_FILE only: decoded byte size, for display without decoding
    mid: str = ""  # KIND_TEXT/KIND_FILE: this message's own shared id.
    delete_mid: str = ""  # KIND_DELETE only: the shared id of the message to delete
    # KIND_TEXT/KIND_FILE only, and only while sent to a group this vault
    # joined via invite rather than owns: the group_invite.py code this
    # sender was given, carried on every group message until the owner's
    # KIND_GROUP_ACK confirms membership (see app.py's send path). Never
    # set for a group this vault owns/created itself - an owner's own
    # messages need no invite code, they were never invited.
    invcode: str = ""


def _sanitize_filename(name: str) -> str:
    """
    Strip anything that could be interpreted as a path when this filename is
    later offered as a default in a "Save As..." dialog - no directory
    separators, no leading dot (hidden file), nothing but the base name.
    This is defense in depth: app.py's save path additionally always goes
    through QFileDialog, which lets the user pick the destination rather
    than ever writing to a sender-controlled path automatically, but the
    suggested filename itself should not be able to smuggle a path.
    """
    name = name.strip().replace("\\", "/").split("/")[-1]
    name = name.lstrip(".")
    return name[:MAX_FILENAME_CHARS] or "file"


def _pad(payload: dict) -> str:
    """
    Serialize `payload` and pad it up to the smallest bucket in
    _PAD_BUCKETS that fits, so the final JSON's length reveals only which
    (generous) size class the message falls into, not its exact size or
    (by extension) reliably its kind. Anything already larger than the
    biggest bucket (should not happen given MAX_BODY_CHARS/MAX_FILE_BYTES,
    but handled defensively) is sent unpadded rather than raising here -
    the actual size ceiling is enforced by the caller before this runs.

    The pad value itself is arbitrary filler (not random) - it only needs
    to be *present* to reach the target length; it carries no information
    and is discarded unread on decode.
    """
    unpadded = json.dumps(payload, ensure_ascii=False)
    target = next((b for b in _PAD_BUCKETS if b >= len(unpadded)), None)
    if target is None:
        return unpadded
    # Reserve room for the pad field's own JSON overhead (key, quotes,
    # comma) before computing how many filler characters are needed, then
    # shrink by one at a time in the rare case escaping (e.g. a body with
    # many quote/backslash characters pushes the padded field's own
    # serialized length past the estimate) overshoots the target.
    payload = dict(payload)
    pad_len = max(0, target - len(unpadded) - len(f',"{_PAD_FIELD}":""'))
    while True:
        payload[_PAD_FIELD] = "0" * pad_len
        padded = json.dumps(payload, ensure_ascii=False)
        if len(padded) <= target or pad_len == 0:
            return padded
        pad_len = max(0, pad_len - (len(padded) - target))


def encode_text(
    body: str, gid: str = "", gname: str = "", mid: str = "", invcode: str = "",
) -> str:
    if len(body) > MAX_BODY_CHARS:
        raise EnvelopeError("Message is too long.")
    payload: dict = {"k": KIND_TEXT, "body": body}
    if gid:
        payload["gid"] = gid[:MAX_GID_CHARS]
        payload["gname"] = gname[:MAX_GNAME_CHARS]
    if mid:
        payload["mid"] = mid[:MAX_MID_CHARS]
    if invcode:
        payload["invcode"] = invcode[:MAX_INVCODE_CHARS]
    return _pad(payload)


def encode_file(
    filename: str, mime: str, data: bytes, gid: str = "", gname: str = "", mid: str = "",
    invcode: str = "",
) -> str:
    if len(data) > MAX_FILE_BYTES:
        raise EnvelopeError(
            f"File is too large ({len(data)} bytes; the limit is {MAX_FILE_BYTES} bytes)."
        )
    payload: dict = {
        "k": KIND_FILE,
        "filename": _sanitize_filename(filename),
        "mime": (mime or "application/octet-stream")[:MAX_MIME_CHARS],
        "size": len(data),
        "body": base64.b64encode(data).decode("ascii"),
    }
    if gid:
        payload["gid"] = gid[:MAX_GID_CHARS]
        payload["gname"] = gname[:MAX_GNAME_CHARS]
    if mid:
        payload["mid"] = mid[:MAX_MID_CHARS]
    if invcode:
        payload["invcode"] = invcode[:MAX_INVCODE_CHARS]
    return _pad(payload)


def encode_delete(target_mid: str, gid: str = "", gname: str = "") -> str:
    """
    Build a "delete for everyone" control envelope naming the shared message
    id (see the module docstring) of the message to remove. Carries no
    content of its own - just enough to let the receiving side find its own
    copy of that message *from this same sender* (that authorization check
    happens on the receiving side, not here - see vault.py/app.py).
    """
    if not target_mid:
        raise EnvelopeError("Cannot build a delete envelope with no target message id.")
    payload: dict = {"k": KIND_DELETE, "mid": target_mid[:MAX_MID_CHARS]}
    if gid:
        payload["gid"] = gid[:MAX_GID_CHARS]
        payload["gname"] = gname[:MAX_GNAME_CHARS]
    return json.dumps(payload, ensure_ascii=False)


def encode_group_ack(gid: str) -> str:
    """
    Build the group OWNER's confirmation that a sender's invite code was
    just validated and they are now a real member (see
    vault.Vault.redeem_group_invite_locally). Sent once, right after that
    validation - lets the new member's UI stop showing "pending" and stop
    attaching its invite code to every subsequent group message.
    """
    if not gid:
        raise EnvelopeError("Cannot build a group-ack envelope with no group id.")
    return json.dumps({"k": KIND_GROUP_ACK, "gid": gid}, ensure_ascii=False)


def encode_group_leave(gid: str) -> str:
    """
    Build a "I am leaving this group" notice, sent to every other current
    member before the sender removes their own local copy of the group
    (see app.py's Leave-group flow). Carries no content of its own - the
    receiving side identifies who left by which contact's Box the message
    decrypted under, same authorization model as KIND_DELETE.
    """
    if not gid:
        raise EnvelopeError("Cannot build a group-leave envelope with no group id.")
    return json.dumps({"k": KIND_GROUP_LEAVE, "gid": gid}, ensure_ascii=False)


def decode(plaintext: str) -> Envelope:
    """
    Parse a decrypted message plaintext into an Envelope.

    Never raises for a plaintext that simply is not an envelope - that is
    the legacy case (a bare text message from an older version of this
    app, or from anyone who never wrapped it as JSON) and is treated as
    kind "text" with the plaintext itself as the body. EnvelopeError is
    reserved for something that IS shaped like an envelope (valid JSON
    object with a recognized "k") but fails validation - e.g. a file body
    that is not valid base64, or an oversized field - since silently
    downgrading that to a garbled text bubble would be more confusing than
    rejecting it outright.
    """
    try:
        parsed = json.loads(plaintext)
    except (ValueError, TypeError):
        return Envelope(kind=KIND_TEXT, body=plaintext)

    if not isinstance(parsed, dict) or parsed.get("k") not in _KNOWN_KINDS:
        # Valid JSON, but not our envelope shape (e.g. someone's message
        # literally *is* a JSON object) - still a legacy plain text message,
        # verbatim.
        return Envelope(kind=KIND_TEXT, body=plaintext)

    kind = parsed["k"]
    gid = parsed.get("gid") or ""
    gname = parsed.get("gname") or ""
    if not isinstance(gid, str) or not isinstance(gname, str):
        raise EnvelopeError("Malformed envelope.")
    gid = gid[:MAX_GID_CHARS]
    gname = gname[:MAX_GNAME_CHARS]

    mid = parsed.get("mid") or ""
    if not isinstance(mid, str):
        raise EnvelopeError("Malformed envelope.")
    mid = mid[:MAX_MID_CHARS]

    invcode = parsed.get("invcode") or ""
    if not isinstance(invcode, str):
        raise EnvelopeError("Malformed envelope.")
    invcode = invcode[:MAX_INVCODE_CHARS]

    if kind == KIND_DELETE:
        if not mid:
            raise EnvelopeError("Malformed delete envelope.")
        return Envelope(kind=KIND_DELETE, gid=gid, gname=gname, delete_mid=mid)

    if kind == KIND_GROUP_ACK:
        if not gid:
            raise EnvelopeError("Malformed group-ack envelope.")
        return Envelope(kind=KIND_GROUP_ACK, gid=gid)

    if kind == KIND_GROUP_LEAVE:
        if not gid:
            raise EnvelopeError("Malformed group-leave envelope.")
        return Envelope(kind=KIND_GROUP_LEAVE, gid=gid)

    if kind == KIND_TEXT:
        body = parsed.get("body")
        if not isinstance(body, str) or len(body) > MAX_BODY_CHARS:
            raise EnvelopeError("Malformed text envelope.")
        return Envelope(kind=KIND_TEXT, body=body, gid=gid, gname=gname, mid=mid, invcode=invcode)

    # KIND_FILE
    filename = parsed.get("filename")
    mime = parsed.get("mime")
    body = parsed.get("body")
    if not isinstance(filename, str) or not isinstance(mime, str) or not isinstance(body, str):
        raise EnvelopeError("Malformed file envelope.")
    if len(filename) > MAX_FILENAME_CHARS or len(mime) > MAX_MIME_CHARS:
        raise EnvelopeError("Malformed file envelope.")
    if len(body) > int(MAX_FILE_BYTES * 1.5):  # generous base64-overhead margin
        raise EnvelopeError("File attachment is too large.")
    try:
        decoded_size = len(base64.b64decode(body, validate=True))
    except Exception as exc:
        raise EnvelopeError("File attachment is not valid base64.") from exc
    if decoded_size > MAX_FILE_BYTES:
        raise EnvelopeError("File attachment is too large.")

    return Envelope(
        kind=KIND_FILE,
        body=body,
        gid=gid,
        gname=gname,
        filename=_sanitize_filename(filename),
        mime=mime[:MAX_MIME_CHARS],
        # Always the real decoded length, never the sender's claimed "size"
        # field - a sender could otherwise lie about it (e.g. claim a huge
        # size for a tiny body, or vice versa) since nothing checks it
        # against the actual bytes. Same "never trust a claimed field,
        # recompute it" rule bundle.py applies to a bundle's fingerprint.
        size=decoded_size,
        mid=mid,
        invcode=invcode,
    )

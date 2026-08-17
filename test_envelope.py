"""
Tests for envelope.py: the structured plaintext carried inside a NaCl Box
payload (see envelope.py's module docstring and transport.py's `body`).

Run without Tor or a vault - pure encode/decode logic.
"""

from __future__ import annotations

import base64
import json

import envelope

results: list[tuple[str, bool]] = []


def check(label: str, condition: bool) -> None:
    results.append((label, condition))
    print(f"  {'PASS' if condition else 'FAIL'}  {label}")


def main() -> None:
    print("Legacy plaintext fallback:")
    env = envelope.decode("just a plain old message, not JSON at all")
    check("legacy plaintext decodes as kind text", env.kind == envelope.KIND_TEXT)
    check("legacy plaintext body preserved verbatim", env.body == "just a plain old message, not JSON at all")
    check("legacy plaintext has no group tag", env.gid == "")

    env2 = envelope.decode('{"unrelated": "json object, not an envelope"}')
    check("unrelated JSON object falls back to legacy text", env2.kind == envelope.KIND_TEXT)
    check("unrelated JSON object body preserved as raw text", env2.body == '{"unrelated": "json object, not an envelope"}')

    print("\nText envelope round-trip:")
    wire = envelope.encode_text("hello there")
    decoded = envelope.decode(wire)
    check("kind is text", decoded.kind == envelope.KIND_TEXT)
    check("body round-trips", decoded.body == "hello there")
    check("no group tag on a 1:1 message", decoded.gid == "")

    print("\nText envelope with group tag:")
    wire_g = envelope.encode_text("hi group", gid="abc123", gname="Friends")
    decoded_g = envelope.decode(wire_g)
    check("gid round-trips", decoded_g.gid == "abc123")
    check("gname round-trips", decoded_g.gname == "Friends")
    check("body round-trips", decoded_g.body == "hi group")

    print("\nOversized text is rejected at encode time:")
    try:
        envelope.encode_text("x" * (envelope.MAX_BODY_CHARS + 1))
        check("oversized text raises EnvelopeError", False)
    except envelope.EnvelopeError:
        check("oversized text raises EnvelopeError", True)

    print("\nFile envelope round-trip:")
    data = bytes(range(256)) * 100  # 25.6 KB, deterministic content
    wire_f = envelope.encode_file("photo.png", "image/png", data)
    decoded_f = envelope.decode(wire_f)
    check("kind is file", decoded_f.kind == envelope.KIND_FILE)
    check("filename round-trips", decoded_f.filename == "photo.png")
    check("mime round-trips", decoded_f.mime == "image/png")
    check("size matches original data", decoded_f.size == len(data))
    check("decoded body base64-decodes back to original bytes", base64.b64decode(decoded_f.body) == data)

    print("\nFile envelope with group tag:")
    wire_fg = envelope.encode_file("doc.txt", "text/plain", b"contents", gid="g1", gname="Team")
    decoded_fg = envelope.decode(wire_fg)
    check("gid round-trips on a file envelope", decoded_fg.gid == "g1")
    check("gname round-trips on a file envelope", decoded_fg.gname == "Team")

    print("\nFilename sanitization (no path traversal into a Save As default):")
    wire_path = envelope.encode_file("../../etc/passwd", "text/plain", b"x")
    decoded_path = envelope.decode(wire_path)
    check("directory components stripped from filename", decoded_path.filename == "passwd")
    check("no slash survives in filename", "/" not in decoded_path.filename)

    wire_hidden = envelope.encode_file("...secret", "text/plain", b"x")
    decoded_hidden = envelope.decode(wire_hidden)
    check("leading dots stripped from filename", not decoded_hidden.filename.startswith("."))

    print("\nOversized file is rejected at encode time:")
    try:
        envelope.encode_file("big.bin", "application/octet-stream", b"\x00" * (envelope.MAX_FILE_BYTES + 1))
        check("oversized file raises EnvelopeError", False)
    except envelope.EnvelopeError:
        check("oversized file raises EnvelopeError", True)

    print("\nMalformed / hostile envelopes are rejected, not silently garbled:")
    bad_b64 = json.dumps({"k": "file", "filename": "a", "mime": "text/plain", "body": "not-valid-base64!!!", "size": 1})
    try:
        envelope.decode(bad_b64)
        check("invalid base64 file body raises EnvelopeError", False)
    except envelope.EnvelopeError:
        check("invalid base64 file body raises EnvelopeError", True)

    missing_field = json.dumps({"k": "file", "mime": "text/plain", "body": "eA=="})
    try:
        envelope.decode(missing_field)
        check("file envelope missing filename raises EnvelopeError", False)
    except envelope.EnvelopeError:
        check("file envelope missing filename raises EnvelopeError", True)

    non_dict = json.dumps([1, 2, 3])
    decoded_list = envelope.decode(non_dict)
    check("a JSON array (not an object) falls back to legacy text", decoded_list.kind == envelope.KIND_TEXT)
    check("legacy fallback body is the raw JSON text", decoded_list.body == non_dict)

    huge_declared_size_but_small_body = json.dumps({
        "k": "file", "filename": "a", "mime": "text/plain",
        "body": base64.b64encode(b"tiny").decode(), "size": 999999999,
    })
    decoded_liar = envelope.decode(huge_declared_size_but_small_body)
    check(
        "declared size field is not trusted over the actual decoded length",
        decoded_liar.size == len(base64.b64decode(decoded_liar.body)),
    )

    print("\n'mid' (shared message id) round-trips on text/file envelopes:")
    wire_mid = envelope.encode_text("hi", mid="msg-1")
    check("mid round-trips on a text envelope", envelope.decode(wire_mid).mid == "msg-1")

    wire_f_mid = envelope.encode_file("a.txt", "text/plain", b"x", mid="msg-2")
    check("mid round-trips on a file envelope", envelope.decode(wire_f_mid).mid == "msg-2")

    wire_no_mid = envelope.encode_text("hi")
    check("mid is empty when not given", envelope.decode(wire_no_mid).mid == "")

    legacy_env = envelope.decode("plain legacy text, no envelope at all")
    check("legacy plaintext has no mid", legacy_env.mid == "")

    print("\n'delete' control envelope:")
    wire_del = envelope.encode_delete("target-mid-1")
    decoded_del = envelope.decode(wire_del)
    check("kind is delete", decoded_del.kind == envelope.KIND_DELETE)
    check("delete_mid round-trips", decoded_del.delete_mid == "target-mid-1")
    check("a delete envelope carries no body content", decoded_del.body == "")

    wire_del_g = envelope.encode_delete("target-mid-2", gid="g1", gname="Team")
    decoded_del_g = envelope.decode(wire_del_g)
    check("delete envelope gid round-trips", decoded_del_g.gid == "g1")
    check("delete envelope gname round-trips", decoded_del_g.gname == "Team")

    try:
        envelope.encode_delete("")
        check("delete envelope with no target mid is rejected at encode time", False)
    except envelope.EnvelopeError:
        check("delete envelope with no target mid is rejected at encode time", True)

    missing_mid_delete = json.dumps({"k": "delete"})
    try:
        envelope.decode(missing_mid_delete)
        check("delete envelope missing mid is rejected at decode time", False)
    except envelope.EnvelopeError:
        check("delete envelope missing mid is rejected at decode time", True)

    print("\nA legacy peer that has never heard of 'delete' just ignores an unknown mid field:")
    ignored_mid = json.dumps({"k": "text", "body": "hello", "mid": "some-id"})
    decoded_ignored = envelope.decode(ignored_mid)
    check("unrecognized-to-old-code 'mid' field does not break ordinary text decoding", decoded_ignored.body == "hello")

    passed = sum(1 for _, ok in results if ok)
    print(f"\n{passed}/{len(results)} checks passed")
    if passed != len(results):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

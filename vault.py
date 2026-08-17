"""
vault.py

The encrypted local store. Everything the application persists lives here:

* the user's identity (X25519 keypair + the Tor onion service private key)
* contacts (their onion address and public key)
* message history

The whole file is encrypted with a key derived from the user's passphrase.
On disk it is a single opaque blob - an attacker who copies the file learns
nothing beyond its size without the passphrase.

File layout (the only unencrypted parts are the format marker and the KDF
salt, both of which are not secret):

    ONIONMSG1 | 16-byte salt | SecretBox ciphertext
"""

from __future__ import annotations

import base64
import json
import logging
import os
import shutil
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from nacl.signing import SigningKey

import bundle as bundle_mod
import crypto
import group_invite as invite_mod
import paths

_logger = logging.getLogger("veilwire")

MAGIC = b"ONIONMSG1"
IDENTITY_MAGIC = b"ONIONMSGID1"
DEFAULT_FILENAME = "vault.dat"

# Cosmetic field, but unbounded attacker-supplied length would still let a
# remote contact bloat the vault file and the contact list UI.
MAX_CONTACT_NAME_LENGTH = 100


class VaultLocked(Exception):
    """Raised when an operation needs an unlocked vault."""


# Delivery state of an outgoing message.
SENT = "sent"        # confirmed delivered and acknowledged
QUEUED = "queued"    # recipient was offline; will be retried automatically
FAILED = "failed"    # gave up, or rejected by the recipient


@dataclass
class Message:
    id: str
    contact_id: str
    direction: str  # "out" or "in"
    timestamp: str  # ISO 8601 UTC
    body: str
    delivered: bool = True
    note: str = ""  # e.g. a delivery failure reason
    status: str = SENT
    attempts: int = 0
    last_attempt: str = ""
    # Group messaging (added for the group-chat feature; "" on every
    # message that predates it or that isn't part of a group, so old vault
    # files keep loading unchanged - same migration pattern as
    # Contact.signing_public_key above).
    #
    # group_id: non-empty for a group message. There is no server, so a
    # "group" is simply this vault's own local label for a set of contacts
    # (see Group below) - a group message is really N individually
    # Box-encrypted 1:1 sends, one per member, each stored as an ordinary
    # Message on that member Contact's own messages list. group_id is what
    # lets the UI pull them back out and render them together as one
    # thread instead of N separate contact conversations.
    group_id: str = ""
    # client_msg_id: shared by every per-member copy of the SAME outgoing
    # group message (one Message per member, N Messages, one client_msg_id)
    # so the UI can collapse them into a single bubble and show an
    # aggregate delivery count ("Delivered to 2/3") instead of N duplicate
    # bubbles. Irrelevant for incoming messages and for ordinary 1:1
    # messages, which is why it is not simply reusing `id`.
    client_msg_id: str = ""
    # sender_contact_id: for an incoming group message, the id of the
    # member contact who actually sent it (this Message is stored under
    # that same contact's messages list, so it is redundant with the list
    # it lives in - kept anyway so the UI does not have to thread contact
    # identity through separately when flattening several members' lists
    # into one merged, timestamp-sorted view). Empty for outgoing messages
    # (direction "out" already means "sent by me", same convention 1:1
    # threads already use) and for non-group messages.
    sender_contact_id: str = ""
    # File/image attachment (added for the file-transfer feature). Empty
    # for an ordinary text message. When set, `body` holds the raw base64
    # file bytes (the same base64 the wire envelope carried - see
    # envelope.py) rather than display text, and attachment_filename /
    # attachment_mime describe it. Kept inside the same encrypted vault.dat
    # as everything else rather than ever being auto-written to a loose
    # file on disk - the user explicitly chooses where to save it (see
    # app.py's "Save As...").
    attachment_filename: str = ""
    attachment_mime: str = ""
    attachment_size: int = 0
    # "Delete for everyone" (added for the message-deletion feature; default
    # False so old vault files keep loading unchanged - same migration
    # pattern as every other field on this dataclass).
    #
    # deleted: this message has been tombstoned - its content is gone
    # (mark_deleted() scrubs body/attachment_* below) but the row itself is
    # kept, in place, so the thread still shows *that* something was sent
    # and deleted rather than leaving a confusing gap or reordering
    # everything else. Set on the sender's own copy when they choose to
    # delete a message they sent, and set on a recipient's copy when a
    # "delete" envelope arrives (see envelope.py) - never set on a message
    # by anyone other than the contact who originally sent it; that check
    # happens in mark_deleted()'s caller (app.py), which only ever applies
    # it to a message whose direction/sender already matches the delete
    # request's sender. See mark_deleted() below.
    deleted: bool = False
    # is_delete_request: this Message row is not a displayed chat message at
    # all - it is a synthetic outgoing entry (direction "out") queued so the
    # existing retry/delivery-worker machinery (queued_messages(),
    # mark_message()) can carry a "delete" envelope (see envelope.py) to the
    # peer(s) the same battle-tested way it already carries "text"/"file"
    # envelopes, without inventing a second delivery path. Its client_msg_id
    # is the id of the message being deleted (not its own), and its body is
    # always empty. See queue_delete_request() below.
    is_delete_request: bool = False
    # pending_invcode: set only on an OUTGOING group message's per-member
    # copy (direction "out", group_id non-empty) when this particular
    # member was directly added (create_group()/"Add/remove members", not
    # invite-redeemed - see Group.pending_onboard_contact_ids) and this
    # copy is the one embedding their individually-minted, single-use
    # invite code. app.py's _wire_body_for reads this back on every
    # retry so a queued/failed onboarding send keeps proving invitation
    # with the SAME code rather than losing it (falling back to the
    # plain shared envelope, which the recipient's client would then
    # have no local Group record to accept at all) or minting a fresh
    # one on every retry (which would silently invalidate the previous
    # code with each attempt via create_group_invite's unlimited
    # issuance, wasting invite records for no reason). Empty for every
    # other message - an ordinary group send, a 1:1 send, an incoming
    # message, all leave this "".
    pending_invcode: str = ""


# A contact is in exactly one of these states.
STATUS_ACCEPTED = "accepted"   # normal contact, can exchange messages
STATUS_PENDING = "pending"     # reached out to us; awaiting our decision
STATUS_BLOCKED = "blocked"     # explicitly refused; messages are dropped


@dataclass
class Contact:
    id: str
    name: str
    onion: str
    public_key: str  # base64
    added: str
    status: str = STATUS_ACCEPTED
    verified: bool = False  # fingerprint confirmed out of band by the user
    messages: list[Message] = field(default_factory=list)
    # Ed25519 public key from the bundle this contact was added from, if
    # any (base64). Empty for a contact added via the legacy plaintext
    # onionmsg:onion:pubkey address, which carries no signature - default
    # empty so old vault files (and the legacy add path) keep working
    # unchanged. Remembered so a later bundle claiming to be the same
    # contact but with a different onion can be checked for a matching
    # signing key rather than only compared by onion string.
    signing_public_key: str = ""

    @property
    def fingerprint(self) -> str:
        """Short code to compare with this contact over a trusted channel."""
        return crypto.fingerprint(self.public_key)

    @property
    def address(self) -> str:
        """
        The full legacy plaintext address for this contact
        (onionmsg:<onion>:<public key>).

        Kept for internal/backward use (the legacy add_contact path still
        parses this format), but this is deliberately NOT what the normal
        UI shows or copies any more - it prints the onion in the clear.
        Use bundle.build_bundle() for anything user-facing.
        """
        return format_address(self.onion, self.public_key)

    @property
    def last_activity(self) -> str:
        if self.messages:
            return max(m.timestamp for m in self.messages)
        return self.added


# Cosmetic bound, same reasoning as MAX_CONTACT_NAME_LENGTH.
MAX_GROUP_NAME_LENGTH = 100
# A group with no members would just be a private notes file to yourself
# under a confusing UI, and one with an unbounded member count means an
# outgoing message fans out to that many individual Tor sends per message -
# generous for real small-group use, bounded to keep a single send from
# taking arbitrarily long.
MAX_GROUP_MEMBERS = 50

# How long a freshly created invite remains redeemable, in hours - offered
# as a small fixed set of choices in the UI (see app.py), not a free-form
# value, so an "expiry" is always one of a few well-understood windows.
INVITE_EXPIRY_CHOICES_HOURS = (1, 24, 24 * 7)

# Ceiling on how many attachment bytes (base64-encoded, i.e. what is
# actually stored in Message.body) a single contact's INCOMING messages may
# accumulate across the whole message history. envelope.MAX_FILE_BYTES
# already bounds any one file, but nothing previously bounded the *count* -
# an accepted-but-hostile contact could otherwise send an unbounded stream
# of maximum-size files and slowly fill the user's disk via vault.dat's
# growth (each one re-encrypting and rewriting the entire vault on save,
# too). 500 MiB is generous for legitimate use (dozens of photos/documents
# from one contact) while still being a real ceiling. Only applied to
# incoming attachments (direction == "in") - the user's own outgoing sends
# are never refused by their own vault.
MAX_ATTACHMENT_BYTES_PER_CONTACT = 500 * 1024 * 1024


@dataclass
class Group:
    """
    A group is this vault's own local label for a set of already-added
    contacts - there is no server, so there is no shared, authoritative
    group roster the way a centralized chat app has one. Each participant
    creates a Group on their own side naming the same members; sending a
    group message is really N individually Box-encrypted, individually
    Tor-delivered 1:1 sends (see Vault.send-side helpers in app.py), tagged
    with this group's id so every member's client can render them together.

    Because membership lives only in each member's own vault, adding or
    removing a member on your side does not change what anyone else's
    client shows - same as the rest of this app's "no shared state,
    nothing to synchronize" design, just applied to groups instead of
    contacts. This is a real limitation (see README) worth being upfront
    about rather than implying a synced roster that does not exist.
    """

    id: str
    name: str
    created: str
    member_contact_ids: list[str] = field(default_factory=list)
    # Contacts explicitly removed via remove_group_member(), as opposed to
    # a contact who simply never joined. An incoming group-tagged message
    # from a sender not currently in member_contact_ids is normally
    # auto-added (see app.py's _file_incoming_group_message - that's what
    # lets a group show up at all with no server to coordinate an invite
    # flow). Without this set, that auto-add logic cannot tell "never
    # joined" apart from "the user removed them on purpose", so a removed
    # member could silently rejoin just by sending one more group message.
    # Checked before auto-adding; NOT cleared by add_group_member(), since
    # only a deliberate action (re-adding via the group's member-management
    # UI, which calls remove-from-removed explicitly) should undo a removal.
    removed_contact_ids: list[str] = field(default_factory=list)
    # Empty string means "this vault's own identity owns this group" (it
    # was created locally via create_group()) - there is no separate id
    # for "myself" the way a Contact has one, so empty-string is the
    # existing "no id needed, it's me" convention already used elsewhere
    # in this file. A non-empty value is the contact id of whoever's
    # signed invite this vault joined the group through (see
    # join_group_from_invite) - that contact is the only one whose
    # "delete group" is honored as deleting the group for real; everyone
    # else can only leave (see app.py's owner-conditional Delete/Leave
    # menu and Vault.delete_group's is_owner check below).
    owner_contact_id: str = ""
    # Invites THIS vault has issued for this group - only meaningful when
    # owner_contact_id == "" (only a group's owner can issue invites for
    # it, see create_group_invite). See GroupInviteRecord's docstring for
    # what "used" actually means given there is no server to enforce it.
    issued_invites: list["GroupInviteRecord"] = field(default_factory=list)
    # The invite code THIS vault redeemed to join, when owner_contact_id
    # != "" (empty/unused when this vault owns the group - an owner never
    # redeems anyone's invite for their own group). app.py's send path
    # (_wire_body_for) attaches this to every outgoing group message
    # until the owner's KIND_GROUP_ACK confirms real membership - see
    # MainWindow._acked_group_ids - since the owner's vault is the only
    # place able to validate it (redeem_group_invite_locally), a message
    # sent before that ack arrives still needs to carry proof of
    # invitation on every attempt, the same way any other queued/retried
    # message here already carries its full context on every retry
    # (see _wire_body_for's own docstring on why retries aren't
    # abbreviated).
    joined_invite_code: str = ""
    # Members added directly (create_group()'s initial list, or
    # add_group_member() from the "Add/remove members" UI) who have not
    # yet been sent an auto-generated personal invite. Only meaningful
    # when owner_contact_id == "" (a non-owner never adds members
    # directly - see app.py's owner-only "Add/remove members" menu gate).
    #
    # A directly-added member has no way to learn the group exists at
    # all otherwise: unlike an invite-redeeming joiner, they never ran
    # join_group_from_invite(), so their own vault has no local Group
    # record whatsoever, and app.py's _file_incoming_group_message()
    # drops any message for a gid it does not already recognize (that is
    # the whole point of removing the old auto-join-on-any-message
    # behavior). So the OWNER'S next send to a member in this set embeds
    # a freshly minted, single-use, real invite (see
    # app.py._start_group_send) instead of the plain shared envelope -
    # the member's client redeems it exactly like a pasted invite would,
    # just delivered automatically instead of requiring a manual paste.
    # Removed from this set the moment that onboarding send is attempted
    # (success or failure - a failed send is retried by the normal
    # queued-message path using the SAME already-embedded invite code
    # stored on that specific queued Message, not a fresh one each time,
    # so a retry cannot mint and burn multiple codes for one member).
    pending_onboard_contact_ids: list[str] = field(default_factory=list)


@dataclass
class GroupInviteRecord:
    """
    One invite this vault's own identity issued for a group it owns,
    tracked so a second redemption attempt of the same code can be
    refused.

    This is the actual single-use enforcement point for group invites -
    see group_invite.py's module docstring for why it has to live here
    (on the owner's own vault) rather than in the invite text itself:
    there is no server to ask "has this code been used by someone else
    already," so the owner's own record of what it has already redeemed
    is the only authority that exists. `used` is checked and set by
    Vault.redeem_group_invite_locally(), the moment the owner sees a
    group-tagged message carrying this code from a sender who is not yet
    a member.
    """

    code: str
    created: str
    expires: str  # ISO-8601 UTC timestamp
    used: bool = False
    used_by_contact_id: str = ""  # set alongside `used`, for the UI's own record


# How many chunks pass between durable Vault.save() calls while a transfer
# is in progress (see Vault.mark_chunk_done()). Vault.save() rewrites and
# re-encrypts the ENTIRE vault on every call (see save()'s own docstring/
# comments) - calling it once per 1 MiB chunk of a multi-GB transfer would
# be a serious write-amplification problem. Batching bounds both how often
# that full rewrite happens AND how much work (at most this many chunks)
# would need to be re-sent/re-received after a crash between saves - the
# two are in tension (bigger batches = fewer rewrites but more possible
# rework), 10 is a reasonable middle point for 1 MiB chunks (at most 10
# MiB of rework, at least a 10x reduction in save() frequency).
FILE_TRANSFER_SAVE_BATCH = 10


@dataclass
class FileTransfer:
    """
    Tracks one chunked file transfer's progress - see envelope.py's
    KIND_FILE_START/KIND_FILE_CHUNK and app.py's ChunkedSendWorker/
    receive-side handling.

    Deliberately NOT part of Message: a transfer's chunk-tracking state is
    operational (exists only while the transfer is incomplete, then folds
    into a normal Message once done - see Vault.complete_file_transfer())
    rather than a permanent display record, so keeping it separate avoids
    adding fields to every ordinary Message that are almost always empty.

    The chunk BYTES themselves are never stored here or in vault.dat while
    a transfer is in progress - only which chunk indices have been sent/
    received (chunks_done). An outgoing transfer re-reads bytes from the
    original file on disk on demand (still there for the duration of the
    send); an incoming transfer appends bytes to a plaintext temp file
    under paths.data_dir()/incoming/<id>.part as they arrive, folded into
    an encrypted Message (like any other attachment) only once complete -
    see Vault.complete_file_transfer()/_incoming_part_path().
    """

    id: str  # the transfer_id / wire "tid"
    contact_id: str  # who this transfer is with (the specific member, for a group send)
    direction: str  # "out" or "in"
    filename: str
    mime: str
    total_size: int
    chunk_count: int
    chunks_done: list[bool] = field(default_factory=list)
    # direction "out" only: the original file's path on disk, so a
    # resumed send (including after an app restart, not just an
    # in-session retry - see DeliveryWorker.resume_transfer) can re-open
    # it and read the still-missing chunks. If the file has since moved
    # or been deleted, the resume attempt fails cleanly (a normal
    # TransportError/OSError from ChunkedSendWorker, handled the same as
    # any other failed send) rather than silently sending garbage -
    # there is no way to recover a moved/deleted source file, same
    # limitation any file-sending feature has.
    source_path: str = ""
    group_id: str = ""
    client_msg_id: str = ""  # ties an outgoing transfer to its placeholder Message bubble
    started: str = ""
    completed: bool = False

    @property
    def chunks_done_count(self) -> int:
        return sum(1 for done in self.chunks_done if done)


@dataclass
class Identity:
    private_key: str  # base64 X25519 private key - NEVER leaves this machine
    public_key: str  # base64 X25519 public key - safe to share with anyone
    onion: str = ""  # populated once the hidden service is running
    onion_key: str = ""  # Tor's ED25519-V3 private key blob, so the address persists
    accept_from_anyone: bool = True  # accept first contact from unknown keys
    # Ed25519 signing keypair, used only to sign shareable contact bundles
    # (see bundle.py) - a distinct key from the X25519 pair above, which is
    # for NaCl Box message encryption and cannot sign. Defaults to "" so an
    # old vault file (saved before this feature existed) still loads
    # unmodified; Vault.unlock() lazily generates and persists a signing
    # keypair the first time it opens a vault that doesn't have one yet.
    signing_private_key: str = ""  # NEVER leaves this machine
    signing_public_key: str = ""  # safe to share; travels inside bundles

    @property
    def address(self) -> str:
        """
        The full legacy plaintext address (onionmsg:<onion>:<public key>).
        See Contact.address's docstring - internal/backward use only.
        """
        return format_address(self.onion, self.public_key)

    @property
    def fingerprint(self) -> str:
        """Read this to a contact so they can confirm they have the real you."""
        return crypto.fingerprint(self.public_key)


# --------------------------------------------------------------------------- #
# Address format
# --------------------------------------------------------------------------- #

ADDRESS_PREFIX = "onionmsg:"


def format_address(onion: str, public_key: str) -> str:
    """
    Build the address a user shares with others.

    It bundles the onion service (where to reach them) with the public key
    (how to encrypt to them, and how to verify messages really came from
    them). Both halves are needed - an onion address alone would let whoever
    controls that service impersonate the owner.
    """
    if not onion:
        return ""
    return f"{ADDRESS_PREFIX}{onion}:{public_key}"


def parse_address(address: str) -> tuple[str, str]:
    """
    Split a shared address into (onion, public_key_b64).

    Raises ValueError if the address is malformed.
    """
    text = address.strip()
    if text.startswith(ADDRESS_PREFIX):
        text = text[len(ADDRESS_PREFIX):]

    parts = text.split(":")
    if len(parts) != 2:
        raise ValueError("Address must look like onionmsg:<onion>:<public key>")

    onion, public_key = parts[0].strip(), parts[1].strip()

    if not onion.endswith(".onion"):
        raise ValueError("The onion part of the address is missing or invalid.")
    # A v3 onion address is 56 characters plus the ".onion" suffix.
    if len(onion) != len(".onion") + 56:
        raise ValueError("That is not a valid v3 onion address.")

    try:
        raw = crypto.b64decode(public_key)
    except Exception as exc:
        raise ValueError("The public key part of the address is not valid base64.") from exc
    if len(raw) != 32:
        raise ValueError("The public key part of the address is the wrong length.")

    return onion, public_key


# --------------------------------------------------------------------------- #
# Vault
# --------------------------------------------------------------------------- #

class Vault:
    def __init__(self, path: str | None = None) -> None:
        self.path = path or os.path.join(paths.data_dir(), DEFAULT_FILENAME)
        if path is None:
            _migrate_legacy_vault(self.path)
        self._key: bytes | None = None
        self._salt: bytes | None = None
        self.identity: Identity | None = None
        self.contacts: list[Contact] = []
        self.groups: list[Group] = []
        self.file_transfers: list[FileTransfer] = []
        # Guards every read/mutation of identity/contacts and every save().
        # This object is called concurrently from the Qt UI thread, the
        # DeliveryWorker thread, and MessageServer's connection-handler
        # threads (app.py), so without this lock two near-simultaneous
        # mutations (e.g. two first-contact requests, or a send racing a
        # delivery retry) can interleave list iteration with list mutation,
        # or interleave two save() calls writing the same temp path.
        # RLock because several methods below call other locked methods on
        # the same object (e.g. accept_contact -> save()).
        self._lock = threading.RLock()

    # -- lifecycle -------------------------------------------------------- #
    def exists(self) -> bool:
        return os.path.exists(self.path)

    def create(self, passphrase: str) -> None:
        """Create a brand new vault with a fresh identity."""
        with self._lock:
            self._salt = crypto.new_salt()
            self._key = crypto.derive_key(passphrase, self._salt)

            private_raw, public_raw = crypto.generate_keypair()
            signing_priv_b64, signing_pub_b64 = _generate_signing_keypair()
            self.identity = Identity(
                private_key=crypto.b64encode(private_raw),
                public_key=crypto.b64encode(public_raw),
                signing_private_key=signing_priv_b64,
                signing_public_key=signing_pub_b64,
            )
            self.contacts = []
            self.groups = []
            self.file_transfers = []
            self.save()

    def unlock(self, passphrase: str) -> None:
        """
        Open an existing vault.

        Raises crypto.DecryptionError if the passphrase is wrong.
        """
        with self._lock:
            with open(self.path, "rb") as f:
                blob = f.read()

            if not blob.startswith(MAGIC):
                raise ValueError("This file is not a Veilwire vault.")

            salt_start = len(MAGIC)
            salt_end = salt_start + crypto._SALT_BYTES
            salt = blob[salt_start:salt_end]
            ciphertext = blob[salt_end:]

            key = crypto.derive_key(passphrase, salt)
            plaintext = crypto.decrypt_blob(ciphertext, key)  # raises on bad passphrase

            data = json.loads(plaintext.decode("utf-8"))
            self._salt = salt
            self._key = key
            self.identity = Identity(**data["identity"])
            self.contacts = [
                Contact(
                    **{**c, "messages": [Message(**m) for m in c.get("messages", [])]}
                )
                for c in data.get("contacts", [])
            ]
            # Absent entirely on a vault saved before the group-chat feature
            # existed - defaults to no groups, same "old file keeps working
            # unchanged" migration as everything else in this method.
            #
            # issued_invites needs its own reconstruction step: json.loads
            # gives back plain dicts for everything, but GroupInviteRecord
            # methods (redeem_group_invite_locally, mark_group_invite_used)
            # access it via attributes (.code, .used, ...), not dict keys -
            # a bare Group(**g) would leave those as dicts and crash the
            # first time an invite is redeemed after any lock/unlock cycle
            # (i.e. after every app restart). Same pattern already used
            # just above for Contact.messages (list[Message] reconstructed
            # from list[dict]).
            self.groups = [
                Group(**{
                    **g,
                    "issued_invites": [
                        GroupInviteRecord(**r) for r in g.get("issued_invites", [])
                    ],
                })
                for g in data.get("groups", [])
            ]
            self.file_transfers = [
                FileTransfer(**t) for t in data.get("file_transfers", [])
            ]

            # Lazy, automatic, one-time migration: a vault saved before the
            # bundle feature existed has no signing keypair (the dataclass
            # default filled in "" above). Generate one now and persist it,
            # so every vault has a signing identity going forward without
            # a separate migration step or a vault-format version bump -
            # everything else about the file (contacts, messages, the
            # X25519 identity) is untouched.
            if not self.identity.signing_public_key:
                signing_priv_b64, signing_pub_b64 = _generate_signing_keypair()
                self.identity.signing_private_key = signing_priv_b64
                self.identity.signing_public_key = signing_pub_b64
                self.save()

    def lock(self) -> None:
        """Forget the key material held in memory."""
        with self._lock:
            self._key = None
            self.identity = None
            self.contacts = []
            self.groups = []
            self.file_transfers = []

    def save(self) -> None:
        with self._lock:
            if self._key is None or self._salt is None or self.identity is None:
                raise VaultLocked("Cannot save a locked vault.")

            payload = {
                "identity": asdict(self.identity),
                "contacts": [asdict(c) for c in self.contacts],
                "groups": [asdict(g) for g in self.groups],
                "file_transfers": [asdict(t) for t in self.file_transfers],
            }
            plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            ciphertext = crypto.encrypt_blob(plaintext, self._key)

            # Write to a temporary file then replace, so an interrupted save
            # cannot leave a truncated vault behind. Permissions are set on
            # the temp file *before* the rename (rename preserves mode), so
            # the final path never exists, even briefly, with a wider mode
            # than 0600. The directory fsync after the rename is needed
            # because rename durability itself is not guaranteed by the
            # file's own fsync on every filesystem - without it, a crash
            # right after os.replace() can still lose the rename.
            tmp_path = f"{self.path}.tmp"
            with open(tmp_path, "wb") as f:
                f.write(MAGIC + self._salt + ciphertext)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, self.path)
            _fsync_dir(os.path.dirname(os.path.abspath(self.path)))

    # -- identity --------------------------------------------------------- #
    def private_key_raw(self) -> bytes:
        with self._lock:
            if self.identity is None:
                raise VaultLocked("Vault is locked.")
            return crypto.b64decode(self.identity.private_key)

    def set_onion(self, onion: str, onion_key: str) -> None:
        with self._lock:
            if self.identity is None:
                raise VaultLocked("Vault is locked.")
            self.identity.onion = onion
            self.identity.onion_key = onion_key
            self.save()

    # -- contacts --------------------------------------------------------- #
    def add_contact(self, name: str, address: str) -> Contact:
        """
        Add a contact from a shared address string.

        Raises ValueError if the address is malformed, already saved, or is
        the user's own address.
        """
        with self._lock:
            onion, public_key = parse_address(address)

            if self.identity is not None and public_key == self.identity.public_key:
                raise ValueError("That is your own address.")

            for existing in self.contacts:
                if existing.public_key == public_key:
                    raise ValueError(f"Already saved as '{existing.name}'.")

            contact = Contact(
                id=str(uuid.uuid4()),
                name=_clean_name(name) or onion[:16],
                onion=onion,
                public_key=public_key,
                added=_now(),
            )
            self.contacts.append(contact)
            self.save()
            return contact

    def add_contact_from_bundle(self, name: str, bundle_text: str) -> Contact:
        """
        Add a contact from a shared "P2PMSG1:..." bundle (see bundle.py).

        Parallel to add_contact() above, which takes the legacy plaintext
        "onionmsg:<onion>:<public key>" address - both remain fully
        supported side by side. The bundle path additionally remembers the
        contact's signing key and checks for the endpoint-change case: if
        this public key already belongs to an ACCEPTED contact under a
        DIFFERENT onion, the bundle is filed as a pending "endpoint
        changed" request instead of being trusted outright or silently
        overwriting the stored endpoint - identity (the public key) matched,
        but the transport endpoint did not, which is exactly the case that
        must never be applied automatically.

        Raises ValueError if the address is malformed (via bundle.BundleError,
        not caught here - callers already handle ValueError from
        add_contact() and bundle.BundleError is not a ValueError, so callers
        of this method should catch (ValueError, bundle_mod.BundleError))
        or if the bundle is the user's own address.
        """
        with self._lock:
            parsed = bundle_mod.parse_bundle(bundle_text)

            if self.identity is not None and parsed.public_key == self.identity.public_key:
                raise ValueError("That is your own address.")

            existing_by_key = self.find_by_public_key(parsed.public_key)
            if existing_by_key is not None:
                if existing_by_key.status == STATUS_ACCEPTED and existing_by_key.onion != parsed.onion:
                    return self._file_endpoint_change(existing_by_key, parsed)
                raise ValueError(f"Already saved as '{existing_by_key.name}'.")

            contact = Contact(
                id=str(uuid.uuid4()),
                name=_clean_name(name) or parsed.onion[:16],
                onion=parsed.onion,
                public_key=parsed.public_key,
                signing_public_key=parsed.signing_public_key,
                added=_now(),
            )
            self.contacts.append(contact)
            self.save()
            return contact

    def _file_endpoint_change(self, existing: "Contact", parsed) -> Contact:
        """
        File a pending "endpoint changed" request for an already-accepted
        contact whose bundle now claims a different onion address.

        The existing contact's stored onion/signing key is never touched
        here - only a new pending record is created, carrying a name that
        marks it clearly as an endpoint-change warning (not a routine new
        request) so the UI can render the dedicated warning screen instead
        of the normal accept/block request flow. The user decides via the
        existing accept_contact()/block_contact() methods - "Review" is the
        existing accept flow, "Reject" is the existing block flow; no new
        vault methods are needed for the decision itself.
        """
        marker_name = f"⚠ Endpoint changed for {existing.name} ({short_id(existing.fingerprint)})"
        contact = Contact(
            id=str(uuid.uuid4()),
            name=_clean_name(marker_name),
            onion=parsed.onion,
            public_key=parsed.public_key,
            signing_public_key=parsed.signing_public_key,
            added=_now(),
            status=STATUS_PENDING,
        )
        self.contacts.append(contact)
        self.save()
        return contact

    def get_contact(self, contact_id: str) -> Contact | None:
        with self._lock:
            for c in self.contacts:
                if c.id == contact_id:
                    return c
            return None

    def find_by_public_key(self, public_key: str) -> Contact | None:
        with self._lock:
            for c in self.contacts:
                if c.public_key == public_key:
                    return c
            return None

    def _find_accepted_by_onion(self, onion: str) -> Contact | None:
        """Any accepted contact currently on file for this onion address."""
        for c in self.contacts:
            if c.onion == onion and c.status == STATUS_ACCEPTED:
                return c
        return None

    def delete_contact(self, contact_id: str) -> None:
        with self._lock:
            self.contacts = [c for c in self.contacts if c.id != contact_id]
            self.save()

    def rename_contact(self, contact_id: str, name: str) -> None:
        with self._lock:
            contact = self.get_contact(contact_id)
            if contact is not None:
                contact.name = _clean_name(name) or contact.name
                self.save()

    # -- groups ------------------------------------------------------------ #
    def create_group(self, name: str, member_contact_ids: list[str]) -> Group:
        """
        Create a group naming a set of already-added, accepted contacts.

        Raises ValueError if there are no members, too many, or any member
        id does not name a currently-accepted contact - a group cannot
        point at a pending request or a blocked/removed contact, since
        there would be nobody reachable at the other end of that "member".
        """
        with self._lock:
            # De-duplicate while preserving order, so a caller that
            # accidentally lists the same contact twice does not create a
            # group that would fan a message out to them twice.
            seen: set[str] = set()
            deduped = [m for m in member_contact_ids if not (m in seen or seen.add(m))]

            if not deduped:
                raise ValueError("A group needs at least one other member.")
            if len(deduped) > MAX_GROUP_MEMBERS:
                raise ValueError(f"A group can have at most {MAX_GROUP_MEMBERS} members.")
            for member_id in deduped:
                member = self.get_contact(member_id)
                if member is None or member.status != STATUS_ACCEPTED:
                    raise ValueError("Every group member must be an existing, accepted contact.")

            group = Group(
                id=str(uuid.uuid4()),
                name=_clean_group_name(name) or "Group",
                created=_now(),
                member_contact_ids=deduped,
                # Every initial member needs an auto-generated invite
                # embedded in the owner's first send to them - see
                # pending_onboard_contact_ids's docstring.
                pending_onboard_contact_ids=list(deduped),
            )
            self.groups.append(group)
            self.save()
            return group

    def get_group(self, group_id: str) -> Group | None:
        with self._lock:
            for g in self.groups:
                if g.id == group_id:
                    return g
            return None

    def group_last_activity(self, group: Group) -> str:
        """
        Most recent activity timestamp for a group, for sidebar sorting.

        A group has no messages list of its own (see Group's docstring -
        every group message actually lives on a member Contact's own
        messages list, tagged with group_id), so this scans the current
        members' messages rather than reading a stored field.
        """
        with self._lock:
            latest = group.created
            for member_id in group.member_contact_ids:
                member = self.get_contact(member_id)
                if member is None:
                    continue
                for message in member.messages:
                    if message.group_id == group.id and message.timestamp > latest:
                        latest = message.timestamp
            return latest

    def group_messages(self, group: Group) -> list[Message]:
        """
        Every message belonging to this group, across all current members'
        own message lists, oldest first.

        Outgoing (direction "out") copies are NOT collapsed here - a group
        send stores one Message per member (see app.py's group send path),
        sharing a client_msg_id. Collapsing those into one displayed bubble
        with an aggregate delivery count is display logic, so it lives in
        app.py alongside the rest of the rendering code, not here.
        """
        with self._lock:
            collected: list[Message] = []
            for member_id in group.member_contact_ids:
                member = self.get_contact(member_id)
                if member is None:
                    continue
                collected.extend(
                    m
                    for m in member.messages
                    if m.group_id == group.id and not m.is_delete_request
                )
            collected.sort(key=lambda m: m.timestamp)
            return collected

    def rename_group(self, group_id: str, name: str) -> None:
        with self._lock:
            group = self.get_group(group_id)
            if group is not None:
                group.name = _clean_group_name(name) or group.name
                self.save()

    def add_group_member(self, group_id: str, contact_id: str, *, needs_onboarding: bool = True) -> None:
        """Add an already-accepted contact to a group. A member added this
        way only sees *future* messages sent while they are a member -
        there is no history to backfill from, since past messages were
        never sent to them (see Group's docstring on there being no shared
        roster).

        This is also how a previously-removed member gets to rejoin - the
        one deliberate path that's allowed to clear removed_contact_ids
        (see that field's docstring).

        `needs_onboarding` controls whether this contact is queued for an
        auto-generated personal invite (see
        Group.pending_onboard_contact_ids). True (the default) for the
        owner's own "add member" UI action - a directly-added member has
        no other way to learn the group exists. False when called from
        app.py's _file_incoming_group_message right after that same
        contact's invite code was validated by
        redeem_group_invite_locally() - they already have a local Group
        record (created via join_group_from_invite on their own side) and
        do not need a second, redundant invite."""
        with self._lock:
            group = self.get_group(group_id)
            if group is None:
                return
            contact = self.get_contact(contact_id)
            if contact is None or contact.status != STATUS_ACCEPTED:
                raise ValueError("Only an existing, accepted contact can be added to a group.")
            if contact_id in group.removed_contact_ids:
                group.removed_contact_ids.remove(contact_id)
            if contact_id in group.member_contact_ids:
                self.save()
                return
            if len(group.member_contact_ids) >= MAX_GROUP_MEMBERS:
                raise ValueError(f"A group can have at most {MAX_GROUP_MEMBERS} members.")
            group.member_contact_ids.append(contact_id)
            if needs_onboarding and contact_id not in group.pending_onboard_contact_ids:
                group.pending_onboard_contact_ids.append(contact_id)
            self.save()

    def clear_group_onboarding(self, group_id: str, contact_id: str) -> None:
        """
        Marks a directly-added member as having received their
        auto-generated personal invite (see
        Group.pending_onboard_contact_ids and app.py's
        _start_group_send). Called once that member's individually-built,
        invite-bearing envelope has actually been queued for sending -
        not once it is confirmed delivered, since a failed/queued send is
        retried with the SAME already-embedded code (see
        _wire_body_for/DeliveryWorker), not a freshly minted one, so
        there is nothing further for this method to do on a later retry.
        """
        with self._lock:
            group = self.get_group(group_id)
            if group is None:
                return
            if contact_id in group.pending_onboard_contact_ids:
                group.pending_onboard_contact_ids.remove(contact_id)
                self.save()

    def remove_group_member(self, group_id: str, contact_id: str) -> None:
        """Remove a member and record the removal so an incoming group
        message from them does not silently re-add them (see
        Group.removed_contact_ids) - the only way back in is the user
        explicitly re-adding them via add_group_member()."""
        with self._lock:
            group = self.get_group(group_id)
            if group is None:
                return
            if contact_id in group.member_contact_ids:
                group.member_contact_ids.remove(contact_id)
            if contact_id not in group.removed_contact_ids:
                group.removed_contact_ids.append(contact_id)
            self.save()

    def delete_group(self, group_id: str) -> None:
        """
        Forget the group. Past messages are left in place on each member's
        own contact record (still tagged with the now-orphaned group_id)
        rather than deleted, matching how removing a contact does not
        retroactively scrub messages already exchanged.

        Raises ValueError if this vault is not the group's owner
        (Group.owner_contact_id != "") - a non-owner member is only ever
        allowed to leave (see app.py's Leave-group flow, which sends a
        KIND_GROUP_LEAVE notice to the other members and THEN calls this
        method to remove its own local copy). The check lives here, not
        only in app.py's menu construction, so it holds even if a future
        call site forgets to check first - same defense-in-depth stance
        create_group()'s own validation already takes.
        """
        with self._lock:
            group = self.get_group(group_id)
            if group is None:
                return
            if group.owner_contact_id != "":
                raise ValueError("Only the group's owner can delete it - you can leave instead.")
            self.groups = [g for g in self.groups if g.id != group_id]
            self.save()

    def leave_group(self, group_id: str) -> None:
        """
        Remove this vault's own local copy of a group it does NOT own -
        the non-owner counterpart to delete_group(). Callers (app.py) are
        expected to have already notified the other members (see
        KIND_GROUP_LEAVE) before calling this - this method only ever
        touches local state, same as delete_group().

        Raises ValueError if this vault IS the group's owner - an owner
        leaving would strand every other member with no one able to issue
        new invites or authoritatively delete the group; the owner's only
        way to end a group for themselves is delete_group().
        """
        with self._lock:
            group = self.get_group(group_id)
            if group is None:
                return
            if group.owner_contact_id == "":
                raise ValueError("The group's owner cannot leave - delete the group instead.")
            self.groups = [g for g in self.groups if g.id != group_id]
            self.save()

    def create_group_invite(self, group_id: str, expiry_hours: int) -> str:
        """
        Issue a fresh, signed, single-use invite for a group this vault
        owns (see group_invite.py). Raises ValueError if this vault does
        not own the group (only an owner can invite - a non-owner member
        minting invites for someone else's group would let them grant
        membership on the owner's behalf with no owner involvement at
        all) or if the identity has no signing key yet (should not
        happen post-unlock - see Identity.signing_private_key's
        docstring - but checked rather than assumed).
        """
        with self._lock:
            if self.identity is None:
                raise VaultLocked("Cannot create an invite on a locked vault.")
            group = self.get_group(group_id)
            if group is None:
                raise ValueError("No such group.")
            if group.owner_contact_id != "":
                raise ValueError("Only the group's owner can create invites for it.")
            if not self.identity.onion or not self.identity.signing_private_key:
                raise ValueError("Cannot create an invite before your identity is fully set up.")

            code = invite_mod.new_invite_code()
            created = _now()
            expires = (
                datetime.now(timezone.utc) + timedelta(hours=expiry_hours)
            ).isoformat(timespec="seconds")

            invite_text = invite_mod.build_invite(
                group.id, group.name, code, expires,
                self.identity.onion, self.identity.public_key,
                self.identity.signing_public_key, self.identity.signing_private_key,
            )
            group.issued_invites.append(
                GroupInviteRecord(code=code, created=created, expires=expires)
            )
            self.save()
            return invite_text

    def redeem_group_invite_locally(self, group_id: str, code: str) -> bool:
        """
        Called on the group OWNER's side when a group-tagged message
        arrives from a sender who is not yet a member, carrying an
        invite code (envelope.py's "invcode"). Returns True (and marks
        the record used) only for a code that is real, unexpired, and not
        already used - the actual single-use/expiry enforcement point,
        see GroupInviteRecord's docstring for why this has to be the
        owner's own record and cannot be enforced any other way without a
        server.
        """
        with self._lock:
            group = self.get_group(group_id)
            if group is None or group.owner_contact_id != "":
                return False
            for record in group.issued_invites:
                if record.code != code:
                    continue
                if record.used:
                    return False
                if record.expires <= _now():
                    return False
                return True
            return False

    def mark_group_invite_used(self, group_id: str, code: str, used_by_contact_id: str) -> None:
        """
        Marks an invite code consumed. Split from
        redeem_group_invite_locally() (which only checks validity,
        read-only) so the caller (app.py) can decide whether to actually
        add the sender as a member (e.g. it might still fail on
        MAX_GROUP_MEMBERS) before committing the code as spent - a code
        that turned out unusable for an unrelated reason should not be
        burned for nothing.
        """
        with self._lock:
            group = self.get_group(group_id)
            if group is None:
                return
            for record in group.issued_invites:
                if record.code == code and not record.used:
                    record.used = True
                    record.used_by_contact_id = used_by_contact_id
                    self.save()
                    return

    def join_group_from_invite(self, invite_text: str) -> Group:
        """
        Parse and verify a signed group invite (group_invite.py), then
        create (or return the existing) local Group record for it, owned
        by the inviting contact.

        Raises group_invite.GroupInviteError for a malformed/tampered/
        forged invite (never a partially-trusted result - see that
        module's docstring), ValueError if the invite has already expired
        (checked here, locally, against this machine's clock - the
        "time-limited" half of the feature) or if the signed owner
        identity is not already an accepted contact of this vault.

        That last check is deliberate: an invite's signed payload proves
        WHO issued it, but this app never auto-trusts a new identity just
        because it showed up in a signed document (see bundle.py's own
        contact-request flow, which always requires an explicit
        accept/block decision) - joining a group is not an exception to
        that. If the owner is not yet a contact, the user is expected to
        add/accept them the normal way first, then redeem the invite.

        Joining here does NOT itself grant membership on the owner's
        side - it only creates this vault's own local copy of the group.
        Real membership is only established once the owner's vault sees
        a message from this identity carrying the invite's code and
        calls redeem_group_invite_locally() - see app.py's send path,
        which keeps attaching the code to outgoing group messages until
        the owner's KIND_GROUP_ACK confirms membership.
        """
        with self._lock:
            invite = invite_mod.parse_invite(invite_text)
            if invite.expires <= _now():
                raise ValueError("This invite has expired.")

            owner = self.find_by_public_key(invite.owner_public_key)
            if owner is None or owner.status != STATUS_ACCEPTED:
                raise ValueError(
                    "Add and accept this invite's sender as a contact before joining their group."
                )

            existing = self.get_group(invite.gid)
            if existing is not None:
                return existing

            group = Group(
                id=invite.gid,
                name=_clean_group_name(invite.gname) or "Group",
                created=_now(),
                owner_contact_id=owner.id,
                joined_invite_code=invite.code,
            )
            self.groups.append(group)
            self.save()
            return group

    # -- messages --------------------------------------------------------- #
    def add_message(
        self,
        contact_id: str,
        direction: str,
        body: str,
        delivered: bool = True,
        note: str = "",
        status: str = SENT,
        group_id: str = "",
        client_msg_id: str = "",
        sender_contact_id: str = "",
        attachment_filename: str = "",
        attachment_mime: str = "",
        attachment_size: int = 0,
        is_delete_request: bool = False,
        pending_invcode: str = "",
    ) -> Message | None:
        with self._lock:
            contact = self.get_contact(contact_id)
            if contact is None:
                return None

            # Only bounds INCOMING attachments - see
            # MAX_ATTACHMENT_BYTES_PER_CONTACT's docstring. attachment_size
            # is the real decoded byte count (envelope.decode() always
            # recomputes it from the actual bytes, never trusting a
            # sender's claimed field), so this cannot be defeated by lying
            # about size in the envelope.
            if direction == "in" and attachment_filename and attachment_size > 0:
                existing = sum(
                    m.attachment_size for m in contact.messages
                    if m.direction == "in" and m.attachment_filename and not m.deleted
                )
                if existing + attachment_size > MAX_ATTACHMENT_BYTES_PER_CONTACT:
                    # Logged without the filename/contact name (both are
                    # peer-controlled/potentially sensitive display text) -
                    # just enough to explain, after the fact, why a file
                    # silently never appeared for a given contact.
                    _logger.warning(
                        "Dropped an incoming attachment: contact %s would exceed "
                        "the %d-byte per-contact attachment cap",
                        contact_id, MAX_ATTACHMENT_BYTES_PER_CONTACT,
                    )
                    return None

            message = Message(
                id=str(uuid.uuid4()),
                contact_id=contact_id,
                direction=direction,
                timestamp=_now(),
                body=body,
                delivered=delivered,
                note=note,
                status=status if direction == "out" else SENT,
                group_id=group_id,
                client_msg_id=client_msg_id,
                sender_contact_id=sender_contact_id,
                attachment_filename=attachment_filename,
                attachment_mime=attachment_mime,
                attachment_size=attachment_size,
                is_delete_request=is_delete_request,
                pending_invcode=pending_invcode,
            )
            contact.messages.append(message)
            self.save()
            return message

    def queued_messages(self) -> list[tuple[Contact, Message]]:
        """
        Every outgoing message still waiting to be delivered, oldest first.

        Queued messages live in this vault, encrypted, and nowhere else. There
        is no server holding them - the sender simply keeps trying until the
        recipient's onion service answers.
        """
        with self._lock:
            pending: list[tuple[Contact, Message]] = []
            for contact in self.contacts:
                if contact.status != STATUS_ACCEPTED:
                    continue
                for message in contact.messages:
                    if (
                        message.direction == "out"
                        and message.status == QUEUED
                        and not message.deleted
                    ):
                        pending.append((contact, message))
            pending.sort(key=lambda pair: pair[1].timestamp)
            return pending

    def mark_message(
        self,
        contact_id: str,
        message_id: str,
        status: str,
        note: str = "",
    ) -> None:
        """Record the outcome of a delivery attempt."""
        with self._lock:
            contact = self.get_contact(contact_id)
            if contact is None:
                return
            for message in contact.messages:
                if message.id == message_id:
                    message.status = status
                    message.delivered = status == SENT
                    message.note = note
                    message.attempts += 1
                    message.last_attempt = _now()
                    self.save()
                    return

    def mark_deleted(self, contact_id: str, message_id: str) -> None:
        """
        Tombstone a message: scrub its displayed content but keep the row in
        place (same id, timestamp, direction, group_id, sender_contact_id)
        so the thread still shows *that* a message was there and was
        deleted, in its original position, rather than a confusing gap.

        This is the local half of "delete for everyone" - it removes this
        vault's own copy of the content. The other half, for a message this
        vault sent, is queue_delete_request() below, which notifies the
        peer(s) so their copies are scrubbed the same way. Nothing here
        checks *who is allowed* to delete this message - that authorization
        decision (a message can only ever be deleted by whoever sent it) is
        made by the caller (app.py) before this is invoked: for the sender's
        own outgoing message that is simply "it's their own message"; for an
        incoming "delete" envelope it is "the envelope's sender matches this
        message's sender" (see app.py's delete-envelope handling). This
        method only performs the mechanical scrub once that decision has
        already been made.
        """
        with self._lock:
            contact = self.get_contact(contact_id)
            if contact is None:
                return
            for message in contact.messages:
                if message.id == message_id:
                    message.deleted = True
                    message.body = ""
                    message.attachment_filename = ""
                    message.attachment_mime = ""
                    message.attachment_size = 0
                    message.note = ""
                    self.save()
                    return

    def queue_delete_request(
        self, contact_id: str, target_client_msg_id: str, group_id: str = ""
    ) -> None:
        """
        Queue a "delete for everyone" notification to a single contact for a
        message previously sent to them, identified by its shared mid (see
        envelope.py's module docstring on "mid"/client_msg_id). Pass
        group_id for a message that was sent as part of a group, so
        _wire_body_for() (app.py) can tag the resulting "delete" envelope
        with the same gid/gname a "text"/"file" envelope for that group
        would carry - it is otherwise not used for anything (there is no
        per-group delivery logic here; a group delete is simply one of
        these queued per member, same as a group send is one Message per
        member).

        This deliberately reuses add_message()/queued_messages() rather than
        a separate delivery path: the resulting row is an ordinary queued
        outgoing Message (so DeliveryWorker's existing retry loop picks it
        up and keeps retrying exactly like any other message until the
        contact's onion service answers - no server, no CDN, nothing else
        involved), just marked is_delete_request=True so app.py's
        _wire_body_for() encodes it as a "delete" envelope instead of a
        "text"/"file" one, and so it is never itself rendered as a chat
        bubble or re-deleted.
        """
        if not target_client_msg_id:
            return
        self.add_message(
            contact_id,
            "out",
            "",
            status=QUEUED,
            group_id=group_id,
            client_msg_id=target_client_msg_id,
            is_delete_request=True,
        )

    def queued_count(self) -> int:
        with self._lock:
            return len(self.queued_messages())

    def sorted_contacts(self) -> list[Contact]:
        with self._lock:
            return sorted(self.contacts, key=lambda c: c.last_activity, reverse=True)

    # -- file transfers ------------------------------------------------------ #
    def start_file_transfer(
        self, contact_id: str, direction: str, filename: str, mime: str,
        total_size: int, chunk_count: int, group_id: str = "", client_msg_id: str = "",
        source_path: str = "", transfer_id: str = "",
    ) -> FileTransfer:
        """
        Begin tracking a chunked file transfer (see FileTransfer's
        docstring). Returns the new record; callers store its `id`
        (the transfer_id) to reference it on every subsequent chunk.
        `source_path` (direction "out" only) is the original file's
        location on disk, persisted so a resumed send - including after
        an app restart - can find it again (see FileTransfer.source_path).

        `transfer_id`, when given, is used as-is instead of minting a
        fresh one - REQUIRED for an outgoing transfer, whose id must be
        the exact same one already embedded in the KIND_FILE_START wire
        message the caller built (see app.py's _start_contact_chunked_send) -
        every chunk that follows is tagged with this id, so the wire
        announcement and the local tracking record generating two
        different ids independently would mean they never match up on
        the receiving end. Left empty only for a caller with no
        wire-level id to match against yet (there is currently no such
        caller - kept optional rather than required so this signature
        stays compatible with any future direction="in"-only use).
        """
        with self._lock:
            transfer = FileTransfer(
                id=transfer_id or str(uuid.uuid4()),
                contact_id=contact_id,
                direction=direction,
                # Already sanitized by envelope.py's _sanitize_filename
                # before it ever reaches here (both on the sending side,
                # where the file's own basename is used, and the
                # receiving side, where it comes from a decoded
                # KIND_FILE_START) - just a defensive length bound here,
                # matching the same 255-char ceiling envelope.py itself
                # enforces (MAX_FILENAME_CHARS), not vault.py's
                # contact/group name conventions (_clean_name is for
                # display names, not filenames).
                filename=(filename.strip() or "file")[:255],
                mime=mime,
                total_size=total_size,
                chunk_count=chunk_count,
                chunks_done=[False] * chunk_count,
                source_path=source_path,
                group_id=group_id,
                client_msg_id=client_msg_id,
                started=_now(),
            )
            self.file_transfers.append(transfer)
            self.save()
            return transfer

    def start_incoming_file_transfer(
        self, transfer_id: str, contact_id: str, filename: str, mime: str,
        total_size: int, chunk_count: int, client_msg_id: str,
    ) -> FileTransfer | None:
        """
        Counterpart to start_file_transfer() for the RECEIVING side:
        unlike an outgoing transfer (whose id this vault mints itself),
        an incoming transfer's id is the sender's own transfer_id (see
        envelope.KIND_FILE_START) - every chunk that follows refers to
        it, so it cannot be regenerated here. Idempotent: returns the
        existing record unchanged if this transfer_id is already known
        (e.g. a duplicate/retried file_start), never creating a second
        FileTransfer for the same id.
        """
        with self._lock:
            existing = self.get_file_transfer(transfer_id)
            if existing is not None:
                return existing
            transfer = FileTransfer(
                id=transfer_id,
                contact_id=contact_id,
                direction="in",
                filename=(filename.strip() or "file")[:255],
                mime=mime,
                total_size=total_size,
                chunk_count=chunk_count,
                chunks_done=[False] * chunk_count,
                client_msg_id=client_msg_id,
                started=_now(),
            )
            self.file_transfers.append(transfer)
            self.save()
            return transfer

    def get_file_transfer(self, transfer_id: str) -> FileTransfer | None:
        with self._lock:
            for t in self.file_transfers:
                if t.id == transfer_id:
                    return t
            return None

    def mark_chunk_done(self, transfer_id: str, index: int) -> None:
        """
        Record that chunk `index` of a transfer has been sent (direction
        "out") or received (direction "in"). Persists to vault.dat only
        every FILE_TRANSFER_SAVE_BATCH chunks, or immediately once the
        transfer is fully complete - see that constant's docstring for
        why calling save() on every single chunk would be a real
        performance problem for a large file. Idempotent: marking an
        already-done index again is a harmless no-op (no double-save).
        """
        with self._lock:
            transfer = self.get_file_transfer(transfer_id)
            if transfer is None or index < 0 or index >= transfer.chunk_count:
                return
            if transfer.chunks_done[index]:
                return
            transfer.chunks_done[index] = True
            done = transfer.chunks_done_count
            just_completed = done == transfer.chunk_count
            if just_completed:
                transfer.completed = True
            if just_completed or done % FILE_TRANSFER_SAVE_BATCH == 0:
                self.save()

    def incomplete_transfers_for_contact(self, contact_id: str) -> list[FileTransfer]:
        """Outgoing transfers to this contact that still have unsent
        chunks - what DeliveryWorker resumes once the contact is seen
        online again (see app.py). Only ever "out": an incomplete
        incoming transfer has nothing for THIS vault to resume sending -
        it is the sender's job to resume, not the receiver's."""
        with self._lock:
            return [
                t for t in self.file_transfers
                if t.contact_id == contact_id and t.direction == "out" and not t.completed
            ]

    def _incoming_part_path(self, transfer_id: str) -> str:
        """
        Where an in-progress incoming transfer's bytes accumulate before
        being folded into an encrypted Message once complete - a
        plaintext file OUTSIDE vault.dat (under paths.data_dir(), the
        same directory vault.dat itself lives in, already 0700 per
        paths._ensure_private_dir), not inside the encrypted vault, so
        appending a chunk never triggers a full-vault rewrite (see
        FILE_TRANSFER_SAVE_BATCH's docstring) - only the small
        FileTransfer bitmap does, batched. Deleted once the transfer
        completes and its bytes have been folded into a real Message
        (see complete_file_transfer()) - nothing about the finished
        attachment's storage model changes: it ends up base64-encoded
        inside an encrypted Message exactly like a single-shot KIND_FILE
        attachment always has.
        """
        incoming_dir = os.path.join(paths.data_dir(), "incoming")
        os.makedirs(incoming_dir, mode=0o700, exist_ok=True)
        os.chmod(incoming_dir, 0o700)
        safe_id = "".join(c for c in transfer_id if c.isalnum() or c in "-_")
        return os.path.join(incoming_dir, f"{safe_id}.part")

    def append_incoming_chunk(self, transfer_id: str, data: bytes) -> None:
        """
        Append one chunk's raw bytes to this transfer's .part file.
        Chunks are expected to arrive in order (envelope.py's decode()
        already range-checks the claimed index against chunk_count, and
        app.py only calls this after confirming the index is the next
        expected one - an out-of-order chunk is dropped there, not
        handled here, since a simple append cannot correctly place a
        chunk anywhere but the end).
        """
        path = self._incoming_part_path(transfer_id)
        with open(path, "ab") as f:
            f.write(data)
        os.chmod(path, 0o600)

    def read_and_discard_incoming_part(self, transfer_id: str) -> bytes:
        """Read a completed transfer's accumulated bytes and delete the
        temp file - called exactly once, when the last chunk arrives, to
        fold the result into a real Message via add_message() (see
        app.py). Returns b"" if the part file is somehow missing rather
        than raising, so a caller can treat that as "nothing to fold in"
        without a special-cased try/except at every call site."""
        path = self._incoming_part_path(transfer_id)
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            return b""
        try:
            os.remove(path)
        except OSError:
            pass
        return data

    def complete_incoming_transfer(self, transfer_id: str) -> bool:
        """
        Fold a just-completed incoming transfer's assembled bytes into
        its placeholder Message (matched by client_msg_id, direction
        "in") - the SAME storage model a single-shot KIND_FILE
        attachment already uses (base64 inside an encrypted Message);
        only how the bytes were assembled beforehand (chunk by chunk,
        via append_incoming_chunk) is new. Reads and deletes the .part
        file, updates the Message, discards the FileTransfer record, and
        saves - all in one lock acquisition, so app.py never has to
        reach into Message internals directly. Returns False (leaving
        everything as-is) if the transfer or its matching Message cannot
        be found, so a caller can distinguish "nothing to do" from "did
        it."
        """
        with self._lock:
            transfer = self.get_file_transfer(transfer_id)
            if transfer is None:
                return False
            contact = self.get_contact(transfer.contact_id)
            if contact is None:
                return False
            message = next(
                (m for m in contact.messages
                 if m.client_msg_id == transfer.client_msg_id and m.direction == "in"),
                None,
            )
            if message is None:
                return False

            data = self.read_and_discard_incoming_part(transfer_id)
            # Standard (padded) base64 via the stdlib module - NOT
            # crypto.b64encode (that's URL-safe/no-padding, used only for
            # keys/fingerprints elsewhere in this file). Every other
            # attachment code path (envelope.py's KIND_FILE encode/decode,
            # app.py's Save As.../render_bubble) already reads
            # Message.body as standard base64 - this has to match exactly
            # or a completed chunked transfer's body is silently
            # undecodable (binascii.Error: Incorrect padding) the moment
            # anything tries to read it back.
            message.body = base64.b64encode(data).decode("ascii")
            message.attachment_size = len(data)
            self.file_transfers = [t for t in self.file_transfers if t.id != transfer_id]
            self.save()
            return True

    def discard_file_transfer(self, transfer_id: str) -> None:
        """Forget a transfer's tracking record (e.g. after it has been
        folded into a Message, or abandoned) and clean up any leftover
        .part file - the counterpart to start_file_transfer()."""
        with self._lock:
            self.file_transfers = [t for t in self.file_transfers if t.id != transfer_id]
            self.save()
        path = self._incoming_part_path(transfer_id)
        try:
            os.remove(path)
        except OSError:
            pass

    # -- contact policy ---------------------------------------------------- #
    def accepted_contacts(self) -> list[Contact]:
        with self._lock:
            return [c for c in self.sorted_contacts() if c.status == STATUS_ACCEPTED]

    def pending_contacts(self) -> list[Contact]:
        with self._lock:
            return [c for c in self.sorted_contacts() if c.status == STATUS_PENDING]

    def may_receive_from(self, public_key: str, onion: str) -> bool:
        """
        Decide whether to accept an inbound message from this key.

        * known and accepted -> yes
        * explicitly blocked -> no
        * unknown -> yes if the user allows first contact from strangers, and
          the sender is filed as a pending request rather than a full contact

        This is what lets someone message you just from your public address,
        while still leaving you in control of who stays. The whole decision
        is made under one lock so two near-simultaneous first messages from
        the same unknown key cannot each pass the "not found yet" check and
        both file a pending request.
        """
        with self._lock:
            existing = self.find_by_public_key(public_key)
            if existing is not None:
                return existing.status in (STATUS_ACCEPTED, STATUS_PENDING)

            if self.identity is None or not self.identity.accept_from_anyone:
                return False

            # First contact from a stranger: record it for the user to decide on.
            try:
                self._add_pending(onion, public_key)
            except ValueError:
                return False
            return True

    def _add_pending(self, onion: str, public_key: str) -> Contact:
        """
        File an unknown sender as a pending request.

        If this onion address already belongs to an accepted contact under a
        *different* key, this is not an ordinary "someone new wants to talk"
        case - it is either that contact's identity changing (they
        regenerated their identity, or restored a different backup onto the
        same onion by mistake) or an attacker who has taken over that onion
        address and is trying to be treated as the existing contact. Either
        way it must not silently replace the trusted key, and the user must
        see a clearly different message than a routine first-contact request.
        The warning is carried in the pending contact's display name (no
        schema change) so it surfaces wherever a contact's name is already
        shown - the sidebar list, the request screen, and status text.
        """
        if not onion.endswith(".onion"):
            raise ValueError("Invalid onion address in request.")
        if len(crypto.b64decode(public_key)) != 32:
            raise ValueError("Invalid public key in request.")

        conflicting = self._find_accepted_by_onion(onion)
        if conflicting is not None:
            name = (
                f"⚠ Possible impersonation of "
                f"{conflicting.name} ({public_key[:8]})"
            )
        else:
            name = f"Unknown ({public_key[:8]})"

        contact = Contact(
            id=str(uuid.uuid4()),
            name=_clean_name(name),
            onion=onion,
            public_key=public_key,
            added=_now(),
            status=STATUS_PENDING,
        )
        self.contacts.append(contact)
        self.save()
        return contact

    def accept_contact(self, contact_id: str, name: str = "") -> None:
        with self._lock:
            contact = self.get_contact(contact_id)
            if contact is None:
                return
            contact.status = STATUS_ACCEPTED
            if name.strip():
                contact.name = _clean_name(name)
            self.save()

    def block_contact(self, contact_id: str) -> None:
        """Refuse this key permanently, keeping the record so it stays blocked."""
        with self._lock:
            contact = self.get_contact(contact_id)
            if contact is None:
                return
            contact.status = STATUS_BLOCKED
            contact.messages = []
            self.save()

    def set_verified(self, contact_id: str, verified: bool) -> None:
        """Mark that the user compared fingerprints over a trusted channel."""
        with self._lock:
            contact = self.get_contact(contact_id)
            if contact is not None:
                contact.verified = verified
                self.save()

    def set_accept_from_anyone(self, allowed: bool) -> None:
        with self._lock:
            if self.identity is not None:
                self.identity.accept_from_anyone = allowed
                self.save()

    # -- identity backup --------------------------------------------------- #
    def export_identity(self, path: str, passphrase: str) -> None:
        """
        Write an encrypted backup of the identity: the X25519 private key and
        the Tor onion key.

        Together these *are* the identity - anyone holding them can be you.
        The file is therefore encrypted with its own passphrase (which may
        differ from the vault's) and written 0600. Contacts and message
        history are deliberately excluded; this backs up who you are, not what
        you said.
        """
        with self._lock:
            if self.identity is None:
                raise VaultLocked("Vault is locked.")

            payload = json.dumps({
                "format": "onionmsg-identity-1",
                "private_key": self.identity.private_key,
                "public_key": self.identity.public_key,
                "onion": self.identity.onion,
                "onion_key": self.identity.onion_key,
            }).encode("utf-8")

            salt = crypto.new_salt()
            key = crypto.derive_key(passphrase, salt)
            blob = IDENTITY_MAGIC + salt + crypto.encrypt_blob(payload, key)

            # Same chmod-before-rename + directory-fsync treatment as save(),
            # for the same crash-safety reason.
            tmp_path = f"{path}.tmp"
            with open(tmp_path, "wb") as f:
                f.write(blob)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, path)
            _fsync_dir(os.path.dirname(os.path.abspath(path)))

    def import_identity(self, path: str, passphrase: str) -> None:
        """
        Replace the current identity with one from a backup.

        Contacts and history are kept, but they will only work if they belong
        to the imported identity, so this is normally done on a fresh vault.
        """
        with self._lock:
            with open(path, "rb") as f:
                blob = f.read()

            if not blob.startswith(IDENTITY_MAGIC):
                raise ValueError("This file is not a Veilwire identity backup.")

            salt_start = len(IDENTITY_MAGIC)
            salt_end = salt_start + crypto._SALT_BYTES
            salt = blob[salt_start:salt_end]

            key = crypto.derive_key(passphrase, salt)
            payload = crypto.decrypt_blob(blob[salt_end:], key)  # raises on bad passphrase
            data = json.loads(payload.decode("utf-8"))

            if data.get("format") != "onionmsg-identity-1":
                raise ValueError("Unsupported identity backup format.")

            private_key = data["private_key"]
            # Derive the public key rather than trusting the file, so a corrupted
            # or tampered backup cannot install a mismatched pair.
            derived = crypto.b64encode(
                crypto.public_key_from_private(crypto.b64decode(private_key))
            )
            if derived != data.get("public_key"):
                raise ValueError("This backup is corrupt: the key pair does not match.")

            self.identity = Identity(
                private_key=private_key,
                public_key=derived,
                onion=data.get("onion", ""),
                onion_key=data.get("onion_key", ""),
                accept_from_anyone=True,
            )
            self.save()

    def regenerate_identity(self) -> None:
        """
        Throw away the current identity and create a new one.

        The onion address changes too, so every contact must add the new
        address before they can reach us again.
        """
        with self._lock:
            private_raw, public_raw = crypto.generate_keypair()
            signing_priv_b64, signing_pub_b64 = _generate_signing_keypair()
            self.identity = Identity(
                private_key=crypto.b64encode(private_raw),
                public_key=crypto.b64encode(public_raw),
                signing_private_key=signing_priv_b64,
                signing_public_key=signing_pub_b64,
            )
            self.save()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _migrate_legacy_vault(new_path: str) -> None:
    """
    One-time move of a pre-XDG-paths vault.dat (from a dev checkout or an
    install predating this change, which stored it next to app.py) to the
    new XDG data directory.

    Only runs when the new location has no vault yet and an old one is
    found - never overwrites an existing vault at the new location, and
    moves (not copies) the file so there is exactly one copy on disk
    afterward, not a stray plaintext-adjacent duplicate. Safe to call on
    every startup: after the first successful move, the old path no longer
    exists, so this becomes a no-op forever after.

    Refuses to migrate if the legacy path is itself a symlink: shutil.move
    would move the symlink, not its contents, so the new vault location
    would silently become a symlink to whatever the old one pointed at,
    and every future save()/unlock() would read and write through it. The
    O_NOFOLLOW open below both proves the legacy path isn't a symlink at
    the moment of use (not just at an earlier check, avoiding a
    check-then-act race) and gives an already-open, symlink-proof file
    descriptor to chmod - a path-based os.chmod() on the destination could
    itself follow a symlink if one were ever placed there between the move
    and the chmod call.
    """
    if os.path.exists(new_path):
        return
    legacy_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), DEFAULT_FILENAME
    )
    if legacy_path == new_path or not os.path.exists(legacy_path):
        return
    if os.path.islink(legacy_path):
        _logger.warning("Legacy vault.dat is a symlink; refusing to auto-migrate it.")
        return
    try:
        shutil.move(legacy_path, new_path)
        fd = os.open(new_path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        _logger.info("Migrated vault.dat to the new data directory.")
    except OSError:
        _logger.exception("Could not migrate legacy vault.dat")


def _clean_name(name: str) -> str:
    """Bound a display name's length. Cosmetic field, but an unbounded
    attacker- or user-supplied name would still bloat the vault file and
    the contact-list UI."""
    return name.strip()[:MAX_CONTACT_NAME_LENGTH]


def _clean_group_name(name: str) -> str:
    """Same bound as _clean_name, for group names."""
    return name.strip()[:MAX_GROUP_NAME_LENGTH]


def _generate_signing_keypair() -> tuple[str, str]:
    """Generate a fresh Ed25519 signing keypair. Returns
    (private_key_b64, public_key_b64), same base64 convention as the
    X25519 identity keys."""
    signing_key = SigningKey.generate()
    return (
        crypto.b64encode(bytes(signing_key)),
        crypto.b64encode(bytes(signing_key.verify_key)),
    )


def short_id(fingerprint_text: str) -> str:
    """
    A short, non-reversible-to-onion identifier for logs and diagnostics:
    the first 8 hex characters of an existing fingerprint (e.g. "ABCD1234"),
    never the onion address itself. Use this anywhere a peer needs to be
    named in a log line - the fingerprint is already meant to be shared, so
    this reveals nothing an onion address exposure would.
    """
    return fingerprint_text.replace(" ", "")[:8]


def _fsync_dir(dir_path: str) -> None:
    """
    Fsync a directory after a rename into it.

    os.replace() is atomic, but the rename becoming durable on disk is a
    separate guarantee on some filesystems - without this, a crash right
    after a successful replace() can still lose the rename on power loss.
    """
    try:
        fd = os.open(dir_path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)

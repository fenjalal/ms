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

import json
import logging
import os
import shutil
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from nacl.signing import SigningKey

import bundle as bundle_mod
import crypto
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

    @property
    def is_locked(self) -> bool:
        return self._key is None

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
            self.groups = [Group(**g) for g in data.get("groups", [])]

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

    def save(self) -> None:
        with self._lock:
            if self._key is None or self._salt is None or self.identity is None:
                raise VaultLocked("Cannot save a locked vault.")

            payload = {
                "identity": asdict(self.identity),
                "contacts": [asdict(c) for c in self.contacts],
                "groups": [asdict(g) for g in self.groups],
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

    def sorted_groups(self) -> list[Group]:
        with self._lock:
            return sorted(self.groups, key=lambda g: self.group_last_activity(g), reverse=True)

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

    def add_group_member(self, group_id: str, contact_id: str) -> None:
        """Add an already-accepted contact to a group. A member added this
        way only sees *future* messages sent while they are a member -
        there is no history to backfill from, since past messages were
        never sent to them (see Group's docstring on there being no shared
        roster)."""
        with self._lock:
            group = self.get_group(group_id)
            if group is None:
                return
            contact = self.get_contact(contact_id)
            if contact is None or contact.status != STATUS_ACCEPTED:
                raise ValueError("Only an existing, accepted contact can be added to a group.")
            if contact_id in group.member_contact_ids:
                return
            if len(group.member_contact_ids) >= MAX_GROUP_MEMBERS:
                raise ValueError(f"A group can have at most {MAX_GROUP_MEMBERS} members.")
            group.member_contact_ids.append(contact_id)
            self.save()

    def remove_group_member(self, group_id: str, contact_id: str) -> None:
        with self._lock:
            group = self.get_group(group_id)
            if group is not None and contact_id in group.member_contact_ids:
                group.member_contact_ids.remove(contact_id)
                self.save()

    def delete_group(self, group_id: str) -> None:
        """Forget the group. Past messages are left in place on each
        member's own contact record (still tagged with the now-orphaned
        group_id) rather than deleted, matching how removing a contact
        does not retroactively scrub messages already exchanged."""
        with self._lock:
            self.groups = [g for g in self.groups if g.id != group_id]
            self.save()

    def create_group_from_invite(self, group_id: str, name: str, first_member_id: str) -> Group:
        """
        Auto-create a local Group the first time an incoming message arrives
        tagged with a group id (envelope.py's "gid") this vault does not
        already have. Since group membership is entirely local (see Group's
        docstring - there is no server-side roster), a group-tagged message
        from a contact you have not filed under any local group yet is,
        practically, that contact including you in a group they set up on
        their side; this is what lets it show up as a group conversation on
        yours too instead of silently being dropped.

        Unlike create_group(), the new Group's id is the SENDER's own gid
        rather than a freshly generated one, so a later message tagged with
        the same gid - from this sender, or from another member once this
        one gets added via add_group_member - is recognized as the same
        group instead of each starting a separate one. If a group with this
        id already exists, it is returned unchanged (idempotent - a caller
        does not need to check existence first).
        """
        with self._lock:
            existing = self.get_group(group_id)
            if existing is not None:
                return existing
            member = self.get_contact(first_member_id)
            if member is None or member.status != STATUS_ACCEPTED:
                raise ValueError("Only an existing, accepted contact can start a group.")
            group = Group(
                id=group_id,
                name=_clean_group_name(name) or "Group",
                created=_now(),
                member_contact_ids=[first_member_id],
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
    ) -> Message | None:
        with self._lock:
            contact = self.get_contact(contact_id)
            if contact is None:
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

# Veilwire v1.0.0

*Open source (MIT). Alpha  see Limitations before relying on it.*

Peer-to-peer encrypted messaging over Tor. No servers, no accounts, no email,
no phone numbers, no third-party services of any kind.

Starting the app publishes a Tor v3 onion service on your own machine. That
onion address, bundled with your public key, is your entire identity. Contacts
connect directly to it through Tor. There is no server in the middle to read
your messages, log your IP address, or be handed a subpoena.

MIT licensed. Linux desktop (Python + PySide6).

---

## How it works

```
  You                          Tor network                      Contact
┌──────────────┐                                          ┌──────────────┐
│ onionmsg     │                                          │ onionmsg     │
│              │   encrypted (NaCl Box)                   │              │
│ hidden       │ ═══════════════════════════════════════► │ hidden       │
│ service      │   inside a Tor circuit                   │ service      │
│              │   (3 relays, no exit node)               │              │
│ vault.dat    │                                          │ vault.dat    │
│ (encrypted)  │   no server ever sees this traffic       │ (encrypted)  │
└──────────────┘                                          └──────────────┘
```

## Keys

You have two key pairs, both created on first launch:

| | Shared? | Purpose |
|---|---|---|
| **Public key** | Yes, freely | Others encrypt to it and verify messages came from you |
| **Private key** | **Never** | Decrypts messages sent to you; stays in the encrypted vault |
| **Signing key pair** | Public half only | Signs your contact bundle (see below) so it cannot be tampered with |
| **Fingerprint** | Yes | A short code (`B991 4DEE 4F8F 70C1 9BFA`) to verify identity by voice |

Your onion address is **not** part of your identity for sharing purposes - it
is the internal Tor endpoint the app connects to on your behalf. It stays
inside the encrypted vault and is never shown in the normal UI, printed in a
contact card, or included in what you copy or export. What you actually
share is a **contact bundle** (below), and what a contact verifies you by is
your **fingerprint**.

Anyone holding your contact bundle can send you a **first message**. It
arrives as a **request**, not a delivered message  you see their fingerprint
and choose to accept or block. Nothing enters a conversation until you
decide. If you would rather nobody can reach you unsolicited, turn off "Let
anyone with my address send a first message" in **Keys...**.

### Sharing your contact

**Keys... → Share Contact...** (or the sidebar's **Share Contact...**
button) shows a QR code and a copyable string that starts with `P2PMSG1:`.
Scan it or paste it into someone's **Add Contact** dialog to give them
everything they need to reach you.

This bundle is **signed, not encrypted**:

- It is authenticated with your signing key, so a bundle that has been
  modified in any way  a different onion, a different public key, a
  swapped fingerprint  fails to verify and is rejected outright. This is
  what stops an attacker from intercepting your bundle and quietly
  redirecting a contact's messages to their own onion service instead.
- It is **not** confidential. Anyone who has the raw bundle text or QR
  image  a screenshot, an intercepted paste  can decode the onion address,
  public key, and fingerprint inside it. There is no way around this for a
  first-time share: encrypting it would require a key belonging to a
  recipient you have no relationship with yet, which does not exist at
  share time. This is the same exposure the old plaintext
  `onionmsg:<onion>:<public key>` address always had  the bundle format
  does not make that worse, it just stops the onion from being printed in
  the clear across the app's normal screens.
- Treat a copied bundle or a screenshot of its QR code the way you'd treat
  the old address string: don't post it somewhere public if you don't want
  strangers reaching you, since "Let anyone with my address send a first
  message" governs what an unknown sender can do with it, not who can read
  it.

The legacy plaintext address (`onionmsg:<onion>:<public key>`) still works
if someone gives you one directly  **Add Contact** accepts either format
pasted into the same box.

### Verify fingerprints

This is the one step no code can do for you. Before trusting a contact, read
your fingerprint to them over a channel you already trust  a phone call, in
person  and have them read theirs back. Matching fingerprints prove you hold
each other's real keys and there is no man in the middle. Verified contacts
show a checkmark.

### If a contact's connection information changes

If someone you have already added sends a bundle claiming the same public
key but a different onion address, the app does **not** silently switch to
the new endpoint. It shows a **"⚠ Identity / Endpoint Changed"** warning
instead of a routine contact request, with only the fingerprint shown  not
the onion, even here  and lets you **Review** (treat it like a fresh
request) or **Reject** it. This covers both an identity that legitimately
moved (e.g. they restored a backup or regenerated their identity onto the
same key by mistake) and an attacker who has taken over the old onion
address and is trying to be treated as the existing contact  the app
cannot tell those apart on its own, so it asks you.

### Backup

**Keys... → Back up identity** writes an encrypted file containing your
private key and onion key, protected by its own passphrase. Restoring it on
another machine gives you the *same identity and the same onion address*, so
contacts never need to re-add you.

Anyone with that file *and* its passphrase can impersonate you. Store it like
a password vault.

### Two layers of encryption

1. **Tor onion service**  the connection itself is end-to-end encrypted and
   authenticated by Tor, with no exit node involved. Traffic never touches the
   clear internet.
2. **NaCl Box (X25519 + XSalsa20-Poly1305)**  the message body is separately
   encrypted to your contact's public key *before* it enters the tunnel.

Layer 2 means that even a flaw in layer 1, or a malicious relay, still cannot
read your messages. Because Box is authenticated encryption, a message that
decrypts successfully *proves* it came from the holder of that private key —
there is no separate signature step to get wrong.

### Local storage

Everything on disk  your identity keys, contacts, and full message history —
lives in a single `vault.dat`, encrypted with a key derived from your
passphrase using Argon2id. Copying the file gives an attacker nothing but its
size. The file is written `0600` and is git-ignored.

---

## Requirements

- Any Linux desktop (Debian, Ubuntu, Kali, Fedora, Arch, openSUSE, Alpine,
  Void, Gentoo, and their derivatives are all detected automatically)
- Python 3.9+
- Tor

You do not need to configure Tor, edit `torrc`, or run anything as root. The
app detects your distribution and either uses the Tor you already have or
starts its own private instance, then publishes the onion service itself.

If Tor is missing, the app tells you the exact install command for *your*
distribution  `apt`, `dnf`, `pacman`, `zypper`, `apk`, `xbps`, or `emerge`.

## Install

### Debian / Ubuntu / Kali / Mint / Pop!_OS (.deb)

```bash
sudo apt install ./veilwire_1.0.0_amd64.deb
```

**Use `apt install ./file.deb`, not `sudo dpkg -i file.deb`.** This is the
one thing people get wrong most often with any `.deb` that has
dependencies (this is normal, standard `apt`/`dpkg` behavior, not specific
to Veilwire): `dpkg -i` only unpacks the file you give it  it does **not**
go fetch missing dependencies (`python3-stem`, `python3-segno`, etc.) from
your distro's repositories, so it fails with "dependency problems" if any
of them aren't already installed. `apt install ./file.deb` resolves and
installs those dependencies automatically in the same step, and is the
command every current Debian/Ubuntu install guide recommends for a local
`.deb` file.

If you already ran `dpkg -i` and hit the dependency error, this fixes it
without starting over:

```bash
sudo apt install -f
```

Once installed, launch **Veilwire** from your application menu, or run:

```bash
veilwire
```

No `python3 app.py`, no virtualenv, no manual `pip install`  the package
declares its dependencies on your distribution's own Python packages
(PySide6, PyNaCl, stem, PySocks, segno) and Tor, so `apt` installs
everything needed in one step.

### Other formats

`.rpm` (Fedora/RHEL/Rocky/AlmaLinux), an Arch package, an AppImage, and a
Flatpak are also supported from the same source  see
[`packaging/`](packaging/) and run `./build.sh <format>` to build them, or
`./build.sh all` to build every format your machine has the tooling for.
Once built:

```bash
sudo dnf install ./veilwire-1.0.0-1.x86_64.rpm        # Fedora/RHEL/Rocky/AlmaLinux
sudo pacman -U ./veilwire-1.0.0-1-x86_64.pkg.tar.zst   # Arch/Manjaro/EndeavourOS
chmod +x ./Veilwire-1.0.0-x86_64.AppImage && ./Veilwire-1.0.0-x86_64.AppImage
flatpak install --user ./Veilwire-1.0.0-x86_64.flatpak
```

### From source (development)

```bash
git clone <your-repo-url> veilwire
cd veilwire
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

## Run

Installed via a package: run `veilwire` or launch it from your
application menu  that's it.

Running from a source checkout: `python3 app.py`.

On first launch you choose a passphrase; a keypair and an onion service are
created for you. Startup takes 30–90 seconds the first time while Tor
bootstraps and publishes your service.

### The status bar

A coloured dot at the bottom shows your real state:

| Dot | Meaning |
|-----|---------|
| Green | Online, onion service published and registered |
|  | Contacts show `●` when their app is open, `○` when it is closed |
| Amber | Working on it  bootstrapping, no circuits yet, or republishing |
| Red | Tor is down, or the listener stopped |
| Grey | Starting up |

**Check now** runs a full end-to-end test: it connects to your *own* onion
address through Tor, exactly as a contact would. This is the only check that
proves the whole path works  Tor thinking it is fine is not the same as
actually being reachable.

### Talking to someone

1. Click **Share Contact...** and let them scan the QR code, or copy the
   bundle and send it to them over any channel you already trust (in person,
   Signal, a call  see the warning below).
2. They do the same.
3. Each of you clicks **Add**, pastes the other's bundle (or address), and
   gives it a name.
4. Type and hit **Send**.

**Both of you must have the app open at the same time.** There is no server
storing messages for later, so if your contact is offline the send fails and
is marked "Not delivered" in the thread. This is a direct consequence of
having no infrastructure  see Limitations.

### Sending a file or image

Click the paperclip button next to **Send** and pick a file. It is sent the
same way a text message is - end-to-end encrypted with NaCl Box, then
through Tor - with no separate upload step and nothing ever touching a
server. Images get an inline preview; anything else shows a filename and
size with a **Save As...** link. Attachments are limited to 8 MB and, once
received, are stored inside the same encrypted `vault.dat` as everything
else - never auto-written to a loose file on disk.

**Sending an image, you get an extra choice: "Send Compressed" (recommended)
or "Send Original".** This is a security decision, not a quality one - a
file that merely *claims* to be an image is a real way to smuggle something
else to a contact, and "Send Compressed" fully decodes the image and
rebuilds it from scratch as a fresh JPEG, so only the decoded picture itself
is ever sent, never any of the original file's raw bytes beyond that (which
also strips embedded metadata, like GPS location, along the way). A file
that fails to decode as an image at all is flagged rather than sent - a
strong sign it is not really an image. "Send Original" stays available for
when you trust the file and need the exact bytes, e.g. for quality or
provenance. Be clear about the limit of this: it protects against a
disguised or booby-trapped *file*, not against a flaw in the image decoder
itself on either end - that is a deeper class of risk no re-encoding step
can fix. See `app._recompress_image_bytes`'s docstring for the precise,
unexaggerated claim.

### Deleting a message ("delete for everyone")

Every message bubble you sent yourself - text or file, delivered or still
queued - has a small **Delete** link. Only your own messages ever offer it;
there is no way to delete a message someone else sent you, on either side of
the conversation. Choosing it does two things: it immediately blanks that
message in your own vault (the bubble stays in place, showing "This message
was deleted", rather than leaving a confusing gap), and it queues a real
"delete" notification to whoever received it - sent the exact same way any
other message is, end-to-end encrypted straight to their onion address, with
no server involved and nothing to delete "on a backend" because there isn't
one. If they are offline right now, the notification waits in your own
queue and keeps retrying, same as a text message would, until it gets
through - deleting does not require the original message to have been
delivered first.

The receiving side only ever acts on a delete request for a message it can
verify actually came from that same sender - it is impossible for anyone to
delete a message *you* sent, or a message a different contact sent you, by
naming its id. See `envelope.py`'s module docstring and
`vault.Vault.mark_deleted()`/`queue_delete_request()` for the mechanism, and
`test_delete.py` for an explicit test of a forged delete attempt being
rejected.

One honest limitation: a message sent before this feature existed has no
delete link, since there is no reliable shared id to delete it by (older
versions never generated one, and nothing else survives to give one
retroactively) - it can be removed locally by deleting the contact or
editing `vault.dat` directly, but not remotely.

### Group chat

**New Group** in the sidebar lets you name a group and pick members from
contacts you have already added - a group can only be built from people
already in your address book, since a message still has to be individually
sent, end-to-end encrypted, straight to each member's own onion address.

Sending in a group is really one individually encrypted message per member,
delivered the same way a 1:1 message is (including the same offline queue
and retry behavior). There is no group server and no shared membership
list: each participant sets up the group's member list on their own side,
and the first group message from someone introduces that group to your
client if you do not already have it. See Limitations for what this does
and does not guarantee.

---

## Threat model

Be clear about what this does and does not protect against.

### Protects against

- **Network surveillance.** Your ISP and anyone watching the wire see Tor
  traffic, not who you talk to or what you say.
- **Server compromise or subpoena.** There is no server. Nothing to seize,
  nothing to log, no company that can be compelled to hand over records.
- **IP address exposure.** Neither side learns the other's IP; Tor hides both
  ends.
- **Metadata collection.** No account, no phone number, no email, no contact
  list uploaded anywhere. Your contacts exist only in your encrypted vault.
- **Message tampering or forgery.** Authenticated encryption rejects any
  modified or forged message.
- **Impersonation.** An attacker can claim any public key they like in the
  frame header, but cannot produce a payload that authenticates against it.
  Verified in the test suite.
- **Contact bundle tampering.** A shared contact bundle is signed - changing
  the onion address, public key, or fingerprint inside it invalidates the
  signature, so a modified bundle is rejected rather than silently
  installing a wrong endpoint. This does **not** make the bundle secret:
  anyone who has the bundle itself can still read what's inside it. See
  "Sharing your contact" above.
- **Stolen laptop.** The vault is useless without the passphrase.
- **Silently going offline.** A background monitor checks every 20 seconds
  that Tor is alive, circuits are up, your onion service is still registered,
  and the listener is accepting. If the service has vanished it is republished
  automatically with the same address, so contacts never have to re-add you.

### Does NOT protect against

- **A compromised endpoint.** Malware or a keylogger on either computer reads
  everything before it is ever encrypted. No messenger can fix this.
- **A malicious contact.** Anyone you talk to can screenshot, log, or leak the
  conversation. Encryption controls who *can* read a message, never what they
  do with it afterwards.
- **"Delete for everyone" undoing something already seen.** Deleting a
  message removes it from both vaults going forward - it cannot reach back
  and un-show something the recipient already read, screenshotted, or copied
  out before you deleted it. It also cannot delete anything from a backup of
  their vault made before the deletion arrived.
- **A weak passphrase.** Argon2id makes guessing expensive, not impossible.
  Use a long passphrase.
- **Contact bundle interception.** The bundle is signed, not encrypted:
  anyone who intercepts it - a screenshot of the QR code, a copied string
  read over someone's shoulder or off an insecure channel - can read the
  onion, public key, and fingerprint inside it, same as with the old
  plaintext address. What the signature stops is a bundle being *modified*
  in transit without detection, not a bundle being *read* in transit. The
  app gives you a fingerprint precisely so you can catch a swapped identity:
  compare it out of band before trusting a contact. Unverified contacts are
  exactly as trustworthy as the channel you got their bundle from.
- **A leaked identity backup.** The backup file plus its passphrase *is* your
  identity. Anyone with both becomes you.
- **Traffic confirmation by a global adversary.** Someone who can watch very
  large parts of the internet at once may correlate timing. This is a known
  limit of Tor itself.
- **The fact that you run Tor.** Your ISP can see you use Tor, just not what
  for. Use a bridge if that alone is a risk where you are.

---

## Limitations

These are design consequences, not bugs:

- **Delivery needs an overlap, not simultaneity.** A message sent to an
  offline contact is **queued**, encrypted, in your own vault, and the app
  keeps retrying until their onion service answers  so closing their app no
  longer loses the message. What is still required is that *your* app is open
  at some moment while they are online. If you send and immediately quit for a
  week, the message waits for you to come back.

  True offline delivery needs somewhere to park the bytes while both of you
  are away. That means either a relay you run (see "Always-on node" below) or
  untrusted store-and-forward infrastructure like Cwtch's. A blockchain is the
  wrong tool: it is a permanent, public, fully-replicated log, which is the
  opposite of what private messaging wants  the ciphertext would sit there
  forever, readable retroactively the day the encryption breaks, with sender
  timing and message sizes visible to everyone.

### Always-on node

The simplest real fix for offline delivery is to be online all the time. Run
onionmsg on a machine that never sleeps  a VPS, a Raspberry Pi, a home
server  and your address is always reachable. Your identity lives in
`vault.dat`, so restore an identity backup there and it *is* you.
- **Group chat has no shared roster.** A group is a local label each member
  sets up on their own side over their existing 1:1 contacts (see
  "Group chat" below) - there is no server to hold a group's membership, so
  adding or removing someone on your side does not change what anyone
  else's client shows. Voice and video are still not supported.
- **File/image attachments are capped at 8 MB** and sent as a single
  message, same as text - no chunked/resumable transfer, and (like text) a
  large attachment still needs both of you online at some point for it to
  go through.
- **Tor is slow.** Expect a few seconds per message, longer for an
  attachment near the size limit. That is the cost of routing through
  three relays.
- **Desktop Linux only.**
- **This is not audited software.** The cryptography comes from libsodium via
  PyNaCl and the transport from Tor  both well reviewed  but the code
  gluing them together here is not. If your safety genuinely depends on it,
  use [Ricochet Refresh](https://www.ricochetrefresh.net/) or
  [Cwtch](https://cwtch.im/) instead; they implement this same model and have
  had far more scrutiny.

---

## Project structure

```
onionmsg/
├── app.py                    # PySide6 UI: unlock, contacts, conversation, composer
├── crypto.py                 # NaCl wrappers: keys, Box encryption, Argon2id KDF
├── vault.py                  # Encrypted store: identity, contacts, messages
├── bundle.py                 # Signed shareable contact bundle (P2PMSG1:...)
├── envelope.py                # Structured message plaintext: text/file, group tag
├── tor_service.py            # Attaches to running Tor or launches one; health checks
├── platform_support.py       # Cross-distro detection: packages, groups, binaries
├── transport.py               # Wire protocol, listener, SOCKS5 client
├── test_transport.py         # Protocol + security tests
├── test_e2e.py                # Two identities exchanging real messages
├── test_py313.py              # Guards against Thread internal name collisions
├── test_platform.py           # Distro detection + health monitoring
├── test_keys.py                # Fingerprints, contact policy, identity backup
├── test_ui.py                  # Theme contrast, controls, version, icon, onion-hiding
├── test_offline.py             # Message queueing, retry, presence detection
├── test_vault_concurrency.py   # Concurrent vault access, atomic saves
├── test_shutdown.py            # Start/stop cycles, connection flooding
├── test_bundle.py              # Contact bundle: signing, tampering, endpoint changes
├── test_envelope.py            # Envelope encode/decode, legacy fallback, size limits
├── test_groups_and_files.py    # Group fan-out, auto-join, file/image transfer end-to-end
├── test_delete.py              # Delete-for-everyone, forged-delete rejection, image recompression
├── theme.py                   # Palette detection and the application stylesheet
├── version.py                 # Single source of truth for the version
├── make_icon.py                # Regenerates the icon PNGs
├── install.sh                  # Desktop launcher + icon install (no root)
├── onionmsg.desktop
├── icons/                      # 16-512px PNGs
├── requirements.txt
├── LICENSE                     # MIT
├── .gitignore
└── README.md
```

## Tests

```bash
python3 test_transport.py         # 27 checks: framing, auth, tampering, abuse,
                                   #            field validation, replay/duplicate detection
python3 test_e2e.py               # 23 checks: full two-party conversation
python3 test_py313.py             #  8 checks: Python 3.13+ threading compatibility
python3 test_platform.py          # 28 checks: distro detection, health monitoring
python3 test_keys.py              # 49 checks: keys, contact policy, backup/restore,
                                   #            impersonation detection, safe error text
python3 test_ui.py                # 124 checks: theme contrast, controls, branding,
                                   #             HTML-injection escaping, activity log,
                                   #             onion address never in normal UI,
                                   #             round send button, app icon,
                                   #             group aggregate-delivery-note rendering
python3 test_offline.py           # 19 checks: queueing, retry, presence
python3 test_vault_concurrency.py # 10 checks: concurrent vault access, atomic saves
python3 test_shutdown.py          # 12 checks: start/stop cycles, connection flooding
python3 test_bundle.py            # 54 checks: bundle signing/tampering, clearnet
                                   #            rejection, endpoint-change detection,
                                   #            no-onion-in-logs guard
python3 test_i18n.py              # 66 checks: translations, RTL, Settings dialog,
                                   #            restart-to-apply-language flow,
                                   #            no tr() call hidden inside an f-string
python3 test_envelope.py          # 40 checks: text/file/group/delete envelope encode-decode,
                                   #            legacy fallback, size limits, path safety
python3 test_groups_and_files.py  # 30 checks: group CRUD, multi-party fan-out and
                                   #            auto-join, end-to-end file/image transfer
python3 test_delete.py            # 35 checks: delete-for-everyone (local tombstone,
                                   #            queued wire notification, forged-delete
                                   #            rejection), image recompression choice
```

525 checks in total.

Both suites run without Tor by connecting over localhost; everything above the
transport is the real production code path.

## Troubleshooting

**Which Tor does it use?**  If you already have Tor running with a reachable
control port (9051, or 9151 for Tor Browser), the app attaches to it and says
"Online via your existing Tor". Otherwise it starts a private instance. Either
way the status bar tells you which.

**"Tor is not installed"**  `sudo apt install tor`.

**"Found Tor on control port 9051, but could not authenticate"**  Tor is
running but your user is not allowed to control it. Either join Tor's group:

```bash
sudo usermod -aG debian-tor $USER   # then log out and back in
```

or stop the system Tor and let the app run its own:

```bash
sudo systemctl stop tor
```

If you prefer to keep using the system Tor, make sure its control port is
enabled in `/etc/tor/torrc`:

```
ControlPort 9051
CookieAuthentication 1
```

**Startup hangs on "Bootstrapped"**  Tor is still connecting. First run can
take a minute or two. If it never finishes, Tor may be blocked on your
network; configure a bridge.

**"They are probably offline"**  expected when your contact does not have the
app running. Both sides must be online at once.

**Address changed after reinstalling**  the onion key lives in `vault.dat`.
Delete or lose that file and you get a new identity, and contacts must re-add
you.

**`TypeError: '_thread._ThreadHandle' object is not callable`**  fixed. This
came from a method name colliding with a private attribute added in Python
3.13. `test_py313.py` guards against it returning. Make sure you are running
the current version.

**Messages look blank or unreadable**  fixed in v0.0.1. Bubbles previously
inherited their text colour from the system palette, which made them invisible
on dark desktops. Colours are now always set in pairs and verified by
`test_ui.py` under both light and dark themes.

**"Queued - they are offline"**  expected. Their app is closed. Yours will
keep retrying every 45 seconds and deliver as soon as they open it, as long as
your app is still running. Nothing is lost if you quit; the queue is saved and
resumes on next launch.

**Forgot the passphrase**  there is no recovery. That is the point. Delete
`vault.dat` and start over with a new identity.

## Security reporting

Found a flaw? Open an issue, or for anything sensitive, contact the maintainer
privately before disclosing.

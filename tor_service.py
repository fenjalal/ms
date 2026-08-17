"""
tor_service.py

Owns the Tor side of the application.

Two ways to get a working Tor:

1. **Attach to a Tor that is already running** (preferred). Most Linux boxes
   already have the `tor` service up. If its control port is reachable we use
   it directly - nothing extra to start, and the onion service appears
   instantly.

2. **Launch a private Tor instance** as a fallback, if no running Tor can be
   controlled.

Note on threading: `stem.process.launch_tor` implements its `timeout` with
`signal.alarm`, which only works on the main thread. This module runs from a
Qt worker thread, so the timeout argument is deliberately not used - passing
it raises "Launching tor with a timeout can only be done in the main thread".

The onion address is the user's network identity, so the key that reproduces
it is kept in the encrypted vault, never on disk in the clear.
"""

from __future__ import annotations

import logging
import re
import threading
import time
from dataclasses import dataclass

import stem.process
from stem.control import Controller, Listener

import platform_support

# Full exception text (which can include local filesystem paths, e.g. the
# tor-data directory under the user's home) is logged here rather than
# placed in a TorError message, since TorError text is shown to the user
# in a dialog. See the calls below for what's kept safe vs. logged.
_logger = logging.getLogger("veilwire")

# The virtual port exposed on the onion service. Contacts always connect here;
# Tor maps it to a random local port on our machine.
ONION_PORT = 9045

# How long to wait for our own Tor to open its control port.
CONTROL_CONNECT_TIMEOUT = 30

# Overall budget for Tor to finish bootstrapping.
BOOTSTRAP_TIMEOUT = 180

# Abort early if bootstrap makes no progress at all for this long. A blocked
# network typically freezes at a low percentage rather than failing outright.
BOOTSTRAP_STALL_TIMEOUT = 60


def _parse_bootstrap_percent(phase: str) -> int:
    match = re.search(r"PROGRESS=(\d+)", phase)
    return int(match.group(1)) if match else 0


def _parse_bootstrap_summary(phase: str) -> str:
    match = re.search(r'SUMMARY="([^"]*)"', phase)
    return match.group(1) if match else "working"

# Control ports worth trying, in order: the standard system daemon, then Tor
# Browser's bundled instance.
COMMON_CONTROL_PORTS = (9051, 9151)

# Matching SOCKS ports, used when the controller cannot tell us itself.
DEFAULT_SOCKS_PORTS = {9051: 9050, 9151: 9150}


class TorError(Exception):
    """Raised when Tor cannot be reached or the onion service cannot be published."""


@dataclass
class OnionService:
    onion: str
    private_key: str  # "ED25519-V3:<blob>", so the address survives restarts
    service_id: str


def tor_is_installed() -> bool:
    """Delegates to platform_support, which also searches /usr/sbin etc."""
    return platform_support.tor_is_installed()


class TorManager:
    """
    Provides a controlled Tor connection and publishes an onion service on it.
    """

    def __init__(self, data_dir: str, socks_port: int = 9250, control_port: int = 9251) -> None:
        self.data_dir = data_dir
        # These are only used if we have to launch our own instance.
        self._own_socks_port = socks_port
        self._own_control_port = control_port

        self.socks_port = socks_port  # updated once we know which Tor we use
        self.using_existing_tor = False

        self._process = None
        self._controller: Controller | None = None
        self._cancelled = threading.Event()
        self.service: OnionService | None = None

    # -- startup ---------------------------------------------------------- #
    def start(self, progress=None) -> None:
        """
        Get a usable, controllable Tor.

        `progress` is an optional callable taking a status string so the UI can
        report what is happening instead of appearing frozen.
        """

        def say(text: str) -> None:
            if progress:
                progress(text)

        say("Looking for a running Tor...")
        if self._attach_to_existing(say):
            return

        say("No controllable Tor found. Starting a private one...")
        self._launch_own(say)

    def _attach_to_existing(self, say) -> bool:
        """Try to control a Tor that is already running. Returns True on success."""
        for port in COMMON_CONTROL_PORTS:
            controller = None
            try:
                controller = Controller.from_port(port=port)
            except Exception:
                continue  # nothing listening on this port

            try:
                controller.authenticate()
            except Exception as exc:
                controller.close()
                # Tor is running but we are not allowed to control it. This is
                # the common "cookie file not readable" case, and it is worth
                # telling the user precisely how to fix it.
                raise TorError(
                    f"Found Tor running on control port {port}, but this app is "
                    f"not allowed to control it.\n\n"
                    f"{platform_support.permission_fix_instructions()}"
                ) from exc

            self._controller = controller
            self.using_existing_tor = True
            self.socks_port = self._detect_socks_port(controller, port)
            say(f"Using the Tor already running (control {port}, SOCKS {self.socks_port}).")

            # It may still be starting up, so wait for it just like our own.
            self._await_bootstrap(controller, say)
            return True

        return False

    @staticmethod
    def _detect_socks_port(controller: Controller, control_port: int) -> int:
        """Ask Tor which SOCKS port it actually listens on."""
        try:
            listeners = controller.get_listeners(Listener.SOCKS)
            if listeners:
                return int(listeners[0][1])
        except Exception:
            pass
        return DEFAULT_SOCKS_PORTS.get(control_port, 9050)

    def _launch_own(self, say) -> None:
        """
        Start a private Tor instance we fully control.

        `stem`'s own timeout is implemented with signal.alarm and is silently
        disabled off the main thread, which would leave a censored or offline
        machine stuck on "Bootstrapped 14%" forever. So we ask stem to return
        as soon as the process is up (completion_percent=0) and run our own
        cancellable bootstrap watchdog instead.
        """
        if not tor_is_installed():
            raise TorError(platform_support.install_instructions())

        try:
            self._process = stem.process.launch_tor_with_config(
                tor_cmd=platform_support.find_tor_binary() or "tor",
                config={
                    "SocksPort": str(self._own_socks_port),
                    "ControlPort": str(self._own_control_port),
                    "DataDirectory": self.data_dir,
                    "CookieAuthentication": "1",
                    "AvoidDiskWrites": "1",
                },
                completion_percent=0,  # return immediately; we poll ourselves
                take_ownership=True,
            )
        except OSError as exc:
            _logger.exception("Failed to launch Tor")
            message = str(exc)
            if "Address already in use" in message or "Could not bind" in message:
                raise TorError(
                    f"Port {self._own_socks_port} or {self._own_control_port} is already in use. "
                    f"Another copy of this app may already be running."
                ) from exc
            raise TorError(
                "Could not start Tor. Check that Tor is correctly installed."
            ) from exc

        # Give Tor a moment to open its control port, then connect.
        controller = None
        for _ in range(int(CONTROL_CONNECT_TIMEOUT / 0.5)):
            if self._cancelled.is_set():
                self.stop()
                raise TorError("Cancelled.")
            try:
                controller = Controller.from_port(port=self._own_control_port)
                break
            except Exception:
                time.sleep(0.5)

        if controller is None:
            self.stop()
            raise TorError("Tor started but never opened its control port.")

        try:
            controller.authenticate()
        except Exception as exc:
            _logger.exception("Could not authenticate to our own Tor")
            self.stop()
            raise TorError("Could not authenticate to our own Tor.") from exc

        self._controller = controller
        self.socks_port = self._own_socks_port
        self.using_existing_tor = False

        self._await_bootstrap(controller, say)

    def _await_bootstrap(self, controller: Controller, say) -> None:
        """
        Poll bootstrap progress until Tor is ready, we time out, or the user
        cancels. This is the watchdog stem cannot give us off the main thread.
        """
        deadline = time.time() + BOOTSTRAP_TIMEOUT
        last_percent = -1
        last_progress_at = time.time()

        while time.time() < deadline:
            if self._cancelled.is_set():
                self.stop()
                raise TorError("Cancelled.")

            try:
                phase = controller.get_info("status/bootstrap-phase")
            except Exception as exc:
                _logger.exception("Lost the connection to Tor while starting")
                self.stop()
                raise TorError("Lost the connection to Tor while starting.") from exc

            percent = _parse_bootstrap_percent(phase)
            summary = _parse_bootstrap_summary(phase)

            if percent != last_percent:
                last_percent = percent
                last_progress_at = time.time()
                say(f"Bootstrapping Tor... {percent}% ({summary})")

            if percent >= 100:
                say("Tor is ready.")
                return

            # Stalled for too long: almost always a blocked or filtered network.
            if time.time() - last_progress_at > BOOTSTRAP_STALL_TIMEOUT:
                self.stop()
                raise TorError(
                    f"Tor stalled at {percent}% ({summary}).\n\n"
                    f"This usually means Tor is blocked on your network. "
                    f"Try configuring a bridge, or check your connection."
                )

            time.sleep(1.0)

        self.stop()
        raise TorError(
            f"Tor did not finish starting within {BOOTSTRAP_TIMEOUT} seconds "
            f"(reached {max(last_percent, 0)}%). It may be blocked on this network."
        )

    def cancel(self) -> None:
        """Ask an in-progress start() to give up."""
        self._cancelled.set()

    # -- health checks ----------------------------------------------------- #
    def is_controller_alive(self) -> bool:
        """Is our control connection to Tor still usable?"""
        if self._controller is None:
            return False
        try:
            self._controller.get_info("version")
            return True
        except Exception:
            return False

    def circuit_established(self) -> bool:
        """Has Tor built working circuits?"""
        if self._controller is None:
            return False
        try:
            return self._controller.get_info("status/circuit-established").strip() == "1"
        except Exception:
            return False

    def is_service_published(self) -> bool:
        """
        Is our onion service still registered with Tor?

        An ephemeral service disappears if Tor restarts or the control
        connection drops, so this is the check that catches a silently dead
        address.
        """
        if self._controller is None or self.service is None:
            return False
        try:
            active = self._controller.list_ephemeral_hidden_services()
            return self.service.service_id in active
        except Exception:
            return False

    def republish(self, local_port: int) -> OnionService:
        """
        Re-register the onion service after it has been lost, keeping the same
        address so contacts do not need to re-add us.
        """
        if self.service is None:
            raise TorError("There is no previous service to republish.")
        return self.publish(local_port, self.service.private_key)

    def self_test(self, timeout: int = 90) -> tuple[bool, str]:
        """
        Prove the onion service is genuinely reachable by connecting to our own
        address through Tor, exactly as a contact would.

        This is the only check that tests the whole path end to end: Tor's
        SOCKS proxy, the onion descriptor lookup, the introduction and
        rendezvous circuits, and our local listener. Everything else only
        confirms Tor *thinks* things are fine.
        """
        if self.service is None:
            return False, "No onion service is published."

        import socks as _socks  # local import keeps the module dependency-light

        sock = _socks.socksocket()
        sock.set_proxy(_socks.SOCKS5, "127.0.0.1", self.socks_port, rdns=True)
        sock.settimeout(timeout)
        try:
            sock.connect((self.service.onion, ONION_PORT))
            return True, "Your onion service is reachable from the Tor network."
        except Exception:
            _logger.exception("Self-test connection failed")
            return False, "Could not reach your own onion service."
        finally:
            try:
                sock.close()
            except OSError:
                pass

    # -- onion service ----------------------------------------------------- #
    def publish(self, local_port: int, private_key: str = "") -> OnionService:
        """
        Publish the onion service pointing at `local_port`.

        Pass a stored `private_key` to keep the same address as last time, or
        an empty string to create a new identity.
        """
        if self._controller is None:
            raise TorError("Tor is not running.")

        if private_key:
            key_type, _, key_content = private_key.partition(":")
        else:
            key_type, key_content = "NEW", "ED25519-V3"

        try:
            response = self._controller.create_ephemeral_hidden_service(
                {ONION_PORT: local_port},
                key_type=key_type,
                key_content=key_content,
                await_publication=True,
                detached=False,
            )
        except Exception as exc:
            _logger.exception("Could not publish the onion service")
            raise TorError("Could not publish the onion service.") from exc

        # Tor returns the private key only when it generates a new one.
        stored_key = private_key or f"{response.private_key_type}:{response.private_key}"

        self.service = OnionService(
            onion=f"{response.service_id}.onion",
            private_key=stored_key,
            service_id=response.service_id,
        )
        return self.service

    # -- shutdown ---------------------------------------------------------- #
    def stop(self) -> None:
        """
        Close the controller and, if we started Tor ourselves, shut it down.

        A Tor we merely attached to is left running - it is not ours to stop.
        Because the onion service is ephemeral and non-detached, it disappears
        as soon as our control connection closes either way.
        """
        if self._controller is not None:
            try:
                self._controller.close()
            except Exception:
                pass
            self._controller = None

        if self._process is not None:
            try:
                self._process.terminate()
                self._process.wait(timeout=10)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None

        self.service = None

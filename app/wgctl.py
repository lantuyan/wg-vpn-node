"""wg0 control: create/configure the interface, manage peers, read stats.

This service OWNS wg0 (it replaces the old `linuxserver/wireguard` sidecar).
Everything here talks to the kernel through `ip`, `wg` and `iptables` via a
single private `_run()`. Rules:

* argv is always a list -- never `shell=True`.
* every call has a timeout and its argv (never secret material) is logged.
* a non-zero exit raises `ApiError` via `errors.wg_unavailable(detail)` with
  stderr folded into the detail.
* private keys and preshared keys are never placed in argv or logged: the
  server's own private key lives in a persisted mode-0600 file on disk and is
  handed to `wg set ... private-key <path>`; a peer's preshared key is written
  to a mode-0600 temp file for the duration of a single `wg set` call and
  removed in a `finally`. Both cases only ever put a *path* in argv.

`self._runner` (default `subprocess.run`) is a plain instance attribute so
tests can swap in a fake without touching the constructor signature, which is
pinned by docs/INTERNALS.md.
"""

from __future__ import annotations

import contextlib
import logging
import os
import re
import shlex
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from app.errors import wg_unavailable
from app.settings import Settings

logger = logging.getLogger("wgvpn.wgctl")


def _decode(data: bytes | str | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return data


def _fmt(argv: list[str]) -> str:
    return " ".join(shlex.quote(a) for a in argv)


@dataclass(frozen=True)
class PeerStat:
    public_key: str
    endpoint: str | None
    allowed_ips: list[str]
    latest_handshake: int
    rx_bytes: int
    tx_bytes: int
    keepalive: int


class WgController:
    def __init__(self, interface: str, settings: Settings) -> None:
        self.interface = interface
        self.settings = settings
        # Injectable: tests replace this attribute with a fake callable
        # matching subprocess.run's signature (argv, *, input=, capture_output=,
        # timeout=) -> CompletedProcess.
        self._runner = subprocess.run

    # ------------------------------------------------------------------
    # low-level exec
    # ------------------------------------------------------------------

    def _run(
        self,
        argv: list[str],
        *,
        input_bytes: bytes | None = None,
        timeout: float = 10.0,
        log_argv: list[str] | None = None,
    ) -> subprocess.CompletedProcess:
        display = log_argv if log_argv is not None else argv
        logger.debug("exec: %s", _fmt(display))
        try:
            proc = self._runner(
                list(argv), input=input_bytes, capture_output=True, timeout=timeout
            )
        except FileNotFoundError as exc:
            raise wg_unavailable(f"{display[0]}: command not found ({exc})") from exc
        except subprocess.TimeoutExpired as exc:
            raise wg_unavailable(
                f"`{_fmt(display)}` timed out after {timeout}s"
            ) from exc
        except OSError as exc:
            raise wg_unavailable(f"`{_fmt(display)}` failed to start: {exc}") from exc
        if proc.returncode != 0:
            stderr = _decode(proc.stderr).strip()
            raise wg_unavailable(
                f"`{_fmt(display)}` exited {proc.returncode}: {stderr or '(no stderr)'}"
            )
        return proc

    def _test(self, argv: list[str], *, timeout: float = 5.0) -> bool:
        """Quiet probe: True on exit 0, False on any error/non-zero/missing
        binary. Never raises -- used for idempotency checks only."""
        logger.debug("probe: %s", _fmt(argv))
        try:
            proc = self._runner(list(argv), capture_output=True, timeout=timeout)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False
        return proc.returncode == 0

    @contextlib.contextmanager
    def _secret_tempfile(self, content: str):
        """Write `content` to a mode-0600 file under <data_dir>/keys and yield
        its path; the file is removed in `finally` regardless of outcome."""
        keys_dir = self.settings.data_dir / "keys"
        keys_dir.mkdir(parents=True, exist_ok=True)
        fd, path = tempfile.mkstemp(prefix=".wgvpn-", suffix=".secret", dir=str(keys_dir))
        try:
            os.chmod(path, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(content.strip() + "\n")
            yield path
        finally:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    @staticmethod
    def _write_key_file(path: Path, content: str, *, mode: int) -> None:
        tmp = path.with_name(path.name + ".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(content.strip() + "\n")
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                tmp.unlink()
            raise
        os.chmod(tmp, mode)
        tmp.replace(path)

    # ------------------------------------------------------------------
    # keys
    # ------------------------------------------------------------------

    def gen_private_key(self) -> str:
        proc = self._run(["wg", "genkey"])
        return _decode(proc.stdout).strip()

    def derive_public_key(self, private_key: str) -> str:
        proc = self._run(["wg", "pubkey"], input_bytes=(private_key.strip() + "\n").encode())
        return _decode(proc.stdout).strip()

    def gen_preshared_key(self) -> str:
        proc = self._run(["wg", "genpsk"])
        return _decode(proc.stdout).strip()

    def public_key(self) -> str:
        """Server public key, read from `<data_dir>/keys/server.key.pub`.
        Requires `ensure_interface()` to have run at least once."""
        pub_path = self.settings.data_dir / "keys" / "server.key.pub"
        try:
            return pub_path.read_text().strip()
        except FileNotFoundError as exc:
            raise wg_unavailable(
                "server key not initialised; ensure_interface() has not run yet"
            ) from exc

    def _ensure_server_key(self) -> Path:
        keys_dir = self.settings.data_dir / "keys"
        keys_dir.mkdir(parents=True, exist_ok=True)
        with contextlib.suppress(OSError):
            os.chmod(keys_dir, 0o700)

        priv_path = keys_dir / "server.key"
        pub_path = keys_dir / "server.key.pub"

        if priv_path.exists():
            private_key = priv_path.read_text().strip()
        else:
            private_key = self.gen_private_key()
            self._write_key_file(priv_path, private_key, mode=0o600)

        public_key = self.derive_public_key(private_key)
        self._write_key_file(pub_path, public_key, mode=0o644)
        return priv_path

    # ------------------------------------------------------------------
    # interface lifecycle
    # ------------------------------------------------------------------

    def interface_up(self) -> bool:
        try:
            proc = self._runner(
                ["ip", "-o", "link", "show", "dev", self.interface],
                capture_output=True,
                timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False
        if proc.returncode != 0:
            return False
        out = _decode(proc.stdout)
        m = re.search(r"<([^>]*)>", out)
        return bool(m and "UP" in m.group(1).split(","))

    def _ensure_link(self) -> None:
        """Idempotently make sure the wg0 link device exists. Preflights that
        the kernel actually supports WireGuard netlink links, trying
        `modprobe wireguard` once, and raises a clear, actionable
        `wg_unavailable` if the kernel has no WireGuard support at all."""
        if self.interface_up():
            return
        if self._test(["ip", "link", "show", "dev", self.interface]):
            # link exists but is administratively down; _configure_link()
            # below brings it up.
            return
        if self._test(["ip", "link", "add", "dev", self.interface, "type", "wireguard"]):
            return
        self._test(["modprobe", "wireguard"])
        if self._test(["ip", "link", "add", "dev", self.interface, "type", "wireguard"]):
            return
        raise wg_unavailable(
            "kernel WireGuard support is unavailable: `ip link add type wireguard` "
            "failed even after `modprobe wireguard`. Ensure the host kernel provides "
            "the wireguard module (Linux >= 5.6, or wireguard-dkms installed on the "
            "host) and that this container has cap NET_ADMIN and is not running in a "
            "network namespace isolated from the host's networking stack."
        )

    def _configure_link(self, priv_path: Path) -> None:
        self._run(["ip", "link", "set", "dev", self.interface, "mtu", str(self.settings.wg_mtu)])
        server_addr = self.settings.network.network_address + 1
        cidr = f"{server_addr}/{self.settings.network.prefixlen}"
        self._run(["ip", "address", "replace", cidr, "dev", self.interface])
        self._run(
            [
                "wg",
                "set",
                self.interface,
                "private-key",
                str(priv_path),
                "listen-port",
                str(self.settings.wg_port),
            ]
        )
        self._run(["ip", "link", "set", "up", "dev", self.interface])

    def _sysctl_set(self, key: str, value: str, *, required: bool = True) -> bool:
        """Write one /proc/sys knob. Returns True when the value is in place.

        The value is read first and only written when it differs. ``/proc/sys``
        is mounted **read-only** inside the container, so the write fails with
        EROFS even for a knob docker already set to the wanted value through
        compose ``sysctls:`` -- which is exactly the case for
        ``net.ipv4.ip_forward``. Checking first turns that into a no-op instead
        of a fatal error.

        ``required=False`` turns a genuine failure into a warning. That
        distinction matters: ``/proc/sys/net/ipv6`` is unwritable in a
        container whose network namespace has no IPv6, and treating that as
        fatal used to abort :meth:`ensure_interface` *before* it installed the
        NAT rules -- leaving a wg0 that completes handshakes but carries no
        traffic, which is about the most confusing state this service can be in.
        """
        path = "/proc/sys/" + key.replace(".", "/")
        try:
            with open(path) as fh:
                if fh.read().strip() == value:
                    return True
        except OSError:
            pass  # unreadable: fall through and let the write report the reason
        try:
            with open(path, "w") as fh:
                fh.write(value)
            return True
        except OSError as exc:
            if not required:
                logger.warning(
                    "could not set %s=%s (%s): %s -- continuing without it",
                    key, value, path, exc,
                )
                return False
            raise wg_unavailable(
                f"cannot set {key}={value} ({path}): {exc}. /proc/sys is read-only "
                f"in the container, so set it through compose `sysctls:` (it is "
                f"then already correct here and this check passes), run with cap "
                f"NET_ADMIN, or set it on the host."
            ) from exc

    def _default_route_iface(self) -> str:
        proc = self._run(["ip", "route", "show", "default"])
        out = _decode(proc.stdout)
        m = re.search(r"\bdev\s+(\S+)", out)
        if not m:
            raise wg_unavailable(
                "could not discover the default-route interface via "
                "`ip route show default` (no default route present in this "
                "container's network namespace?)"
            )
        return m.group(1)

    def _ensure_iptables_rule(
        self, table: str | None, chain: str, rule_args: list[str]
    ) -> None:
        base = ["iptables"]
        if table:
            base += ["-t", table]
        if self._test(base + ["-C", chain] + rule_args):
            return
        self._run(base + ["-A", chain] + rule_args)

    def _ensure_nat_and_forwarding(self) -> None:
        default_if = self._default_route_iface()
        subnet = str(self.settings.network)
        self._ensure_iptables_rule(
            "nat", "POSTROUTING", ["-s", subnet, "-o", default_if, "-j", "MASQUERADE"]
        )
        self._ensure_iptables_rule(
            None, "FORWARD", ["-i", self.interface, "-o", default_if, "-j", "ACCEPT"]
        )
        self._ensure_iptables_rule(
            None,
            "FORWARD",
            [
                "-i",
                default_if,
                "-o",
                self.interface,
                "-m",
                "state",
                "--state",
                "RELATED,ESTABLISHED",
                "-j",
                "ACCEPT",
            ],
        )
        self._ensure_iptables_rule(
            "mangle",
            "FORWARD",
            [
                "-p",
                "tcp",
                "--tcp-flags",
                "SYN,RST",
                "SYN",
                "-j",
                "TCPMSS",
                "--clamp-mss-to-pmtu",
            ],
        )

    def ensure_interface(self) -> None:
        """Idempotent full setup of wg0: preflight kernel support, generate/
        reuse the server key, create the link, configure it, enable
        forwarding, install NAT/forward/MSS-clamp rules exactly once. Safe to
        call on every startup and to call more than once (e.g. from a retry)."""
        self._ensure_link()
        priv_path = self._ensure_server_key()
        self._configure_link(priv_path)
        self._sysctl_set("net.ipv4.ip_forward", "1")
        if any(":" in ip for ip in self.settings.allowed_ips_list):
            # Best effort: peers still route IPv4 without it, and IPv4 NAT is
            # what makes the tunnel usable at all.
            self._sysctl_set("net.ipv6.conf.all.forwarding", "1", required=False)
        self._ensure_nat_and_forwarding()

    # ------------------------------------------------------------------
    # peers
    # ------------------------------------------------------------------

    def set_peer(
        self, *, public_key: str, allowed_ips: list[str], preshared_key: str | None
    ) -> None:
        argv = [
            "wg",
            "set",
            self.interface,
            "peer",
            public_key,
            "allowed-ips",
            ",".join(allowed_ips),
        ]
        if preshared_key:
            with self._secret_tempfile(preshared_key) as psk_path:
                self._run(argv + ["preshared-key", psk_path])
        else:
            self._run(argv)

    def remove_peer(self, public_key: str) -> None:
        self._run(["wg", "set", self.interface, "peer", public_key, "remove"])

    def peer_stats(self) -> dict[str, PeerStat]:
        """Parses `wg show <if> dump`. The first line describes the interface
        itself (private-key, public-key, listen-port, fwmark) and is skipped;
        remaining lines are one peer each, tab separated, with `(none)` used
        as a placeholder for unset endpoint/preshared-key/keepalive."""
        proc = self._run(["wg", "show", self.interface, "dump"])
        text = _decode(proc.stdout)
        lines = [ln for ln in text.split("\n") if ln.strip()]
        result: dict[str, PeerStat] = {}
        for line in lines[1:]:
            fields = line.split("\t")
            if len(fields) < 8:
                continue
            public_key, _psk, endpoint, allowed_ips, handshake, rx, tx, keepalive = fields[:8]
            result[public_key] = PeerStat(
                public_key=public_key,
                endpoint=None if endpoint == "(none)" else endpoint,
                allowed_ips=[] if allowed_ips == "(none)" else allowed_ips.split(","),
                latest_handshake=int(handshake) if handshake.isdigit() else 0,
                rx_bytes=int(rx) if rx.isdigit() else 0,
                tx_bytes=int(tx) if tx.isdigit() else 0,
                keepalive=0 if keepalive == "(none)" else int(keepalive) if keepalive.isdigit() else 0,
            )
        return result

    def sync_peers(self, wanted: list[dict]) -> tuple[int, int]:
        """Makes wg0 match `wanted` (active-peer dicts with `public_key`,
        `address_host`, `preshared_key`) exactly: every wanted peer is
        (re-)applied via `set_peer` (cheap and idempotent, so this also picks
        up address/preshared-key drift for peers that were already present),
        and every peer on the interface that is not wanted is removed.
        Returns `(added, removed)` where `added` only counts peers that were
        not present on wg0 before this call (pure re-applies of already
        present peers are not counted as "added")."""
        current = self.peer_stats()
        wanted_by_key = {p["public_key"]: p for p in wanted}

        added = 0
        for public_key, peer in wanted_by_key.items():
            if public_key not in current:
                added += 1
            address = self.settings.network.network_address + int(peer["address_host"])
            self.set_peer(
                public_key=public_key,
                allowed_ips=[f"{address}/32"],
                preshared_key=peer.get("preshared_key"),
            )

        removed = 0
        for public_key in current:
            if public_key not in wanted_by_key:
                self.remove_peer(public_key)
                removed += 1

        return added, removed

"""Per-peer bandwidth caps on the wg interface, via `tc`.

Direction, from the server's point of view:

* egress on wg0 (server -> peer) is the client's *download*. Capped with one
  HTB class per peer under an `htb` root qdisc, selected by a `u32` filter
  matching the packet's destination IP (the peer's `/32`).
* ingress on wg0 (peer -> server) is the client's *upload*. Capped with a
  `police` action attached to a `u32` filter on wg0's `ingress` qdisc,
  matching the packet's source IP.

Units: everywhere in this codebase (PROTOCOL.md, settings.py, the DB)
"kbps" means **kilobits/s** (1000 bit/s), matching how ISPs advertise plans.
`tc` is ambiguous here: its bare "kbps" unit means kilo-*bytes*/s, while
"kbit" means kilobits/s. So a `down_kbps`/`up_kbps` value of `N` is handed to
`tc` as rate `"{N}kbit"` -- never `"{N}kbps"`, which would be 8x too high.

Everything in this module is **best effort**: when `settings.shaping_enabled`
is false, `tc` is not installed, or any `tc` invocation fails, the failure is
logged once at WARNING and the call returns normally. A shaping failure must
never fail an enrolment -- see `available`.
"""

from __future__ import annotations

import contextlib
import logging
import shlex
import shutil
import subprocess

from app.errors import wg_unavailable
from app.settings import Settings

logger = logging.getLogger("wgvpn.shaper")

# Nominal HTB parent rate/ceiling. This number never actually caps anyone:
# every per-peer class sets rate == ceil to its own cap, so it can't borrow
# past that regardless of what the parent advertises. HTB just requires a
# classful parent to declare *some* rate/ceil.
_ROOT_RATE = "1000mbit"
# Class/qdisc for traffic tc classifies as "none of the per-peer filters
# matched". In steady state nothing should land here (every active peer gets
# its own u32 filter), it just needs to exist as htb's `default`.
_DEFAULT_HEX = "9999"
_DEFAULT_RATE = "1mbit"


def _fmt(argv: list[str]) -> str:
    return " ".join(shlex.quote(a) for a in argv)


def _decode(data: bytes | str | None) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return data


class Shaper:
    def __init__(self, interface: str, settings: Settings) -> None:
        self.interface = interface
        self.settings = settings
        # Injectable, see wgctl.WgController._runner.
        self._runner = subprocess.run
        self._tc_path = shutil.which("tc")
        self._broken = False
        self._warned = False

    # ------------------------------------------------------------------
    # low-level exec
    # ------------------------------------------------------------------

    def _run(self, argv: list[str], *, timeout: float = 5.0) -> subprocess.CompletedProcess:
        logger.debug("exec: %s", _fmt(argv))
        try:
            proc = self._runner(list(argv), capture_output=True, timeout=timeout)
        except FileNotFoundError as exc:
            raise wg_unavailable(f"tc not found: {exc}") from exc
        except subprocess.TimeoutExpired as exc:
            raise wg_unavailable(f"`{_fmt(argv)}` timed out after {timeout}s") from exc
        except OSError as exc:
            raise wg_unavailable(f"`{_fmt(argv)}` failed to start: {exc}") from exc
        if proc.returncode != 0:
            stderr = _decode(proc.stderr).strip()
            raise wg_unavailable(f"`{_fmt(argv)}` exited {proc.returncode}: {stderr or '(no stderr)'}")
        return proc

    def _warn_once(self, msg: str, *args: object) -> None:
        if not self._warned:
            logger.warning(msg, *args)
            self._warned = True
        else:
            logger.debug(msg, *args)

    # ------------------------------------------------------------------
    # availability
    # ------------------------------------------------------------------

    @property
    def available(self) -> bool:
        return bool(self.settings.shaping_enabled) and self._tc_path is not None and not self._broken

    def _peer_ip(self, address_host: int) -> str:
        return str(self.settings.network.network_address + address_host)

    def _handle_for(self, address_host: int) -> str:
        return f"{address_host + 0x10:x}"

    def classid_for(self, address_host: int) -> str:
        """Deterministic per-peer HTB classid: "1:<hex>" where <hex> is
        `address_host + 0x10` in hex, e.g. host 7 -> "1:17"."""
        return f"1:{self._handle_for(address_host)}"

    # ------------------------------------------------------------------
    # root setup / teardown
    # ------------------------------------------------------------------

    def ensure_root(self) -> None:
        """Idempotently builds: htb root qdisc `1:` with a default class,
        the `1:1` parent class, and the `ffff:` ingress qdisc used for
        policing. Uses `... replace ...` throughout so re-running this at
        every startup does not error or duplicate anything. Best effort: any
        failure disables shaping for the rest of this process's life."""
        if not self.settings.shaping_enabled:
            return
        if self._tc_path is None:
            self._warn_once(
                "shaper: 'tc' binary not found in PATH; per-peer bandwidth "
                "shaping is disabled (install iproute2 in the image)"
            )
            return
        try:
            self._run(
                [
                    "tc",
                    "qdisc",
                    "replace",
                    "dev",
                    self.interface,
                    "root",
                    "handle",
                    "1:",
                    "htb",
                    "default",
                    _DEFAULT_HEX,
                ]
            )
            self._run(
                [
                    "tc",
                    "class",
                    "replace",
                    "dev",
                    self.interface,
                    "parent",
                    "1:",
                    "classid",
                    "1:1",
                    "htb",
                    "rate",
                    _ROOT_RATE,
                ]
            )
            self._run(
                [
                    "tc",
                    "class",
                    "replace",
                    "dev",
                    self.interface,
                    "parent",
                    "1:1",
                    "classid",
                    f"1:{_DEFAULT_HEX}",
                    "htb",
                    "rate",
                    _DEFAULT_RATE,
                    "ceil",
                    _ROOT_RATE,
                ]
            )
            self._run(
                ["tc", "qdisc", "replace", "dev", self.interface, "handle", "ffff:", "ingress"]
            )
        except Exception:
            self._broken = True
            self._warn_once(
                "shaper: failed to initialise tc qdiscs on %s; per-peer bandwidth "
                "shaping is disabled for this process",
                self.interface,
            )

    def reset(self) -> None:
        """Tears down the whole qdisc tree (root htb + ingress). Best effort."""
        if not self.available:
            return
        for argv in (
            ["tc", "qdisc", "del", "dev", self.interface, "root"],
            ["tc", "qdisc", "del", "dev", self.interface, "ingress"],
        ):
            try:
                self._run(argv)
            except Exception:
                logger.debug("shaper: reset(): %s failed (already absent?)", _fmt(argv))

    # ------------------------------------------------------------------
    # per-peer apply / clear
    # ------------------------------------------------------------------

    def apply(self, *, address_host: int, down_kbps: int | None, up_kbps: int | None) -> None:
        """Create-or-replace this peer's egress HTB class+filter and ingress
        police filter. `None` for either direction means "no cap in that
        direction" and clears any existing class/filter for it. Best effort:
        never raises, logs once on failure."""
        if not self.available:
            return
        try:
            self._apply_egress(address_host, down_kbps)
            self._apply_ingress(address_host, up_kbps)
        except Exception:
            self._broken = True
            self._warn_once(
                "shaper: apply(address_host=%s) failed; continuing without "
                "per-peer bandwidth caps",
                address_host,
            )

    def clear(self, address_host: int) -> None:
        """Removes this peer's egress class/filter and ingress filter, if
        any. Ignores "not found" (and any other) errors -- best effort."""
        if not self.available:
            return
        self._delete_egress(address_host)
        self._delete_ingress(address_host)

    def _apply_egress(self, address_host: int, down_kbps: int | None) -> None:
        if down_kbps is None:
            self._delete_egress(address_host)
            return
        classid = self.classid_for(address_host)
        handle = self._handle_for(address_host)
        ip = self._peer_ip(address_host)
        rate = f"{down_kbps}kbit"
        self._run(
            [
                "tc",
                "class",
                "replace",
                "dev",
                self.interface,
                "parent",
                "1:1",
                "classid",
                classid,
                "htb",
                "rate",
                rate,
                "ceil",
                rate,
            ]
        )
        self._run(
            [
                "tc",
                "filter",
                "replace",
                "dev",
                self.interface,
                "parent",
                "1:",
                "protocol",
                "ip",
                "prio",
                "1",
                "handle",
                f"800::{handle}",
                "u32",
                "match",
                "ip",
                "dst",
                f"{ip}/32",
                "flowid",
                classid,
            ]
        )

    def _apply_ingress(self, address_host: int, up_kbps: int | None) -> None:
        if up_kbps is None:
            self._delete_ingress(address_host)
            return
        handle = self._handle_for(address_host)
        ip = self._peer_ip(address_host)
        rate = f"{up_kbps}kbit"
        # One second worth of traffic at `up_kbps`, floor 4KB, as the police
        # burst tolerance -- simple and generous enough for interactive use.
        burst_kb = max(4, up_kbps // 8)
        self._run(
            [
                "tc",
                "filter",
                "replace",
                "dev",
                self.interface,
                "parent",
                "ffff:",
                "protocol",
                "ip",
                "prio",
                "1",
                "handle",
                f"800::{handle}",
                "u32",
                "match",
                "ip",
                "src",
                f"{ip}/32",
                "police",
                "rate",
                rate,
                "burst",
                f"{burst_kb}k",
                "drop",
                "flowid",
                ":1",
            ]
        )

    def _delete_egress(self, address_host: int) -> None:
        classid = self.classid_for(address_host)
        handle = self._handle_for(address_host)
        with contextlib.suppress(Exception):
            self._run(
                [
                    "tc",
                    "filter",
                    "del",
                    "dev",
                    self.interface,
                    "parent",
                    "1:",
                    "protocol",
                    "ip",
                    "prio",
                    "1",
                    "handle",
                    f"800::{handle}",
                    "u32",
                ]
            )
        with contextlib.suppress(Exception):
            self._run(["tc", "class", "del", "dev", self.interface, "classid", classid])

    def _delete_ingress(self, address_host: int) -> None:
        handle = self._handle_for(address_host)
        with contextlib.suppress(Exception):
            self._run(
                [
                    "tc",
                    "filter",
                    "del",
                    "dev",
                    self.interface,
                    "parent",
                    "ffff:",
                    "protocol",
                    "ip",
                    "prio",
                    "1",
                    "handle",
                    f"800::{handle}",
                    "u32",
                ]
            )

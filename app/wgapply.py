"""Make a wg interface + tc match a desired peer list.

The one reconcile code path shared by the two kinds of node
(docs/MULTI_NODE.md §4):

* the local node ``nd_local`` (``WGVPN_ROLE=all``): ``PeerService.reconcile``
  renders the node's desired state from the DB and hands it to
  :func:`apply_desired` in-process;
* a remote node (``WGVPN_ROLE=node``): ``node_agent`` fetches the very same
  desired-state document from ``GET /api/node/v1/desired-state`` (or reads it
  from its cache) and hands it to :func:`apply_desired`.

No app imports beyond the standard library: ``wg`` and ``shaper`` are passed
in (``wgctl.WgController``/``shaper.Shaper`` or the test fakes), so this module
is part of the node's self-contained subset.

The desired-state document is untrusted input on a node (plain HTTP, see
PROTOCOL.md §10), so every peer entry is validated before anything is handed
to ``wg``; a malformed entry is skipped and logged, never applied.
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import logging
from collections.abc import Iterable

logger = logging.getLogger("wgvpn.wgapply")


def _is_wg_key(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 44:
        return False
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except (binascii.Error, ValueError):
        return False


def _optional_rate(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"bad rate {value!r}")
    return value


def peers_from_desired(desired: dict) -> tuple[ipaddress.IPv4Network, list[dict]]:
    """Parse a desired-state document into ``(network, peers)``.

    Each returned peer dict has the keys ``wgctl.sync_peers`` and
    ``shaper.apply`` need: ``public_key``, ``preshared_key``, ``address_host``,
    ``rate_down_kbps``, ``rate_up_kbps``.
    """
    network = ipaddress.IPv4Network(desired["interface"]["subnet"], strict=False)
    peers: list[dict] = []
    for entry in desired.get("peers") or []:
        try:
            if not _is_wg_key(entry["public_key"]):
                raise ValueError("bad public_key")
            psk = entry.get("preshared_key")
            if psk is not None and not _is_wg_key(psk):
                raise ValueError("bad preshared_key")
            address = ipaddress.IPv4Interface(entry["address"])
            if address.network.prefixlen != 32 or address.ip not in network:
                raise ValueError(f"address {entry['address']!r} outside {network}")
            host = int(address.ip) - int(network.network_address)
            if host <= 1 or address.ip == network.broadcast_address:
                raise ValueError(f"address {entry['address']!r} is reserved")
            peers.append({
                "public_key": entry["public_key"],
                "preshared_key": psk,
                "address_host": host,
                "rate_down_kbps": _optional_rate(entry.get("rate_down_kbps")),
                "rate_up_kbps": _optional_rate(entry.get("rate_up_kbps")),
            })
        except (KeyError, TypeError, ValueError) as exc:
            logger.warning("desired state: skipping malformed peer entry (%s)", exc)
    return network, peers


def apply_peers(wg, shaper, peers: list[dict], *, clear_hosts: Iterable[int] = ()) -> dict:
    """Make ``wg`` hold exactly ``peers`` and shape each one.

    ``clear_hosts``: address hosts whose tc state must go if no wanted peer
    uses them any more (e.g. a suspended peer that keeps its address, or a
    peer the previous desired state had). Shaping is best effort throughout;
    a wg failure raises (``ApiError`` from wgctl).
    """
    added, removed = wg.sync_peers(peers)

    shaped = 0
    for peer in peers:
        try:
            shaper.apply(
                address_host=peer["address_host"],
                down_kbps=peer["rate_down_kbps"],
                up_kbps=peer["rate_up_kbps"],
            )
            shaped += 1
        except Exception:  # pragma: no cover - shaper is best effort already
            logger.warning("shaper.apply failed for host %s", peer["address_host"], exc_info=True)

    wanted_hosts = {p["address_host"] for p in peers}
    cleared = 0
    for host in set(clear_hosts) - wanted_hosts:
        try:
            shaper.clear(host)
            cleared += 1
        except Exception:  # pragma: no cover - best effort
            logger.warning("shaper.clear failed for host %s", host, exc_info=True)

    return {"added": added, "removed": removed, "shaped": shaped, "cleared": cleared}


def apply_desired(wg, shaper, desired: dict, *, clear_hosts: Iterable[int] = ()) -> dict:
    """:func:`peers_from_desired` then :func:`apply_peers`."""
    _, peers = peers_from_desired(desired)
    return apply_peers(wg, shaper, peers, clear_hosts=clear_hosts)


def counter_delta(current: int, last: int) -> int:
    """wg counters are monotonic per peer but restart at 0 when the peer is
    re-added (or wg0 is recreated): then the whole current value is new."""
    return current - last if current >= last else current

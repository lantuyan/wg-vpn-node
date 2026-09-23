"""Node agent: the whole of a VPN node (``WGVPN_ROLE=node``).

Run as ``python -m app.node_agent``. No HTTP server, no peer database: the
node only makes outbound calls to central's node API (PROTOCOL.md §10) and
makes its wg0 + tc match the desired state central hands it.

Rules (docs/MULTI_NODE.md §6):

* **Central decides, the node applies.** The agent never changes a peer's
  state on its own; while central is unreachable it keeps serving exactly the
  peers it last applied (D3).
* **Cache first.** The last desired state, the unsent counter deltas and the
  report sequence number are persisted in ``<data_dir>/node-state.json``
  (atomic write, mode 0600: it holds preshared keys). On start wg0 is rebuilt
  from that cache *before* central is contacted.
* **Reports are idempotent.** A report is frozen under its ``seq`` before it
  is sent and resent unchanged until central acknowledges it; central ignores
  a ``seq`` it already accepted, so a retry after a lost response is never
  counted twice. New traffic accumulates separately for the next ``seq``.
* **Own keys.** wg0's keypair is generated here (wgctl, ``<data_dir>/keys``);
  only the public key is ever sent.

Imports stay inside the node subset (settings, errors, signing, wgctl,
shaper, wgapply) so ``scripts/publish-node.sh`` can ship this without any
central module.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import secrets
import signal
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from app import __version__, wgapply
from app.settings import Settings
from app.shaper import Shaper
from app.signing import body_sha256, canonical_string, sign
from app.wgctl import WgController

logger = logging.getLogger("wgvpn.node")

CACHE_FILE = "node-state.json"
IP_ECHO_URL = "https://api.ipify.org"
MAX_BACKOFF_SECONDS = 60


# --------------------------------------------------------------------------
# local cache
# --------------------------------------------------------------------------


def _empty_cache() -> dict:
    return {
        "version": 0,        # desired-state version last applied
        "desired": None,     # {"interface": {...}, "peers": [...]} last applied
        "counters": {},      # public_key -> [rx, tx] as last read from wg0
        "pending": {},       # public_key -> {"rx": n, "tx": n} not yet in a report
        "inflight": None,    # {"seq": n, "peers": [...]} sent, not yet acknowledged
        "next_seq": 1,
    }


def load_cache(path: Path) -> dict:
    cache = _empty_cache()
    try:
        cache.update(json.loads(path.read_text()))
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        logger.exception("node cache %s unreadable; starting empty", path)
    return cache


def save_cache(path: Path, cache: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(cache, fh)
    os.replace(tmp, path)


# --------------------------------------------------------------------------
# central client
# --------------------------------------------------------------------------


class CentralError(Exception):
    def __init__(self, status: int, body: object) -> None:
        self.status = status
        self.body = body
        super().__init__(f"central answered {status}: {body}")


class CentralClient:
    """Signs every request with the node secret (PROTOCOL.md §10).

    ``transport(method, path_with_query, headers, body) -> (status, json)`` is
    injectable for tests; the default uses ``urllib``. Network failures raise
    ``OSError`` (``urllib.error.URLError``), non-200 answers ``CentralError``.
    """

    def __init__(self, base_url: str, node_id: str, secret: str, *, transport=None,
                 timeout: float = 15.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.node_id = node_id
        self._secret = secret
        self.timeout = timeout
        self.transport = transport or self._urllib

    def request(self, method: str, path: str, *, query: dict | None = None,
                payload: dict | None = None) -> dict:
        body = b"" if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(16)
        canonical = canonical_string(method, path, timestamp, nonce, body_sha256(body))
        headers = {
            "X-WGVPN-Protocol": "1",
            "X-WGVPN-Node-Id": self.node_id,
            "X-WGVPN-Timestamp": timestamp,
            "X-WGVPN-Nonce": nonce,
            "X-WGVPN-Signature": "v1=" + sign(self._secret, canonical),
            "Content-Type": "application/json",
            "User-Agent": f"wgvpn-node/{__version__}",
        }
        target = path + ("?" + urllib.parse.urlencode(query) if query else "")
        status, data = self.transport(method, target, headers, body)
        if status != 200:
            raise CentralError(status, data)
        return data

    def _urllib(self, method: str, target: str, headers: dict, body: bytes):
        req = urllib.request.Request(
            self.base_url + target, data=body if method != "GET" else None,
            method=method, headers=headers,
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read() or b"{}")
            except ValueError:
                return exc.code, None


def detect_public_ip(timeout: float = 10.0) -> str:
    """Public IPv4 as seen from the internet. Inside a container the kernel's
    own source address is a docker bridge address, so ask an echo service."""
    with urllib.request.urlopen(IP_ECHO_URL, timeout=timeout) as resp:
        text = resp.read().decode("ascii", "replace").strip()
    return str(ipaddress.IPv4Address(text))


def _rfc3339(unix: int) -> str:
    return datetime.fromtimestamp(unix, tz=timezone.utc).isoformat().replace("+00:00", "Z")


# --------------------------------------------------------------------------
# agent
# --------------------------------------------------------------------------


class NodeAgent:
    def __init__(self, settings: Settings, *, wg, shaper, client: CentralClient,
                 cache_path: Path) -> None:
        self.settings = settings
        self.wg = wg
        self.shaper = shaper
        self.client = client
        self.cache_path = cache_path
        self.cache = load_cache(cache_path)
        self.registered = False
        self.poll_seconds = settings.node_poll_seconds
        self.report_seconds = settings.poll_interval_seconds
        self._interface_ready = False
        # public_key -> (latest_handshake, endpoint) from the last wg read
        self._last_seen: dict[str, tuple[int, str | None]] = {}

    def _save(self) -> None:
        save_cache(self.cache_path, self.cache)

    # -- wg0 --------------------------------------------------------------
    def _use_interface(self, desired: dict | None) -> None:
        """Configure wg0 with the subnet/MTU central asks for (every node
        shares central's WGVPN_WG_SUBNET), building it on first use."""
        wanted = self.settings
        if desired is not None:
            iface = desired["interface"]
            wanted = wanted.model_copy(update={
                "wg_subnet": str(ipaddress.IPv4Network(iface["subnet"], strict=False)),
                "wg_mtu": int(iface.get("mtu") or wanted.wg_mtu),
            })
        current = self.wg.settings
        changed = (wanted.wg_subnet, wanted.wg_mtu) != (current.wg_subnet, current.wg_mtu)
        self.wg.settings = self.shaper.settings = wanted
        if changed or not self._interface_ready:
            self.wg.ensure_interface()
            self.shaper.ensure_root()
            self._interface_ready = True

    @staticmethod
    def _hosts(desired: dict | None) -> set[int]:
        if desired is None:
            return set()
        _, peers = wgapply.peers_from_desired(desired)
        return {p["address_host"] for p in peers}

    def _apply(self, desired: dict) -> dict:
        self.collect()  # count the traffic of peers this apply may remove
        previous = self._hosts(self.cache["desired"])
        summary = wgapply.apply_desired(self.wg, self.shaper, desired, clear_hosts=previous)
        logger.info("applied desired state: %s", summary)
        return summary

    def start(self) -> None:
        """D3: bring wg0 back from the cache before central is contacted."""
        desired = self.cache["desired"]
        try:
            self._use_interface(desired)
            if desired is not None:
                self._apply(desired)
                logger.info("wg0 rebuilt from cache (version %s)", self.cache["version"])
        except Exception:  # noqa: BLE001 - retried on the next register/poll
            logger.exception("could not bring wg0 up from the cache yet")

    # -- counters ---------------------------------------------------------
    def collect(self) -> None:
        """Fold wg0's counters into the pending deltas (and persist them)."""
        stats = self.wg.peer_stats()
        last = self.cache["counters"]
        pending = self.cache["pending"]
        counters: dict[str, list[int]] = {}
        for key, stat in stats.items():
            last_rx, last_tx = last.get(key, (0, 0))
            rx = wgapply.counter_delta(stat.rx_bytes, last_rx)
            tx = wgapply.counter_delta(stat.tx_bytes, last_tx)
            if rx or tx:
                entry = pending.setdefault(key, {"rx": 0, "tx": 0})
                entry["rx"] += rx
                entry["tx"] += tx
            counters[key] = [stat.rx_bytes, stat.tx_bytes]
            self._last_seen[key] = (stat.latest_handshake, stat.endpoint)
        self.cache["counters"] = counters
        self._save()

    def stop(self) -> None:
        """On shutdown: count the traffic since the last collect, which would
        otherwise vanish with wg0's counters. Starts from the cache on disk
        (always consistent: atomic writes), since the signal may have
        interrupted a collect halfway."""
        self.cache = load_cache(self.cache_path)
        self.collect()

    # -- central calls ----------------------------------------------------
    def register(self) -> None:
        if not self._interface_ready:
            self._use_interface(self.cache["desired"])
        if not self.settings.wg_host:
            self.settings = self.settings.model_copy(update={"wg_host": detect_public_ip()})
            logger.info("detected public IP %s", self.settings.wg_host)
        data = self.client.request("POST", "/api/node/v1/register", payload={
            "wg_public_key": self.wg.public_key(),
            "endpoint_host": self.settings.wg_host,
            "endpoint_port": self.settings.wg_port,
            "agent_version": __version__,
        })
        self.poll_seconds = max(1, int(data.get("poll_seconds") or self.poll_seconds))
        self.report_seconds = max(5, int(data.get("report_seconds") or self.report_seconds))
        last_seq = int(data.get("last_seq") or 0)
        if self.cache["next_seq"] <= last_seq:
            # Cache lost or restored from an old backup: never reuse a seq
            # central already accepted, or those reports would be ignored.
            self.cache["next_seq"] = last_seq + 1
            self._save()
        self.registered = True
        logger.info("registered with central as %s (%s)", self.client.node_id,
                    data.get("node", {}).get("state"))

    def poll(self) -> bool:
        """Fetch desired-state; apply it when it changed. True if applied."""
        data = self.client.request("GET", "/api/node/v1/desired-state",
                                   query={"since": self.cache["version"]})
        if data.get("unchanged"):
            if self.cache["desired"] is None:
                self.cache["version"] = 0  # nothing cached: ask for the full state
            return False
        desired = {"interface": data["interface"], "peers": data["peers"]}
        self._use_interface(desired)
        self._apply(desired)
        self.cache["desired"] = desired
        self.cache["version"] = int(data["version"])
        self._save()
        return True

    def report(self) -> None:
        self.collect()
        if self.cache["inflight"] is None:
            pending = self.cache["pending"]
            keys = set(pending) | {k for k, (hs, _) in self._last_seen.items() if hs}
            peers = []
            for key in sorted(keys):
                delta = pending.get(key, {"rx": 0, "tx": 0})
                handshake, endpoint = self._last_seen.get(key, (0, None))
                peers.append({
                    "public_key": key,
                    "rx_delta": delta["rx"],
                    "tx_delta": delta["tx"],
                    "last_handshake_at": _rfc3339(handshake) if handshake else None,
                    "endpoint_seen": endpoint,
                })
            self.cache["inflight"] = {"seq": self.cache["next_seq"], "peers": peers}
            self.cache["pending"] = {}
            self.cache["next_seq"] += 1
            self._save()
        inflight = self.cache["inflight"]
        self.client.request("POST", "/api/node/v1/report", payload={
            "seq": inflight["seq"],
            "applied_version": self.cache["version"],
            "peers": inflight["peers"],
        })
        self.cache["inflight"] = None
        self._save()

    # -- main loop --------------------------------------------------------
    def run_forever(self, *, sleep=time.sleep) -> None:
        self.start()
        backoff = 2.0
        poll_failures = 0
        next_poll = next_report = 0.0
        while True:
            if not self.registered:
                try:
                    self.register()
                    backoff = 2.0
                except Exception as exc:  # noqa: BLE001 - keep serving the cache
                    logger.warning("register failed (%s); retrying in %.0fs", exc, backoff)
                    sleep(backoff)
                    backoff = min(backoff * 2, MAX_BACKOFF_SECONDS)
                    continue

            now = time.monotonic()
            if now >= next_poll:
                try:
                    if self.poll():
                        next_report = now  # tell central right away it is applied
                    poll_failures = 0
                    next_poll = now + self.poll_seconds
                except Exception as exc:  # noqa: BLE001 - keep serving what we have
                    poll_failures += 1
                    delay = min(MAX_BACKOFF_SECONDS, self.poll_seconds * 2 ** poll_failures)
                    logger.warning("desired-state poll failed (%s); retrying in %.0fs", exc, delay)
                    next_poll = now + delay
            if now >= next_report:
                try:
                    self.report()
                except Exception as exc:  # noqa: BLE001 - the report stays in flight
                    logger.warning("report failed (%s); will resend", exc)
                next_report = now + self.report_seconds
            sleep(max(0.2, min(next_poll, next_report) - time.monotonic()))


def main() -> None:
    settings = Settings()
    logging.basicConfig(level=settings.log_level,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    missing = [name for name, value in (
        ("WGVPN_CENTRAL_URL", settings.central_url),
        ("WGVPN_NODE_ID", settings.node_id),
        ("WGVPN_NODE_SECRET", settings.node_secret),
    ) if not value]
    if missing:
        logger.error("missing required setting(s): %s", ", ".join(missing))
        sys.exit(2)
    # docker stop sends SIGTERM to PID 1, which ignores it without a handler.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    logger.info("wgvpn node agent %s: node %s, central %s", __version__, settings.node_id,
                settings.central_url)
    agent = NodeAgent(
        settings,
        wg=WgController(settings.wg_interface, settings),
        shaper=Shaper(settings.wg_interface, settings),
        client=CentralClient(settings.central_url, settings.node_id, settings.node_secret),
        cache_path=settings.data_dir / CACHE_FILE,
    )
    try:
        agent.run_forever()
    finally:
        try:
            agent.stop()
        except Exception:  # noqa: BLE001 - shutting down anyway
            logger.exception("could not count the last traffic before exit")


if __name__ == "__main__":
    main()
